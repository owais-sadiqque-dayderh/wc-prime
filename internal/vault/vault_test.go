package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"
)

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return v, dir
}

func save(t *testing.T, v *Vault, n Network) Network {
	t.Helper()
	stored, err := v.Save(n)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestRoundTrip(t *testing.T) {
	v, dir := newVault(t)
	n := save(t, v, Network{SSID: " Secret-network ", Security: wifi.PSK, Passphrase: "secret-passphrase", Portal: true, Username: "login", Password: "portal-secret", PortalURL: "https://example.com/login", Extra: map[string]string{"token": "private-token"}, Enabled: true})
	if n.SSID != "Secret-network" || len(n.ID) != 16 {
		t.Fatalf("unexpected stored network: %#v", n)
	}
	data, err := os.ReadFile(filepath.Join(dir, "vault.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("WCV1")) {
		t.Fatal("missing magic")
	}
	for _, secret := range []string{n.SSID, n.Passphrase, n.Password, "private-token"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("plaintext %q found", secret)
		}
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.List(), []Network{n}) {
		t.Fatalf("round trip mismatch: %#v", reopened.List())
	}
	if got, ok := reopened.FindSSID(n.SSID); !ok || !reflect.DeepEqual(got, n) {
		t.Fatal("FindSSID failed")
	}
	if _, ok := reopened.FindSSID(" Secret-network "); ok {
		t.Fatal("FindSSID must match exactly")
	}
	if _, ok := reopened.Get("missing"); ok {
		t.Fatal("Get found missing ID")
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"vault.bin", "vault.key"} {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("%s mode: %o", name, info.Mode().Perm())
			}
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatalf("directory mode: %o", info.Mode().Perm())
		}
	}
}

func TestOrderAndVersion(t *testing.T) {
	v, dir := newVault(t)
	if v.Version() != 0 {
		t.Fatal("initial version")
	}
	a := save(t, v, Network{SSID: "a"})
	b := save(t, v, Network{SSID: "b"})
	c := save(t, v, Network{SSID: "c"})
	if got := v.List(); got[0].ID != a.ID || got[2].ID != c.ID {
		t.Fatal("insert did not append")
	}
	a.Hidden = true
	save(t, v, a)
	if v.List()[0].ID != a.ID || v.Version() != 4 {
		t.Fatal("update moved network or wrong version")
	}
	for _, ids := range [][]string{{a.ID}, {a.ID, a.ID, c.ID}, {a.ID, b.ID, "missing"}} {
		if err := v.Reorder(ids); err == nil {
			t.Fatalf("accepted reorder %v", ids)
		}
	}
	if v.Version() != 4 {
		t.Fatal("failed reorder bumped version")
	}
	if err := v.Reorder([]string{c.ID, a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if v.Version() != 5 || v.List()[0].ID != c.ID {
		t.Fatal("reorder failed")
	}
	if err := v.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if v.Version() != 6 {
		t.Fatal("delete did not bump version")
	}
	if err := v.Delete(a.ID); err == nil {
		t.Fatal("deleted nonexistent ID")
	}
	if v.Version() != 6 {
		t.Fatal("failed delete bumped version")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.List(); len(got) != 2 || got[0].ID != c.ID || got[1].ID != b.ID {
		t.Fatal("order not persisted")
	}
}

func TestKeepSecretsAndNormalization(t *testing.T) {
	v, _ := newVault(t)
	n := save(t, v, Network{SSID: "psk", Security: wifi.PSK, Passphrase: "password", Portal: true, Username: "user", Password: "secret", PortalHosts: []string{" Login.Example.org ", ""}})
	if len(n.PortalHosts) != 1 || n.PortalHosts[0] != "login.example.org" {
		t.Fatalf("portal hosts not normalised: %q", n.PortalHosts)
	}
	n.Passphrase, n.Password = "", ""
	n = save(t, v, n)
	if n.Passphrase != "password" || n.Password != "secret" {
		t.Fatal("secrets lost on update")
	}
	n.Security, n.Portal = wifi.Open, false
	n.EAP, n.Phase2, n.AnonymousIdentity, n.CACert, n.DomainMatch = "peap", "pap", "anon", "cert", "domain"
	n.PortalURL, n.UserField, n.PassField, n.Extra, n.InsecureTLS = "https://example.com", "u", "p", map[string]string{"x": "y"}, true
	n = save(t, v, n)
	if n.Passphrase != "" || n.EAP != "" || n.Phase2 != "" || n.AnonymousIdentity != "" || n.CACert != "" || n.DomainMatch != "" || n.PortalURL != "" || n.UserField != "" || n.PassField != "" || n.Extra != nil || n.InsecureTLS || n.PortalHosts != nil {
		t.Fatal("irrelevant fields not cleared")
	}
	e := save(t, v, Network{SSID: "enterprise", Security: wifi.Enterprise, Username: "user", Password: "secret", EAP: "ttls", DomainMatch: "radius.example.org"})
	e.Password = ""
	e = save(t, v, e)
	if e.Password != "secret" || e.EAP != "ttls" {
		t.Fatal("enterprise credentials lost")
	}
	click := save(t, v, Network{SSID: "click", Portal: true, Username: "guest", PortalHosts: []string{"portal.example"}})
	if click.Password != "" || click.Security != wifi.Open {
		t.Fatal("click-through/default security")
	}
}

func TestValidation(t *testing.T) {
	v, _ := newVault(t)
	cases := []struct {
		name string
		n    Network
		want string
	}{
		{"empty", Network{}, "SSID is required"},
		{"whitespace", Network{SSID: "  "}, "SSID is required"},
		{"long", Network{SSID: strings.Repeat("x", 33)}, "32 bytes"},
		{"multibyte", Network{SSID: strings.Repeat("é", 17)}, "32 bytes"},
		{"security", Network{SSID: "x", Security: "wep"}, "security"},
		{"short psk", Network{SSID: "x", Security: wifi.PSK, Passphrase: "1234567"}, "8–63"},
		{"long sae", Network{SSID: "x", Security: wifi.SAE, Passphrase: strings.Repeat("x", 64)}, "8–63"},
		{"enterprise username", Network{SSID: "x", Security: wifi.Enterprise, Password: "secret"}, "username and password"},
		{"enterprise password", Network{SSID: "x", Security: wifi.Enterprise, Username: "user"}, "username and password"},
		{"portal username", Network{SSID: "x", Portal: true}, "username"},
		{"enterprise server domain", Network{SSID: "x", Security: wifi.Enterprise, Username: "user", Password: "secret"}, "RADIUS server domain"},
		{"portal trusted host", Network{SSID: "x", Portal: true, Username: "user"}, "trusted portal host"},
		{"portal host path", Network{SSID: "x", Portal: true, Username: "user", PortalHosts: []string{"evil.example/login"}}, "host name"},
		{"portal scheme", Network{SSID: "x", Portal: true, Username: "user", PortalURL: "ftp://example.com"}, "http or https"},
		{"portal relative", Network{SSID: "x", Portal: true, Username: "user", PortalURL: "/login"}, "http or https"},
		{"portal host", Network{SSID: "x", Portal: true, Username: "user", PortalURL: "https:///login"}, "http or https"},
		{"portal malformed", Network{SSID: "x", Portal: true, Username: "user", PortalURL: "http://%xx"}, "http or https"},
		{"unknown ID", Network{ID: "unknown", SSID: "x"}, "does not exist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Save(tc.n); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v; want %q", err, tc.want)
			}
		})
	}
	if v.Version() != 0 || len(v.List()) != 0 {
		t.Fatal("invalid saves changed vault")
	}
	n := save(t, v, Network{SSID: "duplicate"})
	if _, err := v.Save(Network{SSID: " duplicate "}); err == nil {
		t.Fatal("accepted duplicate SSID")
	}
	save(t, v, n)
	save(t, v, Network{SSID: "sae", Security: wifi.SAE, Passphrase: strings.Repeat("x", 63)})
}

func TestCopies(t *testing.T) {
	v, _ := newVault(t)
	input := Network{SSID: "copy", Portal: true, Username: "user", PortalHosts: []string{"h"}, Extra: map[string]string{"k": "original"}}
	saved := save(t, v, input)
	input.Extra["k"] = "input"
	saved.Extra["k"] = "save"
	listed := v.List()
	listed[0].Extra["k"] = "list"
	listed[0].SSID = "changed"
	got, _ := v.Get(saved.ID)
	got.Extra["k"] = "get"
	found, _ := v.FindSSID("copy")
	found.Extra["k"] = "find"
	final, _ := v.Get(saved.ID)
	if final.Extra["k"] != "original" || final.SSID != "copy" {
		t.Fatal("returned data aliases vault")
	}
}

func TestCorruptAndWrongKey(t *testing.T) {
	for _, kind := range []string{"header", "short", "ciphertext", "wrong key", "missing key", "invalid key"} {
		t.Run(kind, func(t *testing.T) {
			v, dir := newVault(t)
			save(t, v, Network{SSID: "precious"})
			path := filepath.Join(dir, "vault.bin")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "header":
				data[0] ^= 1
			case "short":
				data = data[:10]
			case "ciphertext":
				data[len(data)-1] ^= 1
			case "wrong key":
				_, other := newVault(t)
				key, err := os.ReadFile(filepath.Join(other, "vault.key"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "vault.key"), key, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing key":
				if err := os.Remove(filepath.Join(dir, "vault.key")); err != nil {
					t.Fatal(err)
				}
			case "invalid key":
				if err := os.WriteFile(filepath.Join(dir, "vault.key"), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir); err == nil {
				t.Fatal("opened corrupt/wrong-key vault")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, after) {
				t.Fatal("failed Open overwrote vault")
			}
		})
	}
}

func TestFailedPersistence(t *testing.T) {
	v, dir := newVault(t)
	n := save(t, v, Network{SSID: "unchanged"})
	// A directory at the destination makes replacement fail on every platform.
	if err := os.Remove(filepath.Join(dir, "vault.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "vault.bin"), 0700); err != nil {
		t.Fatal(err)
	}
	n.SSID = "changed"
	if _, err := v.Save(n); err == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	if err := v.Delete(n.ID); err == nil {
		t.Fatal("delete unexpectedly succeeded")
	}
	if err := v.Reorder([]string{n.ID}); err == nil {
		t.Fatal("reorder unexpectedly succeeded")
	}
	if v.Version() != 1 || v.List()[0].SSID != "unchanged" {
		t.Fatal("failed persistence changed memory")
	}
}

func TestConcurrentAccess(t *testing.T) {
	v, _ := newVault(t)
	n := save(t, v, Network{SSID: "concurrent", Portal: true, Username: "user", PortalHosts: []string{"h"}, Extra: map[string]string{"k": "v"}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, err := v.Save(n); err != nil {
					t.Error(err)
					return
				}
				v.List()
				v.Get(n.ID)
				v.FindSSID(n.SSID)
				v.Version()
			}
		}()
	}
	wg.Wait()
	if v.Version() != 81 {
		t.Fatalf("version = %d", v.Version())
	}
}
