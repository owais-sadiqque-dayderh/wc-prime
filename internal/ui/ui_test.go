package ui

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/owais-sadiqque-dayderh/wc-prime/internal/events"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/keeper"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/vault"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"
)

type fakeStore struct {
	networks []vault.Network
	saves    []vault.Network
	deleted  string
	order    []string
	err      error
}

func (f *fakeStore) List() []vault.Network { return f.networks }
func (f *fakeStore) Get(id string) (vault.Network, bool) {
	for _, n := range f.networks {
		if n.ID == id {
			return n, true
		}
	}
	return vault.Network{}, false
}
func (f *fakeStore) Save(n vault.Network) (vault.Network, error) {
	f.saves = append(f.saves, n)
	if n.ID == "" {
		n.ID = "new"
	}
	return n, f.err
}
func (f *fakeStore) Delete(id string) error     { f.deleted = id; return f.err }
func (f *fakeStore) Reorder(ids []string) error { f.order = ids; return f.err }

type fakeService struct {
	triggered bool
	scanErr   error
}

func (f *fakeService) Status() keeper.Snapshot {
	return keeper.Snapshot{Health: keeper.Online, SSID: "Home", Signal: 80}
}
func (f *fakeService) Trigger() { f.triggered = true }
func (f *fakeService) Scan(context.Context) ([]wifi.AP, error) {
	return []wifi.AP{{SSID: "Home", Signal: 80, Security: "WPA2"}, {SSID: "Cafe", Signal: 50, Security: "Open"}}, f.scanErr
}
func (f *fakeService) Events() []events.Event { return nil }
func request(h http.Handler, method, path, body, token, host, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	if token != "" {
		r.Header.Set("X-WC-Token", token)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func call(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	return request(h, method, path, body, "secret", "127.0.0.1:7878", "application/json")
}
func TestSecurity(t *testing.T) {
	h := New(&fakeStore{}, &fakeService{}, "secret")
	for _, path := range []string{"/api/status", "/api/networks", "/api/scan", "/api/check", "/api/missing"} {
		for _, token := range []string{"", "wrong"} {
			if w := request(h, "GET", path, "", token, "localhost:7878", ""); w.Code != 401 {
				t.Errorf("%s token %q: %d", path, token, w.Code)
			}
		}
	}
	for _, host := range []string{"evil.example:7878", "127.0.0.1.evil:7878", "0.0.0.0:7878", "[::ffff:127.0.0.1]:7878", "localhost", "evil.example"} {
		for _, path := range []string{"/", "/icon.svg", "/api/status"} {
			if w := request(h, "GET", path, "", "secret", host, ""); w.Code != 403 {
				t.Errorf("host %q %s: %d", host, path, w.Code)
			}
		}
	}
	for _, host := range []string{"localhost:7878", "127.0.0.1:7878", "[::1]:7878"} {
		w := request(h, "GET", "/api/status", "", "secret", host, "")
		if w.Code != 200 {
			t.Errorf("valid host %s: %d", host, w.Code)
		}
		for _, key := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cache-Control"} {
			if w.Header().Get(key) == "" {
				t.Errorf("missing %s", key)
			}
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		if w := request(h, method, "/api/networks/x", "{}", "secret", "localhost:7878", "text/plain"); w.Code != 400 {
			t.Errorf("non-JSON %s: %d", method, w.Code)
		}
	}
}
func TestAssets(t *testing.T) {
	h := New(&fakeStore{}, &fakeService{}, "secret")
	for _, p := range []string{"/", "/icon.svg"} {
		w := request(h, "GET", p, "", "", "localhost:7878", "")
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Errorf("asset %s: %d", p, w.Code)
		}
	}
	w := call(h, "GET", "/", "")
	if !strings.Contains(w.Body.String(), "wc-prime") {
		t.Fatal("missing UI")
	}
}
func TestNoSecrets(t *testing.T) {
	f := &fakeStore{networks: []vault.Network{{ID: "a", SSID: "Home", Passphrase: "secret-phrase", Password: "secret-password"}}}
	h := New(f, &fakeService{}, "secret")
	for _, w := range []*httptest.ResponseRecorder{call(h, "GET", "/api/networks", ""), call(h, "POST", "/api/networks", `{"ssid":"Test","passphrase":"secret-phrase","password":"secret-password"}`)} {
		b := w.Body.String()
		if strings.Contains(b, "secret-phrase") || strings.Contains(b, "secret-password") {
			t.Fatal("response leaked credentials")
		}
		if !strings.Contains(b, `"hasPassphrase":true`) || !strings.Contains(b, `"hasPassword":true`) {
			t.Fatal("missing credential indicators")
		}
	}
}
func TestStoreDelegation(t *testing.T) {
	f := &fakeStore{networks: []vault.Network{{ID: "a", SSID: "Home"}, {ID: "b", SSID: "Work"}}}
	h := New(f, &fakeService{}, "secret")
	w := call(h, "POST", "/api/networks", `{"id":"injected","ssid":"New","security":"psk","passphrase":"pass","enabled":true}`)
	if w.Code != 201 || len(f.saves) != 1 || f.saves[0].ID != "" || f.saves[0].Passphrase != "pass" {
		t.Fatalf("create: %d %+v", w.Code, f.saves)
	}
	w = call(h, "PUT", "/api/networks/a", `{"id":"wrong","ssid":"Updated","enabled":false}`)
	if w.Code != 200 || f.saves[1].ID != "a" || f.saves[1].SSID != "Updated" || f.saves[1].Password != "" {
		t.Fatalf("update: %d %+v", w.Code, f.saves)
	}
	w = call(h, "POST", "/api/networks/order", `{"ids":["b","a"]}`)
	if w.Code != 200 || !reflect.DeepEqual(f.order, []string{"b", "a"}) {
		t.Fatalf("order: %d %+v", w.Code, f.order)
	}
	w = call(h, "DELETE", "/api/networks/a", "")
	if w.Code != 200 || f.deleted != "a" {
		t.Fatalf("delete: %d %s", w.Code, f.deleted)
	}
	for _, method := range []string{"PUT", "DELETE"} {
		if w := call(h, method, "/api/networks/missing", `{}`); w.Code != 404 {
			t.Errorf("missing %s: %d", method, w.Code)
		}
	}
	f.err = errors.New("store rejected operation")
	if w := call(h, "POST", "/api/networks", `{}`); w.Code != 400 || !strings.Contains(w.Body.String(), f.err.Error()) {
		t.Fatal("store error not returned")
	}
}
func TestScanAndCheck(t *testing.T) {
	svc := &fakeService{}
	h := New(&fakeStore{networks: []vault.Network{{SSID: "Home"}}}, svc, "secret")
	w := call(h, "GET", "/api/scan", "")
	var aps []struct {
		SSID   string `json:"ssid"`
		Saved  bool   `json:"saved"`
		Signal int    `json:"signal"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &aps); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(aps) != 2 || !aps[0].Saved || aps[1].Saved || aps[0].Signal != 80 {
		t.Fatalf("scan: %s", w.Body)
	}
	if w := call(h, "POST", "/api/check", `{}`); w.Code != 202 || !svc.triggered {
		t.Fatal("check not triggered")
	}
	svc.scanErr = errors.New("scan failed")
	if w := call(h, "GET", "/api/scan", ""); w.Code != 500 {
		t.Fatal("scan failure status", w.Code)
	}
}
func TestInvalidJSON(t *testing.T) {
	h := New(&fakeStore{}, &fakeService{}, "secret")
	for _, body := range []string{"", `{`, `{} {}`, `{"ssid":"` + strings.Repeat("a", 65536) + `"}`} {
		if w := call(h, "POST", "/api/networks", body); w.Code != 400 {
			t.Errorf("invalid body accepted: %d", w.Code)
		}
	}
	if w := request(h, "POST", "/api/networks", `{}`, "secret", "localhost:7878", "application/json; charset=utf-8"); w.Code != 201 {
		t.Fatal("JSON charset not accepted")
	}
}
func TestToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	a, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(a)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid random token")
	}
	b, err := LoadOrCreateToken(dir)
	if err != nil || a != b {
		t.Fatal("token not persisted", err)
	}
	info, err := os.Stat(filepath.Join(dir, "ui.token"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", info.Mode().Perm())
	}
	if err := os.WriteFile(filepath.Join(dir, "ui.token"), bytes.Repeat([]byte("x"), 64), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(dir); err == nil {
		t.Fatal("invalid existing token accepted")
	}
}
