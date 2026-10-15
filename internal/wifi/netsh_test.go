package wifi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseNetshInterfaces(t *testing.T) {
	for _, tt := range []struct {
		name, in string
		want     Status
	}{
		{"English", "    Name : Wi-Fi\r\n    GUID : abc-123\r\n    State : connected\r\n    SSID : Home Network\r\n    AP BSSID : 00:11:22:33:44:55\r\n    Signal : 87%\r\n", Status{true, true, "Home Network", 87}},
		{"localized", "    Nom : Wi-Fi\n    GUID : abc-123\n    État : connecté\n    SSID : Café réseau\n    AP BSSID : 00:11:22:33:44:55\n    Signalstärke : 76%\n", Status{true, true, "Café réseau", 76}},
		{"AP BSSID only", "    GUID : abc-123\n    AP BSSID : 00:11:22:33:44:55\n", Status{Enabled: true, Signal: -1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseNetshInterfaces(tt.in); got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseNetshNetworks(t *testing.T) {
	const sample = `Interface name : Wi-Fi
There are 3 networks currently visible.
SSID 1 : Home Network
    Network type : Infrastructure
    Authentication : WPA2-Personal
    Encryption : CCMP
    BSSID 1 : 00:11:22:33:44:55
         Signal : 60%
    BSSID 2 : 00:11:22:33:44:56
         Signal : 92%
SSID 2 : Guest
    Authentication : Open
    Signal : 45%
SSID 3 :
    Authentication : WPA2-Personal
    Signal : 100%
`
	want := []AP{{"Home Network", 92, "WPA2-Personal"}, {"Guest", 45, "Open"}}
	if got := parseNetshNetworks(sample); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// xmlNode deliberately ignores schema namespaces so every nested element is decoded.
type xmlNode struct {
	XMLName  xml.Name
	Text     string    `xml:",chardata"`
	Children []xmlNode `xml:",any"`
}

func (n xmlNode) find(name string) string {
	if n.XMLName.Local == name {
		return n.Text
	}
	for _, c := range n.Children {
		if s := c.find(name); s != "" {
			return s
		}
	}
	return ""
}

func TestWinProfileXML(t *testing.T) {
	for _, sec := range []Security{Open, PSK, SAE, Enterprise} {
		t.Run(string(sec), func(t *testing.T) {
			c := Credentials{SSID: "Café <&>", Security: sec, Passphrase: `pass<&>"'phrase`, Identity: "alice", Password: "secret", DomainMatch: "auth.example.edu", Hidden: true}
			data, err := winProfileXML("wcprime-"+c.SSID, c)
			if err != nil {
				t.Fatal(err)
			}
			var root xmlNode
			if err := xml.Unmarshal([]byte(data), &root); err != nil {
				t.Fatalf("invalid XML: %v", err)
			}
			if root.XMLName.Local != "WLANProfile" || root.find("name") != "wcprime-"+c.SSID {
				t.Fatal("wrong profile name/root")
			}
			if got := root.find("hex"); got != strings.ToUpper(hex.EncodeToString([]byte(c.SSID))) {
				t.Errorf("SSID hex=%q", got)
			}
			if sec == PSK || sec == SAE {
				if root.find("keyMaterial") != c.Passphrase {
					t.Error("passphrase did not round-trip")
				}
				if strings.Contains(data, c.Passphrase) {
					t.Error("passphrase not escaped")
				}
			}
			if sec == Enterprise && (root.find("useOneX") != "true" || root.find("Type") != "25") {
				t.Error("missing PEAP configuration")
			}
		})
	}
	_, err := winProfileXML("Campus", Credentials{SSID: "Campus", Security: Enterprise, EAP: "ttls", DomainMatch: "example.edu"})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("TTLS error=%v", err)
	}
}

func TestWinProfileEnterpriseServerValidation(t *testing.T) {
	c := Credentials{SSID: "Campus", Security: Enterprise, Identity: "alice", Password: "secret"}
	for _, domain := range []string{"", " \t\n", "; ;"} {
		c.DomainMatch = domain
		data, err := winProfileXML("Campus", c)
		if !errors.Is(err, ErrNoServerValidation) || data != "" {
			t.Fatalf("domain=%q: profile=%q err=%v", domain, data, err)
		}
	}
	c.DomainMatch = "auth.example.edu;radius.example.edu"
	data, err := winProfileXML("Campus", c)
	if err != nil {
		t.Fatal(err)
	}
	var root xmlNode
	if err := xml.Unmarshal([]byte(data), &root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"PerformServerValidation", "AcceptServerName", "DisableUserPromptForServerValidation"} {
		if got := root.find(name); got != "true" {
			t.Errorf("%s=%q, want true", name, got)
		}
	}
	if got := root.find("ServerNames"); got != c.DomainMatch {
		t.Errorf("ServerNames=%q, want %q", got, c.DomainMatch)
	}
}

func TestWinProfileEnterpriseCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint := sha1.Sum(cert.Raw)
	want := fmt.Sprintf("% x", thumbprint)
	for _, format := range []string{"PEM", "DER"} {
		t.Run(format, func(t *testing.T) {
			data := der
			if format == "PEM" {
				data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
				// A bundle uses its first certificate, not the following entry.
				data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid second certificate")})...)
			}
			path := filepath.Join(t.TempDir(), "ca.crt")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			profile, err := winProfileXML("Campus", Credentials{Security: Enterprise, DomainMatch: "example.edu", CACert: path})
			if err != nil {
				t.Fatal(err)
			}
			// Assert both the fingerprint and the schema's child order.
			validation := `<ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>example.edu</ServerNames><TrustedRootCA>` + want + `</TrustedRootCA></ServerValidation>`
			if !strings.Contains(profile, validation) {
				t.Errorf("missing server validation %s in %s", validation, profile)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "invalid.crt")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, filepath.Join(t.TempDir(), "missing.crt")} {
		profile, err := winProfileXML("Campus", Credentials{Security: Enterprise, DomainMatch: "example.edu", CACert: path})
		if err == nil || profile != "" {
			t.Fatalf("CA=%q: profile=%q err=%v", path, profile, err)
		}
	}
}

func TestWinEapUserXML(t *testing.T) {
	c := Credentials{Identity: `alice<&>"`, Password: `secret<&>'`, AnonymousIdentity: "anonymous<&>@example.edu"}
	var root xmlNode
	if err := xml.Unmarshal([]byte(winEapUserXML(c)), &root); err != nil {
		t.Fatal(err)
	}
	if root.XMLName.Local != "EapHostUserCredentials" || root.find("Username") != c.Identity || root.find("Password") != c.Password || root.find("RoutingIdentity") != c.AnonymousIdentity {
		t.Fatalf("credentials did not round-trip: %#v", root)
	}
}
