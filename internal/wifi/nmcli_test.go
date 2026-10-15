package wifi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSplitTerse(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want []string
	}{
		{"", nil}, {`Cafe\: Guest:78:WPA2`, []string{"Cafe: Guest", "78", "WPA2"}},
		{`Office\\Lab:90:`, []string{`Office\Lab`, "90", ""}},
		{"yes:Home:85\r", []string{"yes", "Home", "85"}}, {":0:--", []string{"", "0", "--"}},
	} {
		t.Run(tt.in, func(t *testing.T) {
			if got := splitTerse(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseNMList(t *testing.T) {
	got := parseNMList("Cafe\\: Guest:78:WPA2\nHome:42:WPA2 WPA3\nHome:92:WPA2 WPA3\n:99:--\ninvalid\nFree:bad:--\n")
	want := []AP{{"Home", 92, "WPA2 WPA3"}, {"Cafe: Guest", 78, "WPA2"}, {"Free", 0, "--"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestNMStatus(t *testing.T) {
	for _, tt := range []struct {
		name, radio, scan string
		want              Status
		calls             int
	}{
		{"disabled", "disabled\n", "", Status{Signal: -1}, 1},
		{"connected", "enabled\n", "no:Guest:60\nyes:Cafe\\: Home:88\n", Status{true, true, "Cafe: Home", 88}, 2},
		{"disconnected", "enabled", "no:Guest:60\n", Status{Enabled: true, Signal: -1}, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			n := NewNM(func(_ context.Context, stdin, name string, args ...string) (string, error) {
				calls++
				if stdin != "" || name != "nmcli" {
					t.Fatalf("unexpected command %s stdin=%q", name, stdin)
				}
				if calls == 1 {
					if !reflect.DeepEqual(args, []string{"-t", "radio", "wifi"}) {
						t.Fatalf("args %v", args)
					}
					return tt.radio, nil
				}
				return tt.scan, nil
			})
			got, err := n.Status(context.Background())
			if err != nil || got != tt.want || calls != tt.calls {
				t.Fatalf("status=%+v err=%v calls=%d", got, err, calls)
			}
		})
	}
}

func TestNMAddArgs(t *testing.T) {
	for _, tt := range []struct {
		name   string
		c      Credentials
		pairs  []string
		secret string
	}{
		{"open", Credentials{SSID: "Guest", Security: Open}, nil, ""},
		{"psk", Credentials{SSID: "Home", Security: PSK, Passphrase: "private-psk", Hidden: true}, []string{"wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk-flags", "2", "802-11-wireless.hidden", "yes"}, "802-11-wireless-security.psk:private-psk\n"},
		{"sae", Credentials{SSID: "Home", Security: SAE, Passphrase: "private-sae"}, []string{"wifi-sec.key-mgmt", "sae", "wifi-sec.psk-flags", "2"}, "802-11-wireless-security.psk:private-sae\n"},
		{"enterprise", Credentials{SSID: "Campus", Security: Enterprise, Identity: "alice", Password: "private-eap", DomainMatch: "example.edu"}, []string{"802-1x.eap", "peap", "802-1x.phase2-auth", "mschapv2", "802-1x.password-flags", "2", "802-1x.system-ca-certs", "yes", "802-1x.domain-suffix-match", "example.edu"}, "802-1x.password:private-eap\n"},
		{"enterprise CA", Credentials{SSID: "Campus", Security: Enterprise, Identity: "alice", Password: "private-eap", DomainMatch: "example.edu;example.org", CACert: "/etc/campus-ca.pem"}, []string{"802-1x.ca-cert", "/etc/campus-ca.pem", "802-1x.domain-suffix-match", "example.edu;example.org"}, "802-1x.password:private-eap\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args, secret, err := nmAddArgs("test", tt.c)
			if err != nil || secret != tt.secret {
				t.Fatalf("secret=%q err=%v", secret, err)
			}
			for i := 0; i < len(tt.pairs); i += 2 {
				found := false
				for j := 0; j+1 < len(args); j++ {
					if args[j] == tt.pairs[i] && args[j+1] == tt.pairs[i+1] {
						found = true
					}
				}
				if !found {
					t.Errorf("missing %v in %v", tt.pairs[i:i+2], args)
				}
			}
			for _, s := range []string{tt.c.Passphrase, tt.c.Password} {
				if s != "" && strings.Contains(strings.Join(args, " "), s) {
					t.Error("secret leaked in args")
				}
			}
			if tt.c.Security == Open && strings.Contains(strings.Join(args, " "), "wifi-sec") {
				t.Error("open network has security args")
			}
			if tt.c.CACert != "" && strings.Contains(strings.Join(args, " "), "802-1x.system-ca-certs") {
				t.Error("custom CA must not enable system CA certificates")
			}
		})
	}
}

func TestNMEnterpriseRequiresServerValidation(t *testing.T) {
	for _, domain := range []string{"", " \t\n", "; ;"} {
		for _, ca := range []string{"", "/etc/campus-ca.pem"} {
			c := Credentials{SSID: "Campus", Security: Enterprise, Identity: "alice", Password: "secret", DomainMatch: domain, CACert: ca}
			args, secrets, err := nmAddArgs("Campus", c)
			if !errors.Is(err, ErrNoServerValidation) || len(args) != 0 || secrets != "" {
				t.Fatalf("args=%v secrets=%q err=%v", args, secrets, err)
			}
			calls := 0
			n := NewNM(func(context.Context, string, string, ...string) (string, error) {
				calls++
				return "", nil
			})
			if err := n.Connect(context.Background(), c); !errors.Is(err, ErrNoServerValidation) {
				t.Fatalf("Connect error=%v", err)
			}
			if calls != 0 {
				t.Fatalf("Connect made %d runner calls without server validation", calls)
			}
		}
	}
}

func TestNMConnect(t *testing.T) {
	type call struct {
		stdin, name string
		args        []string
	}
	var calls []call
	n := NewNM(func(_ context.Context, stdin, name string, args ...string) (string, error) {
		calls = append(calls, call{stdin, name, append([]string(nil), args...)})
		if len(calls) == 1 {
			return "", errors.New("old profile missing")
		}
		return "", nil
	})
	c := Credentials{SSID: "Home", Security: PSK, Passphrase: "secret-pass"}
	if err := n.Connect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	add, secret, _ := nmAddArgs("wcprime-Home", c)
	want := []call{{"", "nmcli", []string{"connection", "delete", "id", "wcprime-Home"}}, {"", "nmcli", add}, {secret, "nmcli", []string{"--wait", "45", "connection", "up", "id", "wcprime-Home", "passwd-file", "/dev/stdin"}}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%#v, want %#v", calls, want)
	}
}
