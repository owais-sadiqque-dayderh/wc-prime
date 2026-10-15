package wifi

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestParseMacHardwarePorts(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"Hardware Port: Ethernet\nDevice: en0\n\nHardware Port: Wi-Fi\nDevice: en1\nEthernet Address: aa:bb:cc:dd:ee:ff\n", "en1"},
		{"Hardware Port: AirPort\nDevice: en0\n", "en0"}, {"Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n", ""},
	} {
		if got := parseMacHardwarePorts(tt.in); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}

func TestParseSystemProfiler(t *testing.T) {
	const sample = `Wi-Fi:
    Interfaces:
        en0:
          Card Type: Wi-Fi (0x14E4, 0x170)
          Current Network Information:
            Office: West:
              PHY Mode: 802.11ax
              Security: WPA2 Personal
              Signal / Noise: -55 dBm / -92 dBm
          Other Local Wi-Fi Networks:
            Guest Lounge:
              Security: None
              Signal / Noise: -70 dBm / -92 dBm
            Office: West:
              Security: WPA2 Personal
              Signal / Noise: -80 dBm / -92 dBm
        awdl0:
          Supported PHY Modes: 802.11n 802.11ac
          Status: Active
`
	want := []AP{{"Office: West", 90, "WPA2 Personal"}, {"Guest Lounge", 60, "None"}}
	if got := parseSystemProfiler(sample); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestMacStatusFallbacks(t *testing.T) {
	for _, tt := range []struct {
		name, summary, addr string
		want                Status
	}{
		{"summary", "  SSID : Coffee Shop\n", "", Status{true, true, "Coffee Shop", -1}},
		{"redacted", "  SSID : <redacted>\n", "192.168.1.12\n", Status{true, true, "", -1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var commands []string
			m := NewMac(func(_ context.Context, stdin, name string, args ...string) (string, error) {
				command := name + " " + strings.Join(args, " ")
				commands = append(commands, command)
				switch command {
				case "networksetup -listallhardwareports":
					return "Hardware Port: Wi-Fi\nDevice: en0\n", nil
				case "networksetup -getairportpower en0":
					return "Wi-Fi Power (en0): On\n", nil
				case "networksetup -getairportnetwork en0":
					return "You are not associated with an AirPort network.\n", nil
				case "ipconfig getsummary en0":
					return tt.summary, nil
				case "ipconfig getifaddr en0":
					return tt.addr, nil
				default:
					t.Fatalf("unexpected command: %s", command)
					return "", nil
				}
			})
			got, err := m.Status(context.Background())
			if err != nil || got != tt.want {
				t.Fatalf("got %+v err=%v", got, err)
			}
			if tt.name == "redacted" && commands[len(commands)-1] != "ipconfig getifaddr en0" {
				t.Fatal("missing address fallback")
			}
		})
	}
}

func TestMacConnectExitZeroFailure(t *testing.T) {
	m := NewMac(func(_ context.Context, stdin, name string, args ...string) (string, error) {
		return "Could not find network Guest.\n", nil
	})
	m.iface = "en0"
	if err := m.Connect(context.Background(), Credentials{SSID: "Guest", Security: Open}); err == nil {
		t.Fatal("exit-zero failure accepted")
	}
}
