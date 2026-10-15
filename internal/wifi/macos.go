package wifi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Mac drives macOS Wi-Fi through networksetup, ipconfig and system_profiler.
//
// WPA-Enterprise networks cannot be configured from the command line on
// macOS; install the institution's configuration profile once and the
// keeper will still join that SSID when it is the best candidate.
type Mac struct {
	run   Runner
	iface string
}

func NewMac(r Runner) *Mac { return &Mac{run: r} }

func (m *Mac) Name() string { return "macos/networksetup" }

func (m *Mac) device(ctx context.Context) (string, error) {
	if m.iface != "" {
		return m.iface, nil
	}
	out, err := m.run(ctx, "", "networksetup", "-listallhardwareports")
	if err != nil {
		return "", err
	}
	dev := parseMacHardwarePorts(out)
	if dev == "" {
		return "", errors.New("no Wi-Fi interface found")
	}
	m.iface = dev
	return dev, nil
}

func parseMacHardwarePorts(out string) string {
	wifi := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "Hardware Port:"); ok {
			v = strings.TrimSpace(v)
			wifi = v == "Wi-Fi" || v == "AirPort"
		} else if v, ok := strings.CutPrefix(line, "Device:"); ok && wifi {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var macSummarySSID = regexp.MustCompile(`(?m)^\s+SSID : (.+)$`)

func (m *Mac) Status(ctx context.Context) (Status, error) {
	st := Status{Signal: -1}
	dev, err := m.device(ctx)
	if err != nil {
		return st, err
	}
	out, err := m.run(ctx, "", "networksetup", "-getairportpower", dev)
	if err != nil {
		return st, err
	}
	st.Enabled = strings.HasSuffix(strings.TrimSpace(out), "On")
	if !st.Enabled {
		return st, nil
	}
	if out, err := m.run(ctx, "", "networksetup", "-getairportnetwork", dev); err == nil {
		if v, ok := strings.CutPrefix(strings.TrimSpace(out), "Current Wi-Fi Network:"); ok {
			st.SSID = strings.TrimSpace(v)
		}
	}
	if st.SSID == "" {
		// networksetup stopped reporting the SSID in macOS 15; ipconfig still does.
		if out, err := m.run(ctx, "", "ipconfig", "getsummary", dev); err == nil {
			if mm := macSummarySSID.FindStringSubmatch(out); mm != nil && mm[1] != "<redacted>" {
				st.SSID = strings.TrimSpace(mm[1])
			}
		}
	}
	if st.SSID != "" {
		st.Connected = true
	} else if out, err := m.run(ctx, "", "ipconfig", "getifaddr", dev); err == nil && strings.TrimSpace(out) != "" {
		st.Connected = true // associated, but the OS hides the name
	}
	return st, nil
}

func (m *Mac) Enable(ctx context.Context) error {
	dev, err := m.device(ctx)
	if err != nil {
		return err
	}
	_, err = m.run(ctx, "", "networksetup", "-setairportpower", dev, "on")
	return err
}

func (m *Mac) Scan(ctx context.Context) ([]AP, error) {
	out, err := m.run(ctx, "", "system_profiler", "SPAirPortDataType")
	if err != nil {
		return nil, err
	}
	return parseSystemProfiler(out), nil
}

var macSignal = regexp.MustCompile(`Signal / Noise:\s*(-?\d+) dBm`)

// parseSystemProfiler reads the "Current Network Information" and
// "Other Local Wi-Fi Networks" sections of system_profiler output.
func parseSystemProfiler(out string) []AP {
	var aps []AP
	sectionIndent, childIndent := -1, -1
	var cur *AP
	flush := func() {
		if cur != nil {
			aps = append(aps, *cur)
			cur = nil
		}
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r ")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if trimmed == "Current Network Information:" || trimmed == "Other Local Wi-Fi Networks:" {
			flush()
			sectionIndent, childIndent = indent, -1
			continue
		}
		if sectionIndent < 0 {
			continue
		}
		if indent <= sectionIndent {
			flush()
			sectionIndent = -1
			continue
		}
		if childIndent < 0 {
			childIndent = indent
		}
		if indent == childIndent && strings.HasSuffix(trimmed, ":") {
			flush()
			cur = &AP{SSID: strings.TrimSuffix(trimmed, ":")}
			continue
		}
		if cur == nil {
			continue
		}
		if v, ok := strings.CutPrefix(trimmed, "Security:"); ok {
			cur.Security = strings.TrimSpace(v)
		} else if mm := macSignal.FindStringSubmatch(trimmed); mm != nil {
			cur.Signal = dBmToPercent(atoiDefault(mm[1], -100))
		}
	}
	flush()
	return dedupe(aps)
}

func (m *Mac) Connect(ctx context.Context, c Credentials) error {
	dev, err := m.device(ctx)
	if err != nil {
		return err
	}
	args := []string{"-setairportnetwork", dev, c.SSID}
	switch c.Security {
	case Open, "":
	case PSK, SAE:
		args = append(args, c.Passphrase)
	case Enterprise:
		// Relies on an installed 802.1X configuration profile for this SSID.
	default:
		return fmt.Errorf("unknown security %q", c.Security)
	}
	out, err := m.run(ctx, "", "networksetup", args...)
	if err != nil {
		return err
	}
	// networksetup exits 0 even when it fails to join.
	if s := strings.TrimSpace(out); s != "" && (strings.Contains(s, "Could not") || strings.Contains(s, "Failed") || strings.Contains(s, "Error")) {
		return errors.New(s)
	}
	return nil
}
