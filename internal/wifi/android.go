package wifi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Android drives Wi-Fi through the `cmd wifi` shell service (Android 11+).
// It needs the shell or root user: run it from `adb shell`, or from Termux
// via `su`. Regular app processes are not allowed to control Wi-Fi.
type Android struct{ run Runner }

func NewAndroid(r Runner) *Android { return &Android{run: r} }

func (a *Android) Name() string { return "android/cmd-wifi" }

var (
	androidConnected = regexp.MustCompile(`Wifi is connected to "(.*)"`)
	androidRSSI      = regexp.MustCompile(`RSSI: (-?\d+)`)
)

func (a *Android) Status(ctx context.Context) (Status, error) {
	out, err := a.run(ctx, "", "cmd", "wifi", "status")
	if err != nil {
		return Status{Signal: -1}, err
	}
	return parseAndroidStatus(out), nil
}

func parseAndroidStatus(out string) Status {
	st := Status{Signal: -1, Enabled: strings.Contains(out, "Wifi is enabled")}
	if m := androidConnected.FindStringSubmatch(out); m != nil {
		st.Connected, st.SSID = true, m[1]
		if r := androidRSSI.FindStringSubmatch(out); r != nil {
			st.Signal = dBmToPercent(atoiDefault(r[1], -100))
		}
	}
	return st
}

func (a *Android) Enable(ctx context.Context) error {
	_, err := a.run(ctx, "", "cmd", "wifi", "set-wifi-enabled", "enabled")
	return err
}

func (a *Android) Scan(ctx context.Context) ([]AP, error) {
	_, _ = a.run(ctx, "", "cmd", "wifi", "start-scan")
	out, err := a.run(ctx, "", "cmd", "wifi", "list-scan-results")
	if err != nil {
		return nil, err
	}
	return parseAndroidScan(out), nil
}

var leadingInt = regexp.MustCompile(`^-?\d+`)

// parseAndroidScan reads rows of "BSSID Frequency RSSI Age SSID Flags".
func parseAndroidScan(out string) []AP {
	var aps []AP
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || strings.EqualFold(f[0], "BSSID") || strings.Count(f[0], ":") != 5 {
			continue
		}
		rssi := leadingInt.FindString(f[2])
		rest := f[4:]
		flags := ""
		if last := rest[len(rest)-1]; strings.HasPrefix(last, "[") {
			flags, rest = last, rest[:len(rest)-1]
		}
		aps = append(aps, AP{SSID: strings.Join(rest, " "), Signal: dBmToPercent(atoiDefault(rssi, -100)), Security: flags})
	}
	return dedupe(aps)
}

func (a *Android) Connect(ctx context.Context, c Credentials) error {
	args := []string{"wifi", "connect-network", c.SSID}
	switch c.Security {
	case Open, "":
		args = append(args, "open")
	case PSK:
		args = append(args, "wpa2", c.Passphrase)
	case SAE:
		args = append(args, "wpa3", c.Passphrase)
	case Enterprise:
		return fmt.Errorf("WPA-Enterprise: %w (add it once in Android settings)", ErrUnsupported)
	default:
		return fmt.Errorf("unknown security %q", c.Security)
	}
	if c.Hidden {
		args = append(args, "-h")
	}
	out, err := a.run(ctx, "", "cmd", args...)
	if err != nil {
		return err
	}
	if strings.Contains(strings.ToLower(out), "fail") {
		return errors.New(strings.TrimSpace(out))
	}
	return nil
}
