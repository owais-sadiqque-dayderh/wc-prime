// Package wifi drives the operating system's Wi-Fi stack through the tools
// each platform already ships (nmcli, netsh, networksetup, cmd wifi), so the
// service needs no drivers, daemons or third-party libraries of its own.
package wifi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// Security is the link-layer protection of a network.
type Security string

const (
	Open       Security = "open"
	PSK        Security = "psk"        // WPA/WPA2-Personal passphrase
	SAE        Security = "sae"        // WPA3-Personal passphrase
	Enterprise Security = "enterprise" // WPA2/3-Enterprise (802.1X)
)

// Status describes the current Wi-Fi association.
type Status struct {
	Enabled   bool
	Connected bool
	SSID      string // empty when unknown (some OSes redact it)
	Signal    int    // 0-100, or -1 when unknown
}

// AP is a network seen in a scan.
type AP struct {
	SSID     string
	Signal   int    // 0-100
	Security string // raw OS description, informational only
}

// Credentials is everything needed to associate with a network.
type Credentials struct {
	SSID       string
	Security   Security
	Passphrase string
	Hidden     bool

	// 802.1X
	EAP               string // peap (default) or ttls
	Phase2            string // mschapv2 (default), pap, gtc
	Identity          string
	Password          string
	AnonymousIdentity string
	CACert            string // path to CA certificate, optional
	DomainMatch       string // required Enterprise server certificate name/domain suffix; semicolon-separated names allowed
}

// ErrNoServerValidation means Enterprise credentials cannot verify the RADIUS server.
var ErrNoServerValidation = errors.New("enterprise network needs the RADIUS server domain (server certificate name) so the server can be verified")

func (c Credentials) validateEnterprise() error {
	if c.Security != Enterprise {
		return nil
	}
	for _, name := range strings.Split(c.DomainMatch, ";") {
		if strings.TrimSpace(name) != "" {
			return nil
		}
	}
	return fmt.Errorf("network %q: %w", c.SSID, ErrNoServerValidation)
}

// Backend is implemented once per platform.
type Backend interface {
	Name() string
	Status(ctx context.Context) (Status, error)
	Enable(ctx context.Context) error
	Scan(ctx context.Context) ([]AP, error)
	Connect(ctx context.Context, c Credentials) error
}

// ErrUnsupported is returned for operations a platform cannot perform.
var ErrUnsupported = errors.New("not supported on this platform")

// Runner executes a command, feeding stdin, and returns stdout.
type Runner func(ctx context.Context, stdin, name string, args ...string) (string, error)

// Exec is the real Runner.
func Exec(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return out.String(), fmt.Errorf("%s %s: %v: %s", name, firstArg(args), err, msg)
	}
	return out.String(), nil
}

func firstArg(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

// New picks the backend for the running platform.
func New() (Backend, error) {
	switch runtime.GOOS {
	case "windows":
		return NewNetsh(Exec), nil
	case "darwin":
		return NewMac(Exec), nil
	case "android":
		return NewAndroid(Exec), nil
	case "linux":
		if isAndroid() {
			return NewAndroid(Exec), nil
		}
		if _, err := exec.LookPath("nmcli"); err == nil {
			return NewNM(Exec), nil
		}
		return nil, errors.New("NetworkManager (nmcli) is required on Linux")
	}
	return nil, fmt.Errorf("unsupported platform %s", runtime.GOOS)
}

// isAndroid detects a linux/* binary running on Android (e.g. under Termux).
func isAndroid() bool {
	_, err := os.Stat("/system/build.prop")
	return err == nil
}

// dedupe keeps the strongest entry per SSID and drops hidden (empty) SSIDs,
// strongest first.
func dedupe(aps []AP) []AP {
	best := map[string]AP{}
	for _, a := range aps {
		if a.SSID == "" {
			continue
		}
		if b, ok := best[a.SSID]; !ok || a.Signal > b.Signal {
			best[a.SSID] = a
		}
	}
	out := make([]AP, 0, len(best))
	for _, a := range best {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Signal != out[j].Signal {
			return out[i].Signal > out[j].Signal
		}
		return out[i].SSID < out[j].SSID
	})
	return out
}

// dBmToPercent maps RSSI to the 0-100 scale used everywhere else.
func dBmToPercent(dbm int) int {
	p := 2 * (dbm + 100)
	return max(0, min(100, p))
}
