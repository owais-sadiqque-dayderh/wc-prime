package wifi

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// NM drives NetworkManager through nmcli (Linux desktops, Raspberry Pi OS,
// most distributions).
//
// Secrets are never written into NetworkManager: profiles are created with
// "not saved" secret flags and the secret is passed on stdin at activation.
type NM struct{ run Runner }

func NewNM(r Runner) *NM { return &NM{run: r} }

func (n *NM) Name() string { return "linux/nmcli" }

func (n *NM) Status(ctx context.Context) (Status, error) {
	st := Status{Signal: -1}
	out, err := n.run(ctx, "", "nmcli", "-t", "radio", "wifi")
	if err != nil {
		return st, err
	}
	st.Enabled = strings.TrimSpace(out) == "enabled"
	if !st.Enabled {
		return st, nil
	}
	out, err = n.run(ctx, "", "nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi", "list", "--rescan", "no")
	if err != nil {
		return st, err
	}
	for _, line := range strings.Split(out, "\n") {
		f := splitTerse(line)
		if len(f) >= 3 && f[0] == "yes" {
			st.Connected, st.SSID = true, f[1]
			st.Signal = atoiDefault(f[2], -1)
			break
		}
	}
	return st, nil
}

func (n *NM) Enable(ctx context.Context) error {
	_, err := n.run(ctx, "", "nmcli", "radio", "wifi", "on")
	return err
}

func (n *NM) Scan(ctx context.Context) ([]AP, error) {
	out, err := n.run(ctx, "", "nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes")
	if err != nil {
		// NM refuses rescans while one is running or just finished; use the cache.
		out, err = n.run(ctx, "", "nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "no")
		if err != nil {
			return nil, err
		}
	}
	return parseNMList(out), nil
}

func parseNMList(out string) []AP {
	var aps []AP
	for _, line := range strings.Split(out, "\n") {
		f := splitTerse(line)
		if len(f) < 3 {
			continue
		}
		aps = append(aps, AP{SSID: f[0], Signal: atoiDefault(f[1], 0), Security: f[2]})
	}
	return dedupe(aps)
}

// ProfileName is the NetworkManager connection we own for an SSID.
func nmProfile(ssid string) string { return "wcprime-" + ssid }

func (n *NM) Connect(ctx context.Context, c Credentials) error {
	name := nmProfile(c.SSID)
	args, secrets, err := nmAddArgs(name, c)
	if err != nil {
		return err
	}
	_, _ = n.run(ctx, "", "nmcli", "connection", "delete", "id", name)
	if _, err := n.run(ctx, "", "nmcli", args...); err != nil {
		return err
	}
	up := []string{"--wait", "45", "connection", "up", "id", name}
	if secrets != "" {
		up = append(up, "passwd-file", "/dev/stdin")
	}
	_, err = n.run(ctx, secrets, "nmcli", up...)
	return err
}

// nmAddArgs builds the "nmcli connection add" arguments and the
// passwd-file content that supplies secrets at activation time.
func nmAddArgs(name string, c Credentials) (args []string, secrets string, err error) {
	if err := c.validateEnterprise(); err != nil {
		return nil, "", err
	}
	args = []string{"connection", "add", "type", "wifi", "con-name", name, "ssid", c.SSID,
		"connection.autoconnect", "no"}
	if c.Hidden {
		args = append(args, "802-11-wireless.hidden", "yes")
	}
	switch c.Security {
	case Open, "":
	case PSK, SAE:
		mgmt := "wpa-psk"
		if c.Security == SAE {
			mgmt = "sae"
		}
		args = append(args, "wifi-sec.key-mgmt", mgmt, "wifi-sec.psk-flags", "2")
		secrets = "802-11-wireless-security.psk:" + c.Passphrase + "\n"
	case Enterprise:
		eap, phase2 := orDefault(c.EAP, "peap"), orDefault(c.Phase2, "mschapv2")
		args = append(args, "wifi-sec.key-mgmt", "wpa-eap",
			"802-1x.eap", eap, "802-1x.phase2-auth", phase2,
			"802-1x.identity", c.Identity, "802-1x.password-flags", "2")
		if c.AnonymousIdentity != "" {
			args = append(args, "802-1x.anonymous-identity", c.AnonymousIdentity)
		}
		if c.CACert != "" {
			args = append(args, "802-1x.ca-cert", c.CACert)
		} else {
			args = append(args, "802-1x.system-ca-certs", "yes")
		}
		args = append(args, "802-1x.domain-suffix-match", c.DomainMatch)
		secrets = "802-1x.password:" + c.Password + "\n"
	default:
		return nil, "", fmt.Errorf("unknown security %q", c.Security)
	}
	return args, secrets, nil
}

// splitTerse splits one line of `nmcli -t` output, honouring \: and \\ escapes.
func splitTerse(line string) []string {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return nil
	}
	var out []string
	var b strings.Builder
	esc := false
	for _, r := range line {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, b.String())
}

func atoiDefault(s string, d int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return d
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
