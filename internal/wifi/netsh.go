package wifi

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Netsh drives Windows WLAN AutoConfig through netsh, plus a few wlanapi.dll
// calls (scan trigger, 802.1X user credentials) that netsh cannot do.
//
// Output is parsed by structure rather than by English labels so it also
// works on localised Windows installs.
type Netsh struct{ run Runner }

func NewNetsh(r Runner) *Netsh { return &Netsh{run: r} }

func (w *Netsh) Name() string { return "windows/netsh" }

var (
	kvLine  = regexp.MustCompile(`^\s*([^:]+?)\s*:\s?(.*)$`)
	pctOnly = regexp.MustCompile(`^(\d+)%$`)
	ssidHdr = regexp.MustCompile(`^SSID \d+\s*:\s?(.*)$`)
)

func (w *Netsh) Status(ctx context.Context) (Status, error) {
	out, err := w.run(ctx, "", "netsh", "wlan", "show", "interfaces")
	if err != nil {
		return Status{Signal: -1}, err
	}
	return parseNetshInterfaces(out), nil
}

func parseNetshInterfaces(out string) Status {
	st := Status{Signal: -1}
	for _, line := range strings.Split(out, "\n") {
		m := kvLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		switch {
		case key == "Name" || key == "GUID":
			st.Enabled = true // an interface exists
		case key == "SSID": // only present while associated
			st.SSID, st.Connected = val, val != ""
		case pctOnly.MatchString(val):
			st.Signal = atoiDefault(strings.TrimSuffix(val, "%"), -1)
		}
	}
	return st
}

func (w *Netsh) Enable(ctx context.Context) error {
	// Windows has no CLI radio toggle; re-enable the adapter (needs admin).
	_, err := w.run(ctx, "", "netsh", "interface", "set", "interface", "name=Wi-Fi", "admin=enabled")
	return err
}

func (w *Netsh) Scan(ctx context.Context) ([]AP, error) {
	if wlanScan() == nil {
		select { // the driver needs a moment to refresh its BSS list
		case <-time.After(4 * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	out, err := w.run(ctx, "", "netsh", "wlan", "show", "networks", "mode=bssid")
	if err != nil {
		return nil, err
	}
	return parseNetshNetworks(out), nil
}

func parseNetshNetworks(out string) []AP {
	var aps []AP
	var cur *AP
	authSeen := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := ssidHdr.FindStringSubmatch(line); m != nil {
			if cur != nil {
				aps = append(aps, *cur)
			}
			cur, authSeen = &AP{SSID: strings.TrimSpace(m[1])}, false
			continue
		}
		if cur == nil {
			continue
		}
		m := kvLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := strings.TrimSpace(m[2])
		if p := pctOnly.FindStringSubmatch(val); p != nil {
			cur.Signal = max(cur.Signal, atoiDefault(p[1], 0))
		} else if !authSeen && (strings.Contains(val, "WPA") || val == "Open" || strings.Contains(val, "OWE")) {
			cur.Security, authSeen = val, true
		}
	}
	if cur != nil {
		aps = append(aps, *cur)
	}
	return dedupe(aps)
}

func winProfile(ssid string) string { return "wcprime-" + ssid }

func (w *Netsh) Connect(ctx context.Context, c Credentials) error {
	name := winProfile(c.SSID)
	profile, err := winProfileXML(name, c)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "wcprime-*.xml")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	_, werr := f.WriteString(profile)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if _, err := w.run(ctx, "", "netsh", "wlan", "add", "profile", "filename="+path, "user=current"); err != nil {
		return err
	}
	_ = os.Remove(path) // drop the plaintext copy as soon as WLAN has it
	if c.Security == Enterprise {
		if err := wlanSetEapUserData(name, winEapUserXML(c)); err != nil {
			return fmt.Errorf("store 802.1X credentials: %w", err)
		}
	}
	_, err = w.run(ctx, "", "netsh", "wlan", "connect", "name="+name, "ssid="+c.SSID)
	return err
}

func xmlEsc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func winProfileXML(name string, c Credentials) (string, error) {
	if err := c.validateEnterprise(); err != nil {
		return "", err
	}
	var sec string
	switch c.Security {
	case Open, "":
		sec = `<authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption>`
	case PSK, SAE:
		auth := "WPA2PSK"
		if c.Security == SAE {
			auth = "WPA3SAE"
		}
		sec = `<authEncryption><authentication>` + auth + `</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>` +
			`<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>` + xmlEsc(c.Passphrase) + `</keyMaterial></sharedKey>`
	case Enterprise:
		if e := strings.ToLower(orDefault(c.EAP, "peap")); e != "peap" {
			return "", fmt.Errorf("EAP method %q: %w (Windows supports PEAP-MSCHAPv2 here)", e, ErrUnsupported)
		}
		trustedRoot := ""
		if c.CACert != "" {
			thumbprint, err := winCAThumbprint(c.CACert)
			if err != nil {
				return "", err
			}
			trustedRoot = `<TrustedRootCA>` + thumbprint + `</TrustedRootCA>`
		}
		sec = `<authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>` +
			`<OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><authMode>user</authMode><EAPConfig>` +
			`<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod>` +
			`<Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>` +
			`<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>` +
			`<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type>` +
			`<EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">` +
			`<ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>` + xmlEsc(c.DomainMatch) + `</ServerNames>` + trustedRoot + `</ServerValidation>` +
			`<FastReconnect>true</FastReconnect><InnerEapOptional>false</InnerEapOptional>` +
			`<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type>` +
			`<EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap>` +
			`<EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>false</RequireCryptoBinding>` +
			`<PeapExtensions><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>` +
			`<AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</AcceptServerName></PeapExtensions>` +
			`</EapType></Eap></Config></EapHostConfig></EAPConfig></OneX>`
	default:
		return "", fmt.Errorf("unknown security %q", c.Security)
	}
	hidden := "false"
	if c.Hidden {
		hidden = "true"
	}
	return `<?xml version="1.0"?>` +
		`<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">` +
		`<name>` + xmlEsc(name) + `</name>` +
		`<SSIDConfig><SSID><hex>` + strings.ToUpper(hex.EncodeToString([]byte(c.SSID))) + `</hex></SSID><nonBroadcast>` + hidden + `</nonBroadcast></SSIDConfig>` +
		`<connectionType>ESS</connectionType><connectionMode>manual</connectionMode>` +
		`<MSM><security>` + sec + `</security></MSM></WLANProfile>`, nil
}

func winCAThumbprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read RADIUS CA certificate: %w", err)
	}
	der := data
	for rest := data; ; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = block.Bytes
			break
		}
		rest = remaining
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return "", fmt.Errorf("parse RADIUS CA certificate: %w", err)
	}
	if len(certs) == 0 {
		return "", fmt.Errorf("parse RADIUS CA certificate: no certificates found")
	}
	// SHA-1 is the certificate identifier required by Windows, not a signature.
	thumbprint := sha1.Sum(certs[0].Raw)
	return fmt.Sprintf("% x", thumbprint), nil
}

// winEapUserXML is the PEAP-MSCHAPv2 user credential blob for
// WlanSetProfileEapXmlUserData.
func winEapUserXML(c Credentials) string {
	routing := c.AnonymousIdentity
	return `<?xml version="1.0"?>` +
		`<EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials" xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon" xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapMethodUserCredentials">` +
		`<EapMethod><eapCommon:Type>25</eapCommon:Type><eapCommon:AuthorId>0</eapCommon:AuthorId></EapMethod>` +
		`<Credentials xmlns:eapUser="http://www.microsoft.com/provisioning/EapUserPropertiesV1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1" xmlns:MsPeap="http://www.microsoft.com/provisioning/MsPeapUserPropertiesV1" xmlns:MsChapV2="http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1">` +
		`<baseEap:Eap><baseEap:Type>25</baseEap:Type><MsPeap:EapType><MsPeap:RoutingIdentity>` + xmlEsc(routing) + `</MsPeap:RoutingIdentity>` +
		`<baseEap:Eap><baseEap:Type>26</baseEap:Type><MsChapV2:EapType>` +
		`<MsChapV2:Username>` + xmlEsc(c.Identity) + `</MsChapV2:Username><MsChapV2:Password>` + xmlEsc(c.Password) + `</MsChapV2:Password><MsChapV2:LogonDomain></MsChapV2:LogonDomain>` +
		`</MsChapV2:EapType></baseEap:Eap></MsPeap:EapType></baseEap:Eap></Credentials></EapHostUserCredentials>`
}
