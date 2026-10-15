package vault

import "github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"

// Network is one saved network. Its position in the vault list is its
// priority: index 0 is the most preferred.
type Network struct {
	ID         string        `json:"id"`
	SSID       string        `json:"ssid"`
	Security   wifi.Security `json:"security"` // open | psk | sae | enterprise
	Passphrase string        `json:"passphrase,omitempty"`
	Hidden     bool          `json:"hidden,omitempty"`
	Enabled    bool          `json:"enabled"` // false = never auto-join

	// Login credentials: the 802.1X identity for enterprise networks and/or
	// the captive-portal username.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// 802.1X options (enterprise only).
	EAP               string `json:"eap,omitempty"`    // peap | ttls
	Phase2            string `json:"phase2,omitempty"` // mschapv2 | pap | gtc
	AnonymousIdentity string `json:"anonymousIdentity,omitempty"`
	CACert            string `json:"caCert,omitempty"`
	DomainMatch       string `json:"domainMatch,omitempty"`

	// Captive portal.
	Portal      bool              `json:"portal,omitempty"`      // submit Username/Password to a login page
	PortalURL   string            `json:"portalURL,omitempty"`   // optional fixed login URL (its host is trusted)
	PortalHosts []string          `json:"portalHosts,omitempty"` // hosts allowed to receive the login
	UserField   string            `json:"userField,omitempty"`   // optional form field name override
	PassField   string            `json:"passField,omitempty"`   // optional form field name override
	Extra       map[string]string `json:"extra,omitempty"`       // extra form fields to send
	InsecureTLS bool              `json:"insecureTLS,omitempty"` // accept self-signed portal certs
}

// Credentials converts a saved network into what the Wi-Fi backend needs.
func (n Network) Credentials() wifi.Credentials {
	return wifi.Credentials{
		SSID: n.SSID, Security: n.Security, Passphrase: n.Passphrase, Hidden: n.Hidden,
		EAP: n.EAP, Phase2: n.Phase2, Identity: n.Username, Password: n.Password,
		AnonymousIdentity: n.AnonymousIdentity, CACert: n.CACert, DomainMatch: n.DomainMatch,
	}
}

// Public is a Network with secrets removed, safe to show in the UI.
type Public struct {
	Network
	HasPassphrase bool `json:"hasPassphrase"`
	HasPassword   bool `json:"hasPassword"`
}

func (n Network) Public() Public {
	p := Public{Network: n, HasPassphrase: n.Passphrase != "", HasPassword: n.Password != ""}
	p.Passphrase, p.Password = "", ""
	return p
}
