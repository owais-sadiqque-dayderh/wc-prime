package portal

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// credentialRequestKey marks the entire redirect chain, including redirects
// which convert a credential POST to a GET.
type credentialRequestKey struct{}

type trustedHost struct {
	host, port, scheme string
	wildcard           bool
}

type trustPolicy []trustedHost

func newTrustPolicy(c Creds) (trustPolicy, error) {
	if len(c.TrustedHosts) == 0 && c.LoginURL == "" {
		return nil, fmt.Errorf("portal: no trusted login host configured")
	}
	var trusted trustPolicy
	for _, entry := range c.TrustedHosts {
		h, err := parseTrustedHost(entry)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, h)
	}
	if c.LoginURL != "" {
		target, err := resolve(c.LoginURL, "")
		if err != nil {
			return nil, err
		}
		u, _ := url.Parse(target)
		h, err := parseTrustedHost(u.Scheme + "://" + u.Host)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, h)
	}
	return trusted, nil
}

func parseTrustedHost(entry string) (trustedHost, error) {
	invalid := func() (trustedHost, error) {
		return trustedHost{}, fmt.Errorf("portal: invalid trusted portal host %q (use a hostname, host:port, *.domain, or HTTP(S) origin)", entry)
	}
	entry = strings.ToLower(strings.TrimSpace(entry))
	origin := strings.Contains(entry, "://")
	raw := entry
	if !origin {
		raw = "//" + entry
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && (!origin || u.Path != "/")) {
		return invalid()
	}
	h := trustedHost{host: u.Hostname(), port: u.Port()}
	if strings.HasSuffix(u.Host, ":") {
		return invalid()
	}
	if h.port != "" {
		port, err := strconv.Atoi(h.port)
		if err != nil || port < 1 || port > 65535 {
			return invalid()
		}
		h.port = strconv.Itoa(port)
	}
	if origin {
		if u.Scheme != "http" && u.Scheme != "https" {
			return invalid()
		}
		h.scheme = u.Scheme
		if h.port == "" {
			h.port = defaultPort(h.scheme)
		}
	}
	if strings.HasPrefix(h.host, "*.") && !origin && h.port == "" {
		h.host = strings.TrimPrefix(h.host, "*.")
		h.wildcard = true
	}
	if strings.ContainsAny(h.host, "* /\\") || h.host == "" {
		return invalid()
	}
	return h, nil
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// Bare hostnames (including wildcards) permit any port and either HTTP scheme.
// host:port entries constrain the effective port; origins also pin the scheme.
func (trusted trustPolicy) check(target, previous *url.URL, action string) error {
	if target.Scheme != "http" && target.Scheme != "https" || target.Hostname() == "" || target.User != nil {
		return fmt.Errorf("portal: unsupported login URL for host %q", target.Host)
	}
	if previous != nil && previous.Scheme == "https" && target.Scheme != "https" {
		return fmt.Errorf("portal: %s %q would downgrade HTTPS to HTTP", action, target.Host)
	}
	host := strings.ToLower(target.Hostname())
	port := target.Port()
	if port == "" {
		port = defaultPort(target.Scheme)
	} else if n, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(n)
	}
	pinnedHTTPS := false
	for _, h := range trusted {
		matches := host == h.host
		if h.wildcard {
			matches = strings.HasSuffix(host, "."+h.host)
		}
		if !matches {
			continue
		}
		if h.scheme == "https" {
			pinnedHTTPS = true
		}
		if (h.port == "" || h.port == port) && (h.scheme == "" || h.scheme == target.Scheme) {
			return nil
		}
	}
	if pinnedHTTPS && target.Scheme == "http" {
		return fmt.Errorf("portal: %s %q would downgrade a trusted HTTPS origin to HTTP", action, target.Host)
	}
	return fmt.Errorf("portal: %s %q which is not a trusted portal host (add it in the network's portal settings)", action, target.Host)
}

// ValidateTrustedHost reports whether entry is a usable TrustedHosts value,
// so it can be rejected when saved rather than at login time.
func ValidateTrustedHost(entry string) error {
	_, err := parseTrustedHost(entry)
	return err
}
