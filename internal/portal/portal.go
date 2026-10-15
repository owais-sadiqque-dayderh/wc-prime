// Package portal logs in to HTML captive portals without a browser or script engine.
package portal

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Creds contains portal credentials and optional form overrides.
type Creds struct {
	Username, Password string
	LoginURL           string            // Optional fixed URL, with direct POST fallback.
	TrustedHosts       []string          // Hosts allowed to receive credentials and to be navigated to.
	UserField          string            // Optional username field override.
	PassField          string            // Optional password field override.
	Extra              map[string]string // Extra fields to set or override.
	InsecureTLS        bool              // Accept self-signed portal certificates.
}

const bodyLimit = 512 << 10
const userAgent = "Mozilla/5.0 (compatible; wc-prime captive portal client)"

var jsRedirectRE = regexp.MustCompile(`(?i)(?:(?:(?:window|top|document)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*["']([^"']+)["']|(?:(?:window|top|document)\s*\.\s*)?location\s*\.\s*(?:replace|assign)\s*\(\s*["']([^"']+)["'])`)

// Login drives a captive portal starting at startURL (or c.LoginURL when set)
// and returns nil once verify reports that the device is online.
func Login(ctx context.Context, startURL string, c Creds, verify func(context.Context) bool) error {
	trusted, err := newTrustPolicy(c)
	if err != nil {
		return err
	}
	if verify == nil {
		return fmt.Errorf("portal: connectivity verifier is required")
	}
	if c.LoginURL != "" {
		startURL = c.LoginURL
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: c.InsecureTLS} // Explicit opt-in for local portal certificates.
	defer transport.CloseIdleConnections()
	client := &http.Client{Jar: jar, Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 10 {
			return fmt.Errorf("portal: more than 10 redirects")
		}
		if len(via) > 0 && via[0].Context().Value(credentialRequestKey{}) == true {
			return trusted.check(req.URL, via[len(via)-1].URL, "login redirect goes to")
		}
		return nil
	}}
	body, current, err := request(ctx, client, http.MethodGet, startURL, "")
	if err != nil {
		return err
	}
	var response string
	for hop := 0; hop < 5; hop++ {
		p := parsePage(body)
		if f, ok := chooseForm(p, c); ok {
			response, current, err = submit(ctx, client, current, f, c, trusted)
			break
		}
		if c.LoginURL != "" {
			user, pass := c.UserField, c.PassField
			if user == "" {
				user = "username"
			}
			if pass == "" {
				pass = "password"
			}
			f := form{action: c.LoginURL, fields: []field{{name: user, kind: "text"}, {name: pass, kind: "password"}}}
			direct := c
			direct.UserField = user
			direct.PassField = pass
			response, current, err = submit(ctx, client, current, f, direct, trusted)
			break
		}
		target := p.refresh
		if target == "" {
			if m := jsRedirectRE.FindStringSubmatch(body); len(m) > 0 {
				target = m[1]
				if target == "" {
					target = m[2]
				}
			}
		}
		if target == "" {
			return fmt.Errorf("portal: no login form found at %s", current)
		}
		if hop == 4 {
			return fmt.Errorf("portal: too many portal hops at %s", current)
		}
		next, e := resolve(current, target)
		if e != nil {
			return e
		}
		u, _ := url.Parse(next)
		previous, _ := url.Parse(current)
		if e := trusted.check(u, previous, "portal hop goes to"); e != nil {
			return e
		}
		body, current, err = request(ctx, client, http.MethodGet, next, "")
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if verify(ctx) {
		return nil
	}
	p := parsePage(response)
	// Some portals require one final acceptance after checking credentials.
	for _, f := range p.forms {
		if f.password(c) {
			continue
		}
		response, current, err = submit(ctx, client, current, f, c, trusted)
		if err != nil {
			return err
		}
		if verify(ctx) {
			return nil
		}
		p = parsePage(response)
		break
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	hint := ""
	if p.title != "" {
		hint = "; page title: " + p.title
	}
	return fmt.Errorf("portal did not accept the login (still captive)%s", hint)
}

func resolve(base, target string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("portal: invalid page URL: %w", err)
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("portal: invalid target URL: %w", err)
	}
	u = b.ResolveReference(u)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("portal: unsupported URL %q", u.String())
	}
	return u.String(), nil
}
func submit(ctx context.Context, client *http.Client, current string, f form, c Creds, trusted trustPolicy) (string, string, error) {
	target, err := resolve(current, f.action)
	if err != nil {
		return "", "", err
	}
	u, _ := url.Parse(target)
	previous, _ := url.Parse(current)
	if err := trusted.check(u, previous, "login form posts to"); err != nil {
		return "", "", err
	}
	method := http.MethodPost
	data := encode(fill(f, c))
	if strings.EqualFold(f.method, "get") {
		method = http.MethodGet
		u, _ := url.Parse(target)
		if u.RawQuery != "" && data != "" {
			u.RawQuery += "&" + data
		} else if data != "" {
			u.RawQuery = data
		}
		target = u.String()
		data = ""
	}
	return request(context.WithValue(ctx, credentialRequestKey{}, true), client, method, target, data)
}
func request(ctx context.Context, client *http.Client, method, target, data string) (string, string, error) {
	target, err := resolve(target, "")
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(data))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", userAgent)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		// net/http includes the complete request URL in url.Error. A portal
		// using a GET form puts credentials in that URL, and this error is
		// later written to the service log and returned through the events API.
		// Keep the underlying failure (including redirect-policy errors),
		// without propagating the credential-bearing URL.
		if requestErr, ok := err.(*url.Error); ok {
			err = requestErr.Err
		}
		return "", "", fmt.Errorf("portal: %s: %w", method, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit+1))
	if err != nil {
		return "", "", fmt.Errorf("portal: read response: %w", err)
	}
	if len(b) > bodyLimit {
		return "", "", fmt.Errorf("portal: response exceeds %d bytes", bodyLimit)
	}
	return string(b), resp.Request.URL.String(), nil
}
