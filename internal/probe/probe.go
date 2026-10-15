// Package probe decides whether the current link actually reaches the
// internet, is held behind a captive portal, or is too poor to use. It uses
// the same plain-HTTP endpoints phones and laptops use for this check.
package probe

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"
)

type State string

const (
	Online     State = "online"
	Captive    State = "captive"     // HTTP is intercepted (login page)
	NoInternet State = "no-internet" // nothing answers
)

type Result struct {
	State     State
	PortalURL string        // where the intercepted request was sent, when Captive
	RTT       time.Duration // round trip of the successful check
}

// Target is one connectivity-check endpoint.
type Target struct {
	URL    string
	Status int    // expected status code
	Body   string // substring the body must contain, if non-empty
}

// DefaultTargets are tried in order until one gives a conclusive answer.
var DefaultTargets = []Target{
	{URL: "http://connectivitycheck.gstatic.com/generate_204", Status: http.StatusNoContent},
	{URL: "http://captive.apple.com/hotspot-detect.html", Status: http.StatusOK, Body: "Success"},
	{URL: "http://www.msftconnecttest.com/connecttest.txt", Status: http.StatusOK, Body: "Microsoft Connect Test"},
}

type Prober struct {
	Targets []Target
	Client  *http.Client
}

// New returns a prober that never follows redirects and never reuses
// connections, so a network change is always seen fresh.
func New(timeout time.Duration) *Prober {
	return &Prober{
		Targets: DefaultTargets,
		Client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Check runs a single connectivity check.
func (p *Prober) Check(ctx context.Context) Result {
	for _, t := range p.Targets {
		if r, ok := p.one(ctx, t); ok {
			return r
		}
		if ctx.Err() != nil {
			break
		}
	}
	return Result{State: NoInternet}
}

// one returns ok=false when the endpoint gave no conclusive answer
// (network error, or a server-side error that says nothing about the link).
func (p *Prober) one(ctx context.Context, t Target) (Result, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return Result{}, false
	}
	req.Header.Set("Cache-Control", "no-cache")
	start := time.Now()
	resp, err := p.Client.Do(req)
	if err != nil {
		return Result{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	rtt := time.Since(start)

	switch {
	case resp.StatusCode == t.Status && (t.Body == "" || bytes.Contains(body, []byte(t.Body))):
		// net/http suppresses a 204 response body, so also reject headers
		// advertising content even when the transport hides the bytes.
		length := resp.Header.Get("Content-Length")
		if t.Status == http.StatusNoContent && (len(body) > 0 || (length != "" && length != "0") || resp.Header.Get("Transfer-Encoding") != "") {
			break // some portals answer 204-lookalikes with a page
		}
		return Result{State: Online, RTT: rtt}, true
	case resp.StatusCode >= 500 && resp.StatusCode != http.StatusNetworkAuthenticationRequired:
		return Result{}, false
	}
	portal := t.URL
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil {
			portal = req.URL.ResolveReference(u).String()
		}
	}
	return Result{State: Captive, PortalURL: portal, RTT: rtt}, true
}

// Quality runs n checks and reports the median RTT of the successful ones
// and how many failed. Used to confirm a suspected poor link.
func (p *Prober) Quality(ctx context.Context, n int) (median time.Duration, failures int) {
	var rtts []time.Duration
	for i := 0; i < n; i++ {
		r := p.Check(ctx)
		if r.State == Online {
			rtts = append(rtts, r.RTT)
		} else {
			failures++
		}
	}
	if len(rtts) == 0 {
		return 0, failures
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[len(rtts)/2], failures
}
