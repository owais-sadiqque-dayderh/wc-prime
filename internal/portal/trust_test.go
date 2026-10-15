package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLoginRequiresTrustWithoutRequests(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer s.Close()
	err := Login(context.Background(), s.URL, Creds{Username: "u", Password: "secret"}, func(context.Context) bool { return false })
	if err == nil || err.Error() != "portal: no trusted login host configured" {
		t.Fatalf("error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("made a request without configured trust")
	}
}

func TestLoginRejectsUntrustedForms(t *testing.T) {
	for _, method := range []string{"post", "get"} {
		t.Run(method, func(t *testing.T) {
			var requests atomic.Int32
			evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
			}))
			defer evil.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `<form action=%q method=%q><input name=username><input type=password name=password></form>`, evil.URL, method)
			}))
			defer s.Close()
			err := Login(context.Background(), "", Creds{LoginURL: s.URL, Username: "u", Password: "secret"}, func(context.Context) bool { return false })
			assertUntrusted(t, err, evil.URL)
			if requests.Load() != 0 {
				t.Fatal("untrusted server received a credential request")
			}
		})
	}
}

func TestLoginExplicitCrossOriginForm(t *testing.T) {
	var online atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("password") != "secret" {
			t.Errorf("missing credential: %v", r.Form)
		}
		online.Store(true)
	}))
	defer destination.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<form action=%q><input type=password name=password></form>`, destination.URL)
	}))
	defer s.Close()
	err := Login(context.Background(), "", Creds{LoginURL: s.URL, TrustedHosts: []string{testHost(destination.URL)}, Password: "secret"}, func(context.Context) bool { return online.Load() })
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoginRejectsUntrustedHops(t *testing.T) {
	for _, markup := range []string{
		`<meta http-equiv=refresh content="0;url=%s">`,
		`<script>location.assign('%s')</script>`,
	} {
		t.Run(markup, func(t *testing.T) {
			var requests atomic.Int32
			evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
			defer evil.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, markup, evil.URL) }))
			defer s.Close()
			err := Login(context.Background(), s.URL, Creds{TrustedHosts: []string{testHost(s.URL)}}, func(context.Context) bool { return false })
			assertUntrusted(t, err, evil.URL)
			if requests.Load() != 0 {
				t.Fatal("untrusted hop was requested")
			}
		})
	}
}

func TestCredentialRedirectTrust(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, direct := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/direct=%v", status, direct), func(t *testing.T) {
				var requests atomic.Int32
				evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
				defer evil.Close()
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						http.Redirect(w, r, evil.URL, status)
						return
					}
					if !direct {
						fmt.Fprint(w, `<form><input type=password name=password></form>`)
					}
				}))
				defer s.Close()
				err := Login(context.Background(), "", Creds{LoginURL: s.URL, Password: "secret"}, func(context.Context) bool { return false })
				assertUntrusted(t, err, evil.URL)
				if requests.Load() != 0 {
					t.Fatal("credential redirect reached untrusted server")
				}
			})
		}
	}
}

func TestLoginRejectsHTTPSDowngrades(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprintf("redirect=%v", redirect), func(t *testing.T) {
			var requests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
			defer destination.Close()
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if redirect && r.Method == http.MethodPost {
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
					return
				}
				action := destination.URL
				if redirect {
					action = "/login"
				}
				fmt.Fprintf(w, `<form action=%q><input type=password name=password></form>`, action)
			}))
			defer s.Close()
			err := Login(context.Background(), "", Creds{LoginURL: s.URL, TrustedHosts: []string{testHost(destination.URL)}, Password: "secret", InsecureTLS: true}, func(context.Context) bool { return false })
			if err == nil || !strings.Contains(err.Error(), "downgrade") {
				t.Fatalf("expected downgrade error, got %v", err)
			}
			if requests.Load() != 0 {
				t.Fatal("sent request over downgraded connection")
			}
		})
	}
}

func TestContinuationRejectsUntrustedForm(t *testing.T) {
	var requests atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer evil.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprintf(w, `<form action=%q><input name=username><button>Continue</button></form>`, evil.URL)
			return
		}
		fmt.Fprint(w, `<form><input type=password name=password></form>`)
	}))
	defer s.Close()
	err := Login(context.Background(), "", Creds{LoginURL: s.URL, Username: "u", Password: "secret"}, func(context.Context) bool { return false })
	assertUntrusted(t, err, evil.URL)
	if requests.Load() != 0 {
		t.Fatal("continuation sent credentials to an untrusted server")
	}
}

func TestDiscoveryRedirectMayCrossOrigins(t *testing.T) {
	var online atomic.Bool
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			online.Store(true)
			return
		}
		fmt.Fprint(w, `<form><input type=password name=p></form>`)
	}))
	defer portal.Close()
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, portal.URL, http.StatusFound) }))
	defer probe.Close()
	err := Login(context.Background(), probe.URL, Creds{TrustedHosts: []string{testHost(portal.URL)}, Password: "secret"}, func(context.Context) bool { return online.Load() })
	if err != nil {
		t.Fatal(err)
	}
}

func TestTrustedHostMatching(t *testing.T) {
	for _, tt := range []struct {
		entry, target string
		allowed       bool
	}{
		{"LOGIN.Campus.edu", "http://login.campus.EDU:8080", true},
		{"login.campus.edu", "https://evil.login.campus.edu", false},
		{"login.campus.edu:80", "http://login.campus.edu", true},
		{"login.campus.edu:443", "https://login.campus.edu", true},
		{"login.campus.edu:443", "https://login.campus.edu:8443", false},
		{"*.campus.edu", "https://login.campus.edu", true},
		{"*.campus.edu", "http://nested.login.CAMPUS.edu:8080", true},
		{"*.campus.edu", "https://campus.edu", false},
		{"*.campus.edu", "https://evilcampus.edu", false},
		{"*.campus.edu", "https://campus.edu.evil.example", false},
		{"HTTPS://LOGIN.CAMPUS.EDU", "https://login.campus.edu:443", true},
		{"https://login.campus.edu:443", "https://login.campus.edu", true},
		{"https://login.campus.edu", "http://login.campus.edu", false},
		{"https://login.campus.edu", "https://login.campus.edu:8443", false},
		{"http://login.campus.edu:80", "http://login.campus.edu", true},
		{"http://login.campus.edu", "https://login.campus.edu", false},
		{"https://login.campus.edu:8443", "https://login.campus.edu:8443/path", true},
		{"[::1]:443", "https://[::1]", true},
	} {
		t.Run(tt.entry+"/"+tt.target, func(t *testing.T) {
			policy, err := newTrustPolicy(Creds{TrustedHosts: []string{tt.entry}})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(tt.target)
			err = policy.check(u, nil, "login form posts to")
			if (err == nil) != tt.allowed {
				t.Fatalf("allowed=%v, error=%v", tt.allowed, err)
			}
		})
	}
}

func TestLoginURLPinsOrigin(t *testing.T) {
	policy, err := newTrustPolicy(Creds{LoginURL: "https://LOGIN.CAMPUS.edu/path?query=yes"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"http://login.campus.edu", "https://login.campus.edu:8443"} {
		u, _ := url.Parse(target)
		if err := policy.check(u, nil, "login form posts to"); err == nil {
			t.Fatalf("implicitly trusted %s", target)
		}
	}
	u, _ := url.Parse("https://login.campus.edu:443/other")
	if err := policy.check(u, nil, "login form posts to"); err != nil {
		t.Fatal(err)
	}
}

func TestRejectInvalidTrustedHosts(t *testing.T) {
	for _, entry := range []string{"", "https://", "ftp://login.example", "login.example/path", "https://user@login.example", "https://login.example/path", "https://*.example", "*example", "example:", "example:65536"} {
		if _, err := newTrustPolicy(Creds{TrustedHosts: []string{entry}}); err == nil {
			t.Errorf("accepted invalid entry %q", entry)
		}
	}
}

func assertUntrusted(t *testing.T, err error, target string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "not a trusted portal host") || !strings.Contains(err.Error(), testHost(target)) {
		t.Fatalf("expected untrusted host %s, got %v", target, err)
	}
}
