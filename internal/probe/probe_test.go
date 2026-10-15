package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	for _, tt := range []struct {
		name           string
		code           int
		body, location string
		want           State
		portal         string
	}{
		{"204", 204, "", "", Online, ""},
		{"redirect", 302, "", "/login?next=wifi", Captive, "/login?next=wifi"},
		{"HTML", 200, "<html>Sign in</html>", "", Captive, "/generate_204"},
		{"authentication required", 511, "Login required", "", Captive, "/generate_204"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Cache-Control") != "no-cache" {
					t.Error("missing no-cache")
				}
				if tt.location != "" {
					w.Header().Set("Location", tt.location)
				}
				w.WriteHeader(tt.code)
				fmt.Fprint(w, tt.body)
			}))
			defer s.Close()
			p := New(time.Second)
			p.Targets = []Target{{URL: s.URL + "/generate_204", Status: 204}}
			got := p.Check(context.Background())
			if got.State != tt.want {
				t.Fatalf("got %+v", got)
			}
			if tt.portal != "" && got.PortalURL != s.URL+tt.portal {
				t.Errorf("portal=%q", got.PortalURL)
			}
		})
	}
}

func Test204WithBodyIsNotOnline(t *testing.T) {
	// net/http servers suppress bodies for 204. Hijack to model a broken portal
	// that advertises and sends a body despite that status.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 204 No Content\r\nContent-Length: 18\r\nConnection: close\r\n\r\n<html>login</html>")
		rw.Flush()
	}))
	defer s.Close()
	p := New(time.Second)
	p.Targets = []Target{{URL: s.URL, Status: 204}}
	if got := p.Check(context.Background()); got.State == Online {
		t.Fatalf("204 with advertised body accepted: %+v", got)
	}
}

func TestCheckFallback(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer second.Close()
	p := New(time.Second)
	p.Targets = []Target{{first.URL, 204, ""}, {second.URL, 204, ""}}
	if got := p.Check(context.Background()); got.State != Online {
		t.Fatalf("fallback=%+v", got)
	}
}

func TestCheckUnreachable(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.Close()
	p := New(time.Second)
	p.Targets = []Target{{s.URL, 204, ""}}
	if got := p.Check(context.Background()); got.State != NoInternet {
		t.Fatalf("got %+v", got)
	}
}

func TestQuality(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			time.Sleep(10 * time.Millisecond)
		case 2:
			w.WriteHeader(511)
			return
		case 3:
			time.Sleep(80 * time.Millisecond)
		case 4:
			time.Sleep(160 * time.Millisecond)
		}
		w.WriteHeader(204)
	}))
	defer s.Close()
	p := New(time.Second)
	p.Targets = []Target{{s.URL, 204, ""}}
	median, failures := p.Quality(context.Background(), 4)
	if failures != 1 || median < 70*time.Millisecond || median >= 150*time.Millisecond {
		t.Fatalf("median=%v failures=%d", median, failures)
	}
	p.Targets = nil
	if m, f := p.Quality(context.Background(), 3); m != 0 || f != 3 {
		t.Fatalf("all failures: median=%v failures=%d", m, f)
	}
	if m, f := p.Quality(context.Background(), 0); m != 0 || f != 0 {
		t.Fatalf("zero checks: median=%v failures=%d", m, f)
	}
}
