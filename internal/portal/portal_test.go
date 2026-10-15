package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLoginFullFlow(t *testing.T) {
	online := false
	posts := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/portal", http.StatusFound) })
	mux.HandleFunc("/portal", func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() == "" {
			t.Error("missing user agent")
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		fmt.Fprint(w, `<form action="/login" method=post><input type=hidden name=csrf value=token><input name=username><input type=password name=password><button name=go value=yes>Log in</button></form>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("bad submission: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "abc" {
			t.Error("missing session cookie")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		for k, v := range map[string]string{"csrf": "token", "username": "alice", "password": "secret", "go": "yes"} {
			if r.Form.Get(k) != v {
				t.Errorf("%s = %q", k, r.Form.Get(k))
			}
		}
		online = true
		fmt.Fprint(w, `<title>Welcome</title>`)
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	if err := Login(context.Background(), s.URL+"/probe", Creds{TrustedHosts: []string{testHost(s.URL)}, Username: "alice", Password: "secret"}, func(context.Context) bool { return online }); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("posts = %d", posts)
	}
}

func TestRedirectHops(t *testing.T) {
	redirects := []string{
		`<meta http-equiv="refresh" content="0; url=login">`,
		`<script>window.location = "login";</script>`,
		`<script>window.location.href = 'login';</script>`,
		`<script>location.href='login';</script>`,
		`<script>location.replace("login");</script>`,
		`<script>location.assign('login');</script>`,
		`<script>top.location = 'login';</script>`,
		`<script>document.location = 'login';</script>`,
	}
	for _, redirect := range redirects {
		t.Run(redirect, func(t *testing.T) {
			online := false
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/start":
					fmt.Fprint(w, redirect)
				case r.Method == "POST" && r.URL.Path == "/login":
					online = true
				case r.URL.Path == "/login":
					fmt.Fprint(w, `<form><button name=accept value=yes>Accept terms</button></form>`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer s.Close()
			if err := Login(context.Background(), s.URL+"/start", Creds{TrustedHosts: []string{testHost(s.URL)}}, func(context.Context) bool { return online }); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoginContinuation(t *testing.T) {
	stage := 0
	checks := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<form action=/auth><input name=user><input type=password name=p></form>`)
		case "/auth":
			stage = 1
			fmt.Fprint(w, `<form action=/continue><input type=hidden name=token value=ok><input type=checkbox name=accept_terms><button name=continue value=yes>Continue</button></form>`)
		case "/continue":
			r.ParseForm()
			if r.Form.Get("token") != "ok" || r.Form.Get("accept_terms") != "on" || r.Form.Get("continue") != "yes" {
				t.Errorf("form: %v", r.Form)
			}
			stage = 2
		}
	}))
	defer s.Close()
	err := Login(context.Background(), s.URL, Creds{TrustedHosts: []string{testHost(s.URL)}, Username: "u", Password: "p"}, func(context.Context) bool { checks++; return stage == 2 })
	if err != nil || checks != 2 {
		t.Fatalf("err=%v checks=%d", err, checks)
	}
}

func TestDirectLogin(t *testing.T) {
	online := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, `<title>API login</title>`)
			return
		}
		r.ParseForm()
		for k, v := range map[string]string{"uid": "u", "pin": "p", "realm": "guest"} {
			if r.Form.Get(k) != v {
				t.Errorf("%s = %q", k, r.Form.Get(k))
			}
		}
		online = true
	}))
	defer s.Close()
	err := Login(context.Background(), "http://unused.invalid", Creds{LoginURL: s.URL, UserField: "uid", PassField: "pin", Username: "u", Password: "p", Extra: map[string]string{"realm": "guest"}}, func(context.Context) bool { return online })
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoginGETOverrides(t *testing.T) {
	online := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/done" {
			if r.Method != "GET" || r.URL.RawQuery != "existing=yes&uid=u&code=p&token=new&extra=ok" {
				t.Errorf("request: %s %s", r.Method, r.URL)
			}
			online = true
			return
		}
		fmt.Fprint(w, `<form action="/done?existing=yes" method=GET><input name=uid><input type=number name=code><input type=hidden name=token value=old></form>`)
	}))
	defer s.Close()
	err := Login(context.Background(), s.URL, Creds{TrustedHosts: []string{testHost(s.URL)}, Username: "u", Password: "p", UserField: "uid", PassField: "code", Extra: map[string]string{"token": "new", "extra": "ok"}}, func(context.Context) bool { return online })
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoginFailures(t *testing.T) {
	for _, tt := range []struct{ name, body, want string }{
		{"no form", `<title>Nothing</title>`, "no login form found at"},
		{"title hint", `<title>Invalid credentials &amp; retry</title><form><input type=password name=p></form>`, "Invalid credentials & retry"},
		{"hop limit", `<meta http-equiv=refresh content="0;url=/">`, "too many portal hops"},
		{"unsupported redirect", `<script>location='javascript:alert(1)'</script>`, "unsupported URL"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tt.body) }))
			defer s.Close()
			err := Login(context.Background(), s.URL, Creds{TrustedHosts: []string{testHost(s.URL)}}, func(context.Context) bool { return false })
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
}

func TestTLSAndLimits(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `<form><button>Continue</button></form>`) }))
	defer s.Close()
	if err := Login(context.Background(), s.URL, Creds{TrustedHosts: []string{testHost(s.URL)}, InsecureTLS: true}, func(context.Context) bool { return true }); err != nil {
		t.Fatal(err)
	}
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", bodyLimit+1)) }))
	defer large.Close()
	if err := Login(context.Background(), large.URL, Creds{TrustedHosts: []string{testHost(large.URL)}}, func(context.Context) bool { return false }); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("size limit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Login(ctx, large.URL, Creds{TrustedHosts: []string{testHost(large.URL)}}, func(context.Context) bool { return false }); err == nil {
		t.Fatal("expected cancellation")
	}
	if err := Login(context.Background(), large.URL, Creds{TrustedHosts: []string{testHost(large.URL)}}, nil); err == nil {
		t.Fatal("expected nil verifier error")
	}
}

func TestDirectDefaultFields(t *testing.T) {
	online := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			if r.Form.Get("username") != "u" || r.Form.Get("password") != "p" {
				t.Errorf("form: %v", r.Form)
			}
			online = true
		}
	}))
	defer s.Close()
	if err := Login(context.Background(), "", Creds{LoginURL: s.URL, Username: "u", Password: "p"}, func(context.Context) bool { return online }); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectLimit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer s.Close()
	err := Login(context.Background(), s.URL, Creds{TrustedHosts: []string{testHost(s.URL)}}, func(context.Context) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "more than 10 redirects") {
		t.Fatalf("redirect limit: %v", err)
	}
}

func testHost(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
}

func TestGETFailureDoesNotExposeCredentials(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		fmt.Fprint(w, `<form action="/auth" method="get"><input name="username"><input type="password" name="password"></form>`)
	}))
	defer s.Close()
	err := Login(context.Background(), s.URL, Creds{
		LoginURL: s.URL, Username: "private-test-user", Password: "private-test-password",
	}, func(context.Context) bool { return false })
	if err == nil {
		t.Fatal("expected a request failure")
	}
	for _, secret := range []string{"private-test-user", "private-test-password"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("credential exposed in propagated error: %v", err)
		}
	}
}
