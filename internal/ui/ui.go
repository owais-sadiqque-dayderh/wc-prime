// Package ui serves the local management interface and its authenticated API.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/owais-sadiqque-dayderh/wc-prime/internal/events"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/keeper"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/vault"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"
)

// Store is the network persistence required by the management interface.
type Store interface {
	List() []vault.Network
	Get(id string) (vault.Network, bool)
	Save(n vault.Network) (vault.Network, error)
	Delete(id string) error
	Reorder(ids []string) error
}

// Service is the keeper functionality exposed through the interface.
type Service interface {
	Status() keeper.Snapshot
	Trigger()
	Scan(ctx context.Context) ([]wifi.AP, error)
	Events() []events.Event
}

//go:embed static/index.html static/icon.svg
var assets embed.FS

// New returns a handler restricted to loopback hosts, with token-protected APIs.
func New(store Store, svc Service, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, "static/index.html", "text/html; charset=utf-8")
	})
	mux.HandleFunc("GET /icon.svg", func(w http.ResponseWriter, r *http.Request) { serveAsset(w, "static/icon.svg", "image/svg+xml") })
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		recent := svc.Events()
		if recent == nil {
			recent = []events.Event{}
		}
		respond(w, http.StatusOK, struct {
			Status keeper.Snapshot `json:"status"`
			Events []events.Event  `json:"events"`
		}{svc.Status(), recent})
	})
	mux.HandleFunc("GET /api/networks", func(w http.ResponseWriter, r *http.Request) {
		out := []vault.Public{}
		for _, n := range store.List() {
			out = append(out, n.Public())
		}
		respond(w, http.StatusOK, out)
	})
	save := func(w http.ResponseWriter, r *http.Request) {
		var n vault.Network
		if !decode(w, r, &n) {
			return
		}
		if r.Method == http.MethodPut {
			n.ID = r.PathValue("id")
			if _, ok := store.Get(n.ID); !ok {
				failure(w, 404, "network not found")
				return
			}
		} else {
			n.ID = ""
		}
		saved, err := store.Save(n)
		if err != nil {
			failure(w, 400, err.Error())
			return
		}
		code := http.StatusOK
		if r.Method == http.MethodPost {
			code = http.StatusCreated
		}
		respond(w, code, saved.Public())
	}
	mux.HandleFunc("POST /api/networks", save)
	mux.HandleFunc("PUT /api/networks/{id}", save)
	mux.HandleFunc("DELETE /api/networks/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, ok := store.Get(id); !ok {
			failure(w, 404, "network not found")
			return
		}
		if err := store.Delete(id); err != nil {
			failure(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/networks/order", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IDs []string `json:"ids"`
		}
		if !decode(w, r, &body) {
			return
		}
		if err := store.Reorder(body.IDs); err != nil {
			failure(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/scan", func(w http.ResponseWriter, r *http.Request) {
		aps, err := svc.Scan(r.Context())
		if err != nil {
			failure(w, 500, err.Error())
			return
		}
		saved := map[string]bool{}
		for _, n := range store.List() {
			saved[n.SSID] = true
		}
		type ap struct {
			SSID     string `json:"ssid"`
			Signal   int    `json:"signal"`
			Security string `json:"security"`
			Saved    bool   `json:"saved"`
		}
		out := []ap{}
		for _, a := range aps {
			out = append(out, ap{a.SSID, a.Signal, a.Security, saved[a.SSID]})
		}
		respond(w, 200, out)
	})
	mux.HandleFunc("POST /api/check", func(w http.ResponseWriter, r *http.Request) {
		svc.Trigger()
		respond(w, 202, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { failure(w, 404, "endpoint not found") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		api := r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")
		if api {
			w.Header().Set("Cache-Control", "no-store")
		}
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil || port == "" || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
			failure(w, 403, "only localhost hosts are allowed")
			return
		}
		if api {
			if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-WC-Token")), []byte(token)) != 1 {
				failure(w, 401, "open the link from wcprime url to connect")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || typ != "application/json" {
					failure(w, 400, "Content-Type must be application/json")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func serveAsset(w http.ResponseWriter, name, typ string) {
	b, err := assets.ReadFile(name)
	if err != nil {
		failure(w, 500, "asset unavailable")
		return
	}
	w.Header().Set("Content-Type", typ)
	_, _ = w.Write(b)
}
func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(r.Body)
	if err := d.Decode(v); err != nil {
		failure(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		failure(w, 400, "body must contain one JSON object")
		return false
	}
	return true
}

// LoadOrCreateToken loads a persistent random access token, stored privately.
func LoadOrCreateToken(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "ui.token")
	b, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(b))
		raw, err := hex.DecodeString(token)
		if err != nil || len(raw) != 32 {
			return "", fmt.Errorf("invalid UI token in %s", path)
		}
		if err := os.Chmod(path, 0600); err != nil {
			return "", err
		}
		return token, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return LoadOrCreateToken(dir)
	}
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(f, token+"\n")
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return token, nil
}
