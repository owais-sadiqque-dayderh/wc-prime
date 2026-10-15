// Command wcprime keeps a device online: it watches Wi-Fi, reconnects to the
// best saved network, and signs in to captive portals. A small web UI on
// localhost manages the saved networks.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/owais-sadiqque-dayderh/wc-prime/internal/events"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/keeper"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/probe"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/ui"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/vault"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"
)

var version = "dev"

const usage = `wcprime keeps this device online.

Usage:
  wcprime run   [flags]   run the service (and the management UI)
  wcprime url   [-dir D]  print the management UI link
  wcprime check           diagnose the current connection once
  wcprime version

Run "wcprime run -h" for flags.
`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "url":
		err = cmdURL(os.Args[2:])
	case "check":
		err = cmdCheck()
	case "version", "-v", "--version":
		fmt.Println("wcprime", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wcprime:", err)
		os.Exit(1)
	}
}

func defaultDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "wc-prime")
	}
	return ".wc-prime"
}

const defaultListen = "127.0.0.1:7878"

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfg := keeper.DefaultConfig()
	dir := fs.String("dir", defaultDir(), "config and vault directory")
	listen := fs.String("listen", defaultListen, "UI address (loopback only)")
	noUI := fs.Bool("no-ui", false, "don't serve the management UI")
	fs.DurationVar(&cfg.Interval, "interval", cfg.Interval, "check interval while online")
	fs.DurationVar(&cfg.FastInterval, "fast-interval", cfg.FastInterval, "check interval while recovering")
	fs.IntVar(&cfg.MinSignal, "min-signal", cfg.MinSignal, "signal % below which a link is poor")
	fs.DurationVar(&cfg.MaxRTT, "max-rtt", cfg.MaxRTT, "check latency above which a link is poor")
	fs.Parse(args)

	// Keep the footprint small: collect garbage early and cap the heap.
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(24 << 20)

	backend, err := wifi.New()
	if err != nil {
		return err
	}
	store, err := vault.Open(*dir)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	evlog := events.New(200)
	k := keeper.New(cfg, backend, probe.New(5*time.Second), store, evlog, nil)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !*noUI {
		if err := loopbackOnly(*listen); err != nil {
			return err
		}
		token, err := ui.LoadOrCreateToken(*dir)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			return fmt.Errorf("UI listen: %w", err)
		}
		srv := &http.Server{
			Handler:           ui.New(store, k, token),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				evlog.Error("UI server: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			srv.Shutdown(sctx)
		}()
		evlog.Info("Management UI: %s", uiURL(ln.Addr().String(), token))
	}

	evlog.Info("wcprime %s started (%s), %d saved networks", version, backend.Name(), len(store.List()))
	k.Run(ctx)
	evlog.Info("stopped")
	return nil
}

// loopbackOnly refuses to expose the UI beyond this machine.
func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to serve the UI on %q: use a loopback address", addr)
}

func uiURL(addr, token string) string { return "http://" + addr + "/#t=" + token }

func cmdURL(args []string) error {
	fs := flag.NewFlagSet("url", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "config and vault directory")
	listen := fs.String("listen", defaultListen, "UI address the service listens on")
	fs.Parse(args)
	token, err := ui.LoadOrCreateToken(*dir)
	if err != nil {
		return err
	}
	fmt.Println(uiURL(*listen, token))
	return nil
}

func cmdCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	backend, err := wifi.New()
	if err != nil {
		return err
	}
	fmt.Println("backend:  ", backend.Name())
	st, err := backend.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("wifi:      enabled=%v connected=%v ssid=%q signal=%d%%\n", st.Enabled, st.Connected, st.SSID, st.Signal)
	p := probe.New(5 * time.Second)
	r := p.Check(ctx)
	fmt.Printf("internet:  %s", r.State)
	if r.State == probe.Captive {
		fmt.Printf(" (login page: %s)", r.PortalURL)
	}
	if r.RTT > 0 {
		fmt.Printf(" rtt=%s", r.RTT.Round(time.Millisecond))
	}
	fmt.Println()
	return nil
}
