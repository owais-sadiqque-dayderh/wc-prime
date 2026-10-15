// Package keeper is the control loop: it watches the link, classifies it,
// and repairs it using only networks the user has saved.
package keeper

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/owais-sadiqque-dayderh/wc-prime/internal/events"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/portal"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/probe"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/vault"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"
)

// Store is the part of the vault the keeper reads.
type Store interface {
	List() []vault.Network
	FindSSID(ssid string) (vault.Network, bool)
}

// Checker is the part of the prober the keeper uses.
type Checker interface {
	Check(ctx context.Context) probe.Result
	Quality(ctx context.Context, n int) (median time.Duration, failures int)
}

// LoginFunc submits saved credentials to a captive portal.
type LoginFunc func(ctx context.Context, portalURL string, n vault.Network, verify func(context.Context) bool) error

// PortalLogin is the default LoginFunc.
func PortalLogin(ctx context.Context, portalURL string, n vault.Network, verify func(context.Context) bool) error {
	return portal.Login(ctx, portalURL, portal.Creds{
		Username: n.Username, Password: n.Password, LoginURL: n.PortalURL,
		UserField: n.UserField, PassField: n.PassField, Extra: n.Extra, InsecureTLS: n.InsecureTLS,
		TrustedHosts: n.PortalHosts,
	}, verify)
}

type Config struct {
	Interval     time.Duration // between checks while healthy
	FastInterval time.Duration // between checks while something is wrong
	MinSignal    int           // below this (0-100) the link counts as poor
	MaxRTT       time.Duration // slower checks than this count as poor
	PoorStrikes  int           // consecutive poor checks before switching
	FailStrikes  int           // consecutive no-internet checks before switching
	Cooldown     time.Duration // how long a failed network is skipped
	ConnectWait  time.Duration // how long to wait for association after Connect
}

func DefaultConfig() Config {
	return Config{
		Interval: 15 * time.Second, FastInterval: 5 * time.Second,
		MinSignal: 20, MaxRTT: 1500 * time.Millisecond,
		PoorStrikes: 3, FailStrikes: 2,
		Cooldown: 5 * time.Minute, ConnectWait: 20 * time.Second,
	}
}

type Keeper struct {
	cfg   Config
	wifi  wifi.Backend
	probe Checker
	store Store
	log   *events.Log
	login LoginFunc
	now   func() time.Time
	sleep func(context.Context, time.Duration) // seam for tests

	trigger chan struct{}

	mu   sync.Mutex
	snap Snapshot

	// Loop-owned state (only touched by the Run goroutine).
	poorStrikes, failStrikes int
	cooldown                 map[string]time.Time
	nextScan                 time.Time // throttles rescans after a fruitless recovery
}

func New(cfg Config, w wifi.Backend, p Checker, s Store, l *events.Log, login LoginFunc) *Keeper {
	if login == nil {
		login = PortalLogin
	}
	k := &Keeper{
		cfg: cfg, wifi: w, probe: p, store: s, log: l, login: login,
		now: time.Now, sleep: sleepCtx,
		trigger:  make(chan struct{}, 1),
		cooldown: map[string]time.Time{},
	}
	k.snap = Snapshot{Health: Starting, Signal: -1, Since: k.now(), Backend: w.Name()}
	return k
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// Status returns the latest snapshot.
func (k *Keeper) Status() Snapshot {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.snap
}

// Trigger asks the loop to check immediately.
func (k *Keeper) Trigger() {
	select {
	case k.trigger <- struct{}{}:
	default:
	}
}

// Scan exposes the backend scan to the UI.
func (k *Keeper) Scan(ctx context.Context) ([]wifi.AP, error) { return k.wifi.Scan(ctx) }

// Events exposes the event log to the UI.
func (k *Keeper) Events() []events.Event { return k.log.Recent() }

// Run loops until ctx is cancelled.
func (k *Keeper) Run(ctx context.Context) {
	for {
		h := k.Tick(ctx)
		wait := k.cfg.FastInterval
		if h == Online {
			wait = k.cfg.Interval
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-k.trigger:
			t.Stop()
		case <-t.C:
		}
	}
}

func (k *Keeper) update(f func(*Snapshot)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	prev := k.snap.Health
	f(&k.snap)
	if k.snap.Health != prev {
		k.snap.Since = k.now()
	}
}

func (k *Keeper) setHealth(h Health, st wifi.Status, rtt time.Duration) {
	k.update(func(s *Snapshot) {
		s.Health, s.SSID, s.Signal = h, st.SSID, st.Signal
		s.RTTMillis = rtt.Milliseconds()
		s.LastCheck = k.now()
	})
}

func (k *Keeper) action(format string, args ...any) {
	k.log.Info(format, args...)
	k.update(func(s *Snapshot) { s.LastAction = k.lastEvent() })
}

func (k *Keeper) lastEvent() string {
	if r := k.log.Recent(); len(r) > 0 {
		return r[0].Message
	}
	return ""
}

// Tick runs one check-and-repair cycle and returns the resulting health.
func (k *Keeper) Tick(ctx context.Context) Health {
	st, err := k.wifi.Status(ctx)
	if err != nil {
		k.log.Error("wifi status: %v", err)
		k.setHealth(Failed, st, 0)
		return Failed
	}
	if !st.Enabled {
		k.setHealth(Disabled, st, 0)
		k.action("Wi-Fi is off, turning it on")
		if err := k.wifi.Enable(ctx); err != nil {
			k.log.Warn("enable Wi-Fi: %v", err)
		}
		return Disabled
	}
	if !st.Connected {
		k.setHealth(Disconnected, st, 0)
		return k.recover(ctx, "", "not connected")
	}

	res := k.probe.Check(ctx)
	saved, isSaved := k.store.FindSSID(st.SSID)
	switch res.State {
	case probe.Online:
		k.failStrikes = 0
		if k.isPoor(ctx, st, res.RTT) {
			k.poorStrikes++
			k.setHealth(Poor, st, res.RTT)
			if k.poorStrikes >= k.cfg.PoorStrikes {
				return k.switchFromPoor(ctx, st)
			}
			return Poor
		}
		k.poorStrikes = 0
		k.setHealth(Online, st, res.RTT)
		return Online

	case probe.Captive:
		k.poorStrikes = 0
		k.setHealth(Captive, st, res.RTT)
		if isSaved && saved.Enabled && saved.Portal && k.portalAllowed(st.SSID) {
			if k.portal(ctx, saved, res.PortalURL) {
				k.setHealth(Online, st, 0)
				return Online
			}
		}
		return k.recover(ctx, st.SSID, "captive portal")

	default: // no internet
		k.poorStrikes = 0
		k.failStrikes++
		k.setHealth(NoInternet, st, 0)
		// Some portals block DNS until login; a configured login URL still works.
		if isSaved && saved.Enabled && saved.Portal && saved.PortalURL != "" && k.portalAllowed(st.SSID) {
			if k.portal(ctx, saved, saved.PortalURL) {
				k.setHealth(Online, st, 0)
				return Online
			}
		}
		if k.failStrikes >= k.cfg.FailStrikes {
			k.failStrikes = 0
			return k.recover(ctx, st.SSID, "no internet")
		}
		return NoInternet
	}
}

// isPoor confirms a suspected poor link with a few extra probes so a single
// slow request doesn't trigger a switch.
func (k *Keeper) isPoor(ctx context.Context, st wifi.Status, rtt time.Duration) bool {
	weak := st.Signal >= 0 && st.Signal < k.cfg.MinSignal
	if !weak && rtt <= k.cfg.MaxRTT {
		return false
	}
	median, failures := k.probe.Quality(ctx, 3)
	return weak || failures >= 2 || median > k.cfg.MaxRTT
}

func (k *Keeper) portalAllowed(ssid string) bool {
	return k.now().After(k.cooldown["portal:"+ssid])
}

func (k *Keeper) portal(ctx context.Context, n vault.Network, url string) bool {
	k.action("Logging in to captive portal on %q", n.SSID)
	verify := func(ctx context.Context) bool { return k.probe.Check(ctx).State == probe.Online }
	lctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := k.login(lctx, url, n, verify); err != nil {
		k.log.Warn("portal login on %q failed: %v", n.SSID, err)
		k.cooldown["portal:"+n.SSID] = k.now().Add(k.cfg.Cooldown)
		return false
	}
	k.action("Portal login on %q succeeded", n.SSID)
	return true
}

// switchFromPoor moves to a clearly better saved network, if one is visible.
// The current link still works, so it is only gambled when it can be
// restored: if every better network fails, the keeper rejoins it.
func (k *Keeper) switchFromPoor(ctx context.Context, st wifi.Status) Health {
	k.poorStrikes = 0 // re-evaluate after a few more strikes, not every tick
	prev, ok := k.store.FindSSID(st.SSID)
	if !ok || !prev.Enabled {
		return Poor // no saved credentials to come back with
	}
	aps, err := k.wifi.Scan(ctx)
	if err != nil {
		k.log.Warn("scan: %v", err)
		return Poor
	}
	var better []candidate
	for _, c := range k.candidates(aps, st.SSID) {
		if !c.cooled && c.signal >= k.cfg.MinSignal+10 && (st.Signal < 0 || c.signal >= st.Signal+15) {
			better = append(better, c)
		}
	}
	if len(better) == 0 {
		return Poor // a weak link beats none
	}
	if h, ok := k.tryCandidates(ctx, better, "poor link"); ok {
		k.cooldown[st.SSID] = k.now().Add(k.cfg.Cooldown)
		return h
	}
	k.action("No better network worked, returning to %q", prev.SSID)
	if h, ok := k.tryConnect(ctx, prev); ok {
		return h
	}
	return k.settle(ctx)
}

func (k *Keeper) recover(ctx context.Context, exclude, reason string) Health {
	if k.now().Before(k.nextScan) {
		return k.Status().Health
	}
	aps, err := k.wifi.Scan(ctx)
	if err != nil {
		k.log.Warn("scan: %v", err)
		k.setHealth(Failed, wifi.Status{Signal: -1}, 0)
		return Failed
	}
	return k.recoverWith(ctx, aps, exclude, reason)
}

// recoverWith leaves a broken link (or none) for saved, visible networks in
// priority order. The network being left is put on cooldown so the keeper
// doesn't bounce straight back.
func (k *Keeper) recoverWith(ctx context.Context, aps []wifi.AP, exclude, reason string) Health {
	cands := k.candidates(aps, exclude)
	if len(cands) == 0 {
		k.nextScan = k.now().Add(30 * time.Second)
		if exclude == "" {
			k.action("%s, and no saved network is in range", capitalize(reason))
			return Disconnected
		}
		// Stay put: leaving would only make things worse.
		return k.Status().Health
	}
	if exclude != "" {
		k.cooldown[exclude] = k.now().Add(k.cfg.Cooldown)
	}
	if h, ok := k.tryCandidates(ctx, cands, reason); ok {
		return h
	}
	k.nextScan = k.now().Add(30 * time.Second)
	k.log.Warn("no saved network could be brought online")
	return k.settle(ctx)
}

// tryCandidates joins each candidate in order until one is online. Failures
// go on cooldown.
func (k *Keeper) tryCandidates(ctx context.Context, cands []candidate, reason string) (Health, bool) {
	k.update(func(s *Snapshot) { s.Health = Recovering })
	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		k.action("%s: trying %q", capitalize(reason), c.n.SSID)
		if h, ok := k.tryConnect(ctx, c.n); ok {
			return h, true
		}
		k.cooldown[c.n.SSID] = k.now().Add(k.cfg.Cooldown)
	}
	return "", false
}

// settle records the link as it actually is after failed repairs, which may
// still be associated to a network without internet.
func (k *Keeper) settle(ctx context.Context) Health {
	st, err := k.wifi.Status(ctx)
	if err == nil && st.Connected {
		k.setHealth(NoInternet, st, 0)
		return NoInternet
	}
	k.setHealth(Disconnected, wifi.Status{Signal: -1}, 0)
	return Disconnected
}

type candidate struct {
	n      vault.Network
	rank   int
	signal int
	cooled bool
}

// candidates lists enabled saved networks that are visible (or hidden ones,
// which never appear in scans), best first: networks not on cooldown, then
// priority, then signal. Cooled-down networks stay as a last resort.
func (k *Keeper) candidates(aps []wifi.AP, exclude string) []candidate {
	seen := map[string]int{}
	for _, a := range aps {
		seen[a.SSID] = a.Signal
	}
	now := k.now()
	var out []candidate
	for i, n := range k.store.List() {
		if !n.Enabled || n.SSID == exclude {
			continue
		}
		sig, ok := seen[n.SSID]
		if !ok && !n.Hidden {
			continue
		}
		if !ok {
			sig = -1
		}
		out = append(out, candidate{n: n, rank: i, signal: sig, cooled: now.Before(k.cooldown[n.SSID])})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.cooled != b.cooled {
			return !a.cooled
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		return a.signal > b.signal
	})
	return out
}

// tryConnect joins n and confirms it reaches the internet, handling a
// captive portal on the way.
func (k *Keeper) tryConnect(ctx context.Context, n vault.Network) (Health, bool) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err := k.wifi.Connect(cctx, n.Credentials())
	cancel()
	if err != nil {
		if errors.Is(err, wifi.ErrUnsupported) {
			k.log.Warn("%q: %v", n.SSID, err)
		} else {
			k.log.Warn("connect %q: %v", n.SSID, err)
		}
		return "", false
	}

	st, ok := k.waitAssociated(ctx, n.SSID)
	if !ok {
		k.log.Warn("%q did not associate", n.SSID)
		return "", false
	}
	for attempt := 0; attempt < 3; attempt++ {
		res := k.probe.Check(ctx)
		switch res.State {
		case probe.Online:
			k.poorStrikes, k.failStrikes = 0, 0
			k.nextScan = time.Time{}
			k.setHealth(Online, st, res.RTT)
			k.action("Online via %q", n.SSID)
			return Online, true
		case probe.Captive:
			if !n.Portal {
				k.log.Warn("%q has a captive portal but no saved login", n.SSID)
				k.setHealth(Captive, st, res.RTT)
				return "", false
			}
			if k.portal(ctx, n, res.PortalURL) {
				k.setHealth(Online, st, 0)
				return Online, true
			}
			return "", false
		}
		k.sleep(ctx, 3*time.Second) // DHCP may still be settling
	}
	k.log.Warn("%q connected but has no internet", n.SSID)
	return "", false
}

func (k *Keeper) waitAssociated(ctx context.Context, ssid string) (wifi.Status, bool) {
	deadline := k.now().Add(k.cfg.ConnectWait)
	for {
		st, err := k.wifi.Status(ctx)
		// An empty SSID means the OS hides the name; accept any association.
		if err == nil && st.Connected && (st.SSID == ssid || st.SSID == "") {
			return st, true
		}
		if !k.now().Before(deadline) || ctx.Err() != nil {
			return st, false
		}
		k.sleep(ctx, time.Second)
	}
}

func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-32) + s[1:]
}
