package keeper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owais-sadiqque-dayderh/wc-prime/internal/events"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/probe"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/vault"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"
)

// fakeWiFi models a radio: Connect succeeds unless the SSID is in fail.
type fakeWiFi struct {
	st        wifi.Status
	aps       []wifi.AP
	fail      map[string]bool
	connects  []string
	scans     int
	enabled   int
	onConnect func(ssid string)
}

func (f *fakeWiFi) Name() string { return "fake" }
func (f *fakeWiFi) Status(context.Context) (wifi.Status, error) {
	return f.st, nil
}
func (f *fakeWiFi) Enable(context.Context) error { f.enabled++; f.st.Enabled = true; return nil }
func (f *fakeWiFi) Scan(context.Context) ([]wifi.AP, error) {
	f.scans++
	return f.aps, nil
}
func (f *fakeWiFi) Connect(_ context.Context, c wifi.Credentials) error {
	f.connects = append(f.connects, c.SSID)
	if f.fail[c.SSID] {
		return errors.New("association failed")
	}
	f.st = wifi.Status{Enabled: true, Connected: true, SSID: c.SSID, Signal: 80}
	if f.onConnect != nil {
		f.onConnect(c.SSID)
	}
	return nil
}

// fakeProbe returns a result per SSID of the fake radio.
type fakeProbe struct {
	w       *fakeWiFi
	results map[string]probe.Result
	quality time.Duration
	qfail   int
}

func (p *fakeProbe) Check(context.Context) probe.Result {
	if r, ok := p.results[p.w.st.SSID]; ok {
		return r
	}
	return probe.Result{State: probe.NoInternet}
}
func (p *fakeProbe) Quality(context.Context, int) (time.Duration, int) { return p.quality, p.qfail }

type fakeStore []vault.Network

func (s fakeStore) List() []vault.Network { return s }
func (s fakeStore) FindSSID(ssid string) (vault.Network, bool) {
	for _, n := range s {
		if n.SSID == ssid {
			return n, true
		}
	}
	return vault.Network{}, false
}

var online = probe.Result{State: probe.Online, RTT: 40 * time.Millisecond}

func net(ssid string) vault.Network {
	return vault.Network{ID: ssid, SSID: ssid, Security: wifi.PSK, Passphrase: "password1", Enabled: true}
}

type rig struct {
	w      *fakeWiFi
	p      *fakeProbe
	k      *Keeper
	logins []string
	clock  time.Time
}

func newRig(store fakeStore) *rig {
	r := &rig{clock: time.Unix(1_700_000_000, 0)}
	r.w = &fakeWiFi{st: wifi.Status{Enabled: true, Signal: -1}, fail: map[string]bool{}}
	r.p = &fakeProbe{w: r.w, results: map[string]probe.Result{}}
	login := func(_ context.Context, url string, n vault.Network, verify func(context.Context) bool) error {
		r.logins = append(r.logins, n.SSID+" "+url)
		r.p.results[n.SSID] = online // portal accepts the login
		if !verify(context.Background()) {
			return errors.New("still captive")
		}
		return nil
	}
	r.k = New(DefaultConfig(), r.w, r.p, store, events.New(50), login)
	r.k.now = func() time.Time { return r.clock }
	r.k.sleep = func(_ context.Context, d time.Duration) { r.clock = r.clock.Add(d) }
	return r
}

func (r *rig) connectedTo(ssid string, signal int) {
	r.w.st = wifi.Status{Enabled: true, Connected: true, SSID: ssid, Signal: signal}
}

func TestHealthyLinkDoesNothing(t *testing.T) {
	r := newRig(fakeStore{net("home")})
	r.connectedTo("home", 90)
	r.p.results["home"] = online
	if h := r.k.Tick(context.Background()); h != Online {
		t.Fatalf("health = %s", h)
	}
	if r.w.scans != 0 || len(r.w.connects) != 0 {
		t.Fatalf("healthy link should not scan/connect: scans=%d connects=%v", r.w.scans, r.w.connects)
	}
	if s := r.k.Status(); s.SSID != "home" || s.RTTMillis != 40 {
		t.Fatalf("snapshot = %+v", s)
	}
}

func TestWiFiOffIsTurnedOn(t *testing.T) {
	r := newRig(nil)
	r.w.st.Enabled = false
	if h := r.k.Tick(context.Background()); h != Disabled || r.w.enabled != 1 {
		t.Fatalf("health=%s enabled=%d", h, r.w.enabled)
	}
}

func TestDisconnectedJoinsByPriorityNotSignal(t *testing.T) {
	r := newRig(fakeStore{net("office"), net("cafe")})
	r.w.aps = []wifi.AP{{SSID: "cafe", Signal: 95}, {SSID: "office", Signal: 40}, {SSID: "stranger", Signal: 99}}
	r.p.results["office"] = online
	if h := r.k.Tick(context.Background()); h != Online {
		t.Fatalf("health = %s", h)
	}
	if len(r.w.connects) != 1 || r.w.connects[0] != "office" {
		t.Fatalf("connects = %v", r.w.connects)
	}
}

func TestFallsThroughToNextCandidate(t *testing.T) {
	r := newRig(fakeStore{net("a"), net("b"), net("c")})
	r.w.aps = []wifi.AP{{SSID: "a", Signal: 70}, {SSID: "b", Signal: 70}, {SSID: "c", Signal: 70}}
	r.w.fail["a"] = true      // association fails
	r.p.results["c"] = online // b associates but has no internet
	if h := r.k.Tick(context.Background()); h != Online {
		t.Fatalf("health = %s", h)
	}
	want := []string{"a", "b", "c"}
	if len(r.w.connects) != 3 || r.w.connects[0] != want[0] || r.w.connects[1] != want[1] || r.w.connects[2] != want[2] {
		t.Fatalf("connects = %v, want %v", r.w.connects, want)
	}
	// a and b are cooled down, so the next recovery prefers c even if a is back.
	cands := r.k.candidates(r.w.aps, "")
	if cands[0].n.SSID != "c" {
		t.Fatalf("first candidate after failures = %s", cands[0].n.SSID)
	}
}

func TestDisabledSkippedHiddenTried(t *testing.T) {
	off := net("off")
	off.Enabled = false
	hidden := net("hidden")
	hidden.Hidden = true
	r := newRig(fakeStore{off, hidden})
	r.w.aps = []wifi.AP{{SSID: "off", Signal: 90}}
	r.p.results["hidden"] = online
	r.k.Tick(context.Background())
	if len(r.w.connects) != 1 || r.w.connects[0] != "hidden" {
		t.Fatalf("connects = %v", r.w.connects)
	}
}

func TestCaptivePortalLogin(t *testing.T) {
	n := net("campus")
	n.Portal, n.Username, n.Password = true, "alice", "pw"
	r := newRig(fakeStore{n})
	r.connectedTo("campus", 70)
	r.p.results["campus"] = probe.Result{State: probe.Captive, PortalURL: "http://login.campus/"}
	if h := r.k.Tick(context.Background()); h != Online {
		t.Fatalf("health = %s", h)
	}
	if len(r.logins) != 1 || r.logins[0] != "campus http://login.campus/" {
		t.Fatalf("logins = %v", r.logins)
	}
}

func TestCaptivePortalAfterConnect(t *testing.T) {
	n := net("hotel")
	n.Portal, n.Username = true, "room101"
	r := newRig(fakeStore{n})
	r.w.aps = []wifi.AP{{SSID: "hotel", Signal: 60}}
	r.p.results["hotel"] = probe.Result{State: probe.Captive, PortalURL: "http://portal/"}
	if h := r.k.Tick(context.Background()); h != Online || len(r.logins) != 1 {
		t.Fatalf("health=%s logins=%v", h, r.logins)
	}
}

func TestUnsavedCaptiveNetworkIsLeftAlone(t *testing.T) {
	r := newRig(fakeStore{net("home")})
	r.connectedTo("airport", 70)
	r.w.aps = []wifi.AP{{SSID: "airport", Signal: 70}}
	r.p.results["airport"] = probe.Result{State: probe.Captive, PortalURL: "http://x/"}
	if h := r.k.Tick(context.Background()); h != Captive {
		t.Fatalf("health = %s", h)
	}
	if len(r.w.connects) != 0 || len(r.logins) != 0 {
		t.Fatalf("should not touch an unsaved network with no alternative: %v %v", r.w.connects, r.logins)
	}
	// The fruitless scan is throttled.
	r.k.Tick(context.Background())
	if r.w.scans != 1 {
		t.Fatalf("scans = %d, want throttled to 1", r.w.scans)
	}
}

func TestNoInternetSwitchesAfterStrikes(t *testing.T) {
	r := newRig(fakeStore{net("home"), net("backup")})
	r.connectedTo("home", 80)
	r.w.aps = []wifi.AP{{SSID: "home", Signal: 80}, {SSID: "backup", Signal: 50}}
	r.p.results["backup"] = online
	if h := r.k.Tick(context.Background()); h != NoInternet || len(r.w.connects) != 0 {
		t.Fatalf("first strike: health=%s connects=%v", h, r.w.connects)
	}
	if h := r.k.Tick(context.Background()); h != Online {
		t.Fatalf("second strike: health = %s", h)
	}
	if r.w.connects[0] != "backup" {
		t.Fatalf("connects = %v", r.w.connects)
	}
}

func TestPoorLinkSwitchesOnlyToClearlyBetter(t *testing.T) {
	r := newRig(fakeStore{net("weak"), net("strong")})
	r.connectedTo("weak", 10)
	r.p.results["weak"] = online
	r.p.results["strong"] = online
	r.w.aps = []wifi.AP{{SSID: "weak", Signal: 10}, {SSID: "strong", Signal: 20}}

	for i := 0; i < 3; i++ {
		if h := r.k.Tick(context.Background()); h != Poor {
			t.Fatalf("tick %d: health = %s", i, h)
		}
	}
	if len(r.w.connects) != 0 {
		t.Fatalf("20%% is not clearly better: %v", r.w.connects)
	}

	r.w.aps[1].Signal = 75
	for i := 0; i < 3; i++ {
		r.k.Tick(context.Background())
	}
	if len(r.w.connects) != 1 || r.w.connects[0] != "strong" {
		t.Fatalf("connects = %v", r.w.connects)
	}
}

func TestSlowSingleProbeIsNotPoor(t *testing.T) {
	r := newRig(fakeStore{net("home")})
	r.connectedTo("home", 80)
	r.p.results["home"] = probe.Result{State: probe.Online, RTT: 3 * time.Second}
	r.p.quality = 100 * time.Millisecond // follow-up probes are fine
	if h := r.k.Tick(context.Background()); h != Online {
		t.Fatalf("health = %s", h)
	}
}

// Review regression: poor-link recovery must only try qualifying networks,
// keeping user priority among them.
func TestPoorLinkSkipsHigherPriorityButWeakerNetwork(t *testing.T) {
	r := newRig(fakeStore{net("weakalt"), net("strong"), net("cur")})
	r.connectedTo("cur", 15)
	r.p.results["cur"] = online
	r.p.results["weakalt"] = online
	r.p.results["strong"] = online
	r.w.aps = []wifi.AP{{SSID: "cur", Signal: 15}, {SSID: "weakalt", Signal: 5}, {SSID: "strong", Signal: 90}}
	for i := 0; i < 3; i++ {
		r.k.Tick(context.Background())
	}
	if len(r.w.connects) != 1 || r.w.connects[0] != "strong" {
		t.Fatalf("connects = %v, want [strong]", r.w.connects)
	}
}

// Review regression: if the better network has no internet, rejoin the
// original working one.
func TestPoorLinkRestoresWorkingNetwork(t *testing.T) {
	r := newRig(fakeStore{net("cur"), net("backup")})
	r.connectedTo("cur", 10)
	r.p.results["cur"] = online // backup has no result → no internet
	r.w.aps = []wifi.AP{{SSID: "cur", Signal: 10}, {SSID: "backup", Signal: 90}}
	var h Health
	for i := 0; i < 3; i++ {
		h = r.k.Tick(context.Background())
	}
	if len(r.w.connects) != 2 || r.w.connects[0] != "backup" || r.w.connects[1] != "cur" {
		t.Fatalf("connects = %v, want [backup cur]", r.w.connects)
	}
	if r.w.st.SSID != "cur" || h != Online {
		t.Fatalf("ended on %q with health %s, want cur/online", r.w.st.SSID, h)
	}
}

func TestPoorUnsavedLinkIsNotGambled(t *testing.T) {
	r := newRig(fakeStore{net("strong")})
	r.connectedTo("friend", 10)
	r.p.results["friend"] = online
	r.w.aps = []wifi.AP{{SSID: "friend", Signal: 10}, {SSID: "strong", Signal: 90}}
	for i := 0; i < 3; i++ {
		r.k.Tick(context.Background())
	}
	if len(r.w.connects) != 0 {
		t.Fatalf("an unsaved link can't be restored, so it must not be left: %v", r.w.connects)
	}
}

func TestFailedRecoveryReportsActualAssociation(t *testing.T) {
	r := newRig(fakeStore{net("home"), net("backup")})
	r.connectedTo("home", 80)
	r.w.aps = []wifi.AP{{SSID: "home", Signal: 80}, {SSID: "backup", Signal: 60}}
	r.k.Tick(context.Background())
	if h := r.k.Tick(context.Background()); h != NoInternet {
		t.Fatalf("health = %s, want no-internet (still associated)", h)
	}
	if s := r.k.Status(); s.SSID != "backup" {
		t.Fatalf("snapshot SSID = %q, want the network actually joined", s.SSID)
	}
}

// Review regression: a disabled entry's portal credentials are never used.
func TestDisabledNetworkPortalNotUsed(t *testing.T) {
	n := net("campus")
	n.Enabled, n.Portal, n.Username, n.PortalURL = false, true, "alice", "http://login.campus/"
	r := newRig(fakeStore{n})
	r.connectedTo("campus", 70)
	r.p.results["campus"] = probe.Result{State: probe.Captive, PortalURL: "http://login.campus/"}
	r.k.Tick(context.Background())
	delete(r.p.results, "campus") // no internet path with a fixed login URL
	r.k.Tick(context.Background())
	if len(r.logins) != 0 {
		t.Fatalf("disabled network's credentials were submitted: %v", r.logins)
	}
}
