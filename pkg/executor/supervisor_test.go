package executor

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeClock is a manually advanced Clock.
//
// After() registers a waiter that fires once the clock passes its deadline, so
// a test steps a supervisor through hours of simulated time without sleeping.
// In auto mode After() instead jumps the clock forward by d and fires
// immediately, which lets a polling loop (WaitForDrain) run at full speed in
// virtual time with no second goroutine ticking it along.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	auto    bool
	waiters []fakeWaiter
}

type fakeWaiter struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: baseTime} }

func newAutoClock() *fakeClock { return &fakeClock{now: baseTime, auto: true} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.auto {
		c.now = c.now.Add(d)
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, fakeWaiter{at: c.now.Add(d), ch: ch})
	return ch
}

// Advance moves the clock and fires every waiter whose deadline has passed.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	kept := c.waiters[:0]
	var fire []chan time.Time
	for _, w := range c.waiters {
		if w.at.After(now) {
			kept = append(kept, w)
			continue
		}
		fire = append(fire, w.ch)
	}
	c.waiters = kept
	c.mu.Unlock()
	for _, ch := range fire {
		ch <- now // buffered; never blocks
	}
}

// memHealthStore is a concurrency-safe in-memory HealthStore. loadErr lets a
// test assert the documented degradation: a health store that cannot be read
// must not stop the supervisor probing.
type memHealthStore struct {
	mu      sync.Mutex
	recs    map[string]Health
	loadErr error
}

func newMemHealthStore() *memHealthStore {
	return &memHealthStore{recs: make(map[string]Health)}
}

func (s *memHealthStore) LoadHealth(id string) (Health, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return Health{}, s.loadErr
	}
	// An unknown executor yields the zero Health and a nil error: "never
	// probed" is a normal state, not a lookup failure.
	return s.recs[id], nil
}

func (s *memHealthStore) SaveHealth(h Health) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[h.ExecutorID] = h
	return nil
}

func (s *memHealthStore) ListHealth() ([]Health, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Health, 0, len(s.recs))
	for _, h := range s.recs {
		out = append(out, h)
	}
	return out, nil
}

func (s *memHealthStore) get(id string) (Health, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.recs[id]
	return h, ok
}

func (s *memHealthStore) setLoadErr(err error) {
	s.mu.Lock()
	s.loadErr = err
	s.mu.Unlock()
}

// memSink records what the event log would have seen. EventSink implementations
// must not block, so this only takes a mutex.
type memSink struct {
	mu          sync.Mutex
	transitions []Transition
	failovers   []FailoverEvent
}

func (s *memSink) ExecutorTransition(t Transition) {
	s.mu.Lock()
	s.transitions = append(s.transitions, t)
	s.mu.Unlock()
}

func (s *memSink) ExecutorFailover(ev FailoverEvent) {
	s.mu.Lock()
	s.failovers = append(s.failovers, ev)
	s.mu.Unlock()
}

func (s *memSink) transitionsFor(id string) []Transition {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Transition, 0, len(s.transitions))
	for _, t := range s.transitions {
		if t.ExecutorID == id {
			out = append(out, t)
		}
	}
	return out
}

func (s *memSink) failoverEvents() []FailoverEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]FailoverEvent(nil), s.failovers...)
}

// drainStore serves a scripted sequence of in-flight counts; the last value
// repeats forever.
type drainStore struct {
	mu     sync.Mutex
	counts []int
	err    error
	calls  int
}

func (s *drainStore) RunningSessions(string) ([]Session, error) { return nil, nil }

func (s *drainStore) ClaimRequeue(string, string, time.Time) (Session, error) {
	return Session{}, ErrSessionClaimLost
}

func (s *drainStore) CountRunning(string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	s.calls++
	if len(s.counts) == 0 {
		return 0, nil
	}
	n := s.counts[0]
	if len(s.counts) > 1 {
		s.counts = s.counts[1:]
	}
	return n, nil
}

func newSupervisorFixture(t *testing.T, cfg SupervisorConfig, opts ...SupervisorOption) (*Supervisor, *Registry) {
	t.Helper()
	reg := NewRegistry()
	return NewSupervisor(reg, cfg, opts...), reg
}

// probeTestConfig is a supervisor that never times out on its own and gives up
// after two consecutive failures, so a test can step it one probe at a time.
func probeTestConfig() SupervisorConfig {
	return SupervisorConfig{
		Interval:            30 * time.Second,
		ProbeTimeout:        5 * time.Second,
		BackoffBase:         5 * time.Second,
		BackoffMax:          time.Minute,
		MaxConcurrentProbes: 4,
		Policy:              HealthPolicy{DegradeAfter: 1, UnreachableAfter: 2},
	}
}

// ---------------------------------------------------------------------------
// ProbeOnce
// ---------------------------------------------------------------------------

// TestProbeOnceDrivesTransitionsAndEmitsOneEventEach walks a node down to
// unreachable and back, asserting that the sink sees exactly one event per
// *state change* — not one per probe. A supervisor that re-announced
// "unreachable" every 30 seconds would bury the event log and re-trigger every
// downstream consumer of the transition.
func TestProbeOnceDrivesTransitionsAndEmitsOneEventEach(t *testing.T) {
	clk := newFakeClock()
	store := newMemHealthStore()
	sink := &memSink{}
	sv, reg := newSupervisorFixture(t, probeTestConfig(),
		WithClock(clk), WithHealthStore(store), WithEventSink(sink))

	edge := newCapExec("edge-1", fullCaps(nil))
	if err := reg.Register(edge); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Round 1: healthy. No transition, but the sighting is persisted.
	if got := sv.ProbeOnce(context.Background()); len(got) != 0 {
		t.Fatalf("ProbeOnce on a healthy node returned %v, want no transitions", got)
	}
	h, ok := store.get("edge-1")
	if !ok {
		t.Fatal("a successful probe persisted nothing; the fleet view would be empty after a restart")
	}
	if h.State != NodeReady || !h.LastSeen.Equal(baseTime) {
		t.Fatalf("persisted health = %+v, want ready last seen at %v", h, baseTime)
	}
	if len(sink.transitionsFor("edge-1")) != 0 {
		t.Fatalf("ready -> ready emitted %v, want nothing", sink.transitionsFor("edge-1"))
	}

	// Round 2: the device drops off. DegradeAfter=1, so this degrades it.
	edge.failWith(errors.New("dial tcp 10.0.0.7:9000: connect: no route to host"))
	clk.Advance(time.Hour)
	got := sv.ProbeOnce(context.Background())
	if len(got) != 1 || got[0].To != NodeDegraded {
		t.Fatalf("ProbeOnce = %v, want one ready -> degraded transition", got)
	}
	if n := len(sink.transitionsFor("edge-1")); n != 1 {
		t.Fatalf("sink saw %d transitions, want 1", n)
	}

	// Round 3: crosses UnreachableAfter.
	clk.Advance(time.Hour)
	got = sv.ProbeOnce(context.Background())
	if len(got) != 1 || got[0].From != NodeDegraded || got[0].To != NodeUnreachable {
		t.Fatalf("ProbeOnce = %v, want degraded -> unreachable", got)
	}
	if n := len(sink.transitionsFor("edge-1")); n != 2 {
		t.Fatalf("sink saw %d transitions, want 2", n)
	}

	// Rounds 4 and 5: still down, still unreachable. No new events.
	for i := 0; i < 2; i++ {
		clk.Advance(time.Hour)
		if got := sv.ProbeOnce(context.Background()); len(got) != 0 {
			t.Fatalf("a repeat failure returned %v, want no transition", got)
		}
	}
	if n := len(sink.transitionsFor("edge-1")); n != 2 {
		t.Fatalf("sink saw %d transitions after repeat failures, want still 2 — "+
			"one event per state change, not one per probe", n)
	}
	if h, _ := store.get("edge-1"); h.ConsecutiveFailures != 4 {
		t.Errorf("persisted ConsecutiveFailures = %d, want 4", h.ConsecutiveFailures)
	}

	// Recovery emits exactly one more.
	edge.setHealth(nil)
	clk.Advance(time.Hour)
	got = sv.ProbeOnce(context.Background())
	if len(got) != 1 || got[0].From != NodeUnreachable || got[0].To != NodeReady {
		t.Fatalf("ProbeOnce = %v, want unreachable -> ready", got)
	}
	if n := len(sink.transitionsFor("edge-1")); n != 3 {
		t.Fatalf("sink saw %d transitions, want 3", n)
	}
	if h, _ := store.get("edge-1"); h.State != NodeReady || h.ConsecutiveFailures != 0 {
		t.Errorf("persisted health after recovery = %+v, want ready with 0 failures", h)
	}
}

// TestProbeOnceReturnsTransitionsSortedByID keeps the CLI's refresh output and
// the event ordering deterministic across a fleet.
func TestProbeOnceReturnsTransitionsSortedByID(t *testing.T) {
	clk := newFakeClock()
	sv, reg := newSupervisorFixture(t, probeTestConfig(), WithClock(clk), WithHealthStore(newMemHealthStore()))

	for _, id := range []string{"zeta", "alpha", "mid"} {
		ex := newCapExec(id, fullCaps(nil))
		ex.failWith(errors.New("down"))
		if err := reg.Register(ex); err != nil {
			t.Fatalf("Register(%s): %v", id, err)
		}
	}

	got := sv.ProbeOnce(context.Background())
	if len(got) != 3 {
		t.Fatalf("ProbeOnce returned %d transitions, want 3", len(got))
	}
	for i, want := range []string{"alpha", "mid", "zeta"} {
		if got[i].ExecutorID != want {
			t.Errorf("transition[%d] = %q, want %q", i, got[i].ExecutorID, want)
		}
	}
}

// TestProbeOnceSkipsNodesNotYetDueAndForgetsDepartedOnes covers the per-node
// due time: a backed-off device is skipped on ticks it is not due for, and its
// schedule entry is dropped when it unregisters so a control plane that churns
// edge devices does not grow the map without bound.
func TestProbeOnceSkipsNodesNotYetDueAndForgetsDepartedOnes(t *testing.T) {
	clk := newFakeClock()
	cfg := probeTestConfig()
	cfg.Interval = 30 * time.Second
	sv, reg := newSupervisorFixture(t, cfg, WithClock(clk), WithHealthStore(newMemHealthStore()))

	edge := newCapExec("edge-1", fullCaps(nil))
	_ = reg.Register(edge)

	sv.ProbeOnce(context.Background())
	if n := edge.probeCount(); n != 1 {
		t.Fatalf("probe count = %d, want 1", n)
	}
	// Not due yet.
	sv.ProbeOnce(context.Background())
	if n := edge.probeCount(); n != 1 {
		t.Fatalf("probe count = %d after an early scan, want still 1", n)
	}
	clk.Advance(cfg.Interval + time.Second)
	sv.ProbeOnce(context.Background())
	if n := edge.probeCount(); n != 2 {
		t.Fatalf("probe count = %d once due, want 2", n)
	}

	// A failing node backs off, so the very next scan skips it.
	edge.failWith(errors.New("down"))
	clk.Advance(cfg.Interval + time.Second)
	sv.ProbeOnce(context.Background())
	before := edge.probeCount()
	clk.Advance(cfg.BackoffBase / 2)
	sv.ProbeOnce(context.Background())
	if edge.probeCount() != before {
		t.Errorf("a failing node was re-probed inside its backoff window (%d -> %d)", before, edge.probeCount())
	}

	sv.mu.Lock()
	_, tracked := sv.nextProbe["edge-1"]
	sv.mu.Unlock()
	if !tracked {
		t.Fatal("no schedule entry for a probed executor")
	}

	reg.Unregister("edge-1")
	sv.ProbeOnce(context.Background())
	sv.mu.Lock()
	_, stillTracked := sv.nextProbe["edge-1"]
	n := len(sv.nextProbe)
	sv.mu.Unlock()
	if stillTracked || n != 0 {
		t.Fatalf("schedule map still holds %d entries after unregistration, want 0", n)
	}
}

// TestSupervisorKeepsProbingWhenTheHealthStoreIsUnreadable: a store that cannot
// be read must not stop liveness supervision. The worst case is a recomputed
// transition, which is noisy, not harmful.
func TestSupervisorKeepsProbingWhenTheHealthStoreIsUnreadable(t *testing.T) {
	clk := newFakeClock()
	store := newMemHealthStore()
	store.setLoadErr(errors.New("statedb: database is locked"))
	sink := &memSink{}
	sv, reg := newSupervisorFixture(t, probeTestConfig(),
		WithClock(clk), WithHealthStore(store), WithEventSink(sink))

	edge := newCapExec("edge-1", fullCaps(nil))
	edge.failWith(errors.New("down"))
	_ = reg.Register(edge)

	if got := sv.ProbeOnce(context.Background()); len(got) != 1 || got[0].To != NodeDegraded {
		t.Fatalf("ProbeOnce with an unreadable store = %v, want a ready -> degraded transition", got)
	}
	if edge.probeCount() == 0 {
		t.Fatal("no probe ran at all")
	}
}

// ---------------------------------------------------------------------------
// Backoff and jitter
// ---------------------------------------------------------------------------

// TestBackoffDoublesAndCaps: a device that is down will be down for the next
// probe too, and hammering it every 30s for an hour keeps a cellular link awake
// and a battery flat.
func TestBackoffDoublesAndCaps(t *testing.T) {
	sv := NewSupervisor(NewRegistry(), SupervisorConfig{
		BackoffBase: time.Second,
		BackoffMax:  30 * time.Second,
	})

	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, time.Second}, // defensive: no failures yet
		{1, time.Second}, // first retry is the base
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 30 * time.Second}, // 32s would exceed the cap
		{7, 30 * time.Second},
		{33, 30 * time.Second}, // just past the shift guard
		{64, 30 * time.Second}, // 2^63 ns would overflow a Duration
		{10_000_000, 30 * time.Second},
	}
	for _, tc := range cases {
		got := sv.backoff(tc.failures)
		if got != tc.want {
			t.Errorf("backoff(%d) = %v, want %v", tc.failures, got, tc.want)
		}
		if got <= 0 {
			t.Errorf("backoff(%d) = %v — a wrapped or negative delay means the device gets hammered", tc.failures, got)
		}
	}

	// Monotonic up to the cap: each step is at least as long as the last.
	prev := time.Duration(0)
	for n := 1; n <= 40; n++ {
		d := sv.backoff(n)
		if d < prev {
			t.Fatalf("backoff(%d) = %v went backwards from %v", n, d, prev)
		}
		if d > 30*time.Second {
			t.Fatalf("backoff(%d) = %v exceeded BackoffMax", n, d)
		}
		prev = d
	}

	// A misconfigured pair is clamped rather than rejected: a bad config must
	// not be able to produce a delay shorter than the base.
	clamped := NewSupervisor(NewRegistry(), SupervisorConfig{
		BackoffBase: 10 * time.Second,
		BackoffMax:  time.Second,
	})
	if clamped.cfg.BackoffMax != 10*time.Second {
		t.Errorf("BackoffMax = %v, want it clamped up to BackoffBase", clamped.cfg.BackoffMax)
	}
	if got := clamped.backoff(9); got != 10*time.Second {
		t.Errorf("backoff(9) with a clamped config = %v, want 10s", got)
	}

	// The zero config is usable.
	def := NewSupervisor(NewRegistry(), SupervisorConfig{})
	if def.cfg.BackoffBase <= 0 || def.cfg.Interval <= 0 || def.cfg.ProbeTimeout <= 0 || def.cfg.MaxConcurrentProbes <= 0 {
		t.Errorf("zero SupervisorConfig normalized to %+v, want usable defaults", def.cfg)
	}
}

// TestJitterStaysWithinFraction: a control plane that restarts and probes forty
// edge devices on the same tick is a thundering herd against whatever shared
// infrastructure they sit behind.
func TestJitterStaysWithinFraction(t *testing.T) {
	const (
		d = 100 * time.Millisecond
		f = 0.2
	)
	lo := time.Duration(float64(d) * (1 - f))
	hi := time.Duration(float64(d) * (1 + f))

	var next float64
	sv := NewSupervisor(NewRegistry(), SupervisorConfig{
		JitterFraction: f,
		Rand:           func() float64 { return next },
	})

	// The band, at both ends and in the middle. A 1ns slack absorbs the
	// float64 round-trip through the factor.
	for _, r := range []float64{0, 0.125, 0.25, 0.5, 0.75, 0.999999} {
		next = r
		got := sv.jitter(d)
		if got < lo-time.Nanosecond || got > hi+time.Nanosecond {
			t.Errorf("jitter(%v) with rand=%v = %v, want within [%v, %v]", d, r, got, lo, hi)
		}
	}

	// rand=0.5 is the midpoint and lands exactly on d, which is the anchor the
	// band is computed around.
	next = 0.5
	if got := sv.jitter(d); got != d {
		t.Errorf("jitter at rand=0.5 = %v, want exactly %v", got, d)
	}
	// Monotonic in the random draw.
	next = 0
	low := sv.jitter(d)
	next = 0.9
	high := sv.jitter(d)
	if !(low < d && d < high) {
		t.Errorf("jitter is not monotonic in rand: %v < %v < %v is false", low, d, high)
	}

	// A property sweep over a deterministic source, since the fixed points
	// above cannot prove the band on their own.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		next = rng.Float64()
		got := sv.jitter(d)
		if got < lo-time.Nanosecond || got > hi+time.Nanosecond {
			t.Fatalf("jitter with rand=%v = %v, outside [%v, %v]", next, got, lo, hi)
		}
	}

	// Jitter is opt-out, and the fraction is clamped so it can never produce a
	// zero or negative delay.
	plain := NewSupervisor(NewRegistry(), SupervisorConfig{JitterFraction: 0})
	if got := plain.jitter(d); got != d {
		t.Errorf("jitter with fraction 0 = %v, want %v unchanged", got, d)
	}
	if got := plain.jitter(0); got != 0 {
		t.Errorf("jitter(0) = %v, want 0", got)
	}
	wild := NewSupervisor(NewRegistry(), SupervisorConfig{
		JitterFraction: 5, Rand: func() float64 { return 0 },
	})
	if wild.cfg.JitterFraction != 0.9 {
		t.Errorf("JitterFraction = %v, want it clamped to 0.9", wild.cfg.JitterFraction)
	}
	if got := wild.jitter(d); got <= 0 {
		t.Errorf("jitter with a clamped fraction = %v, want > 0", got)
	}
	negative := NewSupervisor(NewRegistry(), SupervisorConfig{JitterFraction: -1})
	if negative.cfg.JitterFraction != 0 {
		t.Errorf("negative JitterFraction = %v, want 0", negative.cfg.JitterFraction)
	}

	// With no Rand injected the package source is used and must still respect
	// the band.
	unseeded := NewSupervisor(NewRegistry(), SupervisorConfig{JitterFraction: f})
	for i := 0; i < 500; i++ {
		got := unseeded.jitter(d)
		if got < lo-time.Nanosecond || got > hi+time.Nanosecond {
			t.Fatalf("default jitter source produced %v, outside [%v, %v]", got, lo, hi)
		}
	}
}

// ---------------------------------------------------------------------------
// Probe bounding
// ---------------------------------------------------------------------------

// TestProbeTimeoutBoundsAHungDriver: a remote agent whose TCP connection is
// black-holed must cost one timeout, not one goroutine forever — and it must
// not hold up the rest of the round's results either.
func TestProbeTimeoutBoundsAHungDriver(t *testing.T) {
	cfg := probeTestConfig()
	cfg.ProbeTimeout = 100 * time.Millisecond
	cfg.Policy = HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}
	store := newMemHealthStore()
	// A real clock: the bound is a context deadline, which is real time.
	sv, reg := newSupervisorFixture(t, cfg, WithHealthStore(store))

	hung := newCapExec("edge-hung", fullCaps(nil))
	hung.setHealth(func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			// The driver observes the deadline the supervisor imposed.
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return errors.New("HealthCheck was never bounded by ProbeTimeout")
		}
	})
	quick := newCapExec("edge-quick", fullCaps(nil))
	_ = reg.Register(hung)
	_ = reg.Register(quick)

	start := time.Now()
	got := sv.ProbeOnce(context.Background())
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("ProbeOnce took %v, want it bounded by ProbeTimeout (%v)", elapsed, cfg.ProbeTimeout)
	}
	if len(got) != 1 || got[0].ExecutorID != "edge-hung" || got[0].To != NodeUnreachable {
		t.Fatalf("ProbeOnce = %v, want edge-hung -> unreachable", got)
	}
	h, ok := store.get("edge-hung")
	if !ok {
		t.Fatal("the timed-out probe recorded nothing")
	}
	if h.Reason != context.DeadlineExceeded.Error() {
		t.Errorf("Reason = %q, want %q", h.Reason, context.DeadlineExceeded.Error())
	}
	// The healthy node in the same round is unaffected: one hung driver must
	// not wedge the scan.
	if qh, ok := store.get("edge-quick"); !ok || qh.State != NodeReady || qh.ConsecutiveFailures != 0 {
		t.Fatalf("edge-quick health = %+v (present=%v), want a clean ready record", qh, ok)
	}
}

// TestProbeIgnoresShutdownCancellation: a cancelled *parent* context means the
// control plane is shutting down, not that the node is sick. Recording it as a
// failure would have every restart nudge the whole fleet toward unreachable.
func TestProbeIgnoresShutdownCancellation(t *testing.T) {
	cfg := probeTestConfig()
	cfg.ProbeTimeout = 10 * time.Second
	cfg.Policy = HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}
	store := newMemHealthStore()
	sink := &memSink{}
	sv, reg := newSupervisorFixture(t, cfg, WithHealthStore(store), WithEventSink(sink))

	entered := make(chan struct{})
	edge := newCapExec("edge-1", fullCaps(nil))
	edge.setHealth(func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	_ = reg.Register(edge)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-entered
		cancel()
	}()
	got := sv.ProbeOnce(ctx)
	cancel()

	if len(got) != 0 {
		t.Fatalf("ProbeOnce during shutdown = %v, want no transitions", got)
	}
	if h, ok := store.get("edge-1"); ok {
		t.Fatalf("shutdown persisted health %+v, want nothing recorded", h)
	}
	if n := len(sink.transitionsFor("edge-1")); n != 0 {
		t.Fatalf("shutdown emitted %d transitions, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// Admin actions
// ---------------------------------------------------------------------------

// TestSupervisorAdminActions covers the operator-facing half of the state
// machine as it is actually reached: through the supervisor, with persistence
// and event emission attached.
func TestSupervisorAdminActions(t *testing.T) {
	clk := newFakeClock()
	store := newMemHealthStore()
	sink := &memSink{}
	sv, reg := newSupervisorFixture(t, probeTestConfig(),
		WithClock(clk), WithHealthStore(store), WithEventSink(sink))

	edge := newCapExec("edge-1", fullCaps(nil))
	_ = reg.Register(edge)

	h, err := sv.Cordon("edge-1", "investigating a stuck run")
	if err != nil {
		t.Fatalf("Cordon: %v", err)
	}
	if h.State != NodeCordoned || h.Reason != "investigating a stuck run" {
		t.Fatalf("Cordon returned %+v, want cordoned with the operator's note", h)
	}
	if persisted, ok := store.get("edge-1"); !ok || persisted.State != NodeCordoned {
		t.Fatalf("persisted health = %+v (present=%v), want cordoned", persisted, ok)
	}
	if got := sv.Health("edge-1"); got.State != NodeCordoned {
		t.Fatalf("Health() = %q, want cordoned", got.State)
	}
	if n := len(sink.transitionsFor("edge-1")); n != 1 {
		t.Fatalf("sink saw %d transitions, want 1", n)
	}

	// Probes keep running against a cordoned node and keep counting failures,
	// but must not disturb the operator's hold.
	edge.failWith(errors.New("connection refused"))
	for i := 0; i < 4; i++ {
		clk.Advance(time.Hour)
		if got := sv.ProbeOnce(context.Background()); len(got) != 0 {
			t.Fatalf("probing a cordoned node produced %v, want no transitions", got)
		}
	}
	if got := sv.Health("edge-1"); got.State != NodeCordoned || got.ConsecutiveFailures != 4 {
		t.Fatalf("health = %+v, want cordoned with 4 counted failures", got)
	}

	// Uncordon therefore lands in unreachable, not ready: uncordon must not be
	// a way to launder a broken node into the schedulable set.
	clk.Advance(time.Hour)
	back, err := sv.Uncordon("edge-1")
	if err != nil {
		t.Fatalf("Uncordon: %v", err)
	}
	if back.State != NodeUnreachable {
		t.Fatalf("Uncordon = %q, want unreachable — the probes never recovered", back.State)
	}

	// An uncordoned node is re-probed promptly rather than waiting out the
	// backoff it accumulated while it was held.
	sv.mu.Lock()
	_, scheduled := sv.nextProbe["edge-1"]
	sv.mu.Unlock()
	if scheduled {
		t.Error("Uncordon left a backoff entry in place; the node would sit unprobed")
	}

	// Drain is the same mechanism with retirement intent.
	if h, err := sv.Drain("edge-1", ""); err != nil || h.State != NodeDraining {
		t.Fatalf("Drain = (%q, %v), want draining", h.State, err)
	}

	// Admin actions on an unknown executor fail rather than inventing a record.
	for name, fn := range map[string]func() error{
		"Cordon":   func() error { _, err := sv.Cordon("ghost", ""); return err },
		"Drain":    func() error { _, err := sv.Drain("ghost", ""); return err },
		"Uncordon": func() error { _, err := sv.Uncordon("ghost"); return err },
	} {
		if err := fn(); !errors.Is(err, ErrExecutorNotFound) {
			t.Errorf("%s(unknown) = %v, want ErrExecutorNotFound", name, err)
		}
	}
	if _, ok := store.get("ghost"); ok {
		t.Error("an admin action on an unknown executor persisted a record")
	}

	// Health for an executor with no record normalizes to ready rather than
	// returning a zero-valued, unschedulable state.
	if got := sv.Health("never-probed"); got.State != NodeReady || got.ExecutorID != "never-probed" {
		t.Errorf("Health(unknown) = %+v, want a ready record carrying the ID", got)
	}
}

// ---------------------------------------------------------------------------
// WaitForDrain
// ---------------------------------------------------------------------------

func TestWaitForDrainReturnsWhenInFlightHitsZero(t *testing.T) {
	store := &drainStore{counts: []int{3, 2, 1, 0}}
	sv, _ := newSupervisorFixture(t, probeTestConfig(),
		WithClock(newAutoClock()), WithSessionStore(store))

	n, err := sv.WaitForDrain(context.Background(), "edge-1", 0, time.Second)
	if err != nil {
		t.Fatalf("WaitForDrain = %v, want nil once in-flight reaches zero", err)
	}
	if n != 0 {
		t.Fatalf("remaining = %d, want 0", n)
	}
	if store.calls != 4 {
		t.Errorf("CountRunning called %d times, want 4 (it must poll, not answer once)", store.calls)
	}
}

func TestWaitForDrainTimesOutWithRemainingCount(t *testing.T) {
	// Two sessions that never finish.
	store := &drainStore{counts: []int{2}}
	sv, _ := newSupervisorFixture(t, probeTestConfig(),
		WithClock(newAutoClock()), WithSessionStore(store))

	n, err := sv.WaitForDrain(context.Background(), "edge-1", 10*time.Second, time.Second)
	if err == nil {
		t.Fatal("WaitForDrain returned nil, want a timeout while work was still in flight")
	}
	if !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("error = %v, want it to wrap ErrDrainTimeout", err)
	}
	if n != 2 {
		t.Fatalf("remaining = %d, want 2 — `drain --force` needs to say what it would abandon", n)
	}
	// The message has to carry the count and the node, not just the sentinel.
	for _, want := range []string{"2 session(s)", "edge-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err.Error(), want)
		}
	}
}

func TestWaitForDrainEdgeCases(t *testing.T) {
	// No session store: nothing can be in flight, so a drain trivially
	// succeeds rather than blocking forever.
	sv, _ := newSupervisorFixture(t, probeTestConfig(), WithClock(newAutoClock()))
	if n, err := sv.WaitForDrain(context.Background(), "edge-1", time.Second, time.Millisecond); err != nil || n != 0 {
		t.Fatalf("WaitForDrain without a session store = (%d, %v), want (0, nil)", n, err)
	}

	// Already idle: return immediately without consulting the clock at all.
	idle := &drainStore{counts: []int{0}}
	sv, _ = newSupervisorFixture(t, probeTestConfig(), WithClock(newFakeClock()), WithSessionStore(idle))
	if n, err := sv.WaitForDrain(context.Background(), "edge-1", time.Minute, time.Second); err != nil || n != 0 {
		t.Fatalf("WaitForDrain on an idle node = (%d, %v), want (0, nil)", n, err)
	}

	// A cancelled caller wins over the poll: the clock here never fires, so
	// the select has exactly one ready case and the outcome is deterministic.
	busy := &drainStore{counts: []int{1}}
	sv, _ = newSupervisorFixture(t, probeTestConfig(), WithClock(newFakeClock()), WithSessionStore(busy))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := sv.WaitForDrain(ctx, "edge-1", 0, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForDrain with a cancelled ctx = %v, want context.Canceled", err)
	}
	if n != 1 {
		t.Errorf("remaining = %d, want the last observed count 1", n)
	}

	// A store that cannot answer is an error, not a silent success — reporting
	// "drained" when the count is unknown is how work gets abandoned.
	broken := &drainStore{err: errors.New("statedb: disk I/O error")}
	sv, _ = newSupervisorFixture(t, probeTestConfig(), WithClock(newAutoClock()), WithSessionStore(broken))
	if _, err := sv.WaitForDrain(context.Background(), "edge-1", time.Minute, time.Second); err == nil {
		t.Fatal("WaitForDrain with a broken store returned nil, want the store error")
	}
}

// ---------------------------------------------------------------------------
// Exactly-once failover under concurrent supervisors
// ---------------------------------------------------------------------------

// claimStore implements the real conditional-claim semantics a SessionStore is
// required to have: ClaimRequeue succeeds only if the presented token matches
// the session's current token, and it rotates that token inside the same
// critical section. That single conditional write ("UPDATE ... WHERE id = ? AND
// claim_token = ?") is the entire double-execution guard, so the fake has to
// implement it faithfully or the test below proves nothing.
type claimStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	order    []string

	// ignoreToken weakens the guard on purpose. It exists so the test suite
	// can prove that the exactly-once test actually fails when the latch is
	// removed; a concurrency test that passes against a broken implementation
	// is worthless.
	ignoreToken bool

	attempts  int
	granted   int
	rotations int

	// listGate holds every caller of RunningSessions until all N supervisors
	// have read the same snapshot. Without it the race is real but not
	// guaranteed: a supervisor that happened to read after the winner's claim
	// would simply not see the session, and the token comparison would never
	// be exercised at all.
	listGate *barrier
}

// barrier releases all its participants once the last one arrives, with a
// timeout so a missing participant fails the test instead of hanging the suite.
type barrier struct {
	mu      sync.Mutex
	pending int
	arrived int
	ch      chan struct{}
}

func newBarrier(n int) *barrier { return &barrier{pending: n, ch: make(chan struct{})} }

func (b *barrier) arrive() {
	b.mu.Lock()
	b.arrived++
	b.pending--
	if b.pending == 0 {
		close(b.ch)
	}
	b.mu.Unlock()
	select {
	case <-b.ch:
	case <-time.After(10 * time.Second):
	}
}

func (b *barrier) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.arrived
}

func newClaimStore(listers int) *claimStore {
	return &claimStore{sessions: make(map[string]*Session), listGate: newBarrier(listers)}
}

func (s *claimStore) add(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := sess
	s.sessions[sess.ID] = &cp
	s.order = append(s.order, sess.ID)
}

func (s *claimStore) RunningSessions(executorID string) ([]Session, error) {
	s.mu.Lock()
	out := make([]Session, 0, len(s.order))
	for _, id := range s.order {
		sess := s.sessions[id]
		if executorID == "" || sess.ExecutorID == executorID {
			out = append(out, *sess)
		}
	}
	s.mu.Unlock()

	// The snapshot is taken *before* the barrier and returned after it, so
	// every supervisor is holding the same pre-claim tokens by the time any of
	// them is allowed to proceed. Waiting first would let the winner claim and
	// mark the sessions requeued while the losers were still queued on the
	// mutex, and they would then find nothing to contend for.
	if s.listGate != nil {
		s.listGate.arrive() // no store lock held: blocking under it would deadlock
	}
	return out, nil
}

func (s *claimStore) ClaimRequeue(sessionID, claimToken string, at time.Time) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	sess, ok := s.sessions[sessionID]
	if !ok {
		return Session{}, fmt.Errorf("no such session %q", sessionID)
	}
	if !s.ignoreToken && sess.ClaimToken != claimToken {
		return Session{}, ErrSessionClaimLost
	}
	s.rotations++
	s.granted++
	sess.ClaimToken = fmt.Sprintf("%s-rotated-%d", sessionID, s.rotations)
	sess.Attempt++
	sess.ExecutorID = "" // requeued: no longer running on the dead node
	sess.StartedAt = at
	return *sess, nil
}

func (s *claimStore) CountRunning(executorID string) (int, error) {
	sessions, err := s.RunningSessionsNoGate(executorID)
	return len(sessions), err
}

// RunningSessionsNoGate is the ungated read used by CountRunning, which the
// candidate pool calls and which must not consume a barrier slot.
func (s *claimStore) RunningSessionsNoGate(executorID string) ([]Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.order))
	for _, id := range s.order {
		if sess := s.sessions[id]; executorID == "" || sess.ExecutorID == executorID {
			out = append(out, *sess)
		}
	}
	return out, nil
}

func (s *claimStore) stats() (attempts, granted int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts, s.granted
}

// failoverOutcome is what the concurrent-failover scenario observed.
type failoverOutcome struct {
	// handled counts FailoverHandler invocations per session ID — the number
	// the exactly-once guarantee is about.
	handled map[string]int
	// attempts and granted separate "how many supervisors contended" from
	// "how many won", so a test can prove the race happened before asserting
	// that only one supervisor came out of it.
	attempts  int
	granted   int
	gateCount int
	events    []FailoverEvent
}

// runConcurrentFailover stands up n independent supervisors — the split-brain
// case a control-plane restart produces — each with its own registry and its
// own health store, all sharing ONE session store. They observe the same
// executor go unreachable at the same instant and all try to requeue the same
// sessions.
//
// weakenGuard makes the shared store ignore the claim token, which is the
// falsification control: with the guard intact the handler must run once per
// session, and with it removed the same scenario must run it n times.
func runConcurrentFailover(t *testing.T, n, nsess int, weakenGuard bool) failoverOutcome {
	t.Helper()

	dead := newCapExec("edge-dead", fullCaps(func(c *Capabilities) { c.Isolation = IsolationRemote }))
	dead.failWith(errors.New("dial tcp 10.0.0.7:9000: connect: connection refused"))
	// The replacement is isolated so placement succeeds regardless of which
	// way the process-wide host-execution switch happens to be set.
	spare := newCapExec("edge-spare", fullCaps(func(c *Capabilities) { c.Isolation = IsolationContainer }))

	store := newClaimStore(n)
	store.ignoreToken = weakenGuard
	for i := 0; i < nsess; i++ {
		id := fmt.Sprintf("sess-%d", i)
		store.add(Session{
			ID: id, ExecutorID: dead.ID(), HandleID: "h-" + id,
			ProjectPath: "/projects/app", TaskID: 20162 + i,
			ClaimToken: "token-" + id, Attempt: 1, StartedAt: baseTime,
		})
	}

	var (
		hmu     sync.Mutex
		handled = make(map[string]int)
	)
	sink := &memSink{}

	// One failed probe is terminal here, so every supervisor reaches the
	// failover path on its very first round.
	cfg := probeTestConfig()
	cfg.Policy = HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}

	sups := make([]*Supervisor, 0, n)
	for i := 0; i < n; i++ {
		reg := NewRegistry()
		if err := reg.Register(dead); err != nil {
			t.Fatalf("Register(dead): %v", err)
		}
		if err := reg.Register(spare); err != nil {
			t.Fatalf("Register(spare): %v", err)
		}
		sups = append(sups, NewSupervisor(reg, cfg,
			WithClock(newFakeClock()),
			// Separate health stores on purpose: two control planes each keep
			// their own view, which is exactly why the exactly-once guarantee
			// cannot live in either of them.
			WithHealthStore(newMemHealthStore()),
			WithSessionStore(store),
			WithEventSink(sink),
			WithCandidateSource(func() []Candidate {
				return []Candidate{
					{Executor: dead, Health: Health{ExecutorID: dead.ID(), State: NodeUnreachable}},
					{Executor: spare, Health: Health{ExecutorID: spare.ID(), State: NodeReady}},
				}
			}),
			WithFailoverHandler(func(_ context.Context, ev FailoverEvent) error {
				hmu.Lock()
				handled[ev.Session.ID]++
				hmu.Unlock()
				return nil
			}),
		))
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, sv := range sups {
		wg.Add(1)
		go func(sv *Supervisor) {
			defer wg.Done()
			<-start
			sv.ProbeOnce(context.Background())
		}(sv)
	}
	close(start) // release them all on the same instant
	wg.Wait()

	attempts, granted := store.stats()
	hmu.Lock()
	snapshot := make(map[string]int, len(handled))
	for k, v := range handled {
		snapshot[k] = v
	}
	hmu.Unlock()

	return failoverOutcome{
		handled: snapshot, attempts: attempts, granted: granted,
		gateCount: store.listGate.count(), events: sink.failoverEvents(),
	}
}

// TestFailoverRequeuesExactlyOnceUnderConcurrentSupervisors is the guarantee
// that keeps two agents out of the same repository.
//
// Control planes get restarted, and briefly there may be two supervisors. Both
// will see the same edge device go unreachable and both will try to move its
// work. If the re-dispatch ran before the claim — or if the claim were not a
// single conditional write — the task would run twice and only afterwards would
// anyone discover it.
func TestFailoverRequeuesExactlyOnceUnderConcurrentSupervisors(t *testing.T) {
	const (
		supervisors = 8
		sessions    = 3
	)
	got := runConcurrentFailover(t, supervisors, sessions, false)

	// The race must actually have happened: every supervisor read the same
	// snapshot and every one of them tried to claim every session.
	if got.gateCount != supervisors {
		t.Fatalf("%d supervisors reached the session list, want %d — the race was not exercised",
			got.gateCount, supervisors)
	}
	if want := supervisors * sessions; got.attempts != want {
		t.Fatalf("%d claim attempts, want %d — every supervisor must have contended for every session",
			got.attempts, want)
	}

	// And exactly one of them won, per session.
	if got.granted != sessions {
		t.Fatalf("%d claims granted, want %d (one per session)", got.granted, sessions)
	}
	if len(got.handled) != sessions {
		t.Fatalf("failover handler ran for %d sessions, want %d", len(got.handled), sessions)
	}
	for id, n := range got.handled {
		if n != 1 {
			t.Fatalf("failover handler ran %d times for session %s, want exactly 1 — "+
				"a second re-dispatch means two agents editing the same repository", n, id)
		}
	}
	if len(got.events) != sessions {
		t.Fatalf("%d failover events, want %d (one per session)", len(got.events), sessions)
	}
	for _, ev := range got.events {
		if ev.Err != nil {
			t.Fatalf("failover event for %s carried error %v; the exactly-once assertion "+
				"must not pass merely because placement failed", ev.Session.ID, ev.Err)
		}
		if ev.From != "edge-dead" || ev.To != "edge-spare" {
			t.Errorf("failover event = %s -> %s, want edge-dead -> edge-spare", ev.From, ev.To)
		}
		// The handler receives the session carrying its NEW token, so a
		// subsequent requeue of the same session has something to match on.
		if !strings.Contains(ev.Session.ClaimToken, "rotated") {
			t.Errorf("session %s handed to the handler with token %q, want the rotated one",
				ev.Session.ID, ev.Session.ClaimToken)
		}
		if ev.Session.Attempt != 2 {
			t.Errorf("session %s attempt = %d, want 2", ev.Session.ID, ev.Session.Attempt)
		}
	}
}

// TestFailoverExactlyOnceGuardIsLoadBearing is the falsification control for
// the test above.
//
// It runs the identical scenario with the store's token comparison removed and
// asserts that the failover then happens once per supervisor. If this ever
// reports 1, the conditional claim has stopped being what produces exactly-once
// and the test above has quietly stopped proving anything.
func TestFailoverExactlyOnceGuardIsLoadBearing(t *testing.T) {
	const (
		supervisors = 8
		sessions    = 3
	)
	got := runConcurrentFailover(t, supervisors, sessions, true)

	if got.granted != supervisors*sessions {
		t.Fatalf("with the token check removed, %d claims were granted, want %d",
			got.granted, supervisors*sessions)
	}
	for id, n := range got.handled {
		if n <= 1 {
			t.Fatalf("session %s was failed over %d time(s) with the guard disabled — "+
				"the exactly-once test is not actually testing the guard", id, n)
		}
		if n != supervisors {
			t.Errorf("session %s failed over %d times, want %d (once per supervisor)", id, n, supervisors)
		}
	}
}

// TestFailoverRecordsUnplacedSessions: when there is nowhere to put the work,
// the claim still happens and the event still fires with the reason. Releasing
// the claim instead would re-arm the double-execution risk it exists to prevent.
func TestFailoverRecordsUnplacedSessions(t *testing.T) {
	dead := newCapExec("edge-dead", fullCaps(func(c *Capabilities) { c.Isolation = IsolationRemote }))
	dead.failWith(errors.New("connection refused"))

	store := newClaimStore(1)
	store.add(Session{ID: "sess-0", ExecutorID: "edge-dead", ClaimToken: "token-0", Attempt: 1})

	sink := &memSink{}
	handlerRuns := 0
	cfg := probeTestConfig()
	cfg.Policy = HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}

	reg := NewRegistry()
	_ = reg.Register(dead)
	sv := NewSupervisor(reg, cfg,
		WithClock(newFakeClock()),
		WithHealthStore(newMemHealthStore()),
		WithSessionStore(store),
		WithEventSink(sink),
		// The dead node is the only node, and placeReplacement excludes it.
		WithCandidateSource(func() []Candidate {
			return []Candidate{{Executor: dead, Health: Health{State: NodeUnreachable}}}
		}),
		WithFailoverHandler(func(context.Context, FailoverEvent) error {
			handlerRuns++
			return nil
		}),
	)

	sv.ProbeOnce(context.Background())

	events := sink.failoverEvents()
	if len(events) != 1 {
		t.Fatalf("%d failover events, want 1 — an unplaceable session must still be recorded", len(events))
	}
	ev := events[0]
	if ev.Err == nil || !errors.Is(ev.Err, ErrNoPlacement) {
		t.Fatalf("event error = %v, want a placement failure", ev.Err)
	}
	if ev.To != "" {
		t.Errorf("event target = %q, want empty when nothing could be placed", ev.To)
	}
	if ev.Reason == "" {
		t.Error("event carries no rendered reason; the event payload would be opaque")
	}
	if handlerRuns != 0 {
		t.Errorf("re-dispatch handler ran %d times with nowhere to dispatch to, want 0", handlerRuns)
	}
	// The claim was still consumed, so a second supervisor cannot re-run it.
	if _, granted := store.stats(); granted != 1 {
		t.Errorf("claims granted = %d, want 1 — the claim must not be released on placement failure", granted)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestSupervisorStartRacesRegistryChurn runs the real probe loop against a
// registry that is being mutated underneath it, which is the steady state for a
// control plane whose edge devices enroll and drop out continuously. It is here
// for -race, and for the assertion that shutdown does not deadlock: stop()
// cancels and then waits for in-flight probes, so anything that takes sv.mu on
// the way out would hang a control-plane restart forever.
func TestSupervisorStartRacesRegistryChurn(t *testing.T) {
	store := newMemHealthStore()
	sink := &memSink{}
	cfg := SupervisorConfig{
		Interval:            time.Millisecond,
		ProbeTimeout:        100 * time.Millisecond,
		BackoffBase:         time.Millisecond,
		BackoffMax:          5 * time.Millisecond,
		JitterFraction:      0.2,
		MaxConcurrentProbes: 4,
		Policy:              HealthPolicy{DegradeAfter: 1, UnreachableAfter: 2},
	}
	// A real clock: the point of this test is genuine concurrency, not
	// simulated time.
	sv, reg := newSupervisorFixture(t, cfg,
		WithHealthStore(store), WithEventSink(sink),
		WithSessionStore(&drainStore{counts: []int{0}}))

	stable := newCapExec("stable-1", fullCaps(nil))
	flaky := newCapExec("stable-2", fullCaps(nil))
	flaky.failWith(errors.New("intermittent"))
	_ = reg.Register(stable)
	_ = reg.Register(flaky)

	stop := sv.Start(context.Background())

	// Starting twice must be a no-op that still yields a usable stop.
	stopAgain := sv.Start(context.Background())

	quit := make(chan struct{})
	var wg sync.WaitGroup

	// Registry churn: devices enrolling and dropping out.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-quit:
					return
				default:
				}
				id := fmt.Sprintf("dyn-%d-%d", i, n%3)
				_ = reg.Ensure(newCapExec(id, fullCaps(nil)))
				_ = reg.Bind("/projects/app", "stable-1")
				_, _ = reg.Resolve("/projects/app")
				_ = reg.List()
				reg.Unregister(id)
				reg.Unbind("/projects/app")
			}
		}(i)
	}

	// Operators cordoning and uncordoning while probes land.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := fmt.Sprintf("stable-%d", i+1)
			for {
				select {
				case <-quit:
					return
				default:
				}
				_, _ = sv.Cordon(target, "operator")
				_ = sv.Health(target)
				_, _ = sv.Drain(target, "retiring")
				_, _ = sv.Uncordon(target)
				_ = sv.Health("dyn-0-0")
				sv.ProbeOnce(context.Background())
			}
		}(i)
	}

	time.Sleep(300 * time.Millisecond)
	close(quit)
	wg.Wait()

	// stop() must return promptly. A watchdog rather than a bare call: a
	// deadlock here would otherwise show up as a whole-suite timeout with no
	// indication of which test hung.
	done := make(chan struct{})
	go func() {
		stop()
		stopAgain()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stop() did not return: the supervisor deadlocked on shutdown")
	}

	// Calling stop again after the loop has exited must also be safe.
	stop()

	if n := stable.probeCount(); n == 0 {
		t.Fatal("no probes ran at all; the race test asserted nothing")
	}
	if _, ok := store.get("stable-1"); !ok {
		t.Error("no health record was persisted for stable-1")
	}
}

// TestFailoverUsesTheRegistryPoolByDefault exercises the default candidate
// source — no WithCandidateSource, so the replacement pool is assembled from
// the registry with persisted health and live load attached. That wiring is
// what a production control plane actually runs, and getting it wrong would
// send requeued work to a node the supervisor already knows is dead or full.
func TestFailoverUsesTheRegistryPoolByDefault(t *testing.T) {
	iso := func(c *Capabilities) { c.Isolation = IsolationContainer }

	dead := newCapExec("edge-dead", fullCaps(func(c *Capabilities) { c.Isolation = IsolationRemote }))
	dead.failWith(errors.New("connection refused"))
	// edge-sick was already given up on in an earlier round and is still down,
	// so its probe in this round changes nothing and leaves it unreachable.
	sick := newCapExec("edge-sick", fullCaps(iso))
	sick.failWith(errors.New("still down"))
	full := newCapExec("edge-full", fullCaps(func(c *Capabilities) {
		iso(c)
		c.MaxConcurrent = 1
	}))
	spare := newCapExec("edge-spare", fullCaps(iso))

	store := newClaimStore(1)
	store.add(Session{ID: "sess-0", ExecutorID: "edge-dead", ClaimToken: "token-0", Attempt: 1})
	// edge-full is already running its one permitted session.
	store.add(Session{ID: "sess-busy", ExecutorID: "edge-full", ClaimToken: "token-busy", Attempt: 1})

	health := newMemHealthStore()
	// The pool must carry persisted health rather than assuming everything
	// registered is ready.
	_ = health.SaveHealth(Health{ExecutorID: "edge-sick", State: NodeUnreachable, ConsecutiveFailures: 9})

	sink := &memSink{}
	cfg := probeTestConfig()
	cfg.Policy = HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}

	reg := NewRegistry()
	for _, ex := range []*capExec{dead, sick, full, spare} {
		if err := reg.Register(ex); err != nil {
			t.Fatalf("Register(%s): %v", ex.ID(), err)
		}
	}
	sv := NewSupervisor(reg, cfg,
		WithClock(newFakeClock()),
		WithHealthStore(health),
		WithSessionStore(store),
		WithEventSink(sink),
		WithFailoverHandler(func(context.Context, FailoverEvent) error { return nil }),
	)

	sv.ProbeOnce(context.Background())

	events := sink.failoverEvents()
	if len(events) != 1 {
		t.Fatalf("%d failover events, want 1", len(events))
	}
	ev := events[0]
	if ev.Err != nil {
		t.Fatalf("failover error = %v, want a successful placement", ev.Err)
	}
	if ev.To != "edge-spare" {
		t.Fatalf("requeued onto %q, want edge-spare — the dead node is excluded, edge-sick is "+
			"unreachable in the health store, and edge-full is at its advertised ceiling", ev.To)
	}
	if ev.Session.ID != "sess-0" {
		t.Errorf("requeued session = %q, want sess-0 (the one on the dead node)", ev.Session.ID)
	}
}
