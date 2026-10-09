package executor

// The failover cap (Task 20391): executors.failover.max_attempts bounds how
// often one dispatch is started again elsewhere after the node running it went
// unreachable. These drive the real supervisor against a store that applies
// the cap the way the SQL claim does — inside the claim, under one lock.

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// capFixture is one dead node holding one session, a spare to fail over to,
// and a supervisor whose handler and placement are counted.
type capFixture struct {
	store      *claimStore
	sink       *memSink
	handled    []FailoverEvent
	placements int
	mu         sync.Mutex
}

func (f *capFixture) supervisor(t *testing.T, limit func() int, extra ...SupervisorOption) *Supervisor {
	t.Helper()
	dead := newCapExec("edge-dead", fullCaps(func(c *Capabilities) { c.Isolation = IsolationRemote }))
	dead.failWith(errors.New("connection refused"))
	spare := newCapExec("edge-spare", fullCaps(nil))

	cfg := probeTestConfig()
	cfg.Policy = HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}
	reg := NewRegistry()
	for _, ex := range []*capExec{dead, spare} {
		if err := reg.Register(ex); err != nil {
			t.Fatal(err)
		}
	}
	opts := []SupervisorOption{
		WithClock(newFakeClock()),
		WithHealthStore(newMemHealthStore()),
		WithSessionStore(f.store),
		WithEventSink(f.sink),
		WithCandidateSource(func() []Candidate {
			f.mu.Lock()
			f.placements++
			f.mu.Unlock()
			return []Candidate{
				{Executor: dead, Health: Health{ExecutorID: dead.ID(), State: NodeUnreachable}},
				{Executor: spare, Health: Health{ExecutorID: spare.ID(), State: NodeReady}},
			}
		}),
		WithFailoverHandler(func(_ context.Context, ev FailoverEvent) error {
			f.mu.Lock()
			f.handled = append(f.handled, ev)
			f.mu.Unlock()
			return nil
		}),
	}
	if limit != nil {
		opts = append(opts, WithFailoverLimit(limit))
	}
	opts = append(opts, extra...)
	return NewSupervisor(reg, cfg, opts...)
}

func newCapFixture(listers int, attempt int) *capFixture {
	f := &capFixture{store: newClaimStore(listers), sink: &memSink{}}
	f.store.add(Session{
		ID: "sess-cap", ExecutorID: "edge-dead", ClaimToken: "tok-cap",
		Attempt: attempt, ProjectPath: "/projects/app",
	})
	return f
}

func (f *capFixture) events() []FailoverEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FailoverEvent(nil), f.handled...)
}

// TestFailoverAtTheCapStillRedispatches: a session re-dispatched once, under a
// cap of two, has one re-dispatch left and gets it.
func TestFailoverAtTheCapStillRedispatches(t *testing.T) {
	f := newCapFixture(1, 2) // the original dispatch plus one re-dispatch
	sv := f.supervisor(t, func() int { return 2 })
	sv.ProbeOnce(context.Background())

	evs := f.events()
	if len(evs) != 1 {
		t.Fatalf("handler ran %d times, want once", len(evs))
	}
	ev := evs[0]
	if ev.Exhausted || ev.Err != nil || ev.To != "edge-spare" {
		t.Fatalf("event = exhausted %v, err %v, to %q; want a placed re-dispatch to edge-spare", ev.Exhausted, ev.Err, ev.To)
	}
	if ev.MaxAttempts != 2 {
		t.Errorf("decided under cap %d, want 2", ev.MaxAttempts)
	}
	if f.store.isExhausted("sess-cap") {
		t.Error("the store closed a session that still had a re-dispatch left")
	}
	if ev.Unreachable.IsZero() {
		t.Error("the event does not say when the node went unreachable")
	}
}

// TestFailoverPastTheCapNeverRedispatches: a session already re-dispatched as
// often as the cap allows is closed, not moved — no placement is even looked
// for, because a replacement chosen now is the next node the workload would
// take down.
func TestFailoverPastTheCapNeverRedispatches(t *testing.T) {
	f := newCapFixture(1, 3) // the original dispatch plus two re-dispatches
	sv := f.supervisor(t, func() int { return 2 })
	sv.ProbeOnce(context.Background())

	evs := f.events()
	if len(evs) != 1 {
		t.Fatalf("handler ran %d times, want once — to settle the tasks, not to move them", len(evs))
	}
	ev := evs[0]
	if !ev.Exhausted {
		t.Fatal("the event is not marked exhausted")
	}
	if ev.To != "" {
		t.Errorf("an exhausted session was given a replacement: %q", ev.To)
	}
	if !errors.Is(ev.Err, ErrFailoverExhausted) || ev.Reason == "" {
		t.Errorf("event error = %v (reason %q), want ErrFailoverExhausted with a reason", ev.Err, ev.Reason)
	}
	if f.placements != 0 {
		t.Errorf("placement was consulted %d time(s) for an exhausted session", f.placements)
	}
	if !f.store.isExhausted("sess-cap") {
		t.Error("the store did not record the session as exhausted")
	}
	sinkEvents := f.sink.failoverEvents()
	if len(sinkEvents) != 1 || !sinkEvents[0].Exhausted {
		t.Fatalf("event sink saw %+v, want one exhausted failover", sinkEvents)
	}

	// Nothing about the session is left to claim: the next round finds it
	// gone and re-dispatches nothing.
	sv.ProbeOnce(context.Background())
	if n := len(f.events()); n != 1 {
		t.Fatalf("a later round ran the handler again (%d calls)", n)
	}
}

// TestFailoverCapZeroMeansNoRedispatch: max_attempts 0 ends the run on the
// first lost node.
func TestFailoverCapZeroMeansNoRedispatch(t *testing.T) {
	f := newCapFixture(1, 1)
	sv := f.supervisor(t, func() int { return 0 })
	sv.ProbeOnce(context.Background())
	evs := f.events()
	if len(evs) != 1 || !evs[0].Exhausted || evs[0].To != "" {
		t.Fatalf("events = %+v, want one exhausted, unplaced event", evs)
	}
}

// TestFailoverLimitIsBoundedAndReadPerClaim: whatever the source says, the
// cap in force is inside [0, MaxFailoverAttemptsCeiling] — a bad value is
// never "no cap" — and it is read at each claim, so lowering it takes effect
// without a restart. With no source the default applies.
func TestFailoverLimitIsBoundedAndReadPerClaim(t *testing.T) {
	cases := []struct {
		name string
		src  func() int
		want int
	}{
		{"unset", nil, DefaultMaxFailoverAttempts},
		{"negative", func() int { return -3 }, 0},
		{"huge", func() int { return 1 << 30 }, MaxFailoverAttemptsCeiling},
		{"in band", func() int { return 4 }, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sv := NewSupervisor(NewRegistry(), probeTestConfig(), WithFailoverLimit(tc.src))
			if got := sv.maxFailoverAttempts(); got != tc.want {
				t.Fatalf("cap = %d, want %d", got, tc.want)
			}
		})
	}

	limit := 5
	sv := NewSupervisor(NewRegistry(), probeTestConfig(), WithFailoverLimit(func() int { return limit }))
	if sv.maxFailoverAttempts() != 5 {
		t.Fatal("first read")
	}
	limit = 1
	if got := sv.maxFailoverAttempts(); got != 1 {
		t.Fatalf("after lowering the setting the cap is %d, want 1 — it must be read per claim", got)
	}
}

// TestTwoSupervisorsRacingAtTheCap: two supervisors — a restarting hub and its
// successor, or two hub members — see the same node die at the same instant,
// holding a session past the cap. Exactly one claims it, exactly one handler
// call settles it, and nothing is re-dispatched. Then the same race one
// attempt earlier, at the cap: exactly one re-dispatch, not two.
func TestTwoSupervisorsRacingAtTheCap(t *testing.T) {
	for _, tc := range []struct {
		name          string
		attempt       int
		wantExhausted bool
	}{
		{"past the cap", 3, true},
		{"at the cap", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCapFixture(2, tc.attempt)
			a := f.supervisor(t, func() int { return 2 })
			b := f.supervisor(t, func() int { return 2 })

			start := make(chan struct{})
			var wg sync.WaitGroup
			for _, sv := range []*Supervisor{a, b} {
				wg.Add(1)
				go func(sv *Supervisor) {
					defer wg.Done()
					<-start
					sv.ProbeOnce(context.Background())
				}(sv)
			}
			close(start)
			wg.Wait()

			if n := f.store.listGate.count(); n != 2 {
				t.Fatalf("%d supervisors reached the session list, want 2 — the race was not exercised", n)
			}
			attempts, granted := f.store.stats()
			if attempts != 2 || granted != 1 {
				t.Fatalf("claims attempted %d, granted %d; want both supervisors to contend and one to win", attempts, granted)
			}
			evs := f.events()
			if len(evs) != 1 {
				t.Fatalf("the handler ran %d times across both supervisors, want exactly once", len(evs))
			}
			ev := evs[0]
			if ev.Exhausted != tc.wantExhausted {
				t.Fatalf("exhausted = %v, want %v", ev.Exhausted, tc.wantExhausted)
			}
			redispatched := 0
			for _, e := range evs {
				if e.To != "" && !e.Exhausted {
					redispatched++
				}
			}
			want := 1
			if tc.wantExhausted {
				want = 0
			}
			if redispatched != want {
				t.Fatalf("%d re-dispatches, want %d", redispatched, want)
			}
			if f.store.isExhausted("sess-cap") != tc.wantExhausted {
				t.Fatalf("the store's record (exhausted=%v) disagrees with the event", f.store.isExhausted("sess-cap"))
			}
		})
	}
}

// TestRacingSupervisorsWithDifferentCapsRecordOneDecision: hub members whose
// per-instance overlays set different caps race for one session. Whichever
// wins decides, the store records that decision, and the loser — whose cap
// would have decided differently — acts on nothing.
func TestRacingSupervisorsWithDifferentCapsRecordOneDecision(t *testing.T) {
	f := newCapFixture(2, 3)
	strict := f.supervisor(t, func() int { return 2 })
	lenient := f.supervisor(t, func() int { return 5 })

	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, sv := range []*Supervisor{strict, lenient} {
		wg.Add(1)
		go func(sv *Supervisor) {
			defer wg.Done()
			<-start
			sv.ProbeOnce(context.Background())
		}(sv)
	}
	close(start)
	wg.Wait()

	evs := f.events()
	if len(evs) != 1 {
		t.Fatalf("handler ran %d times, want once", len(evs))
	}
	ev := evs[0]
	wantExhausted := ev.MaxAttempts == 2
	if ev.Exhausted != wantExhausted {
		t.Fatalf("decided under cap %d: exhausted = %v, want %v", ev.MaxAttempts, ev.Exhausted, wantExhausted)
	}
	if f.store.isExhausted("sess-cap") != ev.Exhausted {
		t.Fatal("the stored decision differs from the one the handler was given")
	}
	f.store.mu.Lock()
	caps := append([]int(nil), f.store.caps...)
	f.store.mu.Unlock()
	if len(caps) != 1 || caps[0] != ev.MaxAttempts {
		t.Fatalf("granted claims were decided under caps %v, want exactly the winner's %d", caps, ev.MaxAttempts)
	}
}

// TestCandidateFilterKeepsAnExecutorOutOfPlacement (Task 20396): the control
// plane can rule an executor out as a failover target — one restricted to an
// access list, which nobody can be checked against when the supervisor moves
// a run. A filtered spare is no candidate, so the session has nowhere to go
// and the failover reports it, rather than landing it there.
func TestCandidateFilterKeepsAnExecutorOutOfPlacement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		allow  bool
		wantTo string
	}{
		{"the spare is allowed", true, "edge-spare"},
		{"the spare is filtered out", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCapFixture(1, 1)
			var asked []string
			sv := f.supervisor(t, func() int { return 2 }, WithCandidateFilter(func(ex Executor) bool {
				asked = append(asked, ex.ID())
				return tc.allow || ex.ID() != "edge-spare"
			}))
			sv.ProbeOnce(context.Background())
			evs := f.events()
			if len(evs) != 1 {
				t.Fatalf("handler ran %d times, want once", len(evs))
			}
			ev := evs[0]
			if ev.To != tc.wantTo {
				t.Fatalf("placed on %q, want %q", ev.To, tc.wantTo)
			}
			if tc.wantTo == "" && ev.Err == nil {
				t.Error("a session with every candidate filtered out reports no error")
			}
			for _, id := range asked {
				if id == "edge-dead" {
					t.Error("the filter was asked about the node that just died; it is never a candidate")
				}
			}
		})
	}
}

// TestFailoverNeverBringsAnIsolatedRunOntoTheHost (Task 20396): a run that was
// isolated from the control-plane host stays off it. The dead node is a
// device; the only other executor is the hub's own host driver, which no
// concurrency limit ranks above anything — the session has nowhere to go
// rather than being moved onto the hub.
func TestFailoverNeverBringsAnIsolatedRunOntoTheHost(t *testing.T) {
	f := newCapFixture(1, 1)
	dead := newCapExec("edge-dead", fullCaps(func(c *Capabilities) { c.Isolation = IsolationRemote }))
	dead.failWith(errors.New("connection refused"))
	host := newCapExec("hub-host", fullCaps(func(c *Capabilities) {
		c.Isolation = IsolationNone
		c.MaxConcurrent = 0
	}))
	reg := NewRegistry()
	for _, ex := range []*capExec{dead, host} {
		if err := reg.Register(ex); err != nil {
			t.Fatal(err)
		}
	}
	cfg := probeTestConfig()
	cfg.Policy = HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}
	sv := NewSupervisor(reg, cfg,
		WithClock(newFakeClock()),
		WithHealthStore(newMemHealthStore()),
		WithSessionStore(f.store),
		WithEventSink(f.sink),
		WithFailoverLimit(func() int { return 2 }),
		WithFailoverHandler(func(_ context.Context, ev FailoverEvent) error {
			f.mu.Lock()
			f.handled = append(f.handled, ev)
			f.mu.Unlock()
			return nil
		}),
	)
	if !HostExecutionAllowed() {
		t.Skip("host execution is denied process-wide; the policy alone would refuse the host")
	}
	sv.ProbeOnce(context.Background())
	evs := f.events()
	if len(evs) != 1 {
		t.Fatalf("handler ran %d times, want once", len(evs))
	}
	if evs[0].To != "" {
		t.Fatalf("a run isolated on a device was failed over onto %q, the hub's own host", evs[0].To)
	}
	var pe *PlacementError
	if !errors.As(evs[0].Err, &pe) || pe.Constraint != ConstraintIsolation {
		t.Errorf("the failover reports %v, want the isolation constraint named", evs[0].Err)
	}
}
