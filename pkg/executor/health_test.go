package executor

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// baseTime is a fixed, readable instant so a failing assertion prints a
// comprehensible timestamp instead of whatever "now" happened to be.
var baseTime = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// stepClock hands out an explicitly advancing sequence of instants.
//
// ObserveProbe takes its `at` as a parameter, so the state machine needs no
// Clock at all — this is just a readable way to say "and then, thirty seconds
// later" without any test ever sleeping.
type stepClock struct{ now time.Time }

func newStepClock() *stepClock { return &stepClock{now: baseTime} }

func (c *stepClock) tick(d time.Duration) time.Time {
	c.now = c.now.Add(d)
	return c.now
}

// TestObserveProbeDegradesThenGivesUp walks the probe-owned states in order and
// checks every bookkeeping field at each step, because the UI computes
// "unreachable for 4m" from StateChangedAt and "last seen 10m ago" from
// LastSeen, and getting either wrong is invisible until an operator is trying
// to decide whether a device is worth power-cycling.
func TestObserveProbeDegradesThenGivesUp(t *testing.T) {
	clk := newStepClock()
	policy := HealthPolicy{DegradeAfter: 2, UnreachableAfter: 4}
	h := Health{ExecutorID: "edge-1"}

	// One missed probe is a blip — a wifi roam, a GC pause on a Pi. It must
	// not move a node out of ready.
	t1 := clk.tick(30 * time.Second)
	h, tr := ObserveProbe(h, errors.New("dial tcp: i/o timeout"), t1, policy)
	if tr != nil {
		t.Fatalf("first failure produced transition %v, want none below DegradeAfter", tr)
	}
	if h.State != NodeReady {
		t.Fatalf("state after 1 failure = %q, want ready (DegradeAfter=2)", h.State)
	}
	if h.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", h.ConsecutiveFailures)
	}
	if !h.LastProbe.Equal(t1) {
		t.Errorf("LastProbe = %v, want %v", h.LastProbe, t1)
	}
	if !h.LastSeen.IsZero() {
		t.Errorf("LastSeen = %v after a failed probe, want zero — a failure is not a sighting", h.LastSeen)
	}
	if h.Reason != "dial tcp: i/o timeout" {
		t.Errorf("Reason = %q, want the probe error", h.Reason)
	}

	// Second failure crosses DegradeAfter.
	t2 := clk.tick(30 * time.Second)
	h, tr = ObserveProbe(h, errors.New("dial tcp: i/o timeout"), t2, policy)
	if tr == nil {
		t.Fatal("crossing DegradeAfter produced no transition")
	}
	if tr.From != NodeReady || tr.To != NodeDegraded {
		t.Errorf("transition = %s -> %s, want ready -> degraded", tr.From, tr.To)
	}
	if tr.ExecutorID != "edge-1" || !tr.At.Equal(t2) {
		t.Errorf("transition = %+v, want executor edge-1 at %v", tr, t2)
	}
	if h.State != NodeDegraded || h.ConsecutiveFailures != 2 {
		t.Fatalf("health = %s/%d failures, want degraded/2", h.State, h.ConsecutiveFailures)
	}
	if !h.StateChangedAt.Equal(t2) {
		t.Errorf("StateChangedAt = %v, want %v", h.StateChangedAt, t2)
	}

	// Third failure is still below UnreachableAfter: the state is unchanged,
	// so no transition is emitted, but the reason refreshes to the current
	// error. A node unreachable for an hour should show why it is failing now.
	t3 := clk.tick(30 * time.Second)
	h, tr = ObserveProbe(h, errors.New("connection refused"), t3, policy)
	if tr != nil {
		t.Fatalf("degraded -> degraded produced transition %v, want none", tr)
	}
	if h.State != NodeDegraded {
		t.Fatalf("state = %q, want degraded", h.State)
	}
	if h.Reason != "connection refused" {
		t.Errorf("Reason = %q, want it refreshed to the newest probe error", h.Reason)
	}
	if !h.StateChangedAt.Equal(t2) {
		t.Errorf("StateChangedAt = %v, want it pinned to %v — the state did not change", h.StateChangedAt, t2)
	}
	if !h.LastProbe.Equal(t3) {
		t.Errorf("LastProbe = %v, want %v", h.LastProbe, t3)
	}

	// Fourth failure crosses UnreachableAfter: work gets failed over here.
	t4 := clk.tick(30 * time.Second)
	h, tr = ObserveProbe(h, errors.New("connection refused"), t4, policy)
	if tr == nil || tr.From != NodeDegraded || tr.To != NodeUnreachable {
		t.Fatalf("transition = %v, want degraded -> unreachable", tr)
	}
	if h.State != NodeUnreachable || h.ConsecutiveFailures != 4 {
		t.Fatalf("health = %s/%d, want unreachable/4", h.State, h.ConsecutiveFailures)
	}
	if !h.StateChangedAt.Equal(t4) {
		t.Errorf("StateChangedAt = %v, want %v", h.StateChangedAt, t4)
	}

	// Further failures must not re-emit: failover already ran, and flapping
	// the state would re-arm it for sessions that were already moved.
	t5 := clk.tick(30 * time.Second)
	h, tr = ObserveProbe(h, errors.New("no route to host"), t5, policy)
	if tr != nil {
		t.Fatalf("unreachable -> unreachable produced transition %v, want none", tr)
	}
	if h.ConsecutiveFailures != 5 || h.Reason != "no route to host" {
		t.Errorf("health = %d failures / %q, want 5 / the newest error", h.ConsecutiveFailures, h.Reason)
	}
	if !h.StateChangedAt.Equal(t4) {
		t.Errorf("StateChangedAt moved to %v while staying unreachable, want %v", h.StateChangedAt, t4)
	}
}

// TestObserveProbeSuccessResetsToReady covers the recovery edge: one good probe
// is enough, and it clears the failure count rather than decrementing it.
func TestObserveProbeSuccessResetsToReady(t *testing.T) {
	clk := newStepClock()
	policy := HealthPolicy{DegradeAfter: 1, UnreachableAfter: 2}

	h := Health{ExecutorID: "edge-1"}
	for i := 0; i < 3; i++ {
		h, _ = ObserveProbe(h, errors.New("down"), clk.tick(time.Second), policy)
	}
	if h.State != NodeUnreachable {
		t.Fatalf("setup: state = %q, want unreachable", h.State)
	}

	at := clk.tick(time.Second)
	h, tr := ObserveProbe(h, nil, at, policy)
	if tr == nil || tr.From != NodeUnreachable || tr.To != NodeReady {
		t.Fatalf("transition = %v, want unreachable -> ready", tr)
	}
	if tr.Reason != "probe succeeded" {
		t.Errorf("transition reason = %q, want %q", tr.Reason, "probe succeeded")
	}
	if h.State != NodeReady {
		t.Fatalf("state = %q, want ready", h.State)
	}
	if h.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0 — a success resets, it does not decrement", h.ConsecutiveFailures)
	}
	if !h.LastSeen.Equal(at) || !h.LastProbe.Equal(at) || !h.StateChangedAt.Equal(at) {
		t.Errorf("timestamps = seen %v / probe %v / changed %v, want all %v",
			h.LastSeen, h.LastProbe, h.StateChangedAt, at)
	}

	// A second success on an already-ready node is not a transition, but it
	// still advances LastSeen — that is the liveness signal Stale reads.
	next := clk.tick(30 * time.Second)
	h, tr = ObserveProbe(h, nil, next, policy)
	if tr != nil {
		t.Fatalf("ready -> ready produced transition %v, want none", tr)
	}
	if !h.LastSeen.Equal(next) {
		t.Errorf("LastSeen = %v, want it advanced to %v on every success", h.LastSeen, next)
	}
	if !h.StateChangedAt.Equal(at) {
		t.Errorf("StateChangedAt = %v, want it pinned to %v", h.StateChangedAt, at)
	}
}

// TestProbeNeverLeavesAdminHeldState is the invariant that makes cordon usable
// at all.
//
// An operator who cordons a node to investigate it must not have that decision
// silently reverted because the node answered a health check three seconds
// later. Both directions are asserted explicitly: a *successful* probe on a
// cordoned node must leave it cordoned (while still recording the sighting),
// and a *failing* probe must not push it to unreachable either.
func TestProbeNeverLeavesAdminHeldState(t *testing.T) {
	for _, held := range []struct {
		name  string
		state NodeState
		apply func(Health, string, time.Time) (Health, *Transition)
	}{
		{"cordoned", NodeCordoned, Cordon},
		{"draining", NodeDraining, Drain},
	} {
		t.Run(held.name, func(t *testing.T) {
			clk := newStepClock()
			policy := HealthPolicy{DegradeAfter: 1, UnreachableAfter: 2}

			heldAt := clk.tick(time.Second)
			h, tr := held.apply(Health{ExecutorID: "edge-1"}, "investigating", heldAt)
			if tr == nil || tr.From != NodeReady || tr.To != held.state {
				t.Fatalf("admin transition = %v, want ready -> %s", tr, held.state)
			}
			if h.State != held.state || h.Reason != "investigating" {
				t.Fatalf("health = %s/%q, want %s/investigating", h.State, h.Reason, held.state)
			}

			// Direction 1: a SUCCESSFUL probe must not un-hold the node, but
			// must still record the sighting. "Held, and answering" is exactly
			// what an operator wants to see before uncordoning.
			okAt := clk.tick(30 * time.Second)
			h, tr = ObserveProbe(h, nil, okAt, policy)
			if tr != nil {
				t.Fatalf("a successful probe on a %s node produced transition %v — "+
					"an operator's decision must not be reverted by a health check", held.name, tr)
			}
			if h.State != held.state {
				t.Fatalf("state after successful probe = %q, want %s", h.State, held.state)
			}
			if !h.LastSeen.Equal(okAt) {
				t.Errorf("LastSeen = %v, want %v — a held node that answers is still a sighting", h.LastSeen, okAt)
			}
			if !h.LastProbe.Equal(okAt) {
				t.Errorf("LastProbe = %v, want %v", h.LastProbe, okAt)
			}
			if !h.StateChangedAt.Equal(heldAt) {
				t.Errorf("StateChangedAt = %v, want it pinned to the admin action at %v", h.StateChangedAt, heldAt)
			}
			if h.ConsecutiveFailures != 0 {
				t.Errorf("ConsecutiveFailures = %d, want 0 after a success", h.ConsecutiveFailures)
			}

			// Direction 2: FAILING probes must not push a held node to
			// unreachable either. The count keeps rising (see the uncordon
			// test) but the state is not the probe's to change.
			for i := 1; i <= 5; i++ {
				at := clk.tick(30 * time.Second)
				var trFail *Transition
				h, trFail = ObserveProbe(h, errors.New("connection refused"), at, policy)
				if trFail != nil {
					t.Fatalf("failing probe %d on a %s node produced transition %v, want none", i, held.name, trFail)
				}
				if h.State != held.state {
					t.Fatalf("state after %d failures = %q, want %s", i, h.State, held.state)
				}
				if h.ConsecutiveFailures != i {
					t.Errorf("ConsecutiveFailures = %d, want %d — failures are counted while held", h.ConsecutiveFailures, i)
				}
				if !h.LastSeen.Equal(okAt) {
					t.Errorf("LastSeen = %v, want it frozen at the last success %v", h.LastSeen, okAt)
				}
				if !h.StateChangedAt.Equal(heldAt) {
					t.Errorf("StateChangedAt = %v, want it pinned to %v", h.StateChangedAt, heldAt)
				}
			}
		})
	}
}

// TestUncordonLandsInTheStateProbesJustify checks that uncordon cannot be used
// to launder a broken node into the schedulable set: a node whose probes were
// failing the whole time it was held comes back degraded or unreachable, not
// optimistically ready.
func TestUncordonLandsInTheStateProbesJustify(t *testing.T) {
	policy := HealthPolicy{DegradeAfter: 2, UnreachableAfter: 4}

	cases := []struct {
		name     string
		failures int
		want     NodeState
		wantMsg  string
	}{
		{"healthy while held", 0, NodeReady, "uncordoned"},
		{"still flaky while held", 2, NodeDegraded, "uncordoned; probes still failing"},
		{"gone the whole time", 4, NodeUnreachable, "uncordoned; probes still failing"},
		{"far past the threshold", 99, NodeUnreachable, "uncordoned; probes still failing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newStepClock()
			heldAt := clk.tick(time.Second)
			h, _ := Cordon(Health{ExecutorID: "edge-1"}, "maintenance", heldAt)
			h.ConsecutiveFailures = tc.failures

			at := clk.tick(20 * time.Minute)
			got, tr := Uncordon(h, at, policy)
			if tr == nil {
				t.Fatalf("Uncordon of a cordoned node produced no transition")
			}
			if tr.From != NodeCordoned || tr.To != tc.want {
				t.Errorf("transition = %s -> %s, want cordoned -> %s", tr.From, tr.To, tc.want)
			}
			if got.State != tc.want {
				t.Fatalf("state = %q, want %q after %d failures while held", got.State, tc.want, tc.failures)
			}
			if got.Reason != tc.wantMsg {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantMsg)
			}
			if !got.StateChangedAt.Equal(at) {
				t.Errorf("StateChangedAt = %v, want %v", got.StateChangedAt, at)
			}
			// Uncordon reports what the probes justify; it does not forgive
			// the failures that got us here.
			if got.ConsecutiveFailures != tc.failures {
				t.Errorf("ConsecutiveFailures = %d, want it preserved at %d", got.ConsecutiveFailures, tc.failures)
			}
		})
	}

	// Draining is admin-held too, so uncordon releases it the same way.
	h, _ := Drain(Health{ExecutorID: "edge-1"}, "", baseTime)
	got, tr := Uncordon(h, baseTime.Add(time.Minute), policy)
	if tr == nil || tr.From != NodeDraining || tr.To != NodeReady || got.State != NodeReady {
		t.Fatalf("Uncordon of a draining node = (%q, %v), want ready", got.State, tr)
	}
}

// TestUncordonOfNonAdminHeldNodeIsNoop: uncordoning something that was never
// held must not stamp a fresh StateChangedAt or emit a bogus event.
func TestUncordonOfNonAdminHeldNodeIsNoop(t *testing.T) {
	for _, state := range []NodeState{NodeReady, NodeDegraded, NodeUnreachable} {
		h := Health{
			ExecutorID:          "edge-1",
			State:               state,
			ConsecutiveFailures: 7,
			StateChangedAt:      baseTime,
			Reason:              "original reason",
		}
		got, tr := Uncordon(h, baseTime.Add(time.Hour), DefaultHealthPolicy())
		if tr != nil {
			t.Errorf("Uncordon(%s) produced transition %v, want nil", state, tr)
		}
		if got.State != state {
			t.Errorf("Uncordon(%s) changed state to %q", state, got.State)
		}
		if !got.StateChangedAt.Equal(baseTime) || got.Reason != "original reason" {
			t.Errorf("Uncordon(%s) rewrote bookkeeping: %+v", state, got)
		}
	}
}

// TestCordonIsIdempotent: re-cordoning an already-cordoned node emits nothing,
// so a UI that fires the action twice does not produce two events.
func TestCordonIsIdempotent(t *testing.T) {
	h, tr := Cordon(Health{ExecutorID: "edge-1"}, "first", baseTime)
	if tr == nil {
		t.Fatal("first Cordon produced no transition")
	}
	again, tr := Cordon(h, "second", baseTime.Add(time.Hour))
	if tr != nil {
		t.Fatalf("re-cordoning produced transition %v, want nil", tr)
	}
	if again.Reason != "first" || !again.StateChangedAt.Equal(baseTime) {
		t.Errorf("re-cordoning rewrote the record: %+v", again)
	}

	// Cordon and Drain differ in intent, so moving between them is a real
	// transition an operator should see.
	drained, tr := Drain(again, "", baseTime.Add(2*time.Hour))
	if tr == nil || tr.From != NodeCordoned || tr.To != NodeDraining {
		t.Fatalf("Drain of a cordoned node = %v, want cordoned -> draining", tr)
	}
	if drained.Reason != "draining by operator" {
		t.Errorf("Reason = %q, want the default operator note", drained.Reason)
	}
	// Cordon's default reason is likewise filled in when none is given.
	if h2, _ := Cordon(Health{}, "   ", baseTime); h2.Reason != "cordoned by operator" {
		t.Errorf("blank Cordon reason = %q, want the default", h2.Reason)
	}
}

// TestObserveProbeReasonIsBounded: probe errors can carry an entire HTTP
// response body, and a reason lands in a table cell and an event payload.
func TestObserveProbeReasonIsBounded(t *testing.T) {
	policy := DefaultHealthPolicy()

	h, _ := ObserveProbe(Health{}, errors.New("first line\nsecond line\nthird"), baseTime, policy)
	if h.Reason != "first line" {
		t.Errorf("Reason = %q, want only the first line", h.Reason)
	}

	long := strings.Repeat("a", 500)
	h, _ = ObserveProbe(Health{}, errors.New(long), baseTime, policy)
	if want := strings.Repeat("a", 199) + "…"; h.Reason != want {
		t.Errorf("Reason = %q (len %d), want a 200-rune truncation", h.Reason, len([]rune(h.Reason)))
	}

	h, _ = ObserveProbe(Health{}, errors.New("   "), baseTime, policy)
	if h.Reason != "probe failed" {
		t.Errorf("Reason for a blank error = %q, want %q", h.Reason, "probe failed")
	}
}

func TestHealthPolicyNormalizeClamps(t *testing.T) {
	cases := []struct {
		in, want HealthPolicy
	}{
		// A zero value must not disable liveness supervision for the fleet.
		{HealthPolicy{}, HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}},
		{HealthPolicy{DegradeAfter: 0, UnreachableAfter: 3}, HealthPolicy{DegradeAfter: 1, UnreachableAfter: 3}},
		{HealthPolicy{DegradeAfter: -5, UnreachableAfter: -9}, HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}},
		// UnreachableAfter below DegradeAfter is nonsense; give up at degrade.
		{HealthPolicy{DegradeAfter: 3, UnreachableAfter: 1}, HealthPolicy{DegradeAfter: 3, UnreachableAfter: 3}},
		{HealthPolicy{DegradeAfter: 2, UnreachableAfter: 5}, HealthPolicy{DegradeAfter: 2, UnreachableAfter: 5}},
		{DefaultHealthPolicy(), HealthPolicy{DegradeAfter: 1, UnreachableAfter: 3}},
	}
	for _, tc := range cases {
		if got := tc.in.normalize(); got != tc.want {
			t.Errorf("HealthPolicy%+v.normalize() = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	// The clamp has to be applied by ObserveProbe itself, not just by callers:
	// with a zero policy the very first failure is terminal.
	h, tr := ObserveProbe(Health{ExecutorID: "e"}, errors.New("down"), baseTime, HealthPolicy{})
	if tr == nil || h.State != NodeUnreachable {
		t.Fatalf("zero policy: state = %q, transition = %v, want unreachable", h.State, tr)
	}
}

func TestHealthNormalize(t *testing.T) {
	// A node with no persisted record is ready: refusing to schedule merely
	// because the supervisor has not ticked yet would make every fresh control
	// plane briefly unable to run anything.
	if got := (Health{}).Normalize(); got.State != NodeReady {
		t.Errorf("zero Health normalizes to %q, want ready", got.State)
	}
	if got := (Health{State: "banana"}).Normalize(); got.State != NodeReady {
		t.Errorf("invalid state normalizes to %q, want ready", got.State)
	}
	if got := (Health{ConsecutiveFailures: -3}).Normalize(); got.ConsecutiveFailures != 0 {
		t.Errorf("negative failure count normalizes to %d, want 0", got.ConsecutiveFailures)
	}
	if got := (Health{State: NodeCordoned}).Normalize(); got.State != NodeCordoned {
		t.Errorf("valid state was rewritten to %q", got.State)
	}
}

func TestHealthStale(t *testing.T) {
	const ttl = 5 * time.Minute
	cases := []struct {
		name string
		h    Health
		ref  time.Time
		ttl  time.Duration
		want bool
	}{
		{"no ttl means never stale", Health{}, baseTime.Add(24 * time.Hour), 0, false},
		{"negative ttl means never stale", Health{LastSeen: baseTime}, baseTime.Add(time.Hour), -time.Second, false},
		{"seen recently", Health{LastSeen: baseTime}, baseTime.Add(time.Minute), ttl, false},
		{"seen exactly ttl ago is not yet stale", Health{LastSeen: baseTime}, baseTime.Add(ttl), ttl, false},
		{"seen just over ttl ago", Health{LastSeen: baseTime}, baseTime.Add(ttl + time.Nanosecond), ttl, true},
		// A control plane that just started must not declare its whole fleet
		// stale before the first probe lands.
		{"never seen, never changed", Health{}, baseTime.Add(24 * time.Hour), ttl, false},
		{"never seen, registered recently", Health{StateChangedAt: baseTime}, baseTime.Add(time.Minute), ttl, false},
		{"never seen, registered long ago", Health{StateChangedAt: baseTime}, baseTime.Add(ttl + time.Second), ttl, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.h.Stale(tc.ref, tc.ttl); got != tc.want {
				t.Errorf("Stale() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNodeStateTruthTable(t *testing.T) {
	cases := []struct {
		state                         NodeState
		valid, schedulable, adminHeld bool
	}{
		{NodeReady, true, true, false},
		// Degraded is schedulable on purpose: a probe is a much weaker signal
		// than a workload, and refusing placement on the first missed probe
		// would make a fleet of flaky edge devices permanently unusable.
		{NodeDegraded, true, true, false},
		{NodeUnreachable, true, false, false},
		{NodeCordoned, true, false, true},
		{NodeDraining, true, false, true},
		{NodeState("bogus"), false, false, false},
		{NodeState(""), false, false, false},
	}
	for _, tc := range cases {
		if got := tc.state.Valid(); got != tc.valid {
			t.Errorf("NodeState(%q).Valid() = %v, want %v", tc.state, got, tc.valid)
		}
		if got := tc.state.Schedulable(); got != tc.schedulable {
			t.Errorf("NodeState(%q).Schedulable() = %v, want %v", tc.state, got, tc.schedulable)
		}
		if got := tc.state.AdminHeld(); got != tc.adminHeld {
			t.Errorf("NodeState(%q).AdminHeld() = %v, want %v", tc.state, got, tc.adminHeld)
		}
	}
}

func TestTransitionString(t *testing.T) {
	tr := Transition{ExecutorID: "edge-1", From: NodeReady, To: NodeUnreachable, Reason: "i/o timeout"}
	if got, want := tr.String(), "edge-1: ready -> unreachable (i/o timeout)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	tr.Reason = ""
	if got, want := tr.String(), "edge-1: ready -> unreachable"; got != want {
		t.Errorf("String() without reason = %q, want %q", got, want)
	}
}
