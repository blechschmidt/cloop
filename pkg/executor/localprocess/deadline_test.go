package localprocess

// Tests for timeout survival across a control-plane restart (Task 20191).
//
// Rehydration reattaches to a workload the previous process dispatched. Doing
// that without also restoring the timeout would have swapped one runaway for
// another: an adopted record is *tracked*, so no orphan sweep will ever
// collect it, and a task with a one-hour cap that outlived a restart would
// have run until the machine was rebooted. That is the failure this whole
// task exists to end, so re-arming is not an optimisation.
//
// The deadline is persisted as an absolute instant rather than as the original
// duration, and these tests pin the difference: a hub that was down for a
// while must resume the *remaining* time, not restart the clock.

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// waitForFinish polls until finish has run for a record, or the deadline
// passes.
//
// Deliberately not "wait until Status is terminal": markKilled sets a terminal
// state synchronously from Signal and from the kill timer, while finish — which
// clears the timer, drops the durable row and releases subscribers — happens on
// the adoption watcher's next tick, up to adoptPollInterval later. A test that
// asserted on finish's effects the moment Status went terminal would be racing
// a whole poll interval and would flake in CI rather than here.
func waitForFinish(t *testing.T, rec *record, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rec.finished() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// waitForState polls until the handle reaches a terminal state or the deadline
// passes, returning the last status seen.
func waitForState(t *testing.T, ex *Executor, handleID string, timeout time.Duration) executor.Status {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	var last executor.Status
	for time.Now().Before(deadline) {
		st, err := ex.Status(ctx, handleID)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		last = st
		if st.State.Terminal() {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	return last
}

// TestStart_PersistsTheDeadline: without the row carrying it, there is nothing
// for a restart to re-arm from.
func TestStart_PersistsTheDeadline(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()
	ex := New("deadline-persist")
	ex.AttachHandleStore(store)

	spec := fixtureSpec(t, modeSleep, t.TempDir())
	spec.TimeoutMinutes = 30
	h, err := ex.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(ctx, h.ID, executor.SignalKill) })

	rows, err := store.ListHandles("deadline-persist")
	if err != nil || len(rows) != 1 {
		t.Fatalf("want 1 row, got %d (err=%v)", len(rows), err)
	}
	if rows[0].Deadline.IsZero() {
		t.Fatal("a timed workload must persist its deadline, or a restart has nothing to re-arm")
	}
	// Absolute, and anchored to the dispatch time rather than to whenever the
	// row happened to be written.
	want := h.StartedAt.Add(30 * time.Minute)
	if delta := rows[0].Deadline.Sub(want); delta > time.Second || delta < -time.Second {
		t.Errorf("Deadline = %v, want ~%v (started %v + 30m)", rows[0].Deadline, want, h.StartedAt)
	}
}

// TestStart_UnboundedWorkloadPersistsNoDeadline: a spec with no timeout must
// not acquire one by being persisted, or every restart would start killing
// long-running work that was deliberately uncapped.
func TestStart_UnboundedWorkloadPersistsNoDeadline(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()
	ex := New("deadline-none")
	ex.AttachHandleStore(store)

	h, err := ex.Start(ctx, fixtureSpec(t, modeSleep, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(ctx, h.ID, executor.SignalKill) })

	rows, _ := store.ListHandles("deadline-none")
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if !rows[0].Deadline.IsZero() {
		t.Fatalf("an untimed workload must persist a zero deadline, got %v", rows[0].Deadline)
	}
}

// TestRehydrate_ExpiredDeadlineKillsTheAdoptedWorkload is the point of the
// whole file. The hub was down when the timeout expired; nobody having been
// there to enforce it is not a reprieve.
func TestRehydrate_ExpiredDeadlineKillsTheAdoptedWorkload(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()

	first := New("deadline-expired")
	first.AttachHandleStore(store)
	spec := fixtureSpec(t, modeSleep, t.TempDir())
	h, err := first.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = first.Signal(ctx, h.ID, executor.SignalKill) })

	// Backdate the row's deadline into the past, which is what the store would
	// hold after a hub that was down for longer than the workload's timeout.
	rows, _ := store.ListHandles("deadline-expired")
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	rec := rows[0]
	rec.Deadline = time.Now().Add(-time.Minute)
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// The restart.
	second := New("deadline-expired")
	second.AttachHandleStore(store)

	st := waitForState(t, second, h.ID, 5*time.Second)
	if !st.State.Terminal() {
		t.Fatalf("an adopted workload past its deadline must be killed, state is still %q — "+
			"it is tracked, so no orphan sweep will ever collect it", st.State)
	}
	if st.State != executor.StateKilled {
		t.Errorf("State = %q, want killed so the reason survives into the run's record", st.State)
	}
	if st.Error == "" {
		t.Error("a resumed-deadline kill must say so; an operator seeing a dead task needs the cause")
	}

	// The row goes with the workload: a killed process cannot be reattached to,
	// and a surviving row would be re-adopted and re-killed on every boot. It is
	// dropped by finish, which is a poll interval behind the terminal state
	// asserted above.
	live, err := second.lookup(h.ID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !waitForFinish(t, live, 5*time.Second) {
		t.Fatal("the killed workload's record was never finished")
	}
	if store.Len() != 0 {
		t.Errorf("want the row dropped after the kill, %d remain", store.Len())
	}
}

// TestRehydrate_LiveDeadlineIsNotKilledImmediately: the complement, and the
// one that would catch a re-arm that mistook the absolute instant for a
// duration and computed a negative delay for every adopted workload.
func TestRehydrate_LiveDeadlineIsNotKilledImmediately(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()

	first := New("deadline-live")
	first.AttachHandleStore(store)
	spec := fixtureSpec(t, modeSleep, t.TempDir())
	spec.TimeoutMinutes = 60
	h, err := first.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = first.Signal(ctx, h.ID, executor.SignalKill) })

	second := New("deadline-live")
	second.AttachHandleStore(store)

	// Long enough that an immediate or near-immediate kill would show.
	time.Sleep(300 * time.Millisecond)
	st, err := second.Status(ctx, h.ID)
	if err != nil {
		t.Fatalf("Status after adoption: %v", err)
	}
	if st.State.Terminal() {
		t.Fatalf("a workload with 60 minutes left was killed on adoption (state %q, %q) — "+
			"the deadline was probably read as a duration rather than an instant",
			st.State, st.Error)
	}
}

// TestFinish_StopsTheAdoptedKillTimer guards the sharpest edge in this change.
//
// An adopted record finishes through the liveness watcher, which never touches
// the output pump. A timer left armed would fire after the process had exited
// and deliver SIGKILL to a pid the kernel may by then have handed to something
// else — the recycled-pid kill that adopt's identity check exists to make
// impossible, arriving by the back door.
func TestFinish_StopsTheAdoptedKillTimer(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()

	first := New("deadline-stop")
	first.AttachHandleStore(store)
	spec := fixtureSpec(t, modeSleep, t.TempDir())
	spec.TimeoutMinutes = 60
	h, err := first.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	second := New("deadline-stop")
	second.AttachHandleStore(store)

	// Kill through the adopted driver, which finishes the record via Signal
	// and the watcher rather than via the pump.
	if err := second.Signal(ctx, h.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	st := waitForState(t, second, h.ID, 5*time.Second)
	if !st.State.Terminal() {
		t.Fatalf("killed workload never reached a terminal state, got %q", st.State)
	}

	rec, err := second.lookup(h.ID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !waitForFinish(t, rec, 5*time.Second) {
		t.Fatal("the killed workload's record was never finished")
	}
	rec.mu.Lock()
	timer := rec.killTimer
	rec.mu.Unlock()
	if timer != nil {
		t.Fatal("finish must clear the kill timer: an armed timer on a finished record " +
			"can SIGKILL a pid that has since been recycled")
	}
}

// TestArmKillTimerClampsANegativeDelay: time.AfterFunc treats a negative
// duration as "fire now", which is the behaviour wanted, but the clamp is
// asserted so a future change to AfterFunc's contract cannot silently turn an
// expired deadline into a timer that never fires.
func TestArmKillTimerClampsANegativeDelay(t *testing.T) {
	ex := New("clamp")
	rec := &record{id: "r", pid: -1, state: executor.StateRunning}
	ex.armKillTimer(rec, -time.Hour, "already expired")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		state := rec.state
		rec.mu.Unlock()
		if state == executor.StateKilled {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a negative delay must fire immediately, not never")
}

// TestAdoptedRecordWithoutADeadlineStaysUnbounded: a row written before this
// change, or by a driver whose backend enforces the deadline itself (the
// Kubernetes driver hands the API server activeDeadlineSeconds), carries a
// zero deadline and must not acquire a timer from it.
func TestAdoptedRecordWithoutADeadlineStaysUnbounded(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()

	first := New("deadline-absent")
	first.AttachHandleStore(store)
	h, err := first.Start(ctx, fixtureSpec(t, modeSleep, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = first.Signal(ctx, h.ID, executor.SignalKill) })

	second := New("deadline-absent")
	second.AttachHandleStore(store)

	time.Sleep(200 * time.Millisecond)
	st, err := second.Status(ctx, h.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State.Terminal() {
		t.Fatalf("a row with no deadline must not be killed on adoption, got %q (%q)", st.State, st.Error)
	}
	rec, err := second.lookup(h.ID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	rec.mu.Lock()
	timer := rec.killTimer
	rec.mu.Unlock()
	if timer != nil {
		t.Fatal("a zero deadline must arm no timer")
	}
}
