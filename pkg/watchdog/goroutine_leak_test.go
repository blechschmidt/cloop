package watchdog

// Goroutine-leak regression test for the watchdog Start/Wait lifecycle.
//
// Watchdog.Start spawns exactly one goroutine that drives the inspection
// ticker. The goroutine exits when its parent ctx is cancelled, releases
// its WaitGroup token, and Wait then unblocks. A regression in any of the
// teardown paths — a defer that doesn't run, a ticker.Stop that never
// fires, a tick() that re-launches its own background work without
// awaiting it — would leave one or more goroutines pinned per Start
// invocation, scaling linearly with the number of run/cancel cycles.
//
// This test mirrors the pattern in pkg/orchestrator/goroutine_leak_test.go,
// pkg/ui/goroutine_leak_test.go, pkg/filewatch/goroutine_leak_test.go,
// and pkg/consensus/goroutine_leak_test.go: open N short-lived watchdog
// lifecycles, then assert runtime.NumGoroutine has returned to within a
// small slack of the pre-test baseline. With N=20 a per-cycle leak
// produces a delta of ~20-60, far above the slack threshold; ambient
// runtime/scheduler flapping is ~0-3.
//
// ─────────────────────────────────────────────────────────────────────────
// Goroutine-leak detector pattern (canonical reference for cloop tests)
// ─────────────────────────────────────────────────────────────────────────
//
// cloop intentionally does NOT depend on go.uber.org/goleak. Instead every
// long-lived subsystem ships a small package-local
// `*_goroutine_leak_test.go` file with three pieces:
//
//   1. const goroutineLeakSlack = 10
//      Absorbs runtime/scheduler/driver ambient flapping. Tuned so that a
//      real per-cycle leak (which scales linearly with N) clearly trips it
//      while normal flapping never does. A value much smaller than N is
//      essential — see derivation in the doc comment above each test.
//
//   2. settleGoroutineCount() int
//      Triggers GC, yields the scheduler, sleeps briefly, GCs again, then
//      samples runtime.NumGoroutine. The sleep window is chosen per
//      package based on how long the slowest deferred cleanup takes to
//      finalise (DB drivers fsync; nhooyr's drain loop unwinds; the
//      filewatch debounce timer unblocks). Generally 50-100ms is enough.
//
//   3. TestXxx_NoGoroutineLeak
//      Warm-up call so first-time package init does not pollute the
//      baseline → settleGoroutineCount → loop N happy-path lifecycles →
//      settleGoroutineCount → assert delta <= goroutineLeakSlack.
//
// Why not goleak? Two reasons:
//   - Several driver dependencies (modernc.org/sqlite, nhooyr.io/websocket)
//     keep ambient background goroutines that goleak's default-ignore
//     allowlist does not cover. We would have to maintain a per-package
//     IgnoreCurrent / IgnoreTopFunction list anyway.
//   - The macroscopic delta-vs-baseline assertion is robust to those
//     drivers without any allowlist maintenance. A real leak scales with N;
//     ambient noise does not.
//
// Critical packages that ship one of these tests:
//   - pkg/orchestrator   (parallel fan-out workers + wg closer goroutine)
//   - pkg/ui             (WebSocket and SSE per-connection goroutines)
//   - pkg/watchdog       (this file — Start/Wait lifecycle)
//   - pkg/statedb        (Open/Close — SQLite driver background goroutines)
//   - pkg/filewatch      (fsnotify watcher + debounce fireTrigger)
//   - pkg/compare        (parallel provider fan-out)
//   - pkg/consensus      (parallel fan-out + judge goroutine)
//   - pkg/bench          (parallel provider runs)
//   - pkg/logtail        (long-lived tail follower)
//
// When adding a long-lived background goroutine to any subsystem, add a
// matching *_goroutine_leak_test.go in that package — copy this file's
// shape, document the goroutine you're guarding, and exercise it under N
// open/close cycles. The cost of running such a test is ~1s; the cost of
// shipping a leak is unbounded.

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// watchdogGoroutineLeakSlack absorbs runtime/scheduler ambient flapping.
// Picked to be much smaller than any real per-cycle leak would produce at
// N=20.
const watchdogGoroutineLeakSlack = 10

// settleWatchdogGoroutineCount triggers GC and sleeps briefly so transient
// goroutines have a chance to exit before sampling NumGoroutine. The
// watchdog's deferred ticker.Stop and wg.Done both complete promptly once
// ctx fires; the sleep is short to keep the test fast.
func settleWatchdogGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(80 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// TestWatchdog_StartWaitLifecycle_NoGoroutineLeak runs N start/cancel/Wait
// cycles and asserts runtime.NumGoroutine returns to within
// watchdogGoroutineLeakSlack of the pre-test baseline. Each cycle:
//
//  1. Constructs a fresh Watchdog with a tight 5ms interval (so the
//     ticker actually fires at least once per cycle, exercising the live
//     tick path rather than only the cancel-on-idle path).
//  2. Calls Start(ctx).
//  3. Sleeps long enough to guarantee at least one tick has run.
//  4. Cancels ctx.
//  5. Calls Wait, with a generous deadline that will fail-fast the test
//     if Wait blocks (which would itself indicate a leak).
//
// Catches regressions in:
//   - the deferred wg.Done in the Start goroutine
//   - the deferred ticker.Stop
//   - a tick() implementation that spawns its own goroutines without
//     awaiting them before returning
//   - a Watchdog field whose finalizer keeps a closure alive
func TestWatchdog_StartWaitLifecycle_NoGoroutineLeak(t *testing.T) {
	// Reusable plan provider: every cycle returns the same in-memory plan,
	// which never has a stuck task (StartedAt is in the future), so tick()
	// runs to completion without firing the AutoKill / OnStuck paths.
	// Those paths are exercised by the dedicated tests in watchdog_test.go;
	// here we only care about the goroutine accounting of Start/Wait.
	future := time.Now().Add(1 * time.Hour)
	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "future task", Status: pm.TaskInProgress, StartedAt: &future},
	}}

	runOneCycle := func(t *testing.T) {
		t.Helper()
		w := &Watchdog{
			WorkDir:  t.TempDir(),
			GetPlan:  func() *pm.Plan { return plan },
			Interval: 5 * time.Millisecond,
		}
		ctx, cancel := context.WithCancel(context.Background())
		w.Start(ctx)
		// Sleep long enough to guarantee at least one tick has fired.
		time.Sleep(20 * time.Millisecond)
		cancel()

		done := make(chan struct{})
		go func() {
			w.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Watchdog.Wait did not return within 2s of ctx cancel — possible leaked goroutine")
		}
	}

	// Warm up: one cycle so any one-time package init (timer subsystem,
	// runtime sweep) doesn't pollute the baseline.
	runOneCycle(t)

	baseline := settleWatchdogGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		runOneCycle(t)
	}

	post := settleWatchdogGoroutineCount()
	delta := post - baseline
	if delta > watchdogGoroutineLeakSlack {
		t.Fatalf("goroutine leak in Watchdog Start/Wait lifecycle: baseline=%d post=%d delta=%d (>%d) after %d cycles",
			baseline, post, delta, watchdogGoroutineLeakSlack, N)
	}
}

// TestWatchdog_StartIdempotent_NoGoroutineLeak verifies the documented
// "Start is a no-op on second and subsequent calls" contract does not
// silently leak. If the idempotency check were buggy (e.g. set the
// `started` flag but still wg.Add+go), every duplicate Start would leak
// one goroutine. The previous test catches the *normal* path; this one
// catches the duplicate-Start branch specifically by calling Start three
// times per cycle.
func TestWatchdog_StartIdempotent_NoGoroutineLeak(t *testing.T) {
	runOneCycle := func(t *testing.T) {
		t.Helper()
		w := &Watchdog{
			WorkDir:  t.TempDir(),
			GetPlan:  func() *pm.Plan { return nil },
			Interval: 5 * time.Millisecond,
		}
		ctx, cancel := context.WithCancel(context.Background())
		w.Start(ctx)
		w.Start(ctx) // documented no-op
		w.Start(ctx) // documented no-op
		time.Sleep(15 * time.Millisecond)
		cancel()

		done := make(chan struct{})
		go func() { w.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Watchdog.Wait blocked after duplicate Start — idempotency check leaked extra goroutines")
		}
	}

	runOneCycle(t) // warm up

	baseline := settleWatchdogGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		runOneCycle(t)
	}

	post := settleWatchdogGoroutineCount()
	delta := post - baseline
	if delta > watchdogGoroutineLeakSlack {
		t.Fatalf("goroutine leak in Watchdog duplicate-Start path: baseline=%d post=%d delta=%d (>%d) after %d cycles",
			baseline, post, delta, watchdogGoroutineLeakSlack, N)
	}
}
