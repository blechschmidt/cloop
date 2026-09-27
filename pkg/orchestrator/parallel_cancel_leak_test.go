package orchestrator

// Goroutine-leak regression tests for runPMParallel's *cancellation*
// paths.
//
// orchestrator_test.go's TestRunPMParallel_NoGoroutineLeak guards the
// happy path. parallel_shutdown_test.go's
// TestRunPMParallel_HungProvider_HonoursGracePeriod guards the
// watchdog's elapsed-time bound. Neither asserts goroutine accounting
// on the cancellation path, so a regression that left workers pinned
// per cancelled round (e.g. a missed defer tTaskCancel(), a worker
// blocked sending on a channel nobody drains after the watchdog
// returned, a new branch that allocated a goroutine without an exit
// signal) would scale linearly with cancelled rounds.
//
// Two scenarios are covered:
//
//  1. Honored cancellation: provider returns promptly when its
//     ctx is cancelled, and the result loop drains the whole batch
//     before the grace period ends. Asserts no leak after N cancelled
//     rounds.
//
//  2. Watchdog-early-return path: provider ignores ctx and only
//     returns when its own block channel closes. The watchdog fires,
//     Run returns ctx.Err() while workers are still pinned. After we
//     close the block channel, the workers send into the buffered
//     results channel and exit. Asserts no permanent leak after
//     N rounds + cleanup — i.e. the early-return path doesn't allocate
//     any goroutine that survives once the providers eventually return.

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// honoringProvider blocks on ctx.Done() and returns ctx.Err() when
// cancelled. Models a well-behaved provider that respects per-task
// cancellation, so every worker reports back inside the grace period
// and the result loop drains the batch.
type honoringProvider struct{}

func (honoringProvider) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (honoringProvider) Name() string         { return "honoring" }
func (honoringProvider) DefaultModel() string { return "honoring-model" }

// TestRunPMParallel_HonoredCancellation_NoGoroutineLeak asserts that
// after N cancelled rounds where workers honour ctx, NumGoroutine
// returns to within orchGoroutineLeakSlack of baseline. Catches
// regressions in per-task ctx cancel deferral, the grace timer armed by
// the cancellation, and any new per-round goroutine allocation that
// lacks a corresponding exit signal.
func TestRunPMParallel_HonoredCancellation_NoGoroutineLeak(t *testing.T) {
	prov := honoringProvider{}

	// Warm-up: one cancelled round so any one-time package init
	// doesn't pollute the baseline.
	{
		dir := tempDir(t)
		s := initState(t, dir, "warmup", 0)
		s.PMMode = true
		s.Plan = &pm.Plan{
			Goal: "warmup",
			Tasks: []*pm.Task{
				{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
				{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
				{ID: 3, Title: "C", Priority: 3, Status: pm.TaskPending},
			},
		}
		s.Save()
		o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		_ = o.Run(ctx) // expected to return ctx.Err()
	}

	baseline := settleOrchGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dir := tempDir(t)
		s := initState(t, dir, "goal", 0)
		s.PMMode = true
		s.Plan = &pm.Plan{
			Goal: "goal",
			Tasks: []*pm.Task{
				{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
				{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
				{ID: 3, Title: "C", Priority: 3, Status: pm.TaskPending},
			},
		}
		s.Save()

		o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)
		ctx, cancel := context.WithCancel(context.Background())
		// Cancel after a short delay so the round is in-flight when
		// cancellation arrives; the workers (blocked on ctx.Done)
		// then return ctx.Err() and wg drains naturally.
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		_ = o.Run(ctx) // expected ctx.Err(); we don't assert on it
		cancel()       // belt-and-braces

		// Sanity: state ended in a paused/cancelled state, not still
		// "running". Reading the state file would race with any leaked
		// goroutine still trying to Save(); the goroutine-leak assertion
		// at the end is the load-bearing check.
		final, err := state.Load(dir)
		if err == nil && final.Status == "running" {
			t.Fatalf("iter %d: expected non-running status after cancel, got %q", i, final.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in runPMParallel cancellation path: baseline=%d post=%d delta=%d (>%d) after %d cancelled rounds",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}
}

// releasableStuckProvider ignores ctx and blocks until the shared
// release channel is closed, modelling a misbehaving SDK that the
// watchdog must bound. Unlike parallel_shutdown_test.go's
// stuckProvider, the release channel is shared across all calls so the
// test can unblock every leaked worker at once after the watchdog
// fires.
type releasableStuckProvider struct {
	release <-chan struct{}
	mu      sync.Mutex
	calls   int
}

func (p *releasableStuckProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	<-p.release
	return &provider.Result{Output: "late\nTASK_DONE", Provider: "releasable-stuck"}, nil
}
func (*releasableStuckProvider) Name() string         { return "releasable-stuck" }
func (*releasableStuckProvider) DefaultModel() string { return "releasable-stuck-model" }

// TestRunPMParallel_WatchdogEarlyReturn_NoLeakAfterProvidersDrain
// asserts that the watchdog's early-return path doesn't leave any
// permanently-pinned goroutines once the underlying providers
// eventually return. Run returns while workers are still blocked; once
// we close the release channel, every leaked worker sends its result
// into the buffered results channel (nobody reads it any more, and the
// buffer is what keeps that send from blocking) and exits, and
// NumGoroutine returns to within slack of baseline.
//
// Catches regressions in:
//   - the results channel's buffer (a worker whose send blocked after
//     the watchdog returned would be pinned forever)
//   - any new per-round goroutine allocated on the early-return path
//     that lacks an exit signal independent of the leaked workers
//   - safeComplete's panic-recovery path under late-returning providers
func TestRunPMParallel_WatchdogEarlyReturn_NoLeakAfterProvidersDrain(t *testing.T) {
	prevGrace := parallelShutdownGracePeriod
	parallelShutdownGracePeriod = 50 * time.Millisecond
	t.Cleanup(func() { parallelShutdownGracePeriod = prevGrace })

	// Warm-up: one watchdog-early-return round so any one-time package
	// init doesn't pollute the baseline. Must release providers and
	// wait for goroutines to drain before sampling baseline.
	{
		release := make(chan struct{})
		prov := &releasableStuckProvider{release: release}

		dir := tempDir(t)
		s := initState(t, dir, "warmup", 0)
		s.PMMode = true
		s.Plan = &pm.Plan{
			Goal: "warmup",
			Tasks: []*pm.Task{
				{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
				{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
			},
		}
		s.Save()
		o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		_ = o.Run(ctx)
		cancel()
		// Release the leaked workers so they exit before baseline.
		close(release)
	}

	baseline := settleOrchGoroutineCount()

	// Track every release channel so we can close them all and wait
	// for the leaked workers to drain before sampling NumGoroutine.
	const N = 10 // smaller than honoured-cancel test: watchdog adds 50ms+ per round
	releases := make([]chan struct{}, 0, N)

	for i := 0; i < N; i++ {
		release := make(chan struct{})
		releases = append(releases, release)
		prov := &releasableStuckProvider{release: release}

		dir := tempDir(t)
		s := initState(t, dir, "goal", 0)
		s.PMMode = true
		s.Plan = &pm.Plan{
			Goal: "goal",
			Tasks: []*pm.Task{
				{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
				{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
			},
		}
		s.Save()
		o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		_ = o.Run(ctx)
		elapsed := time.Since(start)
		cancel()

		// Sanity: watchdog must have fired (workers still blocked on
		// release). Bound is generous to absorb scheduler/CI noise.
		if elapsed > 5*time.Second {
			t.Fatalf("iter %d: Run blocked for %s — watchdog did not fire", i, elapsed)
		}
	}

	// At this point N*2 worker goroutines are pinned waiting on their
	// respective release channels. Release them all and wait for the
	// runtime to settle.
	for _, r := range releases {
		close(r)
	}

	// Give the leaked goroutines time to: receive on release, send
	// their result into the buffered channel and exit. Each worker also
	// runs through artifact.OpenLiveArtifact + WriteString, which
	// touches the filesystem. Be generous.
	settled := false
	deadline := time.Now().Add(5 * time.Second)
	var post int
	for time.Now().Before(deadline) {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(100 * time.Millisecond)
		post = runtime.NumGoroutine()
		if post-baseline <= orchGoroutineLeakSlack {
			settled = true
			break
		}
	}
	if !settled {
		t.Fatalf("goroutine leak in runPMParallel watchdog-early-return path: baseline=%d post=%d delta=%d (>%d) after %d cancelled rounds + provider release",
			baseline, post, post-baseline, orchGoroutineLeakSlack, N)
	}
}
