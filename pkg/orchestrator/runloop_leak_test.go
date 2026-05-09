package orchestrator

// Goroutine-leak regression tests for the runLoop autonomous-loop path.
//
// runLoop is a single-goroutine sequential loop that drives the provider
// step by step. It does not itself fan out — but it sits on top of a
// growing set of helpers (safeComplete's panic-recover, the deferred
// learnFromSession, webhook/notify hooks, metrics, ctx-cancellation
// branches in the StepDelay sleep) and a regression that allocated a
// per-iteration goroutine without a clean exit signal would scale
// linearly with the number of `cloop run` invocations a long-running
// daemon driver issues.
//
// This test mirrors the macroscopic shape of the runPMParallel
// (goroutine_leak_test.go), parallel-cancel (parallel_cancel_leak_test.go),
// WS+SSE connection-lifecycle (pkg/ui/goroutine_leak_test.go),
// compare/consensus (pkg/compare/goroutine_leak_test.go,
// pkg/consensus/goroutine_leak_test.go), bench (pkg/bench/goroutine_leak_test.go),
// filewatch (pkg/filewatch/goroutine_leak_test.go) and logtail
// (pkg/logtail/goroutine_leak_test.go) regression guards: open N
// short-lived sessions, then assert runtime.NumGoroutine has returned
// to within a small slack of the pre-test baseline. With N=20 a
// per-invocation leak produces a delta of ~20-60, far above the slack
// threshold; ambient flapping from the runtime/scheduler is ~0-3.

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// TestRunLoop_NoGoroutineLeak_GoalComplete runs N happy-path runLoop
// invocations (provider returns GOAL_COMPLETE on its first step) and
// asserts runtime.NumGoroutine returns to within orchGoroutineLeakSlack
// of the pre-test baseline.
//
// Catches regressions that allocate a per-iteration goroutine without a
// matching exit on the natural success path — e.g. a future change to
// safeComplete that wraps Complete in a fire-and-forget supervisor, or a
// metrics decorator that spawns a long-lived sampler per orchestrator.
func TestRunLoop_NoGoroutineLeak_GoalComplete(t *testing.T) {
	// Warm up: one invocation so any one-time package init doesn't
	// pollute the baseline. Uses a separate tempdir from the loop
	// iterations so no leftover state is reused.
	{
		dir := tempDir(t)
		initState(t, dir, "warmup", 5)
		prov := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "done\nGOAL_COMPLETE", Provider: "mock"},
			},
		}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		if err := o.runLoop(context.Background()); err != nil {
			t.Fatalf("warmup runLoop: %v", err)
		}
	}

	baseline := settleOrchGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dir := tempDir(t)
		initState(t, dir, "goal", 5)
		prov := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "done\nGOAL_COMPLETE", Provider: "mock"},
			},
		}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		if err := o.runLoop(context.Background()); err != nil {
			t.Fatalf("iter %d: runLoop: %v", i, err)
		}
		if o.state.Status != "complete" {
			t.Fatalf("iter %d: expected status=complete, got %q", i, o.state.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in runLoop happy path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}
}

// TestRunLoop_NoGoroutineLeak_ContextCancelled runs N runLoop invocations
// where each is interrupted by a parent-context cancel mid-step. The
// cancellingProvider helper (defined in orchestrator_test.go) cancels the
// shared parent ctx after returning the first step's result; runLoop
// observes the cancellation on the next iteration's select and returns
// ctx.Err(). Asserts that no goroutine is left pinned per cancelled
// invocation.
//
// Catches regressions in the ctx.Done branches inside runLoop's outer
// select and the StepDelay select — e.g. a future change that allocates
// a context-bound watcher goroutine inside the loop body but only
// teardown it on the natural goal-complete path.
func TestRunLoop_NoGoroutineLeak_ContextCancelled(t *testing.T) {
	// Warm up.
	{
		dir := tempDir(t)
		initState(t, dir, "warmup", 0) // unlimited
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "step 1", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		_ = o.runLoop(ctx)
	}

	baseline := settleOrchGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dir := tempDir(t)
		initState(t, dir, "goal", 0) // unlimited so loop only exits via cancel
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "step 1", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		err := o.runLoop(ctx)
		if err == nil {
			t.Fatalf("iter %d: expected ctx-cancellation error, got nil", i)
		}
		if o.state.Status != "paused" {
			t.Fatalf("iter %d: expected status=paused, got %q", i, o.state.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in runLoop ctx-cancelled path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}
}

// TestRunLoop_NoGoroutineLeak_ProviderError runs N runLoop invocations
// where the provider returns an error on its first call. runLoop marks
// the session "failed", fires the webhook (no-op without a configured
// URL), and returns the error. Asserts no goroutine pinned per failed
// invocation.
//
// Catches regressions on the early-error return path — e.g. a future
// change that defers a goroutine-spawning side effect (telemetry flush,
// failed-session notifier) without a matching ctx-bound exit.
func TestRunLoop_NoGoroutineLeak_ProviderError(t *testing.T) {
	// Warm up.
	{
		dir := tempDir(t)
		initState(t, dir, "warmup", 5)
		prov := &mockProvider{
			name: "mock",
			errs: []error{errors.New("boom")},
		}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		_ = o.runLoop(context.Background())
	}

	baseline := settleOrchGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dir := tempDir(t)
		initState(t, dir, "goal", 5)
		prov := &mockProvider{
			name: "mock",
			errs: []error{errors.New("boom")},
		}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		err := o.runLoop(context.Background())
		if err == nil {
			t.Fatalf("iter %d: expected provider error, got nil", i)
		}
		if o.state.Status != "failed" {
			t.Fatalf("iter %d: expected status=failed, got %q", i, o.state.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in runLoop provider-error path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}
}

// TestRunLoop_NoGoroutineLeak_StepDelayCancel exercises the inner
// StepDelay select arm specifically. Each invocation runs one provider
// step (which doesn't trip GOAL_COMPLETE), enters the StepDelay sleep,
// then is cancelled while waiting on the timer. runLoop returns
// ctx.Err() and marks status=paused.
//
// Catches regressions in the second select inside runLoop (the
// time.After + ctx.Done branches in the StepDelay block) — e.g. a
// future change that swaps time.After for a NewTicker without a
// matching Stop() defer would leak a runtime timer goroutine per
// iteration.
func TestRunLoop_NoGoroutineLeak_StepDelayCancel(t *testing.T) {
	// Warm up.
	{
		dir := tempDir(t)
		initState(t, dir, "warmup", 0) // unlimited
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "step 1", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		// 1ms delay so the StepDelay select arm is exercised but the
		// test still completes promptly when ctx fires.
		o := newOrchestrator(t, dir, Config{WorkDir: dir, StepDelay: 50 * time.Millisecond}, prov)
		_ = o.runLoop(ctx)
	}

	baseline := settleOrchGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dir := tempDir(t)
		initState(t, dir, "goal", 0) // unlimited so the StepDelay arm fires
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "step 1", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		o := newOrchestrator(t, dir, Config{WorkDir: dir, StepDelay: 50 * time.Millisecond}, prov)
		err := o.runLoop(ctx)
		if err == nil {
			t.Fatalf("iter %d: expected ctx-cancellation error, got nil", i)
		}
		if o.state.Status != "paused" {
			t.Fatalf("iter %d: expected status=paused, got %q", i, o.state.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in runLoop StepDelay-cancel path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}

	// Reference runtime to keep the import live even if a future refactor
	// removes the explicit NumGoroutine call from settleOrchGoroutineCount.
	_ = runtime.NumGoroutine()
}
