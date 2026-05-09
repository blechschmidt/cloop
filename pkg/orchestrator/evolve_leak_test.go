package orchestrator

// Goroutine-leak regression tests for the auto-evolve loop (`evolve`).
//
// `evolve` is the load-bearing top-level driver entered from `runLoop`
// when GOAL_COMPLETE fires with `--auto-evolve` set. Like `runLoop` it
// is sequential — it doesn't fan out — but it sits on top of the same
// growing set of helpers (safeComplete's panic-recover, the deferred
// learnFromSession in callers, webhook hooks, plan mutation under
// SyncFromDisk) and a regression that allocated a per-iteration
// goroutine inside one of its branches (top-of-loop ctx-poll,
// task-execution arm, evolvePM discovery arm, free-form arm) without a
// matching exit signal would scale linearly across daemon-driven
// `cloop run --auto-evolve` reconnect cycles.
//
// This test mirrors the macroscopic shape of the runLoop
// (runloop_leak_test.go), runPMParallel (goroutine_leak_test.go,
// parallel_cancel_leak_test.go), WS+SSE connection-lifecycle
// (pkg/ui/goroutine_leak_test.go), compare/consensus
// (pkg/compare/goroutine_leak_test.go,
// pkg/consensus/goroutine_leak_test.go), bench
// (pkg/bench/goroutine_leak_test.go), filewatch
// (pkg/filewatch/goroutine_leak_test.go) and logtail
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

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// TestEvolve_NoGoroutineLeak_FreeFormCancel runs N evolve invocations
// where each is interrupted by a parent-context cancel after the first
// free-form provider call. With no plan attached, `evolve` skips the
// task-execution / evolvePM branches and lands directly in the
// free-form branch; the cancellingProvider helper cancels ctx after
// returning the first result, so the next iteration's top-of-loop
// ctx.Done() select arm fires and `evolve` returns nil with
// status=complete.
//
// Catches regressions in the top-of-loop ctx.Done branch and the
// free-form-arm post-call mutation path — e.g. a future change that
// allocates a per-iteration metrics-sampler goroutine without an
// exit signal.
func TestEvolve_NoGoroutineLeak_FreeFormCancel(t *testing.T) {
	// Warm up: one invocation so any one-time package init doesn't
	// pollute the baseline. Uses a separate tempdir from the loop
	// iterations so no leftover state is reused.
	{
		dir := tempDir(t)
		initState(t, dir, "warmup", 0)
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "free-form result", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		_ = o.evolve(ctx)
	}

	baseline := settleOrchGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dir := tempDir(t)
		initState(t, dir, "goal", 0)
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "free-form result", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		if err := o.evolve(ctx); err != nil {
			t.Fatalf("iter %d: evolve: %v", i, err)
		}
		if o.state.Status != "complete" {
			t.Fatalf("iter %d: expected status=complete, got %q", i, o.state.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in evolve free-form cancel path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}
}

// TestEvolve_NoGoroutineLeak_FreeFormProviderError runs N evolve
// invocations where the free-form provider call returns an error on
// its first call. evolve marks status=complete and returns nil.
//
// Catches regressions on the free-form provider-error early-return
// path — e.g. a future change that defers a goroutine-spawning side
// effect (telemetry flush, evolve-failure notifier) without a matching
// ctx-bound exit.
func TestEvolve_NoGoroutineLeak_FreeFormProviderError(t *testing.T) {
	// Warm up.
	{
		dir := tempDir(t)
		initState(t, dir, "warmup", 0)
		prov := &mockProvider{
			name: "mock",
			errs: []error{errors.New("boom")},
		}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		_ = o.evolve(context.Background())
	}

	baseline := settleOrchGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dir := tempDir(t)
		initState(t, dir, "goal", 0)
		prov := &mockProvider{
			name: "mock",
			errs: []error{errors.New("boom")},
		}
		o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
		if err := o.evolve(context.Background()); err != nil {
			t.Fatalf("iter %d: evolve unexpectedly returned err: %v", i, err)
		}
		if o.state.Status != "complete" {
			t.Fatalf("iter %d: expected status=complete, got %q", i, o.state.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in evolve free-form provider-error path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}
}

// TestEvolve_NoGoroutineLeak_TaskExecutionThenCancel runs N evolve
// invocations where the plan has a single pending task. The first
// provider.Complete call returns a TASK_DONE-signalled result and
// cancellingProvider then cancels the parent ctx. After the task is
// marked done, evolve loops back to the top, the ctx.Done() select arm
// fires, and evolve returns nil with status=complete.
//
// Catches regressions in the task-execution arm — the StartedAt /
// CompletedAt mutation path, the safeComplete supervisor invocation,
// the SyncFromDisk + IsComplete check that gates the evolvePM call —
// e.g. a future change that wraps task execution in a fire-and-forget
// timeout watcher without a matching teardown.
func TestEvolve_NoGoroutineLeak_TaskExecutionThenCancel(t *testing.T) {
	// Warm up.
	{
		dir := tempDir(t)
		s := initState(t, dir, "warmup", 0)
		s.PMMode = true
		s.Plan = &pm.Plan{
			Goal: "warmup",
			Tasks: []*pm.Task{
				{ID: 1, Title: "Task A", Description: "Do A", Priority: 1, Status: pm.TaskPending},
			},
		}
		s.Save()
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "did the work\nTASK_DONE", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		// NoDedup so evolvePM (if reached) doesn't fire a second
		// Complete call for dedup; not strictly needed since cancel
		// fires before evolvePM, but defensive.
		o := newOrchestrator(t, dir, Config{WorkDir: dir, NoDedup: true}, prov)
		_ = o.evolve(ctx)
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
				{ID: 1, Title: "Task A", Description: "Do A", Priority: 1, Status: pm.TaskPending},
			},
		}
		s.Save()
		ctx, cancel := context.WithCancel(context.Background())
		inner := &mockProvider{
			name: "mock",
			results: []*provider.Result{
				{Output: "did the work\nTASK_DONE", Provider: "mock"},
			},
		}
		prov := &cancellingProvider{cancel: cancel, inner: inner}
		o := newOrchestrator(t, dir, Config{WorkDir: dir, NoDedup: true}, prov)
		if err := o.evolve(ctx); err != nil {
			t.Fatalf("iter %d: evolve: %v", i, err)
		}
		if o.state.Status != "complete" {
			t.Fatalf("iter %d: expected status=complete, got %q", i, o.state.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in evolve task-execution + cancel path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}

	// Reference runtime to keep the import live even if a future
	// refactor removes the explicit NumGoroutine call from
	// settleOrchGoroutineCount.
	_ = runtime.NumGoroutine()
}
