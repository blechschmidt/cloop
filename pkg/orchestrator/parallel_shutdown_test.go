package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// stuckProvider ignores context cancellation and blocks until block is closed
// or the test's hard cap elapses. Models a misbehaving third-party SDK that
// fails to honour ctx.Done() — the failure mode parallelShutdownGracePeriod
// is meant to bound.
type stuckProvider struct {
	block <-chan struct{}
	hard  time.Duration
}

func (s stuckProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	select {
	case <-s.block:
	case <-time.After(s.hard):
	}
	return &provider.Result{Output: "late\nTASK_DONE", Provider: "stuck"}, nil
}
func (s stuckProvider) Name() string         { return "stuck" }
func (s stuckProvider) DefaultModel() string { return "stuck-model" }

// TestRunPMParallel_HungProvider_HonoursGracePeriod verifies that when the
// parent context is cancelled and a provider ignores cancellation,
// runPMParallel returns within the configured grace period instead of
// blocking on wg.Wait() indefinitely.
func TestRunPMParallel_HungProvider_HonoursGracePeriod(t *testing.T) {
	prev := parallelShutdownGracePeriod
	parallelShutdownGracePeriod = 100 * time.Millisecond
	t.Cleanup(func() { parallelShutdownGracePeriod = prev })

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

	// Provider blocks indefinitely (the hard cap is well beyond grace period
	// + cancellation delay so it never affects the assertion).
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	prov := stuckProvider{block: block, hard: 10 * time.Second}

	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after starting so the parallel round is in-flight when
	// cancellation arrives. The goroutines won't honour it (stuckProvider
	// ignores ctx), so the watchdog must enforce the bound.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := o.Run(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Allow generous slack: cancellation delay (~50ms) + grace period (100ms)
	// + scheduler/CI noise. If we exceed 5s the watchdog clearly didn't fire.
	if elapsed > 5*time.Second {
		t.Fatalf("Run blocked for %s — watchdog did not bound wg.Wait", elapsed)
	}
}

// TestRunPMParallel_NoCancellation_StillWaitsForCompletion verifies the
// watchdog does NOT fire on the happy path: when the parent context is not
// cancelled, runPMParallel waits for workers to complete normally even with
// the grace period set to a tiny value.
func TestRunPMParallel_NoCancellation_StillWaitsForCompletion(t *testing.T) {
	prev := parallelShutdownGracePeriod
	parallelShutdownGracePeriod = 1 * time.Millisecond
	t.Cleanup(func() { parallelShutdownGracePeriod = prev })

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

	prov := &safeProvider{name: "mock", output: "ok\nTASK_DONE"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	final, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	for _, task := range final.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d: expected done, got %s", task.ID, task.Status)
		}
	}
	if final.Status != "complete" {
		t.Errorf("expected status complete, got %s", final.Status)
	}
}
