package orchestrator

// Goroutine-leak regression test for the runPMParallel fan-out path.
//
// runPMParallel spawns one goroutine per ready task plus one wg.Wait
// closer goroutine per round. On the happy path each worker exits when
// its provider's Complete call returns, the closer's wg.Wait unblocks
// and it close()s waitDone, the outer select's `<-waitDone` returns,
// and the round proceeds to result processing. A regression that left
// any of these goroutines pinned (e.g. a missed wg.Done after a new
// branch, a closer that blocked on a never-receiving channel, a
// per-task ctx whose cancel wasn't deferred) would scale linearly with
// the number of orchestrator invocations.
//
// This test mirrors the macroscopic shape of the WS+SSE
// (pkg/ui/goroutine_leak_test.go) and consensus/compare
// (pkg/compare/goroutine_leak_test.go, pkg/consensus/goroutine_leak_test.go)
// regression guards: open N short-lived sessions, then assert
// runtime.NumGoroutine has returned to within a small slack of the
// pre-test baseline. With N=20 a per-invocation leak produces a delta
// of ~20-60, far above the slack threshold; ambient flapping from the
// runtime/scheduler is ~0-3.

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// orchGoroutineLeakSlack absorbs runtime/scheduler ambient flapping.
// Picked to be much smaller than any real per-invocation leak would
// produce at N=20.
const orchGoroutineLeakSlack = 10

// settleOrchGoroutineCount triggers GC and sleeps briefly so transient
// goroutines have a chance to exit before sampling NumGoroutine. The
// state.Save path uses atomicfile.Write which fsyncs the parent dir
// after rename — that's a syscall, not a goroutine, but we still want
// to flush the scheduler so any deferred cleanup completes.
func settleOrchGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// TestRunPMParallel_NoGoroutineLeak runs N happy-path runPMParallel
// invocations and asserts runtime.NumGoroutine returns to within
// orchGoroutineLeakSlack of the pre-test baseline. Each invocation
// runs against its own fresh tempdir + state so there's no
// cross-iteration state coupling, and uses a 3-task plan so each
// round actually exercises the fan-out (>1 worker per round).
//
// Catches regressions in:
//   - per-task wg.Done deferral
//   - per-task ctx cancel deferral
//   - wg.Wait closer goroutine teardown
//   - safeComplete's panic-recovery cleanup
func TestRunPMParallel_NoGoroutineLeak(t *testing.T) {
	prov := &safeProvider{name: "mock", output: "ok\nTASK_DONE"}

	// Warm up: one invocation so any one-time package init doesn't
	// pollute the baseline. Uses a separate tempdir from the loop
	// iterations so no leftover state is reused.
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
		if err := o.Run(context.Background()); err != nil {
			t.Fatalf("warmup Run: %v", err)
		}
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
		if err := o.Run(context.Background()); err != nil {
			t.Fatalf("iter %d: Run: %v", i, err)
		}

		final, err := state.Load(dir)
		if err != nil {
			t.Fatalf("iter %d: state.Load: %v", i, err)
		}
		for _, task := range final.Plan.Tasks {
			if task.Status != pm.TaskDone {
				t.Fatalf("iter %d: task %d expected done, got %s", i, task.ID, task.Status)
			}
		}
		if final.Status != "complete" {
			t.Fatalf("iter %d: expected status complete, got %s", i, final.Status)
		}
	}

	post := settleOrchGoroutineCount()
	delta := post - baseline
	if delta > orchGoroutineLeakSlack {
		t.Fatalf("goroutine leak in runPMParallel: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, orchGoroutineLeakSlack, N)
	}
}
