package filewatch

// Goroutine-leak regression test for the filewatch.Run lifecycle.
//
// Run spawns:
//  1. fsnotify watcher's internal event/error goroutines (cleaned up by
//     watcher.Close in the deferred call).
//  2. time.AfterFunc-fired fireTrigger goroutines (one per debounced batch).
//     Each Add to fireWG must net to exactly one Done — either via Stop()
//     returning true (cancelled before fire) or via fireTrigger's
//     defer-wg.Done (fired). shutdown() drains fireWG.Wait before Run
//     returns so all in-flight triggers have completed.
//
// A regression in any of those (a missed wg.Done in the Stop branch, a
// fireTrigger that panicked before reaching its defer recover, a watcher
// close path that orphaned its inner goroutines) would scale linearly with
// the number of Run() invocations.
//
// This test mirrors the pattern in pkg/orchestrator/goroutine_leak_test.go
// and pkg/bench/goroutine_leak_test.go: run N happy-path lifecycles, then
// assert runtime.NumGoroutine has returned to within a small slack of the
// pre-test baseline.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// goroutineLeakSlack absorbs runtime/scheduler ambient flapping. Picked to
// be much smaller than any real per-call leak would produce at N=15.
const goroutineLeakSlack = 10

// settleGoroutineCount triggers GC and sleeps briefly so transient
// goroutines have a chance to exit before sampling NumGoroutine.
func settleGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(80 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// runOneLifecycle runs filewatch.Run inside a goroutine, optionally writes
// a few files to fire the debounce timer at least once, then cancels and
// waits for Run to return. Returns the trigger count for sanity checking.
func runOneLifecycle(t *testing.T, fireEvents bool) int32 {
	t.Helper()

	tmpDir := t.TempDir()

	s, err := state.Init(tmpDir, "test", 10)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "test",
		Tasks: []*pm.Task{
			{ID: 1, Title: "fix file", Status: pm.TaskFailed},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	subDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "seed.go"), []byte("package src"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := Config{
		WorkDir:  tmpDir,
		Globs:    []string{"src/**/*.go"},
		Debounce: 20 * time.Millisecond,
	}

	var triggerCount int32
	onTrigger := func(evt ChangeEvent) {
		atomic.AddInt32(&triggerCount, 1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, cfg, onTrigger)
	}()

	// Give the watcher a moment to start before generating events.
	time.Sleep(40 * time.Millisecond)

	if fireEvents {
		for i := 0; i < 5; i++ {
			path := filepath.Join(subDir, fmt.Sprintf("file%d.go", i))
			if err := os.WriteFile(path, []byte("package src"), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		// Wait long enough for the debounce timer to fire and fireTrigger
		// to run to completion before we cancel.
		time.Sleep(80 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s after cancel")
	}

	return atomic.LoadInt32(&triggerCount)
}

// TestRun_NoGoroutineLeak_NoEvents runs N start/cancel cycles with no file
// events. Catches regressions where the fsnotify watcher's inner goroutines
// outlive the deferred Close, or where shutdown() fails to balance a
// pending fireWG.Add. With no events, scheduleFire is never called so the
// dominant accounting target is the fsnotify watcher lifecycle.
func TestRun_NoGoroutineLeak_NoEvents(t *testing.T) {
	// Warm up: one cycle so any one-time fsnotify init doesn't pollute the
	// baseline.
	runOneLifecycle(t, false)

	baseline := settleGoroutineCount()

	const N = 15
	for i := 0; i < N; i++ {
		runOneLifecycle(t, false)
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in filewatch.Run (no events): baseline=%d post=%d delta=%d (>%d) after %d cycles",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// TestRun_NoGoroutineLeak_WithEvents runs N start/cancel cycles where each
// cycle fires the debounce timer at least once, exercising the
// fireWG.Add → fireTrigger → fireWG.Done accounting path. A regression
// where fireTrigger panicked before reaching its defer wg.Done, or where
// scheduleFire's Stop()-returns-true branch double-counted, would leak one
// goroutine per cycle and trip the slack threshold.
func TestRun_NoGoroutineLeak_WithEvents(t *testing.T) {
	// Warm up.
	if got := runOneLifecycle(t, true); got == 0 {
		t.Fatal("warmup: expected at least one trigger to fire")
	}

	baseline := settleGoroutineCount()

	const N = 15
	var totalTriggers int32
	for i := 0; i < N; i++ {
		totalTriggers += runOneLifecycle(t, true)
	}

	if totalTriggers == 0 {
		t.Fatal("expected debounce timer to fire across cycles")
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in filewatch.Run (with events): baseline=%d post=%d delta=%d (>%d) after %d cycles, %d total triggers",
			baseline, post, delta, goroutineLeakSlack, N, totalTriggers)
	}
}
