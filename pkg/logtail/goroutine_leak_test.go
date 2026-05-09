package logtail

// Goroutine-leak regression test for the Follow lifecycle.
//
// Follow is documented as not-internally-concurrent: callers (cmd/daemon_cmd.go,
// cmd/agent_cmd.go) spawn it in their own goroutine and drive cancellation via
// ctx. The function itself relies on:
//   - one *time.Timer per sleep() call, with `defer t.Stop()` in the same
//     scope, so a select-on-ctx exit path must release the timer's goroutine
//   - one *os.File handle held across iterations, with closeF() invoked from
//     a top-level defer
//   - bufio.Reader allocated per-open, no goroutines of its own
//
// The cancellation surface is wider than it looks: Follow can exit via ctx
// during the initial-open backoff, during the missing-file recovery loop,
// during a normal poll wait, or during the post-emit fast-poll wait. A
// regression in any of those (a select that forgot a ctx.Done branch, a timer
// whose Stop wasn't called before re-assigning the local var) would pin a
// goroutine per cancelled invocation.
//
// This test mirrors the macroscopic shape of the WS+SSE
// (pkg/ui/goroutine_leak_test.go), consensus/compare, runPMParallel, bench,
// and filewatch goroutine-leak guards: run N short-lived lifecycles across
// the documented exit paths, then assert runtime.NumGoroutine returns to
// within a small slack of the pre-test baseline.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// goroutineLeakSlack absorbs runtime/scheduler ambient flapping. Picked to
// be much smaller than any real per-call leak would produce at N=20.
const goroutineLeakSlack = 10

// settleGoroutineCount triggers GC and sleeps briefly so transient
// goroutines (timer-fired closures, fsnotify deferred cleanup) have a chance
// to exit before sampling NumGoroutine.
func settleGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(80 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// runFollowLifecycle starts Follow in a goroutine, optionally appends a few
// lines so the fast-poll branch is exercised, then cancels and waits for
// Follow to return. Returns the byte count emitted for sanity checking.
func runFollowLifecycle(t *testing.T, fileExistsAtStart, appendBytes bool) int {
	t.Helper()

	dir := t.TempDir()
	p := filepath.Join(dir, "leak.log")
	if fileExistsAtStart {
		if err := os.WriteFile(p, []byte(""), 0644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
	}

	out := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- followWithConfig(ctx, p, out, fastFollowConfig()) }()

	if fileExistsAtStart && appendBytes {
		// Wait briefly for Follow to reach its initial seek-to-EOF, then
		// append so the post-emit fast-poll branch executes at least once.
		time.Sleep(20 * time.Millisecond)
		appendTo(t, p, "x\n")
		_ = waitFor(500*time.Millisecond, func() bool {
			return len(out.String()) > 0
		})
	} else if !fileExistsAtStart {
		// Let Follow back off on the missing file briefly so we exercise
		// the cancel-during-initial-backoff path.
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Follow returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Follow did not return within 2s of ctx cancel")
	}
	return len(out.String())
}

// TestFollow_NoGoroutineLeak runs N happy-path Follow lifecycles where the
// file exists at start and a few bytes are appended (exercises the fast-poll
// branch + main poll branch + ctx-cancel-from-poll exit path), then asserts
// runtime.NumGoroutine returns to within goroutineLeakSlack of the
// pre-test baseline. With N=20 a per-invocation leak produces a delta of
// ~20-60, far above the slack threshold; ambient flapping is ~0-3.
//
// Catches regressions in:
//   - sleep() select missing a ctx.Done branch
//   - timer.Stop() deferral against the re-assigned local
//   - closeF() deferral on the Follow exit path
//   - bufio.Reader / *os.File handle accounting
func TestFollow_NoGoroutineLeak(t *testing.T) {
	// Warm-up: one invocation so any one-time package init (rand seeding,
	// scheduler warmup) doesn't pollute the baseline.
	runFollowLifecycle(t, true, true)

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		_ = runFollowLifecycle(t, true, true)
	}

	post := settleGoroutineCount()
	if delta := post - baseline; delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak: baseline=%d post=%d delta=%d (slack=%d after %d Follow lifecycles)",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// TestFollow_NoGoroutineLeak_MissingFileCancel runs N Follow lifecycles
// where the file never exists, so each invocation cancels while still in
// the initial-open backoff loop. Catches regressions in the missing-file
// backoff sleep's ctx.Done handling and the top-level defer closeF when
// no file was ever opened.
func TestFollow_NoGoroutineLeak_MissingFileCancel(t *testing.T) {
	runFollowLifecycle(t, false, false)

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		_ = runFollowLifecycle(t, false, false)
	}

	post := settleGoroutineCount()
	if delta := post - baseline; delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in missing-file cancel path: baseline=%d post=%d delta=%d (slack=%d after %d lifecycles)",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// TestFollow_NoGoroutineLeak_Concurrent runs many Follow lifecycles
// concurrently to surface any shared-state goroutine accounting bugs (e.g. a
// package-level timer registry) that single-threaded runs would mask. All
// followers hit a fresh tempdir, so they cannot interfere with each other's
// rotation/truncation detection.
func TestFollow_NoGoroutineLeak_Concurrent(t *testing.T) {
	runFollowLifecycle(t, true, false)

	baseline := settleGoroutineCount()

	const concurrency = 8
	const rounds = 4

	var wg sync.WaitGroup
	for r := 0; r < rounds; r++ {
		wg.Add(concurrency)
		for c := 0; c < concurrency; c++ {
			go func(label string) {
				defer wg.Done()
				_ = runFollowLifecycle(t, true, true)
			}(fmt.Sprintf("r%dc%d", r, c))
		}
		wg.Wait()
	}

	post := settleGoroutineCount()
	if delta := post - baseline; delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak under concurrent Follow: baseline=%d post=%d delta=%d (slack=%d after %d lifecycles across %d rounds of %d)",
			baseline, post, delta, goroutineLeakSlack, concurrency*rounds, rounds, concurrency)
	}
}
