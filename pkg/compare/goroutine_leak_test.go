package compare

// Goroutine-leak regression test for the parallel fan-out path.
//
// compare.Run spawns one goroutine per provider plus one wg.Wait closer
// goroutine. On the happy path all workers exit when their Complete call
// returns, the closer's wg.Wait unblocks and it close()s waitDone, and
// outer Run's `<-waitDone` returns. A regression that left any of these
// goroutines pinned (e.g. a missed wg.Done, an unbuffered closer that
// blocked on a never-receiving channel) would scale linearly with the
// number of compare invocations.
//
// This test is deliberately macroscopic: it runs N happy-path Run() calls,
// then asserts runtime.NumGoroutine has returned to within a small slack
// of the pre-test baseline. With N=20 a per-call leak produces a delta of
// ~20-60, far above the slack threshold; ambient flapping is ~0-3.

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// goroutineLeakSlack absorbs runtime/scheduler ambient flapping. Picked to
// be much smaller than any real per-call leak would produce at N=20.
const goroutineLeakSlack = 10

// settleGoroutineCount triggers GC and sleeps briefly so transient
// goroutines have a chance to exit before sampling NumGoroutine.
func settleGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// TestRun_NoGoroutineLeak runs N happy-path Run() invocations and verifies
// runtime.NumGoroutine returns to within goroutineLeakSlack of the
// pre-test baseline. Catches regressions in worker / wg.Wait closer
// teardown.
func TestRun_NoGoroutineLeak(t *testing.T) {
	a := fastProvider{name: "a"}
	b := fastProvider{name: "b"}
	c := fastProvider{name: "c"}
	provs := []provider.Provider{a, b, c}

	// Warm up: one Run() so any one-time package init doesn't pollute the
	// baseline.
	_ = Run(context.Background(), "warmup", provs, "", time.Second)

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		results := Run(context.Background(), "prompt", provs, "", time.Second)
		if len(results) != len(provs) {
			t.Fatalf("iter %d: expected %d results, got %d", i, len(provs), len(results))
		}
		for j, r := range results {
			if r == nil || r.Err != nil {
				t.Fatalf("iter %d: result[%d] err: %v", i, j, r)
			}
		}
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in compare.Run: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// Note: the cancellation-path goroutine bound is already covered by
// TestRun_HungProvider_HonoursGracePeriod in shutdown_test.go (which
// asserts elapsed < 5s rather than NumGoroutine, since the leaked-worker
// path intentionally races on results[idx] writes — see the comment in
// Run() at the watchdog branch — and that race trips -race detection
// even though it's logically safe).
