package consensus

// Goroutine-leak regression test for the parallel fan-out + judge paths.
//
// RunConsensus spawns one goroutine per provider in the fan-out, one
// wg.Wait closer goroutine, plus (when more than one valid candidate
// survives) one judge goroutine. On the happy path all of these must
// exit before RunConsensus returns. A regression in any cleanup chain
// (a missed wg.Done, a closer that blocked on a never-receiving channel,
// a judge goroutine that orphaned its judgeCh send) would scale linearly
// with the number of consensus invocations.
//
// This test is deliberately macroscopic: it runs N happy-path
// RunConsensus calls, then asserts runtime.NumGoroutine has returned to
// within a small slack of the pre-test baseline. With N=20 a per-call
// leak produces a delta of ~20-60, far above the slack threshold;
// ambient flapping is ~0-3.

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

// TestRunConsensus_NoGoroutineLeak runs N happy-path RunConsensus
// invocations with two valid candidates (forcing the judge path) and
// verifies runtime.NumGoroutine returns to within goroutineLeakSlack of
// the pre-test baseline. Catches regressions in worker / wg.Wait closer
// / judge goroutine teardown.
func TestRunConsensus_NoGoroutineLeak(t *testing.T) {
	a := &staticProvider{name: "a", output: "response-a"}
	b := &staticProvider{name: "b", output: "response-b"}
	// Judge returns a valid scoring JSON for both candidates so the
	// happy path through RunConsensus completes (judge call -> winner
	// selection -> return).
	judge := &staticProvider{
		name:   "judge",
		output: `[{"provider":"a","correctness":7,"safety":8,"completeness":7,"rationale":"ok"},{"provider":"b","correctness":6,"safety":8,"completeness":6,"rationale":"meh"}]`,
	}

	// Warm up: one invocation so any one-time package init doesn't
	// pollute the baseline.
	if _, _, err := RunConsensus(
		context.Background(),
		[]provider.Provider{a, b},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		judge, "", 2, 1, "warmup",
	); err != nil {
		t.Fatalf("warmup RunConsensus: %v", err)
	}

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		out, rep, err := RunConsensus(
			context.Background(),
			[]provider.Provider{a, b},
			"prompt",
			provider.Options{Timeout: 5 * time.Second},
			judge, "", 2, 1, "test",
		)
		if err != nil {
			t.Fatalf("iter %d: RunConsensus: %v", i, err)
		}
		if out == "" || rep == nil {
			t.Fatalf("iter %d: empty output or nil report", i)
		}
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in consensus.RunConsensus: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// TestRunConsensus_NoGoroutineLeak_SingleValid runs N invocations where
// only one candidate is valid (one panicker), exercising the
// "skip judge" branch. Verifies the worker / closer teardown is leak-free
// even when the judge goroutine is never spawned.
func TestRunConsensus_NoGoroutineLeak_SingleValid(t *testing.T) {
	good := &staticProvider{name: "good", output: "valid"}
	bad := &panicProvider{name: "bad"}

	// Warm up.
	if _, _, err := RunConsensus(
		context.Background(),
		[]provider.Provider{good, bad},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		good, "", 2, 1, "warmup",
	); err != nil {
		t.Fatalf("warmup RunConsensus: %v", err)
	}

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		_, _, err := RunConsensus(
			context.Background(),
			[]provider.Provider{good, bad},
			"prompt",
			provider.Options{Timeout: 5 * time.Second},
			good, "", 2, 1, "test",
		)
		if err != nil {
			t.Fatalf("iter %d: RunConsensus: %v", i, err)
		}
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in consensus.RunConsensus single-valid path: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}
