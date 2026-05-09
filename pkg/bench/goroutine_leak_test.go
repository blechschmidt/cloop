package bench

// Goroutine-leak regression test for the parallel fan-out + judge paths.
//
// bench.Run spawns one goroutine per provider in the fan-out, plus one
// wg.Wait closer goroutine that closes waitDone once all workers exit.
// When a JudgeProvider is configured, rateResponses additionally spawns
// one goroutine per scored response (each bounded by its own
// rateCtx + outCh + watchdog). On the happy path all of these must exit
// before Run returns. A regression in any cleanup chain (a missed
// wg.Done, a closer that blocked on a never-receiving channel, a judge
// goroutine that orphaned its outCh send) would scale linearly with the
// number of bench invocations.
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

// TestRun_NoGoroutineLeak runs N happy-path Run() invocations with three
// fast providers (no judge) and verifies runtime.NumGoroutine returns to
// within goroutineLeakSlack of the pre-test baseline. Catches regressions
// in worker / wg.Wait closer teardown.
func TestRun_NoGoroutineLeak(t *testing.T) {
	builders := map[string]provider.Provider{
		"a": fastProvider{name: "a"},
		"b": fastProvider{name: "b"},
		"c": fastProvider{name: "c"},
	}
	cfg := RunConfig{
		Prompt:    "prompt",
		Providers: []string{"a", "b", "c"},
		Runs:      1,
		Timeout:   5 * time.Second,
	}

	// Warm up: one Run() so any one-time package init doesn't pollute the
	// baseline.
	if _, err := Run(context.Background(), cfg, builders); err != nil {
		t.Fatalf("warmup Run: %v", err)
	}

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		rep, err := Run(context.Background(), cfg, builders)
		if err != nil {
			t.Fatalf("iter %d: Run: %v", i, err)
		}
		if rep == nil || len(rep.Results) != 3 {
			t.Fatalf("iter %d: expected 3 results, got %v", i, rep)
		}
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in bench.Run: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// scoringJudge always returns a fixed valid integer score so rateResponses
// completes the happy path (one judge goroutine per scored response, each
// joined via outCh receive before the next iteration starts).
type scoringJudge struct{}

func (scoringJudge) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	return &provider.Result{Output: "8", Provider: "judge", Model: "judge-model", InputTokens: 1, OutputTokens: 1}, nil
}
func (scoringJudge) Name() string         { return "judge" }
func (scoringJudge) DefaultModel() string { return "judge-model" }

// TestRun_NoGoroutineLeak_WithJudge runs N happy-path Run() invocations
// with a configured JudgeProvider, exercising both the fan-out goroutines
// and the per-response judge goroutines spawned by rateResponses. Verifies
// no leaks accumulate across the combined cleanup chains.
func TestRun_NoGoroutineLeak_WithJudge(t *testing.T) {
	builders := map[string]provider.Provider{
		"a":     fastProvider{name: "a"},
		"b":     fastProvider{name: "b"},
		"c":     fastProvider{name: "c"},
		"judge": scoringJudge{},
	}
	cfg := RunConfig{
		Prompt:        "prompt",
		Providers:     []string{"a", "b", "c"},
		Runs:          1,
		Timeout:       5 * time.Second,
		JudgeProvider: "judge",
	}

	// Warm up.
	if _, err := Run(context.Background(), cfg, builders); err != nil {
		t.Fatalf("warmup Run: %v", err)
	}

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		rep, err := Run(context.Background(), cfg, builders)
		if err != nil {
			t.Fatalf("iter %d: Run: %v", i, err)
		}
		if rep == nil || len(rep.Results) != 3 {
			t.Fatalf("iter %d: expected 3 results, got %v", i, rep)
		}
		// Sanity: judge actually ran.
		for _, r := range rep.Results {
			if r.QualityScore == 0 {
				t.Fatalf("iter %d: provider %s missing quality score", i, r.ProviderName)
			}
		}
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in bench.Run with judge: baseline=%d post=%d delta=%d (>%d) after %d invocations",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// Note: the cancellation-path goroutine bound is intentionally not covered
// here. TestRun_HungProvider_HonoursGracePeriod and
// TestRun_HungJudge_HonoursGracePeriod in shutdown_test.go assert the
// elapsed-time bound on the watchdog; the watchdog deliberately leaks the
// hung worker/judge goroutine until its own ctx-bounded Complete call
// returns (the buffered outCh / mu-guarded results append makes the leaked
// completion safe). A NumGoroutine assertion would fight that documented
// behaviour rather than catch a regression.
