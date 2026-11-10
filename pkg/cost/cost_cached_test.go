package cost

import (
	"math"
	"testing"
)

func TestEstimateCachedPricesCacheTokensAtTheirOwnRates(t *testing.T) {
	// claude-sonnet-5: $2 in, $10 out per million; a cache read is a tenth of
	// the input price, a 5-minute write 1.25 times it, a 1-hour write twice.
	u := CachedUsage{Input: 1_000_000, Output: 1_000_000, CacheRead: 1_000_000,
		CacheWrite5m: 1_000_000, CacheWrite1h: 1_000_000}
	got, ok := EstimateCached("claude-sonnet-5-20260901", u)
	if !ok {
		t.Fatal("a dated sonnet-5 id was not priced")
	}
	want := 2.0 + 10.0 + 0.2 + 2.5 + 4.0
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("EstimateCached = %v, want %v", got, want)
	}
	// With no cache tokens it is Estimate.
	plain, _ := Estimate("claude-sonnet-5", 1234, 567)
	if c, _ := EstimateCached("claude-sonnet-5", CachedUsage{Input: 1234, Output: 567}); math.Abs(c-plain) > 1e-12 {
		t.Fatalf("EstimateCached without cache tokens = %v, Estimate = %v", c, plain)
	}
	if _, ok := EstimateCached("not-a-model", u); ok {
		t.Fatal("an unknown model was priced")
	}
}

// Anthropic bills cache reads on the newest models below the usual tenth of
// the input price: a fortieth on Fable 5.1 and 5.2 and Mythos 5.1 and 5.2, a
// twentieth on Opus 5.5 and Sonnet 5.5. An agent harness's input is mostly
// cache reads, so the standard tenth would meter a relayed Fable 5.2 run at
// several times what it costs and stop it at its spend cap far too early.
func TestEstimateCachedPricesEachModelsCacheReads(t *testing.T) {
	read := CachedUsage{CacheRead: 1_000_000}
	for model, want := range map[string]float64{
		"claude-fable-5-2":  0.20, // $8 × 0.025
		"claude-fable-5-1":  0.25, // $10 × 0.025
		"claude-mythos-5-2": 0.20,
		"claude-fable-5":    1.00, // $10 × 0.1
		"claude-opus-5-5":   0.20, // $4 × 0.05
		"claude-sonnet-5-5": 0.10, // $2 × 0.05
		"claude-opus-4-8":   0.50, // $5 × 0.1
		// Haiku 5.5's cache reads are in TestEstimateCachedAppliesHaiku55LongPromptPrice:
		// a million of them in one request is a long prompt.
	} {
		got, ok := EstimateCached(model, read)
		if !ok || math.Abs(got-want) > 1e-9 {
			t.Errorf("EstimateCached(%s, 1M cache reads) = %v, %v; want %v", model, got, ok, want)
		}
	}
	// Writes keep their usual multiples on every model.
	got, _ := EstimateCached("claude-fable-5-2", CachedUsage{CacheWrite5m: 1_000_000, CacheWrite1h: 1_000_000})
	if want := 10.0 + 16.0; math.Abs(got-want) > 1e-9 {
		t.Errorf("Fable 5.2 cache writes = %v, want %v", got, want)
	}
}

// Claude Haiku 5.5 costs five times as much for a request whose prompt is
// over 100,000 tokens, and the prompt counts cache reads and writes too.
// EstimateCached sees one response, so it can tell; Estimate sees totals
// across many requests, so it cannot and stays at the standard price.
func TestEstimateCachedAppliesHaiku55LongPromptPrice(t *testing.T) {
	cases := []struct {
		name string
		u    CachedUsage
		want float64
	}{
		{"at the threshold", CachedUsage{Input: 100_000, Output: 1_000_000}, 0.01 + 0.50},
		{"cache reads at the threshold", CachedUsage{CacheRead: 100_000}, 100_000 * 0.01 / 1e6},
		{"one token over", CachedUsage{Input: 100_001, Output: 1_000_000}, 5 * (100_001*0.10/1e6 + 0.50)},
		{"over by cache reads", CachedUsage{Input: 1, CacheRead: 100_000}, 5 * (0.10/1e6 + 100_000*0.01/1e6)},
		{"over by cache writes", CachedUsage{CacheWrite5m: 60_000, CacheWrite1h: 40_001},
			5 * (60_000*0.125/1e6 + 40_001*0.20/1e6)},
	}
	for _, c := range cases {
		got, ok := EstimateCached("claude-haiku-5-5", c.u)
		if !ok || math.Abs(got-c.want) > 1e-12 {
			t.Errorf("%s: EstimateCached = %v, %v; want %v", c.name, got, ok, c.want)
		}
	}
	// Other models have one price at any length.
	got, _ := EstimateCached("claude-sonnet-4-6", CachedUsage{Input: 900_000})
	if want := 900_000 * 3.0 / 1e6; math.Abs(got-want) > 1e-9 {
		t.Errorf("Sonnet 4.6 at 900k input = %v, want %v", got, want)
	}
	// Totals are priced at the standard rate.
	if got, _ := Estimate("claude-haiku-5-5", 2_000_000, 1_000_000); math.Abs(got-(0.20+0.50)) > 1e-9 {
		t.Errorf("Estimate(claude-haiku-5-5, 2M, 1M) = %v, want 0.70", got)
	}
}
