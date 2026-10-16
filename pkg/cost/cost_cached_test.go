package cost

import (
	"math"
	"testing"
)

func TestEstimateCachedPricesCacheTokensAtTheirOwnRates(t *testing.T) {
	// claude-sonnet-5: $3 in, $15 out per million.
	u := CachedUsage{Input: 1_000_000, Output: 1_000_000, CacheRead: 1_000_000,
		CacheWrite5m: 1_000_000, CacheWrite1h: 1_000_000}
	got, ok := EstimateCached("claude-sonnet-5-20260901", u)
	if !ok {
		t.Fatal("a dated sonnet-5 id was not priced")
	}
	want := 3.0 + 15.0 + 0.3 + 3.75 + 6.0
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
