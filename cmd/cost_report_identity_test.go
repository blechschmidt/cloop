package cmd

// Tests for the attribution arithmetic behind `cloop cost report --by-identity`.

import (
	"math"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
)

func TestAggregateByIdentity(t *testing.T) {
	ts := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	entry := func(identity string, in, out, think int, usd float64) cost.LedgerEntry {
		return cost.LedgerEntry{
			Timestamp:      ts,
			Identity:       identity,
			InputTokens:    in,
			OutputTokens:   out,
			ThinkingTokens: think,
			EstimatedUSD:   usd,
		}
	}

	tests := []struct {
		name    string
		entries []cost.LedgerEntry
		want    []identityRow
	}{
		{
			name: "sums tokens and spend across an identity's entries",
			entries: []cost.LedgerEntry{
				entry("ana@example.com", 100, 10, 5, 0.30),
				entry("ana@example.com", 200, 20, 0, 0.20),
				entry("bo@example.com", 50, 5, 1, 0.10),
			},
			want: []identityRow{
				{identity: "ana@example.com", inputTokens: 300, outputTokens: 30, thinkingTokens: 5, usd: 0.50, count: 2},
				{identity: "bo@example.com", inputTokens: 50, outputTokens: 5, thinkingTokens: 1, usd: 0.10, count: 1},
			},
		},
		{
			name: "empty identity is labelled unattributed, not folded into local",
			entries: []cost.LedgerEntry{
				entry(cost.IdentityLocal, 10, 1, 0, 0.40),
				entry("", 20, 2, 0, 0.30),
				entry("", 30, 3, 0, 0.20),
			},
			want: []identityRow{
				{identity: cost.IdentityUnattributed, inputTokens: 50, outputTokens: 5, usd: 0.50, count: 2},
				{identity: cost.IdentityLocal, inputTokens: 10, outputTokens: 1, usd: 0.40, count: 1},
			},
		},
		{
			name: "orders by spend descending with name breaking ties",
			entries: []cost.LedgerEntry{
				entry("carol@example.com", 1, 1, 0, 0.25),
				entry("sub:zed", 1, 1, 0, 0.75),
				entry("alice@example.com", 1, 1, 0, 0.25),
				entry(cost.IdentityLocal, 1, 1, 0, 0.50),
			},
			want: []identityRow{
				{identity: "sub:zed", inputTokens: 1, outputTokens: 1, usd: 0.75, count: 1},
				{identity: cost.IdentityLocal, inputTokens: 1, outputTokens: 1, usd: 0.50, count: 1},
				{identity: "alice@example.com", inputTokens: 1, outputTokens: 1, usd: 0.25, count: 1},
				{identity: "carol@example.com", inputTokens: 1, outputTokens: 1, usd: 0.25, count: 1},
			},
		},
		{
			name:    "no entries yields no rows",
			entries: nil,
			want:    []identityRow{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := aggregateByIdentity(tc.entries)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, want := range tc.want {
				g := got[i]
				if g.identity != want.identity {
					t.Errorf("row %d: identity = %q, want %q", i, g.identity, want.identity)
				}
				if g.count != want.count {
					t.Errorf("row %d (%s): count = %d, want %d", i, want.identity, g.count, want.count)
				}
				if g.inputTokens != want.inputTokens {
					t.Errorf("row %d (%s): inputTokens = %d, want %d", i, want.identity, g.inputTokens, want.inputTokens)
				}
				if g.outputTokens != want.outputTokens {
					t.Errorf("row %d (%s): outputTokens = %d, want %d", i, want.identity, g.outputTokens, want.outputTokens)
				}
				if g.thinkingTokens != want.thinkingTokens {
					t.Errorf("row %d (%s): thinkingTokens = %d, want %d", i, want.identity, g.thinkingTokens, want.thinkingTokens)
				}
				// Summed floats, so compare within a fraction of a cent.
				if math.Abs(g.usd-want.usd) > 1e-9 {
					t.Errorf("row %d (%s): usd = %v, want %v", i, want.identity, g.usd, want.usd)
				}
			}
		})
	}
}

// TestAggregateByIdentityIsDeterministic guards the map-iteration hazard: equal
// spend must still come back in the same order on every call.
func TestAggregateByIdentityIsDeterministic(t *testing.T) {
	entries := []cost.LedgerEntry{
		{Identity: "d@example.com", EstimatedUSD: 1},
		{Identity: "c@example.com", EstimatedUSD: 1},
		{Identity: "b@example.com", EstimatedUSD: 1},
		{Identity: "a@example.com", EstimatedUSD: 1},
		{Identity: "", EstimatedUSD: 1},
	}
	first := aggregateByIdentity(entries)
	for i := 0; i < 50; i++ {
		got := aggregateByIdentity(entries)
		for j := range got {
			if got[j].identity != first[j].identity {
				t.Fatalf("run %d row %d: identity = %q, want %q", i, j, got[j].identity, first[j].identity)
			}
		}
	}
	// All spend is equal, so the name tiebreak fixes the order outright.
	want := []string{cost.IdentityUnattributed, "a@example.com", "b@example.com", "c@example.com", "d@example.com"}
	for i, w := range want {
		if first[i].identity != w {
			t.Errorf("row %d: identity = %q, want %q", i, first[i].identity, w)
		}
	}
}
