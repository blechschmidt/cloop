package cost

import (
	"math"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// The pricing table is the only thing standing between a spend ceiling and a
// run it cannot see. An unpriced model is not an error anywhere in this
// package: lookup misses, Estimate reports (0, false), and EstimateSessionCost
// converts that into a plain 0. A budget cap comparing spend against a limit
// therefore reads an unpriced model as free and never fires.
//
// That is not hypothetical — the whole Claude 5 family was selectable in the
// dashboard's model picker while absent from this table, so every run on one
// of them booked as costing nothing. Later, Claude Haiku 5.5 was missing and
// Claude Fable 5.2 was priced as Fable 5 by the prefix fallback. These tests
// hold every model cloop offers (provider.ClaudeModels) to the price Anthropic
// publishes, so the next model added fails here rather than silently in a
// budget.

// anthropicPricing is Anthropic's published price for each Claude model, per
// million tokens, from https://platform.claude.com/docs/en/about-claude/pricing
// (checked 2026-11-10). A model added to provider.ClaudeModels needs a row.
var anthropicPricing = map[string]ModelPricing{
	"claude-fable-5-2":  {InputPerM: 8, OutputPerM: 40, CacheReadFactor: 0.025},
	"claude-fable-5-1":  {InputPerM: 10, OutputPerM: 50, CacheReadFactor: 0.025},
	"claude-fable-5":    {InputPerM: 10, OutputPerM: 50},
	"claude-opus-5-5":   {InputPerM: 4, OutputPerM: 20, CacheReadFactor: 0.05},
	"claude-opus-5":     {InputPerM: 5, OutputPerM: 25},
	"claude-opus-4-8":   {InputPerM: 5, OutputPerM: 25},
	"claude-opus-4-7":   {InputPerM: 5, OutputPerM: 25},
	"claude-opus-4-6":   {InputPerM: 5, OutputPerM: 25},
	"claude-opus-4-5":   {InputPerM: 5, OutputPerM: 25},
	"claude-sonnet-5-5": {InputPerM: 2, OutputPerM: 10, CacheReadFactor: 0.05},
	"claude-sonnet-5":   {InputPerM: 2, OutputPerM: 10},
	"claude-sonnet-4-6": {InputPerM: 3, OutputPerM: 15},
	"claude-sonnet-4-5": {InputPerM: 3, OutputPerM: 15},
	"claude-haiku-5-5":  {InputPerM: 0.10, OutputPerM: 0.50, LongPromptOver: 100_000, LongPromptFactor: 5},
	"claude-haiku-4-5":  {InputPerM: 1, OutputPerM: 5},
	// Not offered by any picker (limited availability), but relayable.
	"claude-mythos-5-2": {InputPerM: 8, OutputPerM: 40, CacheReadFactor: 0.025},
	"claude-mythos-5-1": {InputPerM: 10, OutputPerM: 50, CacheReadFactor: 0.025},
	"claude-mythos-5":   {InputPerM: 10, OutputPerM: 50},
}

// Every model cloop offers has an entry of its own. A prefix match is not
// enough: it prices a new model as its older neighbour, which is how Claude
// Fable 5.2 ($8/$40) was booked at Fable 5's $10/$50.
func TestEveryOfferedClaudeModelHasItsPublishedPrice(t *testing.T) {
	for _, m := range provider.ClaudeModels {
		want, published := anthropicPricing[m.ID]
		if !published {
			t.Errorf("%s is offered (provider.ClaudeModels) but this test has no published "+
				"price for it: add a row to anthropicPricing from Anthropic's pricing page", m.ID)
			continue
		}
		got, ok := prices[m.ID]
		if !ok {
			t.Errorf("%s has no entry of its own in the prices table in cost.go; an unpriced "+
				"model costs 0, so any budget cap would treat every run on it as free", m.ID)
			continue
		}
		if got != want {
			t.Errorf("prices[%q] = %+v, want the published %+v", m.ID, got, want)
		}
	}
	for id, want := range anthropicPricing {
		if got := prices[id]; got != want {
			t.Errorf("prices[%q] = %+v, want the published %+v", id, got, want)
		}
	}
}

func TestEstimate_SelectableModelsArePriced(t *testing.T) {
	// Exactly 1M input and 1M output tokens, so the expected cost is the sum
	// of the two per-1M rates and an arithmetic slip cannot hide behind a
	// scaling factor.
	const oneMillion = 1_000_000

	for _, m := range provider.ClaudeModels {
		model := m.ID
		t.Run(model, func(t *testing.T) {
			got, ok := Estimate(model, oneMillion, oneMillion)
			if !ok {
				t.Fatalf("Estimate(%q) reported no price. An unpriced model "+
					"costs 0, so any budget cap would treat every run on it as "+
					"free — add it to the prices table in cost.go.", model)
			}
			want := anthropicPricing[model]
			if wantUSD := want.InputPerM + want.OutputPerM; math.Abs(got-wantUSD) > 1e-9 {
				t.Errorf("Estimate(%q, 1M, 1M) = %.4f, want %.4f",
					model, got, wantUSD)
			}
		})
	}
}

// A newer model's ID often extends an older one's (claude-opus-5-5 and
// claude-opus-5, claude-fable-5-2 and claude-fable-5), and lookup falls back
// to a longest-prefix match. Exact matching must win, or the newer model is
// priced as the older one.
func TestLookup_ExactMatchBeatsPrefix(t *testing.T) {
	for _, model := range []string{"claude-opus-5-5", "claude-fable-5-2", "claude-fable-5-1", "claude-sonnet-5-5"} {
		got, ok := lookup(model)
		if !ok {
			t.Fatalf("%s is absent from the prices table", model)
		}
		if want := prices[model]; got != want {
			t.Errorf("lookup(%s) = %+v, want the exact entry %+v "+
				"(a shorter prefix key must not shadow it)", model, got, want)
		}
	}
	// A dated or later point release still finds its line's price.
	if got, ok := lookup("claude-opus-4-5-20251101"); !ok || got != prices["claude-opus-4-5"] {
		t.Errorf("lookup(claude-opus-4-5-20251101) = %+v, %v; want the claude-opus-4-5 price", got, ok)
	}
}

// Callers pass model IDs as they were configured; case and stray spaces must
// not turn a priced model into a free one.
func TestEstimate_MatchesModelCaseInsensitively(t *testing.T) {
	got, ok := Estimate(" Claude-Fable-5-2 ", 1_000_000, 0)
	if !ok || math.Abs(got-8) > 1e-9 {
		t.Errorf("Estimate(\" Claude-Fable-5-2 \", 1M, 0) = %v, %v; want 8, true", got, ok)
	}
}

// EstimateSessionCost is what the budget path actually calls, and it collapses
// the (0, false) miss into a bare 0 — so a caller cannot distinguish "free"
// from "unknown". Assert the models we ship as selectable never reach it.
func TestEstimateSessionCost_ClaudeCodeModelsAreNotFree(t *testing.T) {
	for _, m := range provider.ClaudeModels {
		if usd := EstimateSessionCost("claudecode", m.ID, 1_000_000, 1_000_000); usd <= 0 {
			t.Errorf("EstimateSessionCost(claudecode, %q) = %v; a selectable "+
				"model that estimates as free defeats the spend ceiling",
				m.ID, usd)
		}
	}
}

// Local models are deliberately free, and that must survive the checks above.
func TestEstimateSessionCost_OllamaIsFree(t *testing.T) {
	if usd := EstimateSessionCost("ollama", "llama3.2", 1_000_000, 1_000_000); usd != 0 {
		t.Errorf("EstimateSessionCost(ollama, llama3.2) = %v, want 0", usd)
	}
}
