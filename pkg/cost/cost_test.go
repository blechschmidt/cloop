package cost

import "testing"

// The pricing table is the only thing standing between a spend ceiling and a
// run it cannot see. An unpriced model is not an error anywhere in this
// package: lookup misses, Estimate reports (0, false), and EstimateSessionCost
// converts that into a plain 0. A budget cap comparing spend against a limit
// therefore reads an unpriced model as free and never fires.
//
// That is not hypothetical — the whole Claude 5 family was selectable in the
// dashboard's model picker while absent from this table, so every run on one
// of them booked as costing nothing. These tests pin the family down so the
// next model added to the picker fails here rather than silently in a budget.

// claude5Pricing is the expected per-1M-token rate for each Claude 5 model the
// dashboard offers. Keep it in step with the picker in assets/js/00-core.js.
var claude5Pricing = map[string]ModelPricing{
	"claude-opus-5-5":   {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-opus-5":     {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-sonnet-5":   {InputPerM: 3.00, OutputPerM: 15.00},
	"claude-fable-5":    {InputPerM: 10.00, OutputPerM: 50.00},
	"claude-opus-4-8":   {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-sonnet-4-6": {InputPerM: 3.00, OutputPerM: 15.00},
}

func TestEstimate_SelectableModelsArePriced(t *testing.T) {
	// Exactly 1M input and 1M output tokens, so the expected cost is the sum
	// of the two per-1M rates and an arithmetic slip cannot hide behind a
	// scaling factor.
	const oneMillion = 1_000_000

	for model, want := range claude5Pricing {
		t.Run(model, func(t *testing.T) {
			got, ok := Estimate(model, oneMillion, oneMillion)
			if !ok {
				t.Fatalf("Estimate(%q) reported no price. An unpriced model "+
					"costs 0, so any budget cap would treat every run on it as "+
					"free — add it to the prices table in cost.go.", model)
			}
			if wantUSD := want.InputPerM + want.OutputPerM; got != wantUSD {
				t.Errorf("Estimate(%q, 1M, 1M) = %.2f, want %.2f",
					model, got, wantUSD)
			}
		})
	}
}

// Opus 5.5 is a prefix extension of Opus 5, and lookup falls back to a
// longest-prefix match. Exact matching must win, or a future divergence in
// their rates would be silently papered over by the neighbouring key.
func TestLookup_ExactMatchBeatsPrefix(t *testing.T) {
	got, ok := lookup("claude-opus-5-5")
	if !ok {
		t.Fatal("claude-opus-5-5 is absent from the prices table")
	}
	want := prices["claude-opus-5-5"]
	if got != want {
		t.Errorf("lookup(claude-opus-5-5) = %+v, want the exact entry %+v "+
			"(a prefix key such as claude-opus-5 must not shadow it)", got, want)
	}
}

// EstimateSessionCost is what the budget path actually calls, and it collapses
// the (0, false) miss into a bare 0 — so a caller cannot distinguish "free"
// from "unknown". Assert the models we ship as selectable never reach it.
func TestEstimateSessionCost_ClaudeCodeModelsAreNotFree(t *testing.T) {
	for model := range claude5Pricing {
		if usd := EstimateSessionCost("claudecode", model, 1_000_000, 1_000_000); usd <= 0 {
			t.Errorf("EstimateSessionCost(claudecode, %q) = %v; a selectable "+
				"model that estimates as free defeats the spend ceiling",
				model, usd)
		}
	}
}

// Local models are deliberately free, and that must survive the checks above.
func TestEstimateSessionCost_OllamaIsFree(t *testing.T) {
	if usd := EstimateSessionCost("ollama", "llama3.2", 1_000_000, 1_000_000); usd != 0 {
		t.Errorf("EstimateSessionCost(ollama, llama3.2) = %v, want 0", usd)
	}
}
