package ui

// The limit views show the weekly windows a Claude plan meters for one model
// alone, Fable's among them (Task 20490).
//
// The usage API reports Fable's window only as a model-scoped row of its
// limits[] list; pkg/ratelimit now reads it into seven_day_models. These drive
// the real bundle through both views that draw the snapshot, because the
// assertion is about what is on screen: a grep for "seven_day_models" in the
// source cannot show the row rendered, or that the model's name, which is the
// server's, renders as text.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type usageViewResult struct {
	FablePct       *int   `json:"fable_pct"`
	FableCount     int    `json:"fable_count"`
	WeeklyAllPct   *int   `json:"weekly_all_pct"`
	ShowsUndefined bool   `json:"shows_undefined"`
	ShowsNaN       bool   `json:"shows_nan"`
	RawTag         bool   `json:"raw_tag"`
	EscapedTag     bool   `json:"escaped_tag"`
	Error          string `json:"error"`
}

func runClaudeUsageScenarios(t *testing.T) map[string]usageViewResult {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/claude_usage_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]usageViewResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if fatal, ok := results["fatal"]; ok {
		t.Fatalf("the scenarios threw: %s", fatal.Error)
	}
	return results
}

func TestDashboard_LimitViewsShowModelWindows(t *testing.T) {
	results := runClaudeUsageScenarios(t)

	need := func(name string) usageViewResult {
		got, ok := results[name]
		if !ok {
			t.Fatalf("the %s scenario did not report", name)
		}
		return got
	}
	pct := func(p *int) string {
		if p == nil {
			return "none"
		}
		return fmt.Sprintf("%d%%", *p)
	}

	for _, view := range []string{"overview", "budget"} {
		got := need(view)
		if got.FablePct == nil || *got.FablePct != 7 || got.FableCount != 1 {
			t.Errorf("%s: Fable's weekly window shows %s in %d row(s), want 7%% in one",
				view, pct(got.FablePct), got.FableCount)
		}
		if got.WeeklyAllPct == nil || *got.WeeklyAllPct != 61 {
			t.Errorf("%s: the all-models weekly window shows %s, want 61%%", view, pct(got.WeeklyAllPct))
		}
		if got.ShowsUndefined || got.ShowsNaN {
			t.Errorf("%s: rendered undefined=%v NaN=%v", view, got.ShowsUndefined, got.ShowsNaN)
		}

		// The model's name is the usage API's, so it is text, never markup.
		got = need(view + "_hostile")
		if got.RawTag || !got.EscapedTag {
			t.Errorf("%s: a model named like markup rendered raw=%v escaped=%v; the name must be escaped",
				view, got.RawTag, got.EscapedTag)
		}

		// A hub or plan without model windows draws no row for one.
		got = need(view + "_none")
		if got.FableCount != 0 || got.ShowsUndefined || got.ShowsNaN {
			t.Errorf("%s: with no model windows: Fable rows %d, undefined=%v, NaN=%v",
				view, got.FableCount, got.ShowsUndefined, got.ShowsNaN)
		}
		if got.WeeklyAllPct == nil || *got.WeeklyAllPct != 61 {
			t.Errorf("%s: with no model windows the weekly window shows %s, want 61%%", view, pct(got.WeeklyAllPct))
		}
	}
}
