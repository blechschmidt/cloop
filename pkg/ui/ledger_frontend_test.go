package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type ledgerResult struct {
	HTML   string `json:"html"`
	Banner string `json:"banner"`
	IDs    []int  `json:"ids"`
	Error  string `json:"error"`
}

// TestDashboard_AbortedOutcomesAreVisible drives the real bundle and checks
// that a task the plan calls "done" whose entire summary is a provider refusal
// is legible on the page (Task 20224).
//
// This runs the shipped JavaScript rather than grepping it, because the thing
// that can break is not whether the badge markup exists in a source file but
// whether it survives the render path: the filter, the sort, the escaping, and
// the concatenation order of the bundle — isOpenAbortFinding is defined in
// 02-tasks.js and called from 01-overview.js, so a change in fragment order is
// a real failure mode. A grep gate would pass on a badge that never renders.
//
// It also pins the distinction this panel invites getting wrong: an *open*
// finding is one still filed as done. A reopened task is pending and already
// queued, so counting it would leave the banner permanently accusing the plan
// of work it has re-queued, and an operator learns to ignore a banner that
// never reaches zero.
func TestDashboard_AbortedOutcomesAreVisible(t *testing.T) {
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
	scenarios, err := filepath.Abs("testdata/ledger_scenarios.js")
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

	var results map[string]ledgerResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}

	got, ok := results["task_list"]
	if !ok {
		t.Fatal("scenario task_list produced no result")
	}
	if got.Error != "" {
		t.Fatalf("scenario threw in the browser shim:\n%s", got.Error)
	}
	if len(got.IDs) != 5 {
		t.Fatalf("expected all 5 fixture tasks rendered, got %v", got.IDs)
	}

	for _, want := range []struct{ needle, why string }{
		{"task-abort ab-open", "a task still filed as done on a refusal must carry the open marker"},
		{"task-abort ab-cleared", "a triaged or reopened entry must still be visible, muted"},
		{"has-aborted-outcome", "an open finding must mark the row itself — the status says done and is wrong"},
		{"Never ran", "the row must say plainly that the task did not run"},
		{"provider usage limit", "the class must be rendered in words, not as a raw enum"},
		{"provider quota exhausted", "a second class must render as its own words"},
		{"reopenAbortedTask(194)", "an open finding must offer the reopen verdict"},
		{"clearAbortedTask(194)", "an open finding must offer the keep verdict"},
		{"re-landed by cmd/task_tdd.go", "a cleared entry must show why it was allowed to stand"},
	} {
		if !strings.Contains(got.HTML, want.needle) {
			t.Errorf("task list is missing %q: %s", want.needle, want.why)
		}
	}

	// A reopened task is pending and already queued. It keeps its record as
	// history, but offering the verdicts again would be meaningless.
	for _, unwanted := range []struct{ needle, why string }{
		{"reopenAbortedTask(195)", "a task already reopened must not offer Reopen again"},
		{"clearAbortedTask(195)", "a task already reopened must not offer Keep"},
		{"reopenAbortedTask(193)", "a cleared task must not offer Reopen in the list"},
		{"reopenAbortedTask(20221)", "a task with no finding must not offer the verdicts at all"},
	} {
		if strings.Contains(got.HTML, unwanted.needle) {
			t.Errorf("task list wrongly contains %q: %s", unwanted.needle, unwanted.why)
		}
	}

	// The banner counts open findings only: 194 and 20104, not the reopened
	// 195, the cleared 193, or the untouched 20221.
	if got.Banner == "" {
		t.Fatal("overview banner did not render although two findings are open")
	}
	if !strings.Contains(got.Banner, "2 tasks recorded as done never actually ran") {
		t.Errorf("banner does not count exactly the two open findings:\n%s", got.Banner)
	}
	for _, want := range []string{"#194", "#20104", "provider usage limit", "provider quota exhausted"} {
		if !strings.Contains(got.Banner, want) {
			t.Errorf("banner is missing %q — it must name the cause and the tasks:\n%s", want, got.Banner)
		}
	}
	for _, unwanted := range []string{"#195", "#193", "#20221"} {
		if strings.Contains(got.Banner, unwanted) {
			t.Errorf("banner wrongly names %s; only findings still filed as done are open:\n%s",
				unwanted, got.Banner)
		}
	}

	// And it has to reach zero, or it is noise an operator will learn to skip.
	resolved, ok := results["all_resolved"]
	if !ok {
		t.Fatal("scenario all_resolved produced no result")
	}
	if resolved.Error != "" {
		t.Fatalf("all_resolved threw in the browser shim:\n%s", resolved.Error)
	}
	if resolved.Banner != "" {
		t.Errorf("banner still showing with every finding resolved:\n%s", resolved.Banner)
	}
}
