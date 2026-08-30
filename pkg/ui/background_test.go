package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type backgroundResult struct {
	HTML  string `json:"html"`
	IDs   []int  `json:"ids"`
	Error string `json:"error"`
}

// TestDashboard_BackgroundWorkIsVisible drives the real bundle and checks that
// work an agent left running is legible in the task list (Task 20205).
//
// This runs the shipped JavaScript rather than grepping it, because the thing
// that can break is not whether the badge markup exists in a source file but
// whether it survives the render path: the filter, the sort, the escaping, and
// the concatenation order of the bundle. A grep gate would pass on a badge
// that never reaches the page.
func TestDashboard_BackgroundWorkIsVisible(t *testing.T) {
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
	scenarios, err := filepath.Abs("testdata/background_scenarios.js")
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

	var results map[string]backgroundResult
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
	if len(got.IDs) != 4 {
		t.Fatalf("expected all 4 fixture tasks rendered, got %v", got.IDs)
	}

	// Each state must produce its own marker: an operator distinguishing
	// "still waiting" from "gave up" is the whole point of separating them.
	for _, want := range []struct{ needle, why string }{
		{"task-background bg-waiting", "a task still blocked on background work must be marked as waiting"},
		{"task-background bg-abandoned", "a task whose work never finished must be marked as such"},
		{"task-background bg-drained", "a task that waited for work must show that it waited"},
		{"has-background-waiting", "a task blocked on background work must read as running on the row itself"},
		{"python3", "the surviving processes must be named, or the badge cannot be acted on"},
		{"train.py", "the abandoned task's processes must be named"},
		{"task not complete", "the abandoned badge must say the task is not complete"},
		{"30m", "the abandoned badge must say how long cloop waited (1800s → 30m)"},
	} {
		if !strings.Contains(got.HTML, want.needle) {
			t.Errorf("task list is missing %q — %s", want.needle, want.why)
		}
	}

	// The control task carries no background data and must render no badge, so
	// exactly three of the four rows are marked.
	if n := strings.Count(got.HTML, "task-background "); n != 3 {
		t.Errorf("expected exactly 3 background badges for 4 tasks (one control), got %d", n)
	}
}
