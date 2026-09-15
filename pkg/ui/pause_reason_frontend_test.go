package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboard_PauseReasonIsVisible drives the real bundle and checks that a
// paused project says why (Task 20285).
//
// The regression it guards is not a crash: it is a screen that tells an
// operator work stopped and nothing about whether to wait, approve something,
// raise a budget, or do nothing because a subscription window reopens shortly.
// That was the state for ~26 distinct pause conditions, all rendering the same
// word.
type pauseScenario struct {
	HTML  string `json:"html"`
	Badge string `json:"badge"`
	Clock string `json:"clock"`
	Error string `json:"error"`
}

func runPauseScenarios(t *testing.T) map[string]pauseScenario {
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
	scenarios, err := filepath.Abs("testdata/pause_reason_scenarios.js")
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

	var results map[string]pauseScenario
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range results {
		if r.Error != "" {
			t.Fatalf("scenario %q threw in the browser shim:\n%s", name, r.Error)
		}
	}
	return results
}

func TestDashboard_PauseReasonIsVisible(t *testing.T) {
	results := runPauseScenarios(t)

	t.Run("overview badge names the cause and the clock", func(t *testing.T) {
		got := results["overview_badge"]
		// The whole point: "Paused" alone is what this replaces.
		if !strings.Contains(got.Badge, "5-hour cap reached") {
			t.Errorf("overview badge does not name the cause: %q", got.Badge)
		}
		if !strings.Contains(got.Badge, "resumes "+got.Clock) {
			t.Errorf("overview badge does not say when the run resumes (want %q): %q",
				"resumes "+got.Clock, got.Badge)
		}
	})

	t.Run("project card carries it into the fleet grid", func(t *testing.T) {
		got := results["project_card"]
		if !strings.Contains(got.HTML, "5-hour cap reached") {
			t.Errorf("project card does not name the cause — the grid is where a "+
				"fleet is scanned, so this is where it matters most:\n%s", got.HTML)
		}
		if !strings.Contains(got.HTML, "resumes "+got.Clock) {
			t.Errorf("project card does not say when the run resumes (want %q):\n%s",
				"resumes "+got.Clock, got.HTML)
		}
	})

	t.Run("a pause with no known reset does not imply one", func(t *testing.T) {
		got := results["no_reset"]
		if !strings.Contains(got.Badge, "approval declined for task #7") {
			t.Errorf("badge lost the detail: %q", got.Badge)
		}
		// An approval gate never resumes on its own. Claiming it does would
		// tell an operator to wait for something that will never happen.
		if strings.Contains(got.Badge, "resumes") {
			t.Errorf("badge promises a resume for a pause that needs a human: %q", got.Badge)
		}
	})

	t.Run("a bare code renders prose, not the identifier", func(t *testing.T) {
		got := results["bare_code"]
		if !strings.Contains(got.Badge, "token budget reached") {
			t.Errorf("badge did not fall back to the code's label: %q", got.Badge)
		}
		if strings.Contains(got.Badge, "token_budget") {
			t.Errorf("badge leaked the raw code to the operator: %q", got.Badge)
		}
	})

	t.Run("an elapsed reset reads as pending", func(t *testing.T) {
		got := results["reset_already_passed"]
		if !strings.Contains(got.Badge, "resuming") {
			t.Errorf("an elapsed reset should read as resuming: %q", got.Badge)
		}
		// "resumes 14:50" when it is already 15:10 reads as a broken page.
		if strings.Contains(got.Badge, "resumes ") {
			t.Errorf("badge still advertises a past resume time: %q", got.Badge)
		}
	})

	t.Run("a running project shows no pause text", func(t *testing.T) {
		got := results["running_project"]
		if strings.Contains(got.Badge, "cap reached") || strings.Contains(got.Badge, "resumes") {
			t.Errorf("a running project is showing pause text: %q", got.Badge)
		}
	})
}
