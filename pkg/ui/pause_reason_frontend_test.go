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

	// Task 20362: a run that stopped itself because the project database
	// refused its writes. The badge and the Event History are where an
	// operator learns the run did not merely pause, and what was lost.
	t.Run("a run that could not save its progress says what was lost", func(t *testing.T) {
		got := results["unsaved_progress"]
		// esc() renders the apostrophe as &#39;.
		if !strings.Contains(got.Badge, "could not save task #3&#39;s completion (status done)") {
			t.Errorf("badge does not say what was lost: %q", got.Badge)
		}
		if !strings.Contains(got.Badge, "database or disk is full") {
			t.Errorf("badge does not say why: %q", got.Badge)
		}
		if !strings.Contains(got.HTML, "Run stopped: could not save task #3") {
			t.Errorf("the Event History does not show the stop:\n%s", got.HTML)
		}
		if !strings.Contains(got.HTML, "ev-session") {
			t.Errorf("the stop is not rendered as a session event:\n%s", got.HTML)
		}
	})

	t.Run("the hub's bare record of the same stop reads as prose", func(t *testing.T) {
		got := results["unsaved_progress_bare"]
		if !strings.Contains(got.Badge, "progress not saved") || strings.Contains(got.Badge, "state_not_persisted") {
			t.Errorf("badge = %q, want the code's label rather than the identifier", got.Badge)
		}
	})

	t.Run("a running project shows no pause text", func(t *testing.T) {
		got := results["running_project"]
		if strings.Contains(got.Badge, "cap reached") || strings.Contains(got.Badge, "resumes") {
			t.Errorf("a running project is showing pause text: %q", got.Badge)
		}
	})
}

// TestDashboard_DiskLowRendersAsAWaitingRun drives the bundle through the
// free-space floor's dashboard surfaces (Task 20381): the pause reason, the
// Stop button a waiting run needs, and the admin banner with its nudge.
func TestDashboard_DiskLowRendersAsAWaitingRun(t *testing.T) {
	results := runPauseScenarios(t)

	t.Run("the badge names the volume, the free space and the floor", func(t *testing.T) {
		got := results["disk_low_waiting"]
		if !strings.Contains(got.Badge, "Paused: volume / has 812.3 MB free, below the 1.00 GB floor") {
			t.Errorf("badge = %q", got.Badge)
		}
	})

	t.Run("a waiting run offers Stop, not Start", func(t *testing.T) {
		var ui struct{ Stop, Run, Bar string }
		if err := json.Unmarshal([]byte(results["disk_low_waiting"].HTML), &ui); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if ui.Stop == "none" || ui.Run != "none" {
			t.Errorf("Stop display %q, Run display %q: a run waiting for disk space is alive", ui.Stop, ui.Run)
		}
		if !strings.Contains(ui.Bar, "Paused: volume / has 812.3 MB free") {
			t.Errorf("the Tasks run bar says %q, want the pause, not Running", ui.Bar)
		}
	})

	t.Run("a bare disk_low code renders its label", func(t *testing.T) {
		got := results["disk_low_bare"]
		if !strings.Contains(got.Badge, "disk space low") || strings.Contains(got.Badge, "disk_low") {
			t.Errorf("badge = %q", got.Badge)
		}
	})

	t.Run("the admin banner shows, then clears on the nudge", func(t *testing.T) {
		var b struct {
			Shown struct{ Display, Text string }
			After string
		}
		if err := json.Unmarshal([]byte(results["hub_disk_banner"].HTML), &b); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if b.Shown.Display != "" {
			t.Errorf("banner display %q while /api/me carried hub_disk, want shown", b.Shown.Display)
		}
		for _, want := range []string{"volume /", "300.0 MB free", "1.00 GB floor"} {
			if !strings.Contains(b.Shown.Text, want) {
				t.Errorf("banner text %q lacks %q", b.Shown.Text, want)
			}
		}
		if b.After != "none" {
			t.Errorf("after the hub_disk nudge the banner display is %q, want hidden", b.After)
		}
	})
}
