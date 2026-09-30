package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Task 20357: the review gate's settings are changed from the dashboard or the
// CLI while a run may be going, and have to reach it.
func TestSetReviewGateReachesARunningProcess(t *testing.T) {
	dir := tempDir(t)
	run, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	run.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}}}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}

	gate := &pm.ReviewGate{Enabled: true, Provider: "anthropic", Model: "claude-opus-5-5"}
	if err := SetReviewGate(dir, gate); err != nil {
		t.Fatal(err)
	}
	if err := SetReviewGate(dir, &pm.ReviewGate{Mode: "yolo"}); err == nil {
		t.Error("an invalid gate was stored")
	}

	// The run syncs and sees it, and its own save does not undo it.
	run.SyncFromDisk()
	if !run.ReviewGate.Active() || run.ReviewGate.Model != "claude-opus-5-5" {
		t.Fatalf("the running process did not pick up the gate: %+v", run.ReviewGate)
	}
	run.Plan.Tasks[0].Status = pm.TaskDone
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ReviewGate.Active() || got.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("after the run's save: gate %+v, task %s", got.ReviewGate, got.Plan.Tasks[0].Status)
	}

	// Switched off while the run holds the old copy: the run's next save
	// adopts the change instead of writing its copy back.
	if err := SetReviewGate(dir, &pm.ReviewGate{Enabled: false, Provider: "anthropic"}); err != nil {
		t.Fatal(err)
	}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	got, _ = Load(dir)
	if got.ReviewGate.Active() {
		t.Error("a run's save switched the gate back on")
	}
}

func TestSetReviewGateNeedsAProject(t *testing.T) {
	if err := SetReviewGate(t.TempDir(), &pm.ReviewGate{Enabled: true}); err == nil {
		t.Error("a gate was stored where there is no project")
	}
}

// A run on an isolating executor is seeded through the legacy state.json
// decoder, so the gate has to survive it or a remote run would not review.
func TestLegacyStateCarriesTheReviewGate(t *testing.T) {
	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"goal":"g","pm_mode":true,"review_gate":{"enabled":true,"provider":"claudecode","model":"claude-opus-5-5","mode":"block"},
	  "plan":{"goal":"g","tasks":[{"id":1,"title":"t","status":"pending"}]}}`
	if err := os.WriteFile(StatePath(dir), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ReviewGate.Active() || s.ReviewGate.Mode != pm.ReviewModeBlock || s.ReviewGate.Model != "claude-opus-5-5" {
		t.Fatalf("seeded gate = %+v", s.ReviewGate)
	}
}
