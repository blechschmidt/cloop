package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// Task 20461: the requirements gate is changed from the dashboard or the CLI
// while a run may be going, and has to reach it without the run's saves
// switching it back.
func TestSetRequirementsGateReachesARunningProcess(t *testing.T) {
	dir := statedbtest.Dir(t)
	run, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	run.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}}}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}

	if err := SetRequirementsGate(dir, &pm.RequirementsGate{Mode: pm.RequirementsGateLinkedMust}); err != nil {
		t.Fatal(err)
	}
	run.SyncFromDisk()
	if !run.RequirementsGate.IncludesMust() {
		t.Fatalf("the running process did not pick up the gate: %+v", run.RequirementsGate)
	}

	// Switched off while the run holds the old copy: its next save adopts
	// the change instead of writing its copy back.
	if err := SetRequirementsGate(dir, &pm.RequirementsGate{Mode: pm.RequirementsGateOff, Assess: true}); err != nil {
		t.Fatal(err)
	}
	run.Plan.Tasks[0].Status = pm.TaskDone
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.RequirementsGate.Active() || !got.RequirementsGate.Assess || got.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("after the run's save: gate %+v, task %s", got.RequirementsGate, got.Plan.Tasks[0].Status)
	}
}

func TestSetRequirementsGateRefusesWhatItCannotStore(t *testing.T) {
	if err := SetRequirementsGate(t.TempDir(), &pm.RequirementsGate{Mode: pm.RequirementsGateLinked}); err == nil {
		t.Error("a gate was stored where there is no project")
	}
	if err := SetRequirementsGate(tempDir(t), nil); err == nil {
		t.Error("a nil gate was accepted")
	}
	if err := SetRequirementsGate(statedbtest.Dir(t), &pm.RequirementsGate{Mode: "always"}); err == nil {
		t.Error("an unknown mode was accepted")
	}
}

// A run on an isolating executor is seeded through the legacy state.json
// decoder, so the gate has to survive it: the check runs inside the sandbox,
// beside the work — and so does a task's last gate verdict, which its next
// attempt is told.
func TestLegacyStateCarriesTheRequirementsGate(t *testing.T) {
	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"goal":"g","pm_mode":true,"requirements_gate":{"mode":"linked+must","assess":true},
	  "plan":{"goal":"g","tasks":[{"id":1,"title":"t","status":"pending",
	    "requirements_check":{"mode":"linked","outcome":"unmet","decision":"requeued","consecutive":1,
	      "checked_at":"2026-11-01T00:00:00Z","requirements":[{"requirement_id":3,"verdict":"unfulfilled","method":"tests",
	      "fingerprint":"f","started_at":"2026-11-01T00:00:00Z","duration_ms":0,"blocking":true}]}}]}}`
	if err := os.WriteFile(StatePath(dir), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.RequirementsGate.IncludesMust() || !s.RequirementsGate.Assess {
		t.Fatalf("seeded gate = %+v", s.RequirementsGate)
	}
	rc := s.Plan.Tasks[0].RequirementsCheck
	if !rc.Unmet() || rc.Consecutive != 1 || len(rc.Blocking()) != 1 {
		t.Fatalf("seeded verdict = %+v", rc)
	}
}
