package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// Task 20370: "done means committed" is changed from the dashboard or the CLI
// while a run may be going, and has to reach it without the run's saves
// switching it back.
func TestSetCommitPolicyReachesARunningProcess(t *testing.T) {
	dir := statedbtest.Dir(t)
	run, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	run.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}}}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}

	if err := SetCommitPolicy(dir, &pm.CommitPolicy{Enabled: true, Pushed: true}); err != nil {
		t.Fatal(err)
	}
	run.SyncFromDisk()
	if !run.CommitPolicy.RequiresPush() {
		t.Fatalf("the running process did not pick up the policy: %+v", run.CommitPolicy)
	}

	// Switched off while the run holds the old copy: its next save adopts
	// the change instead of writing its copy back.
	if err := SetCommitPolicy(dir, &pm.CommitPolicy{Pushed: true}); err != nil {
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
	if got.CommitPolicy.Active() || !got.CommitPolicy.Pushed || got.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("after the run's save: policy %+v, task %s", got.CommitPolicy, got.Plan.Tasks[0].Status)
	}
}

func TestSetCommitPolicyNeedsAProject(t *testing.T) {
	if err := SetCommitPolicy(t.TempDir(), &pm.CommitPolicy{Enabled: true}); err == nil {
		t.Error("a policy was stored where there is no project")
	}
	if err := SetCommitPolicy(tempDir(t), nil); err == nil {
		t.Error("a nil policy was accepted")
	}
}

// A run on an isolating executor is seeded through the legacy state.json
// decoder, so the policy has to survive it: the check runs inside the sandbox,
// beside the work.
func TestLegacyStateCarriesTheCommitPolicy(t *testing.T) {
	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := `{"goal":"g","pm_mode":true,"commit_policy":{"enabled":true,"pushed":true},
	  "plan":{"goal":"g","tasks":[{"id":1,"title":"t","status":"pending"}]}}`
	if err := os.WriteFile(StatePath(dir), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.CommitPolicy.RequiresPush() {
		t.Fatalf("seeded policy = %+v", s.CommitPolicy)
	}
}
