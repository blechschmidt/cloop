package projectseed

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func hubDB(t *testing.T, dir string) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.AsProject()
	return db
}

// In linked+must mode a seed carries the approved must requirements with
// tests as well as the linked ones (Task 20461): the device's gate checks
// them, and has no other copy.
func TestSeedRequirementsCarryTheMustRequirements(t *testing.T) {
	plan := &pm.Plan{Tasks: []*pm.Task{{ID: 1, Status: pm.TaskPending, Requirements: []int{1}}}}
	all := []requirements.Requirement{
		{ID: 1, Title: "linked", Tests: []requirements.Test{{Command: "a"}}},
		{ID: 2, Title: "must", Priority: requirements.PriorityMust, Status: requirements.StatusApproved, Tests: []requirements.Test{{Command: "b"}}},
		{ID: 3, Title: "untested must", Priority: requirements.PriorityMust, Status: requirements.StatusApproved},
		{ID: 4, Title: "draft must", Priority: requirements.PriorityMust, Status: requirements.StatusDraft, Tests: []requirements.Test{{Command: "c"}}},
		{ID: 5, Title: "should", Priority: requirements.PriorityShould, Tests: []requirements.Test{{Command: "d"}}},
	}
	ids := func(rs []requirements.Requirement) (out []int) {
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	if got := ids(SeedRequirements(plan, all, false)); len(got) != 1 || got[0] != 1 {
		t.Errorf("linked only = %v", got)
	}
	if got := ids(SeedRequirements(plan, all, true)); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("linked+must = %v, want [1 2]", got)
	}
}

// A device's requirements gate verdict comes back with its task, and the hub
// records it as its own requirement checks — tied to the task and the commit,
// read through requirements.Sanitize against the hub's definitions — once.
func TestApplyRecordsTheDevicesGateChecks(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{
		Goal: "g", Status: "initialized", RequirementsGate: &pm.RequirementsGate{Mode: pm.RequirementsGateLinked},
		Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 1, Title: "build it", Status: pm.TaskPending, Requirements: []int{1, 2}}}},
	})
	db := hubDB(t, hub)
	r1, err := db.AddRequirement(requirements.Requirement{Title: "builds", Tests: []requirements.Test{{Name: "build", Command: "make"}}}, "t")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := db.AddRequirement(requirements.Requirement{Title: "changed meanwhile", Tests: []requirements.Test{{Command: "old"}}}, "t")
	if err != nil {
		t.Fatal(err)
	}
	seed := seedFromHub(t, hub)
	commit := strings.Repeat("e", 40)
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		task := st.Plan.TaskByID(1)
		task.Status = pm.TaskDone
		task.RequirementsCheck = &pm.TaskRequirementsCheck{
			Mode: "linked", Outcome: pm.RequirementsMet, Decision: "met", RunID: "device-run-1", Commit: commit,
			CheckedAt: time.Now().UTC(),
			Requirements: []pm.RequirementVerdict{
				{Linked: true, Result: requirements.Result{RequirementID: r1.ID, Fingerprint: r1.Fingerprint(),
					Method: requirements.MethodTests, Verdict: requirements.VerdictFulfilled,
					// The device claims another command; the hub records its own.
					Tests: []requirements.TestResult{{Name: "forged", Command: "true", Outcome: requirements.OutcomePass}}}},
				{Linked: true, Result: requirements.Result{RequirementID: r2.ID, Fingerprint: r2.Fingerprint(),
					Method: requirements.MethodTests, Verdict: requirements.VerdictFulfilled,
					Tests: []requirements.TestResult{{Command: "old", Outcome: requirements.OutcomePass}}}},
			},
		}
		if err := st.Save(); err != nil {
			t.Fatalf("device save: %v", err)
		}
	})
	// The hub changes R-2 while the run is out.
	r2.Tests = []requirements.Test{{Command: "new"}}
	if _, err := db.UpdateRequirement(r2, "t"); err != nil {
		t.Fatal(err)
	}
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	res, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	rep, err := Apply(hub, res, Provenance{ExecutorID: "edge-1", ExecutorKind: "remote", Isolation: "remote"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rep.RequirementChecks != 1 || !strings.Contains(rep.Summary(), "1 requirement check") {
		t.Errorf("report: %d checks, %q", rep.RequirementChecks, rep.Summary())
	}

	got, err := state.Load(hub)
	if err != nil {
		t.Fatal(err)
	}
	if rc := got.Plan.TaskByID(1).RequirementsCheck; !rc.Met() || rc.RunID != "device-run-1" {
		t.Errorf("the task's record = %+v", rc)
	}
	checks, err := db.RequirementChecks(r1.ID, 10)
	if err != nil || len(checks) != 1 {
		t.Fatalf("R-1 checks = %+v, %v", checks, err)
	}
	c := checks[0]
	if c.TaskID != 1 || c.Commit != commit || c.ExecutorID != "edge-1" || c.RunID != "device-run-1" ||
		c.Tests[0].Command != "make" || c.Tests[0].Name != "build" {
		t.Errorf("recorded check = %+v", c)
	}
	if checks, _ := db.RequirementChecks(r2.ID, 10); len(checks) != 0 {
		t.Errorf("a check of a definition the hub has since changed was recorded: %+v", checks)
	}
	run, err := db.RequirementRunByID("device-run-1")
	if err != nil || run.TaskID != 1 || run.Source != "gate" || run.ExecutorID != "edge-1" {
		t.Errorf("run = %+v, %v", run, err)
	}
}
