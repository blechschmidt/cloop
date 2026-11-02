package projectseed

// The seed and the way back carry every task field (Task 20361).

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/taskfill"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedDerived are the task fields a seed does not carry, because the device
// derives them itself. ChainInput is json:"-" and rebuilt from the chained
// predecessor's output when the orchestrator dispatches the task. Stop is
// json:"-" and stored nowhere: the hub sets it for the one save that records
// a stopped execution (Task 20405). AttachmentCount is counted by the
// database that loads the task: a device's counts only what its own run
// attached (Task 20428).
var seedDerived = []string{"ChainInput", "Stop", "AttachmentCount"}

// TestSeedCarriesEveryTaskField: a task arrives on the device as the hub holds
// it, every field — an assignment, a sprint, a branch, a retry budget — and
// not only the ones a test happened to name. A field lost here is one the run
// on the device works without: a branched plan that stops branching only when
// it runs remotely.
func TestSeedCarriesEveryTaskField(t *testing.T) {
	isolateHome(t)
	want := []*pm.Task{taskfill.Task(1), taskfill.Task(2)}
	hub := hubProject(t, &state.ProjectState{
		Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: want},
	})

	dev := t.TempDir()
	if err := Write(dev, seedFromHub(t, hub)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := state.Load(dev)
	if err != nil {
		t.Fatalf("state.Load on the device: %v", err)
	}
	for _, w := range want {
		g := got.Plan.TaskByID(w.ID)
		if g == nil {
			t.Fatalf("task %d did not reach the device", w.ID)
		}
		for _, name := range taskfill.Diff(w, g, seedDerived...) {
			t.Errorf("task %d: %s did not survive the seed (hub → seed → device database)", w.ID, name)
		}
	}
}

// TestAFullyPopulatedUntouchedPlanComesBackUnchanged: the device measures what
// a run changed against the seed it was sent. A field its database dropped
// would make every task that carried one look changed, and every result would
// carry the whole plan back.
func TestAFullyPopulatedUntouchedPlanComesBackUnchanged(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{
		Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{taskfill.Task(1), taskfill.Task(2)}},
	})
	seed := seedFromHub(t, hub)
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		if err := st.Save(); err != nil {
			t.Fatalf("device save: %v", err)
		}
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	res, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	for _, tc := range res.Tasks {
		if tc.Before != nil && tc.After != nil {
			t.Errorf("untouched task %d came back as changed in %v", tc.After.ID,
				taskfill.Diff(tc.Before, tc.After, "Description", "ArtifactPath"))
		} else {
			t.Errorf("untouched plan came back with %+v", tc)
		}
	}
}

// TestAnOlderDeviceDoesNotWipeTheHubsTDDVerdict: a device whose cloop predates
// migration 0054 cannot store a TDD verdict and reads every task back without
// one. The verdict is an outcome field, which the merge takes from the run —
// so without keepUnstoredVerdict the hub's verdicts would vanish on the first
// dispatch to such a device. A verdict the run actually changed still lands.
func TestAnOlderDeviceDoesNotWipeTheHubsTDDVerdict(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{
		Goal: "g", Status: "initialized",
		Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
			{ID: 1, Title: "verified", Status: pm.TaskPending, TDDStatus: "pass", TDDScore: 80},
			{ID: 2, Title: "also verified", Status: pm.TaskPending, TDDStatus: "pass", TDDScore: 90},
			{ID: 3, Title: "re-verified on the device", Status: pm.TaskPending, TDDStatus: "pass", TDDScore: 70},
		}},
	})
	seed := seedFromHub(t, hub)
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		// What an older device reads back: no verdicts at all.
		for _, task := range st.Plan.Tasks {
			task.TDDStatus, task.TDDScore = "", 0
		}
		// It runs task 2 to completion.
		st.Plan.TaskByID(2).Status = pm.TaskDone
		st.Plan.TaskByID(2).Result = "done on the device"
		// And task 3's verdict genuinely changes there.
		st.Plan.TaskByID(3).TDDStatus, st.Plan.TaskByID(3).TDDScore = "fail", 10
		if err := st.Save(); err != nil {
			t.Fatalf("device save: %v", err)
		}
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	res, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	rep, err := Apply(hub, res, Provenance{ExecutorID: "edge", ExecutorKind: "remote", Isolation: "remote"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := state.Load(hub)
	if err != nil {
		t.Fatalf("reload hub: %v", err)
	}
	if t1 := got.Plan.TaskByID(1); t1.TDDStatus != "pass" || t1.TDDScore != 80 || t1.Status != pm.TaskPending {
		t.Errorf("task 1 = %q/%d (%s); an untouched task lost its verdict to a device that cannot store one",
			t1.TDDStatus, t1.TDDScore, t1.Status)
	}
	if t2 := got.Plan.TaskByID(2); t2.Status != pm.TaskDone || t2.TDDStatus != "pass" || t2.TDDScore != 90 {
		t.Errorf("task 2 = %s %q/%d; want the run's outcome with the hub's verdict kept", t2.Status, t2.TDDStatus, t2.TDDScore)
	}
	if t3 := got.Plan.TaskByID(3); t3.TDDStatus != "fail" || t3.TDDScore != 10 {
		t.Errorf("task 3 = %q/%d; a verdict the run did change must still be taken", t3.TDDStatus, t3.TDDScore)
	}
	for _, id := range rep.Updated {
		if id == 1 {
			t.Errorf("task 1 reported as updated: %s", rep.Summary())
		}
	}
}

// TestADeviceCannotReleaseOrSetAQuarantine: a quarantine travels to the device
// so its orchestrator holds the task (Task 20391), but the way back carries
// none — a device is where a suspected node killer runs, and a hostile one
// must not be able to release its own task, or mark an innocent one, by what
// it reports.
func TestADeviceCannotReleaseOrSetAQuarantine(t *testing.T) {
	isolateHome(t)
	mark := &pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller, Reason: "two nodes", Nodes: []pm.NodeLoss{
		{ExecutorID: "sgx", SessionID: "s1"}, {ExecutorID: "edge-2", SessionID: "s2"},
	}}
	hub := hubProject(t, &state.ProjectState{
		Goal: "g", Status: "initialized",
		Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
			{ID: 1, Title: "suspect", Status: pm.TaskFailed, Quarantine: mark},
			{ID: 2, Title: "innocent", Status: pm.TaskPending},
		}},
	})
	seed := seedFromHub(t, hub)
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		if !st.Plan.TaskByID(1).Quarantined() {
			t.Fatal("the mark did not reach the device, whose orchestrator must hold the task")
		}
		// The device claims to have released task 1, and marks task 2.
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = db.ClearTaskQuarantine(1)
		_ = db.PutTaskQuarantine(2, *mark)
		db.Close()
		st.Plan.TaskByID(1).Status = pm.TaskPending
		st.Plan.TaskByID(2).Status = pm.TaskDone
		if err := st.Save(); err != nil {
			t.Fatalf("device save: %v", err)
		}
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	res, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if _, err := Apply(hub, res, Provenance{ExecutorID: "edge", ExecutorKind: "remote", Isolation: "remote"}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := state.Load(hub)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Plan.TaskByID(1).Quarantined() {
		t.Error("a device's result released the hub's quarantine")
	}
	if got.Plan.TaskByID(2).Quarantined() {
		t.Error("a device's result quarantined a task on the hub")
	}
}

// TestASeedCarriesTheRequirementsItsTasksImplement: a device's run gives each
// task's agent the requirements the task implements as its contract (Task
// 20460), and a device has no requirements table but the one its seed fills.
// What a done task implements, and what no task does, stays on the hub, and
// who wrote a requirement never leaves it.
func TestASeedCarriesTheRequirementsItsTasksImplement(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "pending", Status: pm.TaskPending, Requirements: []int{2, 3}},
		{ID: 2, Title: "done", Status: pm.TaskDone, Requirements: []int{4}},
	}}})
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"nobody's", "two", "three", "a done task's"} {
		r := requirements.Requirement{Title: title, Tests: []requirements.Test{{Command: "go test ./" + title[:3]}}}
		if _, err := db.AddRequirement(r, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	all, err := db.Requirements()
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.LoadLite(hub)
	if err != nil {
		t.Fatal(err)
	}
	linked := LinkedRequirements(st.Plan, all)
	if len(linked) != 2 || linked[0].ID != 2 || linked[1].ID != 3 {
		t.Fatalf("LinkedRequirements = %+v, want R-2 and R-3", linked)
	}
	seed, err := BuildWith(st, linked)
	if err != nil {
		t.Fatal(err)
	}

	onDevice(t, seed, func(dir string, st *state.ProjectState) {
		if got := st.Plan.TaskByID(1).Requirements; len(got) != 2 {
			t.Errorf("task 1 implements %v on the device", got)
		}
		ddb, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		defer ddb.Close()
		got, err := ddb.Requirements()
		if err != nil || len(got) != 2 || got[0].ID != 2 || got[0].Title != "two" || got[1].Tests[0].Command != "go test ./thr" {
			t.Fatalf("the device's requirements: %+v, %v", got, err)
		}
		if got[0].CreatedBy != "" {
			t.Errorf("a requirement's author went to the device: %q", got[0].CreatedBy)
		}
		contract := requirements.ContractSection(requirements.Resolve(st.Plan.TaskByID(1).Requirements, got))
		if !strings.Contains(contract, "### R-2: two") || !strings.Contains(contract, "`go test ./thr`") {
			t.Errorf("the device's contract for task 1:\n%s", contract)
		}
	})

	// A seed without requirements still runs: the links travel, their text
	// does not.
	plain, err := Build(st)
	if err != nil {
		t.Fatal(err)
	}
	onDevice(t, plain, func(dir string, st *state.ProjectState) {
		if got := st.Plan.TaskByID(1).Requirements; len(got) != 2 {
			t.Errorf("task 1 implements %v on the device", got)
		}
	})
}

// TestLinkedRequirementsAreBounded: a plan that links more than a seed may
// carry sends the first ones whole and the rest by id only.
func TestLinkedRequirementsAreBounded(t *testing.T) {
	var all []requirements.Requirement
	var ids []int
	for id := 1; id <= 40; id++ {
		r := requirements.Requirement{ID: id, Title: "big", Description: strings.Repeat("x", requirements.MaxDescriptionRunes)}
		for i := 0; i < requirements.MaxTests; i++ {
			r.Tests = append(r.Tests, requirements.Test{Command: strings.Repeat("c", 3000)})
		}
		all = append(all, r)
		ids = append(ids, id)
	}
	got := LinkedRequirements(&pm.Plan{Tasks: []*pm.Task{{ID: 1, Status: pm.TaskPending, Requirements: ids}}}, all)
	if len(got) == 0 || len(got) >= len(all) {
		t.Fatalf("%d of %d requirements of ~56 KiB each went into the seed", len(got), len(all))
	}
	size := 0
	for _, r := range got {
		size += r.ForSeed().EncodedSize()
	}
	if size > maxSeedRequirementBytes {
		t.Errorf("the seed carries %d bytes of requirements, over %d", size, maxSeedRequirementBytes)
	}
}

// TestASeedCarriesWhereTheRequirementsStand: a device's auto-evolve plans from
// the requirement status summary (Task 20463), and the device's database holds
// neither every approved requirement nor any check. The seed carries the hub's
// facts — never a draft's or a deprecated requirement's — and the run there
// lays its own newer checks over them and assesses them against its own plan.
func TestASeedCarriesWhereTheRequirementsStand(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "pending", Status: pm.TaskPending, Requirements: []int{2}},
	}}})
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []requirements.Requirement{
		{Title: "fails", Priority: requirements.PriorityMust, Tests: []requirements.Test{{Command: "false"}}},
		{Title: "linked", Priority: requirements.PriorityShould, Tests: []requirements.Test{{Command: "true"}}},
		{Title: "a draft", Priority: requirements.PriorityMust, Status: requirements.StatusDraft},
		{Title: "retired", Priority: requirements.PriorityMust, Status: requirements.StatusDeprecated},
	} {
		if _, err := db.AddRequirement(r, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.RecordRequirementVerdict(1, requirements.VerdictUnfulfilled, "exit 1", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	facts, _, err := db.RequirementFacts()
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.LoadLite(hub)
	if err != nil {
		t.Fatal(err)
	}
	sum := requirements.Summarize(facts, pm.TaskViews(st.Plan))
	if len(sum.Requirements) != 2 || sum.Requirements[0].Action != requirements.ActionFix ||
		sum.Requirements[1].Action != requirements.ActionCovered {
		t.Fatalf("the hub's summary %+v", sum.Requirements)
	}
	seed, err := BuildFull(st, nil, sum)
	if err != nil {
		t.Fatal(err)
	}
	onDevice(t, seed, func(dir string, st *state.ProjectState) {
		ddb, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		defer ddb.Close()
		facts, _, err := ddb.AsProject().RequirementFacts()
		if err != nil {
			t.Fatal(err)
		}
		// The device's plan moved on: task 1 finished there.
		done := st.Plan.TaskByID(1)
		done.Status = pm.TaskDone
		at := sum.Requirements[0].CheckedAt.Add(time.Hour)
		done.CompletedAt = &at
		got := requirements.Summarize(facts, pm.TaskViews(st.Plan))
		if len(got.Requirements) != 2 || got.Requirements[0].ID != 1 || got.Requirements[0].Action != requirements.ActionFix ||
			got.Requirements[1].ID != 2 || got.Requirements[1].Action != requirements.ActionCheck {
			t.Errorf("the device's summary %+v", got.Requirements)
		}
		if strings.Contains(got.Section(), "a draft") || strings.Contains(got.Section(), "retired") {
			t.Errorf("a draft or a deprecated requirement reached the device:\n%s", got.Section())
		}
	})
}

// TestACreatedTaskKeepsTheHubsApprovedLinks: a device's auto-evolve links the
// tasks it adds to what they close (Task 20463). The hub keeps those links —
// else the requirement stays a gap on the hub and every dispatch's evolve adds
// the task again — but only to requirements it holds as approved.
func TestACreatedTaskKeepsTheHubsApprovedLinks(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "a", Status: pm.TaskDone},
	}}})
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []requirements.Requirement{
		{Title: "approved"},
		{Title: "a draft", Status: requirements.StatusDraft},
		{Title: "retired", Status: requirements.StatusDeprecated},
	} {
		if _, err := db.AddRequirement(r, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	r := &Result{Format: ResultFormat, Tasks: []TaskChange{
		{After: &pm.Task{ID: 2, Title: "Restore R-1", Status: pm.TaskDone, Requirements: []int{1, 2, 3, 99, 1, -4}}},
		{After: &pm.Task{ID: 3, Title: "Dark mode", Status: pm.TaskPending}},
	}}
	rep, err := Apply(hub, r, Provenance{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != 2 {
		t.Fatalf("added %v", rep.Added)
	}
	st, err := state.LoadLite(hub)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Plan.TaskByID(rep.Added[0]).Requirements; fmt.Sprint(got) != "[1]" {
		t.Errorf("the created task implements %v on the hub, want [1]", got)
	}
	if got := st.Plan.TaskByID(rep.Added[1]).Requirements; got != nil {
		t.Errorf("an unlinked created task implements %v", got)
	}
}
