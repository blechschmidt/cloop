package projectseed

// The seed and the way back carry every task field (Task 20361).

import (
	"testing"

	"github.com/blechschmidt/cloop/internal/taskfill"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedDerived are the task fields a seed does not carry, because the device
// derives them itself. ChainInput is json:"-" and rebuilt from the chained
// predecessor's output when the orchestrator dispatches the task. Stop is
// json:"-" and stored nowhere: the hub sets it for the one save that records
// a stopped execution (Task 20405).
var seedDerived = []string{"ChainInput", "Stop"}

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
