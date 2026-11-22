package ui

// A run on an executor that cannot read this filesystem plans in its own copy
// of the project and reports its outcome only when it ends, so the plan it
// *made* reached the hub only then — and the dashboard, which renders the
// hub's copy, showed an empty project for the whole run (Task 50).

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// reportingExec is a device that has reported the plan of the run it is
// working through.
type reportingExec struct {
	stubExec
	doc []byte
	err error
}

func (e reportingExec) InterimProjectResult(string) (executor.ProjectResult, error) {
	if e.err != nil {
		return executor.ProjectResult{}, e.err
	}
	return executor.ProjectResult{Data: e.doc, Interim: true, Redact: func(s string) string { return s }}, nil
}

// planReport is the document a device sends while its run is going, built the
// way the device builds it: a project dispatched with a goal and no tasks, a
// plan of the run's own making, the first task done and the second under way.
func planReport(t *testing.T) []byte {
	t.Helper()
	const goal = "Build an attested enclave and a client for it"
	seed, err := projectseed.Build(&state.ProjectState{
		Goal: goal, Status: "initialized", Plan: &pm.Plan{Goal: goal},
	})
	if err != nil {
		t.Fatalf("Build the seed the hub would send: %v", err)
	}
	dev := t.TempDir()
	if err := projectseed.Write(dev, seed); err != nil {
		t.Fatalf("place the seed on the device: %v", err)
	}
	st, err := state.Load(dev)
	if err != nil {
		t.Fatalf("load the seeded workspace: %v", err)
	}
	done := time.Now().Add(-time.Minute).UTC()
	st.Plan.Tasks = append(st.Plan.Tasks,
		&pm.Task{ID: 1, Title: "Pin down the enclave protocol", Priority: 1,
			Status: pm.TaskDone, Result: "documented", CompletedAt: &done},
		&pm.Task{ID: 2, Title: "Set up the Cargo workspace", Priority: 2,
			Status: pm.TaskInProgress, StartedAt: &done},
		&pm.Task{ID: 3, Title: "Implement the attested key exchange", Priority: 3},
	)
	st.Status = "running"
	if err := st.Save(); err != nil {
		t.Fatalf("the device's run saves its plan: %v", err)
	}
	data, err := projectseed.HarvestProgress(dev, seed, nil)
	if err != nil {
		t.Fatalf("HarvestProgress: %v", err)
	}
	return data
}

// tasksFrom reads the plan out of an /api/state body.
func tasksFrom(t *testing.T, body map[string]interface{}) []interface{} {
	t.Helper()
	plan, ok := body["plan"].(map[string]interface{})
	if !ok {
		return nil
	}
	tasks, _ := plan["tasks"].([]interface{})
	return tasks
}

func TestStateShowsTheTasksASeededRunPlanned(t *testing.T) {
	dir := setupProjectDir(t, "Build an attested enclave and a client for it", nil)

	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	if got := tasksFrom(t, apiGET(t, ts, "/api/state")); len(got) != 0 {
		t.Fatalf("before any run the hub's plan holds %d tasks, want none", len(got))
	}

	ex := reportingExec{stubExec: stubExec{id: "sgx-1"}, doc: planReport(t)}
	rememberSeededDispatch(ex, "h-plan-1", projectseed.Provenance{
		ExecutorID: ex.id, ExecutorKind: "remote", Isolation: "remote", RunID: "run_1"})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-plan-1") })
	srv.trackRun(dir, ex, "h-plan-1")
	srv.liveLogStartRun(dir)

	body := apiGET(t, ts, "/api/state")
	tasks := tasksFrom(t, body)
	if len(tasks) != 3 {
		t.Fatalf("with a seeded run in flight /api/state shows %d tasks, want the 3 the run planned — "+
			"the device is working through them while the hub's copy holds none", len(tasks))
	}
	first, _ := tasks[0].(map[string]interface{})
	if first["title"] != "Pin down the enclave protocol" || first["status"] != "done" {
		t.Errorf("task #1 = %+v, want the run's own account of it", first)
	}
	// Where it ran is the hub's to say, from its own dispatch record.
	if first["executor_id"] != "sgx-1" || first["isolation"] != "remote" {
		t.Errorf("task #1 is attributed to %v/%v, want the executor the hub dispatched to",
			first["executor_id"], first["isolation"])
	}
	if second, _ := tasks[1].(map[string]interface{}); second["status"] != "in_progress" {
		t.Errorf("task #2 = %+v, want it in progress", second)
	}

	// The record itself is untouched: the overlay is a view, and the merge
	// that writes a run's plan down happens once, when the run ends.
	back, err := state.LoadLite(dir)
	if err != nil {
		t.Fatalf("LoadLite: %v", err)
	}
	if back.Plan != nil && len(back.Plan.Tasks) != 0 {
		t.Fatalf("the hub's recorded plan holds %d tasks; the overlay must not be saved",
			len(back.Plan.Tasks))
	}

	// The run ends: the flag drops, and the hub's own copy speaks again.
	srv.liveLogSetRunning(dir, false)
	srv.untrackRun(dir)
	if got := tasksFrom(t, apiGET(t, ts, "/api/state")); len(got) != 0 {
		t.Fatalf("after the run settled /api/state shows %d tasks, want the hub's own (none)", len(got))
	}
}

// TestStateKeepsTheHubsOwnPlanBesideAReport: the hub's tasks are the hub's. A
// report may say what became of the ones it was sent and add the ones it made;
// it may not remove or retitle one.
func TestStateKeepsTheHubsOwnPlanBesideAReport(t *testing.T) {
	dir := setupProjectDir(t, "two plans", []*pm.Task{
		{ID: 1, Title: "The hub's own task", Priority: 1, Status: pm.TaskPending},
	})

	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	ex := reportingExec{stubExec: stubExec{id: "sgx-1"}, doc: planReport(t)}
	rememberSeededDispatch(ex, "h-plan-2", projectseed.Provenance{ExecutorID: ex.id})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-plan-2") })
	srv.trackRun(dir, ex, "h-plan-2")
	srv.liveLogStartRun(dir)

	tasks := tasksFrom(t, apiGET(t, ts, "/api/state"))
	if len(tasks) != 4 {
		t.Fatalf("/api/state shows %d tasks, want the hub's 1 and the run's 3", len(tasks))
	}
	first, _ := tasks[0].(map[string]interface{})
	if first["title"] != "The hub's own task" || first["status"] != "pending" {
		t.Errorf("the hub's own task came back as %+v", first)
	}
	// The run numbered a task 1 as well; the hub's numbering wins and the
	// device's is renumbered above it, so no outcome lands on the wrong task.
	for _, raw := range tasks[1:] {
		task, _ := raw.(map[string]interface{})
		if task["title"] == "The hub's own task" {
			t.Errorf("a reported task overwrote the hub's own: %+v", task)
		}
	}
}

// TestStateIsUnchangedWhenTheDeviceHasNotReported: a device too old to report,
// or one that has not reported yet, leaves the dashboard exactly as it was.
func TestStateIsUnchangedWhenTheDeviceHasNotReported(t *testing.T) {
	dir := setupProjectDir(t, "silent device", []*pm.Task{
		{ID: 1, Title: "The hub's own task", Priority: 1, Status: pm.TaskPending},
	})
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)

	// A driver that cannot report at all: not an InterimProjectResultFetcher.
	silent := stubExec{id: "old-agent"}
	rememberSeededDispatch(silent, "h-plan-3", projectseed.Provenance{ExecutorID: silent.id})
	t.Cleanup(func() { takeSeededDispatch(silent, "h-plan-3") })
	srv.trackRun(dir, silent, "h-plan-3")
	srv.liveLogStartRun(dir)
	if got := tasksFrom(t, apiGET(t, ts, "/api/state")); len(got) != 1 {
		t.Fatalf("a device that cannot report changed the plan to %d tasks", len(got))
	}
	srv.untrackRun(dir)

	// And one that can, but has nothing to give yet.
	quiet := reportingExec{stubExec: stubExec{id: "sgx-1"}, err: executor.ErrProjectResultUnavailable}
	rememberSeededDispatch(quiet, "h-plan-4", projectseed.Provenance{ExecutorID: quiet.id})
	t.Cleanup(func() { takeSeededDispatch(quiet, "h-plan-4") })
	srv.trackRun(dir, quiet, "h-plan-4")
	if got := tasksFrom(t, apiGET(t, ts, "/api/state")); len(got) != 1 {
		t.Fatalf("a device that has not reported yet changed the plan to %d tasks", len(got))
	}
}

// TestSeededRunInFlightIsTheTrackedHandle pins what decides that a seeded run
// is in flight — and what must not.
//
// It used to be the live-log flag, which only the Overview's Run button
// raises. A run started from the project grid, from POST
// /api/projects/{idx}/run, or adopted after a hub restart therefore showed
// neither its status nor its plan: measured on the live hub, a project whose
// device had just planned twelve tasks answered /api/state with "paused" and
// no plan while the run was under way.
func TestSeededRunInFlightIsTheTrackedHandle(t *testing.T) {
	dir := setupProjectDir(t, "live push", nil)
	srv := New(dir, 0, "")

	if srv.seededRunInFlight(dir) {
		t.Error("a project with no run at all reads as having a seeded run in flight")
	}

	// Tracked, but not seeded: a run on this filesystem writes the hub's own
	// database, and its changes arrive as a state-file change.
	local := stubExec{id: "local-host"}
	srv.trackRun(dir, local, "h-local")
	if srv.seededRunInFlight(dir) {
		t.Error("a run on this filesystem reads as a seeded run")
	}
	srv.untrackRun(dir)

	// Seeded and tracked, and the live-log flag never raised — the project
	// grid's Run button and the API both dispatch this way.
	ex := stubExec{id: "sgx-1"}
	rememberSeededDispatch(ex, "h-seeded", projectseed.Provenance{ExecutorID: ex.id})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-seeded") })
	srv.trackRun(dir, ex, "h-seeded")
	if srv.liveLogRunningFor(dir) {
		t.Fatal("this test is only meaningful while the live-log flag is down")
	}
	if !srv.seededRunInFlight(dir) {
		t.Error("a seeded run started without the live-log flag reads as no run at all — " +
			"its plan and its status would never be shown")
	}

	// Settled: the dispatch is forgotten, and so is the run.
	takeSeededDispatch(ex, "h-seeded")
	if srv.seededRunInFlight(dir) {
		t.Error("a settled dispatch still reads as a seeded run in flight")
	}
}

// TestStateShowsAGridStartedRunsPlan is the same gap at the seam the operator
// meets: the plan of a run nobody raised the live-log flag for.
func TestStateShowsAGridStartedRunsPlan(t *testing.T) {
	dir := setupProjectDir(t, "grid started", nil)
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)

	ex := reportingExec{stubExec: stubExec{id: "sgx-1"}, doc: planReport(t)}
	rememberSeededDispatch(ex, "h-grid", projectseed.Provenance{
		ExecutorID: ex.id, ExecutorKind: "remote", Isolation: "remote"})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-grid") })
	// Exactly what POST /api/projects/{idx}/run leaves behind: a tracked
	// handle, and no live-log room.
	srv.trackRun(dir, ex, "h-grid")

	body := apiGET(t, ts, "/api/state")
	if got := len(tasksFrom(t, body)); got != 3 {
		t.Fatalf("/api/state shows %d tasks for a grid-started seeded run, want the 3 the run planned", got)
	}
	if body["status"] != "running" {
		t.Errorf("status = %v, want running: the device is working through the project", body["status"])
	}
}
