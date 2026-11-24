package ui

// While a run works through a project on another machine, a task's own views
// must say what the task list says (Task 20518).
//
// Measured on the live hub on 2026-11-23: sgx-rust-attestation's run took
// tasks #20 and #21 to the sgx device at 22:43 UTC. #21 was done there at
// 23:37:17, and the run went on with a task it had picked up. The task list
// showed the run's account. Each of the twelve times between 22:50 and 23:39
// that the operator opened #21's details, six while the device worked on it
// and six after it was done, they read the hub's own copy: "pending", nothing
// recorded. And at 23:45 a task the run had created, listed as #23, opened as
// HTTP 404.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// deviceProgress is the report a device sends while it works through the
// project the hub sent it: the seed is built from the hub's own copy, as a
// dispatch builds it, and work changes the device's copy as the run does.
func deviceProgress(t *testing.T, hub *state.ProjectState, work func(dev *state.ProjectState)) []byte {
	t.Helper()
	seed, err := projectseed.Build(hub)
	if err != nil {
		t.Fatalf("build the seed the hub sends: %v", err)
	}
	dev := t.TempDir()
	if err := projectseed.Write(dev, seed); err != nil {
		t.Fatalf("place the seed on the device: %v", err)
	}
	// Load imports the seed into an empty migrated database, without paying
	// for the migrations under -race.
	statedbtest.SeedDir(t, dev)
	st, err := state.Load(dev)
	if err != nil {
		t.Fatalf("load the seeded workspace: %v", err)
	}
	work(st)
	if err := st.Save(); err != nil {
		t.Fatalf("the device's run saves its plan: %v", err)
	}
	data, err := projectseed.HarvestProgress(dev, seed, nil)
	if err != nil {
		t.Fatalf("HarvestProgress: %v", err)
	}
	return data
}

// getAs fetches path and decodes it into out, returning the HTTP status.
func getAs(t *testing.T, ts *httptest.Server, path string, out any) int {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode
}

func TestTaskViewsShowWhatASeededRunDid(t *testing.T) {
	const (
		investigate = "Investigate verification without an Intel API key"
		fixTCB      = "Fix the OutOfDateConfigurationNeeded issue"
		ciGreen     = "Ensure the CI is green"
		addAction   = "Add a GitHub Action that runs the integration test"
		fixed       = "I fixed this on the client side: the status is accepted only with listed advisories."
	)
	// The hub's plan when the run was sent: two tasks waiting.
	dir := setupProjectDir(t, "Attest the enclave", []*pm.Task{
		{ID: 1, Title: investigate, Priority: 1, Status: pm.TaskPending, Tags: []string{"epic:attestation"}},
		{ID: 2, Title: fixTCB, Priority: 2, Status: pm.TaskPending, Tags: []string{"epic:attestation"}},
	})
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)

	// #2 implements a requirement, so the Requirements tab lists it.
	reqID := addRequirementVia(t, ts, map[string]any{
		"title": "The client accepts only the TCB statuses its policy lists.", "status": "approved"})
	hub, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	hub.Plan.TaskByID(2).Requirements = []int{reqID}
	if err := hub.SaveDirect(); err != nil {
		t.Fatal(err)
	}

	// On the device: both are done, and the run has picked up a task of its
	// own and is working on it.
	started := time.Now().Add(-40 * time.Minute).UTC()
	finished := time.Now().Add(-2 * time.Minute).UTC()
	doc := deviceProgress(t, hub, func(dev *state.ProjectState) {
		for _, task := range dev.Plan.Tasks {
			task.Status, task.StartedAt, task.CompletedAt = pm.TaskDone, &started, &finished
			task.Result = "done on the device"
			if task.ID == 2 {
				task.Result = fixed
				task.HealAttempts = 1
				pm.AddAnnotation(task, "ai", "[HEAL 1/2] Succeeded — task signal: done")
			}
		}
		dev.Plan.Tasks = append(dev.Plan.Tasks, &pm.Task{ID: 3, Title: addAction, Priority: 3,
			Status: pm.TaskInProgress, StartedAt: &finished})
	})

	// Meanwhile a task is added here, and takes the number the run gave its
	// own: the run's is shown as #4.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, &pm.Task{ID: 3, Title: ciGreen, Priority: 3, Status: pm.TaskPending})
	if err := ps.SaveDirect(); err != nil {
		t.Fatal(err)
	}

	ex := reportingExec{stubExec: stubExec{id: "sgx-1"}, doc: doc}
	rememberSeededDispatch(ex, "h-views", projectseed.Provenance{
		ExecutorID: ex.id, ExecutorKind: "remote", Isolation: "remote", RunID: "run_views"})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-views") })
	srv.trackRun(dir, ex, "h-views")
	t.Cleanup(func() { srv.untrackRun(dir) })

	// The list, which every view below must agree with.
	want := map[int]struct{ title, status string }{
		1: {investigate, "done"},
		2: {fixTCB, "done"},
		3: {ciGreen, "pending"},
		4: {addAction, "in_progress"},
	}
	listed := map[int]string{}
	for _, raw := range tasksFrom(t, apiGET(t, ts, "/api/state")) {
		task, _ := raw.(map[string]interface{})
		listed[number(task, "id")] = fmt.Sprint(task["status"])
	}
	for id, w := range want {
		if listed[id] != w.status {
			t.Fatalf("the task list shows #%d %q, want %q — the premise of this test", id, listed[id], w.status)
		}
	}

	// The details modal.
	for id, w := range want {
		var d struct {
			Task pm.Task `json:"task"`
		}
		if code := getAs(t, ts, fmt.Sprintf("/api/tasks/%d/details", id), &d); code != http.StatusOK {
			t.Errorf("details of #%d = HTTP %d; the list shows it %s", id, code, w.status)
			continue
		}
		if d.Task.Title != w.title || string(d.Task.Status) != w.status {
			t.Errorf("details of #%d: %q %s, want %q %s as the list shows it",
				id, d.Task.Title, d.Task.Status, w.title, w.status)
		}
	}
	var d2 struct {
		Task pm.Task `json:"task"`
	}
	getAs(t, ts, "/api/tasks/2/details", &d2)
	if d2.Task.Result != fixed || d2.Task.CompletedAt == nil || d2.Task.ExecutorID != "sgx-1" ||
		len(d2.Task.Annotations) == 0 {
		t.Errorf("details of #2 lack what the device recorded: result %q, completed %v, executor %q, %d notes",
			d2.Task.Result, d2.Task.CompletedAt, d2.Task.ExecutorID, len(d2.Task.Annotations))
	}

	// The details modal's deferred sections, for the task only the run has.
	for _, path := range []string{"/api/tasks/4/network", "/api/tasks/4/blocker"} {
		if code := getAs(t, ts, path, nil); code != http.StatusOK {
			t.Errorf("GET %s = HTTP %d; the list shows #4", path, code)
		}
	}

	// GET /api/tasks, filtered as the dashboard filters it.
	var found struct {
		Tasks []pm.Task `json:"tasks"`
	}
	getAs(t, ts, "/api/tasks?status=done", &found)
	if len(found.Tasks) != 2 {
		t.Errorf("GET /api/tasks?status=done = %d tasks, want #1 and #2", len(found.Tasks))
	}

	// The glasses.
	var gl struct {
		Tasks  []glassesTask  `json:"tasks"`
		Counts map[string]int `json:"counts"`
	}
	getAs(t, ts, "/api/glasses/tasks?project_idx=0", &gl)
	for _, g := range gl.Tasks {
		if w, ok := want[g.ID]; ok && g.Status != w.status {
			t.Errorf("the glasses list #%d as %s, want %s", g.ID, g.Status, w.status)
		}
	}
	if gl.Counts["done"] != 2 || gl.Counts["in_progress"] != 1 || len(gl.Tasks) != 4 {
		t.Errorf("the glasses list %d tasks counted %v, want 4 with 2 done and 1 in progress", len(gl.Tasks), gl.Counts)
	}
	var gd struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if code := getAs(t, ts, "/api/glasses/tasks/2?project_idx=0", &gd); code != http.StatusOK || gd.Status != "done" || gd.Result != fixed {
		t.Errorf("the glasses' detail of #2 = HTTP %d %s %q, want done with the device's summary", code, gd.Status, gd.Result)
	}
	if code := getAs(t, ts, "/api/glasses/tasks/4?project_idx=0", &gd); code != http.StatusOK || gd.Status != "in_progress" {
		t.Errorf("the glasses' detail of #4 = HTTP %d %s, want in_progress", code, gd.Status)
	}

	// The charts.
	var tl struct {
		Bars []struct {
			TaskID int    `json:"taskId"`
			Status string `json:"status"`
		} `json:"bars"`
	}
	getAs(t, ts, "/api/timeline", &tl)
	var deps struct {
		Nodes []struct {
			ID     int    `json:"id"`
			Status string `json:"status"`
		} `json:"nodes"`
	}
	getAs(t, ts, "/api/deps", &deps)
	charted := map[string]map[int]string{"timeline": {}, "deps": {}}
	for _, b := range tl.Bars {
		charted["timeline"][b.TaskID] = b.Status
	}
	for _, n := range deps.Nodes {
		charted["deps"][n.ID] = n.Status
	}
	for chart, got := range charted {
		for id, w := range want {
			if got[id] != w.status {
				t.Errorf("%s shows #%d as %q, want %q", chart, id, got[id], w.status)
			}
		}
	}
	var an struct {
		Donut struct {
			Values []int `json:"values"`
		} `json:"status_donut"`
	}
	getAs(t, ts, "/api/analytics", &an)
	if v := an.Donut.Values; len(v) < 3 || v[0] != 1 || v[1] != 1 || v[2] != 2 {
		t.Errorf("analytics counts %v (pending, in progress, done…), want 1, 1, 2", v)
	}
	var ep struct {
		Epics []struct {
			Done  int `json:"done"`
			Total int `json:"total"`
		} `json:"epics"`
	}
	getAs(t, ts, "/api/epics", &ep)
	if len(ep.Epics) != 1 || ep.Epics[0].Done != 2 || ep.Epics[0].Total != 2 {
		t.Errorf("epics = %+v, want attestation 2 of 2 done", ep.Epics)
	}

	// The Requirements tab: the tasks implementing a requirement, and the
	// trace matrix.
	var rc struct {
		Tasks []implementingTask `json:"tasks"`
	}
	getAs(t, ts, fmt.Sprintf("/api/requirements/%d/checks", reqID), &rc)
	if len(rc.Tasks) != 1 || rc.Tasks[0].ID != 2 || rc.Tasks[0].Status != pm.TaskDone {
		t.Errorf("R-%d's tasks = %+v, want #2 done as the list shows it", reqID, rc.Tasks)
	}
	var tr struct {
		Rows []struct {
			Tasks []struct {
				ID     int    `json:"id"`
				Status string `json:"status"`
			} `json:"tasks"`
		} `json:"rows"`
	}
	getAs(t, ts, "/api/requirements/trace", &tr)
	if len(tr.Rows) != 1 || len(tr.Rows[0].Tasks) != 1 || tr.Rows[0].Tasks[0].Status != "done" {
		t.Errorf("the trace matrix = %+v, want R-%d's #2 done", tr.Rows, reqID)
	}

	// None of it was written down: the merge does that once, when the run
	// ends.
	back, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(back.Plan.Tasks); n != 3 {
		t.Fatalf("the hub's recorded plan holds %d tasks, want its own 3", n)
	}
	for _, task := range back.Plan.Tasks {
		if task.Status != pm.TaskPending || task.Result != "" {
			t.Errorf("the record's #%d is %s %q; a view must never be saved", task.ID, task.Status, task.Result)
		}
	}
}
