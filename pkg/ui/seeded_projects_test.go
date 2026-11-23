package ui

// The projects list described every project from the hub's own copy of it. A
// run carried out as a seed works through a copy of its own on another machine
// and brings its state back only when it ends, so for the whole of such a run
// the list described how the *previous* run ended. /api/state has overlaid the
// run in flight since Tasks 20349 and 50; the list never did (Task 20514).
//
// Measured on the live hub on 2026-11-22: a run of sgx-rust-attestation started
// on the sgx device at 22:22 UTC and worked through its tasks, its lease
// renewed "while its run is live", and the projects grid showed the card as
// health "idle" with "Paused: executor … stopped answering and nothing replaced
// the run" — left on the hub's copy by the run before it, which the stable UI's
// spurious failover claim had killed.

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// lostExecutorPause is what the hub records on its copy when a run's executor
// stops answering and nothing replaces the run — the record the live card kept
// showing.
func lostExecutorPause(t *testing.T, dir string) {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	ps.SetPaused(pausereason.New(pausereason.CodeExecutorLost,
		"executor sgx-1 stopped answering and nothing replaced the run"))
	if err := ps.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// projectCard returns the /api/projects entry for dir and the list's stats.
func projectCard(t *testing.T, body map[string]interface{}, dir string) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	list, _ := body["projects"].([]interface{})
	stats, _ := body["stats"].(map[string]interface{})
	for _, raw := range list {
		p, _ := raw.(map[string]interface{})
		if p["path"] == dir {
			return p, stats
		}
	}
	t.Fatalf("/api/projects lists no project at %s: %v", dir, body)
	return nil, nil
}

// number reads a JSON number field as an int.
func number(m map[string]interface{}, key string) int {
	f, _ := m[key].(float64)
	return int(f)
}

// progressReport is the report a device sends while its run is going, for a
// project dispatched with goal and no tasks and a plan of the run's own making
// whose tasks stand at statuses.
func progressReport(t *testing.T, goal string, statuses ...pm.TaskStatus) []byte {
	t.Helper()
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
	// An empty, migrated database beside the seed: Load converts the seed
	// into it as it would into one it made, without paying for the
	// migrations under -race (several seconds a report).
	statedbtest.SeedDir(t, dev)
	st, err := state.Load(dev)
	if err != nil {
		t.Fatalf("load the seeded workspace: %v", err)
	}
	at := time.Now().Add(-time.Minute).UTC()
	for i, status := range statuses {
		task := &pm.Task{ID: i + 1, Title: "Planned on the device, step " + string(rune('A'+i)),
			Priority: i + 1, Status: status}
		switch status {
		case pm.TaskDone:
			task.StartedAt, task.CompletedAt, task.Result = &at, &at, "done on the device"
		case pm.TaskInProgress:
			task.StartedAt = &at
		}
		st.Plan.Tasks = append(st.Plan.Tasks, task)
	}
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

// progressingExec is a device whose run reports more of its plan as it goes.
type progressingExec struct {
	stubExec
	mu  sync.Mutex
	doc []byte
}

func (e *progressingExec) report(doc []byte) {
	e.mu.Lock()
	e.doc = doc
	e.mu.Unlock()
}

func (e *progressingExec) InterimProjectResult(string) (executor.ProjectResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.doc) == 0 {
		return executor.ProjectResult{}, executor.ErrProjectResultUnavailable
	}
	return executor.ProjectResult{Data: e.doc, Interim: true, Redact: func(s string) string { return s }}, nil
}

func TestProjectsListShowsASeededRunInFlight(t *testing.T) {
	const goal = "Build an attested enclave and a client for it"
	dir := setupProjectDir(t, goal, nil)
	lostExecutorPause(t, dir)

	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	card, stats := projectCard(t, apiGET(t, ts, "/api/projects"), dir)
	if card["status"] != "paused" || card["health"] != "idle" || card["pause_reason"] == nil {
		t.Fatalf("before the run the card = status %v, health %v, pause %v; want the recorded pause",
			card["status"], card["health"], card["pause_reason"])
	}
	activeBefore := number(stats, "active_runs")

	// The run as every dispatch path leaves it for a device that was sent the
	// project: seeded and tracked. The device has planned three tasks, done the
	// first and is on the second.
	ex := reportingExec{stubExec: stubExec{id: "sgx-1"},
		doc: progressReport(t, goal, pm.TaskDone, pm.TaskInProgress, pm.TaskPending)}
	rememberSeededDispatch(ex, "h-list-1", projectseed.Provenance{
		ExecutorID: ex.id, ExecutorKind: "remote", Isolation: "remote", RunID: "run_list_1"})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-list-1") })
	srv.trackRun(dir, ex, "h-list-1")

	card, stats = projectCard(t, apiGET(t, ts, "/api/projects"), dir)
	if card["status"] != "running" || card["health"] != "running" || card["running"] != true {
		t.Fatalf("with a seeded run in flight the card = status %v, health %v, running %v; want a running "+
			"project — the device is working through it while the hub's copy says how the last run ended",
			card["status"], card["health"], card["running"])
	}
	if card["pause_reason"] != nil {
		t.Errorf("the card still carries the previous run's pause %v; the grid renders it as "+
			"\"Paused: …\" under a running project", card["pause_reason"])
	}
	if number(card, "total_tasks") != 3 || number(card, "done_tasks") != 1 || number(card, "active_tasks") != 1 {
		t.Errorf("the card counts %d tasks, %d done, %d active; want the run's plan as /api/state shows it "+
			"(3, 1 done, 1 under way)", number(card, "total_tasks"), number(card, "done_tasks"),
			number(card, "active_tasks"))
	}
	if got := number(stats, "active_runs"); got != activeBefore+1 {
		t.Errorf("active_runs = %d, want %d: the run in flight is an active run", got, activeBefore+1)
	}
	// The list and the project's own Overview tell one story.
	if got := apiGET(t, ts, "/api/state")["status"]; got != card["status"] {
		t.Errorf("/api/state says %v while the projects list says %v", got, card["status"])
	}

	// A view, not a write: the record — and the status cache stale-run
	// detection compares liveness with — still says what the databases say.
	back, err := state.LoadLite(dir)
	if err != nil {
		t.Fatalf("LoadLite: %v", err)
	}
	if back.Status != "paused" || back.PauseReason == nil || back.PauseReason.Code != pausereason.CodeExecutorLost {
		t.Fatalf("the recorded status became %q (%v); the overlay must not be saved", back.Status, back.PauseReason)
	}
	srv.projMu.RLock()
	for _, st := range srv.projStatuses {
		if st.Path == dir && st.Status != "paused" {
			t.Errorf("the status cache says %q for %s; it must keep the record", st.Status, dir)
		}
	}
	srv.projMu.RUnlock()

	// The run settles: the record speaks again.
	takeSeededDispatch(ex, "h-list-1")
	srv.untrackRun(dir)
	card, _ = projectCard(t, apiGET(t, ts, "/api/projects"), dir)
	if card["status"] != "paused" || card["health"] != "idle" || card["pause_reason"] == nil {
		t.Fatalf("after the run settled the card = status %v, health %v, pause %v; want the record",
			card["status"], card["health"], card["pause_reason"])
	}
}

// TestProjectsListShowsASeededRunsStatusBeforeItsFirstReport: a device that has
// not reported yet, or is too old to, still has a run in flight — the status
// is the hub's own knowledge; only the counts wait for the device.
func TestProjectsListShowsASeededRunsStatusBeforeItsFirstReport(t *testing.T) {
	dir := setupProjectDir(t, "quiet device", []*pm.Task{
		{ID: 1, Title: "The hub's own task", Priority: 1, Status: pm.TaskPending},
	})
	lostExecutorPause(t, dir)
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)

	for _, ex := range []executor.Executor{
		stubExec{id: "old-agent"}, // cannot report at all
		reportingExec{stubExec: stubExec{id: "sgx-1"}, err: executor.ErrProjectResultUnavailable},
	} {
		rememberSeededDispatch(ex, "h-quiet", projectseed.Provenance{ExecutorID: ex.ID()})
		srv.trackRun(dir, ex, "h-quiet")
		card, _ := projectCard(t, apiGET(t, ts, "/api/projects"), dir)
		if card["status"] != "running" || card["health"] != "running" || card["pause_reason"] != nil {
			t.Errorf("%s: the card = status %v, health %v, pause %v; want running", ex.ID(),
				card["status"], card["health"], card["pause_reason"])
		}
		if number(card, "total_tasks") != 1 || number(card, "done_tasks") != 0 {
			t.Errorf("%s: the card counts %d tasks, %d done; want the hub's own plan until the device reports",
				ex.ID(), number(card, "total_tasks"), number(card, "done_tasks"))
		}
		takeSeededDispatch(ex, "h-quiet")
		srv.untrackRun(dir)
	}
}

// TestProjectsListLeavesALocalRunAlone: a run on this filesystem writes the
// hub's own database, so the list already says what it is doing; overriding it
// would misreport one that is pausing or finishing.
func TestProjectsListLeavesALocalRunAlone(t *testing.T) {
	dir := setupProjectDir(t, "local run", nil)
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	ps.Status = "complete"
	if err := ps.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	srv.trackRun(dir, stubExec{id: "local-host"}, "h-local") // tracked, never seeded
	t.Cleanup(func() { srv.untrackRun(dir) })

	card, _ := projectCard(t, apiGET(t, ts, "/api/projects"), dir)
	if card["status"] != "complete" {
		t.Fatalf("a local run's card says %v, want the status it recorded", card["status"])
	}
}

// TestProjectsListDropsALostSeededRun: a run the failover took off an executor
// that stopped answering is not executing, whatever is still tracked for it.
func TestProjectsListDropsALostSeededRun(t *testing.T) {
	const goal = "lost device"
	dir := setupProjectDir(t, goal, nil)
	lostExecutorPause(t, dir)
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)

	ex := reportingExec{stubExec: stubExec{id: "sgx-1"}, doc: progressReport(t, goal, pm.TaskInProgress)}
	rememberSeededDispatch(ex, "h-lost", projectseed.Provenance{ExecutorID: ex.id})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-lost") })
	srv.trackRun(dir, ex, "h-lost")
	t.Cleanup(func() { srv.untrackRun(dir) })
	if card, _ := projectCard(t, apiGET(t, ts, "/api/projects"), dir); card["status"] != "running" {
		t.Fatalf("precondition: the card says %v, want running", card["status"])
	}

	srv.runHandleMu.Lock()
	run := srv.runHandles[dir]
	run.lost = true
	srv.runHandles[dir] = run
	srv.runHandleMu.Unlock()
	card, _ := projectCard(t, apiGET(t, ts, "/api/projects"), dir)
	if card["status"] == "running" || card["pause_reason"] == nil {
		t.Fatalf("a lost run's card = status %v, pause %v; want the record, not a run in flight",
			card["status"], card["pause_reason"])
	}
}

// TestProjectsListFollowsASeededRunsReports: the device's progress changes what
// the list says without any file on the hub changing, so the hub pushes it —
// once per change, not once per tick.
func TestProjectsListFollowsASeededRunsReports(t *testing.T) {
	const goal = "pushed progress"
	dir := setupProjectDir(t, goal, nil)
	lostExecutorPause(t, dir)
	srv := New(dir, 0, "")

	ex := &progressingExec{stubExec: stubExec{id: "sgx-1"}}
	ex.report(progressReport(t, goal, pm.TaskDone, pm.TaskInProgress, pm.TaskPending))
	rememberSeededDispatch(ex, "h-push", projectseed.Provenance{ExecutorID: ex.id})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-push") })
	srv.trackRun(dir, ex, "h-push")
	t.Cleanup(func() { srv.untrackRun(dir) })

	watcher := subscribe(t, srv, hubRoomGlobal, "viewer@example.com")
	sw := newProjectSweep()
	tick := func() { srv.sweepProjectsTick(sw, time.Now()) }
	cardIn := func(msg wsMessage) map[string]interface{} {
		t.Helper()
		var body map[string]interface{}
		if err := json.Unmarshal(msg.Data, &body); err != nil {
			t.Fatalf("decode projects push: %v", err)
		}
		card, _ := projectCard(t, body, dir)
		return card
	}

	tick()
	card := cardIn(nextMessage(t, watcher, "projects"))
	if card["status"] != "running" || number(card, "done_tasks") != 1 {
		t.Fatalf("first push: status %v, %d done; want running with the run's first task done",
			card["status"], number(card, "done_tasks"))
	}

	// Nothing new: no push.
	tick()
	if msg, ok := pendingMessage(watcher, "projects"); ok {
		t.Fatalf("a tick with nothing new pushed the list again: %s", msg.Data)
	}

	// The device finishes its second task.
	ex.report(progressReport(t, goal, pm.TaskDone, pm.TaskDone, pm.TaskInProgress))
	tick()
	card = cardIn(nextMessage(t, watcher, "projects"))
	if number(card, "done_tasks") != 2 || number(card, "active_tasks") != 1 {
		t.Fatalf("after the device's next report the pushed card counts %d done, %d active; want 2 and 1",
			number(card, "done_tasks"), number(card, "active_tasks"))
	}
}

// TestProjectsListShowsAPeersSeededRun: another member may be the one streaming
// the run (Task 20354). Its owner row says so, and whether the run is a seed.
func TestProjectsListShowsAPeersSeededRun(t *testing.T) {
	dir, a, b := clusterPair(t)
	lostExecutorPause(t, dir)

	if _, err := a.srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("A claimRun: %v", err)
	}
	if ok, err := a.node.UpdateMeta(ownerRun, dir, runOwnerMeta{Executor: "sgx-1", Handle: "h-peer",
		Seeded: true, Provenance: &projectseed.Provenance{ExecutorID: "sgx-1"}}); err != nil || !ok {
		t.Fatalf("UpdateMeta = %v, %v", ok, err)
	}
	card, _ := projectCard(t, apiGET(t, b.ts, "/api/projects"), dir)
	if card["status"] != "running" || card["health"] != "running" || card["pause_reason"] != nil {
		t.Fatalf("B's card for A's seeded run = status %v, health %v, pause %v; want running",
			card["status"], card["health"], card["pause_reason"])
	}

	// A run on A's own filesystem is A's to describe through the database.
	if ok, err := a.node.UpdateMeta(ownerRun, dir, runOwnerMeta{Executor: "local", Handle: "h-peer",
		RunClaimMeta: hubcluster.RunClaimMeta{}}); err != nil || !ok {
		t.Fatalf("UpdateMeta = %v, %v", ok, err)
	}
	card, _ = projectCard(t, apiGET(t, b.ts, "/api/projects"), dir)
	if card["status"] != "paused" {
		t.Fatalf("B's card for A's local run = status %v, want the record", card["status"])
	}
}

// pendingMessage returns a message of type typ the hub client has already been
// sent, without waiting for one.
func pendingMessage(hc *hubClient, typ string) (wsMessage, bool) {
	for {
		select {
		case msg := <-hc.ch:
			if msg.Type == typ {
				return msg, true
			}
		default:
			return wsMessage{}, false
		}
	}
}
