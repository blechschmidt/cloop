package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sendJSON sends a JSON body and decodes the JSON answer.
func sendJSON(t *testing.T, ts *httptest.Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func queueIDs(t *testing.T, dir string) []int {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []int
	for _, task := range ps.Plan.Queue() {
		out = append(out, task.ID)
	}
	return out
}

func loadTask(t *testing.T, dir string, id int) *pm.Task {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	task := ps.Plan.TaskByID(id)
	if task == nil {
		t.Fatalf("task %d missing", id)
	}
	return task
}

func TestTaskGateCreate_PutsTheGateWhereItWasAsked(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "one", Priority: 3, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 3, Status: pm.TaskPending},
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
		{ID: 4, Title: "done", Priority: 1, Status: pm.TaskDone},
	}
	dir := setupProjectDir(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	code, out := sendJSON(t, ts, "POST", "/api/tasks/gate", map[string]any{"after": 1, "title": "Check the parser", "description": "grammar first"})
	if code != http.StatusOK || out["id"] != float64(5) {
		t.Fatalf("POST /api/tasks/gate = %d %v, want 200 with id 5", code, out)
	}
	if got := queueIDs(t, dir); !sameOrder(got, []int{1, 5, 2, 3}) {
		t.Fatalf("queue = %v, want [1 5 2 3]: the gate goes right after task 1, between equal priorities", got)
	}
	g := loadTask(t, dir, 5)
	if !g.IsHumanGate() || g.Title != "Check the parser" || g.Description != "grammar first" || g.Status != pm.TaskPending {
		t.Fatalf("stored gate = %+v", g)
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{1}) {
		t.Fatalf("ReadyTasks = %v, want [1]: 2 and 3 wait behind the gate", got)
	}

	// No position: the end of the queue, with the default title.
	code, out = sendJSON(t, ts, "POST", "/api/tasks/gate", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("POST without a position = %d %v", code, out)
	}
	if got := queueIDs(t, dir); !sameOrder(got, []int{1, 5, 2, 3, 6}) {
		t.Fatalf("queue = %v, want the second gate last", got)
	}
	if g := loadTask(t, dir, 6); g.Title != pm.DefaultGateTitle {
		t.Errorf("untitled gate = %q", g.Title)
	}

	for _, tc := range []struct {
		body map[string]any
		want int
	}{
		{map[string]any{"before": 4}, http.StatusConflict},   // task 4 has run
		{map[string]any{"after": 99}, http.StatusBadRequest}, // no such task
		{map[string]any{"after": 1, "before": 2}, http.StatusBadRequest},
		{map[string]any{"title": strings.Repeat("x", 201)}, http.StatusBadRequest},
		{map[string]any{"after": -1}, http.StatusBadRequest},
	} {
		if code, out := sendJSON(t, ts, "POST", "/api/tasks/gate", tc.body); code != tc.want {
			t.Errorf("POST %v = %d %v, want %d", tc.body, code, out, tc.want)
		}
	}
	if got := queueIDs(t, dir); len(got) != 5 {
		t.Errorf("a refused request added a gate anyway: queue %v", got)
	}
}

func TestTaskApprove_OpensTheGateAndRecordsWho(t *testing.T) {
	gate := pm.NewHumanGate("Check the parser", "")
	gate.ID, gate.Priority = 2, 2
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "one", Priority: 1, Status: pm.TaskDone},
		gate,
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
	})
	// The run stopped at the gate.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.SetPaused(pausereason.NewForTask(pausereason.CodeApproval, "waiting for human review at gate #2", 2))
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, dir, nil)

	code, out := sendJSON(t, ts, "POST", "/api/tasks/2/approve", map[string]any{})
	if code != http.StatusOK || out["waiting"] != true || out["kind"] != string(pm.KindHumanGate) {
		t.Fatalf("approve = %d %v, want 200 with waiting=true", code, out)
	}
	g := loadTask(t, dir, 2)
	if !g.Approved || g.Status != pm.TaskDone || g.GateClosed() {
		t.Fatalf("approved gate = %+v", g)
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{3}) {
		t.Fatalf("ReadyTasks after the approval = %v, want [3]", got)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "task.gate_approve"})
	if err != nil || len(evs) != 1 {
		t.Fatalf("task.gate_approve rows = %d, %v", len(evs), err)
	}
	var payload map[string]any
	_ = json.Unmarshal([]byte(evs[0].Payload), &payload)
	if payload["task_id"] != float64(2) || payload["waiting"] != true || payload["via"] != "dashboard" {
		t.Errorf("audit payload = %v", payload)
	}
	rows, err := db.ListEventsOfType(statedb.EventReviewGate, 10)
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].Message, "approved") {
		t.Errorf("journal rows = %+v, %v", rows, err)
	}

	// A second approval changes nothing and says so.
	if code, out := sendJSON(t, ts, "POST", "/api/tasks/2/approve", map[string]any{}); code != http.StatusOK || out["already"] != true {
		t.Errorf("second approve = %d %v", code, out)
	}
	if code, _ := sendJSON(t, ts, "POST", "/api/tasks/99/approve", map[string]any{}); code != http.StatusNotFound {
		t.Errorf("approving a task that does not exist = %d", code)
	}
	// An ordinary task is pre-approved, for the run's approval gate.
	if code, out := sendJSON(t, ts, "POST", "/api/tasks/3/approve", map[string]any{}); code != http.StatusOK || out["waiting"] != false {
		t.Errorf("pre-approving task 3 = %d %v", code, out)
	}
	if task := loadTask(t, dir, 3); !task.Approved || task.Status != pm.TaskPending {
		t.Errorf("pre-approved task = %+v, want approved and still pending", task)
	}
}

// The two hand-made status routes take a gate's three statuses only, and
// "done" on a gate is its approval.
func TestTaskStatus_GateRules(t *testing.T) {
	gate := pm.NewHumanGate("", "")
	gate.ID, gate.Priority = 1, 1
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{gate, {ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending}})
	ts := newTestServer(t, dir, nil)

	for _, s := range []string{"failed", "in_progress"} {
		if code, out := sendJSON(t, ts, "POST", "/api/task/status", map[string]any{"id": 1, "status": s}); code != http.StatusBadRequest {
			t.Errorf("status %s on a gate = %d %v, want 400", s, code, out)
		}
		if code, out := sendJSON(t, ts, "PATCH", "/api/tasks/1", map[string]any{"status": s}); code != http.StatusBadRequest {
			t.Errorf("PATCH status %s on a gate = %d %v, want 400", s, code, out)
		}
	}
	if g := loadTask(t, dir, 1); g.Status != pm.TaskPending {
		t.Fatalf("a refused status reached the gate: %s", g.Status)
	}

	if code, out := sendJSON(t, ts, "POST", "/api/task/status", map[string]any{"id": 1, "status": "done"}); code != http.StatusOK {
		t.Fatalf("done on a gate = %d %v", code, out)
	}
	if g := loadTask(t, dir, 1); !g.Approved || g.Status != pm.TaskDone {
		t.Fatalf("done did not approve the gate: %+v", g)
	}
	if code, out := sendJSON(t, ts, "POST", "/api/task/status", map[string]any{"id": 1, "status": "pending"}); code != http.StatusOK {
		t.Fatalf("pending on a gate = %d %v", code, out)
	}
	if g := loadTask(t, dir, 1); g.Approved || !g.GateClosed() {
		t.Fatalf("pending did not close the gate again: %+v", g)
	}
	// The Kanban board's drag to Done approves it as well.
	if code, out := sendJSON(t, ts, "PATCH", "/api/tasks/1", map[string]any{"status": "done"}); code != http.StatusOK {
		t.Fatalf("PATCH done on a gate = %d %v", code, out)
	}
	if g := loadTask(t, dir, 1); !g.Approved {
		t.Fatalf("PATCH done did not approve the gate: %+v", g)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "task.gate_approve"}); err != nil || len(evs) != 2 {
		t.Errorf("task.gate_approve rows = %d, %v; want one per approval", len(evs), err)
	}
}

// The move endpoint works inside the queue the orchestrator runs: between
// equal priorities, where swapping priorities used to change nothing.
func TestTaskMove_MovesWithinTheRunQueue(t *testing.T) {
	gate := pm.NewHumanGate("", "")
	gate.ID, gate.Priority = 3, 2
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "one", Priority: 2, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending},
		gate,
		{ID: 4, Title: "done", Priority: 2, Status: pm.TaskDone},
	})
	ts := newTestServer(t, dir, nil)

	code, out := sendJSON(t, ts, "POST", "/api/task/move", map[string]any{"id": 3, "direction": "up"})
	if code != http.StatusOK || out["past"] != float64(2) {
		t.Fatalf("move up = %d %v", code, out)
	}
	if got := queueIDs(t, dir); !sameOrder(got, []int{1, 3, 2}) {
		t.Fatalf("queue = %v, want [1 3 2]", got)
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{1}) {
		t.Fatalf("ReadyTasks = %v, want [1]", got)
	}
	if code, _ := sendJSON(t, ts, "POST", "/api/task/move", map[string]any{"id": 4, "direction": "up"}); code != http.StatusConflict {
		t.Errorf("moving a finished task = %d, want 409", code)
	}
	if code, _ := sendJSON(t, ts, "POST", "/api/task/move", map[string]any{"id": 1, "direction": "up"}); code != http.StatusBadRequest {
		t.Errorf("moving the head up = %d, want 400", code)
	}
}

// Starting a run that would stop at a gate before doing anything is refused,
// rather than dispatching a harness to pause at once.
func TestRun_RefusedWhileTheRunWaitsAtAGate(t *testing.T) {
	gate := pm.NewHumanGate("Check the parser", "")
	gate.ID, gate.Priority = 2, 2
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "one", Priority: 1, Status: pm.TaskDone},
		gate,
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
	})
	ts := newTestServer(t, dir, nil)

	code, out := sendJSON(t, ts, "POST", "/api/run", map[string]any{})
	if code != http.StatusConflict || out["waiting_gate"] != float64(2) {
		t.Fatalf("POST /api/run = %d %v, want 409 naming gate 2", code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "review gate #2") {
		t.Errorf("refusal %q does not name the gate", msg)
	}
}

func TestPerTaskModelCallsRefuseAGate(t *testing.T) {
	gate := pm.NewHumanGate("", "")
	gate.ID, gate.Priority = 1, 1
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{gate})
	ts := newTestServer(t, dir, nil)
	for _, path := range []string{"/api/tasks/1/decompose", "/api/tasks/1/revise"} {
		code, out := sendJSON(t, ts, "POST", path, map[string]any{"instruction": "x", "description": "the gate's note"})
		if code != http.StatusConflict || !strings.Contains(fmt.Sprint(out["error"]), "review gate") {
			t.Errorf("POST %s on a gate = %d %v, want 409", path, code, out)
		}
	}
}

// The seed a remote executor gets says when its plan holds a pending gate,
// which a device whose cloop predates gates would run as a task.
func TestProjectSeedReportsPendingGates(t *testing.T) {
	gate := pm.NewHumanGate("", "")
	gate.ID, gate.Priority = 2, 2
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{{ID: 1, Title: "one", Priority: 1, Status: pm.TaskPending}, gate})

	seed, gates, err := projectSeedWithGates(dir)
	if err != nil || len(seed) == 0 || !gates {
		t.Fatalf("projectSeedWithGates = %d bytes, gates=%v, %v; want a seed flagged as holding a gate", len(seed), gates, err)
	}
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan.TaskByID(2).Status = pm.TaskDone
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if _, gates, err := projectSeedWithGates(dir); err != nil || gates {
		t.Fatalf("a passed gate still flags the seed: gates=%v, %v", gates, err)
	}
}
