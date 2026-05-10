package ui

// Task 20132: handler-level event-payload tests.
//
// These tests verify the REST mutation handlers ship only the delta on the
// WebSocket fan-out — never the full plan. They pre-seed the diff cache so
// the first broadcast after a mutation is incremental (one task changed),
// then assert the payload size and structure match the delta contract.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// seedDiffCache primes the per-project diff cache so the next broadcastStateDiff
// call ships only the delta against this seeded baseline. Without seeding the
// first call would degenerate into a full-state diff, which is the correct
// fallback behaviour but obscures the incremental-payload assertion this test
// is making.
func seedDiffCache(t *testing.T, srv *Server, workDir string) {
	t.Helper()
	ps, err := state.LoadLite(workDir)
	if err != nil {
		t.Fatalf("LoadLite: %v", err)
	}
	cache := srv.ensureDiffCache()
	cache.swap(workDir, ps)
}

// attachHubClient registers a fresh hubClient on workDir and returns it.
// Tests drain the client's outgoing channel to assert what was broadcast.
func attachHubClient(srv *Server, workDir string) *hubClient {
	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     "diff-test",
	}
	srv.hubMu.Lock()
	if srv.hubClients[workDir] == nil {
		srv.hubClients[workDir] = make(map[*hubClient]struct{})
	}
	srv.hubClients[workDir][hc] = struct{}{}
	srv.hubMu.Unlock()
	return hc
}

// drainOne returns the next queued wsMessage or fails the test if none.
func drainOne(t *testing.T, hc *hubClient) wsMessage {
	t.Helper()
	select {
	case msg := <-hc.ch:
		return msg
	default:
		t.Fatal("expected a queued wsMessage, none present")
		return wsMessage{}
	}
}

// drainAll consumes every queued wsMessage and returns them.
func drainAll(hc *hubClient) []wsMessage {
	out := []wsMessage{}
	for {
		select {
		case msg := <-hc.ch:
			out = append(out, msg)
		default:
			return out
		}
	}
}

// TestTaskAddHandler_EmitsStateDiffNotFullPlan verifies POST /api/task/add
// broadcasts a state_diff containing only the newly-added task — not the
// full plan re-marshalled.
func TestTaskAddHandler_EmitsStateDiffNotFullPlan(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "existing 1", Status: pm.TaskDone},
		{ID: 2, Title: "existing 2", Status: pm.TaskDone},
	}
	dir := setupProjectDir(t, cloopGoal, tasks)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	seedDiffCache(t, srv, dir)
	hc := attachHubClient(srv, dir)

	body := strings.NewReader(`{"title":"new task","priority":3}`)
	resp, err := ts.Client().Post(ts.URL+"/api/task/add", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	messages := drainAll(hc)
	if len(messages) == 0 {
		t.Fatal("expected at least one broadcast after task add")
	}

	// Find the state_diff envelope.
	var diff *wsMessage
	for i := range messages {
		if messages[i].Type == "state_diff" {
			diff = &messages[i]
			break
		}
	}
	if diff == nil {
		t.Fatalf("expected state_diff message; got types: %v", types(messages))
	}

	// Parse and assert: tasks_added has exactly the new task, no top-level
	// state churn beyond updated_at and the post-add plan version bump.
	var payload struct {
		TasksAdded   []*pm.Task         `json:"tasks_added"`
		TasksRemoved []int              `json:"tasks_removed"`
		TasksChanged []json.RawMessage  `json:"tasks_changed"`
		StateChanged map[string]any     `json:"state_changed"`
	}
	if err := json.Unmarshal(diff.Data, &payload); err != nil {
		t.Fatalf("unmarshal state_diff: %v", err)
	}
	if len(payload.TasksAdded) != 1 {
		t.Fatalf("expected exactly 1 tasks_added, got %d", len(payload.TasksAdded))
	}
	if payload.TasksAdded[0].Title != "new task" {
		t.Errorf("expected added task title 'new task', got %q", payload.TasksAdded[0].Title)
	}
	if len(payload.TasksRemoved) != 0 {
		t.Errorf("expected no tasks_removed, got %v", payload.TasksRemoved)
	}
	if len(payload.TasksChanged) != 0 {
		t.Errorf("expected no tasks_changed for an add, got %d entries", len(payload.TasksChanged))
	}

	// Payload size sanity: even with a 2-task baseline + the new task the
	// diff envelope should be well under 2 KB (vs full-state which marshals
	// every task field).
	if len(diff.Data) > 2048 {
		t.Errorf("state_diff payload unexpectedly large: %d bytes", len(diff.Data))
	}
}

// TestDeleteTaskHandler_EmitsStateDiffWithRemovedID verifies DELETE
// /api/tasks/{id} ships only the removed task ID, not the surviving plan.
func TestDeleteTaskHandler_EmitsStateDiffWithRemovedID(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "keep", Status: pm.TaskDone},
		{ID: 2, Title: "delete", Status: pm.TaskPending},
		{ID: 3, Title: "keep too", Status: pm.TaskPending},
	}
	dir := setupProjectDir(t, cloopGoal, tasks)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	seedDiffCache(t, srv, dir)
	hc := attachHubClient(srv, dir)

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/tasks/2", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	resp.Body.Close()

	messages := drainAll(hc)
	var diff *wsMessage
	for i := range messages {
		if messages[i].Type == "state_diff" {
			diff = &messages[i]
			break
		}
	}
	if diff == nil {
		t.Fatalf("expected state_diff broadcast on delete; got types: %v", types(messages))
	}

	var payload struct {
		TasksAdded   []*pm.Task `json:"tasks_added"`
		TasksRemoved []int      `json:"tasks_removed"`
	}
	if err := json.Unmarshal(diff.Data, &payload); err != nil {
		t.Fatalf("unmarshal state_diff: %v", err)
	}
	if len(payload.TasksAdded) != 0 {
		t.Errorf("expected no tasks_added on delete, got %d", len(payload.TasksAdded))
	}
	if len(payload.TasksRemoved) != 1 || payload.TasksRemoved[0] != 2 {
		t.Errorf("expected tasks_removed=[2], got %v", payload.TasksRemoved)
	}
}

// TestPutTaskHandler_EmitsStateDiffWithChangedFieldsOnly verifies PUT
// /api/tasks/{id} ships only the changed fields of the edited task — not
// the entire plan or task struct.
func TestPutTaskHandler_EmitsStateDiffWithChangedFieldsOnly(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "original title", Description: "original description", Priority: 5, Status: pm.TaskPending},
		{ID: 2, Title: "untouched", Description: "untouched", Priority: 6, Status: pm.TaskPending},
	}
	dir := setupProjectDir(t, cloopGoal, tasks)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	seedDiffCache(t, srv, dir)
	hc := attachHubClient(srv, dir)

	body := strings.NewReader(`{"title":"NEW title"}`)
	req, _ := http.NewRequest("PUT", ts.URL+"/api/tasks/1", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()

	messages := drainAll(hc)
	var diff *wsMessage
	for i := range messages {
		if messages[i].Type == "state_diff" {
			diff = &messages[i]
			break
		}
	}
	if diff == nil {
		t.Fatalf("expected state_diff on edit; got types: %v", types(messages))
	}

	var payload struct {
		TasksAdded   []*pm.Task        `json:"tasks_added"`
		TasksRemoved []int             `json:"tasks_removed"`
		TasksChanged []json.RawMessage `json:"tasks_changed"`
	}
	if err := json.Unmarshal(diff.Data, &payload); err != nil {
		t.Fatalf("unmarshal state_diff: %v", err)
	}
	if len(payload.TasksChanged) != 1 {
		t.Fatalf("expected 1 tasks_changed entry, got %d", len(payload.TasksChanged))
	}
	var change map[string]any
	if err := json.Unmarshal(payload.TasksChanged[0], &change); err != nil {
		t.Fatalf("unmarshal change: %v", err)
	}
	// Critical: only the title field should be present (plus the ID). The
	// untouched fields (description, priority, status) must not appear —
	// that's the entire point of the delta refactor.
	if change["id"].(float64) != 1 {
		t.Errorf("expected change.id=1, got %v", change["id"])
	}
	if change["title"] != "NEW title" {
		t.Errorf("expected title change to 'NEW title', got %v", change["title"])
	}
	if _, present := change["description"]; present {
		t.Errorf("description was not edited; it must NOT appear in the diff: %v", change["description"])
	}
	if _, present := change["priority"]; present {
		t.Errorf("priority was not edited; it must NOT appear in the diff: %v", change["priority"])
	}
	if _, present := change["status"]; present {
		t.Errorf("status was not edited; it must NOT appear in the diff: %v", change["status"])
	}
}

// TestOptionsToggleHandler_EmitsStateDiffNotFullState verifies that a flag
// flip (auto_evolve, innovate_mode, ...) emits a state_changed delta and
// never includes the task list.
func TestOptionsToggleHandler_EmitsStateDiffNotFullState(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "t1", Status: pm.TaskPending},
		{ID: 2, Title: "t2", Status: pm.TaskPending},
	}
	dir := setupProjectDir(t, cloopGoal, tasks)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	seedDiffCache(t, srv, dir)
	hc := attachHubClient(srv, dir)

	body := strings.NewReader(`{"flag":"auto_evolve","value":true}`)
	resp, err := ts.Client().Post(ts.URL+"/api/options/toggle", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	messages := drainAll(hc)
	var diff *wsMessage
	for i := range messages {
		if messages[i].Type == "state_diff" {
			diff = &messages[i]
			break
		}
	}
	if diff == nil {
		t.Fatalf("expected state_diff on options toggle; got types: %v", types(messages))
	}

	var payload struct {
		TasksAdded   []*pm.Task     `json:"tasks_added"`
		TasksChanged []any          `json:"tasks_changed"`
		StateChanged map[string]any `json:"state_changed"`
	}
	if err := json.Unmarshal(diff.Data, &payload); err != nil {
		t.Fatalf("unmarshal state_diff: %v", err)
	}
	if len(payload.TasksAdded) != 0 {
		t.Errorf("options toggle must not list tasks_added: %v", payload.TasksAdded)
	}
	if len(payload.TasksChanged) != 0 {
		t.Errorf("options toggle must not list tasks_changed: %v", payload.TasksChanged)
	}
	if payload.StateChanged == nil || payload.StateChanged["auto_evolve"] != true {
		t.Errorf("expected state_changed.auto_evolve=true, got %v", payload.StateChanged)
	}
}

// TestPutTaskHandler_NoLegacyFullStatePayload pins the contract that
// task_mutation envelopes (when emitted at all) carry only the conflict hint
// + task summary — never an embedded `state` blob. The full plan ships on
// state_diff or not at all.
func TestPutTaskHandler_NoLegacyFullStatePayload(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskPending}}
	dir := setupProjectDir(t, cloopGoal, tasks)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	seedDiffCache(t, srv, dir)
	hc := attachHubClient(srv, dir)

	body := strings.NewReader(`{"title":"renamed"}`)
	req, _ := http.NewRequest("PUT", ts.URL+"/api/tasks/1", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()

	for _, msg := range drainAll(hc) {
		if msg.Type != "task_mutation" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			t.Fatalf("unmarshal task_mutation: %v", err)
		}
		if _, present := payload["state"]; present {
			t.Errorf("task_mutation must not embed the legacy 'state' blob (Task 20132): %v", payload)
		}
	}
}

// types returns the Type field of every message — handy in error reports.
func types(msgs []wsMessage) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = m.Type
	}
	return out
}
