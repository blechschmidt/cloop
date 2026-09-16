package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// postReorder sends the ids a dragged queue would send and returns the status.
func postReorder(t *testing.T, ts *httptest.Server, ids []int) (int, map[string]interface{}) {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{"ids": ids})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(ts.URL+"/api/tasks/reorder", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/tasks/reorder: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// queueOf reads back the order the orchestrator would run, from disk.
func queueOf(t *testing.T, dir string) []int {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ready := ps.Plan.ReadyTasks()
	out := make([]int, len(ready))
	for i, task := range ready {
		out[i] = task.ID
	}
	return out
}

func sameOrder(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func pendingTasks() []*pm.Task {
	return []*pm.Task{
		{ID: 1, Title: "one", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
	}
}

// The end the whole feature exists for: the order posted from the dashboard is
// the order the scheduler hands out.
func TestReorder_QueueFollowsThePostedOrder(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, pendingTasks())
	ts := newTestServer(t, dir, nil)

	if got := queueOf(t, dir); !sameOrder(got, []int{1, 2, 3}) {
		t.Fatalf("queue starts as %v, want [1 2 3]", got)
	}

	status, out := postReorder(t, ts, []int{3, 1, 2})
	if status != http.StatusOK {
		t.Fatalf("reorder returned HTTP %d: %v", status, out)
	}

	if got := queueOf(t, dir); !sameOrder(got, []int{3, 1, 2}) {
		t.Errorf("queue = %v, want [3 1 2] — the scheduler is not following the "+
			"order the dashboard posted", got)
	}
}

// A reorder is a statement about a whole list. The handler used to skip ids it
// did not recognise and renumber whatever was left, so a client working from a
// stale plan got HTTP 200 and an order nobody asked for.
func TestReorder_RejectsIDsThatAreNotInThePlan(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, pendingTasks())
	ts := newTestServer(t, dir, nil)

	status, _ := postReorder(t, ts, []int{3, 99, 1, 2})
	if status != http.StatusBadRequest {
		t.Errorf("reorder with an unknown id returned HTTP %d, want 400", status)
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{1, 2, 3}) {
		t.Errorf("queue = %v, want the original [1 2 3] — a rejected reorder "+
			"must not have partially applied", got)
	}
}

func TestReorder_RejectsDuplicateIDs(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, pendingTasks())
	ts := newTestServer(t, dir, nil)

	status, _ := postReorder(t, ts, []int{3, 1, 3, 2})
	if status != http.StatusBadRequest {
		t.Errorf("reorder with a duplicate id returned HTTP %d, want 400", status)
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{1, 2, 3}) {
		t.Errorf("queue = %v, want the original [1 2 3]", got)
	}
}

func TestReorder_RejectsAnEmptyList(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, pendingTasks())
	ts := newTestServer(t, dir, nil)

	if status, _ := postReorder(t, ts, []int{}); status != http.StatusBadRequest {
		t.Errorf("empty reorder returned HTTP %d, want 400", status)
	}
}

// The dashboard posts its pending queue, not the whole plan. Completed tasks
// must keep the priority they ran with — renumbering them rewrites history to
// no purpose, and it is the reason the old client sent every task it knew of.
func TestReorder_LeavesUnnamedTasksAlone(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "done", Priority: 7, Status: pm.TaskDone},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
	}
	dir := setupProjectDir(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	if status, out := postReorder(t, ts, []int{3, 2}); status != http.StatusOK {
		t.Fatalf("reorder returned HTTP %d: %v", status, out)
	}

	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := ps.Plan.TaskByID(1).Priority; got != 7 {
		t.Errorf("the completed task's priority became %d, want it left at 7", got)
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{3, 2}) {
		t.Errorf("queue = %v, want [3 2]", got)
	}
}

// Pinning survives a save now (migration 0042). Without the column the flag was
// dropped at the first write, which made the dashboard's pinned-first rendering
// unreachable and the queue's top row a different task than the one displayed.
func TestReorder_PinnedTaskLeadsTheQueueAcrossASave(t *testing.T) {
	tasks := pendingTasks()
	tasks[2].Pinned = true // task 3, the lowest priority of the three
	dir := setupProjectDir(t, cloopGoal, tasks)

	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ps.Plan.TaskByID(3).Pinned {
		t.Fatal("the pinned flag did not survive the save")
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{3, 1, 2}) {
		t.Errorf("queue = %v, want [3 1 2] — the pinned task leads", got)
	}
}

func TestReorder_RejectsNonPOST(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, pendingTasks())
	ts := newTestServer(t, dir, nil)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/tasks/reorder", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	// The route is registered method-first ("POST /api/tasks/reorder"), so a GET
	// never reaches the handler at all — 404 and 405 are both correct answers
	// depending on what else is registered under the path. What matters is that
	// a reorder is not something a GET can perform.
	if resp.StatusCode == http.StatusOK {
		t.Error("GET /api/tasks/reorder returned 200 — a read must not reorder the queue")
	}
	if got := queueOf(t, dir); !sameOrder(got, []int{1, 2, 3}) {
		t.Errorf("queue = %v, want the original [1 2 3]", got)
	}
}
