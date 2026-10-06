package ui

// The dashboard's task writes keep the columns this binary does not know
// (Task 20388).
//
// Every handler below loads the plan, changes it and saves it whole through
// state.SaveDirect, which used to empty plan_tasks and insert the plan again —
// so a hub one migration behind another sharing its database reset the newer
// one's task columns on every edit made from its dashboard. Each request here
// runs against a database with a column no build knows, set in every task.

import (
	"strconv"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestTaskHandlersKeepColumnsTheBinaryDoesNotKnow(t *testing.T) {
	dir := setupProjectWithTasks(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "one", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
	})
	dbPath := state.DBPath(dir)
	statedbtest.AddFutureColumn(t, dbPath, "plan_tasks", `'kept by ' || id`)
	ts := newTestServer(t, dir, nil)

	want := map[string]string{"1": "kept by 1", "2": "kept by 2", "3": "kept by 3"}
	check := func(after string) {
		t.Helper()
		statedbtest.WantFutureValues(t, dbPath, "plan_tasks", "id", after, want)
	}

	if body := apiPOST(t, ts, "/api/task/edit", map[string]any{
		"id": 2, "title": "two, edited", "description": "edited", "priority": 1,
	}); body["ok"] != true {
		t.Fatalf("POST /api/task/edit: %v", body)
	}
	check("POST /api/task/edit")

	if code, body := apiPUT(t, ts, "/api/tasks/1", map[string]any{"title": "one, put"}); code != 200 {
		t.Fatalf("PUT /api/tasks/1: HTTP %d %v", code, body)
	}
	check("PUT /api/tasks/1")

	if body := apiPOST(t, ts, "/api/tasks/reorder", map[string]any{"ids": []int{3, 1, 2}}); body["ok"] != true {
		t.Fatalf("POST /api/tasks/reorder: %v", body)
	}
	check("POST /api/tasks/reorder")

	body := apiPOST(t, ts, "/api/tasks", map[string]any{"title": "four", "description": "added"})
	if body["ok"] != true {
		t.Fatalf("POST /api/tasks: %v", body)
	}
	added, _ := body["task"].(map[string]any)
	id, _ := added["id"].(float64)
	if id == 0 {
		t.Fatalf("POST /api/tasks returned no task id: %v", body)
	}
	want[strconv.Itoa(int(id))] = "" // a new task starts from the column's default
	check("POST /api/tasks")

	if body := apiDELETE(t, ts, "/api/tasks/3"); body["ok"] != true {
		t.Fatalf("DELETE /api/tasks/3: %v", body)
	}
	delete(want, "3")
	check("DELETE /api/tasks/3")

	// The edits themselves landed: the handlers still write what they change.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := ps.Plan.TaskByID(2); got == nil || got.Title != "two, edited" {
		t.Errorf("task 2 = %+v, want the edited title", got)
	}
	if got := ps.Plan.TaskByID(1); got == nil || got.Title != "one, put" {
		t.Errorf("task 1 = %+v, want the PUT title", got)
	}
}
