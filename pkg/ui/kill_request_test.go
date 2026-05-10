// Tests for the manual-abort UI hook (Task 20140). The handlers
// handleTaskStatus (POST /api/task/status) and handlePutTask (PUT/PATCH
// /api/tasks/{id}) must record a kill request whenever the operator's
// status change moves a task out of in_progress.
package ui

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestPostStatus_RequestsKillWhenLeavingInProgress(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "running task", Status: pm.TaskInProgress},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/status", map[string]interface{}{
		"id":     1,
		"status": "done",
	})
	if body["ok"] != true {
		t.Fatalf("expected ok=true, got %v", body)
	}

	rows, err := state.PendingKills(dir)
	if err != nil {
		t.Fatalf("PendingKills: %v", err)
	}
	if len(rows) != 1 || rows[0].TaskID != 1 || rows[0].TargetStatus != "done" {
		t.Errorf("kill_requests = %+v; want one row {task_id:1, target_status:done}", rows)
	}
}

func TestPostStatus_DoesNotRequestKillWhenAlreadyTerminal(t *testing.T) {
	// Moving a task that was already done/pending to a different state must
	// NOT insert a kill request — there is no in-flight provider call to
	// abort. Without this guard the orchestrator would needlessly poll a
	// stale row and (worse) override the operator's choice on a re-running
	// task that has nothing to do with the original status change.
	tasks := []*pm.Task{
		{ID: 1, Title: "done task", Status: pm.TaskDone},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/status", map[string]interface{}{
		"id":     1,
		"status": "pending",
	})
	if body["ok"] != true {
		t.Fatalf("expected ok=true, got %v", body)
	}

	rows, _ := state.PendingKills(dir)
	if len(rows) != 0 {
		t.Errorf("kill_requests = %+v; want empty (transition was not from in_progress)", rows)
	}
}

func TestPostStatus_DoesNotRequestKillForInProgressNoOp(t *testing.T) {
	// Status set to the same in_progress value: nothing to abort.
	tasks := []*pm.Task{
		{ID: 1, Title: "running", Status: pm.TaskInProgress},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	apiPOST(t, ts, "/api/task/status", map[string]interface{}{
		"id":     1,
		"status": "in_progress",
	})

	rows, _ := state.PendingKills(dir)
	if len(rows) != 0 {
		t.Errorf("kill_requests = %+v; want empty (no transition out of in_progress)", rows)
	}
}

func TestPutTask_RequestsKillWhenStatusLeavesInProgress(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 7, Title: "running", Status: pm.TaskInProgress},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPATCH(t, ts, "/api/tasks/7", map[string]interface{}{"status": "skipped"})
	if body["ok"] != true {
		t.Fatalf("PATCH expected ok=true, got %v", body)
	}

	rows, _ := state.PendingKills(dir)
	if len(rows) != 1 || rows[0].TaskID != 7 || rows[0].TargetStatus != "skipped" {
		t.Errorf("kill_requests = %+v; want one row {task_id:7, target_status:skipped}", rows)
	}
}

func TestPutTask_DoesNotRequestKillWhenStatusUnchanged(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 3, Title: "running", Status: pm.TaskInProgress},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	// PATCH only the title — status not in payload.
	apiPATCH(t, ts, "/api/tasks/3", map[string]interface{}{"title": "renamed"})

	rows, _ := state.PendingKills(dir)
	if len(rows) != 0 {
		t.Errorf("kill_requests = %+v; want empty (status field absent from PATCH)", rows)
	}
}
