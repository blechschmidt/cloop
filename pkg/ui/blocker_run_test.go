package ui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestBlockerDetectionAsksTheHubWhetherARunIsExecuting covers GET
// /api/tasks/{id}/blocker with a task three hours into its run (Task 20479).
//
// Its project's state was written when the task started and not since, which
// is all a run writes during one task. The old heuristic called such a task
// stalled thirty minutes in; the hub now asks what stale-run recovery asks —
// is anything executing the project? — and calls the task stalled only when
// nothing is.
func TestBlockerDetectionAsksTheHubWhetherARunIsExecuting(t *testing.T) {
	started := time.Now().Add(-3 * time.Hour)
	dir := setupProjectDir(t, "a long task", []*pm.Task{
		{ID: 1, Title: "train the model", Status: pm.TaskInProgress, StartedAt: &started},
	})
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	srv.trackRun(dir, &stubExecutor{status: executor.Status{State: executor.StateRunning}}, "h1")
	code, body := rawJSON(t, ts, http.MethodGet, "/api/tasks/1/blocker", nil)
	if code != http.StatusOK {
		t.Fatalf("GET with a run executing = %d %v", code, body)
	}
	if body["blocked"] != false || body["run"] != "live" || body["stalled_since"] != nil {
		t.Errorf("a task its run has been on for three hours = %v, want not blocked with run=live", body)
	}

	// The run goes. Now nothing will advance the task.
	srv.untrackRun(dir)
	code, body = rawJSON(t, ts, http.MethodGet, "/api/tasks/1/blocker", nil)
	if code != http.StatusOK {
		t.Fatalf("GET with nothing executing = %d %v", code, body)
	}
	if body["blocked"] != true || body["run"] != "gone" || fmt.Sprint(body["reasons"]) != "[stalled]" {
		t.Errorf("a task in progress with nothing executing it = %v, want blocked as stalled with run=gone", body)
	}
	if body["stalled_since"] == nil {
		t.Errorf("a stalled task did not say since when: %v", body)
	}
}
