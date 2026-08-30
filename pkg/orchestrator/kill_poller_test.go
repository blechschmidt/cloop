// Tests for the manual-abort poller (Task 20140, Task 20203). These exercise
// the two phases — firing the cancel while the worker is still running and
// applying the operator's chosen target_status after the worker drains —
// without spinning up the full PM execution loop.
//
// Phase 2 is always driven through phase 1 rather than by hand-writing a row
// and flipping the status: the poller only rewrites a status for an execution
// it watched running, so a test that skipped phase 1 would be asserting on a
// path production never takes.
package orchestrator

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/watchdog"
)

// newTestOrchestrator returns a minimal Orchestrator wired with state +
// statedb + watchdog so processPendingKills can run end-to-end. Returns a
// cleanup that closes the DB.
func newTestOrchestrator(t *testing.T) *Orchestrator {
	t.Helper()
	dir := t.TempDir()
	ps, err := state.Init(dir, "test goal", 100)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	ps.Plan = pm.NewPlan(ps.Goal)

	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	o := &Orchestrator{
		state:    ps,
		statedb:  db,
		watchdog: &watchdog.Watchdog{},
		log:      logger.NewWithWriter(nil, false),
		config:   Config{WorkDir: dir},
	}
	return o
}

// addInProgressTask appends an in_progress task with id/title and registers a
// cancel func with the watchdog so phase-1 (fire cancel) has something to do.
func addInProgressTask(t *testing.T, o *Orchestrator, id int, title string) (context.Context, *pm.Task) {
	t.Helper()
	now := time.Now()
	task := &pm.Task{ID: id, Title: title, Status: pm.TaskInProgress, StartedAt: &now}
	o.state.Plan.Tasks = append(o.state.Plan.Tasks, task)
	if err := o.state.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.watchdog.Register(id, cancel)
	return ctx, task
}

// requestKill files a kill row the way the UI does: stamped with the attempt
// token of the execution the operator was looking at.
func requestKill(t *testing.T, o *Orchestrator, task *pm.Task, target string) {
	t.Helper()
	if err := o.statedb.RequestKill(statedb.KillRequest{
		TaskID:       task.ID,
		TargetStatus: target,
		RequestedBy:  "ui",
		Attempt:      state.AttemptToken(task),
	}); err != nil {
		t.Fatalf("RequestKill: %v", err)
	}
}

// drainWorker mimics what the orchestrator's worker does once its context is
// cancelled: it records the "canceled -> failed" terminal status.
func drainWorker(task *pm.Task) { task.Status = pm.TaskFailed }

func TestProcessPendingKills_Phase1FiresCancel(t *testing.T) {
	o := newTestOrchestrator(t)
	ctx, task := addInProgressTask(t, o, 11, "phase1")

	requestKill(t, o, task, "done")

	o.processPendingKills()

	// Phase 1: cancel must have fired.
	select {
	case <-ctx.Done():
		// good
	default:
		t.Fatal("ctx.Done() not closed; phase 1 did not fire the cancel")
	}

	// Phase 1 must NOT have cleared the row — phase 2 needs to see it.
	rows, _ := o.statedb.PendingKills()
	if len(rows) != 1 {
		t.Errorf("len(PendingKills) = %d after phase 1, want 1 (row preserved for phase 2)", len(rows))
	}

	// Phase 1 must NOT have changed the task status — only the cancel fires.
	if task.Status != pm.TaskInProgress {
		t.Errorf("task.Status changed during phase 1: got %q, want in_progress", task.Status)
	}
}

func TestProcessPendingKills_Phase2AppliesTargetStatus(t *testing.T) {
	o := newTestOrchestrator(t)
	_, task := addInProgressTask(t, o, 22, "phase2")

	requestKill(t, o, task, "done")

	// Phase 1: the poller sees the task running and fires its cancel.
	o.processPendingKills()

	// The worker exits and records the "canceled -> failed" terminal status.
	drainWorker(task)

	// Phase 2: the operator's choice overrides it.
	o.processPendingKills()

	// Phase 2: target status must have been applied.
	if task.Status != pm.TaskDone {
		t.Errorf("task.Status = %q after phase 2, want done (target_status override)", task.Status)
	}

	// Phase 2 must have cleared the row.
	rows, _ := o.statedb.PendingKills()
	if len(rows) != 0 {
		t.Errorf("len(PendingKills) = %d after phase 2, want 0 (row should be cleared)", len(rows))
	}
}

func TestProcessPendingKills_TargetStatusVariants(t *testing.T) {
	cases := []struct {
		target string
		want   pm.TaskStatus
	}{
		{"done", pm.TaskDone},
		{"skipped", pm.TaskSkipped},
		{"failed", pm.TaskFailed},
		{"pending", pm.TaskPending},
		// "in_progress" target maps to pending so the orchestrator picks it
		// back up on the next loop iteration; the worker's terminal status
		// must not be left in place because that would silently re-run the
		// task forever.
		{"in_progress", pm.TaskPending},
	}
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			o := newTestOrchestrator(t)
			_, task := addInProgressTask(t, o, 1, "t")
			requestKill(t, o, task, c.target)
			o.processPendingKills() // phase 1: fire the cancel
			drainWorker(task)       // worker's default after cancel
			o.processPendingKills() // phase 2: apply the target
			if task.Status != c.want {
				t.Errorf("target=%q -> task.Status=%q, want %q", c.target, task.Status, c.want)
			}
		})
	}
}

func TestProcessPendingKills_UnknownTaskClearsRow(t *testing.T) {
	o := newTestOrchestrator(t)
	if err := o.statedb.RequestKill(statedb.KillRequest{TaskID: 999, TargetStatus: "done"}); err != nil {
		t.Fatalf("RequestKill: %v", err)
	}
	o.processPendingKills()
	rows, _ := o.statedb.PendingKills()
	if len(rows) != 0 {
		t.Errorf("stale kill row for unknown task survived: %v", rows)
	}
}

func TestProcessPendingKills_NoOpsWhenNoRows(t *testing.T) {
	o := newTestOrchestrator(t)
	// Should not panic / error / mutate state when there are no pending kills.
	o.processPendingKills()
}

func TestProcessPendingKills_NilStatedb(t *testing.T) {
	o := &Orchestrator{}
	// Must not panic when statedb is unavailable (degraded operation).
	o.processPendingKills()
}
