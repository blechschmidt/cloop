// Regression tests for Task 20203: a kill request must not outlive the
// execution it was filed against.
//
// The reported symptom was that previously-failed tasks, once reset, were
// sometimes skipped or killed the instant a project was rerun. liebid task #42
// showed the shape of it in its event log:
//
//	19:09:26  task_status_change  in_progress -> pending (via UI)
//	19:10:31  task_started
//	19:10:32  "claude CLI cancelled: context canceled"
//
// One second is killPollInterval. Resetting a task stuck in_progress by a dead
// run is, on disk, a transition out of in_progress, so it files a kill row; no
// orchestrator was alive to consume it; the next run's first poll tick applied
// it to a brand-new attempt.
//
// Each test below is one way that row can reach a run it was never meant for.
package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestStaleKill_DoesNotCancelFreshAttempt is the liebid #42 reproduction. A row
// filed against the attempt that was stuck must not cancel the attempt started
// by the rerun.
func TestStaleKill_DoesNotCancelFreshAttempt(t *testing.T) {
	o := newTestOrchestrator(t)

	// The stuck attempt, and the operator resetting it to pending.
	stuckAt := time.Now().Add(-9 * time.Hour)
	task := &pm.Task{ID: 42, Title: "stuck", Status: pm.TaskInProgress, StartedAt: &stuckAt}
	o.state.Plan.Tasks = append(o.state.Plan.Tasks, task)
	requestKill(t, o, task, "pending") // what the UI files on in_progress -> pending
	task.Status = pm.TaskPending

	// The rerun picks the task up: a new attempt, with a new StartedAt.
	freshAt := time.Now()
	task.Status = pm.TaskInProgress
	task.StartedAt = &freshAt
	if err := o.state.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.watchdog.Register(task.ID, cancel)

	o.processPendingKills()

	select {
	case <-ctx.Done():
		t.Fatal("stale kill request cancelled a freshly-started attempt: " +
			"the reset task would die ~1s after starting (liebid #42)")
	default:
	}
	if task.Status != pm.TaskInProgress {
		t.Errorf("task.Status = %q; want in_progress (fresh attempt left alone)", task.Status)
	}
	if rows, _ := o.statedb.PendingKills(); len(rows) != 0 {
		t.Errorf("stale row survived: %+v; it would fire again on the next tick", rows)
	}
}

// TestStaleKill_DoesNotReapplyTargetToResetTask covers the literal wording of
// the bug: a reset task landing straight back in the terminal status the
// operator had just cleared.
//
// Resetting a task does not advance StartedAt, so the leftover row still names
// a matching attempt. What disqualifies it is that this process never watched
// that attempt run, so there is no cancelled worker whose status it may
// correct.
func TestStaleKill_DoesNotReapplyTargetToResetTask(t *testing.T) {
	for _, target := range []string{"skipped", "failed", "done"} {
		t.Run(target, func(t *testing.T) {
			o := newTestOrchestrator(t)

			startedAt := time.Now().Add(-2 * time.Hour)
			task := &pm.Task{ID: 7, Title: "aborted then reset", Status: pm.TaskInProgress, StartedAt: &startedAt}
			o.state.Plan.Tasks = append(o.state.Plan.Tasks, task)
			requestKill(t, o, task, target)

			// The run ends before the poller's phase 2, leaving the row behind.
			// The operator then resets the task and starts a new run.
			task.Status = pm.TaskPending
			if err := o.state.Save(); err != nil {
				t.Fatalf("state.Save: %v", err)
			}

			o.processPendingKills()

			if task.Status != pm.TaskPending {
				t.Errorf("reset task was forced to %q by a leftover kill row; want pending", task.Status)
			}
			if rows, _ := o.statedb.PendingKills(); len(rows) != 0 {
				t.Errorf("stale row survived: %+v", rows)
			}
		})
	}
}

// TestStaleKill_LegacyRowWithoutAttemptIsDiscarded covers rows written before
// the attempt column existed. They name no execution, so they are dropped
// rather than guessed at — losing an abort costs a click, honouring a stale one
// kills a run.
func TestStaleKill_LegacyRowWithoutAttemptIsDiscarded(t *testing.T) {
	o := newTestOrchestrator(t)
	ctx, _ := addInProgressTask(t, o, 3, "legacy")

	if err := o.statedb.RequestKill(statedb.KillRequest{
		TaskID: 3, TargetStatus: "skipped", RequestedBy: "ui", // no Attempt
	}); err != nil {
		t.Fatalf("RequestKill: %v", err)
	}

	o.processPendingKills()

	select {
	case <-ctx.Done():
		t.Fatal("legacy attempt-less row fired a cancel; it names no execution")
	default:
	}
	if rows, _ := o.statedb.PendingKills(); len(rows) != 0 {
		t.Errorf("legacy row survived: %+v", rows)
	}
}

// TestStaleKill_SurvivesTaskCompletingBeforeCancel guards the ordering where a
// task finishes normally just as the operator aborts it. The row then names a
// finished attempt, and the next task to reuse that ID must not inherit it.
func TestStaleKill_SurvivesTaskCompletingBeforeCancel(t *testing.T) {
	o := newTestOrchestrator(t)

	startedAt := time.Now().Add(-time.Minute)
	task := &pm.Task{ID: 5, Title: "raced", Status: pm.TaskInProgress, StartedAt: &startedAt}
	o.state.Plan.Tasks = append(o.state.Plan.Tasks, task)
	requestKill(t, o, task, "skipped")

	// The worker completed on its own before the poller ever saw it running.
	task.Status = pm.TaskDone
	if err := o.state.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	o.processPendingKills()

	if task.Status != pm.TaskDone {
		t.Errorf("task.Status = %q; want done — a task that finished on its own "+
			"must not be rewritten by a request the poller never acted on", task.Status)
	}
	if rows, _ := o.statedb.PendingKills(); len(rows) != 0 {
		t.Errorf("row survived: %+v", rows)
	}
}

// TestAttemptMatches pins the token comparison, including the formatting drift
// the poller tolerates (same instant, different rendering).
func TestAttemptMatches(t *testing.T) {
	at := time.Date(2026, 8, 29, 19, 10, 31, 123456789, time.UTC)
	task := &pm.Task{ID: 1, StartedAt: &at}
	other := at.Add(time.Second)

	cases := []struct {
		name    string
		attempt string
		task    *pm.Task
		want    bool
	}{
		{"exact token", state.AttemptToken(task), task, true},
		{"same instant, offset rendering", at.In(time.FixedZone("x", 3600)).Format(time.RFC3339Nano), task, true},
		{"different attempt", other.Format(time.RFC3339Nano), task, false},
		{"empty attempt", "", task, false},
		{"unparseable attempt", "not-a-timestamp", task, false},
		{"task never started", state.AttemptToken(task), &pm.Task{ID: 1}, false},
		{"nil task", state.AttemptToken(task), nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := attemptMatches(c.attempt, c.task); got != c.want {
				t.Errorf("attemptMatches(%q, %+v) = %v; want %v", c.attempt, c.task, got, c.want)
			}
		})
	}
}
