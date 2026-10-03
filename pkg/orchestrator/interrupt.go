package orchestrator

import (
	"context"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
)

// A task cut short by its run stopping is not a failed task (Task 20348).
//
// Pressing Stop sends the run SIGINT, cmd/run cancels the run's context, and
// every provider call in flight returns ctx.Err(). Both loops used to file that
// error like any other provider error. The sequential loop marked the task
// failed. The parallel loop left it in_progress, or marked it failed if it read
// the worker's result before it noticed the cancellation. A --timeout expiring
// mid-task marked it timed_out. Failed and timed_out are terminal: the next
// run never picks such a task up, because ReadyTasks takes only pending ones.
// The tasks that depend on it are then skipped as permanently blocked. Stopping
// a project in order to resume it later quietly cancelled the rest of that
// branch of the plan, and the resumed run could declare the plan complete
// without having done it.
//
// An interruption says nothing about the task, so it gets no verdict. Whatever
// the task was doing when the run ended — the agent's first attempt, a heal
// retry, the re-prompt after clarification questions — is abandoned, and the
// task goes back to pending, where the next run starts it again. What had
// already finished keeps its outcome: a result that came back before the stop
// is recorded as usual. Re-running work that is already done is not a neutral
// retry.

// interruptedQueueNote is the activity queue's terminal note for an execution
// that the run's end cut short.
const interruptedQueueNote = "interrupted: the run stopped — task returned to pending"

// runInterrupted reports whether the run as a whole is ending: its context was
// cancelled (Stop, SIGINT or SIGTERM, a budget stop from the hub) or its
// session deadline (--timeout) passed.
//
// ctx must be the run's context, not a task's. A task context is also
// cancelled by the task's own time budget and by a manual abort from the
// dashboard. Those are statements about the task — a timeout, an operator's
// chosen status — and keep their own handling.
func runInterrupted(ctx context.Context) bool {
	return ctx != nil && ctx.Err() != nil
}

// requeueInterrupted returns a task whose execution was cut short by the run
// ending to pending, and records why.
//
// stage completes the sentence "Interrupted ..." and names what the task was
// doing, so an operator reading the task's notes can tell an interrupted first
// attempt from an interrupted retry.
//
// StartedAt is kept: it identifies the attempt that ended, and the terminal
// audit row written when this status is saved reads it. CompletedAt and
// ActualMinutes are cleared, as abortTask clears them, because an execution
// that did not finish has neither, and a pending task that carried them would
// render as a finished one. A background wait is dropped for the same reason:
// the wait ended with the run, and a pending task shown as "still waiting for
// background work" would be describing a wait that no longer exists.
//
// The return to pending is written before it is journalled. The write is
// best-effort: the run is ending, the pause it records next stores the task
// too and ends the run if it cannot, and should neither land, stale-task
// recovery returns the task to pending at the next start — the same status
// this records. The caller must hold whatever lock guards task mutation (the
// parallel loop holds mu).
func (o *Orchestrator) requeueInterrupted(s *state.ProjectState, task *pm.Task, stage string, step int) {
	task.Status = pm.TaskPending
	task.CompletedAt = nil
	task.ActualMinutes = 0
	if task.Background.Pending() {
		task.Background = nil
	}

	pm.AddAnnotation(task, "cloop", fmt.Sprintf(
		"Interrupted %s: the run stopped before the task finished. "+
			"Returned to pending, so the next run starts it again.", stage))
	o.persistBestEffort(s, fmt.Sprintf("task #%d's return to pending after the run stopped", task.ID),
		"the pause the stopping run records next stores it too, and stale-task recovery reaches the same status if neither lands")

	details := map[string]any{
		"stage":         stage,
		"run_id":        task.RunID,
		"executor_id":   task.ExecutorID,
		"executor_kind": task.ExecutorKind,
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventTaskInterrupted,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      step,
		Message: fmt.Sprintf("Task #%d interrupted %s — returned to pending for the next run",
			task.ID, stage),
	}, details)

	if !o.log.IsJSON() {
		color.New(color.FgYellow).Printf(
			"⏸ Task %d interrupted %s — returned to pending; the next run picks it up.\n", task.ID, stage)
	}
	o.log.Warn(logger.EventTaskInterrupted, task.ID, task.Title, details)
}
