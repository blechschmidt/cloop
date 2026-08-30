package orchestrator

// background.go decides what a task's outcome means when its agent left work
// running behind it.
//
// The failure this addresses (Task 20205) is that an agent can start a long
// job — a build, a test suite, a training run — in the background, exit, and
// print TASK_DONE. The task is then marked complete and the next one starts
// against an artifact that is still being written. In the incident that
// prompted this, three consecutive tasks were meant to operate on a model
// trained by the task before them, and all three ran before it existed.
//
// pkg/provider/claudecode detects the surviving process group and waits for it,
// so by the time a result arrives here the work has either finished or
// outlived its budget. What is left is the judgement call, and it is the one
// the task statement makes explicitly: work still running usually means the
// task is not finished. So a task whose background work never drained is not
// accepted as done, no matter what its own output claimed — which both stops
// dependents from consuming a half-written artifact and puts the reason
// somewhere an operator will find it.

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// backgroundNotice is the annotation prefix for every message this file
// writes. Shared so the UI and tests can recognise them.
const backgroundNotice = "Background work: "

// noteBackgroundWait records that cloop has started waiting on work an agent
// left running, and returns the task-level record for it.
//
// It runs while the task is still executing — the provider calls back into it
// mid-completion — so it exists to make a long wait visible as it happens
// rather than only in hindsight.
func noteBackgroundWait(activity provider.BackgroundActivity) *pm.BackgroundWork {
	return &pm.BackgroundWork{
		State:      pm.BackgroundWaiting,
		Detected:   activity.Detected,
		Commands:   activity.Commands,
		DetectedAt: time.Now(),
	}
}

// resolveBackground converts a finished provider result into the persisted
// task record, or nil when the agent left nothing behind.
func resolveBackground(activity *provider.BackgroundActivity) *pm.BackgroundWork {
	if activity == nil || activity.Detected == 0 {
		return nil
	}
	work := &pm.BackgroundWork{
		State:         pm.BackgroundDrained,
		Detected:      activity.Detected,
		Commands:      activity.Commands,
		WaitedSeconds: int(activity.Waited.Round(time.Second).Seconds()),
		Terminated:    activity.Terminated,
		DetectedAt:    time.Now().Add(-activity.Waited),
	}
	if !activity.Drained {
		work.State = pm.BackgroundAbandoned
	}
	return work
}

// applyBackgroundOutcome records background activity on the task and reports
// the signal the task should actually be judged by.
//
// A task whose work drained keeps its own signal: it waited, the work
// finished, and the result is trustworthy. A task whose work did not drain is
// forced to TaskFailed regardless of what it printed, because its output
// describes work that had not happened yet.
//
// Forcing the existing failure signal rather than inventing a new status is
// deliberate. Plan.DepsReady already treats anything other than done or
// skipped as unmet, so dependents are blocked by the same code path that
// blocks them for every other kind of failure; the heal machinery already
// knows how to re-attempt a failed task, and the retry is exactly the right
// remedy here. A new status would have to be taught to each of those
// independently, and any one of them missed would silently let a dependent run
// against the artifact this exists to protect.
func applyBackgroundOutcome(task *pm.Task, activity *provider.BackgroundActivity, signal pm.TaskStatus) pm.TaskStatus {
	work := resolveBackground(activity)
	if work == nil {
		// Clear any "waiting" record from this attempt: the work finished
		// inside the grace window and was never real background activity.
		if task.Background.Pending() {
			task.Background = nil
		}
		return signal
	}
	task.Background = work

	if work.State == pm.BackgroundDrained {
		pm.AddAnnotation(task, "cloop", backgroundNotice+activity.Summary()+".")
		return signal
	}

	// A task that already failed or was skipped keeps that outcome; there is
	// nothing to downgrade, and overwriting the reason would hide it.
	pm.AddAnnotation(task, "cloop", backgroundNotice+activity.Summary()+
		". The task is not complete: its output describes work that was still running.")
	if signal == pm.TaskFailed || signal == pm.TaskSkipped {
		return signal
	}
	return pm.TaskFailed
}

// backgroundFailureDiagnosis is the operator-facing explanation attached to a
// task rejected for leaving work running. It doubles as the guidance the heal
// retry feeds back to the agent, which is why it names the remedy rather than
// only the symptom.
func backgroundFailureDiagnosis(work *pm.BackgroundWork) string {
	if work == nil {
		return ""
	}
	names := ""
	if len(work.Commands) > 0 {
		names = fmt.Sprintf(" (%v)", work.Commands)
	}
	killed := ""
	if work.Terminated > 0 {
		killed = fmt.Sprintf(" cloop terminated %d of them so a retry cannot race the leftovers.", work.Terminated)
	}
	return fmt.Sprintf(
		"The previous attempt signalled completion while %d background process(es)%s it had started were still running after %ds.%s "+
			"Do not report this task complete while work you started is still running: wait for it to finish and check its result, "+
			"or end with TASK_FAILED naming what is still running.",
		work.Detected, names, work.WaitedSeconds, killed)
}

// logBackgroundEvent writes the background activity to the project's event
// journal, where the UI reads it.
func (o *Orchestrator) logBackgroundEvent(s *state.ProjectState, task *pm.Task, work *pm.BackgroundWork) {
	if work == nil {
		return
	}
	var msg string
	switch work.State {
	case pm.BackgroundWaiting:
		msg = fmt.Sprintf("Task #%d is waiting for %d background process(es) it started", task.ID, work.Detected)
	case pm.BackgroundDrained:
		msg = fmt.Sprintf("Task #%d waited %ds for %d background process(es) to finish",
			task.ID, work.WaitedSeconds, work.Detected)
	case pm.BackgroundAbandoned:
		msg = fmt.Sprintf("Task #%d left %d background process(es) still running after %ds — not complete",
			task.ID, work.Detected, work.WaitedSeconds)
	}
	step := 0
	if s != nil {
		step = s.CurrentStep
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventTaskBackground,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      step,
		Message:   msg,
	}, map[string]any{
		"state":          string(work.State),
		"detected":       work.Detected,
		"commands":       work.Commands,
		"waited_seconds": work.WaitedSeconds,
		"terminated":     work.Terminated,
	})
}
