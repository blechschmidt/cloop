package orchestrator

// verdict.go writes the orchestrator's decision about a task where stale-task
// recovery reads it first (Task 20365). pkg/taskrecover/verdict.go describes
// the sidecar and why it exists; this file is about when it is written.
//
// The agent's word is in the live artifact the moment it stops talking. The
// orchestrator's decision used to exist nowhere but memory until the outcome
// write, and a run that died — or, since Task 20362, stopped because that
// write failed — in between left recovery only the agent's word. So the
// decision is written down at each point it is reached, before anything the
// run could die in:
//
//   - When an attempt starts, the previous attempt's sidecar is removed, and a
//     gated execution records that its outcome waits on the review gate: a
//     TASK_DONE the reviewer never approved is not adopted, since the pushes it
//     made were held and died with the run.
//   - When the orchestrator overrides the agent — a clarification question,
//     background work left running, the review gate's verdict, a failed shell
//     verification — before it says so on the terminal, the first place a run
//     whose control plane has gone can die (SIGPIPE on a closed stdout).
//   - In persistOutcome, immediately before every outcome write: the final
//     decision, whatever made it.
//   - When the run stops under a task, or a budget sends it back to pending.
//
// A sidecar that cannot be written is reported and the run carries on: the
// outcome write that follows is the record, and the sidecar only matters if
// that write is lost too.

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
	"github.com/fatih/color"
)

// verdictWhy is who decided a task's outcome and why, as the verdict records
// it: a taskrecover source, a reason code, and a sentence for the operator.
type verdictWhy struct {
	source string
	reason string
	detail string
}

func decidedBy(source, reason, detail string) verdictWhy {
	return verdictWhy{source: source, reason: reason, detail: detail}
}

// agentWhy is the verdict for an outcome taken from the agent's own signal.
func agentWhy(status pm.TaskStatus) verdictWhy {
	switch status {
	case pm.TaskDone:
		return decidedBy(taskrecover.SourceAgent, "agent_done", "the agent reported the task done")
	case pm.TaskFailed:
		return decidedBy(taskrecover.SourceAgent, "agent_failed", "the agent reported the task failed")
	case pm.TaskSkipped:
		return decidedBy(taskrecover.SourceAgent, "agent_skipped", "the agent skipped the task")
	}
	return decidedBy(taskrecover.SourceAgent, "agent_"+string(status), "")
}

// clarificationWhy is the verdict for an agent that asked questions instead of
// working.
func clarificationWhy() verdictWhy {
	return decidedBy(taskrecover.SourceClarification, "clarification_unanswered",
		"the agent asked clarification questions instead of completing the task")
}

// backgroundWhy is the verdict for a task failed for work it left running.
func backgroundWhy(work *pm.BackgroundWork) verdictWhy {
	detail := "the agent left background work running, so its output describes work that had not finished"
	if work != nil {
		detail = fmt.Sprintf("the agent left %d background process(es) running after %ds, so its output "+
			"describes work that had not finished", work.Detected, work.WaitedSeconds)
	}
	return decidedBy(taskrecover.SourceBackground, "background_abandoned", detail)
}

// gateWhy is the verdict the review gate's outcome amounts to.
func gateWhy(out *gateOutcome) verdictWhy {
	reason := "review_approved"
	switch {
	case out == nil || out.review == nil:
	case out.review.Blocked && out.review.Verdict == pm.ReviewUnavailable:
		reason = "review_unavailable"
	case out.review.Blocked:
		reason = "review_blocked"
	case out.fail:
		reason = "publish_failed"
	}
	note := ""
	if out != nil {
		note = out.note
	}
	return decidedBy(taskrecover.SourceReviewGate, reason, note)
}

// abortWhy is the verdict for an execution that produced no finished work.
func abortWhy(ab Abort) verdictWhy {
	return decidedBy(taskrecover.SourceAbort, string(ab.Class), ab.Reason)
}

// noteVerdict records status as the orchestrator's decision about task's
// current execution. It reads the task — the caller holds whatever guards it —
// and never changes it.
func (o *Orchestrator) noteVerdict(task *pm.Task, status pm.TaskStatus, why verdictWhy) {
	if task == nil {
		return
	}
	v := taskrecover.Verdict{
		TaskID:    task.ID,
		Status:    status,
		Reason:    why.reason,
		Source:    why.source,
		Detail:    why.detail,
		Summary:   task.Result,
		StartedAt: copyTime(task.StartedAt),
	}
	if status == pm.TaskFailed || status == pm.TaskTimedOut {
		v.Diagnosis = task.FailureDiagnosis
	}
	if task.Review != nil {
		v.Review = task.Review.Clone()
	}
	if task.Background != nil && !task.Background.Pending() {
		bg := *task.Background
		v.Background = &bg
	}
	o.writeVerdict(v)
}

// writeVerdictFile is the seam every verdict write goes through, so a test can
// make one fail the way a full disk does (Task 20381) without filling one.
var writeVerdictFile = taskrecover.WriteVerdict

// writeVerdict writes v, reporting a failure instead of returning it. A
// parallel worker, which must not read the shared task, builds v itself.
//
// A write the disk refuses for want of space is tried once more on the space
// the free-space reserve frees (writeOnReserve, Task 20381). That is what keeps
// recovery from falling back to the agent's word on a full disk: the verdict
// is the record recovery reads when the outcome write fails in the same moment.
func (o *Orchestrator) writeVerdict(v taskrecover.Verdict) {
	if o == nil || o.config.WorkDir == "" {
		return
	}
	err := o.writeOnReserve(fmt.Sprintf("task #%d's verdict", v.TaskID), func() error {
		return writeVerdictFile(o.config.WorkDir, v)
	})
	if err != nil {
		o.reportVerdictFailure(v.TaskID, fmt.Sprintf("record its verdict (%s)", v.Status), err)
	}
}

// clearVerdict removes a task's sidecar when an attempt starts, so no decision
// about an earlier attempt can be read as this one's. A removal that fails is
// reported; the freshness rule recovery applies makes the leftover harmless.
func (o *Orchestrator) clearVerdict(taskID int) {
	if o == nil || o.config.WorkDir == "" {
		return
	}
	if err := taskrecover.ClearVerdict(o.config.WorkDir, taskID); err != nil {
		o.reportVerdictFailure(taskID, "clear the previous attempt's verdict", err)
	}
}

// awaitReview records that task's outcome waits on the review gate.
func (o *Orchestrator) awaitReview(task *pm.Task) {
	o.noteVerdict(task, pm.TaskInProgress, decidedBy(taskrecover.SourceReviewGate, taskrecover.ReasonReviewPending,
		"the outcome waits on the review gate, and the agent's pushes are held until it approves"))
}

// noteDecision records the decision reached once the agent's own result has
// been judged — after the clarification and background checks, before the
// review gate and before anything is announced. A result the review gate is
// about to judge waits on it; an unsignalled result is not decided yet, which
// the default arm of the outcome switch does; anything else is the decision.
func (o *Orchestrator) noteDecision(task *pm.Task, signal pm.TaskStatus, why verdictWhy, reviewNext bool) {
	switch {
	case reviewNext && (signal == pm.TaskDone || signal == pm.TaskInProgress):
		o.awaitReview(task)
	case signal == pm.TaskInProgress:
		o.clearVerdict(task.ID)
	default:
		o.noteVerdict(task, signal, why)
	}
}

// earlyVerdict is the decision a result forces before anything else judges it:
// a clarification question, or background work still running. ok is false for
// a result that has neither, whose outcome is decided later — and for a
// clarification question when clarifyRetries says the agent is about to be
// re-prompted, since its answer decides. It reads nothing shared, so a
// parallel worker can call it.
func earlyVerdict(output string, bg *provider.BackgroundActivity, clarifyRetries bool) (status pm.TaskStatus, why verdictWhy, work *pm.BackgroundWork, ok bool) {
	signal := pm.CheckTaskSignal(output)
	if signal == pm.TaskInProgress && looksLikeClarificationQuestion(output) {
		if clarifyRetries {
			return "", verdictWhy{}, nil, false
		}
		return pm.TaskFailed, clarificationWhy(), resolveBackground(bg), true
	}
	if bg.Incomplete() && signal != pm.TaskFailed && signal != pm.TaskSkipped {
		work = resolveBackground(bg)
		return pm.TaskFailed, backgroundWhy(work), work, true
	}
	return "", verdictWhy{}, nil, false
}

// noteEarlyVerdict records earlyVerdict's decision for a task whose result has
// just arrived, before the first line about it is printed. It takes the task's
// ID and start rather than the task, because a parallel worker may not read
// the shared task.
func (o *Orchestrator) noteEarlyVerdict(taskID int, startedAt *time.Time, output string, bg *provider.BackgroundActivity, clarifyRetries bool) {
	status, why, work, ok := earlyVerdict(output, bg, clarifyRetries)
	if !ok {
		return
	}
	v := taskrecover.Verdict{
		TaskID:    taskID,
		Status:    status,
		Reason:    why.reason,
		Source:    why.source,
		Detail:    why.detail,
		Summary:   truncate(output, 500),
		StartedAt: copyTime(startedAt),
	}
	if work != nil {
		v.Background = work
		if work.State == pm.BackgroundAbandoned {
			v.Diagnosis = backgroundFailureDiagnosis(work)
		}
	}
	o.writeVerdict(v)
}

// gateVerdict is the decision a finished review gate leaves a parallel task
// with, mirroring what the consumer applies, in its order: the gate's failure,
// a fix turn that asked questions instead of working, background work a fix
// turn left running, an approved completion, or the agent's own failure or
// skip from a fix turn. ok is false for an approved result without a signal,
// which the consumer's default arm decides.
func gateVerdict(out *gateOutcome, output string, bg *provider.BackgroundActivity) (pm.TaskStatus, verdictWhy, *pm.BackgroundWork, bool) {
	signal := pm.CheckTaskSignal(output)
	switch {
	case out != nil && out.fail && signal != pm.TaskSkipped:
		return pm.TaskFailed, gateWhy(out), nil, true
	case signal == pm.TaskInProgress && looksLikeClarificationQuestion(output):
		return pm.TaskFailed, clarificationWhy(), resolveBackground(bg), true
	case bg.Incomplete() && signal != pm.TaskFailed && signal != pm.TaskSkipped:
		work := resolveBackground(bg)
		return pm.TaskFailed, backgroundWhy(work), work, true
	case signal == pm.TaskDone:
		return pm.TaskDone, gateWhy(out), nil, true
	case signal == pm.TaskFailed || signal == pm.TaskSkipped:
		return signal, agentWhy(signal), nil, true
	}
	return "", verdictWhy{}, nil, false
}

// noteGateVerdict records a parallel worker's review outcome before the
// worker hands the result back. See gateVerdict.
func (o *Orchestrator) noteGateVerdict(taskID int, startedAt *time.Time, out *gateOutcome, output string, bg *provider.BackgroundActivity) {
	status, why, work, ok := gateVerdict(out, output, bg)
	if !ok {
		o.clearVerdict(taskID)
		return
	}
	v := taskrecover.Verdict{
		TaskID:     taskID,
		Status:     status,
		Reason:     why.reason,
		Source:     why.source,
		Detail:     why.detail,
		Summary:    truncate(output, 500),
		Background: work,
		StartedAt:  copyTime(startedAt),
	}
	if out != nil && out.review != nil {
		v.Review = out.review.Clone()
		if status == pm.TaskFailed && why.source == taskrecover.SourceReviewGate {
			v.Diagnosis = out.review.Diagnosis()
			if !out.review.Blocked {
				v.Diagnosis = out.note
			}
		}
	}
	if work != nil && work.State == pm.BackgroundAbandoned {
		v.Diagnosis = backgroundFailureDiagnosis(work)
	}
	o.writeVerdict(v)
}

// reportVerdictFailure says that a verdict could not be written or cleared.
// It is not returned: the outcome write is the record, and it still follows.
func (o *Orchestrator) reportVerdictFailure(taskID int, what string, err error) {
	msg := fmt.Sprintf("could not %s for task #%d: %v — carrying on; if the run also fails to store "+
		"the task's outcome, recovery falls back to the agent's own report", what, taskID, err)
	if o.log != nil {
		o.log.Warn(logger.EventStateWrite, taskID, "task verdict not recorded",
			map[string]interface{}{"what": what, "error": err.Error()})
	}
	color.New(color.FgYellow).Fprintf(os.Stderr, "⚠ %s\n", msg)
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// scriptVerifyWhy is the verdict for a task --script-verify failed.
func scriptVerifyWhy() verdictWhy {
	return decidedBy(taskrecover.SourceScriptVerify, "script_verify_failed",
		"the shell verification script exited non-zero")
}

// implicitDoneWhy is the verdict for an unsignalled task promoted to done.
func implicitDoneWhy() verdictWhy {
	return decidedBy(taskrecover.SourceOrchestrator, "implicit_done",
		"the agent finished without a signal, and the task left evidence of its work")
}

// budgetWhy is the verdict for a finished task sent back to pending because a
// budget ran out.
func budgetWhy(reason, detail string) verdictWhy {
	return decidedBy(taskrecover.SourceBudget, reason, detail+", so the task goes back to pending")
}
