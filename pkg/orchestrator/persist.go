// Persistence policy for the orchestrator's state writes (Task 20362, which
// re-lands Task 20295 on the orchestrator as it now is).
//
// state.ProjectState.Save returns an error, and for most of this package's
// history that error was dropped at nearly every call site: a bare `s.Save()`
// statement, which go vet does not flag. A run could then announce an outcome
// it never recorded. At a pause the loop printed the reason, set Paused in
// memory and returned nil while a failed write — a full disk, SQLITE_BUSY past
// busy_timeout, a read-only mount, a schema the binary refuses, a damaged row
// the merge will not save over — left the row saying "running". A task marked
// done, failed or skipped in memory came back pending at the next start and
// ran a second time: the duplicate-execution class of Tasks 20203, 20209,
// 20211 and 20285.
//
// The fix is not "check every error". Many of these writes are genuinely
// best-effort, and ending a run because a priority boost did not land would
// be worse than the bug. It is to make the intent of every write explicit:
//
//	persist            the run is about to report or return on this state: a
//	                   pause, a session status, a plan change. A failure comes
//	                   back as an error wrapping ErrStateNotPersisted, and the
//	                   run ends with it.
//	persistOutcome     the same, for a task's status. The error names the task
//	                   and the status that did not reach the database. It
//	                   writes the orchestrator's verdict first (verdict.go), so
//	                   a run that stops here is recovered as it decided, not
//	                   as the agent said (Task 20365).
//	persistBestEffort  the state may be dropped. The call site says why that is
//	                   true, and a failure is reported, never swallowed.
//
// Order matters as much as the check. An outcome is stored before anything
// announces it — the journal row, the webhook, the activity queue, the line on
// the terminal — so a write that fails leaves nothing claiming a status the
// database does not hold.
//
// TestNoBareSaveCallsInOrchestrator keeps it that way. It walks this package's
// syntax trees and rejects a Save whose error is thrown away, and an activity
// queue write whose error is, because both read exactly like the hundred-odd
// that were wrong.
//
// Why a failed critical write ends the run instead of retrying: by the time
// Save returns an error, busy_timeout has already absorbed ordinary
// contention. What is left — a full disk, a read-only mount, a refused schema,
// a row too damaged to merge — will not let the next write through either, and
// every task a run executes after it can no longer record outcomes is work
// nobody can account for.
package orchestrator

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/webhook"
	"github.com/fatih/color"
)

// ErrStateNotPersisted is carried by every error that ends a run because the
// project database refused a write the run could not do without. Test for it
// with errors.Is: it separates "the run failed at its work" from "the run
// could not record what it did", and only the second can leave the database
// disagreeing with what the operator was told.
var ErrStateNotPersisted = errors.New("orchestrator: project state not persisted")

// saveMode is how a write reaches the database.
type saveMode int

const (
	// mergeExternal writes through state.ProjectState.Save, which first folds
	// in tasks another process added since the run loaded its plan. Every
	// write is this unless it says otherwise.
	mergeExternal saveMode = iota
	// replacePlan writes through SaveDirect: the state in memory is meant to
	// replace what is stored — a split or a replan removed tasks, or a setting
	// must win over the stored one — and a merging write would read the
	// removed tasks back from disk as externally added, or copy the stored
	// setting over the new one.
	replacePlan
	// statusOnly writes the run's status and pause reason and nothing else.
	// Only the abort record uses it: when a full write has just failed, the
	// narrowest write is the one most likely to land.
	statusOnly
)

// saveState is the single seam through which every orchestrator state write
// goes. It is a variable so tests can inject a store that fails for exactly
// the write under examination; they must restore it.
var saveState = func(s *state.ProjectState, mode saveMode) error {
	switch mode {
	case replacePlan:
		return s.SaveDirect()
	case statusOnly:
		return s.SaveRunStatus()
	default:
		return s.Save()
	}
}

// modeOf resolves the optional mode argument of persist and persistBestEffort.
func modeOf(mode []saveMode) saveMode {
	if len(mode) > 0 {
		return mode[0]
	}
	return mergeExternal
}

// persistFailure is a state write that did not land, described by what the
// run was about to claim rather than by what SQLite said.
type persistFailure struct {
	// what names the state that was lost, in the operator's words: "the pause
	// (token budget reached)"; for a task, what of it — "completion", "skip
	// at the approval gate" — which reads after "task #N's". Required at every
	// call site, because it is what makes the message actionable.
	what string
	// taskID, taskTitle and status identify the task whose status was lost;
	// zero for a write that was not about one task.
	taskID    int
	taskTitle string
	status    pm.TaskStatus
	// why is the reason a best-effort write may be dropped; set only on those.
	why string
	err error
}

func (p *persistFailure) tolerated() bool { return p.why != "" }

// lost names the lost state, with the task when there is one.
func (p *persistFailure) lost() string {
	if p.taskID > 0 {
		return fmt.Sprintf("task #%d's %s (status %s)", p.taskID, p.what, p.status)
	}
	return p.what
}

func (p *persistFailure) Error() string {
	if p.tolerated() {
		return fmt.Sprintf("could not save %s: %v — carrying on, because %s; a repeat means the database is refusing writes",
			p.lost(), p.err, p.why)
	}
	return fmt.Sprintf("could not save %s: %v — stopping the run rather than reporting what the database does not hold",
		p.lost(), p.err)
}

func (p *persistFailure) Unwrap() []error {
	if p.tolerated() {
		return []error{p.err}
	}
	return []error{p.err, ErrStateNotPersisted}
}

// reasonDetail is the one-line account a paused run carries: short enough for
// a status badge, specific enough to act on.
func (p *persistFailure) reasonDetail() string {
	cause := strings.TrimSpace(p.err.Error())
	if r := []rune(cause); len(r) > 200 {
		cause = string(r[:200]) + "…"
	}
	return fmt.Sprintf("could not save %s: %s", p.lost(), cause)
}

// persist writes state the run is about to report or return on: a pause, a
// session status, a plan change. The returned error must be propagated — the
// run ends with it. Returning nil from a path that announced a pause while
// this failed is the defect it exists to prevent: the operator is told the run
// paused while the row still says running, and the next start acts on that.
func (o *Orchestrator) persist(s *state.ProjectState, what string, mode ...saveMode) error {
	if err := saveState(s, modeOf(mode)); err != nil {
		pf := &persistFailure{what: what, err: err}
		o.reportPersistFailure(pf)
		return pf
	}
	return nil
}

// persistOutcome writes a task's status, before anything announces it. It is
// persist with the task named, so a failure says which task's outcome was lost
// and what it was — without that the operator sees a SQLite error and no way
// to know which task will run again. The returned error must be propagated.
//
// why says who decided the status and why. It goes into the task's verdict
// sidecar, written before the save: if the save fails and the run stops, or
// the process dies between the two, the next run's stale-task recovery applies
// this decision rather than adopting whatever the agent's transcript says.
func (o *Orchestrator) persistOutcome(s *state.ProjectState, task *pm.Task, what string, why verdictWhy) error {
	if task != nil {
		o.noteVerdict(task, task.Status, why)
	}
	return o.saveOutcome(s, task, what)
}

// saveOutcome is persistOutcome without the verdict, for a write that stores
// more of a task whose outcome persistOutcome has already stored — the step
// record after it — and so decides nothing recovery could need.
//
// Like the verdict, a write refused for want of space is tried once more on
// the space the free-space reserve frees, and the run pauses disk_low before
// it starts anything else (Task 20381). Only a retry that fails as well stops
// the run here.
func (o *Orchestrator) saveOutcome(s *state.ProjectState, task *pm.Task, what string) error {
	writeName := what
	if task != nil {
		writeName = fmt.Sprintf("task #%d's %s", task.ID, what)
	}
	if err := o.writeOnReserve(writeName, func() error { return saveState(s, mergeExternal) }); err != nil {
		pf := &persistFailure{what: what, err: err}
		if task != nil {
			pf.taskID, pf.taskTitle, pf.status = task.ID, task.Title, task.Status
		}
		o.reportPersistFailure(pf)
		return pf
	}
	return nil
}

// persistBestEffort writes state the run can genuinely do without, and says
// why. A write qualifies only if what it carries is recomputed (a priority
// boost, a recurrence reset), is carried by a critical write that follows (an
// annotation the task's outcome write stores anyway), or is narrative rather
// than control flow — and only if nothing reports an outcome on the strength
// of it. Anything the operator is told about, or that decides whether a task
// runs again, belongs in persist or persistOutcome.
//
// A failure is still reported. Best effort means the run carries on, not that
// nobody hears about it: a database that has started refusing writes shows up
// here first, before a critical write has to stop the run.
func (o *Orchestrator) persistBestEffort(s *state.ProjectState, what, why string, mode ...saveMode) {
	if err := saveState(s, modeOf(mode)); err != nil {
		o.reportPersistFailure(&persistFailure{what: what, why: why, err: err})
	}
}

// reportPersistFailure puts a failed write where an operator will see it.
// Every failure goes to the structured log. A tolerated one is also printed,
// since nothing else will say it; one that stops the run is not, because it is
// returned, and the command that ran the loop prints it — once (Task 20294).
// The event journal is not tried: it lives in the database that just refused
// a write, so the attempt would fail the same way and bury the real message
// under a second error. recordAbort tries it once, at the end of a run that
// stops.
func (o *Orchestrator) reportPersistFailure(pf *persistFailure) {
	if o.log != nil {
		fields := map[string]interface{}{"what": pf.what, "error": pf.err.Error(), "stops_run": !pf.tolerated()}
		if pf.taskID > 0 {
			fields["task_status"] = string(pf.status)
		}
		if pf.tolerated() {
			o.log.Warn(logger.EventStateWrite, pf.taskID, "project state not persisted", fields)
		} else {
			o.log.Error(logger.EventStateWrite, pf.taskID, "project state not persisted", fields)
		}
	}
	if pf.tolerated() {
		color.New(color.FgYellow).Fprintf(os.Stderr, "⚠ %s\n", pf.Error())
	}
}

// recordAbort leaves the end of a run on the record when the run stopped
// because it could not save its own progress. The database that just refused a
// write may refuse these too, so the account goes to three places, most
// durable first:
//
//   - The run status: paused, with a state_not_persisted reason naming what was
//     lost. A status-only write, so it can land where the full save could not:
//     a damaged task row stops the merge a full save starts with, and a lock
//     another process held may since have cleared. This is what the
//     dashboard's badge, the project card and `cloop status` show.
//   - The event journal: a session_failed row with the same account, for the
//     dashboard's Event History, and the session_failed webhook.
//   - The terminal, where the run's error says it as well; and the exit
//     status, pausereason.ExitStateNotPersisted, which the hub reads when
//     nothing else could be written.
//
// The plan is not written again. Rewriting it here would retry the very write
// that failed, and if that now succeeded the stopped run's account would be
// wrong the other way. What the run did not store stays unstored, and the next
// run's stale-task recovery settles every task this one left in progress.
//
// The pollers must have stopped: they write state too.
func (o *Orchestrator) recordAbort(cause error) {
	var pf *persistFailure
	if !errors.As(cause, &pf) || o.state == nil {
		return
	}
	s := o.state
	detail := pf.reasonDetail()
	s.SetPaused(pausereason.New(pausereason.CodeStateNotPersisted, detail))
	// A disk too full for the write that failed may be too full for this one:
	// whatever the free-space reserve still holds is spent on it (Task 20381).
	statusErr := o.writeOnReserve("the run's stop record", func() error { return saveState(s, statusOnly) })

	details := map[string]any{
		"cause":           string(pausereason.CodeStateNotPersisted),
		"lost":            pf.what,
		"error":           pf.err.Error(),
		"status_recorded": statusErr == nil,
	}
	if pf.taskID > 0 {
		details["task_status"] = string(pf.status)
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventSessionFailed,
		TaskID:    pf.taskID,
		TaskTitle: pf.taskTitle,
		Step:      state.NoStep,
		Message: "Run stopped: " + detail + ". Nothing after that was recorded; " +
			"the next run recovers the tasks this one left in progress.",
	}, details)
	o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
		Goal:    s.Goal,
		Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
		Error:   webhook.TruncateError("run stopped: " + detail),
	})

	if statusErr != nil {
		if o.log != nil {
			o.log.Error(logger.EventStateWrite, pf.taskID, "run stopped; the stop could not be recorded either",
				map[string]interface{}{"error": statusErr.Error()})
		}
		color.New(color.FgRed, color.Bold).Fprintf(os.Stderr,
			"✗ The stop could not be recorded either (%v). The project still reads as running until the hub notices the run has gone.\n",
			statusErr)
		return
	}
	// The error itself is printed by whoever ran the loop; this says what
	// happens next.
	color.New(color.FgYellow).Fprintf(os.Stderr,
		"⏸ The run is marked paused. Fix the project database (free space, permissions, the damaged row), "+
			"then run again: the next run recovers the tasks this one left in progress.\n")
}

// The activity queue (pkg/taskqueue) is a log of the work a run did, for the
// dashboard's Activity tab. Nothing schedules from it — the plan decides what
// runs — so losing a write to it cannot make a task run twice, and every queue
// write is best-effort. Not silent, though: an entry the database would not
// update keeps showing as running, and the operator should hear why. These
// are the only way the orchestrator writes the queue, and
// TestNoBareSaveCallsInOrchestrator rejects a discarded Mark call anywhere
// else.

func (o *Orchestrator) queueRunning(id int64) {
	o.noteQueueWrite(id, "running", o.queue.MarkRunning(id))
}

func (o *Orchestrator) queueDone(id int64, summary string) {
	o.noteQueueWrite(id, "done", o.queue.MarkDone(id, summary))
}

func (o *Orchestrator) queueFailed(id int64, note string) {
	o.noteQueueWrite(id, "failed", o.queue.MarkFailed(id, note))
}

func (o *Orchestrator) queueSkipped(id int64, note string) {
	o.noteQueueWrite(id, "skipped", o.queue.MarkSkipped(id, note))
}

func (o *Orchestrator) noteQueueWrite(id int64, status string, err error) {
	if err == nil {
		return
	}
	o.reportPersistFailure(&persistFailure{
		what: fmt.Sprintf("activity entry %d as %s", id, status),
		why:  "the activity queue is a log of the run, and nothing schedules from it",
		err:  err,
	})
}

// outcomeNoun names a terminal task status the way persistOutcome's messages
// read: "task #3's completion (status done)".
func outcomeNoun(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "completion"
	case pm.TaskSkipped:
		return "skip"
	case pm.TaskFailed:
		return "failure"
	}
	return string(status)
}
