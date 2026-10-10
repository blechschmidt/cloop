// Package taskrecover repairs tasks left in_progress by a run that died.
//
// A run process can disappear between the moment its agent finishes speaking
// and the moment that outcome reaches the database. The window is small but it
// is not rare: the control plane is killed and the orphaned run inherits a
// closed stdout pipe (Go makes SIGPIPE fatal on fd 1 and 2, so the next status
// line is lethal), the host OOMs, the machine reboots. Whatever the cause, the
// process is gone and the row still says in_progress.
//
// Both recovery paths used to answer that the same way: reset the task to
// pending and run it again. That is right when the agent never finished, and
// destructive when it did. Task 63 of the liebid project is the case that
// motivated this package — an hour of work, a full result, `TASK_DONE` on the
// last line, and the only surviving copy sitting in the live artifact while the
// plan prepared to do all of it a second time. Re-running a task whose work is
// already committed is not a neutral retry; it is an agent rediscovering its
// own finished changes and deciding what to do about them.
//
// # Why the live artifact is trustworthy evidence
//
// The orchestrator streams every token into .cloop/artifacts/<id>_output.txt as
// it arrives, so the file is complete the instant the agent stops talking —
// strictly before the bookkeeping this package exists to replace. It is opened
// O_TRUNC at the start of each execution, so it always describes the newest
// attempt and never an older one.
//
// Adoption then applies exactly the contract the live path applies:
// pm.CheckTaskSignal over the last five lines. This package cannot invent a
// completion the orchestrator would not itself have recognised, because it is
// asking the same function the same question about the same bytes. What it adds
// is one guard the live path does not need — that the artifact is no older than
// the execution being recovered — so a leftover file from a previous attempt
// can never be read as this attempt's result.
//
// # The rule
//
// The orchestrator's verdict first (verdict.go): where it had decided the
// execution's outcome before the run ended, that decision stands, whatever the
// agent said — a review gate's rejection, a failed verification, abandoned
// background work. Where it had not, adopt the agent's terminal signal, unless
// the outcome was still waiting on the review gate and the agent claims done;
// re-queue everything else. Silence is not success: an artifact that stops
// mid-sentence means the agent was interrupted, and that task genuinely has to
// run again.
//
// Callers must guarantee no process owns the project directory. Reconcile is a
// repair for the dead, and running it against a live run would reset a task out
// from under the process executing it.
package taskrecover

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// maxLiveArtifactBytes bounds how much of a live artifact is read into memory.
// Real artifacts are kilobytes; the cap exists so a runaway agent that wrote a
// gigabyte of output cannot turn recovery into an OOM of its own. Beyond it we
// read the tail, which is where the signal lives.
//
// Aliased to the shared artifact cap rather than restating 16 MiB, so recovery
// and every other artifact reader move together.
const maxLiveArtifactBytes = boundedread.ArtifactMaxBytes

// truncationNotice heads an artifact recovered from an over-long live file, so
// nobody reads the surviving tail as the whole transcript.
const truncationNotice = "_[recovered from a truncated live artifact — the earlier output exceeded the recovery read limit and was not preserved]_\n\n"

// Action says what reconciliation did with a task.
type Action string

const (
	// ActionAdopted means the agent had finished and its outcome was taken
	// from the live artifact instead of being thrown away.
	ActionAdopted Action = "adopted"
	// ActionRequeued means no terminal signal was found, so the task was
	// reset to pending to be executed again.
	ActionRequeued Action = "requeued"
)

// Outcome is what happened to one recovered task. Callers use it to log,
// broadcast, and decide whether the plan changed enough to save.
type Outcome struct {
	TaskID int
	Title  string
	Action Action
	// Status is the status the task now has: the adopted signal, or pending.
	Status pm.TaskStatus
	// CompletedAt is when the agent actually stopped writing, for adopted
	// tasks only. Taken from the artifact's mtime rather than from the clock,
	// because reconciliation may happen days after the fact and "completed
	// when we noticed" would be a lie in the timeline.
	CompletedAt time.Time
	// Reason explains a re-queue in words a UI can show.
	Reason string
	// Verdict is the orchestrator's decision the outcome followed (Task
	// 20365), when one was found for this execution; nil when the agent's own
	// report decided it.
	Verdict *Verdict
	// Stop is set on a re-queue caused by a stop from outside the run (Task
	// 20405).
	Stop *pm.TaskStop

	// stop is what ended the run, carried to requeue.
	stop *Stop
}

// Reconcile repairs every task in the plan left in_progress by a run that no
// longer exists, and returns one Outcome per task it touched.
//
// It mutates the plan in place and never persists: the caller owns the state
// handle and decides when to save, which keeps this package free of pkg/state
// and testable with nothing but a temp dir.
//
// The caller must have established that no process is executing this project.
func Reconcile(workDir string, plan *pm.Plan) []Outcome {
	return ReconcileStopped(workDir, plan, nil)
}

// Stop names what ended a run from outside it, when the party settling the run
// knows (Task 20405) — its executor stopped it at its disk limit.
type Stop struct {
	// Reason is the clause a re-queued task's note and journal row give in
	// place of "the agent was interrupted before it reported an outcome".
	Reason string
	// Task is set on each task re-queued for it, for the save that records
	// the re-queue: its task.finish row carries the cause as fields.
	Task pm.TaskStop
}

// ReconcileStopped is Reconcile for a run stopped from outside. What the
// orchestrator decided and what the agent finished stand exactly as Reconcile
// has them; a task the run had not finished goes back to pending for stop's
// reason, noted by cloop rather than inferred from its transcript. A nil stop
// is Reconcile.
func ReconcileStopped(workDir string, plan *pm.Plan, stop *Stop) []Outcome {
	if plan == nil {
		return nil
	}
	var outcomes []Outcome
	for _, t := range plan.Tasks {
		if t == nil || t.Status != pm.TaskInProgress {
			continue
		}
		outcomes = append(outcomes, reconcileTask(workDir, t, stop))
	}
	return outcomes
}

// reconcileTask decides the fate of a single stranded task.
func reconcileTask(workDir string, t *pm.Task, stop *Stop) Outcome {
	out := Outcome{TaskID: t.ID, Title: t.Title, stop: stop}

	// The orchestrator's verdict outranks the agent's report: it is what the
	// run would have stored had it lived (Task 20365).
	v, unusable := verdictFor(workDir, t)
	if v.Decided() {
		return applyVerdict(workDir, t, out, v, true)
	}

	output, modTime, truncated, err := readLiveArtifact(workDir, t.ID)
	if err != nil {
		return requeue(t, out, withNote(fmt.Sprintf("no live output was recoverable (%v)", err), unusable))
	}

	// Freshness guard: an artifact older than the execution we are recovering
	// belongs to a previous attempt, and adopting it would credit this run
	// with work it never did.
	if t.StartedAt != nil && modTime.Before(*t.StartedAt) {
		return requeue(t, out, withNote("the live output predates this execution, so it belongs to an earlier attempt", unusable))
	}

	signal := pm.CheckTaskSignal(output)
	switch signal {
	case pm.TaskDone, pm.TaskFailed, pm.TaskSkipped:
		if signal == pm.TaskDone && v.AwaitingReview() {
			// The gate never approved the work, so its held pushes died
			// with the run: the claim is unreviewed and nothing of it was
			// published. Running it again is how it gets reviewed.
			out.Verdict = v
			return requeue(t, out, "the agent reported it done, but the review gate had not approved it "+
				"when the run ended, so none of its work was published")
		}
		return adopt(workDir, t, out, output, signal, modTime, truncated, unusable)
	default:
		return requeue(t, out, withNote("the agent was interrupted before it reported an outcome", unusable))
	}
}

// verdictFor returns the verdict that decides t's current execution, or nil.
// When a sidecar was there but could not be used, the second result says why,
// for the annotation: a decision may have been lost, and whoever reads the
// task should know its outcome rests on the agent's report alone.
func verdictFor(workDir string, t *pm.Task) (*Verdict, string) {
	v, err := ReadVerdict(workDir, t.ID)
	switch {
	case errors.Is(err, ErrNoVerdict):
		return nil, ""
	case err != nil:
		return nil, fmt.Sprintf("cloop's verdict on it could not be read (%v), so the agent's own report was used", err)
	case !v.For(t):
		// An earlier attempt's: the rule the live artifact is held to.
		return nil, ""
	}
	return v, ""
}

// withNote appends the note about an unusable verdict to a re-queue reason.
func withNote(reason, note string) string {
	if note == "" {
		return reason
	}
	return reason + "; " + note
}

// adopt records the outcome the agent had already reached, reproducing the
// bookkeeping the dying run did not get to do.
func adopt(workDir string, t *pm.Task, out Outcome, output string, signal pm.TaskStatus, modTime time.Time, truncated bool, note string) Outcome {
	body := output
	if truncated {
		body = truncationNotice + output
	}

	t.Status = signal
	completed := modTime
	t.CompletedAt = &completed
	t.Result = truncate(body, 500)

	// Persist the full transcript as the task artifact. Best-effort: losing the
	// artifact must not cost us the status, which is the part that stops the
	// task from being run twice.
	if path, err := artifact.WriteTaskArtifact(workDir, t, body); err == nil {
		t.ArtifactPath = path
	}

	msg := fmt.Sprintf(
		"Recovered after an interrupted run: the agent had already finished and reported %s, "+
			"but the run process died before recording it. The outcome was adopted from the live "+
			"artifact rather than re-executing the task.", signal)
	if note != "" {
		msg += " Note: " + note + "."
	}
	pm.AddAnnotation(t, "ai", msg)

	out.Action = ActionAdopted
	out.Status = signal
	out.CompletedAt = completed
	return out
}

// applyVerdict records the outcome the orchestrator had decided before the run
// ended. A verdict to re-queue re-queues; any other is applied as the task's
// outcome, with the fields the run would have stored alongside it.
//
// readTranscript says whether the live artifact may be read for the task's
// transcript. Reconcile reads it — the same evidence it would otherwise adopt —
// and keeps the transcript as the task artifact; SettleFromVerdicts does not,
// and the verdict's own summary stands in for it.
func applyVerdict(workDir string, t *pm.Task, out Outcome, v *Verdict, readTranscript bool) Outcome {
	out.Verdict = v
	if v.Status == pm.TaskPending {
		return requeue(t, out, "cloop had already returned it to pending — "+v.Describe())
	}

	var body string
	agent := pm.TaskInProgress
	if readTranscript {
		output, modTime, truncated, err := readLiveArtifact(workDir, t.ID)
		if err == nil && (t.StartedAt == nil || !modTime.Before(*t.StartedAt)) {
			body = output
			if truncated {
				body = truncationNotice + output
			}
			agent = pm.CheckTaskSignal(output)
		}
	}

	t.Status = v.Status
	completed := v.WrittenAt
	t.CompletedAt = &completed
	if t.StartedAt != nil && !completed.Before(*t.StartedAt) {
		t.ActualMinutes = int(completed.Sub(*t.StartedAt).Minutes())
	}
	switch {
	case body != "":
		t.Result = truncate(body, 500)
		if path, err := artifact.WriteTaskArtifact(workDir, t, body); err == nil {
			t.ArtifactPath = path
		}
	case v.Summary != "":
		t.Result = v.Summary
	}
	if v.Diagnosis != "" {
		t.FailureDiagnosis = v.Diagnosis
	}
	if v.Review != nil {
		t.Review = v.Review.Clone()
	}
	switch {
	case v.Background != nil:
		bg := *v.Background
		bg.Commands = append([]string(nil), v.Background.Commands...)
		t.Background = &bg
	case t.Background.Pending():
		// The wait ended with the execution; a "waiting" record would show a
		// finished task as blocked.
		t.Background = nil
	}

	msg := fmt.Sprintf("Recovered after an interrupted run: cloop had already decided this execution "+
		"was %s — %s — but the run ended before that reached the database.", v.Status, v.Describe())
	switch {
	case agent == v.Status:
		msg += " The agent had reported the same."
	case agent != pm.TaskInProgress:
		msg += fmt.Sprintf(" That decision was applied, not the agent's own report (%s).", signalWord(agent))
	default:
		msg += " That decision was applied."
	}
	pm.AddAnnotation(t, "cloop", msg)

	out.Action = ActionAdopted
	out.Status = v.Status
	out.CompletedAt = completed
	return out
}

// signalWord renders a status as the agent's signal line.
func signalWord(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "TASK_DONE"
	case pm.TaskFailed:
		return "TASK_FAILED"
	case pm.TaskSkipped:
		return "TASK_SKIPPED"
	}
	return string(s)
}

// SettleFromVerdicts applies the fresh verdicts in workDir to the tasks plan
// left in progress, and leaves every other in-progress task as it is. It reads
// the verdict sidecars and nothing else, and writes nothing: it mutates plan in
// place and returns one Outcome per task it settled.
//
// It is the half of Reconcile that is safe on a remote device. Once a seeded
// run has exited, the device reads back what it left (pkg/executor/projectseed)
// and runs this first, so a run that died — or stopped on a failed write —
// after the orchestrator decided an outcome reports that decision rather than
// a task still in progress. What the orchestrator had not decided stays in
// progress, for the hub's dead-run recovery to settle: the hub cannot read the
// device's live artifact, so it re-queues.
//
// A sidecar that is present but unusable is noted on the task, which stays in
// progress. The caller must guarantee the run has exited.
func SettleFromVerdicts(workDir string, plan *pm.Plan) []Outcome {
	if plan == nil {
		return nil
	}
	var outcomes []Outcome
	for _, t := range plan.Tasks {
		if t == nil || t.Status != pm.TaskInProgress {
			continue
		}
		v, unusable := verdictFor(workDir, t)
		if !v.Decided() {
			if unusable != "" {
				pm.AddAnnotation(t, "cloop", "The run ended with this task in progress, and "+unusable+".")
			}
			continue
		}
		outcomes = append(outcomes, applyVerdict(workDir, t, Outcome{TaskID: t.ID, Title: t.Title}, v, false))
	}
	return outcomes
}

// requeue resets a genuinely unfinished task so it runs again.
//
// A run stopped from outside gives its own reason instead of the transcript's,
// unless the orchestrator's verdict decided the re-queue: that decision came
// first and still explains it.
func requeue(t *pm.Task, out Outcome, reason string) Outcome {
	t.Status = pm.TaskPending
	t.StartedAt = nil
	if t.Background.Pending() {
		t.Background = nil
	}
	author := "ai"
	if out.Verdict != nil {
		author = "cloop"
	}
	if s := out.stop; s != nil && out.Verdict == nil && s.Reason != "" {
		reason = s.Reason
		author = "cloop"
		ts := s.Task
		t.Stop = &ts
		out.Stop = &ts
	}
	pm.AddAnnotation(t, author, fmt.Sprintf(
		"Reset to pending after an interrupted run: %s.", reason))

	out.Action = ActionRequeued
	out.Status = pm.TaskPending
	out.Reason = reason
	return out
}

// readLiveArtifact returns the streamed output for a task, when it was last
// written, and whether the read had to drop a prefix to stay within the cap.
//
// Reading the tail rather than the head when the file is oversized is
// deliberate: the completion signal is on the last line, so the tail is the
// only part that can answer the question being asked.
func readLiveArtifact(workDir string, taskID int) (content string, modTime time.Time, truncated bool, err error) {
	path := artifact.LiveArtifactPath(workDir, taskID)
	f, err := os.Open(path)
	if err != nil {
		return "", time.Time{}, false, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", time.Time{}, false, err
	}
	if info.IsDir() {
		return "", time.Time{}, false, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() == 0 {
		return "", info.ModTime(), false, fmt.Errorf("live artifact is empty")
	}

	if info.Size() > maxLiveArtifactBytes {
		if _, err := f.Seek(info.Size()-maxLiveArtifactBytes, io.SeekStart); err != nil {
			return "", time.Time{}, false, err
		}
		truncated = true
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLiveArtifactBytes))
	if err != nil {
		return "", time.Time{}, false, err
	}
	return string(data), info.ModTime(), truncated, nil
}

// truncate caps a string at n bytes, matching the orchestrator's own summary
// length so a recovered task's Result reads like every other task's.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
