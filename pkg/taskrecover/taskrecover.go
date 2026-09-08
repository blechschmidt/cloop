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
// Adopt a terminal signal; re-queue everything else. Silence is not success: an
// artifact that stops mid-sentence means the agent was interrupted, and that
// task genuinely has to run again.
//
// Callers must guarantee no process owns the project directory. Reconcile is a
// repair for the dead, and running it against a live run would reset a task out
// from under the process executing it.
package taskrecover

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// maxLiveArtifactBytes bounds how much of a live artifact is read into memory.
// Real artifacts are kilobytes; the cap exists so a runaway agent that wrote a
// gigabyte of output cannot turn recovery into an OOM of its own. Beyond it we
// read the tail, which is where the signal lives.
const maxLiveArtifactBytes = 16 << 20

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
	if plan == nil {
		return nil
	}
	var outcomes []Outcome
	for _, t := range plan.Tasks {
		if t == nil || t.Status != pm.TaskInProgress {
			continue
		}
		outcomes = append(outcomes, reconcileTask(workDir, t))
	}
	return outcomes
}

// reconcileTask decides the fate of a single stranded task.
func reconcileTask(workDir string, t *pm.Task) Outcome {
	out := Outcome{TaskID: t.ID, Title: t.Title}

	output, modTime, truncated, err := readLiveArtifact(workDir, t.ID)
	if err != nil {
		return requeue(t, out, fmt.Sprintf("no live output was recoverable (%v)", err))
	}

	// Freshness guard: an artifact older than the execution we are recovering
	// belongs to a previous attempt, and adopting it would credit this run
	// with work it never did.
	if t.StartedAt != nil && modTime.Before(*t.StartedAt) {
		return requeue(t, out, "the live output predates this execution, so it belongs to an earlier attempt")
	}

	signal := pm.CheckTaskSignal(output)
	switch signal {
	case pm.TaskDone, pm.TaskFailed, pm.TaskSkipped:
		return adopt(workDir, t, out, output, signal, modTime, truncated)
	default:
		return requeue(t, out, "the agent was interrupted before it reported an outcome")
	}
}

// adopt records the outcome the agent had already reached, reproducing the
// bookkeeping the dying run did not get to do.
func adopt(workDir string, t *pm.Task, out Outcome, output string, signal pm.TaskStatus, modTime time.Time, truncated bool) Outcome {
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

	pm.AddAnnotation(t, "ai", fmt.Sprintf(
		"Recovered after an interrupted run: the agent had already finished and reported %s, "+
			"but the run process died before recording it. The outcome was adopted from the live "+
			"artifact rather than re-executing the task.", signal))

	out.Action = ActionAdopted
	out.Status = signal
	out.CompletedAt = completed
	return out
}

// requeue resets a genuinely unfinished task so it runs again.
func requeue(t *pm.Task, out Outcome, reason string) Outcome {
	t.Status = pm.TaskPending
	t.StartedAt = nil
	pm.AddAnnotation(t, "ai", fmt.Sprintf(
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
