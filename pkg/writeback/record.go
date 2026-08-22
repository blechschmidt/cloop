package writeback

// record.go is where a landed write-back becomes something a person can see.
//
// Apply gets the work into the repository; this gets it into the two places an
// operator looks. Both are needed and neither substitutes for the other: the
// task record answers "where is the code for task 42" months later, and the
// event journal answers "what happened during this run" — including, and
// especially, the run where the task succeeded and its work did not come back.
//
// # Why it is a separate file and takes an interface
//
// Apply must stay usable without a database. It is called from a hub that has
// one, from tests that do not, and from `cloop` subcommands that may be
// operating on a project directory rather than on the control plane's own
// state. Threading a *statedb.DB through Apply would make the storage a
// prerequisite for landing a branch, which is backwards — the branch is the
// durable thing and the row is the description of it.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Recorder is the subset of *statedb.DB this package needs.
//
// An interface so a caller can pass a real database, a fake, or nothing at
// all. It is deliberately the two narrowest methods rather than the DB: a
// package that writes a task's branch name has no business being able to
// delete a plan.
type Recorder interface {
	LoadTask(id int) (*pm.Task, error)
	UpsertTask(t *pm.Task) error
	RecordEvent(row statedb.EventRow) error
}

// Record writes a write-back's outcome to the task record and the event
// journal.
//
// It records failures as loudly as successes. A run whose work was lost looks
// exactly like a run that changed nothing — same transcript, same exit code,
// same green tick — so the case that most needs a row is the one where there is
// no branch to name.
//
// Errors are returned for a caller that wants to log them and safe to ignore
// for one that does not: nothing here is load-bearing for the work itself,
// which is already on a branch by the time this runs.
func Record(db Recorder, taskID int, taskTitle string, reported executor.WriteBackResult,
	applied Result, applyErr error) error {

	if db == nil {
		return nil
	}

	ev := statedb.EventRow{
		Type:      statedb.EventWriteBack,
		TaskID:    taskID,
		TaskTitle: taskTitle,
		Step:      statedb.NoStep,
		Message:   writeBackMessage(reported, applied, applyErr),
	}
	if detail, err := json.Marshal(writeBackDetail(reported, applied, applyErr)); err == nil {
		ev.Details = string(detail)
	}
	evErr := db.RecordEvent(ev)

	// The task record carries only what is still true afterwards: a branch
	// that exists at a commit that exists. A failed or skipped write-back
	// leaves the fields empty rather than storing the reason, because the
	// fields are a pointer to code and a pointer to code that is not there is
	// worse than none — the event above is where the reason lives.
	if applyErr != nil || !applied.Delivered() {
		return evErr
	}
	task, err := db.LoadTask(taskID)
	if err != nil || task == nil {
		// A write-back for a task the database does not have is not an error
		// worth failing on: the run may be a whole-project one with no task
		// binding at all, and the event row above already recorded it.
		return evErr
	}
	task.WriteBackBranch = applied.Branch
	task.WriteBackCommit = applied.CommitSHA
	if err := db.UpsertTask(task); err != nil {
		return fmt.Errorf("writeback: record branch on task %d: %w", taskID, err)
	}
	return evErr
}

// Delivered reports whether Apply produced a branch worth pointing at.
func (r Result) Delivered() bool {
	return strings.TrimSpace(r.Branch) != "" && strings.TrimSpace(r.CommitSHA) != ""
}

// writeBackMessage is the one-line summary the event list shows.
func writeBackMessage(reported executor.WriteBackResult, applied Result, applyErr error) string {
	switch {
	case applyErr != nil:
		return "the executor's work was refused: " + executor.RedactSecrets(applyErr.Error(), nil)
	case applied.Skipped || reported.Skipped:
		if reason := strings.TrimSpace(reported.SkipReason); reason != "" {
			return "nothing to write back — " + reason
		}
		return "nothing to write back"
	case !applied.Delivered():
		return "no work was returned by the executor"
	}

	s := fmt.Sprintf("landed %s at %s (%d file", applied.Branch,
		executor.ShortSHA(applied.CommitSHA), applied.FilesChanged)
	if applied.FilesChanged != 1 {
		s += "s"
	}
	s += ")"
	switch {
	case applied.Merged:
		s += ", merged as " + executor.ShortSHA(applied.MergeSHA)
	case applied.MergeErr != nil:
		// Named rather than swallowed: the branch is on disk and someone has
		// to be told it is waiting for them.
		s += ", not merged — " + applied.MergeErr.Error()
	}
	return s
}

// writeBackDetail is the structured blob the event row carries, for the UI's
// expandable detail panel. It holds identifiers only — no credential could
// reach here, since neither WriteBackResult nor Result has a field for one.
func writeBackDetail(reported executor.WriteBackResult, applied Result, applyErr error) map[string]any {
	d := map[string]any{
		"mode":   string(reported.Mode),
		"branch": applied.Branch,
		"commit": applied.CommitSHA,
		"base":   reported.BaseSHA,
	}
	if d["branch"] == "" {
		// Report what the executor claimed even when nothing landed: "which
		// branch was refused" is the operator's next question.
		d["branch"] = reported.Branch
	}
	if d["commit"] == "" {
		d["commit"] = reported.CommitSHA
	}
	if applied.Commits > 0 {
		d["commits"] = applied.Commits
	}
	if applied.FilesChanged > 0 {
		d["files_changed"] = applied.FilesChanged
	}
	if applied.Merged {
		d["merged"] = true
		d["merge_commit"] = applied.MergeSHA
	}
	if applied.MergeErr != nil {
		d["merge_error"] = applied.MergeErr.Error()
	}
	if applyErr != nil {
		d["error"] = applyErr.Error()
	} else if reported.Err != "" {
		d["error"] = reported.Err
	}
	if reported.SkipReason != "" {
		d["skip_reason"] = reported.SkipReason
	}
	return d
}
