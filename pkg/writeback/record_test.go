package writeback

// Recording tests. The interesting assertions here are all about the failure
// cases, because the success case is not the one that gets missed: a run whose
// work was lost produces the same transcript, exit code and green tick as one
// that changed nothing, and the journal row is the only thing that tells them
// apart.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeRecorder stands in for the control plane's database.
type fakeRecorder struct {
	tasks  map[int]*pm.Task
	events []statedb.EventRow
	// loadErr simulates a task the database does not have, which is the
	// ordinary case for a whole-project run with no task binding.
	loadErr error
}

func newFakeRecorder(tasks ...*pm.Task) *fakeRecorder {
	r := &fakeRecorder{tasks: map[int]*pm.Task{}}
	for _, t := range tasks {
		r.tasks[t.ID] = t
	}
	return r
}

func (r *fakeRecorder) LoadTask(id int) (*pm.Task, error) {
	if r.loadErr != nil {
		return nil, r.loadErr
	}
	t, ok := r.tasks[id]
	if !ok {
		return nil, statedb.ErrTaskNotFound
	}
	return t, nil
}

func (r *fakeRecorder) UpsertTask(t *pm.Task) error {
	r.tasks[t.ID] = t
	return nil
}

func (r *fakeRecorder) RecordEvent(row statedb.EventRow) error {
	r.events = append(r.events, row)
	return nil
}

func (r *fakeRecorder) onlyEvent(t *testing.T) statedb.EventRow {
	t.Helper()
	if len(r.events) != 1 {
		t.Fatalf("got %d events, want exactly 1: %+v", len(r.events), r.events)
	}
	return r.events[0]
}

func (r *fakeRecorder) eventDetail(t *testing.T) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal([]byte(r.onlyEvent(t).Details), &d); err != nil {
		t.Fatalf("event details are not JSON: %v (%q)", err, r.onlyEvent(t).Details)
	}
	return d
}

func landed() Result {
	return Result{
		Branch: testBranch, CommitSHA: "abc1234567890abc1234567890abc1234567890a",
		Commits: 1, FilesChanged: 3, Merged: true,
		MergeSHA: "def4567890abcdef4567890abcdef4567890abcd",
	}
}

func TestRecord_LandedWorkReachesTheTaskAndTheJournal(t *testing.T) {
	task := &pm.Task{ID: 42, Title: "add a retry"}
	db := newFakeRecorder(task)

	if err := Record(db, 42, "add a retry", executor.WriteBackResult{
		Mode: executor.WriteBackBundle, Branch: testBranch,
	}, landed(), nil); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if got := db.tasks[42].WriteBackBranch; got != testBranch {
		t.Errorf("task branch = %q, want %q", got, testBranch)
	}
	if got := db.tasks[42].WriteBackCommit; got != landed().CommitSHA {
		t.Errorf("task commit = %q, want %q", got, landed().CommitSHA)
	}

	ev := db.onlyEvent(t)
	if ev.Type != statedb.EventWriteBack {
		t.Errorf("event type = %q, want %q", ev.Type, statedb.EventWriteBack)
	}
	if ev.TaskID != 42 || ev.Step != statedb.NoStep {
		t.Errorf("event = %+v, want task 42 and no step", ev)
	}
	for _, want := range []string{testBranch, "abc123456789", "3 files", "merged"} {
		if !strings.Contains(ev.Message, want) {
			t.Errorf("message %q is missing %q", ev.Message, want)
		}
	}
	d := db.eventDetail(t)
	if d["merged"] != true || d["merge_commit"] != landed().MergeSHA {
		t.Errorf("details = %v, want the merge recorded", d)
	}
}

// TestRecord_RefusedWorkIsJournalledAndNotPointedAt is the important one. A
// refusal has to leave a row — it is a security event — and must not leave a
// branch name on the task, because a pointer to code that is not there is
// worse than no pointer at all.
func TestRecord_RefusedWorkIsJournalledAndNotPointedAt(t *testing.T) {
	task := &pm.Task{ID: 42, Title: "add a retry"}
	db := newFakeRecorder(task)

	refusal := &executor.WriteBackRejection{
		Path: ".git/hooks/post-checkout", Branch: testBranch,
		Reason: "is inside the .git directory",
	}
	if err := Record(db, 42, "add a retry",
		executor.WriteBackResult{Mode: executor.WriteBackBundle, Branch: testBranch},
		Result{}, refusal); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if got := db.tasks[42].WriteBackBranch; got != "" {
		t.Errorf("a refused write-back left branch %q on the task", got)
	}
	if got := db.tasks[42].WriteBackCommit; got != "" {
		t.Errorf("a refused write-back left commit %q on the task", got)
	}
	ev := db.onlyEvent(t)
	if !strings.Contains(ev.Message, "refused") {
		t.Errorf("message = %q, want it to say the work was refused", ev.Message)
	}
	d := db.eventDetail(t)
	if d["error"] == nil || !strings.Contains(d["error"].(string), ".git/hooks") {
		t.Errorf("details = %v, want the offending path recorded", d)
	}
	// The branch the executor claimed is still reported, because "which branch
	// was refused" is the operator's next question.
	if d["branch"] != testBranch {
		t.Errorf("details branch = %v, want the claimed branch", d["branch"])
	}
}

// TestRecord_LostWorkIsVisible covers the failure this subsystem exists for: a
// task that ran fine and whose output never came back.
func TestRecord_LostWorkIsVisible(t *testing.T) {
	db := newFakeRecorder(&pm.Task{ID: 42, Title: "add a retry"})

	if err := Record(db, 42, "add a retry", executor.WriteBackResult{
		Mode:   executor.WriteBackPush,
		Branch: testBranch,
		Err:    "the Pod produced no write-back report",
	}, Result{}, nil); err != nil {
		t.Fatalf("Record: %v", err)
	}
	ev := db.onlyEvent(t)
	if ev.Message == "" {
		t.Fatal("a lost write-back produced an empty message")
	}
	if d := db.eventDetail(t); d["error"] == nil {
		t.Errorf("details = %v, want the reason recorded", d)
	}
	if got := db.tasks[42].WriteBackBranch; got != "" {
		t.Errorf("a lost write-back left branch %q on the task", got)
	}
}

// TestRecord_UnmergedBranchNamesTheConflict pins that a branch waiting for a
// human says so. The work is on disk and nothing else would tell anyone.
func TestRecord_UnmergedBranchNamesTheConflict(t *testing.T) {
	db := newFakeRecorder(&pm.Task{ID: 42})
	res := landed()
	res.Merged, res.MergeSHA = false, ""
	res.MergeErr = errors.New("merge conflict in README.md")

	if err := Record(db, 42, "", executor.WriteBackResult{Mode: executor.WriteBackBundle},
		res, nil); err != nil {
		t.Fatalf("Record: %v", err)
	}
	ev := db.onlyEvent(t)
	if !strings.Contains(ev.Message, "not merged") || !strings.Contains(ev.Message, "conflict") {
		t.Errorf("message = %q, want it to name the unmerged conflict", ev.Message)
	}
	// The branch is still recorded: it exists and holds the work.
	if got := db.tasks[42].WriteBackBranch; got != testBranch {
		t.Errorf("an unmerged branch was not recorded on the task: %q", got)
	}
}

func TestRecord_SkippedWriteBackSaysWhy(t *testing.T) {
	db := newFakeRecorder(&pm.Task{ID: 42})
	if err := Record(db, 42, "", executor.WriteBackResult{
		Skipped: true, SkipReason: "the harness exited 1, so its partial changes were not written back",
	}, Result{Skipped: true}, nil); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := db.onlyEvent(t).Message; !strings.Contains(got, "exited 1") {
		t.Errorf("message = %q, want it to carry the skip reason", got)
	}
}

// TestRecord_UnknownTaskStillJournals covers a whole-project run, which has no
// task to attach a branch to but still has an outcome worth recording.
func TestRecord_UnknownTaskStillJournals(t *testing.T) {
	db := newFakeRecorder()
	db.loadErr = statedb.ErrTaskNotFound

	if err := Record(db, 0, "", executor.WriteBackResult{Mode: executor.WriteBackBundle},
		landed(), nil); err != nil {
		t.Fatalf("Record: %v", err)
	}
	db.onlyEvent(t) // fatals if it did not journal
}

func TestRecord_NilRecorderIsANoOp(t *testing.T) {
	if err := Record(nil, 42, "t", executor.WriteBackResult{}, landed(), nil); err != nil {
		t.Fatalf("Record(nil) = %v, want nil", err)
	}
}
