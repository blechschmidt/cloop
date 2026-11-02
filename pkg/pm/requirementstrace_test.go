package pm

import (
	"fmt"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// TestTracePlanTasks: each task brings the commits it records of its own work
// — a write-back commit, and the gate's commit when the work moved HEAD past
// where it started — and nothing for work left uncommitted at the base.
func TestTracePlanTasks(t *testing.T) {
	done := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	plan := &Plan{Tasks: []*Task{
		{ID: 1, Title: "isolated", Status: TaskDone, CompletedAt: &done, Requirements: []int{3},
			WriteBackCommit: "ABCDEF1234567890", WriteBackBranch: "cloop/task-1"},
		{ID: 2, Title: "gated, committed", Status: TaskDone, Requirements: []int{3, 4},
			RequirementsCheck: &TaskRequirementsCheck{Commit: "1111111222", Base: "0000000999"}},
		nil,
		{ID: 3, Title: "gated, uncommitted", Status: TaskInProgress,
			RequirementsCheck: &TaskRequirementsCheck{Commit: "0000000999", Base: "0000000999", Dirty: true}},
		{ID: 4, Title: "no record", Status: TaskPending, WriteBackCommit: "not a hash"},
	}}
	got := TracePlanTasks(plan)
	if len(got) != 4 {
		t.Fatalf("%d tasks, want 4 (the nil one skipped): %+v", len(got), got)
	}
	if got[0].ID != 1 || got[0].Title != "isolated" || !got[0].CompletedAt.Equal(done) || fmt.Sprint(got[0].Requirements) != "[3]" ||
		len(got[0].Commits) != 1 || got[0].Commits[0] != (requirements.TraceCommit{Hash: "abcdef1234567890", TaskID: 1,
		Source: requirements.CommitFromWriteBack}) {
		t.Errorf("the isolated task: %+v", got[0])
	}
	if len(got[1].Commits) != 1 || got[1].Commits[0].Hash != "1111111222" || got[1].Commits[0].Source != requirements.CommitFromGate {
		t.Errorf("the gated task: %+v", got[1].Commits)
	}
	if got[2].ID != 3 || len(got[2].Commits) != 0 {
		t.Errorf("work left uncommitted at the base brings a commit: %+v", got[2])
	}
	if got[3].ID != 4 || len(got[3].Commits) != 0 {
		t.Errorf("a write-back commit that is no hash: %+v", got[3])
	}
	if TracePlanTasks(nil) != nil {
		t.Error("a nil plan has tasks")
	}
}
