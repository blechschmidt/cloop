package compact

import (
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// `cloop compact` removes the task verdicts (Task 20365) a stale-task recovery
// can no longer need, and never an in-progress task's.
func TestRun_PrunesTaskVerdicts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	s, err := state.Init(dir, "compact verdicts", 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Plan = &pm.Plan{Goal: s.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "done", Status: pm.TaskDone},
		{ID: 2, Title: "in progress", Status: pm.TaskInProgress},
		{ID: 3, Title: "failed, decided a minute ago", Status: pm.TaskFailed},
	}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	aged := func(id int, age time.Duration) {
		if err := taskrecover.WriteVerdict(dir, taskrecover.Verdict{TaskID: id, Status: pm.TaskDone}); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(taskrecover.VerdictPath(dir, id), when, when); err != nil {
			t.Fatal(err)
		}
	}
	aged(1, 2*time.Hour)
	aged(2, 2*time.Hour)
	aged(3, time.Minute) // inside the grace a concurrent run needs
	aged(9, 2*time.Hour) // no such task any more

	sum, err := Run(dir, Options{KeepArtifactsDays: 0})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.VerdictsDeleted != 2 || sum.VerdictsBytesFreed == 0 {
		t.Fatalf("summary = %+v, want two verdicts removed", sum)
	}
	for id, want := range map[int]bool{1: false, 2: true, 3: true, 9: false} {
		_, err := os.Stat(taskrecover.VerdictPath(dir, id))
		if got := err == nil; got != want {
			t.Errorf("task %d's verdict present = %v, want %v", id, got, want)
		}
	}
}
