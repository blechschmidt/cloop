package taskrecover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// writeLive plants a live artifact for taskID and stamps its mtime, which is
// the evidence Reconcile reads. modTime is what the streaming write would have
// left behind, so tests control the freshness guard directly.
func writeLive(t *testing.T, workDir string, taskID int, content string, modTime time.Time) string {
	t.Helper()
	path := artifact.LiveArtifactPath(workDir, taskID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir live artifact dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write live artifact: %v", err)
	}
	if !modTime.IsZero() {
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			t.Fatalf("chtimes live artifact: %v", err)
		}
	}
	return path
}

// inProgressTask builds a task in the state a dead run leaves behind.
func inProgressTask(id int, startedAt time.Time) *pm.Task {
	started := startedAt
	return &pm.Task{
		ID:        id,
		Title:     "Analyze and fix the streaming performance",
		Status:    pm.TaskInProgress,
		StartedAt: &started,
	}
}

// TestAdoptsFinishedWork is the case that motivated the package: the agent
// finished, said so, and the run died before recording it. Re-running would
// discard an hour of work and set an agent loose on changes it already made.
func TestAdoptsFinishedWork(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	finished := started.Add(50 * time.Minute)

	writeLive(t, dir, 63, "Did the work.\n\nTASK_DONE\n", finished)
	task := inProgressTask(63, started)
	plan := &pm.Plan{Tasks: []*pm.Task{task}}

	outcomes := Reconcile(dir, plan)

	if len(outcomes) != 1 {
		t.Fatalf("got %d outcomes, want 1", len(outcomes))
	}
	if outcomes[0].Action != ActionAdopted {
		t.Errorf("action = %q, want %q — a finished task must not be re-run", outcomes[0].Action, ActionAdopted)
	}
	if task.Status != pm.TaskDone {
		t.Errorf("status = %q, want %q", task.Status, pm.TaskDone)
	}
	if task.CompletedAt == nil {
		t.Fatal("CompletedAt not set on an adopted task")
	}
	// The completion time must be when the agent stopped, not when we noticed.
	if !task.CompletedAt.Equal(finished.Truncate(time.Second)) &&
		task.CompletedAt.Sub(finished).Abs() > time.Second {
		t.Errorf("CompletedAt = %v, want the artifact mtime %v", task.CompletedAt, finished)
	}
	if task.Result == "" {
		t.Error("Result summary not populated from the recovered output")
	}
	if task.ArtifactPath == "" {
		t.Error("ArtifactPath not set — the transcript was not persisted")
	} else if _, err := os.Stat(filepath.Join(dir, task.ArtifactPath)); err != nil {
		t.Errorf("artifact not written to disk: %v", err)
	}
}

// TestAdoptsTerminalFailureAndSkip checks the other two terminal signals: a
// reported failure is a real outcome, not an excuse to run the task again.
func TestAdoptsTerminalFailureAndSkip(t *testing.T) {
	for _, tc := range []struct {
		signal string
		want   pm.TaskStatus
	}{
		{"TASK_FAILED", pm.TaskFailed},
		{"TASK_SKIPPED", pm.TaskSkipped},
	} {
		t.Run(tc.signal, func(t *testing.T) {
			dir := t.TempDir()
			started := time.Now().Add(-time.Hour)
			writeLive(t, dir, 7, "Tried it.\n\n"+tc.signal+"\n", started.Add(time.Minute))

			task := inProgressTask(7, started)
			outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

			if len(outcomes) != 1 || outcomes[0].Action != ActionAdopted {
				t.Fatalf("outcomes = %+v, want one adoption", outcomes)
			}
			if task.Status != tc.want {
				t.Errorf("status = %q, want %q", task.Status, tc.want)
			}
		})
	}
}

// TestRequeuesInterruptedWork is the complementary half of the rule: silence is
// not success. An agent cut off mid-sentence has to run again.
func TestRequeuesInterruptedWork(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	writeLive(t, dir, 12, "I am partway through the refactor and still writ", started.Add(time.Minute))

	task := inProgressTask(12, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 || outcomes[0].Action != ActionRequeued {
		t.Fatalf("outcomes = %+v, want one requeue", outcomes)
	}
	if task.Status != pm.TaskPending {
		t.Errorf("status = %q, want %q", task.Status, pm.TaskPending)
	}
	if task.StartedAt != nil {
		t.Error("StartedAt must be cleared so the retry is not dated to the dead run")
	}
	if outcomes[0].Reason == "" {
		t.Error("a requeue must carry a reason the UI can show")
	}
}

// TestRequeuesWhenNoArtifactExists covers a run that died before the provider
// produced anything at all.
func TestRequeuesWhenNoArtifactExists(t *testing.T) {
	dir := t.TempDir()
	task := inProgressTask(3, time.Now().Add(-time.Hour))

	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 || outcomes[0].Action != ActionRequeued {
		t.Fatalf("outcomes = %+v, want one requeue", outcomes)
	}
	if task.Status != pm.TaskPending {
		t.Errorf("status = %q, want %q", task.Status, pm.TaskPending)
	}
}

// TestStaleArtifactIsNotAdopted is the guard against crediting a run with an
// earlier attempt's success. A file older than the execution being recovered
// describes different work.
func TestStaleArtifactIsNotAdopted(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	// The artifact predates this execution by a day: it is a leftover.
	writeLive(t, dir, 21, "Old run.\n\nTASK_DONE\n", started.Add(-24*time.Hour))

	task := inProgressTask(21, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 {
		t.Fatalf("got %d outcomes, want 1", len(outcomes))
	}
	if outcomes[0].Action != ActionRequeued {
		t.Errorf("action = %q, want %q — a stale artifact must not be adopted",
			outcomes[0].Action, ActionRequeued)
	}
	if task.Status != pm.TaskPending {
		t.Errorf("status = %q, want %q", task.Status, pm.TaskPending)
	}
}

// TestLeavesSettledTasksAlone: reconciliation must be scoped to in_progress.
// Touching a done or pending task would corrupt a plan it was asked to repair.
func TestLeavesSettledTasksAlone(t *testing.T) {
	dir := t.TempDir()
	// Plant a TASK_DONE artifact for every task so that any task the code
	// wrongly considered would visibly change.
	for _, id := range []int{1, 2, 3, 4} {
		writeLive(t, dir, id, "TASK_DONE\n", time.Now())
	}
	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "done", Status: pm.TaskDone},
		{ID: 2, Title: "pending", Status: pm.TaskPending},
		{ID: 3, Title: "failed", Status: pm.TaskFailed},
		{ID: 4, Title: "skipped", Status: pm.TaskSkipped},
	}}

	if outcomes := Reconcile(dir, plan); len(outcomes) != 0 {
		t.Fatalf("got %d outcomes, want 0 — no task was in_progress", len(outcomes))
	}
	for _, want := range []pm.TaskStatus{pm.TaskDone, pm.TaskPending, pm.TaskFailed, pm.TaskSkipped} {
		for _, task := range plan.Tasks {
			if task.Title == string(want) && task.Status != want {
				t.Errorf("task %d status = %q, want %q", task.ID, task.Status, want)
			}
		}
	}
}

// TestSignalMustBeOnItsOwnLine pins the contract to pm.CheckTaskSignal rather
// than to substring matching: an agent discussing the token in prose has not
// finished, and adopting that would fabricate a completion.
func TestSignalMustBeOnItsOwnLine(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	writeLive(t, dir, 9,
		"I will emit TASK_DONE once the build passes, but it is still running.\n",
		started.Add(time.Minute))

	task := inProgressTask(9, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if outcomes[0].Action != ActionRequeued {
		t.Errorf("action = %q, want %q — prose mentioning the signal is not a completion",
			outcomes[0].Action, ActionRequeued)
	}
}

// TestOversizedArtifactUsesTailAndSaysSo: the signal lives on the last line, so
// an over-long artifact must be read from the end — and the persisted
// transcript must admit it is partial rather than pose as the whole run.
func TestOversizedArtifactUsesTailAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)

	big := strings.Repeat("x", maxLiveArtifactBytes+4096) + "\nTASK_DONE\n"
	writeLive(t, dir, 44, big, started.Add(time.Minute))

	task := inProgressTask(44, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 || outcomes[0].Action != ActionAdopted {
		t.Fatalf("outcomes = %+v, want one adoption from the tail", outcomes)
	}
	if task.Status != pm.TaskDone {
		t.Errorf("status = %q, want %q", task.Status, pm.TaskDone)
	}
	if task.ArtifactPath == "" {
		t.Fatal("no artifact written for the oversized case")
	}
	data, err := os.ReadFile(filepath.Join(dir, task.ArtifactPath))
	if err != nil {
		t.Fatalf("read recovered artifact: %v", err)
	}
	if !strings.Contains(string(data), "recovered from a truncated live artifact") {
		t.Error("a truncated recovery must say so in the artifact")
	}
}

// TestNilSafety: recovery runs on startup paths where the plan may be absent.
func TestNilSafety(t *testing.T) {
	if outcomes := Reconcile(t.TempDir(), nil); outcomes != nil {
		t.Errorf("Reconcile(nil plan) = %+v, want nil", outcomes)
	}
	plan := &pm.Plan{Tasks: []*pm.Task{nil, {ID: 1, Status: pm.TaskPending}}}
	if outcomes := Reconcile(t.TempDir(), plan); len(outcomes) != 0 {
		t.Errorf("Reconcile with a nil task = %+v, want none", outcomes)
	}
}

// TestAnnotationsExplainTheRepair: a status that changed by itself needs to say
// why, or the next person to read the plan has no way to tell recovery from a
// real execution.
func TestAnnotationsExplainTheRepair(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	writeLive(t, dir, 5, "TASK_DONE\n", started.Add(time.Minute))
	adopted := inProgressTask(5, started)

	writeLive(t, dir, 6, "cut off mid-", started.Add(time.Minute))
	requeued := inProgressTask(6, started)

	Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{adopted, requeued}})

	if len(adopted.Annotations) == 0 {
		t.Fatal("adopted task carries no annotation")
	}
	if !strings.Contains(adopted.Annotations[0].Text, "died before recording") {
		t.Errorf("adopted annotation does not explain the repair: %q", adopted.Annotations[0].Text)
	}
	if len(requeued.Annotations) == 0 {
		t.Fatal("requeued task carries no annotation")
	}
	if !strings.Contains(requeued.Annotations[0].Text, "Reset to pending") {
		t.Errorf("requeued annotation does not explain the repair: %q", requeued.Annotations[0].Text)
	}
}
