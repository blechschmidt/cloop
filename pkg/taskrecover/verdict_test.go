package taskrecover

// Tests for the orchestrator's verdict sidecar (Task 20365): recovery applies
// what the orchestrator decided before it falls back to what the agent said.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// rejectedVerdict is the review gate failing a task the agent called done.
func rejectedVerdict(taskID int, started time.Time) Verdict {
	return Verdict{
		TaskID:    taskID,
		Status:    pm.TaskFailed,
		Source:    SourceReviewGate,
		Reason:    "review_blocked",
		Detail:    "Review gate: changes requested by strict-model (1 finding(s)) — not published.",
		Summary:   "Committed the change.\nTASK_DONE",
		Diagnosis: "Review gate: changes requested.\n- [major] calc.txt:1: division by zero",
		Review:    &pm.TaskReview{Verdict: pm.ReviewChangesRequested, Blocked: true, Model: "strict-model", Rounds: 1},
		StartedAt: &started,
		WrittenAt: started.Add(10 * time.Minute),
	}
}

func mustWriteVerdict(t *testing.T, dir string, v Verdict) {
	t.Helper()
	if err := WriteVerdict(dir, v); err != nil {
		t.Fatalf("WriteVerdict: %v", err)
	}
}

func hasAnnotation(t *pm.Task, author string, parts ...string) bool {
	for _, a := range t.Annotations {
		if author != "" && a.Author != author {
			continue
		}
		all := true
		for _, p := range parts {
			if !strings.Contains(a.Text, p) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func TestVerdictRoundTrips(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	want := rejectedVerdict(4, started)
	mustWriteVerdict(t, dir, want)

	got, err := ReadVerdict(dir, 4)
	if err != nil {
		t.Fatalf("ReadVerdict: %v", err)
	}
	if got.Format != VerdictFormat || got.TaskID != 4 || got.Status != pm.TaskFailed ||
		got.Source != SourceReviewGate || got.Reason != "review_blocked" || got.Detail != want.Detail ||
		got.Summary != want.Summary || got.Diagnosis != want.Diagnosis {
		t.Fatalf("read back %+v, want %+v", got, want)
	}
	if got.StartedAt == nil || !got.StartedAt.Equal(started) || !got.WrittenAt.Equal(want.WrittenAt) {
		t.Errorf("times did not survive: started %v written %v", got.StartedAt, got.WrittenAt)
	}
	if got.Review == nil || !got.Review.Blocked || got.Review.Model != "strict-model" {
		t.Errorf("review record = %+v", got.Review)
	}
	if filepath.Dir(VerdictPath(dir, 4)) != artifact.LiveArtifactDir(dir) {
		t.Errorf("the sidecar is not next to the live artifact: %s", VerdictPath(dir, 4))
	}
	if _, err := ReadVerdict(dir, 5); err != ErrNoVerdict {
		t.Errorf("a task without a sidecar: err = %v, want ErrNoVerdict", err)
	}

	if err := ClearVerdict(dir, 4); err != nil {
		t.Fatalf("ClearVerdict: %v", err)
	}
	if _, err := ReadVerdict(dir, 4); err != ErrNoVerdict {
		t.Errorf("after ClearVerdict: err = %v, want ErrNoVerdict", err)
	}
	if err := ClearVerdict(dir, 4); err != nil {
		t.Errorf("clearing an absent sidecar is not an error: %v", err)
	}
}

func TestWriteVerdictRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []Verdict{
		{TaskID: 0, Status: pm.TaskDone},
		{TaskID: 1, Status: "finished"},
	} {
		if err := WriteVerdict(dir, v); err == nil {
			t.Errorf("WriteVerdict(%+v) accepted a verdict recovery would refuse", v)
		}
	}
}

// The case the sidecar exists for: the agent printed TASK_DONE, the review
// gate failed the task, and the run died before the failure was stored.
func TestReconcileAppliesTheVerdictOverTheAgentsSignal(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	writeLive(t, dir, 3, "Committed the change.\n\nTASK_DONE\n", started.Add(9*time.Minute))
	mustWriteVerdict(t, dir, rejectedVerdict(3, started))

	task := inProgressTask(3, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 || outcomes[0].Action != ActionAdopted || outcomes[0].Verdict == nil {
		t.Fatalf("outcomes = %+v, want the verdict applied", outcomes)
	}
	if task.Status != pm.TaskFailed {
		t.Fatalf("status = %q: recovery resurrected a task the review gate rejected", task.Status)
	}
	if !strings.Contains(task.FailureDiagnosis, "division by zero") {
		t.Errorf("diagnosis = %q, want the reviewer's findings", task.FailureDiagnosis)
	}
	if task.Review == nil || !task.Review.Blocked {
		t.Errorf("review record not restored: %+v", task.Review)
	}
	if task.CompletedAt == nil || !task.CompletedAt.Equal(started.Add(10*time.Minute)) {
		t.Errorf("CompletedAt = %v, want when the decision was made", task.CompletedAt)
	}
	if !hasAnnotation(task, "cloop", "review gate", "review_blocked", "TASK_DONE") {
		t.Errorf("the annotation does not say who decided and what the agent claimed: %+v", task.Annotations)
	}
	// The transcript is still kept, as it is for an adopted outcome.
	if task.ArtifactPath == "" || !strings.Contains(task.Result, "Committed the change") {
		t.Errorf("transcript not kept: artifact %q result %q", task.ArtifactPath, task.Result)
	}
}

func TestReconcileRequeuesWhenTheVerdictSaysSo(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	writeLive(t, dir, 9, "Done.\nTASK_DONE\n", started.Add(time.Minute))
	mustWriteVerdict(t, dir, Verdict{TaskID: 9, Status: pm.TaskPending, Source: SourceVerify, Reason: "verify_failed",
		Detail: "AI verification failed; re-queued (attempt 1/2)", StartedAt: &started, WrittenAt: started.Add(2 * time.Minute)})

	task := inProgressTask(9, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 || outcomes[0].Action != ActionRequeued || outcomes[0].Verdict == nil {
		t.Fatalf("outcomes = %+v, want a requeue following the verdict", outcomes)
	}
	if task.Status != pm.TaskPending || task.StartedAt != nil {
		t.Fatalf("status %q started %v, want pending with the start cleared", task.Status, task.StartedAt)
	}
	if !strings.Contains(outcomes[0].Reason, "verification failed") {
		t.Errorf("reason = %q, want the verdict's", outcomes[0].Reason)
	}
}

// A verdict written before this execution started belongs to an earlier
// attempt: the rule the live artifact is held to.
func TestReconcileIgnoresAStaleVerdict(t *testing.T) {
	dir := t.TempDir()
	earlier := time.Now().Add(-3 * time.Hour)
	started := time.Now().Add(-time.Hour)
	mustWriteVerdict(t, dir, rejectedVerdict(5, earlier)) // written two hours before this start
	writeLive(t, dir, 5, "Done.\nTASK_DONE\n", started.Add(time.Minute))

	task := inProgressTask(5, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 || outcomes[0].Verdict != nil || task.Status != pm.TaskDone {
		t.Fatalf("status %q, outcomes %+v: an earlier attempt's verdict decided this one", task.Status, outcomes)
	}
}

// A verdict that names another start belongs to another execution, even when
// a clock that disagrees with this one dates it after the start.
func TestReconcileIgnoresAVerdictForAnotherStart(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	other := started.Add(-5 * time.Minute)
	v := rejectedVerdict(6, other)
	v.WrittenAt = started.Add(time.Minute)
	mustWriteVerdict(t, dir, v)
	writeLive(t, dir, 6, "Done.\nTASK_DONE\n", started.Add(2*time.Minute))

	task := inProgressTask(6, started)
	Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})
	if task.Status != pm.TaskDone {
		t.Fatalf("status = %q, want the agent's report: the verdict was another execution's", task.Status)
	}
}

func TestReconcileFallsBackFromACorruptVerdictWithANote(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	writeLive(t, dir, 8, "Done.\nTASK_DONE\n", started.Add(time.Minute))
	if err := os.WriteFile(VerdictPath(dir, 8), []byte(`{"format":1,"task_id":8,"status":"fai`), 0o644); err != nil {
		t.Fatal(err)
	}

	task := inProgressTask(8, started)
	outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})

	if len(outcomes) != 1 || outcomes[0].Action != ActionAdopted || task.Status != pm.TaskDone {
		t.Fatalf("status %q, outcomes %+v: a corrupt verdict must fall back to the agent's report", task.Status, outcomes)
	}
	if !hasAnnotation(task, "", "verdict on it could not be read") {
		t.Errorf("the fallback is not noted on the task: %+v", task.Annotations)
	}
}

// Multi-agent and consensus runs keep no live artifact; a verdict alone still
// decides, and its summary stands in for the transcript.
func TestReconcileAppliesAVerdictWithoutALiveArtifact(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	mustWriteVerdict(t, dir, Verdict{TaskID: 2, Status: pm.TaskDone, Source: SourceAgent, Reason: "agent_done",
		Summary: "All three passes agreed.", StartedAt: &started, WrittenAt: started.Add(time.Minute)})

	task := inProgressTask(2, started)
	Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})
	if task.Status != pm.TaskDone || task.Result != "All three passes agreed." {
		t.Fatalf("status %q result %q", task.Status, task.Result)
	}
}

// While the review gate has not decided, a TASK_DONE is a claim nobody
// reviewed, and nothing behind it was published: the task runs again. A
// failure or skip the gate never sees is still the agent's to report.
func TestReconcileAwaitingReviewBlocksOnlyACompletion(t *testing.T) {
	for _, tc := range []struct {
		signal string
		want   pm.TaskStatus
	}{
		{"TASK_DONE", pm.TaskPending},
		{"TASK_FAILED", pm.TaskFailed},
		{"TASK_SKIPPED", pm.TaskSkipped},
	} {
		t.Run(tc.signal, func(t *testing.T) {
			dir := t.TempDir()
			started := time.Now().Add(-time.Hour)
			mustWriteVerdict(t, dir, Verdict{TaskID: 1, Status: pm.TaskInProgress, Source: SourceReviewGate,
				Reason: ReasonReviewPending, StartedAt: &started, WrittenAt: started.Add(time.Second)})
			writeLive(t, dir, 1, "Work.\n"+tc.signal+"\n", started.Add(time.Minute))

			task := inProgressTask(1, started)
			outcomes := Reconcile(dir, &pm.Plan{Tasks: []*pm.Task{task}})
			if task.Status != tc.want {
				t.Fatalf("status = %q, want %q (%+v)", task.Status, tc.want, outcomes)
			}
			if tc.want == pm.TaskPending && !strings.Contains(outcomes[0].Reason, "review gate had not approved") {
				t.Errorf("reason = %q", outcomes[0].Reason)
			}
		})
	}
}

func TestReadVerdictRefusesSymbolicLinks(t *testing.T) {
	started := time.Now().Add(-time.Hour)

	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		elsewhere := filepath.Join(t.TempDir(), "secret.json")
		if err := os.WriteFile(elsewhere, []byte(`{"format":1,"task_id":3,"status":"done","written_at":"2030-01-01T00:00:00Z"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(artifact.LiveArtifactDir(dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, VerdictPath(dir, 3)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadVerdict(dir, 3); err == nil || err == ErrNoVerdict {
			t.Fatalf("ReadVerdict followed a link: err = %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		real := t.TempDir()
		mustWriteVerdict(t, real, rejectedVerdict(3, started))
		if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(artifact.LiveArtifactDir(real), artifact.LiveArtifactDir(dir)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadVerdict(dir, 3); err == nil || err == ErrNoVerdict {
			t.Fatalf("ReadVerdict followed a linked directory: err = %v", err)
		}
	})
}

func TestReadVerdictRefusesAnotherTasksVerdict(t *testing.T) {
	dir := t.TempDir()
	mustWriteVerdict(t, dir, rejectedVerdict(7, time.Now()))
	if err := os.Rename(VerdictPath(dir, 7), VerdictPath(dir, 8)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerdict(dir, 8); err == nil || !strings.Contains(err.Error(), "names task #7") {
		t.Fatalf("err = %v, want a refusal naming the other task", err)
	}
}

// On a remote device only verdicts are read, and nothing is written: the
// agent reading back a run must not be steered into a file by the workload.
func TestSettleFromVerdictsReadsOnlyVerdicts(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().Add(-time.Hour)
	mustWriteVerdict(t, dir, rejectedVerdict(1, started))
	writeLive(t, dir, 1, "Committed.\nTASK_DONE\n", started.Add(time.Minute))
	writeLive(t, dir, 2, "Committed.\nTASK_DONE\n", started.Add(time.Minute)) // no verdict
	mustWriteVerdict(t, dir, Verdict{TaskID: 3, Status: pm.TaskInProgress, Source: SourceReviewGate,
		Reason: ReasonReviewPending, StartedAt: &started, WrittenAt: started.Add(time.Second)})

	t1, t2, t3 := inProgressTask(1, started), inProgressTask(2, started), inProgressTask(3, started)
	outcomes := SettleFromVerdicts(dir, &pm.Plan{Tasks: []*pm.Task{t1, t2, t3}})

	if len(outcomes) != 1 || outcomes[0].TaskID != 1 || t1.Status != pm.TaskFailed {
		t.Fatalf("outcomes %+v, task 1 %q: want only the decided task settled", outcomes, t1.Status)
	}
	if t1.Result != rejectedVerdict(1, started).Summary {
		t.Errorf("result = %q, want the verdict's summary (the live artifact is not read here)", t1.Result)
	}
	if t2.Status != pm.TaskInProgress || t3.Status != pm.TaskInProgress {
		t.Errorf("undecided tasks were settled: %q, %q", t2.Status, t3.Status)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop", "tasks")); !os.IsNotExist(err) {
		t.Errorf("SettleFromVerdicts wrote a task artifact: %v", err)
	}
	row, details, ok := EventFor(outcomes[0])
	if !ok || row.Type != "task_failed" || !strings.Contains(row.Message, "cloop had decided it") ||
		details["verdict_source"] != SourceReviewGate {
		t.Errorf("journal row = %+v %v", row, details)
	}
}

func TestPruneVerdicts(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	for id := 1; id <= 4; id++ {
		mustWriteVerdict(t, dir, Verdict{TaskID: id, Status: pm.TaskDone, WrittenAt: now})
		if id <= 3 {
			if err := os.Chtimes(VerdictPath(dir, id), old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A staging file a crash left behind, and the live artifacts, which this
	// must not touch.
	tmp := filepath.Join(artifact.LiveArtifactDir(dir), ".5_verdict.json.123.tmp")
	if err := os.WriteFile(tmp, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(tmp, old, old)
	live := writeLive(t, dir, 1, "TASK_DONE\n", old)

	inProgress := func(id int) bool { return id == 2 }
	cutoff := now.Add(-24 * time.Hour)

	dry, err := PruneVerdicts(dir, inProgress, cutoff, true)
	if err != nil || dry.Deleted != 3 {
		t.Fatalf("dry run: %+v %v, want 3 (tasks 1 and 3, and the staging file)", dry, err)
	}
	if _, err := os.Stat(VerdictPath(dir, 1)); err != nil {
		t.Fatal("a dry run deleted a sidecar")
	}

	res, err := PruneVerdicts(dir, inProgress, cutoff, false)
	if err != nil || res.Deleted != 3 || res.Kept != 2 {
		t.Fatalf("prune: %+v %v", res, err)
	}
	for id, want := range map[int]bool{1: false, 2: true, 3: false, 4: true} {
		_, err := os.Stat(VerdictPath(dir, id))
		if got := err == nil; got != want {
			t.Errorf("task %d's sidecar present = %v, want %v", id, got, want)
		}
	}
	if _, err := os.Stat(live); err != nil {
		t.Errorf("the live artifact was pruned: %v", err)
	}
}
