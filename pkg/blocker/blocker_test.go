package blocker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// inProgressSince is a task an agent began working on at started, with no
// checkpoint or artifact written since — the ordinary shape of a long task,
// whose whole turn is one provider call.
func inProgressSince(started time.Time) *pm.Task {
	return &pm.Task{ID: 1, Title: "train the model", Status: pm.TaskInProgress, StartedAt: &started}
}

func hasReason(info *BlockerInfo, want BlockReason) bool {
	for _, r := range info.Reasons {
		if r == want {
			return true
		}
	}
	return false
}

// TestDetectNeverCallsALongRunningTaskStalled is the bug (Task 20479): a task
// in progress for hours with nothing written since it started used to be
// "stalled" thirty minutes in, while its run was executing it. Time spent is
// not evidence; only a run that is gone is.
func TestDetectNeverCallsALongRunningTaskStalled(t *testing.T) {
	task := inProgressSince(time.Now().Add(-5 * time.Hour))
	for _, run := range []Run{RunLive, RunUnknown} {
		info := Detect(t.TempDir(), task, &pm.Plan{Tasks: []*pm.Task{task}}, run)
		if info.Blocked || hasReason(info, BlockReasonStalled) || info.StalledSince != nil {
			t.Errorf("run=%q: a task five hours into its run was reported %+v, want not blocked", run, info)
		}
		if info.Run != run {
			t.Errorf("run=%q: the detection reported run=%q", run, info.Run)
		}
	}
}

// TestDetectCallsAnAbandonedTaskStalled is the other direction: a task in
// progress with nothing executing it is stranded, and that holds however
// recently it started.
func TestDetectCallsAnAbandonedTaskStalled(t *testing.T) {
	started := time.Now().Add(-time.Second)
	task := inProgressSince(started)
	info := Detect(t.TempDir(), task, &pm.Plan{Tasks: []*pm.Task{task}}, RunGone)
	if !info.Blocked || !hasReason(info, BlockReasonStalled) {
		t.Fatalf("a task in progress with no run executing it = %+v, want blocked as stalled", info)
	}
	if info.StalledSince == nil || !info.StalledSince.Equal(started) {
		t.Errorf("StalledSince = %v, want the task's start %v — it has no later activity", info.StalledSince, started)
	}
	if info.StalledSince == task.StartedAt {
		t.Error("StalledSince aliases the task's own StartedAt; a caller editing one would edit the other")
	}
}

// TestStalledSinceIsTheLastActivity: when the task did write something before
// its run went away, that — not its start — is when it last moved.
func TestStalledSinceIsTheLastActivity(t *testing.T) {
	dir := t.TempDir()
	task := inProgressSince(time.Now().Add(-5 * time.Hour))
	histDir := filepath.Join(dir, ".cloop", "task-checkpoints", "task-1")
	if err := os.MkdirAll(histDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(histDir, "0001.json")
	if err := os.WriteFile(cp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	last := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(cp, last, last); err != nil {
		t.Fatal(err)
	}

	info := Detect(dir, task, nil, RunGone)
	if info.StalledSince == nil || !info.StalledSince.Equal(last) {
		t.Errorf("StalledSince = %v, want the newest checkpoint write %v", info.StalledSince, last)
	}

	// The same checkpoint history says nothing about a task a run is on.
	if live := Detect(dir, task, nil, RunLive); live.Blocked {
		t.Errorf("with a run executing it the task was reported %+v", live)
	}
}

// TestOnlyATaskInProgressStalls: a pending or failed task is not being worked
// on, so a project with no run says nothing about it.
func TestOnlyATaskInProgressStalls(t *testing.T) {
	for _, status := range []pm.TaskStatus{pm.TaskPending, pm.TaskFailed, pm.TaskDone, pm.TaskSkipped} {
		task := &pm.Task{ID: 1, Title: "x", Status: status}
		if info := Detect(t.TempDir(), task, nil, RunGone); hasReason(info, BlockReasonStalled) {
			t.Errorf("a %s task was called stalled", status)
		}
	}
}

// TestTheOtherHeuristicsIgnoreTheRun: a failed dependency and a "blocked"
// annotation block a task whatever is or is not executing its project.
func TestTheOtherHeuristicsIgnoreTheRun(t *testing.T) {
	dep := &pm.Task{ID: 2, Title: "fetch the data", Status: pm.TaskFailed}
	task := &pm.Task{ID: 1, Title: "train", Status: pm.TaskPending, DependsOn: []int{2},
		Annotations: []pm.Annotation{{Author: "me", Text: "Blocked on the GPU quota"}}}
	plan := &pm.Plan{Tasks: []*pm.Task{task, dep}}
	for _, run := range []Run{RunLive, RunUnknown, RunGone} {
		info := Detect(t.TempDir(), task, plan, run)
		if !info.Blocked || !hasReason(info, BlockReasonFailedDep) || !hasReason(info, BlockReasonAnnotation) {
			t.Errorf("run=%q: got %+v, want blocked by the failed dependency and the annotation", run, info)
		}
		if len(info.FailedDeps) != 1 || info.FailedDeps[0] != 2 {
			t.Errorf("run=%q: FailedDeps = %v, want [2]", run, info.FailedDeps)
		}
	}
}

// TestDetectAllReportsOnlyBlockedOpenTasks: finished tasks are not scanned, and
// a long task with its run executing is not in the list.
func TestDetectAllReportsOnlyBlockedOpenTasks(t *testing.T) {
	long := inProgressSince(time.Now().Add(-5 * time.Hour))
	failed := &pm.Task{ID: 2, Title: "fetch", Status: pm.TaskFailed}
	waiting := &pm.Task{ID: 3, Title: "evaluate", Status: pm.TaskPending, DependsOn: []int{2}}
	done := &pm.Task{ID: 4, Title: "old", Status: pm.TaskDone, Annotations: []pm.Annotation{{Text: "was blocked"}}}
	plan := &pm.Plan{Tasks: []*pm.Task{long, failed, waiting, done}}

	got := DetectAll(t.TempDir(), plan, RunLive)
	if len(got) != 1 || got[0].TaskID != 3 {
		t.Fatalf("DetectAll with a run executing = %+v, want only task 3 (failed dependency)", got)
	}

	got = DetectAll(t.TempDir(), plan, RunGone)
	ids := map[int]bool{}
	for _, b := range got {
		ids[b.TaskID] = true
	}
	if len(got) != 2 || !ids[1] || !ids[3] {
		t.Fatalf("DetectAll with nothing executing = %+v, want tasks 1 (stalled) and 3", got)
	}
}

// promptCapture is a provider that records the prompt it was given.
type promptCapture struct{ prompt string }

func (p *promptCapture) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	p.prompt = prompt
	return &provider.Result{Output: `{"root_cause":"r","actions":["a","b","c"],"recommendation":"retry"}`}, nil
}
func (p *promptCapture) Name() string         { return "capture" }
func (p *promptCapture) DefaultModel() string { return "" }

// TestAnalyzeTellsTheModelALiveTaskIsNotStuck: the analysis prompt presumes a
// stuck task, and a model told only "in progress since five hours ago" reads
// the hours as the problem. With a run executing the task, the prompt says so
// and does not call it stalled; without one, it does.
func TestAnalyzeTellsTheModelALiveTaskIsNotStuck(t *testing.T) {
	task := inProgressSince(time.Now().Add(-5 * time.Hour))
	plan := &pm.Plan{Goal: "ship", Tasks: []*pm.Task{task}}

	p := &promptCapture{}
	report, err := Analyze(context.Background(), p, "", time.Minute, task, plan, t.TempDir(), RunLive)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if strings.Contains(p.prompt, "STALLED") {
		t.Errorf("the prompt for a task its run is executing calls it stalled:\n%s", p.prompt)
	}
	if !strings.Contains(p.prompt, "a run is executing this task right now") {
		t.Errorf("the prompt does not tell the model a run is executing the task:\n%s", p.prompt)
	}
	if report.Detection == nil || report.Detection.Blocked || report.Detection.Run != RunLive {
		t.Errorf("report detection = %+v, want not blocked with run=live", report.Detection)
	}

	p = &promptCapture{}
	if _, err := Analyze(context.Background(), p, "", time.Minute, task, plan, t.TempDir(), RunGone); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !strings.Contains(p.prompt, "STALLED: the task is in_progress but no run is executing it") {
		t.Errorf("the prompt for a task nothing is executing does not call it stalled:\n%s", p.prompt)
	}
	if strings.Contains(p.prompt, "a run is executing this task right now") {
		t.Errorf("the prompt for an abandoned task claims a run is executing it:\n%s", p.prompt)
	}
}

// TestRunIsOmittedFromJSONWhenUnknown: the detection says what it was told
// about the run, and says nothing when nobody could tell.
func TestRunIsOmittedFromJSONWhenUnknown(t *testing.T) {
	for run, want := range map[Run]string{RunUnknown: "", RunLive: `"run":"live"`, RunGone: `"run":"gone"`} {
		b, err := json.Marshal(&BlockerInfo{TaskID: 1, Run: run})
		if err != nil {
			t.Fatal(err)
		}
		got := string(b)
		if want == "" && strings.Contains(got, `"run"`) {
			t.Errorf("run=unknown marshalled as %s, want no run key", got)
		}
		if want != "" && !strings.Contains(got, want) {
			t.Errorf("run=%q marshalled as %s, want %s", run, got, want)
		}
	}
}
