package orchestrator

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

func TestApplyBackgroundOutcome(t *testing.T) {
	tests := []struct {
		name       string
		activity   *provider.BackgroundActivity
		signal     pm.TaskStatus
		wantSignal pm.TaskStatus
		wantState  pm.BackgroundState
		wantNil    bool
	}{
		{
			name:       "no background work leaves the signal alone",
			activity:   nil,
			signal:     pm.TaskDone,
			wantSignal: pm.TaskDone,
			wantNil:    true,
		},
		{
			name:       "zero detections is not background work",
			activity:   &provider.BackgroundActivity{Detected: 0},
			signal:     pm.TaskDone,
			wantSignal: pm.TaskDone,
			wantNil:    true,
		},
		{
			// The agent left work running, cloop waited, the work finished.
			// The output can be trusted, so the task keeps its own verdict.
			name: "drained work keeps the task done",
			activity: &provider.BackgroundActivity{
				Detected: 1, Drained: true, Waited: 90 * time.Second, Commands: []string{"python3"},
			},
			signal:     pm.TaskDone,
			wantSignal: pm.TaskDone,
			wantState:  pm.BackgroundDrained,
		},
		{
			// The headline case: TASK_DONE describing work that never
			// finished must not be accepted, or dependents consume a
			// half-written artifact.
			name: "abandoned work overrides TASK_DONE",
			activity: &provider.BackgroundActivity{
				Detected: 2, Drained: false, Waited: 30 * time.Minute, Terminated: 2,
			},
			signal:     pm.TaskDone,
			wantSignal: pm.TaskFailed,
			wantState:  pm.BackgroundAbandoned,
		},
		{
			// An unsignalled task is implicitly treated as done, so it needs
			// the same override or the bug survives through that arm.
			name:       "abandoned work overrides an implicit completion",
			activity:   &provider.BackgroundActivity{Detected: 1, Drained: false, Waited: time.Minute},
			signal:     pm.TaskInProgress,
			wantSignal: pm.TaskFailed,
			wantState:  pm.BackgroundAbandoned,
		},
		{
			name:       "already-failed task keeps its failure",
			activity:   &provider.BackgroundActivity{Detected: 1, Drained: false, Waited: time.Minute},
			signal:     pm.TaskFailed,
			wantSignal: pm.TaskFailed,
			wantState:  pm.BackgroundAbandoned,
		},
		{
			// Overwriting a skip would hide the reason the task was skipped.
			name:       "skipped task keeps its skip",
			activity:   &provider.BackgroundActivity{Detected: 1, Drained: false, Waited: time.Minute},
			signal:     pm.TaskSkipped,
			wantSignal: pm.TaskSkipped,
			wantState:  pm.BackgroundAbandoned,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			task := &pm.Task{ID: 48, Title: "Train the model"}
			got := applyBackgroundOutcome(task, tc.activity, tc.signal)
			if got != tc.wantSignal {
				t.Errorf("signal = %q, want %q", got, tc.wantSignal)
			}
			if tc.wantNil {
				if task.Background != nil {
					t.Errorf("expected no background record, got %+v", task.Background)
				}
				return
			}
			if task.Background == nil {
				t.Fatal("expected a background record")
			}
			if task.Background.State != tc.wantState {
				t.Errorf("state = %q, want %q", task.Background.State, tc.wantState)
			}
			if len(task.Annotations) == 0 {
				t.Error("the reason must be annotated on the task, not only logged")
			}
		})
	}
}

// TestApplyBackgroundOutcomeClearsStaleWaiting covers the sequence a heal or
// clarify retry produces: the first attempt registered a live "waiting"
// record, the retry left nothing behind, and the task must not keep claiming
// it is blocked on work that no longer exists.
func TestApplyBackgroundOutcomeClearsStaleWaiting(t *testing.T) {
	task := &pm.Task{ID: 7, Background: &pm.BackgroundWork{State: pm.BackgroundWaiting, Detected: 3}}
	got := applyBackgroundOutcome(task, nil, pm.TaskDone)
	if got != pm.TaskDone {
		t.Errorf("signal = %q, want done", got)
	}
	if task.Background != nil {
		t.Errorf("a stale waiting record must be cleared, got %+v", task.Background)
	}
}

// A finished record from an earlier attempt is replaced, not cleared, so the
// history of what happened stays attached to the task.
func TestApplyBackgroundOutcomeReplacesFinishedRecord(t *testing.T) {
	task := &pm.Task{ID: 7, Background: &pm.BackgroundWork{State: pm.BackgroundDrained, Detected: 3}}
	applyBackgroundOutcome(task, &provider.BackgroundActivity{
		Detected: 1, Drained: false, Waited: time.Minute,
	}, pm.TaskDone)
	if task.Background == nil || task.Background.State != pm.BackgroundAbandoned {
		t.Fatalf("expected the new outcome to replace the old, got %+v", task.Background)
	}
	if task.Background.Detected != 1 {
		t.Errorf("detected = %d, want 1 from the latest attempt", task.Background.Detected)
	}
}

func TestResolveBackgroundFields(t *testing.T) {
	work := resolveBackground(&provider.BackgroundActivity{
		Detected: 3, Commands: []string{"python3", "tee"},
		Waited: 125 * time.Second, Drained: false, Terminated: 3,
	})
	if work == nil {
		t.Fatal("expected a record")
	}
	if work.WaitedSeconds != 125 {
		t.Errorf("WaitedSeconds = %d, want 125", work.WaitedSeconds)
	}
	if work.Terminated != 3 {
		t.Errorf("Terminated = %d, want 3", work.Terminated)
	}
	if len(work.Commands) != 2 {
		t.Errorf("Commands = %v, want both preserved for diagnosis", work.Commands)
	}
	if work.DetectedAt.IsZero() {
		t.Error("DetectedAt must be set")
	}
}

// The diagnosis is fed back to the agent on a retry, so it has to name the
// remedy rather than only the symptom.
func TestBackgroundFailureDiagnosis(t *testing.T) {
	if got := backgroundFailureDiagnosis(nil); got != "" {
		t.Errorf("nil work has no diagnosis, got %q", got)
	}
	got := backgroundFailureDiagnosis(&pm.BackgroundWork{
		State: pm.BackgroundAbandoned, Detected: 2,
		Commands: []string{"train.py"}, WaitedSeconds: 1800, Terminated: 2,
	})
	for _, want := range []string{"train.py", "1800", "TASK_FAILED", "terminated"} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnosis missing %q: %s", want, got)
		}
	}
}

func TestNoteBackgroundWait(t *testing.T) {
	work := noteBackgroundWait(provider.BackgroundActivity{
		Detected: 2, Commands: []string{"sleep", "python3"},
	})
	if work.State != pm.BackgroundWaiting {
		t.Errorf("state = %q, want waiting", work.State)
	}
	if !work.Pending() {
		t.Error("a waiting record must report Pending")
	}
	if work.Detected != 2 || len(work.Commands) != 2 {
		t.Errorf("unexpected record %+v", work)
	}
}

// TestBackgroundBlocksDependents is the property the whole fix exists to
// protect, asserted against the real dependency gate rather than a
// reimplementation of it: tasks 49-51 must not run while task 48's work is
// unfinished.
func TestBackgroundBlocksDependents(t *testing.T) {
	trainer := &pm.Task{ID: 48, Title: "Train the model", Status: pm.TaskInProgress}
	plan := &pm.Plan{Tasks: []*pm.Task{
		trainer,
		{ID: 49, Title: "Evaluate the model", Status: pm.TaskPending, DependsOn: []int{48}},
		{ID: 50, Title: "Export the model", Status: pm.TaskPending, DependsOn: []int{48}},
		{ID: 51, Title: "Publish metrics", Status: pm.TaskPending, DependsOn: []int{48}},
	}}

	// The agent claims success while the training it started is still running.
	signal := applyBackgroundOutcome(trainer, &provider.BackgroundActivity{
		Detected: 1, Commands: []string{"python3"}, Waited: 30 * time.Minute,
	}, pm.TaskDone)
	trainer.Status = signal

	if trainer.Status == pm.TaskDone {
		t.Fatal("the trainer must not be marked done while its work is running")
	}
	for _, dep := range plan.Tasks[1:] {
		if plan.DepsReady(dep) {
			t.Errorf("task #%d must be blocked while #48 is unfinished", dep.ID)
		}
	}
	if next := plan.NextTask(); next != nil {
		t.Errorf("no dependent task should be runnable, got #%d", next.ID)
	}

	// Once the work genuinely finishes, the dependents unblock.
	trainer.Status = pm.TaskDone
	for _, dep := range plan.Tasks[1:] {
		if !plan.DepsReady(dep) {
			t.Errorf("task #%d should be ready once #48 is done", dep.ID)
		}
	}
}
