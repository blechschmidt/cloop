package statedb

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestBackgroundRoundTrip guards the persistence half of Task 20205.
//
// The field is what the UI renders and what an operator reads when asking why
// three downstream tasks produced nonsense. Held only in memory it would be
// gone at the first save, and every layer above would still look correct —
// which is exactly how it was missed the first time.
func TestBackgroundRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	detected := time.Now().UTC().Truncate(time.Second)
	tasks := []*pm.Task{
		{
			ID: 48, Title: "Train the model", Status: pm.TaskFailed,
			Background: &pm.BackgroundWork{
				State: pm.BackgroundAbandoned, Detected: 2,
				Commands: []string{"python3", "tee"}, WaitedSeconds: 1800,
				Terminated: 2, DetectedAt: detected,
			},
		},
		{
			ID: 49, Title: "Evaluate", Status: pm.TaskDone,
			Background: &pm.BackgroundWork{
				State: pm.BackgroundDrained, Detected: 1,
				Commands: []string{"make"}, WaitedSeconds: 95, DetectedAt: detected,
			},
		},
		// A task that never had background work must read back as nil, not as
		// a zero-valued record that the UI would render as a badge.
		{ID: 50, Title: "Publish", Status: pm.TaskPending},
	}
	st := &State{Goal: "train and ship", Plan: &pm.Plan{Goal: "train and ship", Tasks: tasks}}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	reloaded, err := db.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	loaded := reloaded.Plan.Tasks
	if len(loaded) != 3 {
		t.Fatalf("got %d tasks, want 3", len(loaded))
	}

	got := loaded[0].Background
	if got == nil {
		t.Fatal("task 48 lost its background record across a save/load")
	}
	if got.State != pm.BackgroundAbandoned {
		t.Errorf("state = %q, want abandoned", got.State)
	}
	if got.Detected != 2 || got.Terminated != 2 || got.WaitedSeconds != 1800 {
		t.Errorf("counters did not survive: %+v", got)
	}
	if len(got.Commands) != 2 || got.Commands[0] != "python3" {
		t.Errorf("commands did not survive: %v", got.Commands)
	}
	if !got.DetectedAt.Equal(detected) {
		t.Errorf("DetectedAt = %v, want %v", got.DetectedAt, detected)
	}

	if loaded[1].Background == nil || loaded[1].Background.State != pm.BackgroundDrained {
		t.Errorf("task 49 background = %+v, want drained", loaded[1].Background)
	}
	if loaded[2].Background != nil {
		t.Errorf("a task with no background work must read back nil, got %+v", loaded[2].Background)
	}

	// LoadTask (single) reads the same column and must agree with LoadTasks.
	one, err := db.LoadTask(48)
	if err != nil {
		t.Fatalf("LoadTask: %v", err)
	}
	if one.Background == nil || one.Background.State != pm.BackgroundAbandoned {
		t.Errorf("LoadTask lost the record: %+v", one.Background)
	}

	// Clearing it must persist too, or a stale "waiting" badge outlives the wait.
	tasks[0].Background = nil
	if err := db.SaveState(st); err != nil {
		t.Fatalf("SaveState (clear): %v", err)
	}
	cleared, err := db.LoadTask(48)
	if err != nil {
		t.Fatalf("LoadTask after clear: %v", err)
	}
	if cleared.Background != nil {
		t.Errorf("cleared record came back: %+v", cleared.Background)
	}
}

func TestDecodeBackgroundTolerance(t *testing.T) {
	for _, raw := range []string{"", "null", "{", "not json", `{"detected":3}`} {
		if got := decodeBackground(raw); got != nil {
			t.Errorf("decodeBackground(%q) = %+v, want nil", raw, got)
		}
	}
	if got := encodeBackground(nil); got != "" {
		t.Errorf("encodeBackground(nil) = %q, want empty", got)
	}
}
