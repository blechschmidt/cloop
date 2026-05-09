package filewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"**/*.go", "main.go", true},
		{"**/*.go", "pkg/foo/bar.go", true},
		{"**/*.go", "pkg/foo/bar.ts", false},
		{"*.go", "main.go", true},
		{"*.go", "pkg/main.go", true}, // base name match
		{"src/**/*.ts", "src/components/app.ts", true},
		{"src/**/*.ts", "src/app.ts", true},
		{"src/**/*.ts", "lib/app.ts", false},
		{"**/*.go", ".cloop/state.json", false},
	}
	for _, tc := range tests {
		got := matchGlob(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v; want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestMatchesAnyGlob(t *testing.T) {
	globs := []string{"**/*.go", "**/*.ts"}
	if !matchesAnyGlob("pkg/foo.go", globs) {
		t.Error("expected pkg/foo.go to match")
	}
	if !matchesAnyGlob("src/app.ts", globs) {
		t.Error("expected src/app.ts to match")
	}
	if matchesAnyGlob("README.md", globs) {
		t.Error("expected README.md not to match")
	}
}

func TestResetRelevantTasks(t *testing.T) {
	plan := &pm.Plan{
		Goal: "test",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Write tests", Status: pm.TaskDone},
			{ID: 2, Title: "Fix handler", Description: "Fix the auth handler", Status: pm.TaskFailed},
			{ID: 3, Title: "Deploy service", Status: pm.TaskDone},
			{ID: 4, Title: "Update auth middleware", Status: pm.TaskInProgress},
		},
	}

	// Change to auth.go — should reset task 2 (failed), 4 (in_progress), and 1 (title match "tests" vs test)
	resetIDs := resetRelevantTasks(plan, []string{"pkg/auth.go"})

	// Task 2 must be reset (failed).
	// Task 4 must be reset (in_progress).
	assertContains(t, resetIDs, 2, "failed task should always reset")
	assertContains(t, resetIDs, 4, "in_progress task should always reset")

	// Task 2 and 4 status must be pending.
	for _, task := range plan.Tasks {
		if task.ID == 2 || task.ID == 4 {
			if task.Status != pm.TaskPending {
				t.Errorf("task %d: expected pending, got %s", task.ID, task.Status)
			}
		}
	}
}

func TestBuildChangeContext(t *testing.T) {
	plan := &pm.Plan{
		Tasks: []*pm.Task{
			{ID: 1, Title: "Write tests"},
			{ID: 2, Title: "Fix auth"},
		},
	}
	ctx := buildChangeContext([]string{"auth.go", "handler.go"}, []int{1, 2}, plan)
	if ctx == "" {
		t.Error("expected non-empty context string")
	}
	if len(ctx) < 10 {
		t.Errorf("context too short: %q", ctx)
	}
}

func assertContains(t *testing.T, ids []int, id int, msg string) {
	t.Helper()
	for _, v := range ids {
		if v == id {
			return
		}
	}
	t.Errorf("%s: ID %d not found in %v", msg, id, ids)
}

// TestRun_NoRaceOnConcurrentEvents exercises the debounce/pending logic under a
// flood of file changes. Before the pendingMu fix, the main select loop wrote
// to the `pending` map while the time.AfterFunc-spawned trigger goroutine
// iterated and deleted from it — `go test -race` fatals with
// "concurrent map iteration and map write" or reports a data race.
func TestRun_NoRaceOnConcurrentEvents(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal PM-mode state so applyReEvaluation has work to do
	// (resetRelevantTasks runs against a real plan).
	s, err := state.Init(tmpDir, "test", 10)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "test",
		Tasks: []*pm.Task{
			{ID: 1, Title: "fix file", Status: pm.TaskFailed},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	// Pre-create a watched subdirectory so resolveWatchDirs picks it up.
	subDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Seed one file so the directory is recognized as containing matches.
	if err := os.WriteFile(filepath.Join(subDir, "seed.go"), []byte("package src"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		WorkDir:  tmpDir,
		Globs:    []string{"src/**/*.go"},
		Debounce: 5 * time.Millisecond, // very tight to maximize concurrent fire/append
	}

	var triggerCount int32
	onTrigger := func(evt ChangeEvent) {
		atomic.AddInt32(&triggerCount, 1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, cfg, onTrigger)
	}()

	// Give the watcher a moment to start.
	time.Sleep(80 * time.Millisecond)

	// Hammer with file changes. Periodic small sleeps let the debounce timer
	// fire mid-burst, so fireTrigger runs concurrently with the next batch's
	// pending writes — that's the race we want the detector to catch.
	for i := 0; i < 300; i++ {
		path := filepath.Join(subDir, fmt.Sprintf("file%d.go", i))
		if err := os.WriteFile(path, []byte("package src"), 0644); err != nil {
			t.Fatal(err)
		}
		if i%15 == 0 {
			time.Sleep(7 * time.Millisecond)
		}
	}

	// Let any final debounced trigger fire.
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s after cancel")
	}

	if atomic.LoadInt32(&triggerCount) == 0 {
		t.Error("expected at least one trigger to fire from file changes")
	}
}
