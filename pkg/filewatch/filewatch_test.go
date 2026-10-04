package filewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
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

// TestRun_NoRaceOnConcurrentEvents exercises the debounce/batch hand-off under
// a flood of file changes: the select loop moves each expired window's files
// into the ready batch while the trigger worker takes and clears it. Before
// that map was guarded (it was then shared with a time.AfterFunc goroutine),
// `go test -race` fataled with "concurrent map iteration and map write" or
// reported a data race.
//
// A flood like this one also used to leave a trigger goroutine applying its
// batch for every window that had expired, and shutdown waited for all of
// them after cancel: 2-2.5s on a lightly loaded machine, over 3s on a loaded
// CI runner.
func TestRun_NoRaceOnConcurrentEvents(t *testing.T) {
	tmpDir := statedbtest.Dir(t)

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

	// After cancel Run finishes at most the batch it has in flight — one
	// state load and save — and starts no other.
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

// TestRun_OneBatchAtATimeAndNoneAfterCancel pins the order Run applies
// batches in. It holds the first batch inside onTrigger while more changes
// arrive behind it, then cancels: a correct Run waits for the held batch and
// applies nothing else, so onTrigger runs exactly once. When every expired
// debounce window got a goroutine of its own, the batches behind the held one
// were applied alongside it and, once cancelled, after it.
//
// The sleeps below only give a regression time to show itself; however a
// loaded machine stretches or starves them, a correct Run passes.
func TestRun_OneBatchAtATimeAndNoneAfterCancel(t *testing.T) {
	tmpDir := statedbtest.Dir(t)
	s, err := state.Init(tmpDir, "test", 10)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "test", Tasks: []*pm.Task{{ID: 1, Title: "fix file", Status: pm.TaskFailed}}}
	if err := s.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	subDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(subDir, name), []byte("package src"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("seed.go")

	cfg := Config{WorkDir: tmpDir, Globs: []string{"src/**/*.go"}, Debounce: 5 * time.Millisecond}

	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHeld := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHeld) // a failed assertion must not leave Run blocked in onTrigger
	onTrigger := func(ChangeEvent) {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
		}
		<-release
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, cfg, onTrigger)
	}()

	// fsnotify has no readiness signal, and a change made before Run has
	// added its watches is never seen: keep changing a file until the first
	// batch is being applied. Probing far slower than the debounce keeps the
	// probe from being a flood of its own. 10s only turns a Run that never
	// applies anything into a failure instead of a hang.
	noBatch := time.After(10 * time.Second)
	for held := false; !held; {
		write("probe.go")
		select {
		case <-entered:
			held = true
		case <-time.After(100 * time.Millisecond):
		case <-noBatch:
			t.Fatal("no batch reached onTrigger within 10s of the first change")
		}
	}

	// More changes behind the held batch. Their debounce windows expire while
	// it is still being applied, so they must wait for it.
	for i := 0; i < 10; i++ {
		write(fmt.Sprintf("file%d.go", i))
	}
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case <-runDone:
		t.Fatal("Run returned while a batch was still being applied")
	case <-time.After(50 * time.Millisecond):
	}
	releaseHeld()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second): // hang guard: nothing is left to wait for
		t.Fatal("Run did not return after the batch in flight finished")
	}

	if n := calls.Load(); n != 1 {
		t.Fatalf("onTrigger ran %d times, want 1: the changes queued behind the batch in flight must be dropped at cancel, not applied alongside or after it", n)
	}
}
