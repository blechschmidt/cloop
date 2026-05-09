package multiui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TestComputeHealth verifies the Health classification for each documented
// state.Status value plus the running-vs-stalled time-based logic.
func TestComputeHealth(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		st   *state.ProjectState
		want Health
	}{
		{
			name: "running with recent UpdatedAt is active",
			st: &state.ProjectState{
				Status:    "running",
				UpdatedAt: now.Add(-1 * time.Minute),
			},
			want: HealthRunning,
		},
		{
			name: "evolving with recent UpdatedAt is active",
			st: &state.ProjectState{
				Status:    "evolving",
				UpdatedAt: now.Add(-1 * time.Minute),
			},
			want: HealthRunning,
		},
		{
			name: "running with stale last step is stalled",
			st: &state.ProjectState{
				Status:    "running",
				UpdatedAt: now.Add(-30 * time.Minute),
				Steps: []state.StepResult{
					{Time: now.Add(-30 * time.Minute)},
				},
			},
			want: HealthStalled,
		},
		{
			name: "running with no steps but old UpdatedAt is stalled",
			st: &state.ProjectState{
				Status:    "running",
				UpdatedAt: now.Add(-30 * time.Minute),
			},
			want: HealthStalled,
		},
		{
			name: "complete",
			st:   &state.ProjectState{Status: "complete"},
			want: HealthComplete,
		},
		{
			name: "failed",
			st:   &state.ProjectState{Status: "failed"},
			want: HealthFailed,
		},
		{
			name: "paused is idle",
			st:   &state.ProjectState{Status: "paused"},
			want: HealthIdle,
		},
		{
			name: "initialized is idle",
			st:   &state.ProjectState{Status: "initialized"},
			want: HealthIdle,
		},
		{
			name: "unknown status with goal is idle",
			st:   &state.ProjectState{Status: "", Goal: "build something"},
			want: HealthIdle,
		},
		{
			name: "unknown status without goal is unknown",
			st:   &state.ProjectState{Status: ""},
			want: HealthUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := computeHealth(tc.st)
			if got != tc.want {
				t.Errorf("computeHealth() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRegistryAddListRemove exercises the AddPaths/Load/Save lifecycle of the
// multi-project registry persisted under $HOME/.cloop/projects.json.
func TestRegistryAddListRemove(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// 1. List on empty registry returns no entries and no error.
	list, err := Load()
	if err != nil {
		t.Fatalf("Load on empty registry: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty registry, got %d entries", len(list))
	}

	// 2. Add three project paths.
	a := t.TempDir()
	b := t.TempDir()
	c := t.TempDir()
	if err := AddPaths([]string{a, b, c}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}

	list, err = Load()
	if err != nil {
		t.Fatalf("Load after AddPaths: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(list))
	}

	gotPaths := []string{list[0].Path, list[1].Path, list[2].Path}
	sort.Strings(gotPaths)
	wantPaths := []string{a, b, c}
	sort.Strings(wantPaths)
	for i := range gotPaths {
		if gotPaths[i] != wantPaths[i] {
			t.Errorf("paths[%d] = %q, want %q", i, gotPaths[i], wantPaths[i])
		}
	}

	// Names default to the basename of each absolute path.
	for _, e := range list {
		if e.Name == "" {
			t.Errorf("entry %q has empty Name", e.Path)
		}
		if e.Name != filepath.Base(e.Path) {
			t.Errorf("entry name = %q, want basename %q", e.Name, filepath.Base(e.Path))
		}
	}

	// 3. Re-adding existing paths must be a no-op (deduplication by path).
	if err := AddPaths([]string{a, b}); err != nil {
		t.Fatalf("AddPaths duplicate: %v", err)
	}
	list, _ = Load()
	if len(list) != 3 {
		t.Errorf("expected dedup to keep 3 entries, got %d", len(list))
	}

	// 4. Remove an entry by saving a filtered list back.
	var filtered []ProjectEntry
	for _, e := range list {
		if e.Path != b {
			filtered = append(filtered, e)
		}
	}
	if err := Save(filtered); err != nil {
		t.Fatalf("Save filtered: %v", err)
	}
	list, _ = Load()
	if len(list) != 2 {
		t.Fatalf("expected 2 entries after remove, got %d", len(list))
	}
	for _, e := range list {
		if e.Path == b {
			t.Errorf("path %q should have been removed", b)
		}
	}

	// 5. Verify the registry was actually written under $HOME/.cloop.
	regPath, err := registryPath()
	if err != nil {
		t.Fatalf("registryPath: %v", err)
	}
	if _, err := os.Stat(regPath); err != nil {
		t.Errorf("registry file missing at %s: %v", regPath, err)
	}
}

// TestPerProjectTaskIsolation verifies that GetStatus for two registered
// projects with distinct state.db files returns isolated task counts and
// metadata — no cross-contamination between projects.
func TestPerProjectTaskIsolation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	p1 := t.TempDir()
	p2 := t.TempDir()

	// Project 1: PM mode, running, 3 tasks (1 done, 1 in-progress, 1 failed).
	s1, err := state.Init(p1, "goal-one", 50)
	if err != nil {
		t.Fatalf("state.Init p1: %v", err)
	}
	s1.PMMode = true
	s1.Status = "running"
	s1.UpdatedAt = time.Now()
	s1.Plan = &pm.Plan{
		Goal: "goal-one",
		Tasks: []*pm.Task{
			{ID: 1, Title: "p1-task-1", Status: pm.TaskDone},
			{ID: 2, Title: "p1-task-2", Status: pm.TaskInProgress},
			{ID: 3, Title: "p1-task-3", Status: pm.TaskFailed},
		},
	}
	if err := s1.SaveDirect(); err != nil {
		t.Fatalf("save p1: %v", err)
	}

	// Project 2: PM mode, complete, 2 tasks (both done).
	s2, err := state.Init(p2, "goal-two", 50)
	if err != nil {
		t.Fatalf("state.Init p2: %v", err)
	}
	s2.PMMode = true
	s2.Status = "complete"
	s2.UpdatedAt = time.Now()
	s2.Plan = &pm.Plan{
		Goal: "goal-two",
		Tasks: []*pm.Task{
			{ID: 1, Title: "p2-task-1", Status: pm.TaskDone},
			{ID: 2, Title: "p2-task-2", Status: pm.TaskDone},
		},
	}
	if err := s2.SaveDirect(); err != nil {
		t.Fatalf("save p2: %v", err)
	}

	// Register both projects.
	if err := AddPaths([]string{p1, p2}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 registered projects, got %d", len(entries))
	}

	// Pick statuses for each project by path so this test is order-independent.
	var st1, st2 ProjectStatus
	for _, e := range entries {
		s := GetStatus(e)
		switch s.Path {
		case p1:
			st1 = s
		case p2:
			st2 = s
		}
	}

	// Project 1 assertions — counts and goal must come from p1's own state.
	if st1.Goal != "goal-one" {
		t.Errorf("p1 goal = %q, want %q", st1.Goal, "goal-one")
	}
	if !st1.HasProject {
		t.Errorf("p1 HasProject = false; want true")
	}
	if st1.TotalTasks != 3 || st1.DoneTasks != 1 || st1.ActiveTasks != 1 || st1.FailedTasks != 1 {
		t.Errorf("p1 counts: total=%d done=%d active=%d failed=%d; want 3/1/1/1",
			st1.TotalTasks, st1.DoneTasks, st1.ActiveTasks, st1.FailedTasks)
	}
	if st1.Health != HealthRunning {
		t.Errorf("p1 health = %v; want %v", st1.Health, HealthRunning)
	}

	// Project 2 assertions — counts and goal must come from p2's own state.
	if st2.Goal != "goal-two" {
		t.Errorf("p2 goal = %q, want %q", st2.Goal, "goal-two")
	}
	if !st2.HasProject {
		t.Errorf("p2 HasProject = false; want true")
	}
	if st2.TotalTasks != 2 || st2.DoneTasks != 2 || st2.ActiveTasks != 0 || st2.FailedTasks != 0 {
		t.Errorf("p2 counts: total=%d done=%d active=%d failed=%d; want 2/2/0/0",
			st2.TotalTasks, st2.DoneTasks, st2.ActiveTasks, st2.FailedTasks)
	}
	if st2.Health != HealthComplete {
		t.Errorf("p2 health = %v; want %v", st2.Health, HealthComplete)
	}

	// Aggregate must sum across projects without double-counting.
	agg := Aggregate([]ProjectStatus{st1, st2})
	if agg.TotalProjects != 2 {
		t.Errorf("agg.TotalProjects = %d; want 2", agg.TotalProjects)
	}
	if agg.TotalTasks != 5 || agg.DoneTasks != 3 || agg.FailedTasks != 1 {
		t.Errorf("agg counts: total=%d done=%d failed=%d; want 5/3/1",
			agg.TotalTasks, agg.DoneTasks, agg.FailedTasks)
	}
}

// TestRegistry_AddPathsConcurrent verifies that two in-process callers racing
// to AddPaths the same registry never lose each other's writes. The previous
// implementation did Load → mutate → Save with no synchronisation, so the
// second saver could overwrite the first saver's addition with a stale baseline.
func TestRegistry_AddPathsConcurrent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const goroutines = 16
	const pathsPerGoroutine = 4

	// Pre-create 64 distinct temp dirs (real directories so filepath.Abs +
	// basename behave normally) and partition them across goroutines.
	allDirs := make([]string, 0, goroutines*pathsPerGoroutine)
	for i := 0; i < goroutines*pathsPerGoroutine; i++ {
		allDirs = append(allDirs, t.TempDir())
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := idx * pathsPerGoroutine
			batch := allDirs[start : start+pathsPerGoroutine]
			if err := AddPaths(batch); err != nil {
				t.Errorf("AddPaths goroutine %d: %v", idx, err)
			}
		}(g)
	}
	wg.Wait()

	got, err := Load()
	if err != nil {
		t.Fatalf("Load after concurrent adds: %v", err)
	}
	gotPaths := make(map[string]bool, len(got))
	for _, e := range got {
		gotPaths[e.Path] = true
	}
	for _, want := range allDirs {
		if !gotPaths[want] {
			t.Errorf("path %q lost during concurrent AddPaths", want)
		}
	}
	if len(got) != len(allDirs) {
		t.Errorf("registry size = %d, want %d (entries possibly duplicated or lost)", len(got), len(allDirs))
	}
}

// TestRegistry_SaveLeavesNoTempFile verifies that a successful Save leaves
// only projects.json behind — no orphaned tmp file from the atomic-write
// scheme. Catches regressions where the rename target is wrong or the cleanup
// defer fires too aggressively and removes the destination file.
func TestRegistry_SaveLeavesNoTempFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Save([]ProjectEntry{{Name: "demo", Path: t.TempDir()}}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	regPath, err := registryPath()
	if err != nil {
		t.Fatalf("registryPath: %v", err)
	}
	dir := filepath.Dir(regPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read registry dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(regPath) {
			continue
		}
		t.Errorf("unexpected file left in registry dir after Save: %q", e.Name())
	}
	// Final file must contain a parseable registry — sanity-check the rename
	// actually published the new content rather than leaving an empty file.
	data, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	var parsed registry
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("registry on disk is not valid JSON: %v", err)
	}
	if len(parsed.Projects) != 1 || parsed.Projects[0].Name != "demo" {
		t.Errorf("registry payload = %+v, want one entry named demo", parsed.Projects)
	}
}

// TestRegistry_SaveAtomic_NoPartialReadDuringConcurrentSaves runs many Saves
// while a parallel reader hammers Load. Without the atomic rename, the reader
// could observe an empty or truncated file and Load would either error or
// return a partial slice. With the rename, every observed file must be a
// fully-parseable registry.
func TestRegistry_SaveAtomic_NoPartialReadDuringConcurrentSaves(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Seed the registry once so Load has something to read.
	if err := Save([]ProjectEntry{{Name: "seed", Path: t.TempDir()}}); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	stop := make(chan struct{})
	writerDone := make(chan struct{})
	readerDone := make(chan struct{})

	// Writer: cycle the registry size up and down repeatedly until stop fires.
	go func() {
		defer close(writerDone)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			n := (i % 8) + 1
			projects := make([]ProjectEntry, n)
			for j := 0; j < n; j++ {
				projects[j] = ProjectEntry{
					Name: fmt.Sprintf("p-%d-%d", i, j),
					Path: fmt.Sprintf("/tmp/path-%d-%d", i, j),
				}
			}
			if err := Save(projects); err != nil {
				t.Errorf("Save iter %d: %v", i, err)
				return
			}
		}
	}()

	// Reader: assert every observation parses cleanly.
	go func() {
		defer close(readerDone)
		for i := 0; i < 500; i++ {
			got, err := Load()
			if err != nil {
				t.Errorf("Load iter %d saw partial/corrupt registry: %v", i, err)
				return
			}
			if len(got) == 0 {
				t.Errorf("Load iter %d saw empty registry; expected at least one entry", i)
				return
			}
		}
	}()

	// Wait for the reader to finish 500 iterations, then stop and join the writer.
	<-readerDone
	close(stop)
	<-writerDone
}

// TestGetStatusMissingProject ensures GetStatus on a path with no state.db
// reports HasProject=false and a HealthUnknown status (no panic).
func TestGetStatusMissingProject(t *testing.T) {
	dir := t.TempDir()
	ps := GetStatus(ProjectEntry{Name: "ghost", Path: dir})
	if ps.HasProject {
		t.Errorf("HasProject = true on empty dir; want false")
	}
	if ps.Health != HealthUnknown {
		t.Errorf("Health = %v on empty dir; want %v", ps.Health, HealthUnknown)
	}
}
