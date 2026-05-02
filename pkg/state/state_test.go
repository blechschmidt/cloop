package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-state-test-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// --- Init ---

func TestInit_CreatesStateFile(t *testing.T) {
	dir := tempDir(t)
	s, err := Init(dir, "build a tool", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Goal != "build a tool" {
		t.Errorf("unexpected goal: %q", s.Goal)
	}
	if s.MaxSteps != 10 {
		t.Errorf("unexpected max steps: %d", s.MaxSteps)
	}
	if s.Status != "initialized" {
		t.Errorf("unexpected status: %q", s.Status)
	}
	if _, err := os.Stat(StateDBPath(dir)); err != nil {
		t.Errorf("state file not created: %v", err)
	}
}

func TestInit_UnlimitedSteps(t *testing.T) {
	dir := tempDir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.MaxSteps != 0 {
		t.Errorf("expected 0 (unlimited), got %d", s.MaxSteps)
	}
}

// --- Load ---

func TestLoad_RoundTrip(t *testing.T) {
	dir := tempDir(t)
	original, err := Init(dir, "my goal", 5)
	if err != nil {
		t.Fatalf("init error: %v", err)
	}
	original.Status = "running"
	if err := original.Save(); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.Goal != "my goal" {
		t.Errorf("goal mismatch: %q", loaded.Goal)
	}
	if loaded.Status != "running" {
		t.Errorf("status mismatch: %q", loaded.Status)
	}
	if loaded.MaxSteps != 5 {
		t.Errorf("max steps mismatch: %d", loaded.MaxSteps)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	dir := tempDir(t)
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for missing state file")
	}
}

func TestLoad_CorruptFile(t *testing.T) {
	dir := tempDir(t)
	stateDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(StatePath(dir), []byte("not valid json {{{"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for corrupt state file")
	}
}

// --- AddStep / LastNSteps ---

func TestAddStep_IncrementsCurrentStep(t *testing.T) {
	dir := tempDir(t)
	s, _ := Init(dir, "goal", 0)
	if s.CurrentStep != 0 {
		t.Fatalf("expected initial step 0, got %d", s.CurrentStep)
	}

	s.AddStep(StepResult{Task: "step one", Output: "output", Duration: "1s", Time: time.Now()})
	if s.CurrentStep != 1 {
		t.Errorf("expected step 1 after first add, got %d", s.CurrentStep)
	}
	if len(s.Steps) != 1 {
		t.Errorf("expected 1 step in history, got %d", len(s.Steps))
	}
	if s.Steps[0].Step != 0 {
		t.Errorf("expected step index 0, got %d", s.Steps[0].Step)
	}
}

func TestAddStep_MultipleSteps(t *testing.T) {
	dir := tempDir(t)
	s, _ := Init(dir, "goal", 0)
	for i := 0; i < 5; i++ {
		s.AddStep(StepResult{Task: "task", Output: "out", Duration: "1s", Time: time.Now()})
	}
	if s.CurrentStep != 5 {
		t.Errorf("expected 5, got %d", s.CurrentStep)
	}
	if len(s.Steps) != 5 {
		t.Errorf("expected 5 steps, got %d", len(s.Steps))
	}
}

func TestLastNSteps_LessThanN(t *testing.T) {
	dir := tempDir(t)
	s, _ := Init(dir, "goal", 0)
	s.AddStep(StepResult{Task: "a", Output: "1", Duration: "1s", Time: time.Now()})
	s.AddStep(StepResult{Task: "b", Output: "2", Duration: "1s", Time: time.Now()})

	result := s.LastNSteps(5)
	if len(result) != 2 {
		t.Errorf("expected 2 steps, got %d", len(result))
	}
}

func TestLastNSteps_MoreThanN(t *testing.T) {
	dir := tempDir(t)
	s, _ := Init(dir, "goal", 0)
	for i := 0; i < 10; i++ {
		s.AddStep(StepResult{Task: "t", Output: "o", Duration: "1s", Time: time.Now()})
	}

	result := s.LastNSteps(3)
	if len(result) != 3 {
		t.Errorf("expected 3 steps, got %d", len(result))
	}
	// Should be the last 3 (steps 7, 8, 9)
	if result[0].Step != 7 {
		t.Errorf("expected step 7, got %d", result[0].Step)
	}
}

func TestLastNSteps_Zero(t *testing.T) {
	dir := tempDir(t)
	s, _ := Init(dir, "goal", 0)
	result := s.LastNSteps(3)
	if len(result) != 0 {
		t.Errorf("expected 0 steps, got %d", len(result))
	}
}

// --- SyncFromDisk / mergeExternalTasks ---

func TestSyncFromDisk_PicksUpExternallyAddedTasks(t *testing.T) {
	dir := tempDir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	// Simulate the orchestrator having a plan with one completed task.
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "task one", Status: pm.TaskDone},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Externally add a second task directly to disk (simulates 'cloop task add').
	disk, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	disk.Plan.Tasks = append(disk.Plan.Tasks, &pm.Task{
		ID: 2, Title: "task two", Status: pm.TaskPending,
	})
	if err := disk.Save(); err != nil {
		t.Fatalf("save external: %v", err)
	}

	// At this point s (in-memory) only knows about task 1 and plan appears complete.
	if !s.Plan.IsComplete() {
		t.Fatal("expected plan to be complete before SyncFromDisk")
	}

	// SyncFromDisk should pick up the externally added task.
	s.SyncFromDisk()

	if s.Plan.IsComplete() {
		t.Fatal("expected plan to NOT be complete after SyncFromDisk (external task pending)")
	}
	if len(s.Plan.Tasks) != 2 {
		t.Fatalf("expected 2 tasks after sync, got %d", len(s.Plan.Tasks))
	}
}

// TestMergeExternalTasks_PreservesContentAcrossMultipleSaveCycles verifies that
// an externally-added task (any ID not in memory) is preserved with its full
// title/description content after multiple Save() → re-use cycles.
func TestMergeExternalTasks_PreservesContentAcrossMultipleSaveCycles(t *testing.T) {
	dir := tempDir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	// Simulate the orchestrator having an in-memory plan with one done task.
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "original task", Status: pm.TaskDone},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	// Externally add a second task directly to disk (simulates 'cloop task add').
	disk, err := Load(dir)
	if err != nil {
		t.Fatalf("load for external add: %v", err)
	}
	disk.Plan.Tasks = append(disk.Plan.Tasks, &pm.Task{
		ID: 2, Title: "externally added task", Description: "important description", Status: pm.TaskPending,
	})
	if err := disk.Save(); err != nil {
		t.Fatalf("external save: %v", err)
	}

	// Simulate the orchestrator calling Save() multiple times without re-loading.
	// Each Save() must not drop the external task.
	for i := 0; i < 3; i++ {
		s.Status = "running"
		if err := s.Save(); err != nil {
			t.Fatalf("save cycle %d: %v", i, err)
		}
	}

	// Load fresh from disk and verify external task survived all cycles.
	final, err := Load(dir)
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	if final.Plan == nil {
		t.Fatal("plan is nil after multiple saves")
	}
	if len(final.Plan.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(final.Plan.Tasks))
	}
	var ext *pm.Task
	for _, tt := range final.Plan.Tasks {
		if tt.ID == 2 {
			ext = tt
		}
	}
	if ext == nil {
		t.Fatal("external task (ID=2) missing after multiple Save() cycles")
	}
	if ext.Title != "externally added task" {
		t.Errorf("external task title corrupted: %q", ext.Title)
	}
	if ext.Description != "important description" {
		t.Errorf("external task description corrupted: %q", ext.Description)
	}
}

// TestMergeExternalTasks_SetBasedMerge_NoIDReuse verifies that when an external
// task is assigned an ID that would have been reused by evolvePM (old bug), the
// set-based merge correctly preserves both tasks by ID-set logic.
func TestMergeExternalTasks_SetBasedMerge_NoIDReuse(t *testing.T) {
	dir := tempDir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "task one", Status: pm.TaskDone},
			{ID: 2, Title: "task two", Status: pm.TaskDone},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	// External process adds task with ID=3 to disk.
	disk, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	disk.Plan.Tasks = append(disk.Plan.Tasks, &pm.Task{
		ID: 3, Title: "external task ID=3", Status: pm.TaskPending,
	})
	if err := disk.Save(); err != nil {
		t.Fatalf("external save: %v", err)
	}

	// Simulate orchestrator appending an evolve task that was mistakenly also given ID=3
	// (the old bug: maxID=2 at time of assignment, external ID=3 unknown).
	s.Plan.Tasks = append(s.Plan.Tasks, &pm.Task{
		ID: 3, Title: "evolve task (conflicting ID=3)", Status: pm.TaskPending,
	})
	// Save — mergeExternalTasks runs. With the set-based merge, ID=3 is already
	// in memory so the disk's external task is NOT double-appended. The merge
	// does NOT drop the in-memory evolve task either. This test verifies that
	// repeated saves are stable (no duplicates, no panics).
	if err := s.Save(); err != nil {
		t.Fatalf("save after evolve: %v", err)
	}

	final, err := Load(dir)
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	// Count tasks with ID=3; must be exactly 1 (no duplication).
	count := 0
	for _, tt := range final.Plan.Tasks {
		if tt.ID == 3 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 task with ID=3, got %d", count)
	}
}

// TestMergeExternalTasks_ExternalTaskSurvivesAfterSyncFromDisk verifies that
// SyncFromDisk picks up an external task and subsequent Save() calls preserve it.
func TestMergeExternalTasks_ExternalTaskSurvivesAfterSyncFromDisk(t *testing.T) {
	dir := tempDir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "t1", Status: pm.TaskDone}},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	// Externally add task.
	disk, _ := Load(dir)
	disk.Plan.Tasks = append(disk.Plan.Tasks, &pm.Task{
		ID: 5, Title: "external task", Description: "desc", Status: pm.TaskPending,
	})
	if err := disk.Save(); err != nil {
		t.Fatalf("external save: %v", err)
	}

	// SyncFromDisk should pick it up.
	s.SyncFromDisk()
	if len(s.Plan.Tasks) != 2 {
		t.Fatalf("expected 2 tasks after SyncFromDisk, got %d", len(s.Plan.Tasks))
	}

	// Now save the in-memory state; external task must survive in the DB.
	if err := s.Save(); err != nil {
		t.Fatalf("save after sync: %v", err)
	}
	final, err := Load(dir)
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	found := false
	for _, tt := range final.Plan.Tasks {
		if tt.ID == 5 && tt.Title == "external task" && tt.Description == "desc" {
			found = true
		}
	}
	if !found {
		t.Error("external task (ID=5) not found in final state after SyncFromDisk + Save")
	}
}

// --- StatePath / StateDBPath ---

func TestStatePath(t *testing.T) {
	got := StatePath("/some/dir")
	expected := "/some/dir/.cloop/state.json"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestStateDBPath(t *testing.T) {
	got := StateDBPath("/some/dir")
	expected := "/some/dir/.cloop/state.db"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

// --- Save preserves fields ---

func TestSave_UpdatesTimestamp(t *testing.T) {
	dir := tempDir(t)
	s, _ := Init(dir, "goal", 0)
	before := time.Now()
	time.Sleep(time.Millisecond) // ensure updated_at changes
	s.Status = "running"
	s.Save()

	loaded, _ := Load(dir)
	if loaded.UpdatedAt.Before(before) {
		t.Error("expected UpdatedAt to be updated after Save")
	}
}

func TestSave_PreservesGoalAndSteps(t *testing.T) {
	dir := tempDir(t)
	s, _ := Init(dir, "preserve me", 0)
	s.AddStep(StepResult{Task: "t", Output: "o", Duration: "1s", Time: time.Now()})
	s.Save()

	loaded, _ := Load(dir)
	if loaded.Goal != "preserve me" {
		t.Errorf("goal not preserved: %q", loaded.Goal)
	}
	if len(loaded.Steps) != 1 {
		t.Errorf("steps not preserved: %d", len(loaded.Steps))
	}
}
