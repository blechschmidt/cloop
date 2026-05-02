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
	if _, err := os.Stat(StatePath(dir)); err != nil {
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

// --- StatePath ---

func TestStatePath(t *testing.T) {
	got := StatePath("/some/dir")
	expected := "/some/dir/.cloop/state.json"
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
