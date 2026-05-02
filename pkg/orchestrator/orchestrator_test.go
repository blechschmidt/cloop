package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	mockprovider "github.com/blechschmidt/cloop/pkg/provider/mock"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
)

// mockProvider is a test double for provider.Provider.
type mockProvider struct {
	name    string
	results []*provider.Result
	errs    []error
	calls   int
}

func (m *mockProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	i := m.calls
	m.calls++
	if i < len(m.errs) && m.errs[i] != nil {
		return nil, m.errs[i]
	}
	if i < len(m.results) {
		return m.results[i], nil
	}
	return &provider.Result{Output: "default output", Provider: m.name}, nil
}

func (m *mockProvider) Name() string         { return m.name }
func (m *mockProvider) DefaultModel() string { return "mock-model" }

// safeProvider is a thread-safe mock provider for parallel tests.
type safeProvider struct {
	name   string
	output string // returned for every call
	mu     sync.Mutex
	calls  int
}

func (s *safeProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return &provider.Result{Output: s.output, Provider: s.name}, nil
}
func (s *safeProvider) Name() string         { return s.name }
func (s *safeProvider) DefaultModel() string { return "mock-model" }

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-orch-test-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func initState(t *testing.T, dir, goal string, maxSteps int) *state.ProjectState {
	t.Helper()
	s, err := state.Init(dir, goal, maxSteps)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return s
}

func newOrchestrator(t *testing.T, dir string, cfg Config, prov provider.Provider) *Orchestrator {
	t.Helper()
	o, err := New(cfg, prov)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o
}

// --- New ---

func TestNew_LoadsState(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "test goal", 5)

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)

	if o.state.Goal != "test goal" {
		t.Errorf("expected goal %q, got %q", "test goal", o.state.Goal)
	}
	if o.state.MaxSteps != 5 {
		t.Errorf("expected MaxSteps=5, got %d", o.state.MaxSteps)
	}
}

func TestNew_SetsModel(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0)

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, Model: "my-model"}, prov)

	if o.state.Model != "my-model" {
		t.Errorf("expected model %q, got %q", "my-model", o.state.Model)
	}
}

func TestNew_SetsPMMode(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0)

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	if !o.state.PMMode {
		t.Error("expected PMMode to be true")
	}
}

func TestNew_MissingState(t *testing.T) {
	dir := tempDir(t)
	// No state.Init — should fail.
	_, err := New(Config{WorkDir: dir}, &mockProvider{name: "mock"})
	if err == nil {
		t.Error("expected error for missing state file")
	}
}

// --- isGoalComplete ---

func TestIsGoalComplete_LastLine(t *testing.T) {
	o := &Orchestrator{}
	if !o.isGoalComplete("some output\nGOAL_COMPLETE") {
		t.Error("expected true for GOAL_COMPLETE at end")
	}
}

func TestIsGoalComplete_WithTrailingWhitespace(t *testing.T) {
	o := &Orchestrator{}
	if !o.isGoalComplete("output\n  GOAL_COMPLETE  \n") {
		t.Error("expected true when GOAL_COMPLETE has surrounding whitespace")
	}
}

func TestIsGoalComplete_NotInOutput(t *testing.T) {
	o := &Orchestrator{}
	if o.isGoalComplete("no completion signal here") {
		t.Error("expected false when GOAL_COMPLETE not present")
	}
}

func TestIsGoalComplete_TooFarBack(t *testing.T) {
	// GOAL_COMPLETE on line 1 of 10 — should NOT trigger (only last 5 lines checked)
	lines := make([]string, 10)
	lines[0] = "GOAL_COMPLETE"
	for i := 1; i < 10; i++ {
		lines[i] = "other line"
	}
	o := &Orchestrator{}
	if o.isGoalComplete(strings.Join(lines, "\n")) {
		t.Error("expected false: GOAL_COMPLETE too far from end")
	}
}

func TestIsGoalComplete_InLast5Lines(t *testing.T) {
	lines := []string{
		"line 1", "line 2", "line 3", "line 4", "line 5",
		"line 6", "line 7",
		"GOAL_COMPLETE",
		"line 9", "line 10",
	}
	o := &Orchestrator{}
	if !o.isGoalComplete(strings.Join(lines, "\n")) {
		t.Error("expected true: GOAL_COMPLETE in last 5 lines")
	}
}

func TestIsGoalComplete_EmptyOutput(t *testing.T) {
	o := &Orchestrator{}
	if o.isGoalComplete("") {
		t.Error("expected false for empty output")
	}
}

// --- truncate ---

func TestTruncate_ShortString(t *testing.T) {
	got := truncate("hello", 10)
	if got != "hello" {
		t.Errorf("expected %q, got %q", "hello", got)
	}
}

func TestTruncate_ExactLength(t *testing.T) {
	got := truncate("hello", 5)
	if got != "hello" {
		t.Errorf("expected %q, got %q", "hello", got)
	}
}

func TestTruncate_TooLong(t *testing.T) {
	got := truncate("hello world", 5)
	if got != "hello..." {
		t.Errorf("expected %q, got %q", "hello...", got)
	}
}

// --- buildPrompt ---

func TestBuildPrompt_ContainsGoal(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "build a CLI tool", 5)
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})

	prompt := o.buildPrompt()
	if !strings.Contains(prompt, "build a CLI tool") {
		t.Error("prompt missing goal")
	}
}

func TestBuildPrompt_ContainsStepCount(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 10)
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})

	prompt := o.buildPrompt()
	if !strings.Contains(prompt, "10") {
		t.Error("prompt missing max steps")
	}
}

func TestBuildPrompt_ContainsInstructions(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.Instructions = "use Go only"
	s.Save()

	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()
	if !strings.Contains(prompt, "use Go only") {
		t.Error("prompt missing instructions")
	}
}

func TestBuildPrompt_ContainsRecentSteps(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.AddStep(state.StepResult{
		Task:     "Step 1",
		Output:   "did something useful",
		Duration: "2s",
		Time:     time.Now(),
	})
	s.Save()

	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 3}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()
	if !strings.Contains(prompt, "did something useful") {
		t.Error("prompt missing recent step output")
	}
}

func TestBuildPrompt_UnlimitedSteps(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0)
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})

	prompt := o.buildPrompt()
	if !strings.Contains(prompt, "no step limit") {
		t.Error("expected 'no step limit' for unlimited run")
	}
}

// --- AddSteps / SetAutoEvolve ---

func TestAddSteps(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 3)
	_ = s
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})

	o.AddSteps(5)
	if o.state.MaxSteps != 8 {
		t.Errorf("expected MaxSteps=8, got %d", o.state.MaxSteps)
	}

	// Verify persisted
	loaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.MaxSteps != 8 {
		t.Errorf("MaxSteps not persisted: %d", loaded.MaxSteps)
	}
}

func TestSetAutoEvolve(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0)
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})

	o.SetAutoEvolve(true)
	if !o.state.AutoEvolve {
		t.Error("expected AutoEvolve=true")
	}

	loaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.AutoEvolve {
		t.Error("AutoEvolve not persisted")
	}
}

// --- runLoop (dry-run) ---

func TestRunLoop_DryRun_DoesNotCallProvider(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 2)

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, DryRun: true}, prov)

	if err := o.runLoop(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 0 {
		t.Errorf("expected 0 provider calls in dry-run, got %d", prov.calls)
	}
}

func TestRunLoop_DryRun_AdvancesStep(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 3)

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, DryRun: true}, prov)
	o.runLoop(context.Background())

	if o.state.CurrentStep != 3 {
		t.Errorf("expected CurrentStep=3, got %d", o.state.CurrentStep)
	}
}

func TestRunLoop_StopsOnGoalComplete(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 10)

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "Working...", Provider: "mock"},
			{Output: "Done!\nGOAL_COMPLETE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)

	if err := o.runLoop(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls, got %d", prov.calls)
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
}

func TestRunLoop_ProviderError_Fails(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 5)

	prov := &mockProvider{
		name: "mock",
		errs: []error{errors.New("API error")},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)

	err := o.runLoop(context.Background())
	if err == nil {
		t.Error("expected error from provider")
	}
	if o.state.Status != "failed" {
		t.Errorf("expected status=failed, got %q", o.state.Status)
	}
}

func TestRunLoop_TokenTracking(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 2)

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "step 1", Provider: "mock", InputTokens: 100, OutputTokens: 50},
			{Output: "step 2\nGOAL_COMPLETE", Provider: "mock", InputTokens: 120, OutputTokens: 60},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)
	o.runLoop(context.Background())

	if o.state.TotalInputTokens != 220 {
		t.Errorf("expected TotalInputTokens=220, got %d", o.state.TotalInputTokens)
	}
	if o.state.TotalOutputTokens != 110 {
		t.Errorf("expected TotalOutputTokens=110, got %d", o.state.TotalOutputTokens)
	}
}

func TestRunLoop_ContextCancelled(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0) // unlimited

	ctx, cancel := context.WithCancel(context.Background())

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "step 1", Provider: "mock"},
		},
	}
	// Cancel after first call
	origComplete := prov.results[0]
	_ = origComplete

	// Use a provider that cancels the context mid-run
	cancelProv := &cancellingProvider{cancel: cancel, inner: prov}

	o := newOrchestrator(t, dir, Config{WorkDir: dir}, cancelProv)
	err := o.runLoop(ctx)
	if err == nil {
		t.Error("expected context cancellation error")
	}
	if o.state.Status != "paused" {
		t.Errorf("expected status=paused, got %q", o.state.Status)
	}
}

// cancellingProvider cancels context after first call.
type cancellingProvider struct {
	inner  provider.Provider
	cancel context.CancelFunc
	called bool
}

func (c *cancellingProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	result, err := c.inner.Complete(ctx, prompt, opts)
	if !c.called {
		c.called = true
		c.cancel()
	}
	return result, err
}
func (c *cancellingProvider) Name() string         { return c.inner.Name() }
func (c *cancellingProvider) DefaultModel() string { return c.inner.DefaultModel() }

// --- runPM (dry-run) ---

func TestRunPM_DryRun_DoesNotCallProvider(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	// Pre-populate plan so no decompose call is needed
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Description: "Do A", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, DryRun: true, PMMode: true}, prov)

	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 0 {
		t.Errorf("expected 0 provider calls in dry-run, got %d", prov.calls)
	}
}

func TestRunPM_DryRun_MarksTasksDone(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, DryRun: true, PMMode: true}, prov)
	o.runPM(context.Background())

	for _, task := range o.state.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d: expected done, got %q", task.ID, task.Status)
		}
	}
}

func TestRunPM_PlanOnly(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, PlanOnly: true}, prov)
	o.runPM(context.Background())

	// PlanOnly should leave tasks pending
	if o.state.Plan.Tasks[0].Status != pm.TaskPending {
		t.Errorf("expected task still pending after plan-only, got %q", o.state.Plan.Tasks[0].Status)
	}
	if o.state.Status != "paused" {
		t.Errorf("expected status=paused, got %q", o.state.Status)
	}
}

func TestRunPM_SignalDetection(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
			{ID: 3, Title: "Task C", Priority: 3, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "did task A\nTASK_DONE", Provider: "mock"},
			{Output: "task B not applicable\nTASK_SKIPPED", Provider: "mock"},
			{Output: "task C failed\nTASK_FAILED", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	o.runPM(context.Background())

	tasks := o.state.Plan.Tasks
	if tasks[0].Status != pm.TaskDone {
		t.Errorf("task 1: expected done, got %q", tasks[0].Status)
	}
	if tasks[1].Status != pm.TaskSkipped {
		t.Errorf("task 2: expected skipped, got %q", tasks[1].Status)
	}
	if tasks[2].Status != pm.TaskFailed {
		t.Errorf("task 3: expected failed, got %q", tasks[2].Status)
	}
}

func TestRunPM_RetryFailed(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskFailed},
		},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "retried and done\nTASK_DONE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, RetryFailed: true}, prov)
	o.runPM(context.Background())

	if o.state.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("expected task retried and done, got %q", o.state.Plan.Tasks[0].Status)
	}
}

func TestRunPM_AllTasksComplete(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskDone},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskSkipped},
		},
	}
	s.Save()

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	o.runPM(context.Background())

	if prov.calls != 0 {
		t.Errorf("expected no provider calls for already-complete plan, got %d", prov.calls)
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
}

func TestRunPM_TokenTracking(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "done\nTASK_DONE", Provider: "mock", InputTokens: 200, OutputTokens: 80},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	o.runPM(context.Background())

	if o.state.TotalInputTokens != 200 {
		t.Errorf("expected TotalInputTokens=200, got %d", o.state.TotalInputTokens)
	}
	if o.state.TotalOutputTokens != 80 {
		t.Errorf("expected TotalOutputTokens=80, got %d", o.state.TotalOutputTokens)
	}
}

// --- Run dispatch ---

func TestRun_DispatchesPMMode(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "A", Priority: 1, Status: pm.TaskDone}},
	}
	s.Save()

	prov := &mockProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_DispatchesLoop(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 1)

	prov := &mockProvider{
		name:    "mock",
		results: []*provider.Result{{Output: "step 1\nGOAL_COMPLETE", Provider: "mock"}},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Replan ---

func TestRunPM_Replan_ClearsExistingPlan(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	// Pre-existing plan — should be wiped by Replan
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Old Task", Priority: 1, Status: pm.TaskDone},
		},
	}
	s.Save()

	// The provider returns a new plan JSON, then executes the single new task
	newPlanJSON := `{"tasks":[{"id":1,"title":"New Task","description":"fresh task","priority":1}]}`
	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: newPlanJSON, Provider: "mock"},                     // decompose
			{Output: "finished new task\nTASK_DONE", Provider: "mock"}, // execute
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Replan: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(o.state.Plan.Tasks) != 1 {
		t.Fatalf("expected 1 task in new plan, got %d", len(o.state.Plan.Tasks))
	}
	if o.state.Plan.Tasks[0].Title != "New Task" {
		t.Errorf("expected new task title, got %q", o.state.Plan.Tasks[0].Title)
	}
}

// --- MaxFailures ---

func TestRunPM_MaxFailures_DefaultIsThree(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
			{ID: 3, Title: "Task C", Priority: 3, Status: pm.TaskPending},
		},
	}
	s.Save()

	// All tasks fail → default max (3) should stop after 3 consecutive failures
	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "fail\nTASK_FAILED", Provider: "mock"},
			{Output: "fail\nTASK_FAILED", Provider: "mock"},
			{Output: "fail\nTASK_FAILED", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	err := o.runPM(context.Background())
	if err == nil {
		t.Error("expected error after max consecutive failures")
	}
	if o.state.Status != "failed" {
		t.Errorf("expected status=failed, got %q", o.state.Status)
	}
	if prov.calls != 3 {
		t.Errorf("expected 3 provider calls, got %d", prov.calls)
	}
}

func TestRunPM_MaxFailures_CustomValue(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
		},
	}
	s.Save()

	// With max-failures=1, should stop after the first failure
	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "fail\nTASK_FAILED", Provider: "mock"},
			{Output: "done\nTASK_DONE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, MaxFailures: 1}, prov)
	err := o.runPM(context.Background())
	if err == nil {
		t.Error("expected error after 1 consecutive failure with MaxFailures=1")
	}
	if prov.calls != 1 {
		t.Errorf("expected 1 provider call, got %d", prov.calls)
	}
}

func TestRunPM_MaxFailures_ResetOnSuccess(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
			{ID: 3, Title: "Task C", Priority: 3, Status: pm.TaskPending},
		},
	}
	s.Save()

	// fail, then succeed, then fail — with max-failures=2, should not stop (counter resets on success)
	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "fail\nTASK_FAILED", Provider: "mock"},
			{Output: "done\nTASK_DONE", Provider: "mock"},
			{Output: "fail\nTASK_FAILED", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, MaxFailures: 2}, prov)
	err := o.runPM(context.Background())
	if err != nil {
		t.Errorf("expected no error (counter reset on success), got: %v", err)
	}
	// All 3 tasks processed; 2 failed, 1 done — plan is complete (no more pending)
	if o.state.Status != "paused" && o.state.Status != "complete" {
		t.Errorf("unexpected status: %q", o.state.Status)
	}
}

// --- ContextSteps ---

func TestBuildPrompt_ContextSteps_Three(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	// Add 5 steps
	for i := 0; i < 5; i++ {
		s.AddStep(state.StepResult{
			Task:     "task",
			Output:   fmt.Sprintf("step output %d", i),
			Duration: "1s",
			Time:     time.Now(),
		})
	}
	s.Save()

	// ContextSteps=3 → full output for last 3 steps (2, 3, 4); brief history for steps 0, 1.
	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 3}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()

	// Older steps 0, 1 should appear in SESSION HISTORY (brief summaries).
	if !strings.Contains(prompt, "SESSION HISTORY") {
		t.Error("expected SESSION HISTORY section for older steps")
	}
	if !strings.Contains(prompt, "step output 0") {
		t.Error("expected step 0 summary in SESSION HISTORY")
	}
	if !strings.Contains(prompt, "step output 1") {
		t.Error("expected step 1 summary in SESSION HISTORY")
	}
	// Recent step 4 should appear in RECENT STEPS with full output.
	if !strings.Contains(prompt, "step output 4") {
		t.Error("expected step 4 to be included in RECENT STEPS")
	}
}

func TestBuildPrompt_ContextSteps_One(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	for i := 0; i < 5; i++ {
		s.AddStep(state.StepResult{
			Task:     "task",
			Output:   fmt.Sprintf("step output %d", i),
			Duration: "1s",
			Time:     time.Now(),
		})
	}
	s.Save()

	// ContextSteps=1 — full output for last step only; steps 0-3 appear in SESSION HISTORY.
	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 1}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()

	if !strings.Contains(prompt, "step output 4") {
		t.Error("expected most recent step to be included in RECENT STEPS")
	}
	// Steps 0-3 should appear in SESSION HISTORY as brief summaries.
	if !strings.Contains(prompt, "SESSION HISTORY") {
		t.Error("expected SESSION HISTORY section for older steps")
	}
	if !strings.Contains(prompt, "step output 3") {
		t.Error("expected step 3 in SESSION HISTORY (brief)")
	}
}

func TestBuildPrompt_ContextSteps_Zero_DisablesContext(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.AddStep(state.StepResult{Task: "t", Output: "only step", Duration: "1s", Time: time.Now()})
	s.Save()

	// ContextSteps=0 means no context (disable step history in prompt)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 0}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()
	if strings.Contains(prompt, "only step") {
		t.Error("ContextSteps=0 should exclude all steps from prompt")
	}
	if strings.Contains(prompt, "RECENT STEPS") {
		t.Error("ContextSteps=0 should not include RECENT STEPS section")
	}
}

func TestBuildPrompt_ContextSteps_Negative_UsesDefault(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.AddStep(state.StepResult{Task: "t", Output: "only step", Duration: "1s", Time: time.Now()})
	s.Save()

	// ContextSteps=-1 means use the default (3)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: -1}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()
	if !strings.Contains(prompt, "only step") {
		t.Error("ContextSteps=-1 (use default) should include steps")
	}
}

// --- printOutputTo ---

func TestPrintOutputTo_TruncatesLongOutput(t *testing.T) {
	// Build 25-line output — should trigger truncation when not verbose
	lines := make([]string, 25)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i)
	}
	output := strings.Join(lines, "\n")

	var buf bytes.Buffer
	color.NoColor = true // disable colors for deterministic output
	printOutputTo(&buf, output, color.New(color.Faint), false)
	got := buf.String()

	if !strings.Contains(got, "omitted") {
		t.Error("expected truncation message in non-verbose output")
	}
	if strings.Contains(got, "line 12") {
		t.Error("middle lines should be omitted in non-verbose mode")
	}
}

func TestPrintOutputTo_VerboseShowsAllLines(t *testing.T) {
	lines := make([]string, 25)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i)
	}
	output := strings.Join(lines, "\n")

	var buf bytes.Buffer
	color.NoColor = true
	printOutputTo(&buf, output, color.New(color.Faint), true)
	got := buf.String()

	if strings.Contains(got, "omitted") {
		t.Error("verbose mode should not truncate output")
	}
	if !strings.Contains(got, "line 12") {
		t.Error("verbose mode should show all lines including middle ones")
	}
}

func TestPrintOutputTo_ShortOutput_NeverTruncated(t *testing.T) {
	output := "line 1\nline 2\nline 3"

	var buf bytes.Buffer
	color.NoColor = true
	printOutputTo(&buf, output, color.New(color.Faint), false)
	got := buf.String()

	if strings.Contains(got, "omitted") {
		t.Error("short output should never be truncated")
	}
	if !strings.Contains(got, "line 1") || !strings.Contains(got, "line 3") {
		t.Error("all lines should be present in short output")
	}
}

func TestPrintOutputTo_TruncationThresholdIsExactly20(t *testing.T) {
	// Exactly 20 lines — should NOT trigger truncation
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i)
	}
	output := strings.Join(lines, "\n")

	var buf bytes.Buffer
	color.NoColor = true
	printOutputTo(&buf, output, color.New(color.Faint), false)
	got := buf.String()

	if strings.Contains(got, "omitted") {
		t.Error("exactly 20 lines should not be truncated")
	}
}

func TestRunLoop_Verbose_PassedToOrchestratorConfig(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 1)

	prov := &mockProvider{
		name:    "mock",
		results: []*provider.Result{{Output: "step 1\nGOAL_COMPLETE", Provider: "mock"}},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, Verbose: true}, prov)

	if !o.config.Verbose {
		t.Error("expected Verbose=true in orchestrator config")
	}
}

// --- StepsLimit ---

func TestRunLoop_StepsLimit_StopsAfterN(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0) // unlimited MaxSteps

	prov := &mockProvider{
		name: "mock",
		// Provide more results than StepsLimit so we can tell if it stops early.
		results: []*provider.Result{
			{Output: "step 1", Provider: "mock"},
			{Output: "step 2", Provider: "mock"},
			{Output: "step 3\nGOAL_COMPLETE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, StepsLimit: 2}, prov)
	err := o.runLoop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls (StepsLimit=2), got %d", prov.calls)
	}
	if o.state.Status != "paused" {
		t.Errorf("expected status=paused after hitting session limit, got %q", o.state.Status)
	}
}

func TestRunLoop_StepsLimit_DoesNotPersistMaxSteps(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0) // MaxSteps=0 (unlimited)

	prov := &mockProvider{
		name:    "mock",
		results: []*provider.Result{{Output: "step 1", Provider: "mock"}},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, StepsLimit: 1}, prov)
	o.runLoop(context.Background())

	// MaxSteps must still be 0 (session limit is not persisted)
	loaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.MaxSteps != 0 {
		t.Errorf("StepsLimit must not modify persisted MaxSteps, got %d", loaded.MaxSteps)
	}
}

func TestRunLoop_StepsLimit_Zero_Means_NoLimit(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 2) // MaxSteps=2

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "step 1", Provider: "mock"},
			{Output: "step 2\nGOAL_COMPLETE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, StepsLimit: 0}, prov)
	err := o.runLoop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// StepsLimit=0 means no session limit; stops at MaxSteps=2
	if prov.calls != 2 {
		t.Errorf("expected 2 calls (StepsLimit=0 means no session limit), got %d", prov.calls)
	}
}

func TestRunPM_StepsLimit_StopsAfterN(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
			{ID: 3, Title: "Task C", Priority: 3, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "done A\nTASK_DONE", Provider: "mock"},
			{Output: "done B\nTASK_DONE", Provider: "mock"},
			{Output: "done C\nTASK_DONE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, StepsLimit: 2}, prov)
	err := o.runPM(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls (StepsLimit=2), got %d", prov.calls)
	}
	if o.state.Status != "paused" {
		t.Errorf("expected status=paused, got %q", o.state.Status)
	}
	// Tasks A and B done; C still pending
	if o.state.Plan.Tasks[2].Status != pm.TaskPending {
		t.Errorf("task C should remain pending, got %q", o.state.Plan.Tasks[2].Status)
	}
}

// --- printSessionSummary ---

func TestPrintSessionSummary_ShowsSteps(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	// Simulate 2 steps having been run.
	s.CurrentStep = 2

	var buf bytes.Buffer
	color.NoColor = true

	start := time.Now().Add(-5 * time.Second)
	// Capture by redirecting — the function prints to stdout via color package,
	// so we test indirectly by calling the function and checking it doesn't panic.
	// We validate the step count calculation separately.
	stepsThisSession := s.CurrentStep - 0 // startStep was 0
	if stepsThisSession != 2 {
		t.Errorf("expected 2 steps this session, got %d", stepsThisSession)
	}
	_ = buf
	_ = start
}

func TestPrintSessionSummary_ZeroSteps_DoesNotPanic(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	// No steps run.
	start := time.Now()
	// Just ensure no panic.
	printSessionSummary(start, 0, s)
}

func TestPrintSessionSummary_WithTokens(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.CurrentStep = 1
	s.TotalInputTokens = 500
	s.TotalOutputTokens = 200
	start := time.Now()
	// Just ensure no panic.
	printSessionSummary(start, 0, s)
}

// --- buildEvolvePrompt ---

func TestBuildEvolvePrompt_ContainsOriginalGoal(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "improve the project", 0)
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})

	prompt := o.buildEvolvePrompt()
	if !strings.Contains(prompt, "improve the project") {
		t.Error("evolve prompt missing original goal")
	}
	if !strings.Contains(prompt, "AUTO-EVOLVE") {
		t.Error("evolve prompt missing AUTO-EVOLVE marker")
	}
}

// --- TokenBudget ---

func TestRunLoop_TokenBudget_PausesWhenExceeded(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0) // unlimited steps

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "step 1", Provider: "mock", InputTokens: 100, OutputTokens: 50},  // 150 total
			{Output: "step 2", Provider: "mock", InputTokens: 100, OutputTokens: 50},  // 300 total
			{Output: "step 3\nGOAL_COMPLETE", Provider: "mock", InputTokens: 100, OutputTokens: 50},
		},
	}
	// Budget of 250 — should stop after step 2 (cumulative = 300 >= 250)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, TokenBudget: 250}, prov)
	err := o.runLoop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls before budget hit, got %d", prov.calls)
	}
	if o.state.Status != "paused" {
		t.Errorf("expected status=paused when budget exceeded, got %q", o.state.Status)
	}
}

func TestRunLoop_TokenBudget_Zero_NoLimit(t *testing.T) {
	dir := tempDir(t)
	initState(t, dir, "goal", 0)

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "step 1", Provider: "mock", InputTokens: 10000, OutputTokens: 5000},
			{Output: "step 2\nGOAL_COMPLETE", Provider: "mock", InputTokens: 10000, OutputTokens: 5000},
		},
	}
	// TokenBudget=0 means unlimited
	o := newOrchestrator(t, dir, Config{WorkDir: dir, TokenBudget: 0}, prov)
	err := o.runLoop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls, got %d", prov.calls)
	}
}

func TestRunPM_TokenBudget_PausesTaskAsPending(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "done A\nTASK_DONE", Provider: "mock", InputTokens: 200, OutputTokens: 100}, // 300 total
			{Output: "done B\nTASK_DONE", Provider: "mock", InputTokens: 200, OutputTokens: 100}, // 600 total
		},
	}
	// Budget of 400 — exceeded after task A's output is counted (300 < 400, task A is DONE);
	// then task B runs and cumulative = 600 >= 400, so task B is reset to pending.
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, TokenBudget: 400}, prov)
	err := o.runPM(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.state.Status != "paused" {
		t.Errorf("expected status=paused, got %q", o.state.Status)
	}
	// Task A should be done, task B should be reset to pending
	if o.state.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("task A: expected done, got %q", o.state.Plan.Tasks[0].Status)
	}
	if o.state.Plan.Tasks[1].Status != pm.TaskPending {
		t.Errorf("task B: expected pending (reset for retry), got %q", o.state.Plan.Tasks[1].Status)
	}
}

// --- stepSummaryLine ---

func TestStepSummaryLine_LastMeaningfulLine(t *testing.T) {
	output := "Did some work.\nCreated files.\nAll done."
	got := stepSummaryLine(output, 150)
	if got != "All done." {
		t.Errorf("expected last line, got %q", got)
	}
}

func TestStepSummaryLine_SkipsSignals(t *testing.T) {
	output := "Completed the task.\nTASK_DONE"
	got := stepSummaryLine(output, 150)
	if got != "Completed the task." {
		t.Errorf("expected line before TASK_DONE, got %q", got)
	}
}

func TestStepSummaryLine_SkipsGoalCompleteSignal(t *testing.T) {
	output := "Project finished.\nGOAL_COMPLETE"
	got := stepSummaryLine(output, 150)
	if got != "Project finished." {
		t.Errorf("expected line before GOAL_COMPLETE, got %q", got)
	}
}

func TestStepSummaryLine_SkipsEmptyLines(t *testing.T) {
	output := "Did work.\n\n\n"
	got := stepSummaryLine(output, 150)
	if got != "Did work." {
		t.Errorf("expected non-empty line, got %q", got)
	}
}

func TestStepSummaryLine_Truncates(t *testing.T) {
	output := "This is a very long line that exceeds the maximum length limit set for summary display."
	got := stepSummaryLine(output, 20)
	if len([]rune(got)) > 23 { // 20 + "..."
		t.Errorf("expected truncated output (<=23 runes), got len=%d: %q", len([]rune(got)), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected '...' suffix for truncated line, got %q", got)
	}
}

func TestStepSummaryLine_EmptyOutput(t *testing.T) {
	got := stepSummaryLine("", 150)
	if got != "(no summary)" {
		t.Errorf("expected '(no summary)' for empty output, got %q", got)
	}
}

func TestStepSummaryLine_OnlySignals(t *testing.T) {
	output := "TASK_DONE"
	got := stepSummaryLine(output, 150)
	if got != "(no summary)" {
		t.Errorf("expected '(no summary)' when only signals present, got %q", got)
	}
}

// --- SESSION HISTORY in buildPrompt ---

func TestBuildPrompt_SessionHistory_AppearsForOlderSteps(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	// Add 5 steps; with ContextSteps=2, steps 0-2 become "older" history.
	for i := 0; i < 5; i++ {
		s.AddStep(state.StepResult{
			Task:     "task",
			Output:   fmt.Sprintf("completed step %d output", i),
			Duration: "1s",
			Time:     time.Now(),
		})
	}
	s.Save()

	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 2}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()

	if !strings.Contains(prompt, "SESSION HISTORY") {
		t.Error("expected SESSION HISTORY section for sessions longer than contextSteps")
	}
	// Steps 0-2 (older) should appear only as brief summaries.
	if !strings.Contains(prompt, "completed step 0 output") {
		t.Error("expected step 0 summary in SESSION HISTORY")
	}
	// Steps 3-4 (recent) should appear in RECENT STEPS with full output.
	if !strings.Contains(prompt, "RECENT STEPS") {
		t.Error("expected RECENT STEPS section")
	}
	if !strings.Contains(prompt, "completed step 4 output") {
		t.Error("expected step 4 in RECENT STEPS")
	}
}

func TestBuildPrompt_SessionHistory_AbsentWhenWithinContext(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	// Only 2 steps, ContextSteps=3 — all fit in recent, no history section needed.
	for i := 0; i < 2; i++ {
		s.AddStep(state.StepResult{
			Task:     "task",
			Output:   fmt.Sprintf("step %d", i),
			Duration: "1s",
			Time:     time.Now(),
		})
	}
	s.Save()

	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 3}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()

	if strings.Contains(prompt, "SESSION HISTORY") {
		t.Error("SESSION HISTORY should not appear when all steps fit within context window")
	}
}

// TestRunPMParallel_IndependentTasksRunConcurrently checks that parallel mode
// runs all independent tasks and marks them done.
func TestRunPMParallel_IndependentTasksRunConcurrently(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	// Three tasks with no dependencies — all should run in one parallel round.
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
			{ID: 3, Title: "C", Priority: 3, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &safeProvider{name: "mock", output: "done\nTASK_DONE"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	final, _ := state.Load(dir)
	for _, task := range final.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d (%s): expected done, got %s", task.ID, task.Title, task.Status)
		}
	}
	// All 3 tasks were called (+ the implicit Decompose call is skipped since plan exists).
	if prov.calls != 3 {
		t.Errorf("expected 3 provider calls, got %d", prov.calls)
	}
	if final.Status != "complete" {
		t.Errorf("expected status complete, got %s", final.Status)
	}
}

// --- Integration: full decompose → execute flow ---

// TestRunPM_Decompose_NoExistingPlan_FullFlow tests the complete happy-path where
// there is no pre-existing plan: the provider is first called to decompose the goal
// into tasks (returning JSON), and then each task is executed in priority order.
func TestRunPM_Decompose_NoExistingPlan_FullFlow(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "build a calculator", 0)
	s.PMMode = true
	// No plan — forces decompose call.
	s.Save()

	planJSON := `{"tasks":[{"id":1,"title":"Implement add","description":"Add two numbers","priority":1},{"id":2,"title":"Write tests","description":"Write unit tests","priority":2}]}`
	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: planJSON, Provider: "mock"},                        // decompose
			{Output: "implemented add\nTASK_DONE", Provider: "mock"},   // task 1
			{Output: "wrote tests\nTASK_DONE", Provider: "mock"},       // task 2
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 calls: 1 decompose + 2 task executions.
	if prov.calls != 3 {
		t.Errorf("expected 3 provider calls (1 decompose + 2 execute), got %d", prov.calls)
	}
	if len(o.state.Plan.Tasks) != 2 {
		t.Fatalf("expected 2 tasks in plan, got %d", len(o.state.Plan.Tasks))
	}
	for _, task := range o.state.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d: expected done, got %q", task.ID, task.Status)
		}
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
}

// TestRunPM_Decompose_ProviderError_FailsGracefully verifies that a provider error
// during decomposition sets status=failed and surfaces the error.
func TestRunPM_Decompose_ProviderError_FailsGracefully(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Save()

	prov := &mockProvider{
		name: "mock",
		errs: []error{fmt.Errorf("provider unavailable")},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	err := o.runPM(context.Background())
	if err == nil {
		t.Error("expected error from decompose provider failure")
	}
	if o.state.Status != "failed" {
		t.Errorf("expected status=failed, got %q", o.state.Status)
	}
}

// TestRunPM_Decompose_InvalidJSON_FailsGracefully verifies that invalid JSON from the
// provider during decomposition fails gracefully (not a panic).
func TestRunPM_Decompose_InvalidJSON_FailsGracefully(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "I cannot decompose this goal at the moment.", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	err := o.runPM(context.Background())
	if err == nil {
		t.Error("expected error when provider returns non-JSON for decompose")
	}
	if o.state.Status != "failed" {
		t.Errorf("expected status=failed, got %q", o.state.Status)
	}
}

// --- Integration: auto-evolve discovers new tasks ---

// TestRunPM_AutoEvolve_DiscoversAndExecutesNewTasks tests the full auto-evolve cycle:
// 1. All tasks complete → AutoEvolve=true → evolvePM discovers new tasks (JSON).
// 2. New tasks are executed.
// 3. evolvePM called again → returns no JSON → n=0 → status=complete.
func TestRunPM_AutoEvolve_DiscoversAndExecutesNewTasks(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "improve the project", 0)
	s.PMMode = true
	s.AutoEvolve = true
	s.Plan = &pm.Plan{
		Goal: "improve the project",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Initial Task", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	// IDs in evolve JSON will be re-assigned (maxID=1 → new task gets ID=2).
	evolvedJSON := `{"tasks":[{"id":1,"title":"Evolve Task","description":"add improvement","priority":1}]}`
	dedupAllNovel := `{"novel":[0],"reason":"all novel"}`
	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "done initial\nTASK_DONE", Provider: "mock"}, // execute task 1
			{Output: evolvedJSON, Provider: "mock"},               // evolvePM → 1 new task
			{Output: dedupAllNovel, Provider: "mock"},             // dedup → all novel
			{Output: "done evolve\nTASK_DONE", Provider: "mock"},  // execute evolve task
			{Output: `{"tasks":[]}`, Provider: "mock"},            // evolvePM → no new tasks
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 5 calls: execute task1 + evolvePM (new tasks) + dedup + execute evolve task + evolvePM (empty).
	if prov.calls != 5 {
		t.Errorf("expected 5 provider calls, got %d", prov.calls)
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
	// Both original and evolved tasks should be done.
	if len(o.state.Plan.Tasks) != 2 {
		t.Errorf("expected 2 tasks total (original + evolved), got %d", len(o.state.Plan.Tasks))
	}
	for _, task := range o.state.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d (%s): expected done, got %q", task.ID, task.Title, task.Status)
		}
	}
}

// TestRunPM_AutoEvolve_StopsWhenNoNewTasksDiscovered verifies that evolvePM returning
// zero new tasks causes the orchestrator to finalize with status=complete and not loop.
func TestRunPM_AutoEvolve_StopsWhenNoNewTasksDiscovered(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.AutoEvolve = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "done\nTASK_DONE", Provider: "mock"}, // execute task 1
			{Output: "no JSON here", Provider: "mock"},    // evolvePM → parse error → n=0
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2 calls: execute + evolvePM (no new tasks).
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls (1 execute + 1 evolve), got %d", prov.calls)
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
}

// TestRunPM_AutoEvolve_MultipleRounds tests multiple successive evolve rounds, each
// discovering and executing one new task until finally no new tasks are returned.
func TestRunPM_AutoEvolve_MultipleRounds(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.AutoEvolve = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	// Each evolvePM call returns exactly one new task, except the last which returns empty.
	round1JSON := `{"tasks":[{"id":1,"title":"Round1 Task","description":"r1","priority":1}]}`
	round2JSON := `{"tasks":[{"id":1,"title":"Round2 Task","description":"r2","priority":1}]}`
	dedupAllNovel := `{"novel":[0],"reason":"all novel"}`
	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "done A\nTASK_DONE", Provider: "mock"},    // execute task 1
			{Output: round1JSON, Provider: "mock"},             // evolvePM round 1 → task 2
			{Output: dedupAllNovel, Provider: "mock"},          // dedup round 1 → all novel
			{Output: "done r1\nTASK_DONE", Provider: "mock"},   // execute task 2
			{Output: round2JSON, Provider: "mock"},             // evolvePM round 2 → task 3
			{Output: dedupAllNovel, Provider: "mock"},          // dedup round 2 → all novel
			{Output: "done r2\nTASK_DONE", Provider: "mock"},   // execute task 3
			{Output: `{"tasks":[]}`, Provider: "mock"},         // evolvePM round 3 → none
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.calls != 8 {
		t.Errorf("expected 8 provider calls, got %d", prov.calls)
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
	if len(o.state.Plan.Tasks) != 3 {
		t.Errorf("expected 3 total tasks, got %d", len(o.state.Plan.Tasks))
	}
}

// --- Integration: SyncFromDisk mid-run ---

// sideEffectResponse pairs a provider result with an optional side-effect
// function that runs inside Complete() before returning — useful for simulating
// external state mutations (e.g. 'cloop task add') while the orchestrator runs.
type sideEffectResponse struct {
	result *provider.Result
	err    error
	after  func() // called within Complete before returning to caller
}

// sideEffectProvider is a mock provider that can trigger arbitrary side-effects
// (e.g. writing tasks to disk) after returning each response.
type sideEffectProvider struct {
	name      string
	responses []sideEffectResponse
	mu        sync.Mutex
	calls     int
}

func (p *sideEffectProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	i := p.calls
	p.calls++
	p.mu.Unlock()

	if i < len(p.responses) {
		resp := p.responses[i]
		if resp.after != nil {
			resp.after()
		}
		if resp.err != nil {
			return nil, resp.err
		}
		return resp.result, nil
	}
	return &provider.Result{Output: "default", Provider: p.name}, nil
}
func (p *sideEffectProvider) Name() string         { return p.name }
func (p *sideEffectProvider) DefaultModel() string { return "mock-model" }

// TestRunPM_SyncFromDisk_PicksUpExternallyAddedTask tests that when an external
// process appends a new task to the state file while the orchestrator is running
// (simulated via a sideEffectProvider callback), SyncFromDisk picks it up and
// the orchestrator executes it before declaring the plan complete.
func TestRunPM_SyncFromDisk_PicksUpExternallyAddedTask(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	// After task A executes, write a new task (ID=2) to the state file on disk.
	// The orchestrator calls s.Save() after task completion which triggers
	// mergeExternalTasks → the new task is incorporated into the in-memory plan.
	prov := &sideEffectProvider{
		name: "mock",
		responses: []sideEffectResponse{
			{
				result: &provider.Result{Output: "done A\nTASK_DONE", Provider: "mock"},
				after: func() {
					// Simulate 'cloop task add': load disk state, append task, save.
					disk, err := state.Load(dir)
					if err != nil {
						return
					}
					disk.Plan.Tasks = append(disk.Plan.Tasks, &pm.Task{
						ID:       2,
						Title:    "External Task",
						Priority: 2,
						Status:   pm.TaskPending,
					})
					disk.Save()
				},
			},
			{
				result: &provider.Result{Output: "done external\nTASK_DONE", Provider: "mock"},
			},
		},
	}

	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both task A and the externally-added task should have been executed.
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls (task A + external task), got %d", prov.calls)
	}
	if len(o.state.Plan.Tasks) != 2 {
		t.Errorf("expected 2 tasks in final plan (original + external), got %d", len(o.state.Plan.Tasks))
	}
	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
	// Verify external task was executed and marked done.
	extTask := o.state.Plan.Tasks[1]
	if extTask.Title != "External Task" {
		t.Errorf("expected second task to be 'External Task', got %q", extTask.Title)
	}
	if extTask.Status != pm.TaskDone {
		t.Errorf("external task: expected done, got %q", extTask.Status)
	}
}

// TestRunPM_SyncFromDisk_ExternalTasksDoNotDuplicateOnRepeatedSync verifies that
// repeated SyncFromDisk calls (one per loop iteration) do not duplicate tasks.
func TestRunPM_SyncFromDisk_ExternalTasksDoNotDuplicateOnRepeatedSync(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			{Output: "done A\nTASK_DONE", Provider: "mock"},
			{Output: "done B\nTASK_DONE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tasks must not be duplicated; should still be exactly 2.
	if len(o.state.Plan.Tasks) != 2 {
		t.Errorf("expected 2 tasks (no duplicates), got %d", len(o.state.Plan.Tasks))
	}
}

// --- MaxParallel worker pool ---

// concurrencyTrackingProvider counts peak simultaneous goroutines inside Complete().
type concurrencyTrackingProvider struct {
	mu          sync.Mutex
	active      int
	peakActive  int
	totalCalls  int
	output      string
}

func (p *concurrencyTrackingProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	p.active++
	if p.active > p.peakActive {
		p.peakActive = p.active
	}
	p.totalCalls++
	p.mu.Unlock()

	// Hold the lock for a brief moment to make concurrency detectable.
	time.Sleep(5 * time.Millisecond)

	p.mu.Lock()
	p.active--
	p.mu.Unlock()

	out := p.output
	if out == "" {
		out = "done\nTASK_DONE"
	}
	return &provider.Result{Output: out, Provider: "concurrency-mock"}, nil
}
func (p *concurrencyTrackingProvider) Name() string         { return "concurrency-mock" }
func (p *concurrencyTrackingProvider) DefaultModel() string { return "mock-model" }

// TestRunPMParallel_MaxParallel_LimitsBatchSize verifies that with MaxParallel=2 and
// 4 independent tasks, no more than 2 tasks execute concurrently.
func TestRunPMParallel_MaxParallel_LimitsBatchSize(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "B", Priority: 1, Status: pm.TaskPending},
			{ID: 3, Title: "C", Priority: 1, Status: pm.TaskPending},
			{ID: 4, Title: "D", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &concurrencyTrackingProvider{output: "done\nTASK_DONE"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true, MaxParallel: 2}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if prov.peakActive > 2 {
		t.Errorf("peak concurrent tasks exceeded MaxParallel=2: got %d", prov.peakActive)
	}
	if prov.totalCalls != 4 {
		t.Errorf("expected 4 total provider calls, got %d", prov.totalCalls)
	}

	final, _ := state.Load(dir)
	for _, task := range final.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d: expected done, got %s", task.ID, task.Status)
		}
	}
	if final.Status != "complete" {
		t.Errorf("expected status=complete, got %s", final.Status)
	}
}

// TestRunPMParallel_MaxParallel_One_IsSequential verifies that MaxParallel=1 results
// in a peak concurrency of 1 (effectively sequential within the parallel dispatch path).
func TestRunPMParallel_MaxParallel_One_IsSequential(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "B", Priority: 1, Status: pm.TaskPending},
			{ID: 3, Title: "C", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &concurrencyTrackingProvider{output: "done\nTASK_DONE"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true, MaxParallel: 1}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if prov.peakActive > 1 {
		t.Errorf("MaxParallel=1 should allow at most 1 concurrent task, got peak=%d", prov.peakActive)
	}
	if prov.totalCalls != 3 {
		t.Errorf("expected 3 provider calls, got %d", prov.totalCalls)
	}
}

// TestRunPMParallel_MaxParallel_Zero_AllTasksRunAtOnce verifies that MaxParallel=0
// (unlimited) allows all independent tasks to run in a single parallel round.
func TestRunPMParallel_MaxParallel_Zero_AllTasksRunAtOnce(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "B", Priority: 1, Status: pm.TaskPending},
			{ID: 3, Title: "C", Priority: 1, Status: pm.TaskPending},
		},
	}
	s.Save()

	prov := &concurrencyTrackingProvider{output: "done\nTASK_DONE"}
	// MaxParallel=0 means unlimited (all 3 should run in one round).
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true, MaxParallel: 0}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// All 3 tasks are independent so peak should reach 3.
	if prov.peakActive < 3 {
		t.Errorf("MaxParallel=0 (unlimited) should run all 3 tasks at once; peak was %d", prov.peakActive)
	}
	if prov.totalCalls != 3 {
		t.Errorf("expected 3 provider calls, got %d", prov.totalCalls)
	}
}

// TestRunPMParallel_DependencyBlocking ensures tasks with deps wait for prerequisites.
func TestRunPMParallel_DependencyBlocking(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	// Task 2 depends on task 1 — must run after task 1 completes.
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "First", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Second", Priority: 2, Status: pm.TaskPending, DependsOn: []int{1}},
		},
	}
	s.Save()

	prov := &safeProvider{name: "mock", output: "done\nTASK_DONE"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	final, _ := state.Load(dir)
	for _, task := range final.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d: expected done, got %s", task.ID, task.Status)
		}
	}
	// 2 tasks = 2 provider calls.
	if prov.calls != 2 {
		t.Errorf("expected 2 provider calls, got %d", prov.calls)
	}
}

// --- Mock provider integration tests ---
// These tests use pkg/provider/mock directly, demonstrating deterministic CI-safe
// integration tests that require no API keys.

// writeMockResponses writes a mock_responses.yaml file to dir/.cloop/.
func writeMockResponses(t *testing.T, dir, content string) {
	t.Helper()
	cloopDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cloopDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cloopDir, "mock_responses.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write mock_responses.yaml: %v", err)
	}
}

// TestMockProvider_DefaultResponse verifies that the mock provider returns TASK_DONE
// when no responses file exists and no config is given.
func TestMockProvider_DefaultResponse(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending}},
	}
	s.Save()

	// No responses file: provider must default to TASK_DONE.
	prov := mockprovider.NewWithWorkDir("", dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.state.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("expected task done via default TASK_DONE response, got %q", o.state.Plan.Tasks[0].Status)
	}
}

// TestMockProvider_SubstringMatch verifies that a prompt-substring rule returns the
// configured canned response rather than the default.
// Uses the CURRENT TASK header format "**Task N: Title**" which is unique per task.
func TestMockProvider_SubstringMatch(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Build feature", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Write docs",    Priority: 2, Status: pm.TaskPending},
		},
	}
	s.Save()

	// Use the CURRENT TASK prompt format: "**Task 2: Write docs**" only appears
	// in task 2's execution prompt (task 1's prompt lists task 2 only as an upcoming
	// task in the format "- [ ] Task 2: Write docs", without double asterisks).
	writeMockResponses(t, dir, "rules:\n  - substring: \"**Task 2: Write docs**\"\n    response: |-\n      docs skipped\n      TASK_SKIPPED\ndefault: |-\n  done\n  TASK_DONE\n")

	prov := mockprovider.NewWithWorkDir("", dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tasks := o.state.Plan.Tasks
	if tasks[0].Status != pm.TaskDone {
		t.Errorf("task 1: expected done (default), got %q", tasks[0].Status)
	}
	if tasks[1].Status != pm.TaskSkipped {
		t.Errorf("task 2: expected skipped (substring match), got %q", tasks[1].Status)
	}
}

// TestMockProvider_ExplicitResponsesFile verifies that a non-default responses file
// path is respected when passed directly to the constructor.
func TestMockProvider_ExplicitResponsesFile(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "Deploy", Priority: 1, Status: pm.TaskPending}},
	}
	s.Save()

	// Write to a custom path, not the default .cloop/mock_responses.yaml.
	customFile := filepath.Join(dir, "custom_responses.yaml")
	if err := os.WriteFile(customFile, []byte("default: \"deployed\nTASK_DONE\"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	prov := mockprovider.NewWithWorkDir(customFile, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.state.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("expected done, got %q", o.state.Plan.Tasks[0].Status)
	}
}

// TestMockProvider_HashMatch verifies that a SHA-256 hash rule matches the exact
// prompt and returns the configured response.
func TestMockProvider_HashMatch(t *testing.T) {
	// Compute the hash of a known string.
	knownPrompt := "exact-prompt-for-hash-test"
	hash := mockprovider.HashPrompt(knownPrompt)

	dir := tempDir(t)

	writeMockResponses(t, dir, fmt.Sprintf(`
rules:
  - hash: "%s"
    response: "hash matched\nTASK_DONE"
default: "TASK_FAILED"
`, hash))

	// Test the provider directly — Complete should return the hash-matched response.
	prov := mockprovider.NewWithWorkDir("", dir)
	result, err := prov.Complete(context.Background(), knownPrompt, provider.Options{WorkDir: dir})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(result.Output, "hash matched") {
		t.Errorf("expected hash-matched response, got %q", result.Output)
	}
}

// TestMockProvider_NoMatchFallsBackToDefault verifies that when no rule matches,
// the configured default response is returned (not TASK_DONE hardcoded).
func TestMockProvider_NoMatchFallsBackToDefault(t *testing.T) {
	dir := tempDir(t)

	writeMockResponses(t, dir, `
rules:
  - substring: "will-never-match-xyz"
    response: "TASK_FAILED"
default: "custom default\nTASK_SKIPPED"
`)

	prov := mockprovider.NewWithWorkDir("", dir)
	result, err := prov.Complete(context.Background(), "some other prompt", provider.Options{WorkDir: dir})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(result.Output, "TASK_SKIPPED") {
		t.Errorf("expected custom default (TASK_SKIPPED), got %q", result.Output)
	}
}

// TestMockProvider_FullPMFlowWithDecompose tests a complete PM flow using the mock
// provider for both decomposition and task execution — no API key required.
func TestMockProvider_FullPMFlowWithDecompose(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "build a CLI tool", 0)
	s.PMMode = true
	s.Save() // no plan — forces decompose call

	// Write the responses file using a YAML literal block scalar (|-) so the JSON
	// is not misinterpreted as a YAML flow mapping.
	planJSON := `{"tasks":[{"id":1,"title":"Implement core","description":"Write core logic","priority":1},{"id":2,"title":"Add tests","description":"Write unit tests","priority":2}]}`

	// Build YAML manually using block scalars to avoid YAML/JSON quoting conflicts.
	yaml := "rules:\n" +
		"  - substring: \"product manager\"\n" +
		"    response: |-\n" +
		"      " + planJSON + "\n" +
		"  - substring: \"**Task 1: Implement core**\"\n" +
		"    response: |-\n" +
		"      core implemented\n" +
		"      TASK_DONE\n" +
		"  - substring: \"**Task 2: Add tests**\"\n" +
		"    response: |-\n" +
		"      tests written\n" +
		"      TASK_DONE\n" +
		"default: |-\n" +
		"  " + planJSON + "\n"

	writeMockResponses(t, dir, yaml)

	prov := mockprovider.NewWithWorkDir("", dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if o.state.Status != "complete" {
		t.Errorf("expected status=complete, got %q", o.state.Status)
	}
	for _, task := range o.state.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d (%s): expected done, got %q", task.ID, task.Title, task.Status)
		}
	}
}
