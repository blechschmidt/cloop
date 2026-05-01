package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
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

	// ContextSteps=3 → include last 3 steps
	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 3}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()

	// Should include only last 3 steps (2, 3, 4), not first 2 (0, 1)
	if strings.Contains(prompt, "step output 0") {
		t.Error("expected step 0 to be excluded (only last 3 included)")
	}
	if strings.Contains(prompt, "step output 1") {
		t.Error("expected step 1 to be excluded (only last 3 included)")
	}
	if !strings.Contains(prompt, "step output 4") {
		t.Error("expected step 4 to be included")
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

	// ContextSteps=1 — only include the most recent step
	o := newOrchestrator(t, dir, Config{WorkDir: dir, ContextSteps: 1}, &mockProvider{name: "mock"})
	prompt := o.buildPrompt()

	if !strings.Contains(prompt, "step output 4") {
		t.Error("expected most recent step to be included")
	}
	if strings.Contains(prompt, "step output 3") {
		t.Error("expected step 3 to be excluded with ContextSteps=1")
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
