package pm

import (
	"strings"
	"testing"
	"time"
)

// --- Plan.NextTask ---

func TestNextTask_ReturnsHighestPriority(t *testing.T) {
	plan := &Plan{
		Tasks: []*Task{
			{ID: 1, Priority: 3, Status: TaskPending},
			{ID: 2, Priority: 1, Status: TaskPending},
			{ID: 3, Priority: 2, Status: TaskPending},
		},
	}
	next := plan.NextTask()
	if next == nil {
		t.Fatal("expected a task, got nil")
	}
	if next.ID != 2 {
		t.Errorf("expected task ID 2 (priority 1), got %d", next.ID)
	}
}

func TestNextTask_SkipsNonPending(t *testing.T) {
	plan := &Plan{
		Tasks: []*Task{
			{ID: 1, Priority: 1, Status: TaskDone},
			{ID: 2, Priority: 2, Status: TaskFailed},
			{ID: 3, Priority: 3, Status: TaskPending},
		},
	}
	next := plan.NextTask()
	if next == nil {
		t.Fatal("expected a task, got nil")
	}
	if next.ID != 3 {
		t.Errorf("expected task ID 3, got %d", next.ID)
	}
}

func TestNextTask_NilWhenAllDone(t *testing.T) {
	plan := &Plan{
		Tasks: []*Task{
			{ID: 1, Status: TaskDone},
			{ID: 2, Status: TaskSkipped},
		},
	}
	if plan.NextTask() != nil {
		t.Error("expected nil when all tasks are done/skipped")
	}
}

func TestNextTask_EmptyPlan(t *testing.T) {
	plan := &Plan{Tasks: []*Task{}}
	if plan.NextTask() != nil {
		t.Error("expected nil for empty plan")
	}
}

// --- Plan.IsComplete ---

func TestIsComplete_AllDone(t *testing.T) {
	plan := &Plan{
		Tasks: []*Task{
			{Status: TaskDone},
			{Status: TaskSkipped},
			{Status: TaskDone},
		},
	}
	if !plan.IsComplete() {
		t.Error("expected plan to be complete")
	}
}

func TestIsComplete_HasPending(t *testing.T) {
	plan := &Plan{
		Tasks: []*Task{
			{Status: TaskDone},
			{Status: TaskPending},
		},
	}
	if plan.IsComplete() {
		t.Error("expected plan to not be complete (has pending)")
	}
}

func TestIsComplete_HasInProgress(t *testing.T) {
	plan := &Plan{
		Tasks: []*Task{
			{Status: TaskDone},
			{Status: TaskInProgress},
		},
	}
	if plan.IsComplete() {
		t.Error("expected plan to not be complete (has in_progress)")
	}
}

func TestIsComplete_EmptyPlan(t *testing.T) {
	plan := &Plan{Tasks: []*Task{}}
	if plan.IsComplete() {
		t.Error("empty plan should not be complete")
	}
}

func TestIsComplete_HasFailed(t *testing.T) {
	// Failed tasks count as terminal — plan is complete if all are done/skipped/failed
	// but the current logic requires pending/in_progress to be absent.
	plan := &Plan{
		Tasks: []*Task{
			{Status: TaskDone},
			{Status: TaskFailed},
		},
	}
	if !plan.IsComplete() {
		t.Error("plan with only done/failed tasks should be complete")
	}
}

// --- Plan.Summary ---

func TestSummary(t *testing.T) {
	plan := &Plan{
		Tasks: []*Task{
			{Status: TaskDone},
			{Status: TaskDone},
			{Status: TaskSkipped},
			{Status: TaskFailed},
			{Status: TaskPending},
		},
	}
	got := plan.Summary()
	// 3 done+skipped, 5 total
	if got != "3/5 tasks complete" {
		t.Errorf("unexpected summary: %q", got)
	}
}

func TestSummary_Empty(t *testing.T) {
	plan := &Plan{Tasks: []*Task{}}
	got := plan.Summary()
	if got != "0/0 tasks complete" {
		t.Errorf("unexpected summary: %q", got)
	}
}

// --- CheckTaskSignal ---

func TestCheckTaskSignal_Done(t *testing.T) {
	output := "I finished the task.\n\nTASK_DONE"
	if got := CheckTaskSignal(output); got != TaskDone {
		t.Errorf("expected TaskDone, got %q", got)
	}
}

func TestCheckTaskSignal_Skipped(t *testing.T) {
	output := "This was already done.\nTASK_SKIPPED"
	if got := CheckTaskSignal(output); got != TaskSkipped {
		t.Errorf("expected TaskSkipped, got %q", got)
	}
}

func TestCheckTaskSignal_Failed(t *testing.T) {
	output := "Could not complete it.\nTASK_FAILED"
	if got := CheckTaskSignal(output); got != TaskFailed {
		t.Errorf("expected TaskFailed, got %q", got)
	}
}

func TestCheckTaskSignal_NoSignal(t *testing.T) {
	output := "Some output without any signal."
	if got := CheckTaskSignal(output); got != TaskInProgress {
		t.Errorf("expected TaskInProgress, got %q", got)
	}
}

func TestCheckTaskSignal_SignalWithWhitespace(t *testing.T) {
	output := "Done!\n  TASK_DONE  \n"
	if got := CheckTaskSignal(output); got != TaskDone {
		t.Errorf("expected TaskDone for signal with surrounding whitespace, got %q", got)
	}
}

func TestCheckTaskSignal_SignalBeyondLast5Lines(t *testing.T) {
	// Signal in line 1 of a 10-line output — should NOT be detected (only last 5 checked)
	lines := []string{
		"TASK_DONE", // line 1 — too far back
		"line 2", "line 3", "line 4", "line 5", "line 6",
		"line 7", "line 8", "line 9", "line 10",
	}
	output := strings.Join(lines, "\n")
	if got := CheckTaskSignal(output); got != TaskInProgress {
		t.Errorf("expected TaskInProgress (signal too far back), got %q", got)
	}
}

func TestCheckTaskSignal_SignalInLast5Lines(t *testing.T) {
	lines := []string{
		"line 1", "line 2", "line 3", "line 4", "line 5",
		"line 6", "line 7", "line 8",
		"TASK_DONE", // 9th of 10 — within last 5
		"line 10",
	}
	output := strings.Join(lines, "\n")
	if got := CheckTaskSignal(output); got != TaskDone {
		t.Errorf("expected TaskDone, got %q", got)
	}
}

// --- ParseTaskPlan ---

func TestParseTaskPlan_Valid(t *testing.T) {
	goal := "Build a CLI tool"
	json := `{"tasks":[{"id":1,"title":"Setup","description":"Initialize project","priority":1},{"id":2,"title":"Implement","description":"Write code","priority":2}]}`
	plan, err := ParseTaskPlan(goal, json)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Goal != goal {
		t.Errorf("expected goal %q, got %q", goal, plan.Goal)
	}
	if len(plan.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(plan.Tasks))
	}
	if plan.Tasks[0].Title != "Setup" {
		t.Errorf("unexpected task title: %q", plan.Tasks[0].Title)
	}
	if plan.Tasks[1].Priority != 2 {
		t.Errorf("unexpected priority: %d", plan.Tasks[1].Priority)
	}
	for _, task := range plan.Tasks {
		if task.Status != TaskPending {
			t.Errorf("expected pending status, got %q", task.Status)
		}
	}
}

func TestParseTaskPlan_JSONEmbeddedInText(t *testing.T) {
	// AI often wraps JSON in explanation text
	output := `Here is the task plan:\n{"tasks":[{"id":1,"title":"First","description":"Do first thing","priority":1}]}\nEnd of plan.`
	plan, err := ParseTaskPlan("goal", output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(plan.Tasks))
	}
}

func TestParseTaskPlan_ZeroIDFallsBackToIndex(t *testing.T) {
	json := `{"tasks":[{"id":0,"title":"A","description":"desc","priority":0}]}`
	plan, err := ParseTaskPlan("goal", json)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Tasks[0].ID != 1 {
		t.Errorf("expected ID=1 fallback, got %d", plan.Tasks[0].ID)
	}
	if plan.Tasks[0].Priority != 1 {
		t.Errorf("expected Priority=1 fallback, got %d", plan.Tasks[0].Priority)
	}
}

func TestParseTaskPlan_NoJSON(t *testing.T) {
	_, err := ParseTaskPlan("goal", "no json here at all")
	if err == nil {
		t.Error("expected error for missing JSON")
	}
}

func TestParseTaskPlan_InvalidJSON(t *testing.T) {
	_, err := ParseTaskPlan("goal", "{not valid json}")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- NewPlan ---

func TestNewPlan(t *testing.T) {
	goal := "test goal"
	plan := NewPlan(goal)
	if plan.Goal != goal {
		t.Errorf("expected goal %q, got %q", goal, plan.Goal)
	}
	if plan.Version != 1 {
		t.Errorf("expected version 1, got %d", plan.Version)
	}
	if len(plan.Tasks) != 0 {
		t.Errorf("expected empty tasks, got %d", len(plan.Tasks))
	}
}

// --- Task timestamps ---

func TestTask_Timestamps(t *testing.T) {
	now := time.Now()
	task := &Task{
		ID:        1,
		Status:    TaskInProgress,
		StartedAt: &now,
	}
	if task.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}
	if task.CompletedAt != nil {
		t.Error("expected CompletedAt to be nil")
	}
}

// --- DecomposePrompt ---

func TestDecomposePrompt_ContainsGoal(t *testing.T) {
	goal := "Build a web scraper"
	prompt := DecomposePrompt(goal, "")
	if !strings.Contains(prompt, goal) {
		t.Errorf("prompt missing goal text")
	}
	if !strings.Contains(prompt, "JSON") {
		t.Errorf("prompt missing JSON instruction")
	}
}

func TestDecomposePrompt_WithInstructions(t *testing.T) {
	prompt := DecomposePrompt("goal", "Use Go only")
	if !strings.Contains(prompt, "Use Go only") {
		t.Errorf("prompt missing instructions")
	}
}

func TestDecomposePrompt_NoInstructions(t *testing.T) {
	prompt := DecomposePrompt("goal", "")
	if strings.Contains(prompt, "CONSTRAINTS") {
		t.Errorf("prompt should not contain CONSTRAINTS section when instructions empty")
	}
}

// --- ExecuteTaskPrompt ---

func TestExecuteTaskPrompt_ContainsTask(t *testing.T) {
	task := &Task{ID: 3, Title: "Write tests", Description: "Add unit tests for the pm package"}
	plan := &Plan{Goal: "Build CLI", Tasks: []*Task{task}}
	prompt := ExecuteTaskPrompt("Build CLI", "", "", plan, task)
	if !strings.Contains(prompt, "Write tests") {
		t.Errorf("prompt missing task title")
	}
	if !strings.Contains(prompt, "TASK_DONE") {
		t.Errorf("prompt missing TASK_DONE signal instruction")
	}
}

func TestExecuteTaskPrompt_ShowsCompletedTasks(t *testing.T) {
	done := &Task{ID: 1, Title: "Init project", Status: TaskDone}
	current := &Task{ID: 2, Title: "Add features", Status: TaskPending}
	plan := &Plan{Goal: "goal", Tasks: []*Task{done, current}}
	prompt := ExecuteTaskPrompt("goal", "", "", plan, current)
	if !strings.Contains(prompt, "Init project") {
		t.Errorf("prompt missing completed task")
	}
}

func TestExecuteTaskPrompt_ShowsPendingTasks(t *testing.T) {
	current := &Task{ID: 1, Title: "First", Status: TaskPending}
	upcoming := &Task{ID: 2, Title: "Second", Status: TaskPending}
	plan := &Plan{Goal: "goal", Tasks: []*Task{current, upcoming}}
	prompt := ExecuteTaskPrompt("goal", "", "", plan, current)
	if !strings.Contains(prompt, "Second") {
		t.Errorf("prompt missing upcoming task")
	}
	if strings.Count(prompt, "First") < 1 {
		t.Errorf("prompt missing current task title")
	}
}

func TestExecuteTaskPrompt_IncludesCompletedTaskResult(t *testing.T) {
	done := &Task{
		ID:     1,
		Title:  "Setup DB",
		Status: TaskDone,
		Result: "Created schema with users and products tables.",
	}
	current := &Task{ID: 2, Title: "Add API", Status: TaskPending}
	plan := &Plan{Goal: "goal", Tasks: []*Task{done, current}}
	prompt := ExecuteTaskPrompt("goal", "", "", plan, current)
	if !strings.Contains(prompt, "Created schema") {
		t.Errorf("prompt missing result summary from completed task")
	}
}

func TestExecuteTaskPrompt_TruncatesLongResult(t *testing.T) {
	longResult := strings.Repeat("x", 300)
	done := &Task{ID: 1, Title: "Big task", Status: TaskDone, Result: longResult}
	current := &Task{ID: 2, Title: "Next", Status: TaskPending}
	plan := &Plan{Goal: "goal", Tasks: []*Task{done, current}}
	prompt := ExecuteTaskPrompt("goal", "", "", plan, current)
	// Result should be truncated to 200 chars + "..."
	if strings.Contains(prompt, longResult) {
		t.Errorf("prompt should truncate long result, but full result found")
	}
	if !strings.Contains(prompt, "...") {
		t.Errorf("prompt should contain truncation marker '...'")
	}
}

func TestExecuteTaskPrompt_SkippedTaskUsesMinusMarker(t *testing.T) {
	skipped := &Task{ID: 1, Title: "Optional", Status: TaskSkipped}
	current := &Task{ID: 2, Title: "Main", Status: TaskPending}
	plan := &Plan{Goal: "goal", Tasks: []*Task{skipped, current}}
	prompt := ExecuteTaskPrompt("goal", "", "", plan, current)
	if !strings.Contains(prompt, "[-]") {
		t.Errorf("skipped task should use [-] marker")
	}
}

func TestExecuteTaskPrompt_NoResultOmitsSummaryLine(t *testing.T) {
	done := &Task{ID: 1, Title: "Done task", Status: TaskDone, Result: ""}
	current := &Task{ID: 2, Title: "Next", Status: TaskPending}
	plan := &Plan{Goal: "goal", Tasks: []*Task{done, current}}
	prompt := ExecuteTaskPrompt("goal", "", "", plan, current)
	if strings.Contains(prompt, "Summary:") {
		t.Errorf("prompt should not include 'Summary:' when result is empty")
	}
}
