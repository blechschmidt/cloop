package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

func baseState() *state.ProjectState {
	now := time.Now()
	return &state.ProjectState{
		Goal:      "Build a REST API",
		Status:    "complete",
		Provider:  "anthropic",
		CreatedAt: now,
		UpdatedAt: now,
		Steps:     []state.StepResult{},
	}
}

func TestBuildReport_ContainsGoal(t *testing.T) {
	s := baseState()
	report := buildReport(s)
	if !strings.Contains(report, "Build a REST API") {
		t.Error("report missing goal")
	}
}

func TestBuildReport_ContainsStatus(t *testing.T) {
	s := baseState()
	report := buildReport(s)
	if !strings.Contains(report, "complete") {
		t.Error("report missing status")
	}
}

func TestBuildReport_ContainsProvider(t *testing.T) {
	s := baseState()
	report := buildReport(s)
	if !strings.Contains(report, "anthropic") {
		t.Error("report missing provider")
	}
}

func TestBuildReport_DefaultProviderWhenEmpty(t *testing.T) {
	s := baseState()
	s.Provider = ""
	report := buildReport(s)
	if !strings.Contains(report, "claudecode") {
		t.Error("report should show default provider when empty")
	}
}

func TestBuildReport_ContainsModel(t *testing.T) {
	s := baseState()
	s.Model = "claude-opus-4-6"
	report := buildReport(s)
	if !strings.Contains(report, "claude-opus-4-6") {
		t.Error("report missing model")
	}
}

func TestBuildReport_OmitsModelWhenEmpty(t *testing.T) {
	s := baseState()
	s.Model = ""
	report := buildReport(s)
	if strings.Contains(report, "**Model:**") {
		t.Error("report should not include model section when empty")
	}
}

func TestBuildReport_ContainsInstructions(t *testing.T) {
	s := baseState()
	s.Instructions = "use Go only"
	report := buildReport(s)
	if !strings.Contains(report, "use Go only") {
		t.Error("report missing instructions")
	}
}

func TestBuildReport_ContainsTokenUsage(t *testing.T) {
	s := baseState()
	s.TotalInputTokens = 1000
	s.TotalOutputTokens = 500
	report := buildReport(s)
	if !strings.Contains(report, "1000") {
		t.Error("report missing input token count")
	}
	if !strings.Contains(report, "500") {
		t.Error("report missing output token count")
	}
}

func TestBuildReport_OmitsTokensWhenZero(t *testing.T) {
	s := baseState()
	// TotalInputTokens and TotalOutputTokens are 0 by default
	report := buildReport(s)
	if strings.Contains(report, "**Tokens:**") {
		t.Error("report should not include Tokens line when usage is zero")
	}
}

func TestBuildReport_NoStepsMessage(t *testing.T) {
	s := baseState()
	report := buildReport(s)
	if !strings.Contains(report, "No steps recorded yet") {
		t.Error("report should mention no steps when there are none")
	}
}

func TestBuildReport_ContainsStepHistory(t *testing.T) {
	s := baseState()
	s.Steps = []state.StepResult{
		{
			Step:     0,
			Task:     "Step 1",
			Output:   "Created the project structure",
			Duration: "5s",
			Time:     time.Now(),
		},
	}
	report := buildReport(s)
	if !strings.Contains(report, "Created the project structure") {
		t.Error("report missing step output")
	}
	if !strings.Contains(report, "Step History") {
		t.Error("report missing step history section")
	}
}

func TestBuildReport_StepWithTokens(t *testing.T) {
	s := baseState()
	s.Steps = []state.StepResult{
		{
			Step:         0,
			Task:         "Step 1",
			Output:       "did work",
			Duration:     "3s",
			Time:         time.Now(),
			InputTokens:  200,
			OutputTokens: 80,
		},
	}
	report := buildReport(s)
	if !strings.Contains(report, "200") {
		t.Error("report missing input tokens for step")
	}
}

func TestBuildReport_PMMode(t *testing.T) {
	s := baseState()
	s.PMMode = true
	report := buildReport(s)
	if !strings.Contains(report, "product manager") {
		t.Error("report should mention product manager mode")
	}
}

func TestBuildReport_TaskPlan(t *testing.T) {
	s := baseState()
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "Build REST API",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Setup project", Description: "Init the repo", Priority: 1, Status: pm.TaskDone},
			{ID: 2, Title: "Add endpoints", Description: "Write handlers", Priority: 2, Status: pm.TaskPending},
		},
	}
	report := buildReport(s)
	if !strings.Contains(report, "Task Plan") {
		t.Error("report missing task plan section")
	}
	if !strings.Contains(report, "Setup project") {
		t.Error("report missing task title")
	}
	if !strings.Contains(report, "Add endpoints") {
		t.Error("report missing second task")
	}
}

func TestBuildReport_TaskDetails(t *testing.T) {
	s := baseState()
	s.PMMode = true
	now := time.Now()
	completed := now.Add(5 * time.Second)
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{
				ID:          1,
				Title:       "Setup",
				Description: "Initialize everything",
				Priority:    1,
				Status:      pm.TaskDone,
				Result:      "Done! Created main.go and go.mod.",
				StartedAt:   &now,
				CompletedAt: &completed,
			},
		},
	}
	report := buildReport(s)
	if !strings.Contains(report, "Initialize everything") {
		t.Error("report missing task description")
	}
	if !strings.Contains(report, "Done! Created main.go") {
		t.Error("report missing task result")
	}
}

func TestBuildReport_EscapeMD(t *testing.T) {
	s := baseState()
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Task with | pipe", Priority: 1, Status: pm.TaskPending},
		},
	}
	report := buildReport(s)
	// Pipe chars in table cells must be escaped
	if !strings.Contains(report, `Task with \| pipe`) {
		t.Error("report should escape pipe characters in markdown table cells")
	}
}

func TestBuildReport_IsMarkdown(t *testing.T) {
	s := baseState()
	report := buildReport(s)
	if !strings.HasPrefix(report, "# cloop Session Report") {
		t.Error("report should start with a markdown heading")
	}
}
