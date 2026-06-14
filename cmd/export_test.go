package cmd

import (
	"encoding/csv"
	"encoding/json"
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

// ---------- JSON format tests ----------

func TestBuildJSONReport_IsValidJSON(t *testing.T) {
	s := baseState()
	data, err := buildJSONReport(s)
	if err != nil {
		t.Fatalf("buildJSONReport failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("emitted JSON is not parseable: %v", err)
	}
}

func TestBuildJSONReport_ContainsGoalAndProvider(t *testing.T) {
	s := baseState()
	data, err := buildJSONReport(s)
	if err != nil {
		t.Fatalf("buildJSONReport failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("emitted JSON is not parseable: %v", err)
	}
	if out["goal"] != "Build a REST API" {
		t.Errorf("goal field missing/wrong: %v", out["goal"])
	}
	if out["provider"] != "anthropic" {
		t.Errorf("provider field missing/wrong: %v", out["provider"])
	}
}

func TestBuildJSONReport_RoundTripsPlan(t *testing.T) {
	s := baseState()
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "Build REST API",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Setup", Priority: 1, Status: pm.TaskDone, Role: "backend"},
			{ID: 2, Title: "Endpoints", Priority: 2, Status: pm.TaskPending, Role: "backend"},
		},
	}
	data, err := buildJSONReport(s)
	if err != nil {
		t.Fatalf("buildJSONReport failed: %v", err)
	}
	// Reverse-decode into a ProjectState and verify the plan came through.
	var decoded state.ProjectState
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("emitted JSON cannot be decoded back into ProjectState: %v", err)
	}
	if decoded.Plan == nil || len(decoded.Plan.Tasks) != 2 {
		t.Fatalf("plan did not round-trip: %+v", decoded.Plan)
	}
	if decoded.Plan.Tasks[0].Title != "Setup" || decoded.Plan.Tasks[1].Title != "Endpoints" {
		t.Errorf("task titles wrong after round-trip: %+v", decoded.Plan.Tasks)
	}
}

func TestBuildJSONReport_IsIndented(t *testing.T) {
	s := baseState()
	data, err := buildJSONReport(s)
	if err != nil {
		t.Fatalf("buildJSONReport failed: %v", err)
	}
	// Indented JSON has newlines and 2-space indentation.
	if !strings.Contains(string(data), "\n  ") {
		t.Error("JSON output should be indented for readability")
	}
}

// ---------- CSV format tests ----------

func TestBuildCSVReport_HeaderOnlyWhenEmptyPlan(t *testing.T) {
	s := baseState()
	out, err := buildCSVReport(s)
	if err != nil {
		t.Fatalf("buildCSVReport failed: %v", err)
	}
	rows := mustParseCSV(t, out)
	if len(rows) != 1 {
		t.Fatalf("expected header-only CSV, got %d rows", len(rows))
	}
	want := []string{"id", "title", "status", "priority", "role", "estimated_minutes", "actual_minutes", "variance_pct"}
	if !equalSlice(rows[0], want) {
		t.Errorf("header mismatch:\n got %v\nwant %v", rows[0], want)
	}
}

func TestBuildCSVReport_EmitsTasks(t *testing.T) {
	s := baseState()
	s.PMMode = true
	now := time.Now()
	completed := now.Add(6 * time.Minute)
	s.Plan = &pm.Plan{
		Goal: "Build REST API",
		Tasks: []*pm.Task{
			{
				ID: 1, Title: "Setup", Priority: 1, Status: pm.TaskDone, Role: "backend",
				EstimatedMinutes: 10, ActualMinutes: 12,
			},
			{
				ID: 2, Title: "Endpoints, with comma", Priority: 2, Status: pm.TaskPending, Role: "frontend",
			},
			{
				ID: 3, Title: "Inferred actual", Priority: 3, Status: pm.TaskDone, Role: "qa",
				EstimatedMinutes: 5, StartedAt: &now, CompletedAt: &completed,
			},
		},
	}
	out, err := buildCSVReport(s)
	if err != nil {
		t.Fatalf("buildCSVReport failed: %v", err)
	}
	rows := mustParseCSV(t, out)
	if len(rows) != 4 {
		t.Fatalf("expected 1 header + 3 task rows, got %d", len(rows))
	}

	// Header.
	wantHeader := []string{"id", "title", "status", "priority", "role", "estimated_minutes", "actual_minutes", "variance_pct"}
	if !equalSlice(rows[0], wantHeader) {
		t.Errorf("header mismatch:\n got %v\nwant %v", rows[0], wantHeader)
	}

	// Task 1: estimated 10, actual 12 → variance +20.0.
	want := []string{"1", "Setup", "done", "1", "backend", "10", "12", "20.0"}
	if !equalSlice(rows[1], want) {
		t.Errorf("row 1 mismatch:\n got %v\nwant %v", rows[1], want)
	}

	// Task 2: no estimate, no actual — empty columns. Embedded comma must survive CSV escaping.
	if rows[2][1] != "Endpoints, with comma" {
		t.Errorf("comma in title not escaped: %q", rows[2][1])
	}
	if rows[2][5] != "" || rows[2][6] != "" || rows[2][7] != "" {
		t.Errorf("expected empty estimate/actual/variance columns, got %v", rows[2][5:])
	}

	// Task 3: actual inferred from StartedAt/CompletedAt → 6 minutes; variance +20.0.
	if rows[3][6] != "6" {
		t.Errorf("expected inferred actual=6, got %q", rows[3][6])
	}
	if rows[3][7] != "20.0" {
		t.Errorf("expected variance=20.0, got %q", rows[3][7])
	}
}

func TestBuildCSVReport_NilPlan(t *testing.T) {
	s := baseState()
	s.Plan = nil
	out, err := buildCSVReport(s)
	if err != nil {
		t.Fatalf("buildCSVReport failed with nil plan: %v", err)
	}
	rows := mustParseCSV(t, out)
	if len(rows) != 1 {
		t.Fatalf("expected header-only CSV with nil plan, got %d rows", len(rows))
	}
}

func mustParseCSV(t *testing.T, in string) [][]string {
	t.Helper()
	r := csv.NewReader(strings.NewReader(in))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("emitted CSV is not parseable: %v\n---\n%s", err, in)
	}
	return rows
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
