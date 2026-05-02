package pm

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// mockProvider is a simple provider.Provider for testing.
type mockCloneProvider struct {
	output string
	err    error
}

func (m *mockCloneProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &provider.Result{Output: m.output}, nil
}

func (m *mockCloneProvider) Name() string        { return "mock" }
func (m *mockCloneProvider) DefaultModel() string { return "mock-model" }

// ---- ClonePrompt tests ----

func TestClonePrompt_ContainsOriginalTask(t *testing.T) {
	task := &Task{ID: 3, Title: "Add unit tests for auth", Description: "Write tests covering login and signup.", Role: "testing"}
	prompt := ClonePrompt(task, "for the payment module instead of auth")

	if !strings.Contains(prompt, "Add unit tests for auth") {
		t.Error("prompt should contain original task title")
	}
	if !strings.Contains(prompt, "Write tests covering login and signup.") {
		t.Error("prompt should contain original task description")
	}
	if !strings.Contains(prompt, "for the payment module instead of auth") {
		t.Error("prompt should contain adapt context")
	}
}

func TestClonePrompt_ContainsRoleWhenSet(t *testing.T) {
	task := &Task{ID: 1, Title: "Write docs", Role: "docs"}
	prompt := ClonePrompt(task, "for v2 API")
	if !strings.Contains(prompt, "[role: docs]") {
		t.Error("prompt should include role when set")
	}
}

func TestClonePrompt_NoRoleWhenEmpty(t *testing.T) {
	task := &Task{ID: 1, Title: "Write docs"}
	prompt := ClonePrompt(task, "for v2 API")
	if strings.Contains(prompt, "[role:") {
		t.Error("prompt should not include role bracket when role is empty")
	}
}

func TestClonePrompt_OutputsJSONSchema(t *testing.T) {
	task := &Task{ID: 2, Title: "Add cache layer"}
	prompt := ClonePrompt(task, "for Redis instead of in-memory")
	if !strings.Contains(prompt, `{"title":`) {
		t.Error("prompt should contain JSON output schema hint")
	}
}

// ---- parseCloneResponse tests ----

func TestParseCloneResponse_Valid(t *testing.T) {
	resp := `{"title":"Add unit tests for payment","description":"Write tests covering checkout and refund flows."}`
	item, err := parseCloneResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.Title != "Add unit tests for payment" {
		t.Errorf("expected title, got %q", item.Title)
	}
	if item.Description != "Write tests covering checkout and refund flows." {
		t.Errorf("unexpected description: %q", item.Description)
	}
}

func TestParseCloneResponse_WithSurroundingText(t *testing.T) {
	resp := `Here is the adapted task:\n{"title":"Adapted title","description":"Adapted desc"}\nDone.`
	item, err := parseCloneResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.Title != "Adapted title" {
		t.Errorf("expected 'Adapted title', got %q", item.Title)
	}
}

func TestParseCloneResponse_NoJSON(t *testing.T) {
	_, err := parseCloneResponse("No JSON here at all")
	if err == nil {
		t.Error("expected error for response with no JSON object")
	}
}

func TestParseCloneResponse_EmptyTitle(t *testing.T) {
	_, err := parseCloneResponse(`{"title":"","description":"something"}`)
	if err == nil {
		t.Error("expected error when title is empty")
	}
}

func TestParseCloneResponse_InvalidJSON(t *testing.T) {
	_, err := parseCloneResponse(`{not valid json}`)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ---- Clone function tests ----

func makeTestPlan() *Plan {
	t1 := &Task{
		ID:               1,
		Title:            "Add unit tests for auth",
		Description:      "Write tests covering login and signup.",
		Priority:         2,
		Role:             "testing",
		Status:           TaskDone,
		DependsOn:        []int{},
		Tags:             []string{"auth", "testing"},
		EstimatedMinutes: 30,
	}
	t2 := &Task{
		ID:       2,
		Title:    "Deploy to staging",
		Priority: 3,
		Status:   TaskPending,
	}
	now := time.Now()
	t1.StartedAt = &now
	t1.CompletedAt = &now
	return &Plan{Goal: "test goal", Tasks: []*Task{t1, t2}}
}

func TestClone_WithoutAdapt_CopyTitle(t *testing.T) {
	plan := makeTestPlan()
	cloned, err := Clone(context.Background(), nil, provider.Options{}, plan, 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cloned.Title != "Add unit tests for auth (copy)" {
		t.Errorf("expected '... (copy)' suffix, got %q", cloned.Title)
	}
}

func TestClone_WithoutAdapt_AssignsNextID(t *testing.T) {
	plan := makeTestPlan()
	cloned, err := Clone(context.Background(), nil, provider.Options{}, plan, 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cloned.ID != 3 {
		t.Errorf("expected ID 3 (max was 2), got %d", cloned.ID)
	}
}

func TestClone_WithoutAdapt_StatusPending(t *testing.T) {
	plan := makeTestPlan()
	cloned, err := Clone(context.Background(), nil, provider.Options{}, plan, 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cloned.Status != TaskPending {
		t.Errorf("expected status pending, got %s", cloned.Status)
	}
}

func TestClone_WithoutAdapt_InheritsFields(t *testing.T) {
	plan := makeTestPlan()
	cloned, err := Clone(context.Background(), nil, provider.Options{}, plan, 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cloned.Priority != 2 {
		t.Errorf("expected priority 2, got %d", cloned.Priority)
	}
	if cloned.Role != "testing" {
		t.Errorf("expected role testing, got %q", cloned.Role)
	}
	if len(cloned.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(cloned.Tags))
	}
	if cloned.EstimatedMinutes != 30 {
		t.Errorf("expected estimated minutes 30, got %d", cloned.EstimatedMinutes)
	}
}

func TestClone_WithoutAdapt_AppendedToPlan(t *testing.T) {
	plan := makeTestPlan()
	originalLen := len(plan.Tasks)
	_, err := Clone(context.Background(), nil, provider.Options{}, plan, 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Tasks) != originalLen+1 {
		t.Errorf("expected plan to grow by 1, got %d tasks", len(plan.Tasks))
	}
}

func TestClone_WithoutAdapt_CopiesTagsSlice(t *testing.T) {
	plan := makeTestPlan()
	cloned, err := Clone(context.Background(), nil, provider.Options{}, plan, 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Mutating cloned tags must not affect original
	original := plan.Tasks[0]
	cloned.Tags = append(cloned.Tags, "extra")
	if len(original.Tags) != 2 {
		t.Error("cloned tags slice should be independent of original")
	}
}

func TestClone_WithAdapt_CallsProvider(t *testing.T) {
	plan := makeTestPlan()
	prov := &mockCloneProvider{
		output: `{"title":"Add unit tests for payment","description":"Write tests for payment flows."}`,
	}
	cloned, err := Clone(context.Background(), prov, provider.Options{}, plan, 1, "for the payment module instead of auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cloned.Title != "Add unit tests for payment" {
		t.Errorf("expected adapted title, got %q", cloned.Title)
	}
	if cloned.Description != "Write tests for payment flows." {
		t.Errorf("expected adapted description, got %q", cloned.Description)
	}
}

func TestClone_WithAdapt_ProviderError(t *testing.T) {
	plan := makeTestPlan()
	prov := &mockCloneProvider{err: fmt.Errorf("provider unavailable")}
	_, err := Clone(context.Background(), prov, provider.Options{}, plan, 1, "for payment")
	if err == nil {
		t.Error("expected error when provider fails")
	}
	if !strings.Contains(err.Error(), "provider unavailable") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestClone_WithAdapt_BadJSON(t *testing.T) {
	plan := makeTestPlan()
	prov := &mockCloneProvider{output: "not json at all"}
	_, err := Clone(context.Background(), prov, provider.Options{}, plan, 1, "for payment")
	if err == nil {
		t.Error("expected error when AI returns invalid JSON")
	}
}

func TestClone_TaskNotFound(t *testing.T) {
	plan := makeTestPlan()
	_, err := Clone(context.Background(), nil, provider.Options{}, plan, 999, "")
	if err == nil {
		t.Error("expected error for non-existent task ID")
	}
	if !strings.Contains(err.Error(), "999") {
		t.Errorf("error should mention missing ID: %v", err)
	}
}

func TestClone_WithAdapt_InheritsNonTitleFields(t *testing.T) {
	plan := makeTestPlan()
	prov := &mockCloneProvider{
		output: `{"title":"New title","description":"New desc"}`,
	}
	cloned, err := Clone(context.Background(), prov, provider.Options{}, plan, 1, "adapt context")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Non-title fields should still be inherited from original
	if cloned.Priority != 2 {
		t.Errorf("expected inherited priority 2, got %d", cloned.Priority)
	}
	if cloned.Role != "testing" {
		t.Errorf("expected inherited role, got %q", cloned.Role)
	}
}
