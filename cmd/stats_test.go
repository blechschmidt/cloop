package cmd

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestComputeStepDurations_empty(t *testing.T) {
	total, min, max, count := computeStepDurations(nil)
	if count != 0 || total != 0 || min != 0 || max != 0 {
		t.Errorf("expected all zeros for empty input, got total=%v min=%v max=%v count=%d", total, min, max, count)
	}
}

func TestComputeStepDurations_valid(t *testing.T) {
	steps := []state.StepResult{
		{Duration: "10s"},
		{Duration: "30s"},
		{Duration: "20s"},
	}
	total, min, max, count := computeStepDurations(steps)
	if count != 3 {
		t.Errorf("expected count=3, got %d", count)
	}
	if total != 60*time.Second {
		t.Errorf("expected total=60s, got %v", total)
	}
	if min != 10*time.Second {
		t.Errorf("expected min=10s, got %v", min)
	}
	if max != 30*time.Second {
		t.Errorf("expected max=30s, got %v", max)
	}
}

func TestComputeStepDurations_invalidSkipped(t *testing.T) {
	steps := []state.StepResult{
		{Duration: "5s"},
		{Duration: "not-a-duration"},
		{Duration: "15s"},
	}
	total, min, max, count := computeStepDurations(steps)
	if count != 2 {
		t.Errorf("expected count=2, skipping invalid; got %d", count)
	}
	if total != 20*time.Second {
		t.Errorf("expected total=20s, got %v", total)
	}
	if min != 5*time.Second {
		t.Errorf("expected min=5s, got %v", min)
	}
	if max != 15*time.Second {
		t.Errorf("expected max=15s, got %v", max)
	}
}

func TestEstimateCost_unknownModel(t *testing.T) {
	s := &state.ProjectState{
		Model:             "unknown-model",
		TotalInputTokens:  1000,
		TotalOutputTokens: 500,
	}
	_, ok := estimateCost(s)
	if ok {
		t.Error("expected no cost estimate for unknown model")
	}
}

func TestEstimateCost_emptyModel(t *testing.T) {
	s := &state.ProjectState{
		TotalInputTokens:  1000,
		TotalOutputTokens: 500,
	}
	_, ok := estimateCost(s)
	if ok {
		t.Error("expected no cost estimate when model is empty")
	}
}

func TestEstimateCost_knownModel(t *testing.T) {
	s := &state.ProjectState{
		Model:             "gpt-4o",
		TotalInputTokens:  1_000_000,
		TotalOutputTokens: 1_000_000,
	}
	cost, ok := estimateCost(s)
	if !ok {
		t.Fatal("expected cost estimate for gpt-4o")
	}
	// 1M input * $2.5/1M + 1M output * $10/1M = $12.50
	expected := 12.50
	if cost < expected-0.01 || cost > expected+0.01 {
		t.Errorf("expected cost ~$%.2f, got $%.4f", expected, cost)
	}
}

func TestEstimateCost_claudeSonnet(t *testing.T) {
	s := &state.ProjectState{
		Model:             "claude-sonnet-4-6",
		TotalInputTokens:  2_000_000,
		TotalOutputTokens: 500_000,
	}
	cost, ok := estimateCost(s)
	if !ok {
		t.Fatal("expected cost estimate for claude-sonnet-4-6")
	}
	// 2M input * $3/1M + 0.5M output * $15/1M = $6 + $7.5 = $13.5
	expected := 13.5
	if cost < expected-0.01 || cost > expected+0.01 {
		t.Errorf("expected cost ~$%.2f, got $%.4f", expected, cost)
	}
}

// cloop stats prices with pkg/cost, so every model the pickers offer has the
// price the budget caps use instead of a second table that drifts.
func TestEstimateCost_newestClaudeModels(t *testing.T) {
	for model, want := range map[string]float64{
		"claude-fable-5-2":  8 + 40,
		"claude-opus-5-5":   4 + 20,
		"claude-sonnet-5-5": 2 + 10,
		"claude-haiku-5-5":  0.10 + 0.50,
		"claude-opus-4-6":   5 + 25,
	} {
		s := &state.ProjectState{Model: model, TotalInputTokens: 1_000_000, TotalOutputTokens: 1_000_000}
		got, ok := estimateCost(s)
		if !ok || got < want-0.001 || got > want+0.001 {
			t.Errorf("estimateCost(%s, 1M, 1M) = %v, %v; want %v", model, got, ok, want)
		}
	}
}

func TestPrintStats_noSteps(t *testing.T) {
	// printStats should not panic when there are no steps
	s := &state.ProjectState{
		Goal:      "test goal",
		Status:    "initialized",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	// Just verify it doesn't panic
	printStats(s)
}

func TestPrintStats_withPMMode(t *testing.T) {
	now := time.Now()
	s := &state.ProjectState{
		Goal:      "pm test",
		Status:    "running",
		PMMode:    true,
		CreatedAt: now.Add(-10 * time.Minute),
		UpdatedAt: now,
		Plan: &pm.Plan{
			Goal: "pm test",
			Tasks: []*pm.Task{
				{ID: 1, Title: "Task A", Status: pm.TaskDone, Priority: 1},
				{ID: 2, Title: "Task B", Status: pm.TaskFailed, Priority: 2},
				{ID: 3, Title: "Task C", Status: pm.TaskPending, Priority: 3},
			},
		},
		Steps: []state.StepResult{
			{Step: 0, Duration: "5s", InputTokens: 100, OutputTokens: 200},
		},
		TotalInputTokens:  100,
		TotalOutputTokens: 200,
	}
	// Just verify it doesn't panic
	printStats(s)
}
