package cmd

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
)

// --- grepSteps ---

func TestGrepSteps_MatchesOutput(t *testing.T) {
	steps := []state.StepResult{
		{Step: 0, Task: "task", Output: "wrote main.go with handler", Duration: "1s", Time: time.Now()},
		{Step: 1, Task: "task", Output: "added unit tests", Duration: "1s", Time: time.Now()},
		{Step: 2, Task: "task", Output: "fixed compilation error", Duration: "1s", Time: time.Now()},
	}
	got := grepSteps(steps, "unit tests")
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	if got[0].Step != 1 {
		t.Errorf("expected step index 1, got %d", got[0].Step)
	}
}

func TestGrepSteps_CaseInsensitive(t *testing.T) {
	steps := []state.StepResult{
		{Step: 0, Task: "task", Output: "Added REST API endpoints", Duration: "1s", Time: time.Now()},
	}
	got := grepSteps(steps, "rest api")
	if len(got) != 1 {
		t.Fatalf("expected 1 match (case-insensitive), got %d", len(got))
	}
}

func TestGrepSteps_MatchesTaskName(t *testing.T) {
	steps := []state.StepResult{
		{Step: 0, Task: "Setup database", Output: "running migrations", Duration: "1s", Time: time.Now()},
		{Step: 1, Task: "Add auth routes", Output: "implemented JWT", Duration: "1s", Time: time.Now()},
	}
	got := grepSteps(steps, "database")
	if len(got) != 1 {
		t.Fatalf("expected 1 match by task name, got %d", len(got))
	}
	if got[0].Step != 0 {
		t.Errorf("expected step 0, got %d", got[0].Step)
	}
}

func TestGrepSteps_NoMatch(t *testing.T) {
	steps := []state.StepResult{
		{Step: 0, Task: "task", Output: "did something", Duration: "1s", Time: time.Now()},
	}
	got := grepSteps(steps, "nonexistent pattern xyz")
	if len(got) != 0 {
		t.Errorf("expected 0 matches, got %d", len(got))
	}
}

func TestGrepSteps_EmptyInput(t *testing.T) {
	got := grepSteps([]state.StepResult{}, "anything")
	if got != nil && len(got) != 0 {
		t.Errorf("expected empty result for empty input, got %d", len(got))
	}
}

func TestGrepSteps_MultipleMatches(t *testing.T) {
	steps := []state.StepResult{
		{Step: 0, Task: "task", Output: "error: file not found", Duration: "1s", Time: time.Now()},
		{Step: 1, Task: "task", Output: "no error this time", Duration: "1s", Time: time.Now()},
		{Step: 2, Task: "task", Output: "another error occurred", Duration: "1s", Time: time.Now()},
	}
	got := grepSteps(steps, "error")
	if len(got) != 3 {
		t.Errorf("expected 3 matches (all contain 'error'), got %d", len(got))
	}
}

// makeSteps builds a slice of N StepResults with sequential Step indices.
func makeSteps(n int) []state.StepResult {
	steps := make([]state.StepResult, n)
	for i := 0; i < n; i++ {
		steps[i] = state.StepResult{
			Step:     i,
			Task:     "task",
			Output:   "output",
			Duration: "1s",
			Time:     time.Now(),
		}
	}
	return steps
}

// --- filterSteps ---

func TestFilterSteps_NoFilter(t *testing.T) {
	steps := makeSteps(5)
	got, err := filterSteps(steps, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5 steps, got %d", len(got))
	}
}

func TestFilterSteps_SpecificStep_Found(t *testing.T) {
	steps := makeSteps(5) // steps 0..4, 1-indexed: 1..5
	got, err := filterSteps(steps, 3, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 step, got %d", len(got))
	}
	if got[0].Step != 2 { // step index 2 = step number 3
		t.Errorf("expected step index 2, got %d", got[0].Step)
	}
}

func TestFilterSteps_SpecificStep_NotFound(t *testing.T) {
	steps := makeSteps(3)
	_, err := filterSteps(steps, 10, 0)
	if err == nil {
		t.Error("expected error for non-existent step")
	}
}

func TestFilterSteps_SpecificStep_First(t *testing.T) {
	steps := makeSteps(4)
	got, err := filterSteps(steps, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Step != 0 {
		t.Errorf("expected step index 0, got len=%d", len(got))
	}
}

func TestFilterSteps_SpecificStep_Last(t *testing.T) {
	steps := makeSteps(4)
	got, err := filterSteps(steps, 4, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Step != 3 {
		t.Errorf("expected step index 3, got %d", got[0].Step)
	}
}

func TestFilterSteps_LastN_LessThanTotal(t *testing.T) {
	steps := makeSteps(10)
	got, err := filterSteps(steps, 0, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(got))
	}
	// Should be the last 3: indices 7, 8, 9
	if got[0].Step != 7 {
		t.Errorf("expected first returned step index 7, got %d", got[0].Step)
	}
	if got[2].Step != 9 {
		t.Errorf("expected last returned step index 9, got %d", got[2].Step)
	}
}

func TestFilterSteps_LastN_GreaterThanTotal(t *testing.T) {
	steps := makeSteps(3)
	got, err := filterSteps(steps, 0, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected all 3 steps, got %d", len(got))
	}
}

func TestFilterSteps_LastN_ExactTotal(t *testing.T) {
	steps := makeSteps(5)
	got, err := filterSteps(steps, 0, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5 steps, got %d", len(got))
	}
}

func TestFilterSteps_LastN_One(t *testing.T) {
	steps := makeSteps(7)
	got, err := filterSteps(steps, 0, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 step, got %d", len(got))
	}
	if got[0].Step != 6 {
		t.Errorf("expected step index 6 (last), got %d", got[0].Step)
	}
}

func TestFilterSteps_EmptyInput_NoError(t *testing.T) {
	got, err := filterSteps([]state.StepResult{}, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d", len(got))
	}
}

func TestFilterSteps_EmptyInput_SpecificStep_Error(t *testing.T) {
	_, err := filterSteps([]state.StepResult{}, 1, 0)
	if err == nil {
		t.Error("expected error when searching for step in empty slice")
	}
}

// stepNum takes priority over lastN when both are set (stepNum > 0 is checked first).
func TestFilterSteps_StepNumTakesPriorityOverLastN(t *testing.T) {
	steps := makeSteps(10)
	got, err := filterSteps(steps, 2, 3) // both set — stepNum wins
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Step != 1 {
		t.Errorf("expected single step with index 1, got len=%d", len(got))
	}
}
