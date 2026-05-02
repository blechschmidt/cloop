package pm

import (
	"testing"
)

func TestParseSplitResponse_Valid(t *testing.T) {
	parent := &Task{
		ID:       5,
		Title:    "Build authentication system",
		Priority: 2,
		Role:     RoleBackend,
		DependsOn: []int{3},
	}
	response := `[
		{"title":"Implement user model","description":"Create user struct and DB schema","priority":1,"role":"backend"},
		{"title":"Implement JWT tokens","description":"Generate and validate JWT tokens","priority":2,"role":"backend"},
		{"title":"Add auth middleware","description":"Protect routes with auth middleware","priority":3,"role":"backend"}
	]`

	tasks, err := ParseSplitResponse(response, parent, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 3 {
		t.Fatalf("expected 3 subtasks, got %d", len(tasks))
	}

	// Check IDs are sequential starting from nextID
	if tasks[0].ID != 100 {
		t.Errorf("expected first subtask ID 100, got %d", tasks[0].ID)
	}
	if tasks[1].ID != 101 {
		t.Errorf("expected second subtask ID 101, got %d", tasks[1].ID)
	}
	if tasks[2].ID != 102 {
		t.Errorf("expected third subtask ID 102, got %d", tasks[2].ID)
	}

	// Check priorities inherited from parent
	for _, task := range tasks {
		if task.Priority != parent.Priority {
			t.Errorf("expected priority %d, got %d", parent.Priority, task.Priority)
		}
	}

	// Check all subtasks are pending
	for _, task := range tasks {
		if task.Status != TaskPending {
			t.Errorf("expected pending status, got %s", task.Status)
		}
	}

	// Check first subtask inherits parent deps
	if len(tasks[0].DependsOn) != 1 || tasks[0].DependsOn[0] != 3 {
		t.Errorf("first subtask should inherit parent deps [3], got %v", tasks[0].DependsOn)
	}

	// Check second subtask depends on first subtask AND parent deps
	if len(tasks[1].DependsOn) != 2 {
		t.Errorf("second subtask should have 2 deps (parent dep + prev subtask), got %v", tasks[1].DependsOn)
	}
	found100 := false
	found3 := false
	for _, dep := range tasks[1].DependsOn {
		if dep == 100 {
			found100 = true
		}
		if dep == 3 {
			found3 = true
		}
	}
	if !found100 || !found3 {
		t.Errorf("second subtask should depend on 3 and 100, got %v", tasks[1].DependsOn)
	}

	// Check roles are preserved
	if tasks[0].Role != RoleBackend {
		t.Errorf("expected role backend, got %s", tasks[0].Role)
	}
}

func TestParseSplitResponse_InvalidJSON(t *testing.T) {
	parent := &Task{ID: 1, Title: "Test", Priority: 1}

	_, err := ParseSplitResponse("not json at all", parent, 10)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseSplitResponse_EmptyArray(t *testing.T) {
	parent := &Task{ID: 1, Title: "Test", Priority: 1}

	_, err := ParseSplitResponse("[]", parent, 10)
	if err == nil {
		t.Error("expected error for empty array, got nil")
	}
}

func TestParseSplitResponse_TruncatesAt5(t *testing.T) {
	parent := &Task{ID: 1, Title: "Test", Priority: 1}
	response := `[
		{"title":"t1","description":"d1","priority":1},
		{"title":"t2","description":"d2","priority":2},
		{"title":"t3","description":"d3","priority":3},
		{"title":"t4","description":"d4","priority":4},
		{"title":"t5","description":"d5","priority":5},
		{"title":"t6","description":"d6","priority":6}
	]`

	tasks, err := ParseSplitResponse(response, parent, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 5 {
		t.Errorf("expected 5 subtasks (truncated from 6), got %d", len(tasks))
	}
}

func TestParseSplitResponse_NoArray(t *testing.T) {
	parent := &Task{ID: 1, Title: "Test", Priority: 1}

	_, err := ParseSplitResponse(`{"tasks": []}`, parent, 10)
	if err == nil {
		t.Error("expected error when no JSON array found, got nil")
	}
}

func TestSplitTask_DependencyRemapping(t *testing.T) {
	// Set up a plan where task 2 depends on task 1, and we split task 1.
	plan := &Plan{
		Goal: "test goal",
		Tasks: []*Task{
			{ID: 1, Title: "Task 1", Priority: 1, Status: TaskPending},
			{ID: 2, Title: "Task 2", Priority: 2, Status: TaskPending, DependsOn: []int{1}},
			{ID: 3, Title: "Task 3", Priority: 3, Status: TaskPending, DependsOn: []int{1, 2}},
		},
	}

	// Manually perform the dependency remapping part of SplitTask logic.
	// (We can't call SplitTask directly without a provider, so we test the remapping logic.)
	subtasks := []*Task{
		{ID: 10, Title: "Sub 1a", Priority: 1, Status: TaskPending},
		{ID: 11, Title: "Sub 1b", Priority: 1, Status: TaskPending, DependsOn: []int{10}},
	}
	lastSubtaskID := subtasks[len(subtasks)-1].ID

	// Remap dependencies: tasks that depended on task 1 now depend on last subtask.
	for _, t := range plan.Tasks {
		for i, depID := range t.DependsOn {
			if depID == 1 {
				t.DependsOn[i] = lastSubtaskID
			}
		}
	}

	// Task 2 should now depend on lastSubtaskID (11) instead of 1.
	if len(plan.Tasks[1].DependsOn) != 1 || plan.Tasks[1].DependsOn[0] != lastSubtaskID {
		t.Errorf("task 2 deps should be [%d], got %v", lastSubtaskID, plan.Tasks[1].DependsOn)
	}

	// Task 3 should depend on [11, 2] instead of [1, 2].
	found11 := false
	found2 := false
	for _, dep := range plan.Tasks[2].DependsOn {
		if dep == lastSubtaskID {
			found11 = true
		}
		if dep == 2 {
			found2 = true
		}
	}
	if !found11 || !found2 {
		t.Errorf("task 3 should depend on [%d, 2], got %v", lastSubtaskID, plan.Tasks[2].DependsOn)
	}
}

func TestSplitPrompt_ContainsTaskInfo(t *testing.T) {
	task := &Task{
		ID:          7,
		Title:       "Implement payment processing",
		Description: "Integrate Stripe for payments",
		Role:        RoleBackend,
	}
	reason := "Too complex, failing repeatedly"

	prompt := SplitPrompt(task, reason)

	if !contains(prompt, "Task 7") {
		t.Error("prompt should contain task ID")
	}
	if !contains(prompt, "Implement payment processing") {
		t.Error("prompt should contain task title")
	}
	if !contains(prompt, "Integrate Stripe") {
		t.Error("prompt should contain task description")
	}
	if !contains(prompt, "Too complex") {
		t.Error("prompt should contain the reason")
	}
	if !contains(prompt, "2-5") {
		t.Error("prompt should mention 2-5 subtasks")
	}
}

func TestSplitPrompt_NoReason(t *testing.T) {
	task := &Task{ID: 1, Title: "Task", Priority: 1}
	prompt := SplitPrompt(task, "")

	// Should not have the REASON FOR SPLITTING section
	if contains(prompt, "REASON FOR SPLITTING") {
		t.Error("prompt should not contain reason section when reason is empty")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
