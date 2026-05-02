package filewatch

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"**/*.go", "main.go", true},
		{"**/*.go", "pkg/foo/bar.go", true},
		{"**/*.go", "pkg/foo/bar.ts", false},
		{"*.go", "main.go", true},
		{"*.go", "pkg/main.go", true}, // base name match
		{"src/**/*.ts", "src/components/app.ts", true},
		{"src/**/*.ts", "src/app.ts", true},
		{"src/**/*.ts", "lib/app.ts", false},
		{"**/*.go", ".cloop/state.json", false},
	}
	for _, tc := range tests {
		got := matchGlob(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v; want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestMatchesAnyGlob(t *testing.T) {
	globs := []string{"**/*.go", "**/*.ts"}
	if !matchesAnyGlob("pkg/foo.go", globs) {
		t.Error("expected pkg/foo.go to match")
	}
	if !matchesAnyGlob("src/app.ts", globs) {
		t.Error("expected src/app.ts to match")
	}
	if matchesAnyGlob("README.md", globs) {
		t.Error("expected README.md not to match")
	}
}

func TestResetRelevantTasks(t *testing.T) {
	plan := &pm.Plan{
		Goal: "test",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Write tests", Status: pm.TaskDone},
			{ID: 2, Title: "Fix handler", Description: "Fix the auth handler", Status: pm.TaskFailed},
			{ID: 3, Title: "Deploy service", Status: pm.TaskDone},
			{ID: 4, Title: "Update auth middleware", Status: pm.TaskInProgress},
		},
	}

	// Change to auth.go — should reset task 2 (failed), 4 (in_progress), and 1 (title match "tests" vs test)
	resetIDs := resetRelevantTasks(plan, []string{"pkg/auth.go"})

	// Task 2 must be reset (failed).
	// Task 4 must be reset (in_progress).
	assertContains(t, resetIDs, 2, "failed task should always reset")
	assertContains(t, resetIDs, 4, "in_progress task should always reset")

	// Task 2 and 4 status must be pending.
	for _, task := range plan.Tasks {
		if task.ID == 2 || task.ID == 4 {
			if task.Status != pm.TaskPending {
				t.Errorf("task %d: expected pending, got %s", task.ID, task.Status)
			}
		}
	}
}

func TestBuildChangeContext(t *testing.T) {
	plan := &pm.Plan{
		Tasks: []*pm.Task{
			{ID: 1, Title: "Write tests"},
			{ID: 2, Title: "Fix auth"},
		},
	}
	ctx := buildChangeContext([]string{"auth.go", "handler.go"}, []int{1, 2}, plan)
	if ctx == "" {
		t.Error("expected non-empty context string")
	}
	if len(ctx) < 10 {
		t.Errorf("context too short: %q", ctx)
	}
}

func assertContains(t *testing.T, ids []int, id int, msg string) {
	t.Helper()
	for _, v := range ids {
		if v == id {
			return
		}
	}
	t.Errorf("%s: ID %d not found in %v", msg, id, ids)
}
