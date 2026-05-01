package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// --- marshalTasksJSON ---

func TestMarshalTasksJSON_SortsByPriority(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Low prio", Priority: 3, Status: pm.TaskPending},
		{ID: 2, Title: "High prio", Priority: 1, Status: pm.TaskDone},
		{ID: 3, Title: "Mid prio", Priority: 2, Status: pm.TaskSkipped},
	}
	got := marshalTasksJSON(tasks)

	// Unmarshal and check order
	var decoded []struct {
		ID       int    `json:"id"`
		Priority int    `json:"priority"`
	}
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v\n%s", err, got)
	}
	if len(decoded) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(decoded))
	}
	if decoded[0].Priority != 1 {
		t.Errorf("expected first task priority=1, got %d", decoded[0].Priority)
	}
	if decoded[1].Priority != 2 {
		t.Errorf("expected second task priority=2, got %d", decoded[1].Priority)
	}
	if decoded[2].Priority != 3 {
		t.Errorf("expected third task priority=3, got %d", decoded[2].Priority)
	}
}

func TestMarshalTasksJSON_ValidJSON(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Setup", Description: "Initialize the project", Priority: 1, Status: pm.TaskPending},
	}
	got := marshalTasksJSON(tasks)

	var decoded []*pm.Task
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("marshalTasksJSON produced invalid JSON: %v\n%s", err, got)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 task, got %d", len(decoded))
	}
	if decoded[0].Title != "Setup" {
		t.Errorf("title mismatch: %q", decoded[0].Title)
	}
	if decoded[0].Description != "Initialize the project" {
		t.Errorf("description mismatch: %q", decoded[0].Description)
	}
}

func TestMarshalTasksJSON_EmptyTasks(t *testing.T) {
	got := marshalTasksJSON([]*pm.Task{})
	// Should be a JSON array (either [] or [\n])
	var decoded []*pm.Task
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("empty tasks produced invalid JSON: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("expected empty array, got %d elements", len(decoded))
	}
}

func TestMarshalTasksJSON_PreservesStatus(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskDone},
		{ID: 2, Title: "B", Priority: 2, Status: pm.TaskFailed},
		{ID: 3, Title: "C", Priority: 3, Status: pm.TaskSkipped},
	}
	got := marshalTasksJSON(tasks)

	if !strings.Contains(got, `"done"`) {
		t.Error("expected 'done' status in JSON")
	}
	if !strings.Contains(got, `"failed"`) {
		t.Error("expected 'failed' status in JSON")
	}
	if !strings.Contains(got, `"skipped"`) {
		t.Error("expected 'skipped' status in JSON")
	}
}

func TestMarshalTasksJSON_StableForEqualPriority(t *testing.T) {
	// Two tasks with same priority — insertion order should be preserved (stable sort).
	tasks := []*pm.Task{
		{ID: 10, Title: "First", Priority: 1, Status: pm.TaskPending},
		{ID: 20, Title: "Second", Priority: 1, Status: pm.TaskPending},
	}
	got := marshalTasksJSON(tasks)

	var decoded []struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded[0].ID != 10 {
		t.Errorf("stable sort violated: expected ID 10 first, got %d", decoded[0].ID)
	}
}

// --- taskMarker ---

func TestTaskMarker_Done(t *testing.T) {
	if got := taskMarker(pm.TaskDone); got != "[x]" {
		t.Errorf("expected [x], got %q", got)
	}
}

func TestTaskMarker_Skipped(t *testing.T) {
	if got := taskMarker(pm.TaskSkipped); got != "[-]" {
		t.Errorf("expected [-], got %q", got)
	}
}

func TestTaskMarker_Failed(t *testing.T) {
	if got := taskMarker(pm.TaskFailed); got != "[!]" {
		t.Errorf("expected [!], got %q", got)
	}
}

func TestTaskMarker_InProgress(t *testing.T) {
	if got := taskMarker(pm.TaskInProgress); got != "[~]" {
		t.Errorf("expected [~], got %q", got)
	}
}

func TestTaskMarker_Pending(t *testing.T) {
	if got := taskMarker(pm.TaskPending); got != "[ ]" {
		t.Errorf("expected [ ], got %q", got)
	}
}

// --- truncateStr ---

func TestTruncateStr_ShortString(t *testing.T) {
	got := truncateStr("hello", 10)
	if got != "hello" {
		t.Errorf("expected %q, got %q", "hello", got)
	}
}

func TestTruncateStr_ExactLength(t *testing.T) {
	got := truncateStr("hello", 5)
	if got != "hello" {
		t.Errorf("expected %q, got %q", "hello", got)
	}
}

func TestTruncateStr_TooLong(t *testing.T) {
	got := truncateStr("hello world", 5)
	if got != "hello..." {
		t.Errorf("expected %q, got %q", "hello...", got)
	}
}

func TestTruncateStr_UnicodeAware(t *testing.T) {
	// Japanese characters are multi-byte — should truncate by rune count
	got := truncateStr("こんにちは世界", 5)
	if got != "こんにちは..." {
		t.Errorf("expected rune-aware truncation, got %q", got)
	}
}
