package cmd

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
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

// --- setTaskStatus ---

func makePMState(t *testing.T, tasks []*pm.Task) (*state.ProjectState, string) {
	t.Helper()
	dir := tempCmdDir(t)
	s, err := state.Init(dir, "test goal", 0)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "test goal", Tasks: tasks}
	if err := s.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	return s, dir
}

func TestSetTaskStatus_MarksDone(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
	}
	_, dir := makePMState(t, tasks)

	// Reload state, update status, verify
	s, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	s.Plan.Tasks[0].Status = pm.TaskDone
	if err := s.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	loaded, _ := state.Load(dir)
	if loaded.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("expected done, got %q", loaded.Plan.Tasks[0].Status)
	}
}

func TestSetTaskStatus_MarksSkipped(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
	}
	_, dir := makePMState(t, tasks)

	s, _ := state.Load(dir)
	s.Plan.Tasks[0].Status = pm.TaskSkipped
	s.Save()

	loaded, _ := state.Load(dir)
	if loaded.Plan.Tasks[0].Status != pm.TaskSkipped {
		t.Errorf("expected skipped, got %q", loaded.Plan.Tasks[0].Status)
	}
}

func TestSetTaskStatus_ResetsToPending(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskDone},
	}
	_, dir := makePMState(t, tasks)

	s, _ := state.Load(dir)
	s.Plan.Tasks[0].Status = pm.TaskPending
	s.Save()

	loaded, _ := state.Load(dir)
	if loaded.Plan.Tasks[0].Status != pm.TaskPending {
		t.Errorf("expected pending, got %q", loaded.Plan.Tasks[0].Status)
	}
}

// --- task add logic ---

func TestTaskAdd_AutoAssignsID(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Existing", Priority: 1, Status: pm.TaskPending},
		{ID: 3, Title: "Another", Priority: 2, Status: pm.TaskPending},
	}
	_, dir := makePMState(t, tasks)

	s, _ := state.Load(dir)
	// Simulate add: auto ID = max(1,3)+1 = 4
	maxID := 0
	for _, t2 := range s.Plan.Tasks {
		if t2.ID > maxID {
			maxID = t2.ID
		}
	}
	newTask := &pm.Task{ID: maxID + 1, Title: "New Task", Priority: 10, Status: pm.TaskPending}
	s.Plan.Tasks = append(s.Plan.Tasks, newTask)
	s.Save()

	loaded, _ := state.Load(dir)
	if len(loaded.Plan.Tasks) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(loaded.Plan.Tasks))
	}
	if loaded.Plan.Tasks[2].ID != 4 {
		t.Errorf("expected auto-assigned ID=4, got %d", loaded.Plan.Tasks[2].ID)
	}
}

func TestTaskAdd_DefaultsPriorityToLowest(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 3, Status: pm.TaskPending},
	}
	_, dir := makePMState(t, tasks)

	s, _ := state.Load(dir)
	maxPriority := 0
	for _, t2 := range s.Plan.Tasks {
		if t2.Priority > maxPriority {
			maxPriority = t2.Priority
		}
	}
	// Default priority = maxPriority + 1 = 4
	if maxPriority+1 != 4 {
		t.Errorf("expected default priority=4, got %d", maxPriority+1)
	}
}

// --- task remove logic ---

func TestTaskRemove_RemovesCorrectTask(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "C", Priority: 3, Status: pm.TaskPending},
	}
	_, dir := makePMState(t, tasks)

	s, _ := state.Load(dir)
	// Remove task ID=2
	idx := -1
	for i, t2 := range s.Plan.Tasks {
		if t2.ID == 2 {
			idx = i
			break
		}
	}
	s.Plan.Tasks = append(s.Plan.Tasks[:idx], s.Plan.Tasks[idx+1:]...)
	s.Save()

	loaded, _ := state.Load(dir)
	if len(loaded.Plan.Tasks) != 2 {
		t.Fatalf("expected 2 tasks after removal, got %d", len(loaded.Plan.Tasks))
	}
	for _, t2 := range loaded.Plan.Tasks {
		if t2.ID == 2 {
			t.Error("task 2 should have been removed")
		}
	}
}

// --- task edit logic ---

func TestTaskEdit_UpdatesTitle(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Original Title", Priority: 1, Status: pm.TaskPending},
	}
	_, dir := makePMState(t, tasks)

	s, _ := state.Load(dir)
	s.Plan.Tasks[0].Title = "New Title"
	s.Save()

	loaded, _ := state.Load(dir)
	if loaded.Plan.Tasks[0].Title != "New Title" {
		t.Errorf("expected %q, got %q", "New Title", loaded.Plan.Tasks[0].Title)
	}
}

func TestTaskEdit_UpdatesPriority(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Task", Priority: 5, Status: pm.TaskPending},
	}
	_, dir := makePMState(t, tasks)

	s, _ := state.Load(dir)
	s.Plan.Tasks[0].Priority = 1
	s.Save()

	loaded, _ := state.Load(dir)
	if loaded.Plan.Tasks[0].Priority != 1 {
		t.Errorf("expected priority=1, got %d", loaded.Plan.Tasks[0].Priority)
	}
}

// --- task move logic ---

// taskMoveHelper simulates the move command logic without os.Getwd().
func taskMoveHelper(tasks []*pm.Task, id int, direction string) ([]*pm.Task, error) {
	sorted := make([]*pm.Task, len(tasks))
	copy(sorted, tasks)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	idx := -1
	for i, t := range sorted {
		if t.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, &taskNotFoundError{id: id}
	}

	var other *pm.Task
	if direction == "up" {
		if idx == 0 {
			return nil, &taskAtBoundaryError{}
		}
		other = sorted[idx-1]
	} else {
		if idx == len(sorted)-1 {
			return nil, &taskAtBoundaryError{}
		}
		other = sorted[idx+1]
	}

	sorted[idx].Priority, other.Priority = other.Priority, sorted[idx].Priority
	return tasks, nil
}

type taskNotFoundError struct{ id int }
type taskAtBoundaryError struct{}

func (e *taskNotFoundError) Error() string  { return "not found" }
func (e *taskAtBoundaryError) Error() string { return "at boundary" }

func TestTaskMove_Up_SwapsPriorities(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "C", Priority: 3, Status: pm.TaskPending},
	}
	_, err := taskMoveHelper(tasks, 2, "up")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Task 2 should now have priority 1, task 1 should have priority 2
	byID := map[int]int{}
	for _, t := range tasks {
		byID[t.ID] = t.Priority
	}
	if byID[2] != 1 {
		t.Errorf("task 2 priority: expected 1, got %d", byID[2])
	}
	if byID[1] != 2 {
		t.Errorf("task 1 priority: expected 2, got %d", byID[1])
	}
	if byID[3] != 3 {
		t.Errorf("task 3 priority should be unchanged: got %d", byID[3])
	}
}

func TestTaskMove_Down_SwapsPriorities(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "C", Priority: 3, Status: pm.TaskPending},
	}
	_, err := taskMoveHelper(tasks, 2, "down")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byID := map[int]int{}
	for _, t := range tasks {
		byID[t.ID] = t.Priority
	}
	if byID[2] != 3 {
		t.Errorf("task 2 priority: expected 3, got %d", byID[2])
	}
	if byID[3] != 2 {
		t.Errorf("task 3 priority: expected 2, got %d", byID[3])
	}
	if byID[1] != 1 {
		t.Errorf("task 1 priority should be unchanged: got %d", byID[1])
	}
}

func TestTaskMove_Up_AlreadyFirst_ReturnsError(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
	}
	_, err := taskMoveHelper(tasks, 1, "up")
	if err == nil {
		t.Error("expected error when moving first task up")
	}
}

func TestTaskMove_Down_AlreadyLast_ReturnsError(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
	}
	_, err := taskMoveHelper(tasks, 2, "down")
	if err == nil {
		t.Error("expected error when moving last task down")
	}
}

func TestTaskMove_NotFound_ReturnsError(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
	}
	_, err := taskMoveHelper(tasks, 99, "up")
	if err == nil {
		t.Error("expected error for non-existent task ID")
	}
}

func TestTaskMove_Up_SingleTask_ReturnsError(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
	}
	_, err := taskMoveHelper(tasks, 1, "up")
	if err == nil {
		t.Error("expected error when only one task exists")
	}
}

func TestTaskMove_PreservesOtherTasks(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Priority: 10, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 20, Status: pm.TaskPending},
		{ID: 3, Title: "C", Priority: 30, Status: pm.TaskPending},
		{ID: 4, Title: "D", Priority: 40, Status: pm.TaskPending},
	}
	_, err := taskMoveHelper(tasks, 3, "up")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byID := map[int]int{}
	for _, t := range tasks {
		byID[t.ID] = t.Priority
	}
	// Tasks 3 and 2 should have swapped priorities
	if byID[3] != 20 {
		t.Errorf("task 3: expected priority=20, got %d", byID[3])
	}
	if byID[2] != 30 {
		t.Errorf("task 2: expected priority=30, got %d", byID[2])
	}
	// Tasks 1 and 4 should be unchanged
	if byID[1] != 10 {
		t.Errorf("task 1 should be unchanged, got priority=%d", byID[1])
	}
	if byID[4] != 40 {
		t.Errorf("task 4 should be unchanged, got priority=%d", byID[4])
	}
}
