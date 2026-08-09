package decompose

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// scriptedProvider returns one canned output (or error) per Complete call, in
// order, and records the prompts it received.
type scriptedProvider struct {
	outputs []string
	errs    []error
	calls   int
	prompts []string
}

func (s *scriptedProvider) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	i := s.calls
	s.calls++
	s.prompts = append(s.prompts, prompt)
	if i >= len(s.outputs) {
		return nil, fmt.Errorf("scriptedProvider: unexpected call %d", i)
	}
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	return &provider.Result{Output: s.outputs[i]}, nil
}

func (s *scriptedProvider) Name() string         { return "scripted" }
func (s *scriptedProvider) DefaultModel() string { return "scripted-model" }

func subtaskJSON(n int) string {
	items := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		items = append(items, fmt.Sprintf(
			`{"title":"Sub-task %d","description":"Do part %d","priority":%d,"role":"backend","estimated_minutes":15}`, i, i, i))
	}
	return "[" + strings.Join(items, ",") + "]"
}

func testPlan() (*pm.Plan, *pm.Task) {
	parent := &pm.Task{
		ID: 2, Title: "Build the auth system",
		Description: "Full login/signup with sessions", Priority: 1,
		Status: pm.TaskPending, Tags: []string{"auth"}, Assignee: "alice",
	}
	plan := &pm.Plan{
		Goal: "Ship the product",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Set up repo", Status: pm.TaskDone, Priority: 1},
			parent,
			{ID: 5, Title: "Write docs", Status: pm.TaskPending, Priority: 3},
		},
	}
	return plan, parent
}

// ---- ParseSubTasks / extraction robustness ----

func TestParseSubTasks_CleanArray(t *testing.T) {
	parent := &pm.Task{ID: 9, Title: "P", Priority: 2, Tags: []string{"x"}, Assignee: "bob"}
	tasks, err := ParseSubTasks(subtaskJSON(3), parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 3 {
		t.Fatalf("want 3 sub-tasks, got %d", len(tasks))
	}
	if tasks[0].Title != "Sub-task 1" || tasks[2].Title != "Sub-task 3" {
		t.Errorf("titles wrong: %q, %q", tasks[0].Title, tasks[2].Title)
	}
	if len(tasks[0].DependsOn) != 1 || tasks[0].DependsOn[0] != 9 {
		t.Errorf("first sub-task must depend on parent, got %v", tasks[0].DependsOn)
	}
	for i, st := range tasks {
		if st.Priority != parent.Priority {
			t.Errorf("sub-task %d: priority = %d, want parent priority %d", i, st.Priority, parent.Priority)
		}
		if st.Assignee != "bob" || len(st.Tags) != 1 || st.Tags[0] != "x" {
			t.Errorf("sub-task %d: inheritance broken: assignee=%q tags=%v", i, st.Assignee, st.Tags)
		}
		if st.Status != pm.TaskPending {
			t.Errorf("sub-task %d: status = %q, want pending", i, st.Status)
		}
	}
}

func TestParseSubTasks_MarkdownFences(t *testing.T) {
	resp := "```json\n" + subtaskJSON(4) + "\n```"
	tasks, err := ParseSubTasks(resp, &pm.Task{ID: 1, Title: "P"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 4 {
		t.Fatalf("want 4 sub-tasks, got %d", len(tasks))
	}
}

func TestParseSubTasks_PreambleWithBrackets(t *testing.T) {
	// The '[' inside the narration used to corrupt the naive
	// first-'['-to-last-']' extraction and fail the whole parse.
	resp := "Sure! [analysis] I split task [2] as follows:\n\n" + subtaskJSON(3) + "\n\nLet me know."
	tasks, err := ParseSubTasks(resp, &pm.Task{ID: 2, Title: "P"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 3 {
		t.Fatalf("want 3 sub-tasks, got %d", len(tasks))
	}
}

func TestParseSubTasks_EnvelopeObject(t *testing.T) {
	resp := `{"subtasks": ` + subtaskJSON(3) + `}`
	tasks, err := ParseSubTasks(resp, &pm.Task{ID: 2, Title: "P"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 3 {
		t.Fatalf("want 3 sub-tasks, got %d", len(tasks))
	}
}

func TestParseSubTasks_LoneObject(t *testing.T) {
	resp := `{"title":"Only one","description":"d","priority":1}`
	tasks, err := ParseSubTasks(resp, &pm.Task{ID: 2, Title: "P"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 1 || tasks[0].Title != "Only one" {
		t.Fatalf("want single sub-task 'Only one', got %+v", tasks)
	}
}

func TestParseSubTasks_Garbage(t *testing.T) {
	if _, err := ParseSubTasks("I cannot decompose this task.", &pm.Task{ID: 1, Title: "P"}); err == nil {
		t.Fatal("want error for non-JSON response")
	}
}

func TestParseSubTasks_ClampsToSeven(t *testing.T) {
	tasks, err := ParseSubTasks(subtaskJSON(9), &pm.Task{ID: 1, Title: "P"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 7 {
		t.Fatalf("want clamp to 7 sub-tasks, got %d", len(tasks))
	}
}

func TestParseSubTasks_SkipsEmptyTitle_ParentDepOnFirstKept(t *testing.T) {
	resp := `[{"title":"  ","description":"blank"},{"title":"Real work","description":"d"},{"title":"More work","description":"d"}]`
	tasks, err := ParseSubTasks(resp, &pm.Task{ID: 7, Title: "P"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("want 2 sub-tasks after skipping blank title, got %d", len(tasks))
	}
	// The parent dependency must land on the first KEPT sub-task, not on
	// whatever happened to be at raw index 0.
	if len(tasks[0].DependsOn) != 1 || tasks[0].DependsOn[0] != 7 {
		t.Errorf("first kept sub-task must depend on parent, got %v", tasks[0].DependsOn)
	}
}

// ---- Decompose ----

func TestDecompose_SingleCallNoDedup(t *testing.T) {
	plan, parent := testPlan()
	prov := &scriptedProvider{outputs: []string{subtaskJSON(4)}}

	res, err := Decompose(context.Background(), prov, provider.Options{}, plan, parent.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.SubTasks) != 4 {
		t.Fatalf("want 4 sub-tasks, got %d", len(res.SubTasks))
	}
	// Regression: a second provider round-trip used to run semantic dedup of
	// the sub-tasks against the plan INCLUDING the parent. Because sub-tasks
	// by construction cover the parent's work, the dedup classified them all
	// as duplicates and returned zero or one sub-task.
	if prov.calls != 1 {
		t.Fatalf("want exactly 1 provider call (no dedup round-trip), got %d", prov.calls)
	}
	if res.Parent != parent {
		t.Error("result parent mismatch")
	}
}

func TestDecompose_RetriesOnSingleSubtask(t *testing.T) {
	plan, parent := testPlan()
	prov := &scriptedProvider{outputs: []string{subtaskJSON(1), subtaskJSON(4)}}

	res, err := Decompose(context.Background(), prov, provider.Options{}, plan, parent.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 2 {
		t.Fatalf("want retry (2 calls), got %d", prov.calls)
	}
	if !strings.Contains(prov.prompts[1], "MUST respond with ONLY a JSON array") {
		t.Error("retry prompt should carry the firmer instruction")
	}
	if len(res.SubTasks) != 4 {
		t.Fatalf("want the 4 retry sub-tasks, got %d", len(res.SubTasks))
	}
}

func TestDecompose_RetriesOnUnparseable(t *testing.T) {
	plan, parent := testPlan()
	prov := &scriptedProvider{outputs: []string{"Sorry, I can't help with that.", subtaskJSON(3)}}

	res, err := Decompose(context.Background(), prov, provider.Options{}, plan, parent.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 2 || len(res.SubTasks) != 3 {
		t.Fatalf("want 2 calls and 3 sub-tasks, got %d calls, %d sub-tasks", prov.calls, len(res.SubTasks))
	}
}

func TestDecompose_KeepsSingleWhenRetryNoBetter(t *testing.T) {
	plan, parent := testPlan()
	prov := &scriptedProvider{outputs: []string{subtaskJSON(1), subtaskJSON(1)}}

	res, err := Decompose(context.Background(), prov, provider.Options{}, plan, parent.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prov.calls != 2 || len(res.SubTasks) != 1 {
		t.Fatalf("want 2 calls and the single sub-task kept, got %d calls, %d sub-tasks", prov.calls, len(res.SubTasks))
	}
}

func TestDecompose_ErrorWhenBothAttemptsUnparseable(t *testing.T) {
	plan, parent := testPlan()
	prov := &scriptedProvider{outputs: []string{"nope", "still nope"}}

	_, err := Decompose(context.Background(), prov, provider.Options{}, plan, parent.ID)
	if err == nil {
		t.Fatal("want error when both attempts are unparseable")
	}
	if prov.calls != 2 {
		t.Fatalf("want 2 calls, got %d", prov.calls)
	}
}

func TestDecompose_ProviderErrorNoRetry(t *testing.T) {
	plan, parent := testPlan()
	provErr := errors.New("connection refused")
	prov := &scriptedProvider{outputs: []string{""}, errs: []error{provErr}}

	_, err := Decompose(context.Background(), prov, provider.Options{}, plan, parent.ID)
	if err == nil || !errors.Is(err, provErr) {
		t.Fatalf("want wrapped provider error, got %v", err)
	}
	if prov.calls != 1 {
		t.Fatalf("transport errors must not be retried here (providers retry internally), got %d calls", prov.calls)
	}
}

func TestDecompose_TaskNotFound(t *testing.T) {
	plan, _ := testPlan()
	prov := &scriptedProvider{}
	if _, err := Decompose(context.Background(), prov, provider.Options{}, plan, 999); err == nil {
		t.Fatal("want error for unknown task id")
	}
	if prov.calls != 0 {
		t.Fatalf("no provider call expected, got %d", prov.calls)
	}
}

// ---- InjectSubTasks ----

func TestInjectSubTasks_WiringAndParentSkip(t *testing.T) {
	plan, parent := testPlan()
	subs, err := ParseSubTasks(subtaskJSON(3), parent)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	added := InjectSubTasks(plan, &DecomposeResult{Parent: parent, SubTasks: subs})
	if len(added) != 3 {
		t.Fatalf("want 3 injected, got %d", len(added))
	}
	// Highest pre-existing ID is 5 → sub-tasks get 6, 7, 8.
	for i, want := range []int{6, 7, 8} {
		if added[i].ID != want {
			t.Errorf("sub-task %d: ID = %d, want %d", i, added[i].ID, want)
		}
	}
	if added[0].DependsOn[0] != parent.ID {
		t.Errorf("first sub-task depends on %v, want parent %d", added[0].DependsOn, parent.ID)
	}
	if added[1].DependsOn[0] != 6 || added[2].DependsOn[0] != 7 {
		t.Errorf("sequential wiring broken: %v, %v", added[1].DependsOn, added[2].DependsOn)
	}
	if parent.Status != pm.TaskSkipped {
		t.Errorf("parent status = %q, want skipped", parent.Status)
	}
	if len(parent.Annotations) == 0 {
		t.Error("parent should carry the 'Decomposed into sub-tasks' annotation")
	}
	// Sub-tasks are inserted directly after the parent (plan position 1).
	if len(plan.Tasks) != 6 {
		t.Fatalf("plan should have 6 tasks, got %d", len(plan.Tasks))
	}
	if plan.Tasks[2].ID != 6 || plan.Tasks[3].ID != 7 || plan.Tasks[4].ID != 8 || plan.Tasks[5].ID != 5 {
		ids := make([]int, len(plan.Tasks))
		for i, tk := range plan.Tasks {
			ids[i] = tk.ID
		}
		t.Errorf("insertion order wrong: %v", ids)
	}
}
