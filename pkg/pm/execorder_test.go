package pm

import "testing"

// mk builds a pending task with the three keys the execution order reads.
func mk(id, priority int, pinned bool) *Task {
	return &Task{ID: id, Priority: priority, Pinned: pinned, Status: TaskPending}
}

func ids(tasks []*Task) []int {
	out := make([]int, len(tasks))
	for i, t := range tasks {
		out[i] = t.ID
	}
	return out
}

func sameIDs(a, b []int) bool {
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

func TestExecutionOrder_KeyPrecedence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		in    []*Task
		want  []int
		about string
	}{
		{
			name:  "priority beats id",
			in:    []*Task{mk(1, 9, false), mk(2, 1, false), mk(3, 5, false)},
			want:  []int{2, 3, 1},
			about: "lower priority value runs first",
		},
		{
			name:  "id breaks a priority tie",
			in:    []*Task{mk(7, 2, false), mk(3, 2, false), mk(5, 2, false)},
			want:  []int{3, 5, 7},
			about: "equal priorities fall back to creation order",
		},
		{
			name: "pinned beats priority",
			in:   []*Task{mk(1, 1, false), mk(2, 99, true)},
			want: []int{2, 1},
			about: "a pinned task leads the queue even against the most urgent " +
				"priority — otherwise the dashboard's top row is not what runs next",
		},
		{
			name:  "pinned tasks order among themselves",
			in:    []*Task{mk(1, 3, true), mk(2, 1, true), mk(3, 0, false)},
			want:  []int{2, 1, 3},
			about: "the pinned group is itself sorted by priority",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ids(SortByExecutionOrder(tc.in))
			if !sameIDs(got, tc.want) {
				t.Errorf("order = %v, want %v — %s", got, tc.want, tc.about)
			}
		})
	}
}

// SortByExecutionOrder hands back a copy. Callers pass plan.Tasks itself, and
// reordering that slice in place would silently change what every index into
// the plan refers to.
func TestSortByExecutionOrder_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	in := []*Task{mk(1, 9, false), mk(2, 1, false)}
	before := ids(in)
	SortByExecutionOrder(in)
	if !sameIDs(ids(in), before) {
		t.Errorf("input slice was reordered to %v, want it left at %v", ids(in), before)
	}
}

// ReadyTasks is what both orchestrator paths gate on, so it has to hand its
// candidates over already ordered — the parallel path truncates this list to
// the worker-pool size and never sorts it.
func TestReadyTasks_ReturnsExecutionOrder(t *testing.T) {
	t.Parallel()

	p := &Plan{Tasks: []*Task{
		mk(1, 9, false),
		mk(2, 5, false),
		mk(3, 1, false),
		mk(4, 2, true),
	}}
	// Slice order here is ID order, which is what a plan read back from SQLite
	// always looks like (loadTasks does ORDER BY id).
	got := ids(p.ReadyTasks())
	want := []int{4, 3, 2, 1}
	if !sameIDs(got, want) {
		t.Errorf("ReadyTasks = %v, want %v — the parallel path caps this list "+
			"without sorting it, so an unordered return dispatches by ID", got, want)
	}
}

func TestReadyTasks_ExcludesUnreadyAndNonPending(t *testing.T) {
	t.Parallel()

	blocked := mk(3, 1, false)
	blocked.DependsOn = []int{2}
	p := &Plan{Tasks: []*Task{
		{ID: 1, Priority: 1, Status: TaskDone},
		{ID: 2, Priority: 1, Status: TaskInProgress},
		blocked,
		mk(4, 7, false),
	}}
	got := ids(p.ReadyTasks())
	if !sameIDs(got, []int{4}) {
		t.Errorf("ReadyTasks = %v, want [4] — done, running and dependency-blocked "+
			"tasks are not in the queue", got)
	}
}

// NextTask and the gate must name the same task. They are separate code paths
// (the CLI's readouts vs. the orchestrator's scheduler) and used to compare
// priority independently, so pinning made them disagree.
func TestNextTask_IsHeadOfReadyTasks(t *testing.T) {
	t.Parallel()

	p := &Plan{Tasks: []*Task{
		mk(1, 1, false),
		mk(2, 8, true),
		mk(3, 4, false),
	}}
	next := p.NextTask()
	if next == nil {
		t.Fatal("NextTask returned nil with three runnable tasks")
	}
	if head := p.ReadyTasks()[0]; next != head {
		t.Errorf("NextTask = %d but ReadyTasks[0] = %d — the CLI would name a "+
			"different task than the orchestrator runs", next.ID, head.ID)
	}
	if next.ID != 2 {
		t.Errorf("NextTask = %d, want the pinned task 2", next.ID)
	}
}

func TestNextTask_NilWhenNothingIsRunnable(t *testing.T) {
	t.Parallel()

	p := &Plan{Tasks: []*Task{{ID: 1, Status: TaskDone}}}
	if got := p.NextTask(); got != nil {
		t.Errorf("NextTask = %v, want nil", got)
	}
}
