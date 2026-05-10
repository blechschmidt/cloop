package ui

import (
	"encoding/json"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// makeState builds a ProjectState fixture with the given tasks and goal.
// Steps are intentionally nil since they are never part of the diff.
func makeState(goal string, tasks ...*pm.Task) *state.ProjectState {
	return &state.ProjectState{
		Goal:   goal,
		Status: "running",
		Plan: &pm.Plan{
			Goal:    goal,
			Tasks:   tasks,
			Version: 1,
		},
	}
}

// TestComputeStateDiff_NilPrevYieldsFullState verifies the first-broadcast
// path: with no previous snapshot every task lands in tasks_added and every
// persisted top-level field lands in state_changed.
func TestComputeStateDiff_NilPrevYieldsFullState(t *testing.T) {
	curr := makeState("build a thing",
		&pm.Task{ID: 1, Title: "first", Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "second", Status: pm.TaskDone},
	)

	diff := computeStateDiff(nil, curr)

	if !diff.HasChanges {
		t.Fatal("expected HasChanges=true for first broadcast")
	}
	if len(diff.TasksAdded) != 2 {
		t.Fatalf("expected 2 tasks_added, got %d", len(diff.TasksAdded))
	}
	if len(diff.TasksRemoved) != 0 {
		t.Errorf("expected no tasks_removed, got %v", diff.TasksRemoved)
	}
	if len(diff.TasksChanged) != 0 {
		t.Errorf("expected no tasks_changed, got %v", diff.TasksChanged)
	}
	if diff.StateChanged["goal"] != "build a thing" {
		t.Errorf("expected state_changed.goal, got %v", diff.StateChanged["goal"])
	}
	if diff.StateChanged["status"] != "running" {
		t.Errorf("expected state_changed.status, got %v", diff.StateChanged["status"])
	}
}

// TestComputeStateDiff_NoChanges verifies that identical states produce an
// empty diff with HasChanges=false — callers skip the broadcast entirely.
func TestComputeStateDiff_NoChanges(t *testing.T) {
	prev := makeState("g", &pm.Task{ID: 1, Title: "t", Status: pm.TaskPending})
	curr := makeState("g", &pm.Task{ID: 1, Title: "t", Status: pm.TaskPending})

	diff := computeStateDiff(prev, curr)
	if diff.HasChanges {
		t.Fatalf("expected no changes, got %+v", diff)
	}
}

// TestComputeStateDiff_TaskAdded verifies a new task ID appears in tasks_added.
func TestComputeStateDiff_TaskAdded(t *testing.T) {
	prev := makeState("g", &pm.Task{ID: 1, Title: "t1", Status: pm.TaskPending})
	curr := makeState("g",
		&pm.Task{ID: 1, Title: "t1", Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "t2", Status: pm.TaskPending},
	)

	diff := computeStateDiff(prev, curr)
	if !diff.HasChanges {
		t.Fatal("expected HasChanges=true")
	}
	if len(diff.TasksAdded) != 1 || diff.TasksAdded[0].ID != 2 {
		t.Errorf("expected tasks_added=[2], got %+v", diff.TasksAdded)
	}
	if len(diff.TasksRemoved) != 0 || len(diff.TasksChanged) != 0 {
		t.Errorf("expected no removals or changes, got %+v", diff)
	}
}

// TestComputeStateDiff_TaskRemoved verifies a missing task ID lands in
// tasks_removed.
func TestComputeStateDiff_TaskRemoved(t *testing.T) {
	prev := makeState("g",
		&pm.Task{ID: 1, Title: "t1", Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "t2", Status: pm.TaskPending},
	)
	curr := makeState("g", &pm.Task{ID: 1, Title: "t1", Status: pm.TaskPending})

	diff := computeStateDiff(prev, curr)
	if !diff.HasChanges {
		t.Fatal("expected HasChanges=true")
	}
	if len(diff.TasksRemoved) != 1 || diff.TasksRemoved[0] != 2 {
		t.Errorf("expected tasks_removed=[2], got %+v", diff.TasksRemoved)
	}
}

// TestComputeStateDiff_TaskFieldChange verifies only changed fields appear
// in a tasks_changed entry — unchanged fields are not duplicated to the wire.
func TestComputeStateDiff_TaskFieldChange(t *testing.T) {
	prev := makeState("g",
		&pm.Task{ID: 1, Title: "t1", Status: pm.TaskPending, Priority: 1},
	)
	curr := makeState("g",
		&pm.Task{ID: 1, Title: "t1", Status: pm.TaskDone, Priority: 1},
	)

	diff := computeStateDiff(prev, curr)
	if !diff.HasChanges {
		t.Fatal("expected HasChanges=true")
	}
	if len(diff.TasksChanged) != 1 {
		t.Fatalf("expected 1 task_changed, got %d", len(diff.TasksChanged))
	}
	change := diff.TasksChanged[0]
	if change.ID != 1 {
		t.Errorf("expected id=1, got %d", change.ID)
	}
	if change.Fields["status"] != "done" {
		t.Errorf("expected status=done, got %v", change.Fields["status"])
	}
	// title and priority did NOT change — they must not appear in the diff.
	if _, present := change.Fields["title"]; present {
		t.Errorf("expected title to be absent from diff (unchanged), got %v", change.Fields["title"])
	}
	if _, present := change.Fields["priority"]; present {
		t.Errorf("expected priority to be absent from diff (unchanged), got %v", change.Fields["priority"])
	}
}

// TestComputeStateDiff_TopLevelOnlyChange verifies state_changed captures
// scalar updates without inventing task entries.
func TestComputeStateDiff_TopLevelOnlyChange(t *testing.T) {
	prev := makeState("old goal", &pm.Task{ID: 1, Title: "t", Status: pm.TaskPending})
	curr := makeState("new goal", &pm.Task{ID: 1, Title: "t", Status: pm.TaskPending})

	diff := computeStateDiff(prev, curr)
	if !diff.HasChanges {
		t.Fatal("expected HasChanges=true")
	}
	if len(diff.TasksAdded) != 0 || len(diff.TasksRemoved) != 0 || len(diff.TasksChanged) != 0 {
		t.Errorf("expected only top-level change, got %+v", diff)
	}
	if diff.StateChanged["goal"] != "new goal" {
		t.Errorf("expected state_changed.goal=new goal, got %v", diff.StateChanged["goal"])
	}
	// Plan goal is part of plan; verify it's reflected too.
	planChange, ok := diff.StateChanged["plan"].(map[string]any)
	if !ok {
		t.Fatalf("expected plan field in state_changed, got %v", diff.StateChanged["plan"])
	}
	if planChange["goal"] != "new goal" {
		t.Errorf("expected plan.goal=new goal, got %v", planChange["goal"])
	}
}

// TestComputeStateDiff_MarshalJSON_FlattensTaskChange verifies the wire
// format: a taskChange marshals as {"id":N, "field":...} — flat, not nested.
func TestComputeStateDiff_MarshalJSON_FlattensTaskChange(t *testing.T) {
	c := taskChange{
		ID:     7,
		Fields: map[string]any{"status": "done", "title": "hello"},
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["id"].(float64) != 7 {
		t.Errorf("expected id=7, got %v", parsed["id"])
	}
	if parsed["status"] != "done" {
		t.Errorf("expected status=done, got %v", parsed["status"])
	}
	if parsed["title"] != "hello" {
		t.Errorf("expected title=hello, got %v", parsed["title"])
	}
}

// TestComputeStateDiff_ClearedFieldEmitsNull verifies the omitempty path:
// a field that becomes its zero value (and was tagged omitempty so it drops
// from the marshalled JSON) is reported as null so the client can clear it
// instead of silently keeping the stale value.
func TestComputeStateDiff_ClearedFieldEmitsNull(t *testing.T) {
	prev := makeState("g",
		&pm.Task{ID: 1, Title: "t", Status: pm.TaskPending, Assignee: "alice"},
	)
	curr := makeState("g",
		&pm.Task{ID: 1, Title: "t", Status: pm.TaskPending, Assignee: ""}, // omitempty drops it
	)

	diff := computeStateDiff(prev, curr)
	if !diff.HasChanges {
		t.Fatal("expected HasChanges=true (assignee cleared)")
	}
	if len(diff.TasksChanged) != 1 {
		t.Fatalf("expected 1 task_changed, got %d", len(diff.TasksChanged))
	}
	v, present := diff.TasksChanged[0].Fields["assignee"]
	if !present {
		t.Fatal("expected assignee to be present (as null) in the diff")
	}
	if v != nil {
		t.Errorf("expected assignee=nil (cleared), got %v", v)
	}
}

// TestStateCache_SwapReturnsPrev verifies cache.swap stores the new state
// and returns the prior one. Subsequent mutations on the inserted argument
// must not affect the cached snapshot.
func TestStateCache_SwapReturnsPrev(t *testing.T) {
	c := newStateCache()

	s1 := makeState("g1", &pm.Task{ID: 1, Title: "first", Status: pm.TaskPending})
	prev := c.swap("/proj", s1)
	if prev != nil {
		t.Errorf("expected nil prev on first swap, got %+v", prev)
	}

	// Mutate s1 *after* swap — the cache must be unaffected.
	s1.Plan.Tasks[0].Title = "MUTATED"

	s2 := makeState("g1", &pm.Task{ID: 1, Title: "first", Status: pm.TaskDone})
	cached := c.swap("/proj", s2)
	if cached == nil {
		t.Fatal("expected non-nil prev on second swap")
	}
	if cached.Plan.Tasks[0].Title != "first" {
		t.Errorf("cache was mutated by external write: title=%q, want first", cached.Plan.Tasks[0].Title)
	}
	if cached.Plan.Tasks[0].Status != pm.TaskPending {
		t.Errorf("expected pending in cached prev, got %v", cached.Plan.Tasks[0].Status)
	}
}

// TestStateCache_Drop verifies dropping a workDir entry forgets it so the
// next swap returns nil prev.
func TestStateCache_Drop(t *testing.T) {
	c := newStateCache()
	c.swap("/proj", makeState("g"))
	c.drop("/proj")
	if prev := c.swap("/proj", makeState("g")); prev != nil {
		t.Errorf("expected nil prev after drop, got %+v", prev)
	}
}

// TestBroadcastStateDiff_FirstCallProducesFullStateEvent verifies the
// end-to-end broadcast path: on first call (cache empty), every task lands
// in tasks_added on the wire as a state_diff event.
func TestBroadcastStateDiff_FirstCallProducesFullStateEvent(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     "test",
	}
	srv.hubMu.Lock()
	srv.hubClients[dir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()

	ps := makeState("goal",
		&pm.Task{ID: 1, Title: "alpha", Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "beta", Status: pm.TaskDone},
	)
	srv.broadcastStateDiff(dir, ps)

	select {
	case msg := <-hc.ch:
		if msg.Type != "state_diff" {
			t.Fatalf("expected state_diff envelope, got %q", msg.Type)
		}
		var diff struct {
			TasksAdded []*pm.Task `json:"tasks_added"`
		}
		if err := json.Unmarshal(msg.Data, &diff); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(diff.TasksAdded) != 2 {
			t.Errorf("expected 2 tasks_added on first broadcast, got %d", len(diff.TasksAdded))
		}
	default:
		t.Fatal("expected a state_diff message in the hubClient channel")
	}
}

// TestBroadcastStateDiff_SecondCallProducesIncrementalEvent verifies that
// after the cache is seeded, only the delta is shipped. This is the whole
// point of Task 20132: large projects should produce small diffs.
func TestBroadcastStateDiff_SecondCallProducesIncrementalEvent(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     "test",
	}
	srv.hubMu.Lock()
	srv.hubClients[dir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()

	// Seed the cache with three pending tasks.
	srv.broadcastStateDiff(dir, makeState("g",
		&pm.Task{ID: 1, Title: "a", Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "b", Status: pm.TaskPending},
		&pm.Task{ID: 3, Title: "c", Status: pm.TaskPending},
	))
	<-hc.ch // drain the first (full-state) diff

	// Mutate one task: 1 → done.
	srv.broadcastStateDiff(dir, makeState("g",
		&pm.Task{ID: 1, Title: "a", Status: pm.TaskDone},
		&pm.Task{ID: 2, Title: "b", Status: pm.TaskPending},
		&pm.Task{ID: 3, Title: "c", Status: pm.TaskPending},
	))

	select {
	case msg := <-hc.ch:
		if msg.Type != "state_diff" {
			t.Fatalf("expected state_diff, got %q", msg.Type)
		}
		var diff struct {
			TasksAdded   []*pm.Task        `json:"tasks_added"`
			TasksRemoved []int             `json:"tasks_removed"`
			TasksChanged []json.RawMessage `json:"tasks_changed"`
		}
		if err := json.Unmarshal(msg.Data, &diff); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(diff.TasksAdded) != 0 {
			t.Errorf("expected no tasks_added on incremental, got %d", len(diff.TasksAdded))
		}
		if len(diff.TasksRemoved) != 0 {
			t.Errorf("expected no tasks_removed, got %d", len(diff.TasksRemoved))
		}
		if len(diff.TasksChanged) != 1 {
			t.Fatalf("expected 1 task_changed (the one status flip), got %d", len(diff.TasksChanged))
		}
		// Verify the per-task change is the minimal one: id + status only.
		var change map[string]any
		if err := json.Unmarshal(diff.TasksChanged[0], &change); err != nil {
			t.Fatalf("unmarshal change: %v", err)
		}
		if change["id"].(float64) != 1 {
			t.Errorf("expected change for id=1, got id=%v", change["id"])
		}
		if change["status"] != "done" {
			t.Errorf("expected status=done in change, got %v", change["status"])
		}
		// Unchanged fields must NOT be present — that's the wire-size win.
		if _, present := change["title"]; present {
			t.Errorf("unchanged title should not appear in incremental diff, got %v", change["title"])
		}
	default:
		t.Fatal("expected a state_diff message after incremental broadcast")
	}
}

// TestBroadcastStateDiff_NoChangeSkipsBroadcast verifies that broadcasting
// an identical state does NOT spam the channel with empty diffs.
func TestBroadcastStateDiff_NoChangeSkipsBroadcast(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     "test",
	}
	srv.hubMu.Lock()
	srv.hubClients[dir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()

	ps := makeState("g", &pm.Task{ID: 1, Title: "t", Status: pm.TaskPending})
	srv.broadcastStateDiff(dir, ps)
	<-hc.ch // drain first

	// Identical state — should NOT broadcast anything.
	srv.broadcastStateDiff(dir, makeState("g", &pm.Task{ID: 1, Title: "t", Status: pm.TaskPending}))

	select {
	case msg := <-hc.ch:
		t.Fatalf("expected no broadcast for unchanged state, got %+v", msg)
	default:
	}
}

// TestBroadcastStateDiff_PayloadFractionVsFullState is the real win this
// task is about: a single-field flip on a 200-task project should produce
// a diff under 1% the size of the full marshalled state.
func TestBroadcastStateDiff_PayloadFractionVsFullState(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     "test",
	}
	srv.hubMu.Lock()
	srv.hubClients[dir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()

	tasks := make([]*pm.Task, 0, 200)
	for i := 1; i <= 200; i++ {
		tasks = append(tasks, &pm.Task{
			ID:          i,
			Title:       "task with a moderately long title for realistic sizing",
			Description: "and a description filled with text so the marshalled task is non-trivial in size",
			Status:      pm.TaskPending,
			Priority:    i,
		})
	}
	ps := makeState("a goal for the project", tasks...)

	// First broadcast — full state on the wire.
	srv.broadcastStateDiff(dir, ps)
	fullMsg := <-hc.ch
	fullSize := len(fullMsg.Data)

	// Flip task 100 to done.
	tasks[99].Status = pm.TaskDone
	srv.broadcastStateDiff(dir, makeState("a goal for the project", tasks...))
	diffMsg := <-hc.ch
	diffSize := len(diffMsg.Data)

	// Sanity: full state is large (~tens of KB on 200 realistic tasks).
	if fullSize < 10_000 {
		t.Errorf("test fixture is too small to be meaningful: full=%d bytes", fullSize)
	}
	// Diff should be well under 1% of full state.
	if diffSize*100 > fullSize {
		t.Errorf("incremental diff is too large: diff=%d, full=%d (>1%%)", diffSize, fullSize)
	}
	t.Logf("payload sizes: full=%d bytes, incremental diff=%d bytes (%.2f%%)",
		fullSize, diffSize, 100.0*float64(diffSize)/float64(fullSize))
}
