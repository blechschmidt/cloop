package depseditor

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// helpers

func makeTask(id int, deps ...int) *pm.Task {
	return &pm.Task{ID: id, Title: "Task", DependsOn: deps}
}

func makePlan(tasks ...*pm.Task) *pm.Plan {
	return &pm.Plan{Goal: "test", Tasks: tasks}
}

// ── HasCycle ─────────────────────────────────────────────────────────────────

func TestHasCycle_Empty(t *testing.T) {
	if HasCycle(nil) {
		t.Error("empty task list should not have a cycle")
	}
	if HasCycle([]*pm.Task{}) {
		t.Error("empty task list should not have a cycle")
	}
}

func TestHasCycle_SingleTask_NoDeps(t *testing.T) {
	tasks := []*pm.Task{makeTask(1)}
	if HasCycle(tasks) {
		t.Error("single task with no deps should not have a cycle")
	}
}

func TestHasCycle_LinearChain(t *testing.T) {
	// 1 → 2 → 3 (each task depends on the previous)
	tasks := []*pm.Task{
		makeTask(1),
		makeTask(2, 1),
		makeTask(3, 2),
	}
	if HasCycle(tasks) {
		t.Error("linear chain 1→2→3 should not have a cycle")
	}
}

func TestHasCycle_Diamond(t *testing.T) {
	// 1 → 2, 1 → 3, 2 → 4, 3 → 4 (diamond, no cycle)
	tasks := []*pm.Task{
		makeTask(1),
		makeTask(2, 1),
		makeTask(3, 1),
		makeTask(4, 2, 3),
	}
	if HasCycle(tasks) {
		t.Error("diamond dependency graph should not have a cycle")
	}
}

func TestHasCycle_DirectCycle(t *testing.T) {
	// A depends on B, B depends on A
	tasks := []*pm.Task{
		makeTask(1, 2),
		makeTask(2, 1),
	}
	if !HasCycle(tasks) {
		t.Error("mutual dependency 1↔2 should be detected as a cycle")
	}
}

func TestHasCycle_TransitiveCycle(t *testing.T) {
	// A→B→C→A
	tasks := []*pm.Task{
		makeTask(1, 3), // 1 depends on 3
		makeTask(2, 1), // 2 depends on 1
		makeTask(3, 2), // 3 depends on 2 → cycle: 1→3→2→1
	}
	if !HasCycle(tasks) {
		t.Error("transitive cycle 1→3→2→1 should be detected")
	}
}

func TestHasCycle_SelfLoop(t *testing.T) {
	tasks := []*pm.Task{makeTask(1, 1)} // depends on itself
	if !HasCycle(tasks) {
		t.Error("self-loop should be detected as a cycle")
	}
}

func TestHasCycle_TwoDisjointComponents_OneCycle(t *testing.T) {
	// Component A: 1→2 (clean)
	// Component B: 3→4→3 (cycle)
	tasks := []*pm.Task{
		makeTask(1),
		makeTask(2, 1),
		makeTask(3, 4),
		makeTask(4, 3),
	}
	if !HasCycle(tasks) {
		t.Error("should detect cycle in second component")
	}
}

func TestHasCycle_TwoDisjointComponents_NoCycle(t *testing.T) {
	tasks := []*pm.Task{
		makeTask(1),
		makeTask(2, 1),
		makeTask(3),
		makeTask(4, 3),
	}
	if HasCycle(tasks) {
		t.Error("two clean chains should not be detected as cyclic")
	}
}

// ── WouldCreateCycle ─────────────────────────────────────────────────────────

func TestWouldCreateCycle_SafeAddition(t *testing.T) {
	plan := makePlan(makeTask(1), makeTask(2))
	// Adding dep 1 to task 2 (2 depends on 1) — safe
	if WouldCreateCycle(plan, 2, 1) {
		t.Error("adding dep 1 to task 2 should not create a cycle")
	}
}

func TestWouldCreateCycle_DirectCycle(t *testing.T) {
	// task 2 already depends on task 1; adding dep 2 to task 1 creates a cycle
	plan := makePlan(
		makeTask(1),    // task 1: no deps yet
		makeTask(2, 1), // task 2: depends on 1
	)
	if !WouldCreateCycle(plan, 1, 2) {
		t.Error("adding dep 2 to task 1 should create cycle 1↔2")
	}
}

func TestWouldCreateCycle_TransitiveCycle(t *testing.T) {
	// 3→2→1; adding 1→3 creates 1→3→2→1
	plan := makePlan(
		makeTask(1),
		makeTask(2, 1),
		makeTask(3, 2),
	)
	if !WouldCreateCycle(plan, 1, 3) {
		t.Error("adding dep 3 to task 1 should create transitive cycle")
	}
}

func TestWouldCreateCycle_DoesNotMutate(t *testing.T) {
	original := makeTask(1)
	plan := makePlan(original, makeTask(2))
	WouldCreateCycle(plan, 1, 2)
	if len(original.DependsOn) != 0 {
		t.Error("WouldCreateCycle must not mutate the original task")
	}
}

// ── PlanHasCycle ─────────────────────────────────────────────────────────────

func TestPlanHasCycle_Clean(t *testing.T) {
	plan := makePlan(makeTask(1), makeTask(2, 1), makeTask(3, 2))
	if PlanHasCycle(plan) {
		t.Error("clean plan should not report a cycle")
	}
}

func TestPlanHasCycle_WithCycle(t *testing.T) {
	plan := makePlan(makeTask(1, 2), makeTask(2, 1))
	if !PlanHasCycle(plan) {
		t.Error("plan with cycle should be detected")
	}
}

// ── Model ─────────────────────────────────────────────────────────────────────

func TestNew_UnknownTask(t *testing.T) {
	plan := makePlan(makeTask(1), makeTask(2))
	_, err := New(plan, 99)
	if err == nil {
		t.Error("expected error for unknown task ID")
	}
}

func TestNew_InitialSelection(t *testing.T) {
	plan := makePlan(makeTask(1), makeTask(2, 1), makeTask(3))
	m, err := New(plan, 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.selected[1] {
		t.Error("task 1 should be pre-selected as a dep of task 2")
	}
	if m.selected[3] {
		t.Error("task 3 should not be pre-selected")
	}
}

func TestModel_Result(t *testing.T) {
	plan := makePlan(makeTask(1), makeTask(2), makeTask(3))
	m, _ := New(plan, 3)
	// Manually select task 1
	m.selected[1] = true
	m.selected[2] = false

	result := m.Result()
	if len(result) != 1 || result[0] != 1 {
		t.Errorf("expected [1], got %v", result)
	}
}

func TestModel_CycleDetection(t *testing.T) {
	// task 2 depends on task 1; editing task 1 to add dep on task 2 should detect cycle
	plan := makePlan(makeTask(1), makeTask(2, 1))
	m, _ := New(plan, 1)

	m.selected[2] = true
	cycle := m.computeHasCycle()
	if !cycle {
		t.Error("selecting task 2 as dep of task 1 should detect cycle (1→2→1)")
	}
}

func TestModel_OthersExcludesTarget(t *testing.T) {
	plan := makePlan(makeTask(1), makeTask(2), makeTask(3))
	m, _ := New(plan, 2)
	for _, other := range m.others {
		if other.ID == 2 {
			t.Error("target task should not appear in others list")
		}
	}
}
