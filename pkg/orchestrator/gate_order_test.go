package orchestrator

import (
	"context"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// runnableIDs is what the caller would launch, in the order it would launch it.
func runnableIDs(d GateDecision) []int {
	out := make([]int, len(d.Runnable))
	for i, t := range d.Runnable {
		out[i] = t.ID
	}
	return out
}

func eqInts(a, b []int) bool {
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

// queuePlan is a plan whose slice order is ID order — the shape every plan has
// after a round trip through SQLite, whose loadTasks does ORDER BY id. That is
// exactly the case where an unsorted gate looks correct in a unit test built
// from append order and wrong in production.
func queuePlan() *pm.Plan {
	return &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Priority: 4, Status: pm.TaskPending},
		{ID: 2, Priority: 3, Status: pm.TaskPending},
		{ID: 3, Priority: 2, Status: pm.TaskPending},
		{ID: 4, Priority: 1, Status: pm.TaskPending},
	}}
}

// The regression this test exists for: the parallel path took every eligible
// task in plan order and the caller truncated that list to the worker-pool
// size. Reordering the queue in the dashboard rewrote the priorities the
// scheduler reads, and a capped parallel run still dispatched tasks 1 and 2 —
// the lowest IDs — because nothing between the two ever compared priority.
func TestGateTasks_ParallelOrdersTheBatchSoTheCapTakesTheQueueHead(t *testing.T) {
	t.Parallel()

	d := GateTasks(context.Background(), queuePlan(), GateConfig{Parallel: true})

	got := runnableIDs(d)
	want := []int{4, 3, 2, 1}
	if !eqInts(got, want) {
		t.Fatalf("parallel batch = %v, want %v — Runnable is documented as being "+
			"in launch order and the caller caps it without sorting, so any other "+
			"order dispatches the wrong tasks whenever max-parallel < ready", got, want)
	}

	// Spell out the consequence the operator actually sees: with two workers,
	// the two tasks that start are the two at the top of their list.
	const maxParallel = 2
	started := got[:maxParallel]
	if !eqInts(started, []int{4, 3}) {
		t.Errorf("with max-parallel=2 the run starts %v, want [4 3]", started)
	}
}

func TestGateTasks_SequentialTakesTheQueueHead(t *testing.T) {
	t.Parallel()

	d := GateTasks(context.Background(), queuePlan(), GateConfig{})
	if got := runnableIDs(d); !eqInts(got, []int{4}) {
		t.Errorf("sequential selection = %v, want [4]", got)
	}
}

// Pinning is a scheduling decision, not a decoration: `cloop task pin` puts a
// task at the top of the list, and both paths have to agree that the top of the
// list is what runs next.
func TestGateTasks_PinnedLeadsBothPaths(t *testing.T) {
	t.Parallel()

	plan := func() *pm.Plan {
		return &pm.Plan{Tasks: []*pm.Task{
			{ID: 1, Priority: 1, Status: pm.TaskPending},
			{ID: 2, Priority: 9, Status: pm.TaskPending, Pinned: true},
			{ID: 3, Priority: 2, Status: pm.TaskPending},
		}}
	}

	seq := GateTasks(context.Background(), plan(), GateConfig{})
	if got := runnableIDs(seq); !eqInts(got, []int{2}) {
		t.Errorf("sequential picked %v, want the pinned task [2]", got)
	}

	par := GateTasks(context.Background(), plan(), GateConfig{Parallel: true})
	if got := runnableIDs(par); !eqInts(got, []int{2, 1, 3}) {
		t.Errorf("parallel batch = %v, want [2 1 3] — pinned first, then priority", got)
	}
}

// The two paths must never disagree about which task is next. They are
// separately reachable (a run flips between them when max-parallel changes
// mid-flight) and they used to compare priority with independent code.
func TestGateTasks_BothPathsAgreeOnTheNextTask(t *testing.T) {
	t.Parallel()

	plans := []*pm.Plan{
		queuePlan(),
		{Tasks: []*pm.Task{
			{ID: 5, Priority: 2, Status: pm.TaskPending},
			{ID: 6, Priority: 2, Status: pm.TaskPending},
			{ID: 7, Priority: 2, Status: pm.TaskPending, Pinned: true},
		}},
		{Tasks: []*pm.Task{
			{ID: 8, Priority: 0, Status: pm.TaskPending},
			{ID: 9, Priority: 0, Status: pm.TaskPending},
		}},
	}

	for _, p := range plans {
		seq := GateTasks(context.Background(), p, GateConfig{})
		par := GateTasks(context.Background(), p, GateConfig{Parallel: true})
		if len(seq.Runnable) == 0 || len(par.Runnable) == 0 {
			t.Fatalf("a plan of runnable tasks gated to nothing: seq=%v par=%v",
				runnableIDs(seq), runnableIDs(par))
		}
		if seq.Runnable[0].ID != par.Runnable[0].ID {
			t.Errorf("sequential runs %d next, parallel starts with %d",
				seq.Runnable[0].ID, par.Runnable[0].ID)
		}
		if next := p.NextTask(); next == nil || next.ID != seq.Runnable[0].ID {
			t.Errorf("Plan.NextTask disagrees with the gate: %v vs %d",
				next, seq.Runnable[0].ID)
		}
	}
}

// The whole feature in one assertion: a drag in the dashboard, made while a run
// is already going, changes which task that run picks up next.
//
// Every piece below is separately covered — the handler's rewrite, the merge
// that adopts it, the gate's ordering — but each is covered against its own
// neighbour, and the property the user cares about spans all three. It only
// holds if the handler writes priorities the merge reads and the gate sorts by;
// any one of them speaking a different dialect breaks it silently, which is
// exactly the state this task found the code in.
func TestReorderDuringARunChangesWhatRunsNext(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Init(dir, "ship it", 0)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Plan = &pm.Plan{Goal: "ship it", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
	}}
	if err := s.SaveDirect(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// This is the orchestrator's own copy, the one it schedules from.
	run, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	gate := GateTasks(context.Background(), run.Plan, GateConfig{})
	if len(gate.Runnable) == 0 || gate.Runnable[0].ID != 1 {
		t.Fatalf("the run would start with %v, want task 1", runnableIDs(gate))
	}

	// The operator drags task 3 to the top, in another process, mid-run. The
	// dashboard handler assigns dense priorities in the order it was given.
	ui, err := state.Load(dir)
	if err != nil {
		t.Fatalf("handler load: %v", err)
	}
	for i, id := range []int{3, 1, 2} {
		ui.Plan.TaskByID(id).Priority = i + 1
	}
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("handler save: %v", err)
	}

	// Next iteration of the run loop.
	run.SyncFromDisk()

	gate = GateTasks(context.Background(), run.Plan, GateConfig{})
	if len(gate.Runnable) == 0 || gate.Runnable[0].ID != 3 {
		t.Errorf("after the drag the run picks %v, want task 3 — the queue on "+
			"screen is not the queue being executed", runnableIDs(gate))
	}

	// And in parallel mode, where the batch is capped, the same drag decides
	// which tasks get a worker.
	par := GateTasks(context.Background(), run.Plan, GateConfig{Parallel: true})
	if got := runnableIDs(par); !eqInts(got, []int{3, 1, 2}) {
		t.Errorf("parallel batch = %v, want [3 1 2]", got)
	}
}

// Dependencies still outrank the queue order: a task the user dragged to the
// top cannot run before the task it depends on.
func TestGateTasks_OrderNeverOverridesDependencies(t *testing.T) {
	t.Parallel()

	p := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Priority: 9, Status: pm.TaskPending},
		{ID: 2, Priority: 1, Status: pm.TaskPending, Pinned: true, DependsOn: []int{1}},
	}}

	d := GateTasks(context.Background(), p, GateConfig{Parallel: true})
	if got := runnableIDs(d); !eqInts(got, []int{1}) {
		t.Errorf("batch = %v, want [1] — task 2 leads the queue but depends on 1", got)
	}
}
