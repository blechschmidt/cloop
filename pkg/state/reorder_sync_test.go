package state

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// planIDsByExecutionOrder is what the orchestrator's gate would run next, read
// off whichever copy of the plan is passed in.
func planIDsByExecutionOrder(p *pm.Plan) []int {
	ordered := p.ReadyTasks()
	out := make([]int, len(ordered))
	for i, t := range ordered {
		out[i] = t.ID
	}
	return out
}

func eqIDs(a, b []int) bool {
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

// seedRun creates a project with a three-task queue and returns the state the
// "orchestrator" is holding in memory for the duration of its run.
func seedRun(t *testing.T) (*ProjectState, string) {
	t.Helper()
	dir := tempDir(t)
	s, err := Init(dir, "ship it", 0)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Plan = &pm.Plan{Goal: "ship it", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "three", Priority: 3, Status: pm.TaskPending},
	}}
	if err := s.SaveDirect(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return s, dir
}

// reorderOnDisk is what POST /api/tasks/reorder does: it loads its own copy of
// the project, assigns dense priorities in the requested order and saves. The
// running orchestrator is a different process holding different pointers, which
// is the whole difficulty.
func reorderOnDisk(t *testing.T, dir string, order []int) {
	t.Helper()
	ui, err := Load(dir)
	if err != nil {
		t.Fatalf("handler load: %v", err)
	}
	byID := map[int]*pm.Task{}
	for _, task := range ui.Plan.Tasks {
		byID[task.ID] = task
	}
	for i, id := range order {
		byID[id].Priority = i + 1
	}
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("handler save: %v", err)
	}
}

// The bug this test was written for. SyncFromDisk's merge only ever *appended*
// task IDs it had not seen, so a reorder performed while a run was in flight
// was invisible to the orchestrator — and worse than invisible, because its
// next Save upserts every task in its in-memory plan and wrote the old
// priorities straight back over the new ones. The row moved in the dashboard
// and then snapped back.
func TestSyncFromDisk_PicksUpAReorderMadeDuringARun(t *testing.T) {
	s, dir := seedRun(t)

	if got := planIDsByExecutionOrder(s.Plan); !eqIDs(got, []int{1, 2, 3}) {
		t.Fatalf("queue starts as %v, want [1 2 3]", got)
	}

	// The operator drags task 3 to the top.
	reorderOnDisk(t, dir, []int{3, 1, 2})

	s.SyncFromDisk()

	if got := planIDsByExecutionOrder(s.Plan); !eqIDs(got, []int{3, 1, 2}) {
		t.Errorf("after sync the running plan would execute %v, want [3 1 2] — "+
			"the orchestrator is still scheduling from the pre-drag order", got)
	}
}

// The other half: having adopted the new order, the orchestrator's next save
// must not write the old one back. Save upserts every task it holds, so a sync
// that missed the change turns the handler's write into a round trip that
// reverts itself.
func TestSyncFromDisk_ReorderSurvivesTheOrchestratorsNextSave(t *testing.T) {
	s, dir := seedRun(t)

	reorderOnDisk(t, dir, []int{3, 1, 2})
	s.SyncFromDisk()

	if err := s.SaveDirect(); err != nil {
		t.Fatalf("orchestrator save: %v", err)
	}

	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := planIDsByExecutionOrder(reloaded.Plan); !eqIDs(got, []int{3, 1, 2}) {
		t.Errorf("on disk the queue is %v, want [3 1 2] — the running orchestrator "+
			"clobbered the reorder with its stale copy", got)
	}
}

// Pinning from the CLI is the other way the queue head changes mid-run, and it
// travels the same path.
func TestSyncFromDisk_PicksUpAPinMadeDuringARun(t *testing.T) {
	s, dir := seedRun(t)

	ui, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ui.Plan.TaskByID(3).Pinned = true
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("pin save: %v", err)
	}

	s.SyncFromDisk()

	if got := planIDsByExecutionOrder(s.Plan); !eqIDs(got, []int{3, 1, 2}) {
		t.Errorf("after pinning task 3 the queue is %v, want [3 1 2]", got)
	}
}

// The sync adopts two ordering keys and nothing else. Copying execution state
// from a disk copy would let a stale reader resurrect a task a worker has just
// finished — the merge runs on every loop iteration, against a database other
// processes are also writing.
func TestSyncFromDisk_DoesNotAdoptExecutionStateFromDisk(t *testing.T) {
	s, dir := seedRun(t)

	// The run has finished task 1 and started task 2; neither is persisted yet.
	s.Plan.TaskByID(1).Status = pm.TaskDone
	s.Plan.TaskByID(1).Result = "did the thing"
	s.Plan.TaskByID(2).Status = pm.TaskInProgress

	// Meanwhile the dashboard reorders. Its copy still believes every task is
	// pending, because that is what is on disk.
	reorderOnDisk(t, dir, []int{3, 2, 1})

	s.SyncFromDisk()

	if got := s.Plan.TaskByID(1).Status; got != pm.TaskDone {
		t.Errorf("task 1 status = %q, want done — the sync reverted a finished task", got)
	}
	if got := s.Plan.TaskByID(1).Result; got != "did the thing" {
		t.Errorf("task 1 result = %q, want it preserved", got)
	}
	if got := s.Plan.TaskByID(2).Status; got != pm.TaskInProgress {
		t.Errorf("task 2 status = %q, want in_progress", got)
	}
	// Task 3 is still pending, so its new position is adopted.
	if got := s.Plan.TaskByID(3).Priority; got != 1 {
		t.Errorf("task 3 priority = %d, want 1 — a pending task's new position "+
			"must still be picked up", got)
	}
}

// The read/write split. Save merges from disk before it writes, so if the merge
// took the order from disk unconditionally then every writer that goes through
// Save would discard the edit it was called to persist — `cloop task edit
// --priority`, `task pin`, the CLI's own `task reorder`. Only SyncFromDisk, the
// read side, adopts what is on disk.
func TestSave_KeepsTheCallersOwnOrderingEdit(t *testing.T) {
	_, dir := seedRun(t)

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s.Plan.TaskByID(3).Priority = 0
	s.Plan.TaskByID(3).Pinned = true
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.Plan.TaskByID(3).Priority; got != 0 {
		t.Errorf("priority = %d, want 0 — Save's merge reverted the edit it was "+
			"called to persist", got)
	}
	if !reloaded.Plan.TaskByID(3).Pinned {
		t.Error("pinned = false, want true — Save's merge reverted the pin")
	}
	if got := planIDsByExecutionOrder(reloaded.Plan); !eqIDs(got, []int{3, 1, 2}) {
		t.Errorf("queue = %v, want [3 1 2]", got)
	}
}

// The sync must not lose the behaviour it already had: a task added externally
// while the run is in flight still arrives.
func TestSyncFromDisk_StillAppendsExternallyAddedTasks(t *testing.T) {
	s, dir := seedRun(t)

	ui, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ui.Plan.Tasks = append(ui.Plan.Tasks,
		&pm.Task{ID: 4, Title: "four", Priority: 1, Status: pm.TaskPending})
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("save: %v", err)
	}

	s.SyncFromDisk()

	if s.Plan.TaskByID(4) == nil {
		t.Fatal("task 4 was added externally during the run and never arrived")
	}
	if got := planIDsByExecutionOrder(s.Plan); !eqIDs(got, []int{1, 4, 2, 3}) {
		t.Errorf("queue = %v, want [1 4 2 3] — the new task sorts into the "+
			"queue by its own priority", got)
	}
}
