package orchestrator

// A parallel run keeps the task columns its binary does not know (Task 20388).
//
// Every outcome a parallel round persists goes through state.Save, which
// merges what other processes wrote and then hands the whole plan to
// statedb.SaveState. That used to empty plan_tasks and insert the plan again,
// so each completion reset every column the running binary did not know — the
// columns a newer hub sharing the database had added. This runs a parallel
// plan against a database that has such a column, with a task added from
// outside while the round is in flight, and checks every value survives.

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// addingProvider completes every task, and on its first call runs add — the
// dashboard adding a task while the round is in flight.
type addingProvider struct {
	once sync.Once
	add  func()
	mu   sync.Mutex
	n    int
}

func (p *addingProvider) Complete(context.Context, string, provider.Options) (*provider.Result, error) {
	p.once.Do(p.add)
	p.mu.Lock()
	p.n++
	p.mu.Unlock()
	return &provider.Result{Output: "done\nTASK_DONE", Provider: "mock"}, nil
}
func (p *addingProvider) Name() string         { return "mock" }
func (p *addingProvider) DefaultModel() string { return "mock-model" }

func TestRunPMParallel_KeepsColumnsTheBinaryDoesNotKnow(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "C", Priority: 3, Status: pm.TaskPending},
		{ID: 4, Title: "D", Priority: 4, Status: pm.TaskPending},
	}}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	dbPath := state.DBPath(dir)
	statedbtest.AddFutureColumn(t, dbPath, "plan_tasks", `'kept by ' || id`)

	prov := &addingProvider{add: func() {
		ui, err := state.Load(dir)
		if err != nil {
			t.Errorf("the dashboard's Load: %v", err)
			return
		}
		ui.Plan.Tasks = append(ui.Plan.Tasks, &pm.Task{ID: 9, Title: "added mid-round", Priority: 9, Status: pm.TaskPending})
		if err := ui.SaveDirect(); err != nil {
			t.Errorf("the dashboard's SaveDirect: %v", err)
			return
		}
		statedbtest.SetFutureValue(t, dbPath, "plan_tasks", `'kept by ' || id`, `id = 9`)
	}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true, MaxParallel: 4}, prov)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	final, err := state.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]string{}
	for _, task := range final.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d (%s) = %s, want done", task.ID, task.Title, task.Status)
		}
		want[strconv.Itoa(task.ID)] = "kept by " + strconv.Itoa(task.ID)
	}
	if len(want) != 5 {
		t.Fatalf("the plan holds %d tasks, want 5 — the task added mid-round was lost", len(want))
	}
	statedbtest.WantFutureValues(t, dbPath, "plan_tasks", "id", "a parallel run", want)
}
