package orchestrator

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// reviewGate builds a closed human review gate at a queue position.
func reviewGate(id, priority int) *pm.Task {
	g := pm.NewHumanGate("Check the parser", "Look at the grammar before the codegen starts.")
	g.ID, g.Priority = id, priority
	return g
}

func TestGateTasks_StopsAtAClosedReviewGate(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		plan := &pm.Plan{Tasks: []*pm.Task{
			{ID: 1, Priority: 1, Status: pm.TaskPending},
			reviewGate(2, 2),
			{ID: 3, Priority: 3, Status: pm.TaskPending},
		}}
		cfg := GateConfig{Parallel: parallel, EvalCondition: proceedAlways}

		d := GateTasks(context.Background(), plan, cfg)
		if got := taskIDs(d.Runnable); len(got) != 1 || got[0] != 1 {
			t.Fatalf("parallel=%v: Runnable = %v, want [1]: task 3 is behind the gate", parallel, got)
		}
		if d.Waiting != nil || d.Exhausted || d.Changed() {
			t.Fatalf("parallel=%v: Waiting=%v Exhausted=%v Changed=%v with work ahead of the gate",
				parallel, d.Waiting, d.Exhausted, d.Changed())
		}

		plan.Tasks[0].Status = pm.TaskDone
		d = GateTasks(context.Background(), plan, cfg)
		if len(d.Runnable) != 0 || d.Exhausted {
			t.Fatalf("parallel=%v: Runnable=%v Exhausted=%v once the gate is reached", parallel, taskIDs(d.Runnable), d.Exhausted)
		}
		if d.Waiting == nil || d.Waiting.ID != 2 {
			t.Fatalf("parallel=%v: Waiting = %v, want the gate", parallel, d.Waiting)
		}
		if plan.Tasks[1].Status != pm.TaskPending {
			t.Fatalf("parallel=%v: the gate became %s without an approval", parallel, plan.Tasks[1].Status)
		}
	}
}

func TestGateTasks_PassesAnApprovedGateInTheSamePass(t *testing.T) {
	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Priority: 1, Status: pm.TaskDone},
		reviewGate(2, 2),
		{ID: 3, Priority: 3, Status: pm.TaskPending, DependsOn: []int{2}},
	}}
	plan.Tasks[1].Approved = true

	d := GateTasks(context.Background(), plan, GateConfig{EvalCondition: proceedAlways})
	if g := plan.Tasks[1]; g.Status != pm.TaskDone || g.CompletedAt == nil {
		t.Fatalf("approved gate = %s (completed %v), want passed", g.Status, g.CompletedAt)
	}
	if got := taskIDs(d.Runnable); len(got) != 1 || got[0] != 3 {
		t.Fatalf("Runnable = %v, want [3], which waited on the gate", got)
	}
	if !d.Changed() || len(d.ChangedIDs()) != 1 || d.ChangedIDs()[0] != 2 {
		t.Fatalf("Changed=%v ChangedIDs=%v: a passed gate must be persisted", d.Changed(), d.ChangedIDs())
	}
}

// A dependency that failed is not a reason to skip a gate (that would open it
// without the person it waits for), nor the tasks it holds: the reviewer may
// reset the failed task.
func TestGateTasks_SweepNeverReachesPastAClosedGate(t *testing.T) {
	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Priority: 1, Status: pm.TaskFailed},
		{ID: 2, Priority: 2, Status: pm.TaskPending, DependsOn: []int{1}}, // ahead: swept
		reviewGate(3, 3),
		{ID: 4, Priority: 4, Status: pm.TaskPending, DependsOn: []int{1}}, // held: kept
	}}
	plan.Tasks[2].DependsOn = []int{1}

	d := GateTasks(context.Background(), plan, GateConfig{EvalCondition: proceedAlways})
	if got := d.SkippedIDs(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("swept %v, want [2]", got)
	}
	if plan.Tasks[2].Status != pm.TaskPending || plan.Tasks[3].Status != pm.TaskPending {
		t.Fatalf("gate %s, held task %s: neither may be swept", plan.Tasks[2].Status, plan.Tasks[3].Status)
	}
	d = GateTasks(context.Background(), plan, GateConfig{EvalCondition: proceedAlways})
	if d.Waiting == nil || d.Waiting.ID != 3 || d.Exhausted {
		t.Fatalf("Waiting=%v Exhausted=%v, want the run stopped at gate 3", d.Waiting, d.Exhausted)
	}
}

// promptRecorder answers every task with TASK_DONE and keeps the prompts.
type promptRecorder struct {
	mu      sync.Mutex
	prompts []string
	onCall  func(n int)
}

func (p *promptRecorder) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	p.prompts = append(p.prompts, prompt)
	n := len(p.prompts)
	hook := p.onCall
	p.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return &provider.Result{Output: "did it\nTASK_DONE", Provider: "mock"}, nil
}
func (p *promptRecorder) Name() string         { return "mock" }
func (p *promptRecorder) DefaultModel() string { return "mock-model" }

func (p *promptRecorder) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.prompts)
}

func gatedPlan() *pm.Plan {
	return &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "Write the parser", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "Test the parser", Priority: 2, Status: pm.TaskPending},
		reviewGate(3, 3),
		{ID: 4, Title: "Generate code", Priority: 4, Status: pm.TaskPending},
	}}
}

// The whole loop, both paths: the run stops at the gate with the work ahead of
// it done and the work behind it untouched, a run started again without an
// approval runs what was put ahead of the gate meanwhile and stops at it again,
// and one started after the approval carries on to the end.
func TestRunStopsAtAReviewGateUntilItIsApproved(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		name := map[bool]string{false: "sequential", true: "parallel"}[parallel]
		t.Run(name, func(t *testing.T) {
			dir := tempDir(t)
			s := initState(t, dir, "goal", 0)
			s.PMMode = true
			s.Plan = gatedPlan()
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
			cfg := Config{WorkDir: dir, PMMode: true, NoHeal: true, Parallel: parallel}

			prov := &promptRecorder{}
			if err := newOrchestrator(t, dir, cfg, prov).Run(context.Background()); err != nil {
				t.Fatalf("Run: %v", err)
			}
			st := loadState(t, dir)
			assertStatuses(t, st, map[int]pm.TaskStatus{1: pm.TaskDone, 2: pm.TaskDone, 3: pm.TaskPending, 4: pm.TaskPending})
			if prov.calls() != 2 {
				t.Fatalf("provider calls = %d, want 2: neither the gate nor the task behind it reaches an agent", prov.calls())
			}
			for _, p := range prov.prompts {
				if strings.Contains(p, "Check the parser") {
					t.Fatalf("an agent's prompt lists the review gate as a task:\n%s", p)
				}
			}
			pr := st.PauseReason
			if st.Status != "paused" || pr == nil || pr.Code != pausereason.CodeApproval || pr.TaskID != 3 {
				t.Fatalf("status %q, reason %+v: want paused for approval at gate 3", st.Status, pr)
			}
			if !strings.Contains(pr.Detail, "gate #3") {
				t.Errorf("pause detail %q does not name the gate", pr.Detail)
			}

			// A fix-up task put ahead of the gate while it waits runs on the
			// next start, and the run stops at the gate again.
			fix := &pm.Task{ID: st.Plan.NextTaskID(), Title: "Fix the parser's error messages", Status: pm.TaskPending}
			if err := st.Plan.InsertInQueue(fix, 0, 3); err != nil {
				t.Fatal(err)
			}
			if err := st.Save(); err != nil {
				t.Fatal(err)
			}
			prov2 := &promptRecorder{}
			if err := newOrchestrator(t, dir, cfg, prov2).Run(context.Background()); err != nil {
				t.Fatalf("second Run: %v", err)
			}
			st = loadState(t, dir)
			assertStatuses(t, st, map[int]pm.TaskStatus{fix.ID: pm.TaskDone, 3: pm.TaskPending, 4: pm.TaskPending})
			if prov2.calls() != 1 || st.PauseReason == nil || st.PauseReason.TaskID != 3 {
				t.Fatalf("second run: %d call(s), reason %+v; want the fix-up only, then the gate again", prov2.calls(), st.PauseReason)
			}

			// Approved: the next run passes the gate and finishes the plan.
			pm.ApproveGate(st.Plan.TaskByID(3), "reviewer@example.com", time.Now())
			st.Plan.TaskByID(3).Status = pm.TaskPending // as if a live run's save had written it back
			if err := st.Save(); err != nil {
				t.Fatal(err)
			}
			prov3 := &promptRecorder{}
			if err := newOrchestrator(t, dir, cfg, prov3).Run(context.Background()); err != nil {
				t.Fatalf("third Run: %v", err)
			}
			st = loadState(t, dir)
			assertStatuses(t, st, map[int]pm.TaskStatus{3: pm.TaskDone, 4: pm.TaskDone})
			if prov3.calls() != 1 || st.Status != "complete" {
				t.Fatalf("third run: %d call(s), status %q; want task 4 alone, then complete", prov3.calls(), st.Status)
			}
		})
	}
}

// An approval made while a run holds the plan is a definition field, so the
// run's next sync adopts it and the run never stops at that gate.
func TestApprovalDuringARunIsAdoptedAndTheRunCarriesOn(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = gatedPlan()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	prov := &promptRecorder{}
	prov.onCall = func(n int) {
		if n != 1 {
			return
		}
		// The dashboard's approval, written while task 1 runs.
		other, err := state.Load(dir)
		if err != nil {
			t.Errorf("load: %v", err)
			return
		}
		other.Plan.TaskByID(3).Approved = true
		if err := other.SaveDirect(); err != nil {
			t.Errorf("save: %v", err)
		}
	}
	if err := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	st := loadState(t, dir)
	assertStatuses(t, st, map[int]pm.TaskStatus{1: pm.TaskDone, 2: pm.TaskDone, 3: pm.TaskDone, 4: pm.TaskDone})
	if st.Status != "complete" || prov.calls() != 3 {
		t.Fatalf("status %q after %d call(s); the approval made mid-run was lost", st.Status, prov.calls())
	}
	if g := st.Plan.TaskByID(3); !g.Approved {
		t.Error("the run's save wrote the gate's approval away")
	}
}

// A gate as the last entry stops the run before it is called complete, so
// auto-evolve does not plan past a review nobody has done.
func TestAReviewGateAtTheEndHoldsCompletion(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "Only task", Priority: 1, Status: pm.TaskPending},
		reviewGate(2, 2),
	}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	prov := &promptRecorder{}
	if err := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	st := loadState(t, dir)
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.TaskID != 2 {
		t.Fatalf("status %q, reason %+v: want paused at gate 2, not complete", st.Status, st.PauseReason)
	}
}

func loadState(t *testing.T, dir string) *state.ProjectState {
	t.Helper()
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	return st
}

func assertStatuses(t *testing.T, st *state.ProjectState, want map[int]pm.TaskStatus) {
	t.Helper()
	for id, w := range want {
		task := st.Plan.TaskByID(id)
		if task == nil {
			t.Fatalf("task %d missing", id)
		}
		if task.Status != w {
			t.Errorf("task %d (%s) = %s, want %s", id, task.Title, task.Status, w)
		}
	}
}
