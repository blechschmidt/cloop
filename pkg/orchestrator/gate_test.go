package orchestrator

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/condition"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// proceedAlways is a condition evaluator that lets everything through. Used
// where a test is about a gate other than the condition gate.
func proceedAlways(_ context.Context, _ *pm.Plan, _ *pm.Task) (condition.Result, error) {
	return condition.Result{Proceed: true, Reason: "test: always proceed"}, nil
}

// shellLikeEvaluator mimics condition.Evaluate for the two shell conditions
// the tests use, without shelling out.
func shellLikeEvaluator(_ context.Context, _ *pm.Plan, t *pm.Task) (condition.Result, error) {
	if strings.TrimSpace(strings.TrimPrefix(t.Condition, "$")) == "true" {
		return condition.Result{Proceed: true, Reason: "shell condition passed: true"}, nil
	}
	return condition.Result{Proceed: false, Reason: "shell condition failed (exit non-zero): false"}, nil
}

func taskIDs(tasks []*pm.Task) []int {
	ids := make([]int, 0, len(tasks))
	for _, t := range tasks {
		ids = append(ids, t.ID)
	}
	return ids
}

// --- GateTasks unit coverage ---

// TestGateTasks_SequentialPicksSameTaskAsNextTask pins the equivalence the
// gate relies on: in sequential mode it must select exactly the task
// Plan.NextTask would have returned, ties included.
func TestGateTasks_SequentialPicksSameTaskAsNextTask(t *testing.T) {
	plans := []*pm.Plan{
		{Tasks: []*pm.Task{
			{ID: 1, Priority: 5, Status: pm.TaskPending},
			{ID: 2, Priority: 1, Status: pm.TaskPending},
			{ID: 3, Priority: 3, Status: pm.TaskPending},
		}},
		// Ties must resolve to the first task in plan order.
		{Tasks: []*pm.Task{
			{ID: 7, Priority: 2, Status: pm.TaskPending},
			{ID: 8, Priority: 2, Status: pm.TaskPending},
		}},
		// Unsatisfied dependencies are invisible to both.
		{Tasks: []*pm.Task{
			{ID: 1, Priority: 9, Status: pm.TaskPending},
			{ID: 2, Priority: 0, Status: pm.TaskPending, DependsOn: []int{1}},
		}},
		// A skipped dependency counts as satisfied.
		{Tasks: []*pm.Task{
			{ID: 1, Priority: 9, Status: pm.TaskSkipped},
			{ID: 2, Priority: 0, Status: pm.TaskPending, DependsOn: []int{1}},
		}},
	}

	for i, plan := range plans {
		want := plan.NextTask()
		got := GateTasks(context.Background(), plan, GateConfig{EvalCondition: proceedAlways})
		switch {
		case want == nil && len(got.Runnable) != 0:
			t.Errorf("plan %d: NextTask returned nil but gate returned %v", i, taskIDs(got.Runnable))
		case want == nil:
			// Both agree there is nothing to run.
		case len(got.Runnable) != 1:
			t.Errorf("plan %d: gate returned %v, want exactly task %d", i, taskIDs(got.Runnable), want.ID)
		case got.Runnable[0] != want:
			t.Errorf("plan %d: gate chose task %d, NextTask chose %d", i, got.Runnable[0].ID, want.ID)
		}
	}
}

// TestGateTasks_ParallelReturnsEveryEligibleTask is the corresponding promise
// for the batch path: the runnable set is exactly Plan.ReadyTasks.
func TestGateTasks_ParallelReturnsEveryEligibleTask(t *testing.T) {
	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Priority: 3, Status: pm.TaskPending},
		{ID: 2, Priority: 1, Status: pm.TaskPending},
		{ID: 3, Priority: 1, Status: pm.TaskDone},
		{ID: 4, Priority: 1, Status: pm.TaskPending, DependsOn: []int{1}},
	}}
	want := taskIDs(plan.ReadyTasks())
	got := taskIDs(GateTasks(context.Background(), plan,
		GateConfig{Parallel: true, EvalCondition: proceedAlways}).Runnable)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("runnable = %v, want ReadyTasks %v", got, want)
	}
}

// TestGateTasks_BlockedSweepDefersUntilNothingIsEligible is the one ordering
// disagreement the two paths genuinely had. The sequential path swept only
// when nothing could run; the parallel path swept on every iteration. The
// sequential semantics are now the shared ones, so a task whose dependency has
// failed is not skipped while other work is still runnable — which leaves the
// auto-heal paths a chance to reset that dependency first.
func TestGateTasks_BlockedSweepDefersUntilNothingIsEligible(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel=%v", parallel), func(t *testing.T) {
			plan := &pm.Plan{Tasks: []*pm.Task{
				{ID: 1, Status: pm.TaskFailed},
				{ID: 2, Status: pm.TaskPending, DependsOn: []int{1}},
				{ID: 3, Status: pm.TaskPending},
			}}
			cfg := GateConfig{Parallel: parallel, EvalCondition: proceedAlways}

			// Task 3 is runnable, so the blocked task 2 is left alone.
			d := GateTasks(context.Background(), plan, cfg)
			if got := taskIDs(d.Runnable); !reflect.DeepEqual(got, []int{3}) {
				t.Fatalf("runnable = %v, want [3]", got)
			}
			if d.Skipped() != 0 {
				t.Fatalf("swept %v while task 3 was still runnable", d.SkippedIDs())
			}
			if plan.Tasks[1].Status != pm.TaskPending {
				t.Fatalf("task 2 status = %q, want still pending", plan.Tasks[1].Status)
			}

			// Once task 3 is done the sweep fires.
			plan.Tasks[2].Status = pm.TaskDone
			d = GateTasks(context.Background(), plan, cfg)
			if got := d.SkippedIDs(); !reflect.DeepEqual(got, []int{2}) {
				t.Fatalf("skipped = %v, want [2]", got)
			}
			if d.Exhausted {
				t.Error("Exhausted set on the pass that skipped a task — the caller would stop early")
			}

			// And the pass after it reports the plan exhausted.
			d = GateTasks(context.Background(), plan, cfg)
			if !d.Exhausted || len(d.Runnable) != 0 || d.Skipped() != 0 {
				t.Errorf("final pass: exhausted=%v runnable=%v skipped=%v, want exhausted with nothing to do",
					d.Exhausted, taskIDs(d.Runnable), d.SkippedIDs())
			}
		})
	}
}

// TestGateTasks_SkipAnnotationsAreModeIndependent is the direct regression
// test for the divergence this refactor removed: the parallel path used to
// append "(parallel mode)" to all three skip annotations, so the same decision
// read differently depending on which loop made it.
func TestGateTasks_SkipAnnotationsAreModeIndependent(t *testing.T) {
	build := func() *pm.Plan {
		return &pm.Plan{Tasks: []*pm.Task{
			{ID: 1, Title: "tagged out", Status: pm.TaskPending, Tags: []string{"docs"}},
			{ID: 2, Title: "condition false", Status: pm.TaskPending, Tags: []string{"build"}, Condition: "$ false"},
		}}
	}
	// Reasons keyed by task ID, collected from both the annotation the gate
	// writes and the console line it emits.
	collect := func(parallel bool) map[int][2]string {
		plan := build()
		cfg := GateConfig{
			TagFilter:     []string{"build"},
			Parallel:      parallel,
			EvalCondition: shellLikeEvaluator,
		}
		out := map[int][2]string{}
		// Sequential considers one task per pass, so drain the plan.
		for pass := 0; pass < 8; pass++ {
			d := GateTasks(context.Background(), plan, cfg)
			for _, e := range d.Events {
				if e.IsSkip() {
					out[e.Task.ID] = [2]string{e.Annotation, e.Line}
				}
			}
			if d.Exhausted {
				break
			}
			// Nothing in this fixture is runnable; if something were, mark it
			// done so the loop makes progress.
			for _, r := range d.Runnable {
				r.Status = pm.TaskDone
			}
		}
		// The annotation the gate wrote onto the task must match the one it
		// reported, or the two could still drift.
		for _, task := range plan.Tasks {
			if got, ok := out[task.ID]; ok {
				if n := len(task.Annotations); n == 0 || task.Annotations[n-1].Text != got[0] {
					t.Errorf("parallel=%v task %d: annotation on task %q != reported %q",
						parallel, task.ID, lastAnnotation(task), got[0])
				}
			}
		}
		return out
	}

	seq, par := collect(false), collect(true)
	if !reflect.DeepEqual(seq, par) {
		t.Errorf("skip wording differs between modes:\n sequential: %v\n parallel:   %v", seq, par)
	}
	for id, got := range seq {
		if strings.Contains(got[0], "parallel mode") || strings.Contains(got[1], "parallel mode") {
			t.Errorf("task %d: skip text still names a mode: %q / %q", id, got[0], got[1])
		}
	}
}

func lastAnnotation(t *pm.Task) string {
	if n := len(t.Annotations); n > 0 {
		return t.Annotations[n-1].Text
	}
	return ""
}

// TestGateTasks_ConditionEvaluatorErrorStillRuns keeps the graceful-degradation
// promise: a transient evaluator failure must not silently skip work.
func TestGateTasks_ConditionEvaluatorErrorStillRuns(t *testing.T) {
	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "gated", Status: pm.TaskPending, Condition: "is the moon full"},
	}}
	d := GateTasks(context.Background(), plan, GateConfig{
		EvalCondition: func(context.Context, *pm.Plan, *pm.Task) (condition.Result, error) {
			// This is what condition.Evaluate returns on a provider error.
			return condition.Result{Proceed: true, Reason: "defaulting to proceed"}, fmt.Errorf("provider down")
		},
	})
	if got := taskIDs(d.Runnable); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("runnable = %v, want [1] — an evaluator outage must not skip the task", got)
	}
	// The evaluator's Result still decides, so the error is reported and the
	// passing verdict is logged after it — exactly what both loops printed
	// before the gate existed.
	if len(d.Events) != 2 ||
		d.Events[0].Kind != GateConditionError ||
		d.Events[1].Kind != GateConditionMet {
		t.Fatalf("events = %+v, want condition_error followed by condition_met", d.Events)
	}
}

// TestGateTasks_MissingConditionEvaluatorIsLoud guards the wiring: a caller
// that forgets an evaluator must not silently stop gating conditions.
func TestGateTasks_MissingConditionEvaluatorIsLoud(t *testing.T) {
	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "gated", Status: pm.TaskPending, Condition: "$ false"},
	}}
	d := GateTasks(context.Background(), plan, GateConfig{})
	if len(d.Runnable) != 1 {
		t.Fatalf("runnable = %v, want the task to proceed rather than be silently skipped", taskIDs(d.Runnable))
	}
	if len(d.Events) != 1 || d.Events[0].Kind != GateConditionError {
		t.Fatalf("events = %+v, want one condition_error naming the missing evaluator", d.Events)
	}
}

// TestGateTasks_NilPlanIsExhausted covers the degenerate input rather than
// letting it panic inside a run loop.
func TestGateTasks_NilPlanIsExhausted(t *testing.T) {
	d := GateTasks(context.Background(), nil, GateConfig{})
	if !d.Exhausted || len(d.Runnable) != 0 || len(d.Events) != 0 {
		t.Errorf("nil plan: %+v, want exhausted with nothing to do", d)
	}
}

// --- Differential test: the two PM paths must agree ---

// gateDiffProvider is the stub both runs share. It records which task it was
// asked to execute by reading the task header out of the prompt, and always
// signals TASK_DONE so the run makes progress.
type gateDiffProvider struct {
	mu       sync.Mutex
	executed []int
}

var gateDiffTaskHeader = regexp.MustCompile(`(?m)^\*\*Task (\d+): `)

func (p *gateDiffProvider) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	if m := gateDiffTaskHeader.FindStringSubmatch(prompt); m != nil {
		id, _ := strconv.Atoi(m[1])
		p.mu.Lock()
		p.executed = append(p.executed, id)
		p.mu.Unlock()
	}
	return &provider.Result{
		Output:   "Made the change and verified it.\nTASK_DONE",
		Provider: "gate-diff-mock",
	}, nil
}

func (p *gateDiffProvider) Name() string         { return "gate-diff-mock" }
func (p *gateDiffProvider) DefaultModel() string { return "mock-model" }

func (p *gateDiffProvider) executedSet() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := append([]int(nil), p.executed...)
	sort.Ints(ids)
	return ids
}

// gateDiffPlan builds the shared fixture. Every gating input the orchestrator
// understands is exercised: tags, shell conditions, dependency chains,
// deadlines, pins, a previously-failed task and the tasks that hang off it,
// plus terminal tasks that must not be touched at all.
//
// Expected outcome under TagFilter=["build"]:
//
//	 1 runs            — highest priority, tagged
//	 2 skipped (tag)   — wrong tag
//	 3 skipped (tag)   — no tags at all
//	 4 stays failed    — previously failed, not retried
//	 5 skipped (block) — depends on the failed task 4
//	 6 runs            — depends on 5, which the sweep turns into "skipped"
//	 7 skipped (cond)  — shell condition exits non-zero
//	 8 runs            — shell condition exits zero
//	 9 runs            — depends on 1
//	10 runs            — pinned and overdue
//	11 runs            — depends on the condition-skipped task 7
//	12 stays done      — already terminal
//	13 stays skipped   — already terminal
func gateDiffPlan() *pm.Plan {
	overdue := time.Now().Add(-48 * time.Hour)
	build := []string{"build"}
	return &pm.Plan{
		Goal: "differential gating fixture",
		Tasks: []*pm.Task{
			{ID: 1, Title: "seed", Description: "d", Priority: 0, Status: pm.TaskPending, Tags: build},
			{ID: 2, Title: "wrong tag", Description: "d", Priority: 1, Status: pm.TaskPending, Tags: []string{"docs"}},
			{ID: 3, Title: "untagged", Description: "d", Priority: 2, Status: pm.TaskPending},
			{ID: 4, Title: "previously failed", Description: "d", Priority: 0, Status: pm.TaskFailed, Tags: build},
			{ID: 5, Title: "depends on failed", Description: "d", Priority: 1, Status: pm.TaskPending, Tags: build, DependsOn: []int{4}},
			{ID: 6, Title: "depends on blocked", Description: "d", Priority: 1, Status: pm.TaskPending, Tags: build, DependsOn: []int{5}},
			{ID: 7, Title: "condition false", Description: "d", Priority: 1, Status: pm.TaskPending, Tags: build, Condition: "$ false"},
			{ID: 8, Title: "condition true", Description: "d", Priority: 1, Status: pm.TaskPending, Tags: build, Condition: "$ true"},
			{ID: 9, Title: "depends on seed", Description: "d", Priority: 3, Status: pm.TaskPending, Tags: build, DependsOn: []int{1}},
			{ID: 10, Title: "pinned and overdue", Description: "d", Priority: 4, Status: pm.TaskPending, Tags: build, Pinned: true, Deadline: &overdue},
			{ID: 11, Title: "depends on condition-skipped", Description: "d", Priority: 2, Status: pm.TaskPending, Tags: build, DependsOn: []int{7}},
			{ID: 12, Title: "already done", Description: "d", Priority: 1, Status: pm.TaskDone},
			{ID: 13, Title: "already skipped", Description: "d", Priority: 1, Status: pm.TaskSkipped},
		},
	}
}

// gateDiffOutcome is everything the two paths must agree on.
type gateDiffOutcome struct {
	Executed []int                 // task IDs the provider was asked to run
	Status   map[int]pm.TaskStatus // final status of every task
	Skips    map[int]string        // gate annotation, per skipped task
}

func (o gateDiffOutcome) skippedIDs() []int {
	ids := make([]int, 0, len(o.Skips))
	for id := range o.Skips {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// runGateDiff drives the fixture through one of the two PM paths and reports
// what ran, what was skipped and why.
func runGateDiff(t *testing.T, parallel bool) gateDiffOutcome {
	t.Helper()

	dir := tempDir(t)
	s := initState(t, dir, "differential gating fixture", 0)
	s.PMMode = true
	s.AutoEvolve = false
	s.Parallel = parallel
	s.Plan = gateDiffPlan()
	if parallel {
		// Wide enough that the worker-pool cap never truncates a batch, so
		// any difference in outcome is a gating difference, not a queueing one.
		s.MaxParallel = 16
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg := Config{
		WorkDir:   dir,
		PMMode:    true,
		TagFilter: []string{"build"},
	}
	if parallel {
		cfg.Parallel = true
		cfg.MaxParallel = 16
	}
	// MaxParallel must stay unset for the sequential run: New promotes
	// state.Parallel whenever the cap exceeds 1, so a cap set "just in case"
	// silently routes both halves of this test through runPMParallel and the
	// comparison becomes a tautology.
	prov := &gateDiffProvider{}
	o := newOrchestrator(t, dir, cfg, prov)
	if got := o.wantParallel(); got != parallel {
		t.Fatalf("dispatcher would take the wrong path: wantParallel() = %v, want %v", got, parallel)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := o.runPM(ctx); err != nil {
		t.Fatalf("runPM(parallel=%v): %v", parallel, err)
	}

	out := gateDiffOutcome{
		Executed: prov.executedSet(),
		Status:   map[int]pm.TaskStatus{},
		Skips:    map[int]string{},
	}
	for _, task := range o.state.Plan.Tasks {
		out.Status[task.ID] = task.Status
		for _, a := range task.Annotations {
			if strings.HasPrefix(a.Text, "Task skipped:") {
				out.Skips[task.ID] = a.Text
			}
		}
	}
	return out
}

// TestPMPaths_AgreeOnWhatRunsAndWhatIsSkipped is the differential test.
//
// The same plan is driven through runPMSequential and runPMParallel with a
// stub provider, and both must produce the same executed and skipped task ID
// sets with the same recorded reasons. Deliberately not compared: the order in
// which tasks run, which is the whole point of the parallel path.
func TestPMPaths_AgreeOnWhatRunsAndWhatIsSkipped(t *testing.T) {
	seq := runGateDiff(t, false)
	par := runGateDiff(t, true)

	if !reflect.DeepEqual(seq.Executed, par.Executed) {
		t.Errorf("executed task sets differ:\n sequential: %v\n parallel:   %v", seq.Executed, par.Executed)
	}
	if !reflect.DeepEqual(seq.Skips, par.Skips) {
		t.Errorf("skip reasons differ:\n sequential: %v\n parallel:   %v", seq.Skips, par.Skips)
	}
	if !reflect.DeepEqual(seq.Status, par.Status) {
		t.Errorf("final task statuses differ:\n sequential: %v\n parallel:   %v", seq.Status, par.Status)
	}

	// Agreeing on the wrong answer would satisfy the comparison above, so pin
	// the expected outcome too. See gateDiffPlan for the reasoning per task.
	wantExecuted := []int{1, 6, 8, 9, 10, 11}
	wantSkips := map[int]string{
		2: "Task skipped: did not match active tag filter [build].",
		3: "Task skipped: did not match active tag filter [build].",
		5: "Task skipped: permanently blocked by failed dependency.",
		7: `Task skipped: condition gate "$ false" not met. Reason: shell condition failed (exit non-zero): false`,
	}
	wantStatus := map[int]pm.TaskStatus{
		1: pm.TaskDone, 2: pm.TaskSkipped, 3: pm.TaskSkipped, 4: pm.TaskFailed,
		5: pm.TaskSkipped, 6: pm.TaskDone, 7: pm.TaskSkipped, 8: pm.TaskDone,
		9: pm.TaskDone, 10: pm.TaskDone, 11: pm.TaskDone, 12: pm.TaskDone,
		13: pm.TaskSkipped,
	}

	for name, got := range map[string]gateDiffOutcome{"sequential": seq, "parallel": par} {
		if !reflect.DeepEqual(got.Executed, wantExecuted) {
			t.Errorf("%s: executed = %v, want %v", name, got.Executed, wantExecuted)
		}
		if !reflect.DeepEqual(got.Skips, wantSkips) {
			t.Errorf("%s: skips = %v, want %v", name, got.Skips, wantSkips)
		}
		if !reflect.DeepEqual(got.Status, wantStatus) {
			t.Errorf("%s: statuses = %v, want %v", name, got.Status, wantStatus)
		}
		if ids := got.skippedIDs(); !reflect.DeepEqual(ids, []int{2, 3, 5, 7}) {
			t.Errorf("%s: skipped IDs = %v, want [2 3 5 7]", name, ids)
		}
	}
}
