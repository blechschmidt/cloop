package suggest

import (
	"reflect"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// fourStepPlan is a plan whose shape exercises every rule: 2 and 3 both build
// on 1, and 4 needs both of them.
func fourStepPlan() *Result {
	r := &Result{Request: "add OAuth login", Suggestions: []*Suggestion{
		{ID: 1, Title: "config", Category: CategoryFeature, Effort: EffortL},
		{ID: 2, Title: "callback", Category: CategorySecurity, Effort: EffortXS, DependsOn: []int{1}},
		{ID: 3, Title: "button", Category: CategoryUX, Effort: EffortS, DependsOn: []int{1}},
		{ID: 4, Title: "docs", Category: CategoryDocs, Effort: EffortM, DependsOn: []int{2, 3}},
	}}
	return r
}

// existingPlan is a project that already has work queued, so the plan's tasks
// have something to queue behind.
func existingPlan() *pm.Plan {
	p := pm.NewPlan("goal")
	p.Tasks = []*pm.Task{
		{ID: 1, Title: "old done", Status: pm.TaskDone, Priority: 1},
		{ID: 7, Title: "old pending", Status: pm.TaskPending, Priority: 2},
	}
	return p
}

func pick(r *Result, ids ...int) []*Suggestion {
	var out []*Suggestion
	for _, id := range ids {
		for _, s := range r.Suggestions {
			if s.ID == id {
				out = append(out, s)
			}
		}
	}
	return out
}

func taskByTitle(p *pm.Plan, title string) *pm.Task {
	for _, t := range p.Tasks {
		if t.Title == title {
			return t
		}
	}
	return nil
}

func depsOf(p *pm.Plan, title string) []int {
	t := taskByTitle(p, title)
	if t == nil {
		return nil
	}
	return append([]int(nil), t.DependsOn...)
}

// Accepting the whole plan: new IDs after the highest, the queue's tail in
// plan order, and the plan's dependencies translated to task IDs.
func TestLedger_AcceptingAPlanKeepsItsOrderAndShape(t *testing.T) {
	r := fourStepPlan()
	plan := existingPlan()
	// Sent out of order on purpose: the plan's order decides, not the request's.
	added := NewLedger(r).Apply(plan, pick(r, 4, 2, 3, 1))

	if len(added) != 4 {
		t.Fatalf("added %d tasks, want 4", len(added))
	}
	var gotIDs, gotPri []int
	for _, a := range added {
		gotIDs = append(gotIDs, a.ID)
		gotPri = append(gotPri, a.Priority)
	}
	if !reflect.DeepEqual(gotIDs, []int{8, 9, 10, 11}) {
		t.Errorf("task IDs = %v, want 8..11 (after the highest existing ID, in plan order)", gotIDs)
	}
	if !reflect.DeepEqual(gotPri, []int{3, 4, 5, 6}) {
		t.Errorf("priorities = %v, want 3..6: the queue's tail in plan order, not an effort guess — "+
			"an xs step 2 must not jump the l step 1 it builds on", gotPri)
	}
	for title, want := range map[string][]int{"config": nil, "callback": {8}, "button": {8}, "docs": {9, 10}} {
		if got := depsOf(plan, title); !reflect.DeepEqual(got, want) {
			t.Errorf("%s depends on %v, want %v", title, got, want)
		}
	}
	if role := taskByTitle(plan, "callback").Role; role != pm.RoleSecurity {
		t.Errorf("callback's role = %q, want security (from its category)", role)
	}

	// And the run queue agrees: sequential execution walks the plan in order.
	var order []string
	for _, tk := range pm.SortByExecutionOrder(plan.Tasks) {
		if tk.Status == pm.TaskPending {
			order = append(order, tk.Title)
		}
	}
	if want := []string{"old pending", "config", "callback", "button", "docs"}; !reflect.DeepEqual(order, want) {
		t.Errorf("run order = %v, want %v", order, want)
	}
}

// Skipping a step must not cut the chain: docs needs callback, callback needs
// config, so without callback docs waits for config directly.
func TestLedger_ASkippedStepIsLookedThrough(t *testing.T) {
	r := fourStepPlan()
	plan := existingPlan()
	NewLedger(r).Apply(plan, pick(r, 1, 3, 4)) // not 2

	if got := depsOf(plan, "docs"); !reflect.DeepEqual(got, []int{8, 9}) {
		t.Errorf("docs depends on %v, want [8 9] — config (through the skipped callback) and button", got)
	}
}

// A step added before one of its prerequisites gains the dependency when the
// prerequisite arrives: clicking the cards out of order must not let a later
// step run first.
func TestLedger_AStepAddedEarlyGainsItsPrerequisiteLater(t *testing.T) {
	r := fourStepPlan()
	plan := existingPlan()
	l := NewLedger(r)

	l.Apply(plan, pick(r, 4))
	if got := depsOf(plan, "docs"); len(got) != 0 {
		t.Fatalf("docs depends on %v before anything it needs exists", got)
	}
	l.Apply(plan, pick(r, 2))
	if got := depsOf(plan, "docs"); !reflect.DeepEqual(got, []int{9}) {
		t.Errorf("after callback: docs depends on %v, want [9]", got)
	}
	l.Apply(plan, pick(r, 1))
	if got := depsOf(plan, "callback"); !reflect.DeepEqual(got, []int{10}) {
		t.Errorf("after config: callback depends on %v, want [10]", got)
	}
	// docs also needs button, which is not a task, and button needs config —
	// so docs waits for config directly as well.
	if got := depsOf(plan, "docs"); !reflect.DeepEqual(got, []int{9, 10}) {
		t.Errorf("after config: docs depends on %v, want [9 10]", got)
	}
}

// A task that already started is not rewired under the orchestrator.
func TestLedger_OnlyPendingTasksAreRewired(t *testing.T) {
	r := fourStepPlan()
	plan := existingPlan()
	l := NewLedger(r)
	l.Apply(plan, pick(r, 2))
	taskByTitle(plan, "callback").Status = pm.TaskInProgress
	l.Apply(plan, pick(r, 1))
	if got := depsOf(plan, "callback"); len(got) != 0 {
		t.Errorf("a running task gained dependencies %v", got)
	}
}

// Accepting twice — a double click, two tabs — adds nothing the second time.
func TestLedger_RepeatingAnAcceptIsANoOp(t *testing.T) {
	r := fourStepPlan()
	plan := existingPlan()
	l := NewLedger(r)
	l.Apply(plan, pick(r, 1, 2))
	if again := l.Apply(plan, pick(r, 1, 2)); len(again) != 0 {
		t.Errorf("a repeated accept added %d more tasks", len(again))
	}
	if len(plan.Tasks) != 4 {
		t.Errorf("plan has %d tasks, want 4", len(plan.Tasks))
	}
	if p := l.Pending(r.Suggestions); len(p) != 2 || p[0].ID != 3 || p[1].ID != 4 {
		t.Errorf("pending = %v, want steps 3 and 4", p)
	}
}

// A task the user deleted no longer counts: its step can be added again, and
// until it is, later steps look through it.
func TestLedger_ADeletedTaskCountsAsNeverAdded(t *testing.T) {
	r := fourStepPlan()
	plan := existingPlan()
	l := NewLedger(r)
	l.Apply(plan, pick(r, 1))
	plan.Tasks = plan.Tasks[:2] // config removed again

	// callback now gets config's old ID, 8: the ID alone must not make it
	// look like config.
	l.Apply(plan, pick(r, 2))
	if got := depsOf(plan, "callback"); len(got) != 0 {
		t.Errorf("callback depends on %v, but config is gone", got)
	}
	again := l.Apply(plan, pick(r, 1))
	if len(again) != 1 {
		t.Fatalf("re-adding a deleted step added %d tasks, want 1", len(again))
	}
	if got := depsOf(plan, "callback"); !reflect.DeepEqual(got, []int{again[0].ID}) {
		t.Errorf("callback depends on %v, want the re-added config %d", got, again[0].ID)
	}
}

// A dependency edited by hand can turn the plan's own edge into a cycle. That
// edge is skipped rather than deadlocking both tasks — and a dependency the
// user removed is not put back.
func TestLedger_NeverClosesACycle(t *testing.T) {
	r := fourStepPlan()
	plan := existingPlan()
	l := NewLedger(r)
	l.Apply(plan, pick(r, 1, 4))
	config, docs := taskByTitle(plan, "config"), taskByTitle(plan, "docs")
	// The user reverses the plan's edge: config now waits for docs.
	docs.DependsOn = nil
	config.DependsOn = []int{docs.ID}

	l.Apply(plan, pick(r, 2))
	callback := taskByTitle(plan, "callback")
	if !reflect.DeepEqual(callback.DependsOn, []int{config.ID}) {
		t.Errorf("callback depends on %v, want config %d", callback.DependsOn, config.ID)
	}
	if containsInt(docs.DependsOn, callback.ID) {
		t.Error("docs was made to wait for callback, which waits for docs through config: a cycle")
	}
	if containsInt(docs.DependsOn, config.ID) {
		t.Error("docs regained the dependency on config that the user removed")
	}
}

func TestLedger_IdeasStayIndependent(t *testing.T) {
	r := &Result{Suggestions: []*Suggestion{
		{ID: 1, Title: "dark mode", Category: CategoryUX, Effort: EffortS},
		{ID: 2, Title: "rate limits", Category: CategorySecurity, Effort: EffortXL, DependsOn: []int{1}},
	}}
	plan := existingPlan()
	added := NewLedger(r).Apply(plan, r.Suggestions)
	if len(added) != 2 {
		t.Fatalf("added %d, want 2", len(added))
	}
	if added[0].Priority != 3 || added[1].Priority != 5 {
		t.Errorf("idea priorities = %d, %d; want the effort mapping 3 and 5", added[0].Priority, added[1].Priority)
	}
	if len(added[1].DependsOn) != 0 {
		t.Error("ideas are independent and must not depend on each other")
	}
	if added[0].Role != pm.RoleFrontend || added[1].Role != pm.RoleSecurity {
		t.Errorf("roles = %q, %q", added[0].Role, added[1].Role)
	}
}

// Clone is what lets the hub apply, save, and only then keep the result.
func TestLedger_CloneIsIndependent(t *testing.T) {
	r := fourStepPlan()
	l := NewLedger(r)
	c := l.Clone()
	c.Apply(existingPlan(), pick(r, 1))
	if len(l.Pending(r.Suggestions)) != 4 {
		t.Error("applying a clone changed the original")
	}
	if len(c.Pending(r.Suggestions)) != 3 {
		t.Error("the clone did not record what it applied")
	}
}
