package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/condition"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/fatih/color"
)

// Task gating — deciding which tasks run, which are skipped and which are
// merely deferred until a dependency lands — is the orchestrator's most
// consequential decision. It used to be written twice: once in
// runPMSequential and once in runPMParallel. The two copies had already
// drifted (the parallel annotations carried a "(parallel mode)" suffix the
// sequential ones did not) and the class of bug that produces is the one
// fixed in Task 20203 (a reset task immediately skipped) and Task 20224
// (auto-evolve building on tasks that never ran).
//
// GateTasks is now the single implementation. Both paths call it and differ
// only in GateConfig.Parallel, which decides how many of the eligible tasks
// the caller intends to launch this iteration.

// GateEventKind classifies one line of the gate's reasoning. Skip kinds change
// a task's status; the rest are observations worth logging.
type GateEventKind string

const (
	// GateSkipBlocked marks a pending task that can never run because a
	// dependency failed or timed out.
	GateSkipBlocked GateEventKind = "skip_blocked"
	// GateSkipTagFilter marks a task cut by the active --tag filter.
	GateSkipTagFilter GateEventKind = "skip_tag_filter"
	// GateSkipCondition marks a task whose condition gate refused to proceed.
	GateSkipCondition GateEventKind = "skip_condition"
	// GateConditionMet records a condition that passed.
	GateConditionMet GateEventKind = "condition_met"
	// GateConditionError records an evaluator failure. The task still runs:
	// a transient provider outage must not silently skip work.
	GateConditionError GateEventKind = "condition_error"
	// GateHoldQuarantined records a pending task held back because it is
	// quarantined as a suspected node killer (Task 20391). Its status is left
	// alone: it waits, visibly pending, for the explicit reset that releases it.
	GateHoldQuarantined GateEventKind = "hold_quarantined"
	// GatePassedReview records a human review gate a person approved, which
	// the run now records as passed (Task 20477). It changes the gate's
	// status, so the caller persists the plan.
	GatePassedReview GateEventKind = "passed_review"
)

// GateEvent is one decision the gate made about one task, carrying both the
// console line and — for skips — the plan annotation. Keeping the two
// together is what stops the wording of a skip diverging between callers.
type GateEvent struct {
	Kind GateEventKind
	Task *pm.Task
	// Line is the console message, already formatted and newline-terminated.
	Line string
	// Annotation is the text recorded on the task. Empty for non-skip events.
	Annotation string
}

// changesPlan reports whether this event changed the task it names, so the
// pass that produced it must be persisted: a skip, or a review gate passed.
func (e GateEvent) changesPlan() bool { return e.IsSkip() || e.Kind == GatePassedReview }

// IsSkip reports whether this event changed the task's status to skipped.
func (e GateEvent) IsSkip() bool {
	switch e.Kind {
	case GateSkipBlocked, GateSkipTagFilter, GateSkipCondition:
		return true
	default:
		return false
	}
}

// IsAlert reports whether the event should be printed prominently rather than
// dimmed. Only a dependency failure taking a task down with it qualifies.
func (e GateEvent) IsAlert() bool { return e.Kind == GateSkipBlocked }

// ConditionFunc evaluates a task's Condition field. It mirrors
// condition.Evaluate with the provider and workdir already bound. A non-nil
// error is advisory: the returned Result still decides, and condition.Evaluate
// deliberately returns Proceed=true when the provider call fails.
type ConditionFunc func(ctx context.Context, plan *pm.Plan, task *pm.Task) (condition.Result, error)

// GateConfig is the slice of run configuration that decides what runs.
type GateConfig struct {
	// TagFilter, when non-empty, restricts execution to tasks carrying at
	// least one of these tags. Non-matching tasks are skipped, not deferred.
	TagFilter []string
	// Parallel selects batch semantics. When false the gate considers only the
	// single highest-priority eligible task, matching the sequential loop.
	Parallel bool
	// EvalCondition evaluates task conditions. When nil, a task carrying a
	// condition proceeds and the gate emits a GateConditionError so the gap is
	// visible rather than silent.
	EvalCondition ConditionFunc
}

// GateDecision is the result of one gating pass over a plan.
type GateDecision struct {
	// Runnable holds the tasks that cleared every gate, in the order the
	// caller should launch them. Empty means nothing runs this iteration.
	Runnable []*pm.Task
	// Events records every skip and observation, in the order they occurred.
	Events []GateEvent
	// Exhausted is true when no pending task had its dependencies satisfied
	// and the blocked sweep found nothing either — the plan has no more work
	// the gate can unblock, so the caller should leave its loop.
	Exhausted bool
	// Waiting is the human review gate the run has reached (Task 20477):
	// closed, first in the queue, and with no work ahead of it left to run.
	// The caller stops the run there for a person to review; nil otherwise.
	// Never set together with Exhausted or a non-empty Runnable.
	Waiting *pm.Task
}

// Changed reports whether this pass changed the plan — a skip or a review
// gate recorded as passed — so the caller must persist it.
func (d GateDecision) Changed() bool {
	for _, e := range d.Events {
		if e.changesPlan() {
			return true
		}
	}
	return false
}

// ChangedIDs returns the IDs of the tasks this pass changed, in order.
func (d GateDecision) ChangedIDs() []int {
	var ids []int
	for _, e := range d.Events {
		if e.changesPlan() {
			ids = append(ids, e.Task.ID)
		}
	}
	return ids
}

// Skipped returns the number of tasks this pass moved to skipped. A non-zero
// count means the plan was mutated and the caller must persist it.
func (d GateDecision) Skipped() int {
	n := 0
	for _, e := range d.Events {
		if e.IsSkip() {
			n++
		}
	}
	return n
}

// SkippedIDs returns the IDs of the tasks this pass skipped, in order.
func (d GateDecision) SkippedIDs() []int {
	var ids []int
	for _, e := range d.Events {
		if e.IsSkip() {
			ids = append(ids, e.Task.ID)
		}
	}
	return ids
}

// GateTasks decides what runs next. It applies, in order:
//
//  0. Human review gates a person approved are recorded as passed (Task
//     20477), so the tasks they held become eligible in this same pass.
//  1. Eligibility — pending work whose dependencies are all done or skipped,
//     which is not held behind a closed human review gate, and which is not
//     quarantined as a suspected node killer.
//  2. The blocked sweep — only when nothing is eligible, so a task whose
//     failed dependency is still being healed is not skipped prematurely.
//     It reaches no further than the first closed review gate: a person
//     reviewing there may yet reset the failed dependency. With nothing
//     swept and a closed gate first in the queue, the run has reached it
//     (Waiting).
//  3. Selection — every eligible task in parallel mode, otherwise the single
//     highest-priority one.
//  4. The tag filter.
//  5. The condition gate.
//
// Skips and passed gates are applied to the plan before returning; the caller
// is responsible for printing Events and persisting the plan when Changed().
func GateTasks(ctx context.Context, plan *pm.Plan, cfg GateConfig) GateDecision {
	var d GateDecision
	if plan == nil {
		d.Exhausted = true
		return d
	}

	// (0) Approved review gates. An approval is a definition field, so it
	// reaches a run that held the plan when the person approved (its sync
	// adopts it); the status is the run's to write, and it writes it here.
	// Only an approval opens a gate this way — the run never decides on its
	// own that a review is done.
	passed := 0
	now := time.Now()
	for _, t := range plan.Tasks {
		if t != nil && !t.IsWork() && t.Approved && t.Status == pm.TaskPending {
			pm.PassGate(t, now)
			passed++
			d.Events = append(d.Events, GateEvent{
				Kind: GatePassedReview,
				Task: t,
				Line: fmt.Sprintf("✓ Review gate %d approved — continuing past it: %s\n", t.ID, t.Title),
			})
		}
	}

	// (1) Eligibility. ReadyTasks is pending work with its dependencies
	// satisfied, ahead of the first closed review gate, in execution order.
	eligible := plan.ReadyTasks()

	// A quarantined task never runs, whatever its status (Task 20391). It
	// fails when it is marked, and the explicit reset that returns it to
	// pending is the one thing that clears the mark — so a quarantined task
	// that is pending got there some other way: --retry-failed on a build that
	// predates the mark, a hand edit, a plan import. Running it would hand the
	// next node the workload two nodes already went down under.
	if held := quarantinedOf(eligible); len(held) > 0 {
		kept := make([]*pm.Task, 0, len(eligible)-len(held))
		for _, t := range eligible {
			if !t.Quarantined() {
				kept = append(kept, t)
			}
		}
		eligible = kept
		for _, t := range held {
			d.Events = append(d.Events, GateEvent{
				Kind: GateHoldQuarantined,
				Task: t,
				Line: fmt.Sprintf("  Task %d is held: quarantined as a suspected node killer (%s). "+
					"Reset it (`cloop task reset %d`) to run it again.\n",
					t.ID, pm.DescribeNodeLosses(t.Quarantine.Nodes), t.ID),
			})
		}
	}

	// (2) The blocked sweep runs only when nothing is eligible. This is the
	// sequential path's trigger, adopted for both: the parallel path used to
	// sweep on every iteration, which skips a dependent task the moment its
	// dependency fails — even though the auto-heal paths can still reset that
	// dependency to pending. Deferring the sweep until the queue drains gives
	// a heal its chance and cannot change which tasks ultimately run, because
	// PermanentlyBlocked only ever becomes true, never false, for a task whose
	// dependency stays failed.
	if len(eligible) == 0 {
		// Only work is swept, and only work ahead of the first closed review
		// gate (Task 20477). A gate is never skipped for a dependency: that
		// would open it without the person it waits for. And the tasks it
		// holds wait for the review too, which may reset the failed task they
		// depend on rather than let them be skipped under it.
		barrier := plan.GateBarrier()
		swept := 0
		for _, t := range plan.Tasks {
			if t.Status == pm.TaskPending && t.IsWork() && !pm.HeldBy(barrier, t) && plan.PermanentlyBlocked(t) {
				d.Events = append(d.Events, applySkip(blockedSkip(t)))
				swept++
			}
		}
		// Exhausted when the sweep changed nothing. Counted from the sweep
		// alone: a held quarantined task is an event too, and counting it
		// would keep the caller looping over a plan with nothing it may run.
		// A gate passed above changed the plan as a skip does, so the caller
		// looks again. And a closed gate first in the queue with nothing
		// ahead of it left to run is not the end of the plan: the run has
		// reached it, and stops there for a person.
		if swept == 0 && passed == 0 {
			if w := plan.WaitingGate(); w != nil {
				d.Waiting = w
			} else {
				d.Exhausted = true
			}
		}
		return d
	}

	// (3) Selection. ReadyTasks returns its candidates already in execution
	// order (pm.LessByExecutionOrder), so sequential mode takes the head and
	// parallel mode keeps the whole list — in that order, because the caller
	// truncates it to the worker-pool size. Parallel mode used to keep the list
	// unsorted, which made the cap select by ID: reordering the queue in the UI
	// changed the priorities the scheduler read and still dispatched the same
	// low-numbered tasks (Task 20299).
	candidates := eligible
	if !cfg.Parallel {
		candidates = []*pm.Task{eligible[0]}
	}

	// (4) Tag filter.
	if len(cfg.TagFilter) > 0 {
		kept := make([]*pm.Task, 0, len(candidates))
		for _, t := range candidates {
			if pm.TaskMatchesTags(t, cfg.TagFilter) {
				kept = append(kept, t)
				continue
			}
			d.Events = append(d.Events, applySkip(tagFilterSkip(t, cfg.TagFilter)))
		}
		candidates = kept
	}

	// (5) Condition gate.
	kept := make([]*pm.Task, 0, len(candidates))
	for _, t := range candidates {
		if t.Condition == "" {
			kept = append(kept, t)
			continue
		}
		if cfg.EvalCondition == nil {
			d.Events = append(d.Events, conditionErrorEvent(t, errNoConditionEvaluator))
			kept = append(kept, t)
			continue
		}
		res, err := cfg.EvalCondition(ctx, plan, t)
		if err != nil {
			d.Events = append(d.Events, conditionErrorEvent(t, err))
		}
		if !res.Proceed {
			d.Events = append(d.Events, applySkip(conditionSkip(t, res)))
			continue
		}
		d.Events = append(d.Events, GateEvent{
			Kind: GateConditionMet,
			Task: t,
			Line: fmt.Sprintf("  Condition met for task %d: %s\n", t.ID, res.Reason),
		})
		kept = append(kept, t)
	}

	d.Runnable = kept
	return d
}

// quarantinedOf returns the quarantined tasks among ts.
func quarantinedOf(ts []*pm.Task) []*pm.Task {
	var out []*pm.Task
	for _, t := range ts {
		if t.Quarantined() {
			out = append(out, t)
		}
	}
	return out
}

// gateConfig builds the gate's view of the run configuration. Both PM paths
// use it, so the only thing that distinguishes them is the parallel flag.
func (o *Orchestrator) gateConfig(parallel bool) GateConfig {
	return GateConfig{
		TagFilter: o.config.TagFilter,
		Parallel:  parallel,
		EvalCondition: func(ctx context.Context, plan *pm.Plan, t *pm.Task) (condition.Result, error) {
			return condition.Evaluate(ctx, t, plan, o.provider, provider.Options{
				Model:   o.state.Model,
				Timeout: o.config.StepTimeout,
			}, o.config.WorkDir)
		},
	}
}

// printGateDecision writes the gate's reasoning to the console in the order it
// was produced, so a condition that passed still appears between the skips
// around it. alert is used for a dependency failure taking a task down with
// it; everything else is dimmed.
func printGateDecision(d GateDecision, alert, dim *color.Color) {
	for _, e := range d.Events {
		if e.IsAlert() {
			alert.Print(e.Line)
		} else {
			dim.Print(e.Line)
		}
	}
}

// errNoConditionEvaluator is reported when a task carries a condition but the
// caller wired no evaluator. The task proceeds — refusing to run it would be
// a silent skip — but the gap is logged like any other evaluator failure.
var errNoConditionEvaluator = fmt.Errorf("no condition evaluator configured")

// applySkip records the skip on the task and returns the event describing it.
// Status and annotation are set together here and nowhere else, so the two can
// never describe a task differently.
func applySkip(e GateEvent) GateEvent {
	e.Task.Status = pm.TaskSkipped
	pm.AddAnnotation(e.Task, "ai", e.Annotation)
	return e
}

func blockedSkip(t *pm.Task) GateEvent {
	return GateEvent{
		Kind:       GateSkipBlocked,
		Task:       t,
		Line:       fmt.Sprintf("⊘ Task %d skipped (blocked by failed dependency): %s\n", t.ID, t.Title),
		Annotation: "Task skipped: permanently blocked by failed dependency.",
	}
}

func tagFilterSkip(t *pm.Task, filter []string) GateEvent {
	return GateEvent{
		Kind:       GateSkipTagFilter,
		Task:       t,
		Line:       fmt.Sprintf("⊘ Task %d skipped (no matching tag): %s\n", t.ID, t.Title),
		Annotation: fmt.Sprintf("Task skipped: did not match active tag filter %v.", filter),
	}
}

// conditionErrorEvent reports an evaluator that could not answer. The task
// runs regardless — condition.Evaluate returns Proceed=true on provider error
// precisely so a transient outage cannot silently skip work.
func conditionErrorEvent(t *pm.Task, err error) GateEvent {
	return GateEvent{
		Kind: GateConditionError,
		Task: t,
		Line: fmt.Sprintf("  condition eval error for task %d (proceeding): %v\n", t.ID, err),
	}
}

func conditionSkip(t *pm.Task, res condition.Result) GateEvent {
	return GateEvent{
		Kind: GateSkipCondition,
		Task: t,
		Line: fmt.Sprintf("⊘ Task %d skipped (condition not met): %s\n  Condition: %s\n  Reason: %s\n",
			t.ID, t.Title, t.Condition, res.Reason),
		Annotation: fmt.Sprintf("Task skipped: condition gate %q not met. Reason: %s", t.Condition, res.Reason),
	}
}
