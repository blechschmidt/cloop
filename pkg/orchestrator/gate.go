package orchestrator

import (
	"context"
	"fmt"

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
//  1. Eligibility — pending tasks whose dependencies are all done or skipped.
//  2. The blocked sweep — only when nothing is eligible, so a task whose
//     failed dependency is still being healed is not skipped prematurely.
//  3. Selection — every eligible task in parallel mode, otherwise the single
//     highest-priority one.
//  4. The tag filter.
//  5. The condition gate.
//
// Skips are applied to the plan (status plus annotation) before returning;
// the caller is responsible for printing Events and persisting the plan when
// Skipped() is non-zero.
func GateTasks(ctx context.Context, plan *pm.Plan, cfg GateConfig) GateDecision {
	var d GateDecision
	if plan == nil {
		d.Exhausted = true
		return d
	}

	// (1) Eligibility. ReadyTasks is pending && DepsReady in plan order.
	eligible := plan.ReadyTasks()

	// (2) The blocked sweep runs only when nothing is eligible. This is the
	// sequential path's trigger, adopted for both: the parallel path used to
	// sweep on every iteration, which skips a dependent task the moment its
	// dependency fails — even though the auto-heal paths can still reset that
	// dependency to pending. Deferring the sweep until the queue drains gives
	// a heal its chance and cannot change which tasks ultimately run, because
	// PermanentlyBlocked only ever becomes true, never false, for a task whose
	// dependency stays failed.
	if len(eligible) == 0 {
		for _, t := range plan.Tasks {
			if t.Status == pm.TaskPending && plan.PermanentlyBlocked(t) {
				d.Events = append(d.Events, applySkip(blockedSkip(t)))
			}
		}
		d.Exhausted = len(d.Events) == 0
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
