// Live per-task deadline management (Task 20143).
//
// Each in-flight task gets a child context whose cancellation fires when the
// effective wall-clock budget elapses. The budget is resolved at task start
// via effectiveTaskBudgetMinutes, but operators can change any of the inputs
// (task.MaxMinutes, state.DefaultMaxMinutes) at any time through the Web UI.
// To make those changes take effect on the *running* task — not just the next
// one — we replace context.WithTimeout with context.WithCancel + an external
// *time.Timer, and periodically re-evaluate the budget against the task's
// StartedAt. When the effective deadline shrinks past "now", the task is
// cancelled immediately; when it grows, the timer is reset to fire later.
//
// The deadlinePoller goroutine drives this. It is bound to the run context
// (same lifecycle as the kill_request poller) and ticks every few seconds —
// fast enough that a UI change is reflected within seconds, slow enough that
// the DB read isn't a hot path.

package orchestrator

import (
	"context"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
)

// deadlinePollInterval is the cadence of the live-deadline poller. A few
// seconds balances responsiveness (operator updates the timeout → running
// task picks it up almost immediately) against load on the state-load path,
// which already runs every second from the kill poller.
const deadlinePollInterval = 3 * time.Second

// liveDeadline tracks one in-flight task's cancellable budget. The cancel
// fires either by the timer (budget elapsed) or by an external caller
// (parent context cancel, manual kill). currentMin is the budget that
// armed the timer most recently — the poller compares it against the
// freshly-resolved effective budget to decide whether to reset.
//
// cancel is a context.CancelCauseFunc so callers can attach a sentinel
// describing *why* the context was cancelled. The timer path passes
// context.DeadlineExceeded so isTimeoutErr can recognise the firing as a
// budget exhaustion (Task 20143); manual release passes context.Canceled,
// preserving the pre-existing semantics for parent-cancel/kill paths.
type liveDeadline struct {
	taskID     int
	startedAt  time.Time
	currentMin int // most recently applied budget in minutes
	timer      *time.Timer
	cancel     context.CancelCauseFunc
	fired      bool // set once cancel has been invoked; suppresses duplicates
}

// liveDeadlineRegistry indexes liveDeadline by taskID. All access is mediated
// by the embedded mutex so the poller and per-task setup paths can race
// without corruption. The orchestrator owns one of these on its struct;
// nil-safe so tests that bypass New() don't panic.
type liveDeadlineRegistry struct {
	mu      sync.Mutex
	entries map[int]*liveDeadline
}

func newLiveDeadlineRegistry() *liveDeadlineRegistry {
	return &liveDeadlineRegistry{entries: make(map[int]*liveDeadline)}
}

// startTaskDeadline installs a fresh per-task deadline timer and registers it
// under taskID. Returns (ctx, cancel) suitable for use in place of
// context.WithTimeout: the returned ctx is cancelled when budgetMin elapses
// from time.Now or when the caller invokes the returned cancel — whichever
// fires first. The returned cancel also removes the entry from the registry
// and stops the timer, so it is always safe to defer.
//
// budgetMin may be 0, meaning "no timeout" (Task 20148): the entry is still
// registered (so the live poller can later arm a timer if an operator opts the
// running task into a budget via the UI), but no initial timer is armed, so the
// context is never cancelled by a deadline — only by the parent, a manual
// release, or a poller-driven adjustment. A positive budgetMin arms a timer as
// before.
func (r *liveDeadlineRegistry) startTaskDeadline(parent context.Context, taskID int, budgetMin int, unit time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	now := time.Now()
	entry := &liveDeadline{
		taskID:     taskID,
		startedAt:  now,
		currentMin: budgetMin,
		cancel:     cancel,
	}
	// Arm the initial timer only when a positive budget is set. If the parent
	// context is already cancelled the goroutine spawned by AfterFunc still
	// runs but no-ops: cancel() is idempotent and the registry lookup will
	// simply find no entry.
	if budgetMin > 0 {
		entry.timer = time.AfterFunc(time.Duration(budgetMin)*unit, func() {
			r.fire(taskID)
		})
	}

	r.mu.Lock()
	// If a stale entry is still registered for this taskID (e.g. a previous
	// run that didn't cleanly release), tear it down before overwriting.
	if old, ok := r.entries[taskID]; ok && old != nil {
		if old.timer != nil {
			old.timer.Stop()
		}
	}
	r.entries[taskID] = entry
	r.mu.Unlock()

	wrapped := func() {
		r.release(taskID)
	}
	return ctx, wrapped
}

// fire is invoked by the timer goroutine when the budget elapses. It marks
// the entry fired (so a follow-up reset doesn't re-arm a dead context) and
// fires the cancel with context.DeadlineExceeded as the cause so downstream
// isTimeoutErr can distinguish budget exhaustion from a manual cancel.
// Idempotent.
func (r *liveDeadlineRegistry) fire(taskID int) {
	r.mu.Lock()
	entry, ok := r.entries[taskID]
	if !ok || entry == nil || entry.fired {
		r.mu.Unlock()
		return
	}
	entry.fired = true
	cancel := entry.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel(context.DeadlineExceeded)
	}
}

// release tears down the timer and the cancel function for taskID, removing
// the entry from the registry. Safe to call when the task never registered
// (no-op). Used as the wrapped cancel function returned by startTaskDeadline.
func (r *liveDeadlineRegistry) release(taskID int) {
	r.mu.Lock()
	entry, ok := r.entries[taskID]
	if ok {
		delete(r.entries, taskID)
	}
	r.mu.Unlock()
	if !ok || entry == nil {
		return
	}
	if entry.timer != nil {
		entry.timer.Stop()
	}
	if entry.cancel != nil {
		entry.cancel(context.Canceled)
	}
}

// snapshot returns a shallow copy of the registry contents so the poller can
// iterate without holding the lock during expensive state reads.
func (r *liveDeadlineRegistry) snapshot() []*liveDeadline {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*liveDeadline, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}

// adjust applies a freshly-resolved budget to the entry for taskID. If the
// new effective deadline (startedAt + newMin*unit) is already in the past,
// the entry is fired immediately. Otherwise the timer is reset to fire at
// the new deadline. Calls into a no-op when the entry is gone (task already
// completed) or its currentMin already matches newMin.
//
// Returns true when an adjustment actually happened so the caller (the
// poller) can log it.
func (r *liveDeadlineRegistry) adjust(taskID int, newMin int, unit time.Duration) bool {
	if newMin <= 0 {
		return false
	}
	r.mu.Lock()
	entry, ok := r.entries[taskID]
	if !ok || entry == nil || entry.fired {
		r.mu.Unlock()
		return false
	}
	if entry.currentMin == newMin {
		r.mu.Unlock()
		return false
	}
	deadline := entry.startedAt.Add(time.Duration(newMin) * unit)
	remaining := time.Until(deadline)
	entry.currentMin = newMin
	timer := entry.timer
	r.mu.Unlock()

	if remaining <= 0 {
		// New budget already exceeded — fire now. fire() is locked and
		// idempotent so racing with a natural timer expiry is safe.
		r.fire(taskID)
		return true
	}
	if timer != nil {
		// timer.Reset is safe even when the timer has already been Stop()ed
		// or fired, as long as we don't read from its channel — and we
		// don't (AfterFunc has no channel). The behaviour we want is "the
		// callback fires after `remaining` from now"; Reset gives us that.
		timer.Reset(remaining)
	} else {
		// The task started with no timeout (no timer armed; Task 20148) and an
		// operator has now opted it into a budget via the UI. Arm a fresh
		// timer so the newly-set deadline actually fires.
		r.mu.Lock()
		if e, ok := r.entries[taskID]; ok && e != nil && !e.fired {
			e.timer = time.AfterFunc(remaining, func() { r.fire(taskID) })
		}
		r.mu.Unlock()
	}
	return true
}

// startDeadlinePoller launches the background goroutine that watches for
// timeout changes on running tasks. Bound to ctx; exits when ctx is
// cancelled. Safe to call when the registry is nil (no-op) — the poller is
// only useful when at least one task has registered a deadline.
//
// Each tick reloads the project state (cheap: LoadLite skips per-step rows)
// and resolves the effective budget for every registered task. When the
// resolved budget differs from the most-recently-applied value the timer
// is reset; when the new deadline is already in the past the task is
// cancelled immediately.
func (o *Orchestrator) startDeadlinePoller(ctx context.Context) {
	if o == nil || o.liveDeadlines == nil {
		return
	}
	o.killWG.Add(1)
	go func() {
		defer o.killWG.Done()
		t := time.NewTicker(deadlinePollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				o.refreshLiveDeadlines()
			}
		}
	}()
}

// refreshLiveDeadlines is one tick of the deadline poller. Reads the freshly
// persisted disk state (so the orchestrator picks up UI-driven changes
// written by another process to DefaultMaxMinutes or per-task MaxMinutes)
// and re-evaluates the effective budget for every registered task.
func (o *Orchestrator) refreshLiveDeadlines() {
	if o == nil || o.liveDeadlines == nil || o.state == nil {
		return
	}
	// LoadLite skips the per-step rows so we don't allocate megabytes of
	// step history on every tick. We only need the plan tasks and the
	// project-level default budget.
	disk, err := state.LoadLite(o.state.WorkDir)
	if err != nil || disk == nil {
		return
	}
	for _, entry := range o.liveDeadlines.snapshot() {
		if entry == nil {
			continue
		}
		// Resolve task.MaxMinutes from disk so a UI PATCH propagates even
		// though our in-memory copy still has the old value. Per-task is
		// the highest-priority signal in effectiveTaskBudgetMinutes.
		var taskMaxMin int
		if disk.Plan != nil {
			for _, t := range disk.Plan.Tasks {
				if t != nil && t.ID == entry.taskID {
					taskMaxMin = t.MaxMinutes
					break
				}
			}
		}
		newMin := resolveEffectiveBudget(taskMaxMin, disk.DefaultMaxMinutes, o.config.TaskTimeoutMinutes)
		if newMin == entry.currentMin {
			continue
		}
		if o.liveDeadlines.adjust(entry.taskID, newMin, taskTimeoutUnit) && o.log != nil {
			o.log.Info(logger.EventTaskStart, entry.taskID,
				"task timeout updated mid-run",
				map[string]interface{}{
					"task_id":     entry.taskID,
					"old_minutes": entry.currentMin,
					"new_minutes": newMin,
				})
		}
	}
}

// resolveEffectiveBudget mirrors effectiveTaskBudgetMinutes but takes the
// inputs as plain values so it can be called against freshly-loaded disk
// state without mutating o.state. Keeps the priority order identical:
// task > project > process-wide config. Returns 0 when no explicit budget is
// set anywhere (the default; Task 20148: tasks have no timeout).
func resolveEffectiveBudget(taskMaxMin, projectDefault, processDefault int) int {
	if taskMaxMin > 0 {
		return taskMaxMin
	}
	if projectDefault > 0 {
		return projectDefault
	}
	if processDefault >= config.OrchestratorTaskTimeoutMinutesLower &&
		processDefault <= config.OrchestratorTaskTimeoutMinutesUpper {
		return processDefault
	}
	return 0
}
