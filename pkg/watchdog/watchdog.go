// Package watchdog maintains the registry of per-task context cancel
// functions used to abort in-flight PM tasks on demand.
//
// The orchestrator registers a cancel for each task before launching it and
// unregisters it when the task leaves in_progress. The kill-request poller
// (Task 20140) calls Cancel when an operator changes a running task's status
// through the UI, cancelling the task's context by the same mechanism the
// orchestrator uses for its own teardown.
//
// Historical note: this package previously also ran a background goroutine
// that flagged long-running tasks as "stuck" (artifact-mtime heuristics,
// stuck_tasks forensics rows, task_stuck events). That detection was removed
// in Task 20151 — with per-task timeouts disabled by default (Task 20148),
// long provider calls are expected, and the "stuck" events were pure noise.
package watchdog

import (
	"context"
	"sync"
)

// Watchdog is a concurrency-safe registry mapping task IDs to the cancel
// functions of their in-flight contexts. The zero value is ready to use, and
// all methods are safe on a nil receiver (they become no-ops), so callers
// never need to guard call sites.
type Watchdog struct {
	mu      sync.Mutex
	cancels map[int]context.CancelFunc // per-task cancels registered by orchestrator
}

// Register associates a per-task context cancel function with taskID. The
// orchestrator MUST call this before launching the task and Unregister when
// the task completes (or fails / is cancelled) so the registry stays bounded.
func (w *Watchdog) Register(taskID int, cancel context.CancelFunc) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancels == nil {
		w.cancels = make(map[int]context.CancelFunc)
	}
	w.cancels[taskID] = cancel
}

// Unregister removes the registered cancel for taskID. The orchestrator
// should call Unregister whenever a task transitions out of in_progress.
func (w *Watchdog) Unregister(taskID int) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.cancels, taskID)
}

// Cancel fires the cancel function registered for taskID and removes the
// entry from the registry. Returns true when a cancel was fired, false when
// no cancel was registered (taskID unknown or already cleared). Used by the
// kill-request poller (Task 20140) to abort a running task on operator
// request.
//
// Safe to call from any goroutine; idempotent per task ID.
func (w *Watchdog) Cancel(taskID int) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	cancel, ok := w.cancels[taskID]
	if ok {
		delete(w.cancels, taskID)
	}
	w.mu.Unlock()
	if !ok || cancel == nil {
		return false
	}
	cancel()
	return true
}
