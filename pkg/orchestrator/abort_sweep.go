package orchestrator

// abort_sweep.go stops auto-evolve building on tasks that never ran
// (Task 20224).
//
// Task 20211 taught the live path to recognise a provider refusal and reset the
// task to pending rather than closing it as done. Everything recorded before
// that fix stayed wrong, and `cloop task audit-ledger` — which could list the
// damage — was consulted by nothing. On this project fourteen tasks were
// recorded as done whose whole summary was "You've hit your limit" or the
// harness declining to run under root. The plan counted them, declared itself
// complete, and auto-evolve invented new work on top. Three of the features
// they were supposed to deliver were simply absent from the tree for about a
// hundred iterations.
//
// The sweep closes that loop: before a plan is allowed to count as complete or
// to trigger an evolve round, every task the plan believes it finished is
// checked against the classifier, and one whose "work" is a refusal goes back
// to pending. A plan cannot finish on the strength of an error message.
//
// Why reopen rather than merely refuse to finish: an aborted task never ran, so
// pending is the truthful status — the same call abortTask makes for a live
// abort. Refusing to complete while leaving the task marked done would deadlock
// the loop, since nothing would be left for NextTask to hand out.
//
// The audit cannot be trusted blindly in the other direction either. Of those
// fourteen, nine turned out to have been quietly re-implemented by later tasks:
// the refusal summary is genuine, the work exists anyway. Those carry a cleared
// record naming what re-landed them, which keeps them visible as bad ledger
// entries without reopening finished work. See pm.TaskAbort.

import (
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
)

// classifyStoredOutcome returns the abort record a task's stored summary
// warrants, and whether that record was derived now rather than reused.
//
// Only done tasks are candidates: a failed or skipped task whose summary is a
// refusal is already visible as not-complete, which is the state this sweep
// exists to restore.
//
// An empty summary is deliberately not a signature. Live, an empty response is
// an abort and the orchestrator classifies it as one. Stored, it only means no
// summary was ever recorded — true of dozens of tasks in this project that
// genuinely shipped (#174 and #20043 among them). Treating absence as evidence
// here would reopen real work, so the sweep demands a recognisable refusal and
// nothing less.
func classifyStoredOutcome(t *pm.Task) (rec *pm.TaskAbort, fresh bool) {
	if t == nil || t.Status != pm.TaskDone {
		return nil, false
	}
	if strings.TrimSpace(t.Result) == "" {
		return nil, false
	}
	// A persisted record that still describes this exact summary is reused
	// verbatim — that is the point of persisting it. The fingerprint is what
	// makes the reuse safe: once the task runs again and its summary changes, the
	// record stops matching and is re-derived below, so neither a stale
	// classification nor a stale clearance can outlive the text it judged.
	if pm.AbortAppliesTo(t.Abort, t.Result) {
		return t.Abort, false
	}
	ab, ok := ClassifyAbort(t.Result)
	if !ok || ab.Class == AbortEmptyOutput {
		return nil, false
	}
	return &pm.TaskAbort{
		Class:              string(ab.Class),
		Reason:             ab.Reason,
		Evidence:           ab.Evidence,
		DetectedAt:         time.Now().UTC(),
		SummaryFingerprint: pm.FingerprintSummary(t.Result),
	}, true
}

// ClassifyStoredOutcome returns the abort record a task's stored summary
// warrants, or nil when the summary describes work.
//
// Exported so `cloop task audit-ledger` reports exactly what the orchestrator
// acts on. Two implementations of "is this summary a refusal" would drift, and
// a ledger command that disagrees with the loop it is auditing is worse than no
// command at all — which is roughly what the previous one turned out to be.
func ClassifyStoredOutcome(t *pm.Task) *pm.TaskAbort {
	rec, _ := classifyStoredOutcome(t)
	return rec
}

// sweepAbortedOutcomes classifies every done task's stored summary, persists
// what it finds, and returns any uncleared refusal to pending. It reports how
// many tasks it reopened.
//
// Callers must invoke it with no task in flight — the top of either PM loop,
// after SyncFromDisk and before the completion check.
func (o *Orchestrator) sweepAbortedOutcomes(s *state.ProjectState) int {
	if s == nil || s.Plan == nil {
		return 0
	}
	reopened, changed := 0, false
	for _, t := range s.Plan.Tasks {
		if t == nil {
			continue
		}
		rec, fresh := classifyStoredOutcome(t)
		if rec == nil {
			// The task's summary is not a refusal. Any record still hanging
			// off it describes a summary that no longer exists — the task was
			// re-run and produced real work — so it is history, not a finding.
			if t.Status == pm.TaskDone && t.Abort != nil && !pm.AbortAppliesTo(t.Abort, t.Result) {
				t.Abort = nil
				changed = true
			}
			continue
		}
		if fresh {
			t.Abort = rec
			changed = true
		}
		if !rec.Blocks() {
			// Triaged: the work exists despite the summary. The record stays
			// so the bad ledger entry remains visible, but it does not reopen.
			continue
		}
		o.reopenAbortedOutcome(s, t, rec)
		reopened++
		changed = true
	}
	if changed {
		s.Save()
	}
	return reopened
}

// reopenAbortedOutcome returns one task recorded as done on a refusal to
// pending, and says so loudly enough that the reason is not lost.
func (o *Orchestrator) reopenAbortedOutcome(s *state.ProjectState, t *pm.Task, rec *pm.TaskAbort) {
	t.Status = pm.TaskPending
	// A run that produced nothing has no completion instant and no elapsed
	// work; leaving these set would keep rendering the task as finished.
	t.CompletedAt = nil
	t.ActualMinutes = 0

	pm.AddAnnotation(t, "cloop", fmt.Sprintf(
		"Reopened by the ledger sweep: recorded done, but the stored summary is a %s (%s), not a description of work. "+
			"Reset to pending — it never ran.", rec.Class, rec.Reason))

	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventTaskAborted,
		TaskID:    t.ID,
		TaskTitle: t.Title,
		Step:      state.NoStep,
		Message: fmt.Sprintf("Task #%d reopened by ledger sweep (%s): %s — recorded done but never ran",
			t.ID, rec.Class, rec.Reason),
	}, map[string]any{
		"abort_class": rec.Class,
		"reason":      rec.Reason,
		"evidence":    rec.Evidence,
		"source":      "ledger-sweep",
	})

	if !o.log.IsJSON() {
		color.New(color.FgYellow).Printf(
			"↻ Task %d reopened: recorded done, but its summary is a %s (%s) — it never ran\n",
			t.ID, rec.Class, rec.Reason)
	}
	o.log.Warn(logger.EventTaskAborted, t.ID, t.Title, map[string]interface{}{
		"abort_class": rec.Class,
		"reason":      rec.Reason,
		"source":      "ledger-sweep",
	})
}
