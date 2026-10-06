package ui

// failover_settle.go decides what a lost node's work means for the project it
// belonged to (Task 20391).
//
// The supervisor claims a session stranded on an executor that stopped
// answering, and the claim says whether the session may be re-dispatched or
// has used up executors.failover.max_attempts. This file settles the tasks:
//
//   - every task the lost node was running gets the loss recorded against it,
//     in the project's own task_node_losses;
//   - a task two or more distinct nodes went down under is a suspected node
//     killer: it is quarantined and fails, and runs again only after an
//     explicit reset;
//   - when the session is exhausted, the tasks it was running fail too, with
//     every node the run was lost on and when named in the reason — not
//     returned to pending for the next dispatch to pick up and carry onto the
//     next node;
//   - otherwise a task goes back to pending for the replacement run, as
//     failover always did.
//
// Every failed task gets its verdict sidecar written before its status, so
// stale-run recovery — which applies the orchestrator's verdict before the
// agent's word (Task 20365) — fails it again rather than resurrecting it if
// anything brings it back to in_progress. Everything is journalled, and the
// quarantine is audited in the project's chain; the exhaustion itself is
// audited in the control plane's by the supervisor's event sink.
//
// Which tasks a node "was running" has two sources, because a run sees its
// project in one of two places. A run on an executor sharing the hub's
// filesystem writes the hub's own plan, so its in_progress tasks are the
// answer. A run on a device works on a copy, and the hub learns of its
// progress only from the run's own announcements — the orchestrator's
// "━━━ Task 7/12: …" lines — which watchSessionExit records on the session
// (run_progress.go). Both are consulted, and a task already finished in the
// hub's plan is never charged.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// failoverOutcome is what settling one claimed session did, for tests and
// for the caller's log line.
type failoverOutcome struct {
	// Charged are the tasks the lost node was running.
	Charged []int
	// Requeued went back to pending for the replacement run.
	Requeued []int
	// Failed failed: the session was exhausted, or they were quarantined.
	Failed []int
	// Quarantined were marked as suspected node killers.
	Quarantined []int
	// Lost is every node the run was lost on so far, oldest first.
	Lost []pm.NodeLoss
}

// Verdict reason codes a failover writes.
const (
	failoverReasonExhausted  = "failover_exhausted"
	failoverReasonNodeKiller = "node_killer"
)

// settleFailover settles the tasks of one claimed session. dir is the
// control plane's directory. Failures are reported and do not stop the
// caller: a session whose tasks could not be marked must still be
// re-dispatched or closed, exactly as before this existed.
func settleFailover(dir string, ev executor.FailoverEvent) failoverOutcome {
	var out failoverOutcome
	projectPath := executorstore.FailoverProjectPath(ev.Session)
	lostAt := ev.Unreachable
	if lostAt.IsZero() {
		lostAt = ev.At
	}
	if lostAt.IsZero() {
		lostAt = time.Now()
	}
	thisLoss := pm.NodeLoss{
		ExecutorID: ev.From, LostAt: lostAt, SessionID: ev.Session.ID, Attempt: ev.Session.Attempt,
	}
	out.Lost = failoverChain(dir, ev, thisLoss)

	if projectPath == "" || !hasProjectDB(projectPath) {
		return out
	}
	st, err := state.Load(projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: failover of session %s: load %s: %v\n", ev.Session.ID, projectPath, err)
		return out
	}
	db, err := statedb.Open(state.DBPath(projectPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: failover of session %s: open %s: %v\n", ev.Session.ID, projectPath, err)
		return out
	}
	defer db.Close()
	db.AsProject()

	charged := chargedTasks(st, ev.Session)
	now := time.Now()
	type failure struct {
		task   *pm.Task
		reason string
		code   string
		mark   *pm.TaskQuarantine
	}
	var failures []failure
	for _, t := range charged {
		out.Charged = append(out.Charged, t.ID)
		if _, err := db.RecordTaskNodeLoss(t.ID, thisLoss); err != nil {
			fmt.Fprintf(os.Stderr, "ui: failover: record node loss on task %d: %v\n", t.ID, err)
		}
		losses, err := db.TaskNodeLosses(t.ID)
		if err != nil || len(losses) == 0 {
			losses = []pm.NodeLoss{thisLoss}
		}

		switch {
		case pm.SuspectedNodeKiller(losses):
			mark := &pm.TaskQuarantine{
				Kind:     pm.QuarantineNodeKiller,
				Reason:   nodeKillerReason(losses),
				Nodes:    losses,
				MarkedAt: now,
				MarkedBy: "failover",
			}
			failures = append(failures, failure{task: t, reason: mark.Reason, code: failoverReasonNodeKiller, mark: mark})
		case ev.Exhausted:
			failures = append(failures, failure{task: t, reason: exhaustedReason(ev, out.Lost), code: failoverReasonExhausted})
		default:
			// Failed-with-retry: the attempt on the dead node did fail, and the
			// task is going to be retried. Recorded as a FailCount bump plus a
			// return to pending rather than as TaskFailed, because TaskFailed
			// is a state the orchestrator will not re-run without
			// --retry-failed — and a task whose executor died once deserves an
			// automatic retry, not a manual one.
			t.Status = pm.TaskPending
			t.FailCount++
			out.Requeued = append(out.Requeued, t.ID)
		}
	}

	// Verdict, then mark, then status. Each write is what makes the next one
	// safe to lose: if the status write fails, or a stale writer later puts
	// the task back in progress, recovery reads the verdict before anything
	// else and fails the task again; and a mark written before the status
	// leaves, at worst, a task that still reads pending but is held — while
	// the other order could leave a failed task unmarked, which --retry-failed
	// would run on the next node.
	for _, f := range failures {
		t := f.task
		v := taskrecover.Verdict{
			TaskID: t.ID, Status: pm.TaskFailed, Reason: f.code,
			Source: taskrecover.SourceFailover, Detail: f.reason, StartedAt: t.StartedAt,
		}
		if err := taskrecover.WriteVerdict(projectPath, v); err != nil {
			fmt.Fprintf(os.Stderr, "ui: failover: verdict for task %d: %v\n", t.ID, err)
		}
		if f.mark != nil {
			if err := db.PutTaskQuarantine(t.ID, *f.mark); err != nil {
				fmt.Fprintf(os.Stderr, "ui: failover: quarantine task %d: %v\n", t.ID, err)
			} else {
				statedb.AuditTaskQuarantine(db, t, *f.mark, "failover")
				out.Quarantined = append(out.Quarantined, t.ID)
			}
		}
		t.Status = pm.TaskFailed
		t.FailCount++
		completed := now
		t.CompletedAt = &completed
		t.Result = f.reason
		t.Annotations = append(t.Annotations, pm.Annotation{Timestamp: now, Author: "cloop", Text: f.reason})
		out.Failed = append(out.Failed, t.ID)
	}

	if len(out.Requeued)+len(out.Failed) > 0 {
		if err := st.SaveDirect(); err != nil {
			fmt.Fprintf(os.Stderr, "ui: failover: persist the tasks of %s: %v\n", projectPath, err)
		}
	}

	reasons := make(map[int]journalFailure, len(failures))
	for _, f := range failures {
		reasons[f.task.ID] = journalFailure{reason: f.reason, quarantined: f.mark != nil}
	}
	journalFailover(projectPath, ev, out, reasons)
	return out
}

// journalFailure is what the journal says about one failed task.
type journalFailure struct {
	reason      string
	quarantined bool
}

// journalFailover writes what the failover did to the project's journal: a
// row per task it touched, and — when the run is not going anywhere — a row
// for the run itself, so a project with nothing attributed still says why its
// run stopped.
func journalFailover(projectPath string, ev executor.FailoverEvent, out failoverOutcome, failed map[int]journalFailure) {
	details := map[string]any{
		"executor":     ev.From,
		"session_id":   ev.Session.ID,
		"attempt":      ev.Session.Attempt,
		"max_attempts": ev.MaxAttempts,
		"failover":     true,
		"nodes":        nodeLossDetails(out.Lost),
	}
	for _, id := range out.Requeued {
		state.LogEventDetails(projectPath, state.EventRow{
			Type:    state.EventFailover,
			TaskID:  id,
			Step:    state.NoStep,
			Message: fmt.Sprintf("executor %s became unreachable; task requeued for retry", ev.From),
		}, details)
	}
	for _, id := range out.Failed {
		f := failed[id]
		msg := "task failed: " + f.reason
		if f.quarantined {
			msg = "task quarantined as a suspected node killer: " + f.reason
		}
		state.LogEventDetails(projectPath, state.EventRow{
			Type:    state.EventFailover,
			TaskID:  id,
			Step:    state.NoStep,
			Message: msg,
		}, details)
	}
	switch {
	case ev.Exhausted:
		state.LogEventDetails(projectPath, state.EventRow{
			Type:    state.EventFailover,
			Step:    state.NoStep,
			Message: "run not re-dispatched: " + exhaustedReason(ev, out.Lost),
		}, details)
	case ev.To == "" && ev.Reason != "":
		state.LogEventDetails(projectPath, state.EventRow{
			Type:    state.EventFailover,
			Step:    state.NoStep,
			Message: fmt.Sprintf("executor %s became unreachable and no executor could take its run: %s", ev.From, ev.Reason),
		}, details)
	}
}

// chargedTasks returns the tasks a lost session was running: those the
// session recorded, and those the hub's own plan holds in progress. A task
// that is done, skipped, failed or timed out in the hub's plan is not charged
// — its work ended before the node did.
func chargedTasks(st *state.ProjectState, sess executor.Session) []*pm.Task {
	if st == nil || st.Plan == nil {
		return nil
	}
	want := map[int]bool{}
	if sess.TaskID > 0 {
		want[sess.TaskID] = true
	}
	for _, id := range sess.RunningTasks {
		want[id] = true
	}
	var out []*pm.Task
	for _, t := range st.Plan.Tasks {
		if t == nil {
			continue
		}
		switch t.Status {
		case pm.TaskInProgress:
			out = append(out, t)
		case pm.TaskPending:
			if want[t.ID] {
				out = append(out, t)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// failoverChain returns every node the run behind ev has been lost on, oldest
// first, ending with this one. The chain is read from the control plane's
// session records; when it cannot be, this loss alone is what is known.
func failoverChain(dir string, ev executor.FailoverEvent, this pm.NodeLoss) []pm.NodeLoss {
	sched, db, err := newScheduler(dir)
	if err != nil {
		return []pm.NodeLoss{this}
	}
	defer db.Close()
	lost, err := sched.LostNodes(ev.Session.ID)
	if err != nil || len(lost) == 0 {
		return []pm.NodeLoss{this}
	}
	// The claim's own time stands in for each earlier node; for this one the
	// transition's time is known exactly.
	if last := &lost[len(lost)-1]; last.SessionID == this.SessionID {
		last.LostAt = this.LostAt
	}
	return lost
}

// exhaustedReason is the failure reason of a task whose run used up
// executors.failover.max_attempts: every node the run was lost on, and when.
func exhaustedReason(ev executor.FailoverEvent, lost []pm.NodeLoss) string {
	return fmt.Sprintf("executor failover exhausted: the run was lost on %d node(s) — %s — and "+
		"executors.failover.max_attempts (%d) allows no further re-dispatch",
		len(lost), pm.DescribeNodeLosses(lost), ev.MaxAttempts)
}

// nodeKillerReason is the failure reason of a quarantined task.
func nodeKillerReason(losses []pm.NodeLoss) string {
	return fmt.Sprintf("suspected node killer: %d distinct executors went unreachable while this task "+
		"was running — %s; it runs again only after an explicit reset",
		len(pm.DistinctNodes(losses)), pm.DescribeNodeLosses(losses))
}

// nodeLossDetails renders losses for a journal row's details.
func nodeLossDetails(losses []pm.NodeLoss) []map[string]string {
	out := make([]map[string]string, 0, len(losses))
	for _, l := range losses {
		out = append(out, map[string]string{
			"executor_id":    l.ExecutorID,
			"unreachable_at": l.LostAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// hasProjectDB reports whether dir holds a cloop project database to settle
// tasks in. A failover must never create one: the path came out of a stored
// session, and a session dispatched for a path that no longer holds a project
// has no tasks to mark.
func hasProjectDB(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	_, err := os.Stat(state.DBPath(dir))
	return err == nil
}
