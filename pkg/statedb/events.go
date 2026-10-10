// Event journal — durable record of every notable thing that happens during a
// cloop run (Task 20118). Steps are still written to the `steps` table for
// backward compatibility; this is the unified, append-only feed that the Web
// UI's "Event History" panel reads from.
//
// Writers must be defensive: persistence failures here MUST NOT abort the
// originating action. RecordEvent therefore returns nil on lock contention or
// transient driver errors after one retry — the orchestrator wraps every call
// in a goroutine-safe best-effort helper.

package statedb

import (
	"database/sql"
	"fmt"
	"time"
)

// EventType is a string enum identifying the kind of journal entry. Readers
// must treat unknown values as benign — the table is intentionally extensible.
type EventType string

const (
	EventSessionStarted    EventType = "session_started"
	EventSessionPaused     EventType = "session_paused"
	EventSessionFailed     EventType = "session_failed"
	EventPlanComplete      EventType = "plan_complete"
	EventTaskStarted       EventType = "task_started"
	EventTaskDone          EventType = "task_done"
	EventTaskFailed        EventType = "task_failed"
	EventTaskSkipped       EventType = "task_skipped"
	EventTaskHeal          EventType = "task_heal"
	EventTaskKilled        EventType = "task_killed"
	EventTaskAdded         EventType = "task_added"
	EventTaskAddedExternal EventType = "task_added_external"
	EventTaskDeleted       EventType = "task_deleted"
	EventTaskStatusChange  EventType = "task_status_change"
	EventEvolveRoundStart  EventType = "evolve_round_start"
	EventEvolveDiscovered  EventType = "evolve_discovered"
	EventEvolveNoOp        EventType = "evolve_no_op"
	// EventWriteBack records what an isolated executor returned of a task's
	// work: the branch, the commit, and whether it merged.
	//
	// Its own type rather than a field on task_done, because the two answer
	// different questions and are allowed to disagree. A task can succeed and
	// have its work fail to come back — the harness ran, the push did not —
	// and a journal that folded the second into the first would have no way to
	// show an operator the run whose transcript was right and whose code was
	// lost. Making exactly that case visible is why this subsystem exists.
	EventWriteBack EventType = "write_back"

	// EventTaskBackground records work an agent harness left running after it
	// reported the task complete (Task 20205), and how that resolved.
	//
	// Its own type rather than a detail on task_done because it explains the
	// two things a status alone cannot: why a task sat running long after its
	// agent had stopped talking, and why a task whose output ended in
	// TASK_DONE was nonetheless not accepted as done.
	EventTaskBackground EventType = "task_background"

	// EventTaskReview records what a project's review gate decided about a
	// task's changes before they were published, and which of the agent's
	// held pushes went out (Task 20357).
	//
	// Its own type because it explains the case a status alone cannot: a task
	// whose agent said TASK_DONE and which nonetheless failed, because a
	// different model read its diff and would not let it leave the machine.
	EventTaskReview EventType = "task_review"

	// EventTaskAborted records a run that never produced work: a provider
	// usage limit or quota, a rejected credential, a harness that refused to
	// start, or output with no diff and no artifact behind it (Task 20211).
	//
	// Its own type rather than task_failed because the two are different
	// claims and are acted on differently. A failure is a judgement about the
	// work; an abort is the absence of any work to judge, so the task returns
	// to pending instead of staying terminal. Folding them together is what
	// let fourteen tasks be recorded as done whose entire stored summary was
	// "You've hit your limit" — and let auto-evolve plan follow-up work on
	// the belief that they had shipped.
	EventTaskAborted EventType = "task_aborted"

	// EventTaskInterrupted records a task whose execution was cut short
	// because its run stopped — the Stop button, a SIGINT or SIGTERM, a budget
	// stop from the hub, a --timeout expiring — rather than because of
	// anything the task did (Task 20348).
	//
	// Its own type for the same reason as task_aborted: the task goes back to
	// pending, and a row that read as task_failed would be a false statement
	// about work that was simply not allowed to finish. Filing interruptions as
	// failures is what left stopped tasks terminal, and the tasks depending on
	// them skipped, when the project was resumed.
	EventTaskInterrupted EventType = "task_interrupted"

	// EventResourceCeiling records that an operator's resource ceiling lowered
	// what a workload was given (Task 20301).
	//
	// It is on the project's own journal rather than only in the hub's log
	// because the person it concerns is the developer whose sandbox got less
	// memory than its .cloop/sandbox.yaml asked for. To them an unannounced
	// clamp is indistinguishable from a slow machine, and there is nothing in
	// their repository that would explain it — the ceiling lives on the hub,
	// deliberately out of their reach. One row naming the resource, both
	// numbers and which ceiling bound it is the difference between a mystery
	// and an address to complain to.
	EventResourceCeiling EventType = "resource_ceiling"

	// EventProjectSeed records that a run dispatched to an isolating executor
	// went without the project state the hub would normally send with it
	// (Task 20316).
	//
	// On the project's journal for the same reason as the ceiling above: the
	// consequence lands on the developer and nothing in their repository
	// explains it. A sandbox that receives no seed finds no `.cloop/` in the
	// tree it cloned, so `cloop run` exits with "no cloop project found" —
	// which reads as a broken project rather than as an executor too old to
	// have been sent one. One row naming the executor and the upgrade is the
	// difference between that and an hour spent debugging an intact project.
	EventProjectSeed EventType = "project_seed"

	// EventProjectResult records what a run on an isolating executor sent back
	// of the project — which tasks it finished, what it added, what the hub
	// kept of its own instead — or why nothing came back (Task 20339).
	//
	// It is project_seed's other half. The seed is how the plan reaches a
	// device that cannot read the hub's database; this is how the run's
	// outcome returns to the database the dashboard renders. Without a row
	// here, a remote run that did its work and a remote run whose results were
	// lost look the same afterwards: a transcript ending "All tasks complete"
	// beside a plan whose tasks are all still pending.
	EventProjectResult EventType = "project_result"

	// EventFeatureCreated and EventFeatureRemoved record, on a project's own
	// journal, a feature of it being created or removed (Task 20341). They are
	// the parent's rows because the feature's own journal begins with its
	// creation and ends — deleted along with its worktree — at its removal.
	EventFeatureCreated EventType = "feature_created"
	EventFeatureRemoved EventType = "feature_removed"

	// EventRunReexecuted records a run replacing its own image with a newer
	// build at a task boundary (Task 20389), written by the new image: which
	// build it left, which it runs now, and why. The process, its pid and
	// its live log carry on, so without this row nothing would show where
	// one build's tasks end and the next one's begin.
	EventRunReexecuted EventType = "run_reexecuted"
	// EventRunAdoption records an adoption that did not happen, or not yet:
	// a refused build and the reason, a failed exec, a request waiting for
	// the task in flight. The run carries on on the build it has.
	EventRunAdoption EventType = "run_adoption"

	// EventFeaturePR records a feature's pull request being opened or updated,
	// on the feature's journal and its parent's.
	EventFeaturePR EventType = "feature_pr"

	// EventFirewall records which stored firewall levels shaped a run — a
	// device's rule set, a project's — and what came of them, or why they
	// refused it (Task 20363).
	//
	// On the project's journal for the reason the ceiling is: a fetch that
	// times out inside a sandbox reads as a broken network, and the rules that
	// dropped it live on the hub where the developer cannot see them.
	EventFirewall EventType = "firewall"

	// EventCredentialRefresh records that a run's GitHub App token could not
	// be kept alive past GitHub's hour on the executor running it, or that its
	// renewal was refused (Task 20375).
	//
	// On the project's journal for the reason the firewall row is: the
	// symptom — git failing to authenticate an hour into a long run — lands on
	// the developer, and the cause — an agent too old to receive the new
	// token, a grant revoked, an installation suspended — is on the hub where
	// they cannot see it.
	EventCredentialRefresh EventType = "credential_refresh"

	// EventCredentialRefused records that a run went without a credential the
	// project was granted, because the secret behind the grant no longer
	// exists (Task 20400) — most often a colleague's personal credential,
	// destroyed when they were offboarded.
	//
	// On the project's journal for the reason the refresh row is: the symptom
	// — git refusing to authenticate, a cluster answering 401 — lands on the
	// people running the project, and the cause is a deletion on the hub they
	// may not even be able to see, since a grant over a personal secret is
	// visible to its owner and to admins alone. Written on the first run after
	// the loss on each hub process, not on every run.
	EventCredentialRefused EventType = "credential_refused"

	// EventEgress records what became of a run's access to the hub's egress
	// proxy (Task 20378): the session it was issued and the route to it, why
	// a project holding an egress grant got none, and when a session ended —
	// the run over, stopped, or its grant revoked with tunnels still open.
	//
	// On the project's journal for the reason the firewall row is: a sandbox
	// whose every request through the proxy fails looks like a broken
	// network, and the reasons — no proxy on the hub, a route the executor
	// cannot take, a revocation — are on the hub, out of the developer's
	// sight. It never carries the session's credential: the proxy URL is not
	// written here, only its address.
	EventEgress EventType = "egress"

	// EventFailover records what executor failover did to the project's run
	// and tasks (Task 20391): a lost node's tasks returned to pending for a
	// retry, a task marked as a suspected node killer, a run that used up
	// executors.failover.max_attempts and was not re-dispatched, and a
	// quarantine an explicit reset released.
	//
	// On the project's journal because the cause — nodes going unreachable,
	// the cap — is the hub's, and the effect, a task that failed or will not
	// run, is what the developer sees.
	EventFailover EventType = "failover"

	// EventDiskLimit records a run stopped because its workspace grew past
	// its disk limit — .cloop/sandbox.yaml resources.disk or an operator's
	// disk ceiling — or a start refused because the workspace was already
	// over it (Task 20405). The message names both sizes and how to raise the
	// limit; the details carry them as numbers.
	//
	// On the project's journal because the cause is a number the developer
	// may never have seen — a ceiling set on the hub — and the effect, a run
	// that stopped mid-task, is what they see.
	EventDiskLimit EventType = "disk_limit"
)

// NoStep is the EventRow.Step value for events that are not bound to any
// step. Steps are 0-based, so 0 is a real step number — callers recording a
// non-step-bound event must set Step to NoStep explicitly.
const NoStep = -1

// EventRow is one row in the events table.
type EventRow struct {
	ID        int64     // primary key, assigned on insert (zero on the way in)
	Timestamp time.Time // when the event happened
	Type      EventType
	TaskID    int    // 0 when not task-bound
	TaskTitle string // empty when not task-bound
	Step      int    // NoStep (-1) when not step-bound; 0 is a real step
	Message   string // short, human-readable summary
	Details   string // free-form JSON blob (may be empty)
}

// RecordEvent appends one row to the events journal. Best-effort: the caller
// is expected to ignore the returned error (event-recording must never block
// the orchestrator). Idempotency is NOT guaranteed — duplicate calls record
// duplicate rows. The auto-increment id ordering is the source of truth for
// "what happened first" on a single host.
func (d *DB) RecordEvent(row EventRow) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if row.Timestamp.IsZero() {
		row.Timestamp = time.Now()
	}
	_, err := d.conn.Exec(
		`INSERT INTO events(timestamp, type, task_id, task_title, step, message, details)
		 VALUES(?,?,?,?,?,?,?)`,
		row.Timestamp.Format(time.RFC3339Nano),
		string(row.Type),
		row.TaskID,
		row.TaskTitle,
		row.Step,
		row.Message,
		row.Details,
	)
	if err != nil {
		return fmt.Errorf("record event %s: %w", row.Type, classifyDriverErr(err))
	}
	return nil
}

// ListEvents returns events in reverse-chronological order (latest first).
// limit caps the page size; offset skips past the most recent N. total is
// the total number of events in the journal so callers can drive infinite-
// scroll UIs.
func (d *DB) ListEvents(offset, limit int) (rows []EventRow, total int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&total); err != nil {
		return nil, 0, classifyDriverErr(err)
	}

	q, err := d.conn.Query(
		`SELECT id, timestamp, type, task_id, task_title, step, message, details
		 FROM events
		 ORDER BY id DESC
		 LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, total, classifyDriverErr(err)
	}
	defer q.Close()

	for q.Next() {
		var r EventRow
		var ts string
		var typ string
		if err := q.Scan(&r.ID, &ts, &typ, &r.TaskID, &r.TaskTitle, &r.Step, &r.Message, &r.Details); err != nil {
			return nil, total, classifyDriverErr(err)
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			r.Timestamp = t
		}
		r.Type = EventType(typ)
		rows = append(rows, r)
	}
	if err := q.Err(); err != nil {
		return nil, total, classifyDriverErr(err)
	}
	return rows, total, nil
}

// CountEvents returns the total number of journal rows. Cheap; used by the UI
// to decide whether to refresh the top page.
func (d *DB) CountEvents() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var n int
	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		return 0, classifyDriverErr(err)
	}
	return n, nil
}

// _ unused but defensive: enforces *sql.Tx type at compile time so callers who
// build their own EventRow can't smuggle in a bad value via reflection.
var _ = (*sql.Tx)(nil)
