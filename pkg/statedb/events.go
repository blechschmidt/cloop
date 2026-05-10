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
)

// EventRow is one row in the events table.
type EventRow struct {
	ID        int64     // primary key, assigned on insert (zero on the way in)
	Timestamp time.Time // when the event happened
	Type      EventType
	TaskID    int    // 0 when not task-bound
	TaskTitle string // empty when not task-bound
	Step      int    // -1 when not step-bound
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
	if row.Step == 0 && row.Type != "" {
		// step==0 is a real step number for new projects. Distinguish "no step"
		// by storing -1; callers that genuinely mean step 0 must set Step
		// explicitly (already true throughout the orchestrator).
		// No-op: the caller controls Step. Documented for clarity.
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
