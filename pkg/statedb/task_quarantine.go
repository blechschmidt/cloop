package statedb

// task_quarantine.go stores the evidence executor failover collects against a
// task, and the mark it leaves on a task it suspects of taking nodes down
// (Task 20391). See migrations/0061_failover_cap.sql for the tables, and
// pkg/pm/quarantine.go for what the mark means.
//
// Both tables are written by exactly two parties: the failover that records a
// loss or marks a task, and the explicit reset that clears them. SaveState
// never touches either. That is the property the mark depends on: a running
// orchestrator saves a copy of the plan it loaded before any mark existed, and
// a writer that persisted the in-memory copy would erase a quarantine the
// moment the run next saved — or, from an older copy, write one back after a
// person had cleared it.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Bounds on what a quarantine row carries. Every field is written by the hub
// from executor ids and timestamps, but executor ids come from enrollment and
// configuration, and a mark is loaded with every plan read.
const (
	maxQuarantineNodes  = 32
	maxQuarantineReason = 1024
	maxQuarantineText   = 128
)

// RecordTaskNodeLoss records that loss.ExecutorID went unreachable while task
// taskID was running. Recording the same session twice for one task is a
// no-op: the claim that produces a loss is exactly-once, and a retry of its
// handler must not count one lost node twice.
//
// It reports whether a row was added.
func (d *DB) RecordTaskNodeLoss(taskID int, loss pm.NodeLoss) (bool, error) {
	if taskID <= 0 {
		return false, fmt.Errorf("statedb: record node loss: invalid task id %d", taskID)
	}
	executorID := clipText(strings.TrimSpace(loss.ExecutorID), maxQuarantineText)
	sessionID := clipText(strings.TrimSpace(loss.SessionID), maxQuarantineText)
	if executorID == "" || sessionID == "" {
		return false, fmt.Errorf("statedb: record node loss for task %d: executor and session are required", taskID)
	}
	at := loss.LostAt
	if at.IsZero() {
		at = time.Now()
	}
	attempt := loss.Attempt
	if attempt <= 0 {
		attempt = 1
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`INSERT INTO task_node_losses(task_id, session_id, executor_id, lost_at, attempt)
		 VALUES(?,?,?,?,?)
		 ON CONFLICT(task_id, session_id) DO NOTHING`,
		taskID, sessionID, executorID, at.UTC().Format(time.RFC3339Nano), attempt)
	if err != nil {
		return false, fmt.Errorf("statedb: record node loss for task %d: %w", taskID, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: record node loss for task %d: %w", taskID, classifyDriverErr(err))
	}
	return n > 0, nil
}

// TaskNodeLosses returns the losses recorded against a task since its last
// explicit reset, oldest first.
func (d *DB) TaskNodeLosses(taskID int) ([]pm.NodeLoss, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT executor_id, lost_at, session_id, attempt FROM task_node_losses
		 WHERE task_id = ? ORDER BY lost_at ASC, session_id ASC`, taskID)
	if err != nil {
		return nil, fmt.Errorf("statedb: read node losses of task %d: %w", taskID, classifyDriverErr(err))
	}
	defer rows.Close()
	var out []pm.NodeLoss
	for rows.Next() {
		var (
			l      pm.NodeLoss
			lostAt string
		)
		if err := rows.Scan(&l.ExecutorID, &lostAt, &l.SessionID, &l.Attempt); err != nil {
			return nil, fmt.Errorf("statedb: read node losses of task %d: %w", taskID, classifyDriverErr(err))
		}
		l.LostAt = parseOptionalTime(lostAt)
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read node losses of task %d: %w", taskID, classifyDriverErr(err))
	}
	return out, nil
}

// PutTaskQuarantine marks a task. Marking one that is already marked updates
// the mark in place: the newest evidence names more nodes, never fewer.
func (d *DB) PutTaskQuarantine(taskID int, q pm.TaskQuarantine) error {
	if taskID <= 0 {
		return fmt.Errorf("statedb: quarantine: invalid task id %d", taskID)
	}
	q = boundQuarantine(q)
	if q.Kind == "" {
		q.Kind = pm.QuarantineNodeKiller
	}
	if q.MarkedAt.IsZero() {
		q.MarkedAt = time.Now()
	}
	nodes, err := json.Marshal(q.Nodes)
	if err != nil {
		return fmt.Errorf("statedb: quarantine task %d: encode nodes: %w", taskID, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(
		`INSERT INTO task_quarantine(task_id, kind, reason, nodes_json, marked_at, marked_by)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(task_id) DO UPDATE SET
		   kind = excluded.kind, reason = excluded.reason, nodes_json = excluded.nodes_json,
		   marked_at = excluded.marked_at, marked_by = excluded.marked_by`,
		taskID, q.Kind, q.Reason, string(nodes),
		q.MarkedAt.UTC().Format(time.RFC3339Nano), q.MarkedBy); err != nil {
		return fmt.Errorf("statedb: quarantine task %d: %w", taskID, classifyDriverErr(err))
	}
	return nil
}

// TaskQuarantine returns a task's mark, or nil when it carries none.
func (d *DB) TaskQuarantine(taskID int) (*pm.TaskQuarantine, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var kind, reason, nodes, markedAt, markedBy string
	err := d.conn.QueryRow(
		`SELECT kind, reason, nodes_json, marked_at, marked_by FROM task_quarantine WHERE task_id = ?`,
		taskID).Scan(&kind, &reason, &nodes, &markedAt, &markedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("statedb: read the quarantine of task %d: %w", taskID, classifyDriverErr(err))
	}
	return quarantineFromColumns(kind, reason, nodes, markedAt, markedBy), nil
}

// ListTaskQuarantines returns every marked task's mark, keyed by task id.
func (d *DB) ListTaskQuarantines() (map[int]*pm.TaskQuarantine, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT task_id, kind, reason, nodes_json, marked_at, marked_by FROM task_quarantine ORDER BY task_id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list quarantined tasks: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	out := map[int]*pm.TaskQuarantine{}
	for rows.Next() {
		var (
			id                                      int
			kind, reason, nodes, markedAt, markedBy string
		)
		if err := rows.Scan(&id, &kind, &reason, &nodes, &markedAt, &markedBy); err != nil {
			return nil, fmt.Errorf("statedb: list quarantined tasks: %w", classifyDriverErr(err))
		}
		out[id] = quarantineFromColumns(kind, reason, nodes, markedAt, markedBy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list quarantined tasks: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ClearTaskQuarantine is the explicit reset's half: it removes a task's mark
// and the losses behind it, so the task starts again with no evidence against
// it. It reports whether there was a mark to remove.
//
// The losses go with the mark on purpose. A reset is a person deciding the
// task deserves another chance; keeping its old losses would quarantine it
// again on the first node lost afterwards, which is not another chance. The
// audit trail and the event journal keep the history.
func (d *DB) ClearTaskQuarantine(taskID int) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: release task %d: %w", taskID, classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`DELETE FROM task_quarantine WHERE task_id = ?`, taskID)
	if err != nil {
		return false, fmt.Errorf("statedb: release task %d: %w", taskID, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: release task %d: %w", taskID, classifyDriverErr(err))
	}
	if _, err := tx.Exec(`DELETE FROM task_node_losses WHERE task_id = ?`, taskID); err != nil {
		return false, fmt.Errorf("statedb: release task %d: %w", taskID, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: release task %d: %w", taskID, classifyDriverErr(err))
	}
	return n > 0, nil
}

// quarantineSelect is the correlated subquery taskSelect reads a task's mark
// through: one JSON document, or ” for a task without one. A nodes column
// that is not valid JSON reads as no nodes rather than failing the plan load —
// the mark itself still holds the task back.
const quarantineSelect = `COALESCE((SELECT json_object(
		'kind', q.kind, 'reason', q.reason,
		'nodes', CASE WHEN json_valid(q.nodes_json) THEN json(q.nodes_json) ELSE json('[]') END,
		'marked_at', q.marked_at, 'marked_by', q.marked_by)
		FROM task_quarantine q WHERE q.task_id = plan_tasks.id), '')`

// decodeQuarantine reads quarantineSelect's document. An unreadable one still
// marks the task: a damaged row must fail closed, holding the task back, not
// open.
func decodeQuarantine(doc string) *pm.TaskQuarantine {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var raw struct {
		Kind     string          `json:"kind"`
		Reason   string          `json:"reason"`
		Nodes    json.RawMessage `json:"nodes"`
		MarkedAt string          `json:"marked_at"`
		MarkedBy string          `json:"marked_by"`
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return &pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller, Reason: "the quarantine record is unreadable"}
	}
	return quarantineFromColumns(raw.Kind, raw.Reason, string(raw.Nodes), raw.MarkedAt, raw.MarkedBy)
}

func quarantineFromColumns(kind, reason, nodes, markedAt, markedBy string) *pm.TaskQuarantine {
	q := pm.TaskQuarantine{
		Kind: kind, Reason: reason, MarkedBy: markedBy,
		MarkedAt: parseOptionalTime(markedAt),
	}
	if strings.TrimSpace(nodes) != "" {
		_ = json.Unmarshal([]byte(nodes), &q.Nodes) // damage reads as no nodes; the mark stands
	}
	if q.Kind == "" {
		q.Kind = pm.QuarantineNodeKiller
	}
	q = boundQuarantine(q)
	return &q
}

func boundQuarantine(q pm.TaskQuarantine) pm.TaskQuarantine {
	q.Kind = clipText(strings.TrimSpace(q.Kind), maxQuarantineText)
	q.Reason = clipText(q.Reason, maxQuarantineReason)
	q.MarkedBy = clipText(q.MarkedBy, maxQuarantineText)
	if len(q.Nodes) > maxQuarantineNodes {
		q.Nodes = q.Nodes[len(q.Nodes)-maxQuarantineNodes:]
	}
	nodes := make([]pm.NodeLoss, 0, len(q.Nodes))
	for _, n := range q.Nodes {
		n.ExecutorID = clipText(n.ExecutorID, maxQuarantineText)
		n.SessionID = clipText(n.SessionID, maxQuarantineText)
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		nodes = nil
	}
	q.Nodes = nodes
	return q
}

// clipText keeps at most n bytes of s, cut at a rune boundary.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

// QuarantinedTask is one marked task as PeekTaskQuarantines reads it.
type QuarantinedTask struct {
	TaskID int
	Title  string
	Status string
	Mark   pm.TaskQuarantine
}

// PeekTaskQuarantines lists the marked tasks in the project database at
// dbPath without migrating or writing it: a read-only connection, for code
// that surveys many projects from outside them, such as
// `cloop executor list --inventory`. A database that predates the table has
// none.
func PeekTaskQuarantines(dbPath string) ([]QuarantinedTask, error) {
	conn, err := OpenConn(dbPath, ReadOnly)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.Query(
		`SELECT q.task_id, COALESCE(t.title, ''), COALESCE(t.status, ''),
		        q.kind, q.reason, q.nodes_json, q.marked_at, q.marked_by
		 FROM task_quarantine q LEFT JOIN plan_tasks t ON t.id = q.task_id
		 ORDER BY q.task_id`)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, fmt.Errorf("statedb: list quarantined tasks in %s: %w", dbPath, classifyDriverErr(err))
	}
	defer rows.Close()
	var out []QuarantinedTask
	for rows.Next() {
		var (
			q                                       QuarantinedTask
			kind, reason, nodes, markedAt, markedBy string
		)
		if err := rows.Scan(&q.TaskID, &q.Title, &q.Status, &kind, &reason, &nodes, &markedAt, &markedBy); err != nil {
			return nil, fmt.Errorf("statedb: list quarantined tasks in %s: %w", dbPath, classifyDriverErr(err))
		}
		q.Mark = *quarantineFromColumns(kind, reason, nodes, markedAt, markedBy)
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list quarantined tasks in %s: %w", dbPath, classifyDriverErr(err))
	}
	return out, nil
}
