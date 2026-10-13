package statedb

// The database side of approval notifications (Task 20427): the outbox of
// notices the cluster leader has recorded, and how far each webhook has got
// through it. pkg/approvalnotify decides what is worth a notice and sends it;
// this file only remembers what was noticed, once, and refuses to move a
// cursor out of order.
//
// Every write is one statement: a notice insert must not wait behind, or hold
// up, an audit append on the same file, and a compare-and-swap UPDATE is atomic
// on its own.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ApprovalNotice is one row of the outbox.
type ApprovalNotice struct {
	ID        int64
	Key       string
	Event     string
	Payload   string
	CreatedAt time.Time
}

// ApprovalNotifyCursor is where one webhook has got to.
type ApprovalNotifyCursor struct {
	Sink string
	// AckedID is the newest notice the webhook has been handed: delivered,
	// or given up on after its retries and counted in Dropped.
	AckedID   int64
	Delivered int64
	Dropped   int64
	// Failures counts failed sends of the notice after AckedID, and
	// NextAttemptAt is when it may be tried again. Both clear when the
	// cursor moves.
	Failures        int64
	NextAttemptAt   time.Time
	LastError       string
	LastErrorAt     time.Time
	LastDeliveredAt time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ErrApprovalNotifyCursorMoved is returned when a cursor no longer holds the
// position the caller read it at: another leader moved it.
var ErrApprovalNotifyCursorMoved = errors.New("statedb: the approval notification cursor moved")

const approvalCursorColumns = `sink, acked_id, delivered, dropped, failures, next_attempt_at,
	last_error, last_error_at, last_delivered_at, created_at, updated_at`

func formatNoticeTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseNoticeTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// InsertApprovalNotice records a notice unless one with its key exists, and
// reports whether this call recorded it.
func (d *DB) InsertApprovalNotice(key, event, payload string, at time.Time) (bool, error) {
	if key == "" || event == "" {
		return false, fmt.Errorf("statedb approval notices: a notice needs a key and an event")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`INSERT INTO approval_notices (notice_key, event, payload, created_at)
		VALUES (?,?,?,?) ON CONFLICT(notice_key) DO NOTHING`, key, event, payload, formatNoticeTime(at))
	if err != nil {
		return false, fmt.Errorf("statedb approval notices: record %s: %w", key, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb approval notices: record %s: %w", key, classifyDriverErr(err))
	}
	return n > 0, nil
}

// ApprovalNoticeRecorded reports whether a notice with key exists.
func (d *DB) ApprovalNoticeRecorded(key string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var one int
	err := d.conn.QueryRow(`SELECT 1 FROM approval_notices WHERE notice_key = ?`, key).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("statedb approval notices: look up %s: %w", key, classifyDriverErr(err))
	}
	return true, nil
}

// ApprovalNoticesAfter returns up to limit notices with an id above after, in
// id order.
func (d *DB) ApprovalNoticesAfter(after int64, limit int) ([]ApprovalNotice, error) {
	if limit <= 0 {
		limit = 50
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT id, notice_key, event, payload, created_at FROM approval_notices
		WHERE id > ? ORDER BY id LIMIT ?`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb approval notices: list after %d: %w", after, classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ApprovalNotice
	for rows.Next() {
		var (
			n  ApprovalNotice
			at string
		)
		if err := rows.Scan(&n.ID, &n.Key, &n.Event, &n.Payload, &at); err != nil {
			return nil, fmt.Errorf("statedb approval notices: scan: %w", classifyDriverErr(err))
		}
		n.CreatedAt = parseNoticeTime(at)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb approval notices: rows: %w", classifyDriverErr(err))
	}
	return out, nil
}

// MaxApprovalNoticeID returns the newest notice's id, or 0 when there is none
// — including when every notice has been pruned, which is why a new cursor
// also consults the AUTOINCREMENT sequence.
func (d *DB) MaxApprovalNoticeID() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var id sql.NullInt64
	if err := d.conn.QueryRow(`SELECT MAX(id) FROM approval_notices`).Scan(&id); err != nil {
		return 0, fmt.Errorf("statedb approval notices: newest id: %w", classifyDriverErr(err))
	}
	var seq sql.NullInt64
	err := d.conn.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'approval_notices'`).Scan(&seq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("statedb approval notices: sequence: %w", classifyDriverErr(err))
	}
	if seq.Int64 > id.Int64 {
		return seq.Int64, nil
	}
	return id.Int64, nil
}

// PruneApprovalNotices deletes notices recorded before cutoff that no cursor
// still has ahead of it (id at or below floor) and whose key is not in keep,
// and returns how many went. keep names the notices for what is still waiting
// — a pending request's filing and reminder, a waiting token — because their
// rows are what stops the next leader announcing them again.
func (d *DB) PruneApprovalNotices(cutoff time.Time, floor int64, keep map[string]bool) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT id, notice_key FROM approval_notices WHERE created_at < ? AND id <= ?`,
		formatNoticeTime(cutoff), floor)
	if err != nil {
		return 0, fmt.Errorf("statedb approval notices: prune: %w", classifyDriverErr(err))
	}
	var doomed []any
	for rows.Next() {
		var (
			id  int64
			key string
		)
		if err := rows.Scan(&id, &key); err != nil {
			rows.Close()
			return 0, fmt.Errorf("statedb approval notices: prune: %w", classifyDriverErr(err))
		}
		if !keep[key] {
			doomed = append(doomed, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, fmt.Errorf("statedb approval notices: prune: %w", classifyDriverErr(err))
	}
	var total int64
	for len(doomed) > 0 {
		n := min(len(doomed), 500)
		res, err := d.conn.Exec(`DELETE FROM approval_notices WHERE id IN (?`+strings.Repeat(",?", n-1)+`)`, doomed[:n]...)
		if err != nil {
			return total, fmt.Errorf("statedb approval notices: prune: %w", classifyDriverErr(err))
		}
		affected, _ := res.RowsAffected()
		total += affected
		doomed = doomed[n:]
	}
	return total, nil
}

func scanApprovalCursor(row interface{ Scan(...any) error }) (ApprovalNotifyCursor, error) {
	var (
		c                                            ApprovalNotifyCursor
		next, errAt, deliveredAt, created, updatedAt string
	)
	if err := row.Scan(&c.Sink, &c.AckedID, &c.Delivered, &c.Dropped, &c.Failures, &next,
		&c.LastError, &errAt, &deliveredAt, &created, &updatedAt); err != nil {
		return ApprovalNotifyCursor{}, err
	}
	c.NextAttemptAt = parseNoticeTime(next)
	c.LastErrorAt = parseNoticeTime(errAt)
	c.LastDeliveredAt = parseNoticeTime(deliveredAt)
	c.CreatedAt = parseNoticeTime(created)
	c.UpdatedAt = parseNoticeTime(updatedAt)
	return c, nil
}

// ApprovalNotifyCursors returns every webhook's cursor, by name.
func (d *DB) ApprovalNotifyCursors() ([]ApprovalNotifyCursor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + approvalCursorColumns + ` FROM approval_notify_cursors ORDER BY sink`)
	if err != nil {
		return nil, fmt.Errorf("statedb approval notices: list cursors: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ApprovalNotifyCursor
	for rows.Next() {
		c, err := scanApprovalCursor(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb approval notices: scan cursor: %w", classifyDriverErr(err))
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb approval notices: cursor rows: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ApprovalNotifyCursorFor returns one webhook's cursor, and whether it exists.
func (d *DB) ApprovalNotifyCursorFor(sink string) (ApprovalNotifyCursor, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := scanApprovalCursor(d.conn.QueryRow(
		`SELECT `+approvalCursorColumns+` FROM approval_notify_cursors WHERE sink = ?`, sink))
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalNotifyCursor{}, false, nil
	}
	if err != nil {
		return ApprovalNotifyCursor{}, false, fmt.Errorf("statedb approval notices: read cursor %s: %w", sink, classifyDriverErr(err))
	}
	return c, true, nil
}

// InitApprovalNotifyCursor creates sink's cursor at position at unless it
// exists, and returns the cursor as stored: an existing one untouched, so a
// second leader starting the same webhook does not reset a position the first
// has advanced.
func (d *DB) InitApprovalNotifyCursor(sink string, at int64, now time.Time) (ApprovalNotifyCursor, error) {
	if sink == "" {
		return ApprovalNotifyCursor{}, fmt.Errorf("statedb approval notices: a cursor needs a webhook name")
	}
	ts := formatNoticeTime(now)
	d.mu.Lock()
	_, err := d.conn.Exec(`INSERT INTO approval_notify_cursors (sink, acked_id, created_at, updated_at)
		VALUES (?,?,?,?) ON CONFLICT(sink) DO NOTHING`, sink, at, ts, ts)
	d.mu.Unlock()
	if err != nil {
		return ApprovalNotifyCursor{}, fmt.Errorf("statedb approval notices: create cursor %s: %w", sink, classifyDriverErr(err))
	}
	c, ok, err := d.ApprovalNotifyCursorFor(sink)
	if err != nil {
		return ApprovalNotifyCursor{}, err
	}
	if !ok {
		return ApprovalNotifyCursor{}, fmt.Errorf("statedb approval notices: cursor %s vanished after it was written", sink)
	}
	return c, nil
}

// TouchApprovalNotifyCursor records that sink is still configured on the
// member leading: prune forgets only a cursor nobody has touched for a while.
func (d *DB) TouchApprovalNotifyCursor(sink string, now time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE approval_notify_cursors SET updated_at = ? WHERE sink = ?`,
		formatNoticeTime(now), sink); err != nil {
		return fmt.Errorf("statedb approval notices: touch cursor %s: %w", sink, classifyDriverErr(err))
	}
	return nil
}

// DeleteApprovalNotifyCursor forgets a webhook that is no longer configured,
// so one configured again under its name starts at the newest notice rather
// than replaying everything since it was removed.
func (d *DB) DeleteApprovalNotifyCursor(sink string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM approval_notify_cursors WHERE sink = ?`, sink); err != nil {
		return fmt.Errorf("statedb approval notices: delete cursor %s: %w", sink, classifyDriverErr(err))
	}
	return nil
}

// ApprovalNotifyAdvance is one cursor move: from the position the caller read
// to the notice it handed over, delivered or given up on.
type ApprovalNotifyAdvance struct {
	From, To  int64
	Delivered bool
	Dropped   bool
	// Error is kept on a drop: the reason the notice was given up on.
	Error string
	At    time.Time
}

// AdvanceApprovalNotifyCursor moves sink's cursor, returning
// ErrApprovalNotifyCursorMoved when it is no longer at adv.From. The failure
// record clears with the move.
func (d *DB) AdvanceApprovalNotifyCursor(sink string, adv ApprovalNotifyAdvance) error {
	at := formatNoticeTime(adv.At)
	q := `UPDATE approval_notify_cursors SET acked_id = ?, failures = 0, next_attempt_at = '', updated_at = ?`
	args := []any{adv.To, at}
	if adv.Delivered {
		q += `, delivered = delivered + 1, last_delivered_at = ?`
		args = append(args, at)
	}
	if adv.Dropped {
		msg := adv.Error
		if len(msg) > 1024 {
			msg = msg[:1024]
		}
		q += `, dropped = dropped + 1, last_error = ?, last_error_at = ?`
		args = append(args, msg, at)
	}
	q += ` WHERE sink = ? AND acked_id = ?`
	args = append(args, sink, adv.From)
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(q, args...)
	if err != nil {
		return fmt.Errorf("statedb approval notices: advance cursor %s: %w", sink, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrApprovalNotifyCursorMoved
	}
	return nil
}

// NoteApprovalNotifyFailure records a failed send of the notice after at, and
// when to try it again. A cursor that has moved past at is left alone.
func (d *DB) NoteApprovalNotifyFailure(sink string, at int64, message string, next, now time.Time) error {
	if len(message) > 1024 {
		message = message[:1024]
	}
	ts := formatNoticeTime(now)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE approval_notify_cursors SET failures = failures + 1, next_attempt_at = ?,
		last_error = ?, last_error_at = ?, updated_at = ? WHERE sink = ? AND acked_id = ?`,
		formatNoticeTime(next), message, ts, ts, sink, at)
	if err != nil {
		return fmt.Errorf("statedb approval notices: note failure on %s: %w", sink, classifyDriverErr(err))
	}
	return nil
}
