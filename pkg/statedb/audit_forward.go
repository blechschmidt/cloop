package statedb

// The database side of audit forwarding (Task 20426): the per-sink, per-chain
// cursors the cluster leader advances as sinks acknowledge rows, and the
// retention floor they impose. pkg/auditforward decides what to send and when;
// this file only remembers how far each sink has got, and refuses to forget it
// out of order.
//
// Every write is one statement, not a transaction: a cursor advance must not
// wait behind, or hold up, an audit append on the same file, and a
// compare-and-swap UPDATE is atomic on its own.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"time"
)

// AuditForwardMark is one acknowledged point of a chain: a row id and the
// row_hash the sink was sent for it.
type AuditForwardMark struct {
	ID   int64  `json:"id"`
	Hash string `json:"hash"`
}

// AuditForwardCursor is where one sink has got to in one chain.
type AuditForwardCursor struct {
	Sink   string
	Chain  string // absolute database path
	Source string // control-plane | project
	Dir    string

	// AckedID and AckedHash are the newest row the sink acknowledged; 0 and
	// the predecessor's hash before it has acknowledged any. AckedRowAt is
	// that row's timestamp, AckedAt when the sink acknowledged it.
	AckedID    int64
	AckedHash  string
	AckedRowAt time.Time
	AckedAt    time.Time

	// Delivered counts rows acknowledged over the cursor's life.
	Delivered int64

	// Marks are older acknowledged points, newest last.
	Marks []AuditForwardMark

	LastError   string
	LastErrorAt time.Time
	Failures    int64

	CreatedAt time.Time
	UpdatedAt time.Time
	// RetiredAt is set while the sink is not configured or the chain not
	// served.
	RetiredAt time.Time
}

// Retired reports whether the cursor is out of service.
func (c AuditForwardCursor) Retired() bool { return !c.RetiredAt.IsZero() }

// ErrAuditForwardCursorMoved is returned by AdvanceAuditForwardCursor when the
// cursor no longer holds the position the caller read it at: another leader
// moved it, which makes this caller's batch a duplicate the sink can identify
// by row_hash.
var ErrAuditForwardCursorMoved = errors.New("statedb: the audit forward cursor moved")

// ErrAuditForwardCursorMissing is returned by AdvanceAuditForwardCursor when
// the cursor's row is gone — deleted, or a control plane restored from before
// it existed. The caller creates it again.
var ErrAuditForwardCursorMissing = errors.New("statedb: the audit forward cursor does not exist")

const auditForwardColumns = `sink, chain, source, dir, acked_id, acked_hash,
	acked_row_at, acked_at, delivered, marks, last_error, last_error_at,
	failures, created_at, updated_at, retired_at`

func scanAuditForwardCursor(sc interface{ Scan(...any) error }) (AuditForwardCursor, error) {
	var (
		c                                   AuditForwardCursor
		rowAt, ackedAt, errAt, created, upd string
		retired, marks                      string
	)
	if err := sc.Scan(&c.Sink, &c.Chain, &c.Source, &c.Dir, &c.AckedID, &c.AckedHash,
		&rowAt, &ackedAt, &c.Delivered, &marks, &c.LastError, &errAt,
		&c.Failures, &created, &upd, &retired); err != nil {
		return AuditForwardCursor{}, err
	}
	c.AckedRowAt = parseForwardTime(rowAt)
	c.AckedAt = parseForwardTime(ackedAt)
	c.LastErrorAt = parseForwardTime(errAt)
	c.CreatedAt = parseForwardTime(created)
	c.UpdatedAt = parseForwardTime(upd)
	c.RetiredAt = parseForwardTime(retired)
	if strings.TrimSpace(marks) != "" {
		// A mark list that does not decode is a resume hint lost, not a
		// cursor lost: the cursor itself is in its own columns.
		_ = json.Unmarshal([]byte(marks), &c.Marks)
	}
	return c, nil
}

func parseForwardTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func formatForwardTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// AuditForwardCursors returns every cursor, retired ones included, ordered by
// sink and chain.
func (d *DB) AuditForwardCursors() ([]AuditForwardCursor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + auditForwardColumns + ` FROM audit_forward_cursors ORDER BY sink, chain`)
	if err != nil {
		return nil, fmt.Errorf("statedb audit forward: list cursors: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []AuditForwardCursor
	for rows.Next() {
		c, err := scanAuditForwardCursor(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb audit forward: scan cursor: %w", classifyDriverErr(err))
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb audit forward: cursor rows: %w", classifyDriverErr(err))
	}
	return out, nil
}

// AuditForwardCursorFor returns one cursor, and whether it exists.
func (d *DB) AuditForwardCursorFor(sink, chain string) (AuditForwardCursor, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := scanAuditForwardCursor(d.conn.QueryRow(
		`SELECT `+auditForwardColumns+` FROM audit_forward_cursors WHERE sink = ? AND chain = ?`, sink, chain))
	if errors.Is(err, sql.ErrNoRows) {
		return AuditForwardCursor{}, false, nil
	}
	if err != nil {
		return AuditForwardCursor{}, false, fmt.Errorf("statedb audit forward: read cursor %s/%s: %w", sink, chain, classifyDriverErr(err))
	}
	return c, true, nil
}

// InitAuditForwardCursor creates the cursor for (c.Sink, c.Chain) at c's
// position unless one exists, and returns the cursor as stored: the existing
// one, untouched, when there was one — a second leader starting the same sink
// must not reset a position the first has advanced — and returned in service
// either way.
func (d *DB) InitAuditForwardCursor(c AuditForwardCursor, now time.Time) (AuditForwardCursor, error) {
	if c.Sink == "" || c.Chain == "" {
		return AuditForwardCursor{}, fmt.Errorf("statedb audit forward: a cursor needs a sink and a chain")
	}
	ts := formatForwardTime(now)
	d.mu.Lock()
	_, err := d.conn.Exec(`INSERT INTO audit_forward_cursors
		(sink, chain, source, dir, acked_id, acked_hash, acked_row_at, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(sink, chain) DO UPDATE SET retired_at = '', source = excluded.source,
			dir = excluded.dir, updated_at = excluded.updated_at
		WHERE audit_forward_cursors.retired_at != '' OR audit_forward_cursors.source != excluded.source
			OR audit_forward_cursors.dir != excluded.dir`,
		c.Sink, c.Chain, c.Source, c.Dir, c.AckedID, c.AckedHash, formatForwardTime(c.AckedRowAt), ts, ts)
	d.mu.Unlock()
	if err != nil {
		return AuditForwardCursor{}, fmt.Errorf("statedb audit forward: create cursor %s/%s: %w", c.Sink, c.Chain, classifyDriverErr(err))
	}
	got, ok, err := d.AuditForwardCursorFor(c.Sink, c.Chain)
	if err != nil {
		return AuditForwardCursor{}, err
	}
	if !ok {
		return AuditForwardCursor{}, fmt.Errorf("statedb audit forward: cursor %s/%s vanished after it was written", c.Sink, c.Chain)
	}
	return got, nil
}

// AuditForwardAdvance is a cursor move.
type AuditForwardAdvance struct {
	// FromID and FromHash are the position the caller read the cursor at.
	FromID   int64
	FromHash string
	// ToID, ToHash and ToRowAt are the new position.
	ToID    int64
	ToHash  string
	ToRowAt time.Time
	// Delivered is how many rows the move acknowledges; zero for a reposition
	// that skips or rewinds without a delivery.
	Delivered int64
	// At is when the sink acknowledged. A reposition with nothing delivered
	// leaves acked_at as it was.
	At time.Time
}

// AdvanceAuditForwardCursor moves a cursor from the position the caller read
// to a new one, returning ErrAuditForwardCursorMoved when it is no longer at
// the old position. An acknowledgement clears the failure record and records
// the old position among the marks.
func (d *DB) AdvanceAuditForwardCursor(sink, chain string, adv AuditForwardAdvance) error {
	cur, ok, err := d.AuditForwardCursorFor(sink, chain)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s/%s", ErrAuditForwardCursorMissing, sink, chain)
	}
	if cur.AckedID != adv.FromID || cur.AckedHash != adv.FromHash {
		return ErrAuditForwardCursorMoved
	}
	marks := cur.Marks
	if adv.FromID > 0 && adv.FromHash != "" && adv.ToID > adv.FromID {
		marks = append(append([]AuditForwardMark(nil), marks...), AuditForwardMark{ID: adv.FromID, Hash: adv.FromHash})
	}
	marks = ThinAuditForwardMarks(marks, adv.ToID)
	encoded := ""
	if len(marks) > 0 {
		b, err := json.Marshal(marks)
		if err != nil {
			return fmt.Errorf("statedb audit forward: encode marks: %w", err)
		}
		encoded = string(b)
	}
	now := formatForwardTime(time.Now())
	ackedAt := formatForwardTime(adv.At)

	d.mu.Lock()
	defer d.mu.Unlock()
	q := `UPDATE audit_forward_cursors SET acked_id = ?, acked_hash = ?, acked_row_at = ?,
			delivered = delivered + ?, marks = ?, updated_at = ?`
	args := []any{adv.ToID, adv.ToHash, formatForwardTime(adv.ToRowAt), adv.Delivered, encoded, now}
	if adv.Delivered > 0 {
		q += `, acked_at = ?, last_error = '', last_error_at = '', failures = 0`
		args = append(args, ackedAt)
	}
	q += ` WHERE sink = ? AND chain = ? AND acked_id = ? AND acked_hash = ?`
	args = append(args, sink, chain, adv.FromID, adv.FromHash)
	res, err := d.conn.Exec(q, args...)
	if err != nil {
		return fmt.Errorf("statedb audit forward: advance cursor %s/%s: %w", sink, chain, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrAuditForwardCursorMoved
	}
	return nil
}

// NoteAuditForwardFailure records a failed send on a cursor.
func (d *DB) NoteAuditForwardFailure(sink, chain, message string, at time.Time) error {
	if len(message) > 1024 {
		message = message[:1024]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE audit_forward_cursors SET last_error = ?, last_error_at = ?,
		failures = failures + 1, updated_at = ? WHERE sink = ? AND chain = ?`,
		message, formatForwardTime(at), formatForwardTime(at), sink, chain)
	if err != nil {
		return fmt.Errorf("statedb audit forward: note failure on %s/%s: %w", sink, chain, classifyDriverErr(err))
	}
	return nil
}

// AuditForwardKey names one cursor.
type AuditForwardKey struct {
	Sink  string
	Chain string
}

// SyncAuditForwardCursors brings the cursors' service state in line with
// live, the (sink, chain) pairs being forwarded: a cursor not in live is
// retired, so it stops holding retention, and a retired one in live is
// returned to service, whatever any forwarder remembers. It writes only what
// differs, so calling it on every pass costs a read.
func (d *DB) SyncAuditForwardCursors(live []AuditForwardKey, at time.Time) (retired, restored int, err error) {
	keep := make(map[AuditForwardKey]bool, len(live))
	for _, k := range live {
		keep[k] = true
	}
	all, err := d.AuditForwardCursors()
	if err != nil {
		return 0, 0, err
	}
	ts := formatForwardTime(at)
	for _, c := range all {
		inLive := keep[AuditForwardKey{Sink: c.Sink, Chain: c.Chain}]
		var q string
		switch {
		case inLive && c.Retired():
			q = `UPDATE audit_forward_cursors SET retired_at = '', updated_at = ?
				WHERE sink = ? AND chain = ? AND retired_at != ''`
			restored++
		case !inLive && !c.Retired():
			q = `UPDATE audit_forward_cursors SET retired_at = ?, updated_at = ?
				WHERE sink = ? AND chain = ? AND retired_at = ''`
			retired++
		default:
			continue
		}
		args := []any{ts, c.Sink, c.Chain}
		if !inLive {
			args = []any{ts, ts, c.Sink, c.Chain}
		}
		d.mu.Lock()
		_, err := d.conn.Exec(q, args...)
		d.mu.Unlock()
		if err != nil {
			return retired, restored, fmt.Errorf("statedb audit forward: sync %s/%s: %w", c.Sink, c.Chain, classifyDriverErr(err))
		}
	}
	return retired, restored, nil
}

// AuditForwardHold is the lowest acknowledged position of the live cursors on
// one chain: the newest row retention may remove without destroying a row a
// configured sink has not acknowledged.
type AuditForwardHold struct {
	// ThroughID is the lowest acked_id; rows above it have not reached Sink.
	ThroughID int64
	// Sink is the cursor holding it — the slowest sink.
	Sink string
	// Sinks is every live cursor on the chain, by sink, with its position.
	Sinks map[string]int64
}

// AuditForwardHoldFor returns the hold the live cursors put on chain, and
// whether there is one: a chain no live cursor names is not being forwarded.
func (d *DB) AuditForwardHoldFor(chain string) (AuditForwardHold, bool, error) {
	all, err := d.AuditForwardCursors()
	if err != nil {
		return AuditForwardHold{}, false, err
	}
	var (
		h     AuditForwardHold
		found bool
	)
	for _, c := range all {
		if c.Chain != chain || c.Retired() {
			continue
		}
		if h.Sinks == nil {
			h.Sinks = map[string]int64{}
		}
		h.Sinks[c.Sink] = c.AckedID
		if !found || c.AckedID < h.ThroughID || (c.AckedID == h.ThroughID && c.Sink < h.Sink) {
			h.ThroughID, h.Sink, found = c.AckedID, c.Sink, true
		}
	}
	return h, found, nil
}

// auditForwardMarksKeepNewest is how many of the newest marks survive
// thinning whatever their spacing; auditForwardMarksMax bounds the list.
const (
	auditForwardMarksKeepNewest = 4
	auditForwardMarksMax        = 48
)

// ThinAuditForwardMarks keeps the newest few marks below head and, of the
// older ones, the newest in each power-of-two band of distance from head — so
// a list of a few dozen points reaches back across millions of rows, densest
// where a resume is most likely to land. Marks at or above head are dropped:
// they describe positions the cursor has not passed.
func ThinAuditForwardMarks(marks []AuditForwardMark, head int64) []AuditForwardMark {
	in := make([]AuditForwardMark, 0, len(marks))
	for _, m := range marks {
		if m.ID > 0 && m.ID < head && m.Hash != "" {
			in = append(in, m)
		}
	}
	sort.SliceStable(in, func(i, j int) bool { return in[i].ID < in[j].ID })
	// One mark per id: the newest written wins, which after the sort is the
	// last of a run.
	dedup := in[:0]
	for i, m := range in {
		if i+1 < len(in) && in[i+1].ID == m.ID {
			continue
		}
		dedup = append(dedup, m)
	}
	in = dedup
	if len(in) <= auditForwardMarksKeepNewest {
		return in
	}
	keep := make([]bool, len(in))
	for i := len(in) - auditForwardMarksKeepNewest; i < len(in); i++ {
		keep[i] = true
	}
	bands := map[int]bool{}
	for i := len(in) - auditForwardMarksKeepNewest - 1; i >= 0; i-- {
		band := bits.Len64(uint64(head - in[i].ID))
		if bands[band] {
			continue
		}
		bands[band] = true
		keep[i] = true
	}
	out := make([]AuditForwardMark, 0, len(in))
	for i, m := range in {
		if keep[i] {
			out = append(out, m)
		}
	}
	if len(out) > auditForwardMarksMax {
		out = out[len(out)-auditForwardMarksMax:]
	}
	return out
}

// ReadAuditRowAfter returns, through a bare connection, the oldest row with an
// id above afterID, and whether there is one: the next row a sink that
// acknowledged afterID has to receive. A database that predates the audit
// table has none.
func ReadAuditRowAfter(conn *sql.DB, afterID int64) (AuditEvent, bool, error) {
	if ok, err := tableExists(conn, "audit_events"); err != nil || !ok {
		return AuditEvent{}, false, err
	}
	var (
		ev AuditEvent
		ts string
	)
	err := conn.QueryRow(
		`SELECT id, timestamp, actor, event_type, entity_type, entity_id,
				payload, prev_hash, row_hash
		 FROM audit_events WHERE id > ? ORDER BY id ASC LIMIT 1`, afterID,
	).Scan(&ev.ID, &ts, &ev.Actor, &ev.EventType, &ev.EntityType, &ev.EntityID,
		&ev.Payload, &ev.PrevHash, &ev.RowHash)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditEvent{}, false, nil
	}
	if err != nil {
		return AuditEvent{}, false, fmt.Errorf("statedb audit forward: read the row after %d: %w", afterID, classifyDriverErr(err))
	}
	ev.Timestamp = parseForwardTime(ts)
	return ev, true, nil
}

// ReadAuditForwardCursors returns every cursor through a bare connection — a
// read-only one, for a diagnostic that must not migrate or create the control
// plane. A database that predates the table has none.
func ReadAuditForwardCursors(conn *sql.DB) ([]AuditForwardCursor, error) {
	if ok, err := tableExists(conn, "audit_forward_cursors"); err != nil || !ok {
		return nil, err
	}
	rows, err := conn.Query(`SELECT ` + auditForwardColumns + ` FROM audit_forward_cursors ORDER BY sink, chain`)
	if err != nil {
		return nil, fmt.Errorf("statedb audit forward: list cursors: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []AuditForwardCursor
	for rows.Next() {
		c, err := scanAuditForwardCursor(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb audit forward: scan cursor: %w", classifyDriverErr(err))
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
