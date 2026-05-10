// Audit event log — append-only, hash-chained record of every state mutation
// (Task 20119). Provides forensic traceability: who changed what, when, and
// in what order; with tamper detection via SHA-256 chain verification, and a
// replay capability that rebuilds a database from the journal alone.
//
// Distinct from `events` (Task 20118), which is a UI-friendly journal of
// noteworthy run events. `audit_events` is the *legal record*: one row per
// mutation, with a chained hash so any insert/edit/delete in the table
// post-hoc is detectable. Writers must hold the DB mutex for the duration
// of an Append so the hash chain stays consistent under concurrent calls.
//
// Best-effort write semantics: callers in mutation hot paths swallow errors
// (audit failures must not block user work). The verify command surfaces
// lost-row gaps as a hash break; that's the explicit cost of best-effort.

package statedb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditEvent is one row in the audit_events table.
type AuditEvent struct {
	ID         int64     // monotonic primary key, assigned on append
	Timestamp  time.Time // UTC
	Actor      string    // "system", "orchestrator", "ui", "cli", or user-supplied
	EventType  string    // e.g. "task.create", "plan.update", "config.set"
	EntityType string    // "task" | "plan" | "config" | "step" | "session"
	EntityID   string    // stringified id ("12" for task 12), empty for singletons
	Payload    string    // JSON blob describing the mutation
	PrevHash   string    // 64-hex SHA-256 of prior row, or 64 zeros for the first row
	RowHash    string    // 64-hex SHA-256 of this row
}

// genesisHash is the prev_hash of the very first row in the chain. Using a
// constant string of 64 zeros makes "no predecessor" explicit and visually
// distinct from a corrupted hash, and lets the verifier treat all rows
// uniformly.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AppendAuditEvent appends one row to the audit_events table, computing the
// hash chain link from the previous row. Holds the DB mutex so the chain is
// consistent under concurrent writers in the same process. Cross-process
// safety is provided by SQLite WAL + busy_timeout — concurrent writers
// serialise at the file level.
//
// Mutates ev in place: the assigned ID, computed hashes, and any
// auto-populated fields (Timestamp, Actor) are written back so callers can
// inspect them.
func (d *DB) AppendAuditEvent(ev *AuditEvent) error {
	if ev == nil {
		return fmt.Errorf("statedb audit: nil event")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	} else {
		ev.Timestamp = ev.Timestamp.UTC()
	}
	if ev.Actor == "" {
		ev.Actor = "system"
	}
	if ev.EventType == "" {
		return fmt.Errorf("statedb audit: empty event_type")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb audit: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	// Read the current chain tip. SELECT MAX(id) is reliable because we hold
	// d.mu and are inside a tx; no concurrent insert can interleave.
	var (
		maxID    sql.NullInt64
		lastHash sql.NullString
	)
	if err := tx.QueryRow(
		`SELECT id, row_hash FROM audit_events ORDER BY id DESC LIMIT 1`,
	).Scan(&maxID, &lastHash); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("statedb audit: read tip: %w", classifyDriverErr(err))
	}

	prevHash := genesisHash
	if maxID.Valid && lastHash.Valid && lastHash.String != "" {
		prevHash = lastHash.String
	}
	nextID := maxID.Int64 + 1
	ev.ID = nextID
	ev.PrevHash = prevHash
	ev.RowHash = computeRowHash(*ev)

	if _, err := tx.Exec(
		`INSERT INTO audit_events(id, timestamp, actor, event_type,
			entity_type, entity_id, payload, prev_hash, row_hash)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		ev.ID,
		ev.Timestamp.Format(time.RFC3339Nano),
		ev.Actor, ev.EventType, ev.EntityType, ev.EntityID,
		ev.Payload, ev.PrevHash, ev.RowHash,
	); err != nil {
		return fmt.Errorf("statedb audit: insert: %w", classifyDriverErr(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb audit: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// computeRowHash returns SHA-256(prev_hash || canonical(row)).
//
// Canonicalisation: tab-separated fields in a fixed order, including the
// id and timestamp, with a leading version tag so we can evolve the
// algorithm without breaking old chains. The literal payload string is
// included verbatim — re-canonicalising the JSON would let an attacker
// re-order keys without changing the canonical form, which is the bug
// we are trying to detect.
func computeRowHash(ev AuditEvent) string {
	var b strings.Builder
	b.WriteString("v1\t")
	b.WriteString(ev.PrevHash)
	b.WriteByte('\t')
	fmt.Fprintf(&b, "%d", ev.ID)
	b.WriteByte('\t')
	b.WriteString(ev.Timestamp.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\t')
	b.WriteString(ev.Actor)
	b.WriteByte('\t')
	b.WriteString(ev.EventType)
	b.WriteByte('\t')
	b.WriteString(ev.EntityType)
	b.WriteByte('\t')
	b.WriteString(ev.EntityID)
	b.WriteByte('\t')
	b.WriteString(ev.Payload)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// AuditFilter narrows ListAuditEvents down to the rows the caller cares
// about. All fields are optional — zero values mean "no filter".
type AuditFilter struct {
	Actor      string    // exact-match
	EntityType string    // exact-match (e.g. "task")
	EntityID   string    // exact-match within EntityType
	EventType  string    // exact-match (e.g. "task.update")
	Since      time.Time // only events with timestamp >= Since
	Until      time.Time // only events with timestamp <= Until
	FromID     int64     // only events with id >= FromID
	ToID       int64     // only events with id <= ToID
	Search     string    // case-insensitive LIKE on payload
	Order      string    // "asc" (default) or "desc"
	Limit      int       // 0 = no limit (capped to 10 000 internally)
	Offset     int
}

// ListAuditEvents returns rows matching the filter, plus the unfiltered
// total count for paging UIs.
func (d *DB) ListAuditEvents(f AuditFilter) (rows []AuditEvent, total int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("statedb audit: count: %w", classifyDriverErr(err))
	}

	q := `SELECT id, timestamp, actor, event_type, entity_type, entity_id,
			payload, prev_hash, row_hash
		FROM audit_events`
	var (
		conds []string
		args  []any
	)
	if f.Actor != "" {
		conds = append(conds, "actor = ?")
		args = append(args, f.Actor)
	}
	if f.EntityType != "" {
		conds = append(conds, "entity_type = ?")
		args = append(args, f.EntityType)
	}
	if f.EntityID != "" {
		conds = append(conds, "entity_id = ?")
		args = append(args, f.EntityID)
	}
	if f.EventType != "" {
		conds = append(conds, "event_type = ?")
		args = append(args, f.EventType)
	}
	if !f.Since.IsZero() {
		conds = append(conds, "timestamp >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "timestamp <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}
	if f.FromID > 0 {
		conds = append(conds, "id >= ?")
		args = append(args, f.FromID)
	}
	if f.ToID > 0 {
		conds = append(conds, "id <= ?")
		args = append(args, f.ToID)
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		conds = append(conds, "LOWER(payload) LIKE ?")
		args = append(args, "%"+strings.ToLower(s)+"%")
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	order := strings.ToLower(strings.TrimSpace(f.Order))
	if order == "desc" {
		q += " ORDER BY id DESC"
	} else {
		q += " ORDER BY id ASC"
	}

	limit := f.Limit
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	q += " LIMIT ?"
	args = append(args, limit)
	if f.Offset > 0 {
		q += " OFFSET ?"
		args = append(args, f.Offset)
	}

	qrows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, total, fmt.Errorf("statedb audit: query: %w", classifyDriverErr(err))
	}
	defer qrows.Close()
	for qrows.Next() {
		var (
			ev AuditEvent
			ts string
		)
		if err := qrows.Scan(&ev.ID, &ts, &ev.Actor, &ev.EventType,
			&ev.EntityType, &ev.EntityID, &ev.Payload, &ev.PrevHash, &ev.RowHash,
		); err != nil {
			return nil, total, fmt.Errorf("statedb audit: scan: %w", classifyDriverErr(err))
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			ev.Timestamp = t
		}
		rows = append(rows, ev)
	}
	if err := qrows.Err(); err != nil {
		return nil, total, fmt.Errorf("statedb audit: rows: %w", classifyDriverErr(err))
	}
	return rows, total, nil
}

// AuditVerifyReport summarises a chain-verification run.
type AuditVerifyReport struct {
	Total     int    // rows checked
	OK        bool   // true when every link verified
	BreakAtID int64  // first row whose hash did not match (0 if OK)
	Reason    string // human-readable description of the break
}

// VerifyAuditChain walks audit_events in id order and recomputes each row's
// hash, comparing to the stored value. The first mismatch (or gap, or
// missing prev_hash linkage) stops the walk and is reported. Verification
// is read-only and holds the DB mutex only during the row scan.
func (d *DB) VerifyAuditChain() (AuditVerifyReport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, timestamp, actor, event_type, entity_type, entity_id,
				payload, prev_hash, row_hash
		 FROM audit_events ORDER BY id ASC`,
	)
	if err != nil {
		return AuditVerifyReport{}, fmt.Errorf("statedb audit: verify: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	report := AuditVerifyReport{OK: true}
	expectedPrev := genesisHash
	var lastID int64
	for rows.Next() {
		report.Total++
		var (
			ev AuditEvent
			ts string
		)
		if err := rows.Scan(&ev.ID, &ts, &ev.Actor, &ev.EventType,
			&ev.EntityType, &ev.EntityID, &ev.Payload, &ev.PrevHash, &ev.RowHash,
		); err != nil {
			return AuditVerifyReport{}, fmt.Errorf("statedb audit: scan: %w", classifyDriverErr(err))
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			ev.Timestamp = t
		}

		// Detect missing rows (a deletion shows up as a gap in id).
		if lastID > 0 && ev.ID != lastID+1 {
			return AuditVerifyReport{
				Total:     report.Total,
				OK:        false,
				BreakAtID: ev.ID,
				Reason:    fmt.Sprintf("id gap: expected %d, got %d", lastID+1, ev.ID),
			}, nil
		}
		lastID = ev.ID

		if ev.PrevHash != expectedPrev {
			return AuditVerifyReport{
				Total:     report.Total,
				OK:        false,
				BreakAtID: ev.ID,
				Reason:    fmt.Sprintf("prev_hash mismatch at id %d: stored=%s expected=%s", ev.ID, short(ev.PrevHash), short(expectedPrev)),
			}, nil
		}
		want := computeRowHash(ev)
		if want != ev.RowHash {
			return AuditVerifyReport{
				Total:     report.Total,
				OK:        false,
				BreakAtID: ev.ID,
				Reason:    fmt.Sprintf("row_hash mismatch at id %d: stored=%s recomputed=%s", ev.ID, short(ev.RowHash), short(want)),
			}, nil
		}
		expectedPrev = ev.RowHash
	}
	if err := rows.Err(); err != nil {
		return AuditVerifyReport{}, fmt.Errorf("statedb audit: verify rows: %w", classifyDriverErr(err))
	}
	return report, nil
}

// short returns the first 12 hex chars of a hash for friendlier error output.
// 12 chars (48 bits) keeps collision probability vanishingly small for the
// typical audit_events row count and stays readable in a terminal.
func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// MaxAuditID returns the largest id currently in the table, or 0 if empty.
// Used by the `events tail --follow` poller to discover new rows.
func (d *DB) MaxAuditID() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var v sql.NullInt64
	if err := d.conn.QueryRow(`SELECT MAX(id) FROM audit_events`).Scan(&v); err != nil {
		return 0, fmt.Errorf("statedb audit: max id: %w", classifyDriverErr(err))
	}
	if !v.Valid {
		return 0, nil
	}
	return v.Int64, nil
}

// MarshalAuditPayload is a small helper around json.Marshal used by audit
// callers that want a non-empty payload but don't want to import encoding/json
// at every call site. Returns "" on marshal failure rather than aborting the
// caller's flow — the audit row still records the mutation type.
func MarshalAuditPayload(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// AuditDistinctActors returns the set of distinct actor values across the
// audit log, sorted ascending. Used by the Web UI's filter dropdown so the
// user sees only actors that actually exist.
func (d *DB) AuditDistinctActors() ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT DISTINCT actor FROM audit_events ORDER BY actor ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb audit: distinct actors: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("statedb audit: scan: %w", classifyDriverErr(err))
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out, rows.Err()
}

// AuditDistinctEntities returns the set of distinct (entity_type, entity_id)
// pairs as "type/id" strings (id may be empty for singletons). Sorted.
func (d *DB) AuditDistinctEntityTypes() ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT DISTINCT entity_type FROM audit_events
		 WHERE entity_type != '' ORDER BY entity_type ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("statedb audit: distinct entities: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("statedb audit: scan: %w", classifyDriverErr(err))
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
