package statedb

// The database side of the audit head checkpoints (Task 20404).
//
// A hash chain proves that what it holds was not edited, and nothing about
// what it no longer holds: delete the newest rows and the survivors are a
// shorter chain that verifies. pkg/auditcheckpoint closes that by writing the
// head of every chain somewhere off the database, under a seal nothing in this
// file can produce. What lives here is only what that needs from the database:
// the head to write down, the rows and anchors to check it against later, and
// the shared marker that lets one cluster leader at a time write each window.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AuditHead is where a chain ends, and what anchors its beginning.
type AuditHead struct {
	// LastID, LastRowHash and LastTimestamp describe the newest row; all zero
	// when the table is empty.
	LastID        int64
	LastRowHash   string
	LastTimestamp time.Time
	// FirstID is the oldest surviving row's id, 0 when empty.
	FirstID int64
	// Rows is how many rows the table holds.
	Rows int64
	// Anchor is the newest prune anchor, nil when the chain was never pruned.
	Anchor *AuditAnchor
}

// AuditHead reads the chain's newest row, its row count and its newest
// anchor.
//
// Three plain reads rather than one transaction: every transaction this package
// opens takes the write lock at BEGIN (connpolicy.go), and a checkpoint must
// neither stall writers nor fail on a database that has stopped taking writes
// — that is exactly when its record matters. Holding d.mu orders them against
// this handle's own appends; another process appending in between moves the
// head forward, which describes a later moment rather than an inconsistent one.
func (d *DB) AuditHead() (AuditHead, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var h AuditHead
	row := d.conn.QueryRow(`SELECT ` + anchorColumns + ` FROM audit_anchors
		ORDER BY pruned_through_id DESC, id DESC LIMIT 1`)
	a, err := scanAnchor(row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return AuditHead{}, fmt.Errorf("statedb audit: head anchor: %w", classifyDriverErr(err))
	default:
		h.Anchor = &a
	}

	var ts string
	err = d.conn.QueryRow(
		`SELECT id, row_hash, timestamp FROM audit_events ORDER BY id DESC LIMIT 1`,
	).Scan(&h.LastID, &h.LastRowHash, &ts)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return AuditHead{}, fmt.Errorf("statedb audit: head: %w", classifyDriverErr(err))
	default:
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			h.LastTimestamp = t
		}
	}
	var first sql.NullInt64
	if err := d.conn.QueryRow(`SELECT MIN(id), COUNT(*) FROM audit_events`).Scan(&first, &h.Rows); err != nil {
		return AuditHead{}, fmt.Errorf("statedb audit: head count: %w", classifyDriverErr(err))
	}
	h.FirstID = first.Int64
	return h, nil
}

// AuditRowAt returns the row with id, and whether there is one.
func (d *DB) AuditRowAt(id int64) (AuditEvent, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var (
		ev AuditEvent
		ts string
	)
	err := d.conn.QueryRow(
		`SELECT id, timestamp, actor, event_type, entity_type, entity_id,
				payload, prev_hash, row_hash
		 FROM audit_events WHERE id = ?`, id,
	).Scan(&ev.ID, &ts, &ev.Actor, &ev.EventType, &ev.EntityType, &ev.EntityID,
		&ev.Payload, &ev.PrevHash, &ev.RowHash)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditEvent{}, false, nil
	}
	if err != nil {
		return AuditEvent{}, false, fmt.Errorf("statedb audit: row %d: %w", id, classifyDriverErr(err))
	}
	if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
		ev.Timestamp = t
	}
	return ev, true, nil
}

// AuditGapSummary is what a chain's audit.gap rows add up to, read without
// walking the chain.
type AuditGapSummary struct {
	Gaps      int
	Events    int64
	LastID    int64
	LastAt    time.Time
	FirstAt   time.Time
	Truncated bool // more gap rows than were read; Events is a lower bound
}

// maxGapSummaryRows bounds how many gap rows AuditGapSummary decodes.
const maxGapSummaryRows = 10000

// AuditGapSummary totals the chain's audit.gap rows through the event_type
// index. It is the cheap question `cloop hub doctor` asks; VerifyAuditChain
// is the thorough one.
func (d *DB) AuditGapSummary() (AuditGapSummary, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, timestamp, payload FROM audit_events
		 WHERE event_type = ? ORDER BY id ASC LIMIT ?`, auditGapEventType, maxGapSummaryRows+1)
	if err != nil {
		return AuditGapSummary{}, fmt.Errorf("statedb audit: gap summary: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var s AuditGapSummary
	for rows.Next() {
		var (
			id          int64
			ts, payload string
		)
		if err := rows.Scan(&id, &ts, &payload); err != nil {
			return AuditGapSummary{}, fmt.Errorf("statedb audit: gap summary: %w", classifyDriverErr(err))
		}
		if s.Gaps == maxGapSummaryRows {
			s.Truncated = true
			break
		}
		s.Gaps++
		s.LastID = id
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			if s.FirstAt.IsZero() {
				s.FirstAt = t
			}
			s.LastAt = t
		}
		s.Events += AuditGapLostEvents(payload)
	}
	if err := rows.Err(); err != nil {
		return AuditGapSummary{}, fmt.Errorf("statedb audit: gap summary: %w", classifyDriverErr(err))
	}
	return s, nil
}

// ── one writer per checkpoint window ─────────────────────────────────────────

// auditCheckpointWindowKey is the hub meta key holding the window marker.
const auditCheckpointWindowKey = "audit.checkpoint.window"

// AuditCheckpointWindow is the shared record of which checkpoint window was
// last claimed, by which hub member, and whether it was written.
//
// It is what keeps a leader change from either skipping or doubling a window:
// a new leader resumes from it rather than from its own clock. It lives in the
// database the checkpoints exist to distrust, which is acceptable because all
// it can be used for is liveness — the worst a forged marker does is stop
// checkpoints being written, which `cloop hub doctor` reports as stale — and a
// marker claiming a window in the future is ignored rather than obeyed.
type AuditCheckpointWindow struct {
	Window int64 `json:"window"`
	// IntervalS is the interval, in seconds, the window was numbered under:
	// a window number means nothing without it.
	IntervalS int64     `json:"interval_s,omitempty"`
	Member    string    `json:"member"`
	ClaimedAt time.Time `json:"claimed_at"`
	Done      bool      `json:"done"`
}

// AuditCheckpointClaim says what ClaimAuditCheckpointWindow decided.
type AuditCheckpointClaim struct {
	// Claimed: the caller writes Window now. Window is the window asked
	// for, or the one before it when a member that claimed that one died
	// before writing it — the window is then written late rather than not
	// at all, and the caller asks again for the current one.
	Claimed bool
	Window  int64
	// Prior is the marker as it was found.
	Prior AuditCheckpointWindow
	// HeldBy names another member writing a window right now, whose claim
	// goes stale at RetryAt; the caller should look again then.
	HeldBy  string
	RetryAt time.Time
	// FutureMarker reports a marker more than one window ahead of the
	// caller's clock, which was overwritten rather than obeyed.
	FutureMarker bool
}

// ClaimAuditCheckpointWindow decides, under one write transaction, whether
// member writes checkpoint window w of interval.
//
//   - Nothing claimed yet, an older window, or a window numbered under
//     another interval (the interval was changed): w is claimed.
//   - w, or the window before it, claimed and not written: by member itself
//     (a retry) or by a member whose claim is older than stale (it died
//     between claiming and writing), that window is claimed — late, if it is
//     the one before; by anybody else, not claimed, and RetryAt says when the
//     claim lapses.
//   - w already written, or the next window claimed (that member is ahead):
//     not claimed.
//   - Further ahead than that: the marker cannot be right, and is replaced.
func (d *DB) ClaimAuditCheckpointWindow(w int64, interval time.Duration, member string, now time.Time, stale time.Duration) (AuditCheckpointClaim, error) {
	if member == "" {
		return AuditCheckpointClaim{}, errors.New("statedb: checkpoint window claim needs a member")
	}
	key, err := hubMetaKey(auditCheckpointWindowKey)
	if err != nil {
		return AuditCheckpointClaim{}, err
	}
	intervalS := int64(interval / time.Second)
	now = now.UTC()

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return AuditCheckpointClaim{}, fmt.Errorf("statedb: claim checkpoint window: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	res := AuditCheckpointClaim{Window: w}
	var raw string
	err = tx.QueryRow(`SELECT value FROM metadata WHERE key = ?`, key).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res.Claimed = true
	case err != nil:
		return AuditCheckpointClaim{}, fmt.Errorf("statedb: read checkpoint window: %w", classifyDriverErr(err))
	default:
		if jerr := json.Unmarshal([]byte(raw), &res.Prior); jerr != nil {
			res.Claimed = true // unreadable: nothing to defer to
			break
		}
		p := res.Prior
		takeover := !p.Done && (p.Member == member || now.Sub(p.ClaimedAt) >= stale)
		switch {
		case p.IntervalS != 0 && p.IntervalS != intervalS:
			res.Claimed = true
		case p.Window < w-1:
			res.Claimed = true
		case p.Window > w+1:
			res.Claimed, res.FutureMarker = true, true
		case p.Window == w+1:
		case p.Done:
			res.Claimed = p.Window < w
		case takeover:
			res.Claimed, res.Window = true, p.Window
		default:
			res.HeldBy = p.Member
			res.RetryAt = p.ClaimedAt.Add(stale)
		}
	}
	if !res.Claimed {
		return res, nil
	}
	body, err := json.Marshal(AuditCheckpointWindow{Window: res.Window, IntervalS: intervalS, Member: member, ClaimedAt: now})
	if err != nil {
		return AuditCheckpointClaim{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO metadata(key, value) VALUES (?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(body),
	); err != nil {
		return AuditCheckpointClaim{}, fmt.Errorf("statedb: claim checkpoint window: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return AuditCheckpointClaim{}, fmt.Errorf("statedb: claim checkpoint window: %w", classifyDriverErr(err))
	}
	return res, nil
}

// CompleteAuditCheckpointWindow marks window w written, if member still holds
// it. Reports whether it did: a member whose claim was taken over in the
// meantime does not overwrite the new holder's marker.
func (d *DB) CompleteAuditCheckpointWindow(w int64, member string) (bool, error) {
	key, err := hubMetaKey(auditCheckpointWindowKey)
	if err != nil {
		return false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: complete checkpoint window: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	var raw string
	if err := tx.QueryRow(`SELECT value FROM metadata WHERE key = ?`, key).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("statedb: read checkpoint window: %w", classifyDriverErr(err))
	}
	var cur AuditCheckpointWindow
	if err := json.Unmarshal([]byte(raw), &cur); err != nil || cur.Window != w || cur.Member != member {
		return false, nil
	}
	cur.Done = true
	body, err := json.Marshal(cur)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE metadata SET value = ? WHERE key = ?`, string(body), key); err != nil {
		return false, fmt.Errorf("statedb: complete checkpoint window: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: complete checkpoint window: %w", classifyDriverErr(err))
	}
	return true, nil
}

// AuditCheckpointWindowMarker reads the window marker, for status output.
func (d *DB) AuditCheckpointWindowMarker() (AuditCheckpointWindow, bool, error) {
	raw, ok, err := d.HubMeta(auditCheckpointWindowKey)
	if err != nil || !ok {
		return AuditCheckpointWindow{}, ok, err
	}
	var w AuditCheckpointWindow
	if err := json.Unmarshal([]byte(raw), &w); err != nil {
		return AuditCheckpointWindow{}, true, fmt.Errorf("statedb: checkpoint window marker is unreadable: %w", err)
	}
	return w, true, nil
}
