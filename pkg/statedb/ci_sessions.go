// Durable record of CI relay sessions (Task 20390).
//
// Rows for migrations/0060_ci_sessions.sql. See that file for why a session a
// pipeline holds needs a record outside the process that minted it. This file
// owns the SQL; what a policy, a provenance or a counter set holds is
// pkg/claudeproxy's and pkg/ui's business (each arrives here as an opaque JSON
// document), and when a session may be restored is pkg/ui's.
//
// The writes a holder makes name the holder they expect, as proxy_sessions'
// do: a process that lost a session to the one that restored it can neither
// checkpoint nor close it, and two processes racing to restore the same
// session cannot both win. The closes an operator causes on a rule — edited,
// disabled or deleted — and a revocation are not fenced: they end the record
// whoever holds it, so a session no process serves at that moment cannot be
// restored afterwards under a rule that no longer stands. Federation switched
// off is an instance's own configuration, and ends only that instance's
// records (pkg/ui).

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CISessionRow is one minted CI relay session. It says who serves the session,
// which pipeline it was minted for, what it may do and how its token hashes —
// never a token, and never the credential the relay presents upstream.
type CISessionRow struct {
	SessionID string
	// TokenSHA256 is the hex SHA-256 of the session token the pipeline
	// presents.
	TokenSHA256 string
	// RuleID is the allowlist rule that admitted the pipeline.
	RuleID string
	// Holder is the hub process serving the session.
	Holder string
	// Instance is the hub instance whose configuration governs the session:
	// the port of the process that minted or last restored it.
	Instance string
	// Provenance is the JSON account of the pipeline the rule admitted: the
	// rule's name, the project it binds, and the verified claims of the OIDC
	// token the session was minted for.
	Provenance string
	// Policy is the JSON account of what the session may do.
	Policy string
	// Counters is the JSON checkpoint of what the session has spent.
	Counters    string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	LastUsedAt  time.Time
	UpdatedAt   time.Time
	ClosedAt    time.Time
	CloseReason string
}

// Open reports whether the session has not been closed.
func (r CISessionRow) Open() bool { return r.ClosedAt.IsZero() }

// InsertCISession records a session that was just minted. A row with the same
// id is an error, never overwritten: an id is 96 random bits, and a second
// session under one would be a session whose record describes another.
func (d *DB) InsertCISession(row CISessionRow) error {
	if strings.TrimSpace(row.SessionID) == "" {
		return errors.New("statedb: a CI session needs an id")
	}
	if strings.TrimSpace(row.TokenSHA256) == "" {
		return errors.New("statedb: a CI session needs its token's hash")
	}
	for _, doc := range []*string{&row.Provenance, &row.Policy, &row.Counters} {
		if strings.TrimSpace(*doc) == "" {
			*doc = "{}"
		}
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO ci_sessions(session_id, token_sha256, rule_id, holder, instance, provenance_json,
		                         policy_json, counters_json, issued_at, expires_at, last_used_at,
		                         updated_at, closed_at, close_reason)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.SessionID, row.TokenSHA256, row.RuleID, row.Holder, row.Instance, row.Provenance,
		row.Policy, row.Counters, formatOptionalTime(row.IssuedAt), formatOptionalTime(row.ExpiresAt),
		formatOptionalTime(row.LastUsedAt), formatOptionalTime(row.UpdatedAt),
		formatOptionalTime(row.ClosedAt), row.CloseReason,
	)
	if err != nil {
		return fmt.Errorf("statedb: record CI session %s: %w", row.SessionID, classifyDriverErr(err))
	}
	return nil
}

// ciSessionColumns is the column list scanCISession reads.
const ciSessionColumns = `session_id, token_sha256, rule_id, holder, instance, provenance_json, policy_json,
	counters_json, issued_at, expires_at, last_used_at, updated_at, closed_at, close_reason`

// GetCISession returns one session, or a wrapped ErrCISessionNotFound.
func (d *DB) GetCISession(id string) (CISessionRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec, err := scanCISession(d.conn.QueryRow(`SELECT `+ciSessionColumns+` FROM ci_sessions
		WHERE session_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return CISessionRow{}, fmt.Errorf("%w: %s", ErrCISessionNotFound, id)
	}
	if err != nil {
		return CISessionRow{}, fmt.Errorf("statedb: get CI session %s: %w", id, classifyDriverErr(err))
	}
	return rec, nil
}

// CISessionFilter narrows ListCISessions. Zero fields do not filter.
type CISessionFilter struct {
	RuleID string
	Holder string
	// OpenOnly drops closed sessions.
	OpenOnly bool
}

// ListCISessions returns the sessions matching f, oldest first.
func (d *DB) ListCISessions(f CISessionFilter) ([]CISessionRow, error) {
	var (
		where []string
		args  []any
	)
	if f.RuleID != "" {
		where = append(where, "rule_id = ?")
		args = append(args, f.RuleID)
	}
	if f.Holder != "" {
		where = append(where, "holder = ?")
		args = append(args, f.Holder)
	}
	if f.OpenOnly {
		where = append(where, "closed_at = ''")
	}
	q := `SELECT ` + ciSessionColumns + ` FROM ci_sessions`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY issued_at, session_id"

	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list CI sessions: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []CISessionRow
	for rows.Next() {
		rec, err := scanCISession(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan CI session: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list CI sessions: %w", classifyDriverErr(err))
	}
	return out, nil
}

// OpenCISessionIDsHeldBy returns the ids of the open sessions holder holds:
// what a hub process checks the sessions it serves against on every
// checkpoint tick, without reading the records themselves.
func (d *DB) OpenCISessionIDsHeldBy(holder string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT session_id FROM ci_sessions WHERE holder = ? AND closed_at = ''`, holder)
	if err != nil {
		return nil, fmt.Errorf("statedb: list CI sessions held by %s: %w", holder, classifyDriverErr(err))
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("statedb: scan CI session id: %w", classifyDriverErr(err))
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list CI sessions held by %s: %w", holder, classifyDriverErr(err))
	}
	return out, nil
}

// TakeCISession moves an open session to holder, of instance, provided from
// still holds it, and reports whether it did. The condition is what lets two
// processes race to restore the same session and only one of them serve it.
func (d *DB) TakeCISession(id, from, holder, instance string) (bool, error) {
	return d.execOne(`UPDATE ci_sessions SET holder = ?, instance = ?, updated_at = ?
		WHERE session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("take over CI session %s", id),
		holder, instance, formatOptionalTime(time.Now().UTC()), id, from)
}

// CheckpointCISession replaces an open session's counters and last use,
// provided holder holds it, and reports whether it did.
func (d *DB) CheckpointCISession(id, holder, counters string, lastUsed time.Time) (bool, error) {
	if strings.TrimSpace(counters) == "" {
		counters = "{}"
	}
	return d.execOne(`UPDATE ci_sessions SET counters_json = ?, last_used_at = ?, updated_at = ?
		WHERE session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("checkpoint CI session %s", id),
		counters, formatOptionalTime(lastUsed), formatOptionalTime(time.Now().UTC()), id, holder)
}

// NarrowCISession rewrites an open session's policy and deadline — what a
// restore held it to — and the instance now serving it, provided holder holds
// it, and reports whether it did.
func (d *DB) NarrowCISession(id, holder, instance, policy string, expiresAt time.Time) (bool, error) {
	if strings.TrimSpace(policy) == "" {
		return false, errors.New("statedb: a CI session's policy cannot be empty")
	}
	return d.execOne(`UPDATE ci_sessions SET policy_json = ?, expires_at = ?, instance = ?, updated_at = ?
		WHERE session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("narrow CI session %s", id),
		policy, formatOptionalTime(expiresAt), instance, formatOptionalTime(time.Now().UTC()), id, holder)
}

// CloseCISession marks an open session closed with reason, provided holder
// holds it, and reports whether it did. counters, when non-empty, replaces the
// checkpoint with the session's final count. A session closed once stays
// closed: nothing restores it, and a second close changes nothing.
func (d *DB) CloseCISession(id, holder string, at time.Time, reason, counters string) (bool, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if strings.TrimSpace(reason) == "" {
		reason = "closed"
	}
	if strings.TrimSpace(counters) == "" {
		return d.execOne(`UPDATE ci_sessions SET closed_at = ?, close_reason = ?, updated_at = ?
			WHERE session_id = ? AND holder = ? AND closed_at = ''`,
			fmt.Sprintf("close CI session %s", id),
			formatOptionalTime(at), reason, formatOptionalTime(time.Now().UTC()), id, holder)
	}
	return d.execOne(`UPDATE ci_sessions SET closed_at = ?, close_reason = ?, counters_json = ?, updated_at = ?
		WHERE session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("close CI session %s", id),
		formatOptionalTime(at), reason, counters, formatOptionalTime(time.Now().UTC()), id, holder)
}

// CloseCISessionsForRule closes every open session ruleID minted, whoever
// holds it, and returns them as they were before the close. It is how an
// operator's edit, disable or deletion of a rule reaches a session no process
// is serving at that moment, which would otherwise be restored later under a
// rule that no longer stands.
func (d *DB) CloseCISessionsForRule(ruleID string, at time.Time, reason string) ([]CISessionRow, error) {
	if strings.TrimSpace(ruleID) == "" {
		return nil, nil
	}
	return d.closeCISessionsWhere(`rule_id = ?`, []any{ruleID}, at, reason)
}

// CloseCISessionAny marks an open session closed whoever holds it, and
// reports whether it did: an operator's revocation, which must land whether
// or not the process holding the record is the one asked, or alive. The
// holder, if live, stops serving it at its next checkpoint.
func (d *DB) CloseCISessionAny(id string, at time.Time, reason string) (bool, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if strings.TrimSpace(reason) == "" {
		reason = "closed"
	}
	return d.execOne(`UPDATE ci_sessions SET closed_at = ?, close_reason = ?, updated_at = ?
		WHERE session_id = ? AND closed_at = ''`,
		fmt.Sprintf("close CI session %s", id),
		formatOptionalTime(at), reason, formatOptionalTime(time.Now().UTC()), id)
}

// closeCISessionsWhere closes the open sessions cond selects, in one
// transaction, and returns them.
func (d *DB) closeCISessionsWhere(cond string, args []any, at time.Time, reason string) ([]CISessionRow, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if strings.TrimSpace(reason) == "" {
		reason = "closed"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: close CI sessions: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT `+ciSessionColumns+` FROM ci_sessions
		WHERE closed_at = '' AND `+cond+` ORDER BY issued_at, session_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: close CI sessions: %w", classifyDriverErr(err))
	}
	var open []CISessionRow
	for rows.Next() {
		rec, err := scanCISession(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("statedb: scan CI session: %w", classifyDriverErr(err))
		}
		open = append(open, rec)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("statedb: close CI sessions: %w", classifyDriverErr(err))
	}
	now := formatOptionalTime(time.Now().UTC())
	var closed []CISessionRow
	for _, rec := range open {
		res, err := tx.Exec(`UPDATE ci_sessions SET closed_at = ?, close_reason = ?, updated_at = ?
			WHERE session_id = ? AND closed_at = ''`, formatOptionalTime(at), reason, now, rec.SessionID)
		if err != nil {
			return nil, fmt.Errorf("statedb: close CI session %s: %w", rec.SessionID, classifyDriverErr(err))
		}
		if n, _ := res.RowsAffected(); n == 1 {
			closed = append(closed, rec)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: close CI sessions: %w", classifyDriverErr(err))
	}
	return closed, nil
}

// DeleteCISession forgets a session, provided holder holds it, and reports
// whether a row went. It is how the janitor retires the record of a session
// that closed or lapsed.
func (d *DB) DeleteCISession(id, holder string) (bool, error) {
	return d.execOne(`DELETE FROM ci_sessions WHERE session_id = ? AND holder = ?`,
		fmt.Sprintf("delete CI session %s", id), id, holder)
}

type ciSessionScanner interface {
	Scan(dest ...any) error
}

func scanCISession(s ciSessionScanner) (CISessionRow, error) {
	var (
		rec                                                CISessionRow
		issuedAt, expiresAt, lastUsed, updatedAt, closedAt string
	)
	if err := s.Scan(&rec.SessionID, &rec.TokenSHA256, &rec.RuleID, &rec.Holder, &rec.Instance, &rec.Provenance,
		&rec.Policy, &rec.Counters, &issuedAt, &expiresAt, &lastUsed, &updatedAt, &closedAt,
		&rec.CloseReason); err != nil {
		return CISessionRow{}, err
	}
	rec.IssuedAt = parseOptionalTime(issuedAt)
	rec.ExpiresAt = parseOptionalTime(expiresAt)
	rec.LastUsedAt = parseOptionalTime(lastUsed)
	rec.UpdatedAt = parseOptionalTime(updatedAt)
	rec.ClosedAt = parseOptionalTime(closedAt)
	return rec, nil
}
