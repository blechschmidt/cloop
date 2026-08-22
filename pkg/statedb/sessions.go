package statedb

// Durable dashboard sessions (Task 20176). See migrations/0017_sessions.sql
// for the column-by-column rationale; this file is the mechanical accessor
// layer and holds no policy. Whether a session is idle, expired, or due for an
// IdP check is decided in pkg/oidcauth, which passes the resulting cutoffs
// down as absolute times.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionRow is one row of the sessions table.
//
// RefreshSealed is ciphertext. Nothing in this package encrypts or decrypts
// it — the sealing happens in pkg/sessionstore, so the storage layer never
// holds a live credential and cannot leak one by logging a row.
type SessionRow struct {
	ID               string
	Subject          string
	Issuer           string
	Email            string
	DisplayName      string
	OwnerKey         string
	Groups           []string
	Roles            []string
	IP               string
	UserAgent        string
	IssuedAt         time.Time
	LastSeen         time.Time
	ExpiresAt        time.Time
	RefreshSealed    []byte
	// RefreshKeyID and RefreshWrappedDEK are the envelope this row's sealed
	// refresh token belongs to (Task 20181). "legacy" means the token is
	// sealed directly under the passphrase-derived key, with no wrapped DEK.
	RefreshKeyID      string
	RefreshWrappedDEK []byte
	RefreshCheckedAt time.Time
}

const sessionColumns = `id, subject, issuer, email, display_name, owner_key,
	groups_json, roles_json, ip, user_agent,
	issued_at, last_seen, expires_at, refresh_sealed, refresh_checked_at,
	refresh_key_id, refresh_wrapped_dek`

// PutSession inserts a session row.
//
// An insert rather than an upsert: the id is a digest of 256 random bits, so a
// collision is not a case worth writing code for, while silently overwriting
// one would replace a live session's subject and roles with another's.
func (d *DB) PutSession(row SessionRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: session id is required")
	}
	groups, err := marshalStringSlice(row.Groups)
	if err != nil {
		return fmt.Errorf("statedb: marshal session groups: %w", err)
	}
	roles, err := marshalStringSlice(row.Roles)
	if err != nil {
		return fmt.Errorf("statedb: marshal session roles: %w", err)
	}
	if row.IssuedAt.IsZero() {
		row.IssuedAt = time.Now()
	}
	if row.LastSeen.IsZero() {
		row.LastSeen = row.IssuedAt
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err = d.conn.Exec(
		`INSERT INTO sessions(`+sessionColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.Subject, row.Issuer, row.Email, row.DisplayName, row.OwnerKey,
		groups, roles, row.IP, row.UserAgent,
		row.IssuedAt.UTC().Format(time.RFC3339Nano),
		row.LastSeen.UTC().Format(time.RFC3339Nano),
		formatOptionalTime(row.ExpiresAt),
		row.RefreshSealed,
		formatOptionalTime(row.RefreshCheckedAt),
		defaultString(row.RefreshKeyID, "legacy"),
		row.RefreshWrappedDEK,
	)
	if err != nil {
		return fmt.Errorf("statedb: insert session: %w", classifyDriverErr(err))
	}
	return nil
}

// GetSession returns one session by id, or an error wrapping
// ErrSessionNotFound.
//
// This sits on the authentication path, so the lookup is by primary key: a
// signed-in request must not cost a scan, and a scan would make request
// latency a function of how many people are logged in.
func (d *DB) GetSession(id string) (SessionRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id)
	out, err := scanSessionRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRow{}, ErrSessionNotFound
	}
	if err != nil {
		return SessionRow{}, fmt.Errorf("statedb: get session: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ListSessions returns every session, most recently active first.
func (d *DB) ListSessions() ([]SessionRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + sessionColumns + ` FROM sessions ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list sessions: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	return collectSessionRows(rows)
}

// TouchSession records that a session was used at t.
//
// Called off the authentication path and throttled by the caller; a failure is
// advisory. The write is conditional on moving the timestamp forward so two
// concurrent requests cannot walk last_seen backwards — the ordering the
// caller's in-memory cache enforces within one process, enforced again here
// for the cross-process case.
func (d *DB) TouchSession(id string, t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`UPDATE sessions SET last_seen = ? WHERE id = ? AND last_seen < ?`,
		t.UTC().Format(time.RFC3339Nano), id, t.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("statedb: touch session: %w", classifyDriverErr(err))
	}
	return nil
}

// UpdateSessionRefresh stores a rotated refresh token and stamps the check
// time. A nil sealed value clears the stored token, which is how a session
// that can no longer be revalidated stops being retried.
//
// Clearing also blanks the key id. Leaving a stale one behind would make the
// row look, to the rotator and to `cloop hub key retire`, like material still
// sealed under a key that in fact protects nothing — which is exactly the kind
// of phantom reference that makes an operator conclude retirement is broken.
func (d *DB) UpdateSessionRefresh(id, keyID string, wrappedDEK, sealed []byte, checkedAt time.Time) error {
	if len(sealed) == 0 {
		keyID, wrappedDEK = "", nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE sessions SET refresh_sealed = ?, refresh_key_id = ?, refresh_wrapped_dek = ?,
		        refresh_checked_at = ? WHERE id = ?`,
		sealed, keyID, wrappedDEK, formatOptionalTime(checkedAt), id,
	)
	if err != nil {
		return fmt.Errorf("statedb: update session refresh: %w", classifyDriverErr(err))
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// DeleteSession removes one session and reports whether a row existed.
func (d *DB) DeleteSession(id string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("statedb: delete session: %w", classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: delete session: %w", classifyDriverErr(err))
	}
	return n > 0, nil
}

// DeleteSessionsBySubject removes every session belonging to subject except
// the one named by keepID (pass "" to remove all of them), returning the rows
// it deleted so the caller can audit each one.
//
// Read-then-delete inside one transaction: an audit entry the operator cannot
// tie to a specific session is not much of an audit entry, and doing it in two
// statements outside a transaction would let a login between them produce a
// row that is deleted but never recorded.
func (d *DB) DeleteSessionsBySubject(subject, keepID string) ([]SessionRow, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, errors.New("statedb: session subject is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: delete sessions by subject: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.Query(
		`SELECT `+sessionColumns+` FROM sessions WHERE subject = ? AND id <> ?`, subject, keepID)
	if err != nil {
		return nil, fmt.Errorf("statedb: select sessions by subject: %w", classifyDriverErr(err))
	}
	doomed, err := collectSessionRows(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(doomed) == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(
		`DELETE FROM sessions WHERE subject = ? AND id <> ?`, subject, keepID); err != nil {
		return nil, fmt.Errorf("statedb: delete sessions by subject: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: delete sessions by subject: %w", classifyDriverErr(err))
	}
	return doomed, nil
}

// DeleteExpiredSessions removes sessions past either clock and returns what it
// deleted.
//
// absoluteCutoff is compared against expires_at (the ceiling set at login) and
// idleCutoff against last_seen. Both are absolute times computed by the caller
// from its configured policy, so this layer stays free of any opinion about
// how long a session should live.
func (d *DB) DeleteExpiredSessions(absoluteCutoff, idleCutoff time.Time) ([]SessionRow, error) {
	abs := absoluteCutoff.UTC().Format(time.RFC3339Nano)
	idle := idleCutoff.UTC().Format(time.RFC3339Nano)
	// expires_at = '' means "no absolute ceiling" and must not match; last_seen
	// is written on every insert, so it needs no such guard.
	const where = `WHERE (expires_at <> '' AND expires_at <= ?) OR last_seen <= ?`

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: expire sessions: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.Query(`SELECT `+sessionColumns+` FROM sessions `+where, abs, idle)
	if err != nil {
		return nil, fmt.Errorf("statedb: select expired sessions: %w", classifyDriverErr(err))
	}
	doomed, err := collectSessionRows(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(doomed) == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(`DELETE FROM sessions `+where, abs, idle); err != nil {
		return nil, fmt.Errorf("statedb: expire sessions: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: expire sessions: %w", classifyDriverErr(err))
	}
	return doomed, nil
}

// SessionsDueForRefresh returns sessions whose IdP check is older than cutoff
// and that still hold a sealed refresh token, oldest first and at most limit
// rows.
//
// The limit bounds one pass: a hub where every session comes due at once must
// spread the token-endpoint calls over several ticks rather than opening a
// thousand connections to the IdP in one burst, which the IdP would rightly
// treat as an attack.
func (d *DB) SessionsDueForRefresh(cutoff time.Time, limit int) ([]SessionRow, error) {
	if limit <= 0 {
		limit = 50
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT `+sessionColumns+` FROM sessions
		 WHERE refresh_sealed IS NOT NULL AND length(refresh_sealed) > 0
		   AND (refresh_checked_at = '' OR refresh_checked_at <= ?)
		 ORDER BY refresh_checked_at ASC LIMIT ?`,
		cutoff.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: select sessions due for refresh: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	return collectSessionRows(rows)
}

// ── scanning ────────────────────────────────────────────────────────────────

func scanSessionRow(sc rowScanner) (SessionRow, error) {
	var (
		out                             SessionRow
		groups, roles                   string
		issued, lastSeen, expires, chkd string
		sealed                          []byte
	)
	if err := sc.Scan(
		&out.ID, &out.Subject, &out.Issuer, &out.Email, &out.DisplayName, &out.OwnerKey,
		&groups, &roles, &out.IP, &out.UserAgent,
		&issued, &lastSeen, &expires, &sealed, &chkd,
		&out.RefreshKeyID, &out.RefreshWrappedDEK,
	); err != nil {
		return SessionRow{}, err
	}
	out.Groups = unmarshalStringSlice(groups)
	out.Roles = unmarshalStringSlice(roles)
	out.IssuedAt = parseOptionalTime(issued)
	out.LastSeen = parseOptionalTime(lastSeen)
	out.ExpiresAt = parseOptionalTime(expires)
	out.RefreshCheckedAt = parseOptionalTime(chkd)
	out.RefreshSealed = sealed
	return out, nil
}

func collectSessionRows(rows *sql.Rows) ([]SessionRow, error) {
	var out []SessionRow
	for rows.Next() {
		row, err := scanSessionRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan session: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: iterate sessions: %w", classifyDriverErr(err))
	}
	return out, nil
}
