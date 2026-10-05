// Durable record of proxy sessions and GitHub App token slots (Task 20383).
//
// Rows for migrations/0058_proxy_sessions.sql. See that file for why a session
// needs a record outside the process that minted it. This file owns the SQL;
// what a scope holds is the registries' business (it arrives here as an opaque
// JSON document) and what to do with a session whose holder stopped is
// pkg/ui's.
//
// Every write after the insert names the holder it expects, as secret_leases
// does: a process that lost a session to the one that adopted its run can
// neither extend, checkpoint nor close it, and two processes racing to restore
// the same session cannot both win.

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Proxy session kinds.
const (
	ProxySessionGit    = "git"
	ProxySessionKube   = "kube"
	ProxySessionEgress = "egress"
)

// ProxySessionRow is one minted session. It says who serves the session, what
// it enforces and how its token hashes — never a token or the credential the
// session presents upstream.
type ProxySessionRow struct {
	Kind      string
	SessionID string
	// TokenSHA256 is the hex SHA-256 of the bearer token the sandbox presents.
	TokenSHA256 string
	LeaseID     string
	GrantID     string
	// Holder is the hub process serving the session.
	Holder     string
	RunID      string
	ProjectID  string
	ExecutorID string
	TaskID     string
	Actor      string
	// Scope is the registry's JSON account of what the session enforces.
	Scope string
	// Counters is the registry's JSON checkpoint of what the session has
	// moved, for a session whose quota outlives its process (egress).
	Counters    string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	UpdatedAt   time.Time
	ClosedAt    time.Time
	CloseReason string
}

// Open reports whether the session has not been closed.
func (r ProxySessionRow) Open() bool { return r.ClosedAt.IsZero() }

// PutProxySession records a session, replacing any row with the same kind and
// id.
func (d *DB) PutProxySession(row ProxySessionRow) error {
	if strings.TrimSpace(row.Kind) == "" || strings.TrimSpace(row.SessionID) == "" {
		return errors.New("statedb: proxy session kind and id are required")
	}
	if strings.TrimSpace(row.Scope) == "" {
		row.Scope = "{}"
	}
	if strings.TrimSpace(row.Counters) == "" {
		row.Counters = "{}"
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO proxy_sessions(kind, session_id, token_sha256, lease_id, grant_id, holder,
		                            run_id, project_id, executor_id, task_id, actor,
		                            scope_json, counters_json, issued_at, expires_at, updated_at,
		                            closed_at, close_reason)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(kind, session_id) DO UPDATE SET
		   token_sha256  = excluded.token_sha256,
		   lease_id      = excluded.lease_id,
		   grant_id      = excluded.grant_id,
		   holder        = excluded.holder,
		   run_id        = excluded.run_id,
		   project_id    = excluded.project_id,
		   executor_id   = excluded.executor_id,
		   task_id       = excluded.task_id,
		   actor         = excluded.actor,
		   scope_json    = excluded.scope_json,
		   counters_json = excluded.counters_json,
		   issued_at     = excluded.issued_at,
		   expires_at    = excluded.expires_at,
		   updated_at    = excluded.updated_at,
		   closed_at     = excluded.closed_at,
		   close_reason  = excluded.close_reason`,
		row.Kind, row.SessionID, row.TokenSHA256, row.LeaseID, row.GrantID, row.Holder,
		row.RunID, row.ProjectID, row.ExecutorID, row.TaskID, row.Actor,
		row.Scope, row.Counters, formatOptionalTime(row.IssuedAt), formatOptionalTime(row.ExpiresAt),
		formatOptionalTime(row.UpdatedAt), formatOptionalTime(row.ClosedAt), row.CloseReason,
	)
	if err != nil {
		return fmt.Errorf("statedb: put proxy session %s/%s: %w", row.Kind, row.SessionID, classifyDriverErr(err))
	}
	return nil
}

// proxySessionColumns is the column list scanProxySession reads.
const proxySessionColumns = `kind, session_id, token_sha256, lease_id, grant_id, holder,
	run_id, project_id, executor_id, task_id, actor, scope_json, counters_json,
	issued_at, expires_at, updated_at, closed_at, close_reason`

// GetProxySession returns one session, or a wrapped ErrProxySessionNotFound.
func (d *DB) GetProxySession(kind, id string) (ProxySessionRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(`SELECT `+proxySessionColumns+` FROM proxy_sessions
		WHERE kind = ? AND session_id = ?`, kind, id)
	rec, err := scanProxySession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ProxySessionRow{}, fmt.Errorf("%w: %s/%s", ErrProxySessionNotFound, kind, id)
	}
	if err != nil {
		return ProxySessionRow{}, fmt.Errorf("statedb: get proxy session %s/%s: %w", kind, id, classifyDriverErr(err))
	}
	return rec, nil
}

// ProxySessionFilter narrows ListProxySessions. Zero fields do not filter.
type ProxySessionFilter struct {
	Kind string
	// LeaseIDs keeps the sessions fed by any of these leases.
	LeaseIDs []string
	// SessionIDs keeps the sessions with any of these ids.
	SessionIDs []string
	RunID      string
	Holder     string
	// OpenOnly drops closed sessions.
	OpenOnly bool
}

// ListProxySessions returns the sessions matching f, oldest first.
func (d *DB) ListProxySessions(f ProxySessionFilter) ([]ProxySessionRow, error) {
	var (
		where []string
		args  []any
	)
	if f.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.RunID != "" {
		where = append(where, "run_id = ?")
		args = append(args, f.RunID)
	}
	if f.Holder != "" {
		where = append(where, "holder = ?")
		args = append(args, f.Holder)
	}
	if f.OpenOnly {
		where = append(where, "closed_at = ''")
	}
	in := func(col string, vals []string) {
		marks := make([]string, len(vals))
		for i, v := range vals {
			marks[i] = "?"
			args = append(args, v)
		}
		where = append(where, col+" IN ("+strings.Join(marks, ",")+")")
	}
	if f.LeaseIDs != nil {
		if len(f.LeaseIDs) == 0 {
			return nil, nil
		}
		in("lease_id", f.LeaseIDs)
	}
	if f.SessionIDs != nil {
		if len(f.SessionIDs) == 0 {
			return nil, nil
		}
		in("session_id", f.SessionIDs)
	}
	q := `SELECT ` + proxySessionColumns + ` FROM proxy_sessions`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY issued_at, kind, session_id"

	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list proxy sessions: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ProxySessionRow
	for rows.Next() {
		rec, err := scanProxySession(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan proxy session: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list proxy sessions: %w", classifyDriverErr(err))
	}
	return out, nil
}

// TakeProxySession moves an open session to holder, provided from still holds
// it, and reports whether it did. The condition is what lets two processes race
// to restore the same session and only one of them serve it.
func (d *DB) TakeProxySession(kind, id, from, holder string) (bool, error) {
	return d.execOne(`UPDATE proxy_sessions SET holder = ?, updated_at = ?
		WHERE kind = ? AND session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("take over proxy session %s/%s", kind, id),
		holder, formatOptionalTime(time.Now().UTC()), kind, id, from)
}

// ExtendProxySession moves an open session's deadline, provided holder holds
// it, and reports whether it did.
func (d *DB) ExtendProxySession(kind, id, holder string, expiresAt time.Time) (bool, error) {
	return d.execOne(`UPDATE proxy_sessions SET expires_at = ?, updated_at = ?
		WHERE kind = ? AND session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("extend proxy session %s/%s", kind, id),
		formatOptionalTime(expiresAt), formatOptionalTime(time.Now().UTC()), kind, id, holder)
}

// CheckpointProxySession replaces an open session's counters, provided holder
// holds it, and reports whether it did.
func (d *DB) CheckpointProxySession(kind, id, holder, counters string) (bool, error) {
	if strings.TrimSpace(counters) == "" {
		counters = "{}"
	}
	return d.execOne(`UPDATE proxy_sessions SET counters_json = ?, updated_at = ?
		WHERE kind = ? AND session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("checkpoint proxy session %s/%s", kind, id),
		counters, formatOptionalTime(time.Now().UTC()), kind, id, holder)
}

// CloseProxySession marks an open session closed with reason, provided holder
// holds it, and reports whether it did. counters, when non-empty, replaces the
// checkpoint with the session's final count. A session closed once stays
// closed: nothing restores it, and a second close changes nothing.
func (d *DB) CloseProxySession(kind, id, holder string, at time.Time, reason, counters string) (bool, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if strings.TrimSpace(reason) == "" {
		reason = "closed"
	}
	if strings.TrimSpace(counters) == "" {
		return d.execOne(`UPDATE proxy_sessions SET closed_at = ?, close_reason = ?, updated_at = ?
			WHERE kind = ? AND session_id = ? AND holder = ? AND closed_at = ''`,
			fmt.Sprintf("close proxy session %s/%s", kind, id),
			formatOptionalTime(at), reason, formatOptionalTime(time.Now().UTC()), kind, id, holder)
	}
	return d.execOne(`UPDATE proxy_sessions SET closed_at = ?, close_reason = ?, counters_json = ?, updated_at = ?
		WHERE kind = ? AND session_id = ? AND holder = ? AND closed_at = ''`,
		fmt.Sprintf("close proxy session %s/%s", kind, id),
		formatOptionalTime(at), reason, counters, formatOptionalTime(time.Now().UTC()), kind, id, holder)
}

// DeleteProxySession forgets a session, provided holder holds it, and reports
// whether a row went. It is how the janitor retires the record of a session
// that closed or lapsed.
func (d *DB) DeleteProxySession(kind, id, holder string) (bool, error) {
	return d.execOne(`DELETE FROM proxy_sessions WHERE kind = ? AND session_id = ? AND holder = ?`,
		fmt.Sprintf("delete proxy session %s/%s", kind, id), kind, id, holder)
}

// execOne runs a statement that changes at most one row and reports whether
// it changed one.
func (d *DB) execOne(q, what string, args ...any) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(q, args...)
	if err != nil {
		return false, fmt.Errorf("statedb: %s: %w", what, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

type proxySessionScanner interface {
	Scan(dest ...any) error
}

func scanProxySession(s proxySessionScanner) (ProxySessionRow, error) {
	var (
		rec                                     ProxySessionRow
		issuedAt, expiresAt, updatedAt, closeAt string
	)
	if err := s.Scan(&rec.Kind, &rec.SessionID, &rec.TokenSHA256, &rec.LeaseID, &rec.GrantID, &rec.Holder,
		&rec.RunID, &rec.ProjectID, &rec.ExecutorID, &rec.TaskID, &rec.Actor, &rec.Scope, &rec.Counters,
		&issuedAt, &expiresAt, &updatedAt, &closeAt, &rec.CloseReason); err != nil {
		return ProxySessionRow{}, err
	}
	rec.IssuedAt = parseOptionalTime(issuedAt)
	rec.ExpiresAt = parseOptionalTime(expiresAt)
	rec.UpdatedAt = parseOptionalTime(updatedAt)
	rec.ClosedAt = parseOptionalTime(closeAt)
	return rec, nil
}

// ---------------------------------------------------------------------------
// GitHub App token slots
// ---------------------------------------------------------------------------

// AppTokenSlotRow is one GitHub App installation token a lease holds: the
// scope it was minted at and when the token held now expires, never the token.
type AppTokenSlotRow struct {
	LeaseID    string
	GrantID    string
	Holder     string
	SecretID   string
	SecretName string
	// Scope is the broker's JSON account of the mint: installation, repository
	// ids, permissions asked for and granted.
	Scope string
	// Guarded: a git proxy session presents the token, named by SessionID.
	Guarded     bool
	SessionID   string
	EnvExported bool
	// FileName is the lease file an unguarded token is delivered in.
	FileName string
	// TokenExpiresAt is when the token the workload or session holds stops
	// working at GitHub.
	TokenExpiresAt time.Time
	UpdatedAt      time.Time
}

// PutAppTokenSlot records a slot, replacing any row for the same lease and
// grant.
func (d *DB) PutAppTokenSlot(row AppTokenSlotRow) error {
	if strings.TrimSpace(row.LeaseID) == "" || strings.TrimSpace(row.GrantID) == "" {
		return errors.New("statedb: app token slot lease and grant are required")
	}
	if strings.TrimSpace(row.Scope) == "" {
		row.Scope = "{}"
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO app_token_slots(lease_id, grant_id, holder, secret_id, secret_name, scope_json,
		                             guarded, session_id, env_exported, file_name, token_expires_at, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(lease_id, grant_id) DO UPDATE SET
		   holder           = excluded.holder,
		   secret_id        = excluded.secret_id,
		   secret_name      = excluded.secret_name,
		   scope_json       = excluded.scope_json,
		   guarded          = excluded.guarded,
		   session_id       = excluded.session_id,
		   env_exported     = excluded.env_exported,
		   file_name        = excluded.file_name,
		   token_expires_at = excluded.token_expires_at,
		   updated_at       = excluded.updated_at`,
		row.LeaseID, row.GrantID, row.Holder, row.SecretID, row.SecretName, row.Scope,
		boolInt(row.Guarded), row.SessionID, boolInt(row.EnvExported), row.FileName,
		formatOptionalTime(row.TokenExpiresAt), formatOptionalTime(row.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put app token slot %s/%s: %w", row.LeaseID, row.GrantID, classifyDriverErr(err))
	}
	return nil
}

// ListAppTokenSlots returns the slots leaseID holds, or every slot when leaseID
// is empty.
func (d *DB) ListAppTokenSlots(leaseID string) ([]AppTokenSlotRow, error) {
	q := `SELECT lease_id, grant_id, holder, secret_id, secret_name, scope_json, guarded,
	             session_id, env_exported, file_name, token_expires_at, updated_at
	        FROM app_token_slots`
	var args []any
	if leaseID != "" {
		q += " WHERE lease_id = ?"
		args = append(args, leaseID)
	}
	q += " ORDER BY lease_id, grant_id"
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list app token slots: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []AppTokenSlotRow
	for rows.Next() {
		var (
			rec                AppTokenSlotRow
			guarded, exported  int
			expires, updatedAt string
		)
		if err := rows.Scan(&rec.LeaseID, &rec.GrantID, &rec.Holder, &rec.SecretID, &rec.SecretName,
			&rec.Scope, &guarded, &rec.SessionID, &exported, &rec.FileName, &expires, &updatedAt); err != nil {
			return nil, fmt.Errorf("statedb: scan app token slot: %w", classifyDriverErr(err))
		}
		rec.Guarded, rec.EnvExported = guarded != 0, exported != 0
		rec.TokenExpiresAt = parseOptionalTime(expires)
		rec.UpdatedAt = parseOptionalTime(updatedAt)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list app token slots: %w", classifyDriverErr(err))
	}
	return out, nil
}

// UpdateAppTokenSlot rewrites a slot's mutable fields — guarded, session,
// whether the token was exported, the held token's expiry, and its scope when
// row.Scope is set (a restore narrows it to its grant) — provided row.Holder
// holds it, and reports whether it did.
func (d *DB) UpdateAppTokenSlot(row AppTokenSlotRow) (bool, error) {
	return d.execOne(`UPDATE app_token_slots SET guarded = ?, session_id = ?, env_exported = ?,
		token_expires_at = ?, scope_json = COALESCE(NULLIF(?, ''), scope_json), updated_at = ?
		WHERE lease_id = ? AND grant_id = ? AND holder = ?`,
		fmt.Sprintf("update app token slot %s/%s", row.LeaseID, row.GrantID),
		boolInt(row.Guarded), row.SessionID, boolInt(row.EnvExported), formatOptionalTime(row.TokenExpiresAt),
		strings.TrimSpace(row.Scope), formatOptionalTime(time.Now().UTC()), row.LeaseID, row.GrantID, row.Holder)
}

// TakeAppTokenSlots moves every slot of leaseID still held by from to holder,
// and returns how many moved.
func (d *DB) TakeAppTokenSlots(leaseID, from, holder string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`UPDATE app_token_slots SET holder = ?, updated_at = ?
		WHERE lease_id = ? AND holder = ?`, holder, formatOptionalTime(time.Now().UTC()), leaseID, from)
	if err != nil {
		return 0, fmt.Errorf("statedb: take over app token slots of %s: %w", leaseID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DeleteAppTokenSlots forgets the slots of leaseID that holder holds, and
// returns how many went.
func (d *DB) DeleteAppTokenSlots(leaseID, holder string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM app_token_slots WHERE lease_id = ? AND holder = ?`, leaseID, holder)
	if err != nil {
		return 0, fmt.Errorf("statedb: delete app token slots of %s: %w", leaseID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DeleteAppTokenSlot forgets one slot, provided holder holds it.
func (d *DB) DeleteAppTokenSlot(leaseID, grantID, holder string) (bool, error) {
	return d.execOne(`DELETE FROM app_token_slots WHERE lease_id = ? AND grant_id = ? AND holder = ?`,
		fmt.Sprintf("delete app token slot %s/%s", leaseID, grantID), leaseID, grantID, holder)
}

// DeleteOrphanedAppTokenSlots forgets every slot whose lease has no record any
// more — released, retired or swept — and returns how many went. The janitor's
// sweep: a slot outlives its lease only when the process holding both stopped
// between the two deletes.
func (d *DB) DeleteOrphanedAppTokenSlots() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM app_token_slots
		WHERE lease_id NOT IN (SELECT lease_id FROM secret_leases)`)
	if err != nil {
		return 0, fmt.Errorf("statedb: delete orphaned app token slots: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
