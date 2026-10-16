package statedb

// forwarder_bindings.go stores which projects a device forwarder's device is
// made available to, and the requests for that (Task 20430; migration 0078).
//
// A binding is never deleted: revoking one stamps revoked_at, so the audit
// trail and the dashboard can still name what a run held and who took it back.
// Writes are conditional UPDATEs and INSERT ... ON CONFLICT DO UPDATE of the
// mutable columns only — never a row replacement, which an older binary
// sharing the control plane would turn into a column wipe.

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	// ErrForwarderBindingNotFound reports no binding with an id.
	ErrForwarderBindingNotFound = errors.New("statedb: forwarder binding not found")
	// ErrForwarderBindingRequestNotFound reports no binding request with an id.
	ErrForwarderBindingRequestNotFound = errors.New("statedb: forwarder binding request not found")
)

// ForwarderBindingRow is one row of forwarder_bindings.
type ForwarderBindingRow struct {
	ID              string
	ForwarderID     string
	Project         string
	VirtualExecutor string
	InterfaceJSON   string
	Note            string
	CreatedBy       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RequestID       string
	RevokedAt       time.Time
	RevokedBy       string
	RevokeReason    string
}

// Revoked reports whether the binding was revoked.
func (r ForwarderBindingRow) Revoked() bool { return !r.RevokedAt.IsZero() }

// Expired reports whether the binding's TTL has run out as of now.
func (r ForwarderBindingRow) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// Active reports whether the binding is in force as of now.
func (r ForwarderBindingRow) Active(now time.Time) bool {
	return !r.Revoked() && !r.Expired(now)
}

// ForwarderBindingFilter narrows ListForwarderBindings. Zero fields match
// everything; a non-zero ActiveAt keeps only bindings in force then.
type ForwarderBindingFilter struct {
	Project     string
	ForwarderID string
	ActiveAt    time.Time
}

const forwarderBindingCols = `id, forwarder_id, project, virtual_executor, interface_json, note,
	created_by, created_at, expires_at, request_id, revoked_at, revoked_by, revoke_reason`

// PutForwarderBinding inserts a binding, or updates its mutable fields — its
// expiry, note and interface shape — when the id exists.
func (d *DB) PutForwarderBinding(row ForwarderBindingRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: forwarder binding id is required")
	}
	if strings.TrimSpace(row.ForwarderID) == "" || strings.TrimSpace(row.Project) == "" {
		return fmt.Errorf("statedb: forwarder binding %q needs a forwarder and a project", row.ID)
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO forwarder_bindings(`+forwarderBindingCols+`)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   interface_json = excluded.interface_json,
		   note           = excluded.note,
		   expires_at     = excluded.expires_at`,
		row.ID, row.ForwarderID, row.Project, row.VirtualExecutor, row.InterfaceJSON, row.Note,
		row.CreatedBy, row.CreatedAt.UTC().Format(time.RFC3339Nano), formatOptionalTime(row.ExpiresAt),
		row.RequestID, formatOptionalTime(row.RevokedAt), row.RevokedBy, row.RevokeReason,
	)
	if err != nil {
		return fmt.Errorf("statedb: put forwarder binding %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetForwarderBinding returns one binding.
func (d *DB) GetForwarderBinding(id string) (ForwarderBindingRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(`SELECT `+forwarderBindingCols+` FROM forwarder_bindings WHERE id = ?`, id)
	out, err := scanForwarderBinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwarderBindingRow{}, fmt.Errorf("%w: %q", ErrForwarderBindingNotFound, id)
	}
	if err != nil {
		return ForwarderBindingRow{}, fmt.Errorf("statedb: get forwarder binding %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// ListForwarderBindings returns the bindings f matches, newest first.
func (d *DB) ListForwarderBindings(f ForwarderBindingFilter) ([]ForwarderBindingRow, error) {
	q := `SELECT ` + forwarderBindingCols + ` FROM forwarder_bindings`
	var where []string
	var args []any
	if f.Project != "" {
		where = append(where, "project = ?")
		args = append(args, f.Project)
	}
	if f.ForwarderID != "" {
		where = append(where, "forwarder_id = ?")
		args = append(args, f.ForwarderID)
	}
	if !f.ActiveAt.IsZero() {
		where = append(where, "revoked_at = ''")
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	all, err := d.queryForwarderBindings(q, args...)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		// Expiry is compared as a time, not as text: RFC3339 strings with
		// different fractional precision do not sort chronologically.
		if !f.ActiveAt.IsZero() && !r.Active(f.ActiveAt) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (d *DB) queryForwarderBindings(q string, args ...any) ([]ForwarderBindingRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list forwarder bindings: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ForwarderBindingRow
	for rows.Next() {
		r, err := scanForwarderBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan forwarder binding: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list forwarder bindings: %w", classifyDriverErr(err))
	}
	return out, nil
}

// RevokeForwarderBinding stamps a binding revoked. It reports whether this
// call revoked it; a binding already revoked is left as it was.
func (d *DB) RevokeForwarderBinding(id, by, reason string, at time.Time) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE forwarder_bindings SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
		 WHERE id = ? AND revoked_at = ''`,
		formatOptionalTime(at), by, reason, id)
	if err != nil {
		return false, fmt.Errorf("statedb: revoke forwarder binding %q: %w", id, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		var exists int
		if scanErr := d.conn.QueryRow(`SELECT COUNT(1) FROM forwarder_bindings WHERE id = ?`, id).Scan(&exists); scanErr == nil && exists == 0 {
			return false, fmt.Errorf("%w: %q", ErrForwarderBindingNotFound, id)
		}
		return false, nil
	}
	return true, nil
}

// RevokeForwarderBindingsOf revokes every live binding of one forwarder — what
// revoking the forwarder itself implies — and returns their ids.
func (d *DB) RevokeForwarderBindingsOf(forwarderID, by, reason string, at time.Time) ([]string, error) {
	live, err := d.ListForwarderBindings(ForwarderBindingFilter{ForwarderID: forwarderID})
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, b := range live {
		if b.Revoked() {
			continue
		}
		ok, err := d.RevokeForwarderBinding(b.ID, by, reason, at)
		if err != nil {
			return ids, err
		}
		if ok {
			ids = append(ids, b.ID)
		}
	}
	return ids, nil
}

func scanForwarderBinding(s rowScanner) (ForwarderBindingRow, error) {
	var r ForwarderBindingRow
	var created, expires, revoked string
	if err := s.Scan(&r.ID, &r.ForwarderID, &r.Project, &r.VirtualExecutor, &r.InterfaceJSON, &r.Note,
		&r.CreatedBy, &created, &expires, &r.RequestID, &revoked, &r.RevokedBy, &r.RevokeReason); err != nil {
		return ForwarderBindingRow{}, err
	}
	r.CreatedAt = parseOptionalTime(created)
	r.ExpiresAt = parseOptionalTime(expires)
	r.RevokedAt = parseOptionalTime(revoked)
	return r, nil
}

// Binding request states, as for secret grant requests.
const (
	ForwarderRequestPending   = "pending"
	ForwarderRequestApproved  = "approved"
	ForwarderRequestDenied    = "denied"
	ForwarderRequestWithdrawn = "withdrawn"
	ForwarderRequestExpired   = "expired"
)

// ForwarderBindingRequestRow is one row of forwarder_binding_requests.
type ForwarderBindingRequestRow struct {
	ID              string
	ForwarderID     string
	Project         string
	VirtualExecutor string
	InterfaceJSON   string
	TTL             time.Duration
	Justification   string
	RequestedBy     string
	State           string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedBy       string
	DecidedAt       time.Time
	DecisionNote    string
	BindingID       string
}

// Lapsed reports whether a pending request has waited past its expiry.
func (r ForwarderBindingRequestRow) Lapsed(now time.Time) bool {
	return r.State == ForwarderRequestPending && !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

const forwarderRequestCols = `id, forwarder_id, project, virtual_executor, interface_json, ttl_seconds,
	justification, requested_by, state, created_at, expires_at, decided_by, decided_at,
	decision_note, binding_id`

// PutForwarderBindingRequest files a new request. An existing id is refused:
// a request's decision is changed only by DecideForwarderBindingRequest.
func (d *DB) PutForwarderBindingRequest(row ForwarderBindingRequestRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: forwarder binding request id is required")
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	if row.State == "" {
		row.State = ForwarderRequestPending
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO forwarder_binding_requests(`+forwarderRequestCols+`)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.ForwarderID, row.Project, row.VirtualExecutor, row.InterfaceJSON,
		int64(row.TTL/time.Second), row.Justification, row.RequestedBy, row.State,
		row.CreatedAt.UTC().Format(time.RFC3339Nano), formatOptionalTime(row.ExpiresAt),
		row.DecidedBy, formatOptionalTime(row.DecidedAt), row.DecisionNote, row.BindingID,
	)
	if err != nil {
		return fmt.Errorf("statedb: file forwarder binding request %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetForwarderBindingRequest returns one request.
func (d *DB) GetForwarderBindingRequest(id string) (ForwarderBindingRequestRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(`SELECT `+forwarderRequestCols+` FROM forwarder_binding_requests WHERE id = ?`, id)
	out, err := scanForwarderRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwarderBindingRequestRow{}, fmt.Errorf("%w: %q", ErrForwarderBindingRequestNotFound, id)
	}
	if err != nil {
		return ForwarderBindingRequestRow{}, fmt.Errorf("statedb: get forwarder binding request %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// ListForwarderBindingRequests returns requests, newest first; a non-empty
// state keeps only those in it.
func (d *DB) ListForwarderBindingRequests(state string) ([]ForwarderBindingRequestRow, error) {
	q := `SELECT ` + forwarderRequestCols + ` FROM forwarder_binding_requests`
	var args []any
	if state != "" {
		q += ` WHERE state = ?`
		args = append(args, state)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list forwarder binding requests: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ForwarderBindingRequestRow
	for rows.Next() {
		r, err := scanForwarderRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan forwarder binding request: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list forwarder binding requests: %w", classifyDriverErr(err))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// DecideForwarderBindingRequest moves a pending request to state, recording
// who decided and, for an approval, the binding it minted. It reports whether
// this call decided it: a request decided by someone else first is left alone.
func (d *DB) DecideForwarderBindingRequest(id, state, by, note, bindingID string, at time.Time) (bool, error) {
	switch state {
	case ForwarderRequestApproved, ForwarderRequestDenied, ForwarderRequestWithdrawn, ForwarderRequestExpired:
	default:
		return false, fmt.Errorf("statedb: %q is not a decision", state)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE forwarder_binding_requests
		 SET state = ?, decided_by = ?, decided_at = ?, decision_note = ?, binding_id = ?
		 WHERE id = ? AND state = 'pending'`,
		state, by, formatOptionalTime(at), note, bindingID, id)
	if err != nil {
		return false, fmt.Errorf("statedb: decide forwarder binding request %q: %w", id, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetForwarderBindingRequestBinding records the binding an approval minted,
// on a request already marked approved.
func (d *DB) SetForwarderBindingRequestBinding(id, bindingID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE forwarder_binding_requests SET binding_id = ? WHERE id = ? AND state = 'approved'`,
		bindingID, id)
	if err != nil {
		return fmt.Errorf("statedb: record the binding of request %q: %w", id, classifyDriverErr(err))
	}
	return nil
}

// ExpireForwarderBindingRequests marks every pending request that has waited
// past its expiry as expired and returns them.
func (d *DB) ExpireForwarderBindingRequests(now time.Time) ([]ForwarderBindingRequestRow, error) {
	pending, err := d.ListForwarderBindingRequests(ForwarderRequestPending)
	if err != nil {
		return nil, err
	}
	var out []ForwarderBindingRequestRow
	for _, r := range pending {
		if !r.Lapsed(now) {
			continue
		}
		ok, err := d.DecideForwarderBindingRequest(r.ID, ForwarderRequestExpired, "", "the request was not decided before it lapsed", "", now)
		if err != nil {
			return out, err
		}
		if ok {
			r.State = ForwarderRequestExpired
			out = append(out, r)
		}
	}
	return out, nil
}

func scanForwarderRequest(s rowScanner) (ForwarderBindingRequestRow, error) {
	var r ForwarderBindingRequestRow
	var ttl int64
	var created, expires, decided string
	if err := s.Scan(&r.ID, &r.ForwarderID, &r.Project, &r.VirtualExecutor, &r.InterfaceJSON, &ttl,
		&r.Justification, &r.RequestedBy, &r.State, &created, &expires, &r.DecidedBy, &decided,
		&r.DecisionNote, &r.BindingID); err != nil {
		return ForwarderBindingRequestRow{}, err
	}
	r.TTL = time.Duration(ttl) * time.Second
	r.CreatedAt = parseOptionalTime(created)
	r.ExpiresAt = parseOptionalTime(expires)
	r.DecidedAt = parseOptionalTime(decided)
	return r, nil
}
