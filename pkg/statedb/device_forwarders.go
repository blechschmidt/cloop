package statedb

// device_forwarders.go is the durable half of the device-forwarder enrollment
// handshake (Task 20429), mirroring executor_agents.go. A forwarder is not an
// executor — it runs no work — so its rows live in their own tables, and the
// single-use latch on redemption lives in the UPDATE ... WHERE clause for the
// same reason it does for agents.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors for forwarder rows, reusing the executor ones' meaning.
var (
	// ErrForwarderEnrollmentNotFound reports no such enrollment token.
	ErrForwarderEnrollmentNotFound = errors.New("statedb: forwarder enrollment token not found")
	// ErrForwarderEnrollmentSpent reports a token already redeemed.
	ErrForwarderEnrollmentSpent = errors.New("statedb: forwarder enrollment token already redeemed")
	// ErrForwarderNotFound reports no such forwarder credential.
	ErrForwarderNotFound = errors.New("statedb: forwarder not found")
)

// ForwarderEnrollmentRow is one row of forwarder_enrollment_tokens.
type ForwarderEnrollmentRow struct {
	ID                  string
	Name                string
	SecretHash          string
	DeviceJSON          string
	Owner               string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	CreatedBy           string
	RedeemedAt          time.Time
	RedeemedForwarderID string
	RevokedAt           time.Time
}

// ForwarderRow is one row of device_forwarders.
type ForwarderRow struct {
	ForwarderID  string
	Name         string
	SecretHash   string
	DeviceJSON   string
	Owner        string
	CreatedAt    time.Time
	LastSeen     time.Time
	RevokedAt    time.Time
	EnrollmentID string
	Status       string
	StatusAt     time.Time
}

// PutForwarderEnrollment inserts or updates a minted token.
func (d *DB) PutForwarderEnrollment(row ForwarderEnrollmentRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: forwarder enrollment id is required")
	}
	if strings.TrimSpace(row.SecretHash) == "" {
		return fmt.Errorf("statedb: forwarder enrollment %q has an empty secret hash", row.ID)
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	if strings.TrimSpace(row.DeviceJSON) == "" {
		row.DeviceJSON = "{}"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO forwarder_enrollment_tokens(id, name, secret_hash, device_json, owner,
		        created_at, expires_at, created_by, redeemed_at, redeemed_forwarder_id, revoked_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   name       = excluded.name,
		   device_json= excluded.device_json,
		   owner      = excluded.owner,
		   expires_at = excluded.expires_at`,
		row.ID, row.Name, row.SecretHash, row.DeviceJSON, row.Owner,
		row.CreatedAt.UTC().Format(time.RFC3339Nano), formatOptionalTime(row.ExpiresAt), row.CreatedBy,
		formatOptionalTime(row.RedeemedAt), row.RedeemedForwarderID, formatOptionalTime(row.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put forwarder enrollment %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetForwarderEnrollment returns one token by ID.
func (d *DB) GetForwarderEnrollment(id string) (ForwarderEnrollmentRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT id, name, secret_hash, device_json, owner, created_at, expires_at,
		        created_by, redeemed_at, redeemed_forwarder_id, revoked_at
		 FROM forwarder_enrollment_tokens WHERE id = ?`, id)
	out, err := scanForwarderEnrollment(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwarderEnrollmentRow{}, fmt.Errorf("%w: %q", ErrForwarderEnrollmentNotFound, id)
	}
	if err != nil {
		return ForwarderEnrollmentRow{}, fmt.Errorf("statedb: get forwarder enrollment %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// RedeemForwarderEnrollment atomically claims a token for forwarderID.
func (d *DB) RedeemForwarderEnrollment(id, forwarderID string, at time.Time) error {
	if strings.TrimSpace(forwarderID) == "" {
		return errors.New("statedb: redeeming forwarder id is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE forwarder_enrollment_tokens
		 SET redeemed_at = ?, redeemed_forwarder_id = ?
		 WHERE id = ? AND redeemed_at = '' AND revoked_at = ''`,
		formatOptionalTime(at), forwarderID, id)
	if err != nil {
		return fmt.Errorf("statedb: redeem forwarder enrollment %q: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("statedb: redeem forwarder enrollment %q: %w", id, classifyDriverErr(err))
	}
	if n == 0 {
		var exists int
		if scanErr := d.conn.QueryRow(
			`SELECT COUNT(1) FROM forwarder_enrollment_tokens WHERE id = ?`, id).Scan(&exists); scanErr == nil && exists == 0 {
			return fmt.Errorf("%w: %q", ErrForwarderEnrollmentNotFound, id)
		}
		return fmt.Errorf("%w: %q", ErrForwarderEnrollmentSpent, id)
	}
	return nil
}

// RevokeForwarderEnrollment marks a token revoked.
func (d *DB) RevokeForwarderEnrollment(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE forwarder_enrollment_tokens SET revoked_at = ? WHERE id = ?`,
		formatOptionalTime(at), id)
	if err != nil {
		return fmt.Errorf("statedb: revoke forwarder enrollment %q: %w", id, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: %q", ErrForwarderEnrollmentNotFound, id)
	}
	return nil
}

// ListForwarderEnrollments returns every token, newest first.
func (d *DB) ListForwarderEnrollments() ([]ForwarderEnrollmentRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT id, name, secret_hash, device_json, owner, created_at, expires_at,
		        created_by, redeemed_at, redeemed_forwarder_id, revoked_at
		 FROM forwarder_enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list forwarder enrollments: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ForwarderEnrollmentRow
	for rows.Next() {
		rec, err := scanForwarderEnrollment(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan forwarder enrollment: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// PutForwarder inserts or updates a forwarder credential.
func (d *DB) PutForwarder(row ForwarderRow) error {
	if strings.TrimSpace(row.ForwarderID) == "" {
		return errors.New("statedb: forwarder id is required")
	}
	if strings.TrimSpace(row.SecretHash) == "" {
		return fmt.Errorf("statedb: forwarder %q has an empty secret hash", row.ForwarderID)
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	if strings.TrimSpace(row.DeviceJSON) == "" {
		row.DeviceJSON = "{}"
	}
	if strings.TrimSpace(row.Status) == "" {
		row.Status = "offline"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO device_forwarders(forwarder_id, name, secret_hash, device_json, owner,
		        created_at, last_seen, revoked_at, enrollment_id, status, status_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(forwarder_id) DO UPDATE SET
		   name        = excluded.name,
		   device_json = excluded.device_json,
		   owner       = excluded.owner,
		   enrollment_id = excluded.enrollment_id`,
		row.ForwarderID, row.Name, row.SecretHash, row.DeviceJSON, row.Owner,
		row.CreatedAt.UTC().Format(time.RFC3339Nano), formatOptionalTime(row.LastSeen),
		formatOptionalTime(row.RevokedAt), row.EnrollmentID, row.Status, formatOptionalTime(row.StatusAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put forwarder %q: %w", row.ForwarderID, classifyDriverErr(err))
	}
	return nil
}

// GetForwarder returns one forwarder by ID.
func (d *DB) GetForwarder(forwarderID string) (ForwarderRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT forwarder_id, name, secret_hash, device_json, owner, created_at, last_seen,
		        revoked_at, enrollment_id, status, status_at
		 FROM device_forwarders WHERE forwarder_id = ?`, forwarderID)
	out, err := scanForwarder(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwarderRow{}, fmt.Errorf("%w: %q", ErrForwarderNotFound, forwarderID)
	}
	if err != nil {
		return ForwarderRow{}, fmt.Errorf("statedb: get forwarder %q: %w", forwarderID, classifyDriverErr(err))
	}
	return out, nil
}

// RevokeForwarder marks a forwarder credential revoked.
func (d *DB) RevokeForwarder(forwarderID string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE device_forwarders SET revoked_at = ? WHERE forwarder_id = ?`,
		formatOptionalTime(at), forwarderID)
	if err != nil {
		return fmt.Errorf("statedb: revoke forwarder %q: %w", forwarderID, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: %q", ErrForwarderNotFound, forwarderID)
	}
	return nil
}

// TouchForwarder records that a forwarder was seen.
func (d *DB) TouchForwarder(forwarderID string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`UPDATE device_forwarders SET last_seen = ? WHERE forwarder_id = ?`,
		formatOptionalTime(at), forwarderID)
	if err != nil {
		return fmt.Errorf("statedb: touch forwarder %q: %w", forwarderID, classifyDriverErr(err))
	}
	return nil
}

// SetForwarderStatus records a forwarder's connectivity for the dashboard.
func (d *DB) SetForwarderStatus(forwarderID, status string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`UPDATE device_forwarders SET status = ?, status_at = ? WHERE forwarder_id = ?`,
		status, formatOptionalTime(at), forwarderID)
	if err != nil {
		return fmt.Errorf("statedb: set forwarder %q status: %w", forwarderID, classifyDriverErr(err))
	}
	return nil
}

// ListForwarders returns every forwarder, newest first.
func (d *DB) ListForwarders() ([]ForwarderRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT forwarder_id, name, secret_hash, device_json, owner, created_at, last_seen,
		        revoked_at, enrollment_id, status, status_at
		 FROM device_forwarders ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list forwarders: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ForwarderRow
	for rows.Next() {
		rec, err := scanForwarder(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan forwarder: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func scanForwarderEnrollment(s rowScanner) (ForwarderEnrollmentRow, error) {
	var r ForwarderEnrollmentRow
	var created, expires, redeemed, revoked string
	if err := s.Scan(&r.ID, &r.Name, &r.SecretHash, &r.DeviceJSON, &r.Owner,
		&created, &expires, &r.CreatedBy, &redeemed, &r.RedeemedForwarderID, &revoked); err != nil {
		return ForwarderEnrollmentRow{}, err
	}
	r.CreatedAt = parseOptionalTime(created)
	r.ExpiresAt = parseOptionalTime(expires)
	r.RedeemedAt = parseOptionalTime(redeemed)
	r.RevokedAt = parseOptionalTime(revoked)
	return r, nil
}

func scanForwarder(s rowScanner) (ForwarderRow, error) {
	var r ForwarderRow
	var created, lastSeen, revoked, statusAt string
	if err := s.Scan(&r.ForwarderID, &r.Name, &r.SecretHash, &r.DeviceJSON, &r.Owner,
		&created, &lastSeen, &revoked, &r.EnrollmentID, &r.Status, &statusAt); err != nil {
		return ForwarderRow{}, err
	}
	r.CreatedAt = parseOptionalTime(created)
	r.LastSeen = parseOptionalTime(lastSeen)
	r.RevokedAt = parseOptionalTime(revoked)
	r.StatusAt = parseOptionalTime(statusAt)
	return r, nil
}
