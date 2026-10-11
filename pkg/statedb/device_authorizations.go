package statedb

// Device authorizations: the codes a terminal asks for when it signs in to an
// SSO hub (Task 20412). See migrations/0066_device_login.sql for what each
// column holds and why none of them is a credential; this file is the
// mechanical accessor layer. Which transitions are allowed — pending to
// approved or denied, approved to consumed, the slow_down rule — is decided in
// pkg/oidcauth, which hands UpdateDeviceAuthorization the change to apply.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeviceAuthorizationRow is one row of device_authorizations.
type DeviceAuthorizationRow struct {
	DeviceHash     string
	UserCodeHash   string
	CredentialHash string
	Status         string

	ClientIP        string
	ClientUserAgent string
	ClientHostname  string

	CreatedAt       time.Time
	ExpiresAt       time.Time
	IntervalSeconds int
	LastPolledAt    time.Time

	Approver        string
	ApproverSession string
	Subject         string
	DecidedAt       time.Time
	Reason          string
}

const deviceColumns = `device_hash, user_code_hash, credential_hash, status,
	client_ip, client_user_agent, client_hostname,
	created_at, expires_at, interval_seconds, last_polled_at,
	approver, approver_session, subject, decided_at, reason`

// PutDeviceAuthorization inserts a row. An insert rather than an upsert, as
// for sessions: the device code is 256 random bits, and silently replacing a
// row would hand one terminal's approval to another.
func (d *DB) PutDeviceAuthorization(row DeviceAuthorizationRow) error {
	if strings.TrimSpace(row.DeviceHash) == "" {
		return errors.New("statedb: device authorization needs a device code digest")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`INSERT INTO device_authorizations(`+deviceColumns+`)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, deviceArgs(row)...)
	if err != nil {
		return fmt.Errorf("statedb: insert device authorization: %w", classifyDriverErr(err))
	}
	return nil
}

// GetDeviceAuthorization returns the row for a device code digest, or an
// error wrapping ErrDeviceAuthorizationNotFound.
func (d *DB) GetDeviceAuthorization(deviceHash string) (DeviceAuthorizationRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return getDeviceAuthorization(d.conn.QueryRow(
		`SELECT `+deviceColumns+` FROM device_authorizations WHERE device_hash = ?`, deviceHash))
}

// GetDeviceAuthorizationByUserCode returns the newest row for a user code
// digest. Newest, because the index is not unique: a code drawn again after its
// first holder expired would otherwise resolve to the dead one.
func (d *DB) GetDeviceAuthorizationByUserCode(userCodeHash string) (DeviceAuthorizationRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return getDeviceAuthorization(d.conn.QueryRow(
		`SELECT `+deviceColumns+` FROM device_authorizations WHERE user_code_hash = ?
		 ORDER BY created_at DESC LIMIT 1`, userCodeHash))
}

func getDeviceAuthorization(row *sql.Row) (DeviceAuthorizationRow, error) {
	out, err := scanDeviceAuthorization(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceAuthorizationRow{}, ErrDeviceAuthorizationNotFound
	}
	if err != nil {
		return DeviceAuthorizationRow{}, fmt.Errorf("statedb: get device authorization: %w", classifyDriverErr(err))
	}
	return out, nil
}

// UpdateDeviceAuthorization reads the row for deviceHash, hands it to change,
// and writes it back when change reports that it changed it — all under the
// database's write lock, so two hub processes deciding the same code (an
// approval racing a denial, two polls racing the exchange) are serialised and
// the second one sees the first one's result. It returns the row as stored
// afterwards.
//
// change must not touch the database: it runs inside the transaction.
func (d *DB) UpdateDeviceAuthorization(deviceHash string, change func(*DeviceAuthorizationRow) (bool, error)) (DeviceAuthorizationRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return DeviceAuthorizationRow{}, fmt.Errorf("statedb: update device authorization: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	// Write first, read second: the no-op update takes the write lock, so the
	// read below cannot be overtaken by another connection's commit between
	// it and our own write — the race takeWriteLock exists for in keys.go.
	if _, err := tx.Exec(`UPDATE device_authorizations SET status = status WHERE device_hash = ?`, deviceHash); err != nil {
		return DeviceAuthorizationRow{}, fmt.Errorf("statedb: lock device authorization: %w", classifyDriverErr(err))
	}
	row, err := scanDeviceAuthorization(tx.QueryRow(
		`SELECT `+deviceColumns+` FROM device_authorizations WHERE device_hash = ?`, deviceHash))
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceAuthorizationRow{}, ErrDeviceAuthorizationNotFound
	}
	if err != nil {
		return DeviceAuthorizationRow{}, fmt.Errorf("statedb: read device authorization: %w", classifyDriverErr(err))
	}
	changed, err := change(&row)
	if err != nil {
		return DeviceAuthorizationRow{}, err
	}
	if !changed {
		return row, nil
	}
	row.DeviceHash = deviceHash // the key is not the change's to move
	if _, err := tx.Exec(`UPDATE device_authorizations SET
		user_code_hash = ?, credential_hash = ?, status = ?,
		client_ip = ?, client_user_agent = ?, client_hostname = ?,
		created_at = ?, expires_at = ?, interval_seconds = ?, last_polled_at = ?,
		approver = ?, approver_session = ?, subject = ?, decided_at = ?, reason = ?
		WHERE device_hash = ?`, append(deviceArgs(row)[1:], deviceHash)...); err != nil {
		return DeviceAuthorizationRow{}, fmt.Errorf("statedb: write device authorization: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return DeviceAuthorizationRow{}, fmt.Errorf("statedb: update device authorization: %w", classifyDriverErr(err))
	}
	return row, nil
}

// DeleteDeviceAuthorizationsBefore removes the rows whose expires_at is at or
// before cutoff and returns them, so the caller can act on an approval nobody
// collected. Read and deleted in one transaction, for the reason
// DeleteExpiredSessions gives.
func (d *DB) DeleteDeviceAuthorizationsBefore(cutoff time.Time) ([]DeviceAuthorizationRow, error) {
	at := cutoff.UTC().Format(time.RFC3339Nano)
	const where = `WHERE expires_at <> '' AND expires_at <= ?`

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: sweep device authorizations: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.Query(`SELECT `+deviceColumns+` FROM device_authorizations `+where, at)
	if err != nil {
		return nil, fmt.Errorf("statedb: select expired device authorizations: %w", classifyDriverErr(err))
	}
	doomed, err := collectDeviceAuthorizations(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(doomed) == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(`DELETE FROM device_authorizations `+where, at); err != nil {
		return nil, fmt.Errorf("statedb: sweep device authorizations: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: sweep device authorizations: %w", classifyDriverErr(err))
	}
	return doomed, nil
}

// CountDeviceAuthorizations counts the rows with created_at after since — the
// code-issuing rate a hub with several members shares.
func (d *DB) CountDeviceAuthorizations(since time.Time) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var n int
	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM device_authorizations WHERE created_at > ?`,
		since.UTC().Format(time.RFC3339Nano)).Scan(&n); err != nil {
		return 0, fmt.Errorf("statedb: count device authorizations: %w", classifyDriverErr(err))
	}
	return n, nil
}

func deviceArgs(row DeviceAuthorizationRow) []any {
	interval := row.IntervalSeconds
	if interval <= 0 {
		interval = 5
	}
	return []any{
		row.DeviceHash, row.UserCodeHash, row.CredentialHash, defaultString(row.Status, "pending"),
		row.ClientIP, row.ClientUserAgent, row.ClientHostname,
		formatOptionalTime(row.CreatedAt), formatOptionalTime(row.ExpiresAt), interval,
		formatOptionalTime(row.LastPolledAt),
		row.Approver, row.ApproverSession, row.Subject, formatOptionalTime(row.DecidedAt), row.Reason,
	}
}

func scanDeviceAuthorization(sc rowScanner) (DeviceAuthorizationRow, error) {
	var (
		out                                 DeviceAuthorizationRow
		created, expires, polled, decidedAt string
	)
	if err := sc.Scan(
		&out.DeviceHash, &out.UserCodeHash, &out.CredentialHash, &out.Status,
		&out.ClientIP, &out.ClientUserAgent, &out.ClientHostname,
		&created, &expires, &out.IntervalSeconds, &polled,
		&out.Approver, &out.ApproverSession, &out.Subject, &decidedAt, &out.Reason,
	); err != nil {
		return DeviceAuthorizationRow{}, err
	}
	out.CreatedAt = parseOptionalTime(created)
	out.ExpiresAt = parseOptionalTime(expires)
	out.LastPolledAt = parseOptionalTime(polled)
	out.DecidedAt = parseOptionalTime(decidedAt)
	return out, nil
}

func collectDeviceAuthorizations(rows *sql.Rows) ([]DeviceAuthorizationRow, error) {
	var out []DeviceAuthorizationRow
	for rows.Next() {
		row, err := scanDeviceAuthorization(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan device authorization: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: iterate device authorizations: %w", classifyDriverErr(err))
	}
	return out, nil
}
