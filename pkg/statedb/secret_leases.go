// Durable record of live secret leases (Task 20382).
//
// Rows for migrations/0057_secret_leases.sql. See that file for why a lease
// needs a record outside the process that issued it. This file owns the SQL;
// what a record holds is pkg/secretbroker's business (it arrives here as an
// opaque JSON document) and what to do with one whose holder stopped is
// pkg/ui's.

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SecretLeaseRow is one live lease. It says who holds the lease and who it was
// issued to, never what it carries.
type SecretLeaseRow struct {
	LeaseID string
	// Holder is the hub process keeping the lease alive.
	Holder     string
	ExecutorID string
	ProjectID  string
	RunID      string
	// Record is the broker's JSON account of the lease: requester, actor,
	// kinds, grant ids.
	Record    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	UpdatedAt time.Time
}

// PutSecretLease records a lease, replacing any row with the same id.
func (d *DB) PutSecretLease(row SecretLeaseRow) error {
	if strings.TrimSpace(row.LeaseID) == "" {
		return errors.New("statedb: secret lease id is required")
	}
	if strings.TrimSpace(row.Record) == "" {
		row.Record = "{}"
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO secret_leases(lease_id, holder, executor_id, project_id, run_id,
		                           record_json, issued_at, expires_at, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(lease_id) DO UPDATE SET
		   holder      = excluded.holder,
		   executor_id = excluded.executor_id,
		   project_id  = excluded.project_id,
		   run_id      = excluded.run_id,
		   record_json = excluded.record_json,
		   issued_at   = excluded.issued_at,
		   expires_at  = excluded.expires_at,
		   updated_at  = excluded.updated_at`,
		row.LeaseID, row.Holder, row.ExecutorID, row.ProjectID, row.RunID, row.Record,
		formatOptionalTime(row.IssuedAt), formatOptionalTime(row.ExpiresAt), formatOptionalTime(row.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put secret lease %q: %w", row.LeaseID, classifyDriverErr(err))
	}
	return nil
}

// GetSecretLease returns one lease, or a wrapped ErrSecretLeaseNotFound.
func (d *DB) GetSecretLease(leaseID string) (SecretLeaseRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT lease_id, holder, executor_id, project_id, run_id, record_json,
		        issued_at, expires_at, updated_at
		   FROM secret_leases WHERE lease_id = ?`, leaseID)
	rec, err := scanSecretLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SecretLeaseRow{}, fmt.Errorf("%w: %s", ErrSecretLeaseNotFound, leaseID)
	}
	if err != nil {
		return SecretLeaseRow{}, fmt.Errorf("statedb: get secret lease %q: %w", leaseID, classifyDriverErr(err))
	}
	return rec, nil
}

// ListSecretLeases returns every recorded lease, oldest first.
func (d *DB) ListSecretLeases() ([]SecretLeaseRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT lease_id, holder, executor_id, project_id, run_id, record_json,
		        issued_at, expires_at, updated_at
		   FROM secret_leases ORDER BY issued_at, lease_id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list secret leases: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []SecretLeaseRow
	for rows.Next() {
		rec, err := scanSecretLease(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan secret lease: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list secret leases: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ExtendSecretLease moves a lease's deadline, provided holder still holds it,
// and reports whether it did. A lease taken over by another process is not
// extended by the one that lost it.
func (d *DB) ExtendSecretLease(leaseID, holder string, expiresAt time.Time) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE secret_leases SET expires_at = ?, updated_at = ?
		  WHERE lease_id = ? AND holder = ?`,
		formatOptionalTime(expiresAt), formatOptionalTime(time.Now().UTC()), leaseID, holder)
	if err != nil {
		return false, fmt.Errorf("statedb: extend secret lease %q: %w", leaseID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// TakeSecretLease moves a lease to holder, provided it is still held by from,
// and reports whether it did. The condition is what lets two processes race to
// adopt the same run and only one of them hold its lease.
func (d *DB) TakeSecretLease(leaseID, from, holder string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE secret_leases SET holder = ?, updated_at = ?
		  WHERE lease_id = ? AND holder = ?`,
		holder, formatOptionalTime(time.Now().UTC()), leaseID, from)
	if err != nil {
		return false, fmt.Errorf("statedb: take over secret lease %q: %w", leaseID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RewriteSecretLeaseRecord replaces a lease's record document, provided holder
// still holds it, and reports whether it did (Task 20403): a grant withdrawn
// from a live lease, or one standing on its successor, is written into the
// record so the process that takes the lease over inherits it.
func (d *DB) RewriteSecretLeaseRecord(leaseID, holder, record string) (bool, error) {
	if strings.TrimSpace(record) == "" {
		record = "{}"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE secret_leases SET record_json = ?, updated_at = ?
		  WHERE lease_id = ? AND holder = ?`,
		record, formatOptionalTime(time.Now().UTC()), leaseID, holder)
	if err != nil {
		return false, fmt.Errorf("statedb: rewrite secret lease %q: %w", leaseID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DeleteSecretLease forgets a lease, provided holder still holds it, and
// reports whether a row went. A missing row is not an error: a lease can be
// released twice — once when its run ends, once by a revocation that raced
// it — and neither call should fail.
func (d *DB) DeleteSecretLease(leaseID, holder string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM secret_leases WHERE lease_id = ? AND holder = ?`, leaseID, holder)
	if err != nil {
		return false, fmt.Errorf("statedb: delete secret lease %q: %w", leaseID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// secretLeaseScanner is the part of *sql.Row and *sql.Rows scanSecretLease uses.
type secretLeaseScanner interface {
	Scan(dest ...any) error
}

func scanSecretLease(s secretLeaseScanner) (SecretLeaseRow, error) {
	var (
		rec                           SecretLeaseRow
		issuedAt, expiresAt, updateAt string
	)
	if err := s.Scan(&rec.LeaseID, &rec.Holder, &rec.ExecutorID, &rec.ProjectID, &rec.RunID,
		&rec.Record, &issuedAt, &expiresAt, &updateAt); err != nil {
		return SecretLeaseRow{}, err
	}
	rec.IssuedAt = parseOptionalTime(issuedAt)
	rec.ExpiresAt = parseOptionalTime(expiresAt)
	rec.UpdatedAt = parseOptionalTime(updateAt)
	return rec, nil
}
