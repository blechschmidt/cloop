// Durable record of materialised credential directories (Task 20193).
//
// Rows for migrations/0022_secret_lease_dirs.sql. See that file for why the row
// is written *before* the directory exists and why a blind sweep of
// /dev/shm/cloop-lease-* would be wrong.
//
// This file owns the SQL only. What counts as an orphan and what to do about
// one is policy, and lives in pkg/ui alongside the lease registry it reconciles
// against.

package statedb

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// SecretLeaseDirRow is one credential directory this hub has committed to
// creating. It records where plaintext is, never what it is.
type SecretLeaseDirRow struct {
	// Dir is the absolute path of the lease directory and the primary key.
	Dir string
	// LeaseID is the lease whose material lives there.
	LeaseID string
	// ExecutorID is the executor the lease was issued to, '' when unbound.
	ExecutorID string
	// ProjectPath is the project the work belongs to, '' when not scoped.
	ProjectPath string
	// CreatedAt is when the intent was recorded — before the directory was
	// created, not after.
	CreatedAt time.Time
	// ExpiresAt is the lease's expiry; the zero time means unbounded. The
	// sweep does not need it to decide, but an operator reading the audit
	// event for a swept directory needs to know whether it had already lapsed.
	ExpiresAt time.Time
}

// PutSecretLeaseDir records the intent to materialise a lease at row.Dir.
//
// Call it before anything writes plaintext there. The ordering is the whole
// point of the table: a row without a directory is harmless and self-clearing,
// a directory without a row is an orphan nothing can attribute.
func (d *DB) PutSecretLeaseDir(row SecretLeaseDirRow) error {
	if strings.TrimSpace(row.Dir) == "" {
		return errors.New("statedb: secret lease dir path is required")
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO secret_lease_dirs(dir, lease_id, executor_id, project_path,
		                               created_at, expires_at)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(dir) DO UPDATE SET
		   lease_id     = excluded.lease_id,
		   executor_id  = excluded.executor_id,
		   project_path = excluded.project_path,
		   created_at   = excluded.created_at,
		   expires_at   = excluded.expires_at`,
		row.Dir, row.LeaseID, row.ExecutorID, row.ProjectPath,
		formatOptionalTime(row.CreatedAt), formatOptionalTime(row.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put secret lease dir %q: %w", row.Dir, classifyDriverErr(err))
	}
	return nil
}

// ListSecretLeaseDirs returns every recorded directory, oldest first.
//
// At startup this is precisely the orphan set: a hub that shut down cleanly
// deleted its rows as it wiped, so anything still here outlived the process
// that created it.
func (d *DB) ListSecretLeaseDirs() ([]SecretLeaseDirRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT dir, lease_id, executor_id, project_path, created_at, expires_at
		   FROM secret_lease_dirs
		  ORDER BY created_at, dir`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list secret lease dirs: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []SecretLeaseDirRow
	for rows.Next() {
		var (
			rec                  SecretLeaseDirRow
			createdAt, expiresAt string
		)
		if err := rows.Scan(&rec.Dir, &rec.LeaseID, &rec.ExecutorID, &rec.ProjectPath,
			&createdAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("statedb: scan secret lease dir: %w", classifyDriverErr(err))
		}
		rec.CreatedAt = parseOptionalTime(createdAt)
		rec.ExpiresAt = parseOptionalTime(expiresAt)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list secret lease dirs: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteSecretLeaseDir forgets one directory, after it has been wiped.
//
// Deleting a row that is not there is not an error: a lease can be wiped twice
// — once when its workload exits, once by a revocation that raced it — and
// neither call should fail.
func (d *DB) DeleteSecretLeaseDir(dir string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM secret_lease_dirs WHERE dir = ?`, dir); err != nil {
		return fmt.Errorf("statedb: delete secret lease dir %q: %w", dir, classifyDriverErr(err))
	}
	return nil
}
