// Durable lease revocations (Task 20419).
//
// Rows for migrations/0069_run_supervision.sql's secret_lease_revocations. See
// that file for why a revocation needs a record of its own. This file owns the
// SQL; what a revocation binds is pkg/secretbroker's business and who enforces
// it is pkg/ui's.

package statedb

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// LeaseRevocationRow is one revocation of a lease, or of one grant of it.
type LeaseRevocationRow struct {
	LeaseID string
	// GrantID is the grant the revocation names, "" for the whole lease.
	GrantID    string
	Action     string
	Reason     string
	Actor      string
	ExecutorID string
	ProjectID  string
	// Holder is the hub member that held the lease when it was revoked.
	Holder    string
	RevokedAt time.Time
	// EnforcedAt is when the material was found taken back from every
	// holder, zero while the revocation is pending.
	EnforcedAt time.Time
	EnforcedBy string
	Detail     string
}

// Pending reports whether the revocation has not been enforced yet.
func (r LeaseRevocationRow) Pending() bool { return r.EnforcedAt.IsZero() }

// leaseRevocationColumns is every column, in the order scanLeaseRevocation
// reads them.
const leaseRevocationColumns = `lease_id, grant_id, action, reason, actor, executor_id, project_id,
	holder, revoked_at, enforced_at, enforced_by, detail`

// PutLeaseRevocation records a revocation. Revoking a lease (or grant) that
// is already revoked re-opens it: the reason and actor are the latest ones, a
// kill is never weakened to a scrub, the first revocation's time is kept, and
// the enforcement is cleared — the new request is enforced again, which for a
// revocation already enforced finds nothing left and settles at once.
func (d *DB) PutLeaseRevocation(row LeaseRevocationRow) error {
	if strings.TrimSpace(row.LeaseID) == "" {
		return errors.New("statedb: lease revocation needs a lease id")
	}
	if strings.TrimSpace(row.Action) == "" {
		row.Action = "scrub"
	}
	if row.RevokedAt.IsZero() {
		row.RevokedAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO secret_lease_revocations(`+leaseRevocationColumns+`)
		 VALUES(?,?,?,?,?,?,?,?,?,'','','')
		 ON CONFLICT(lease_id, grant_id) DO UPDATE SET
		   action      = CASE WHEN excluded.action = 'kill' THEN 'kill' ELSE secret_lease_revocations.action END,
		   reason      = excluded.reason,
		   actor       = excluded.actor,
		   executor_id = CASE WHEN excluded.executor_id <> '' THEN excluded.executor_id ELSE secret_lease_revocations.executor_id END,
		   project_id  = CASE WHEN excluded.project_id <> '' THEN excluded.project_id ELSE secret_lease_revocations.project_id END,
		   holder      = CASE WHEN excluded.holder <> '' THEN excluded.holder ELSE secret_lease_revocations.holder END,
		   enforced_at = '',
		   enforced_by = '',
		   detail      = ''`,
		row.LeaseID, strings.TrimSpace(row.GrantID), row.Action, row.Reason, row.Actor,
		row.ExecutorID, row.ProjectID, row.Holder, formatOptionalTime(row.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: record revocation of lease %q: %w", row.LeaseID, classifyDriverErr(err))
	}
	return nil
}

// LeaseRevocations returns every revocation recorded for leaseID, the
// whole-lease one first.
func (d *DB) LeaseRevocations(leaseID string) ([]LeaseRevocationRow, error) {
	return d.queryLeaseRevocations(`WHERE lease_id = ? ORDER BY grant_id`, leaseID)
}

// ListLeaseRevocations returns every recorded revocation, or with pendingOnly
// those not yet enforced, oldest first.
func (d *DB) ListLeaseRevocations(pendingOnly bool) ([]LeaseRevocationRow, error) {
	if pendingOnly {
		return d.queryLeaseRevocations(`WHERE enforced_at = '' ORDER BY revoked_at, lease_id, grant_id`)
	}
	return d.queryLeaseRevocations(`ORDER BY revoked_at, lease_id, grant_id`)
}

func (d *DB) queryLeaseRevocations(tail string, args ...any) ([]LeaseRevocationRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+leaseRevocationColumns+` FROM secret_lease_revocations `+tail, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list lease revocations: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []LeaseRevocationRow
	for rows.Next() {
		r, err := scanLeaseRevocation(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan lease revocation: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list lease revocations: %w", classifyDriverErr(err))
	}
	return out, nil
}

// MarkLeaseRevocationEnforced records that a pending revocation's material was
// taken back from every holder, and reports whether it was pending.
func (d *DB) MarkLeaseRevocationEnforced(leaseID, grantID, by, detail string, at time.Time) (bool, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE secret_lease_revocations SET enforced_at = ?, enforced_by = ?, detail = ?
		  WHERE lease_id = ? AND grant_id = ? AND enforced_at = ''`,
		formatOptionalTime(at), by, detail, leaseID, strings.TrimSpace(grantID))
	if err != nil {
		return false, fmt.Errorf("statedb: settle revocation of lease %q: %w", leaseID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// NoteLeaseRevocation records why a pending revocation is still pending. A
// revocation already enforced is left alone.
func (d *DB) NoteLeaseRevocation(leaseID, grantID, detail string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(
		`UPDATE secret_lease_revocations SET detail = ?
		  WHERE lease_id = ? AND grant_id = ? AND enforced_at = ''`,
		detail, leaseID, strings.TrimSpace(grantID)); err != nil {
		return fmt.Errorf("statedb: note revocation of lease %q: %w", leaseID, classifyDriverErr(err))
	}
	return nil
}

// PruneLeaseRevocations deletes the revocations enforced before cutoff, and
// reports how many went. A pending revocation is never pruned: it is the one
// thing that tells a member reaching its workload to take the material back.
func (d *DB) PruneLeaseRevocations(cutoff time.Time) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`DELETE FROM secret_lease_revocations WHERE enforced_at <> '' AND enforced_at < ?`,
		formatOptionalTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("statedb: prune lease revocations: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func scanLeaseRevocation(s interface{ Scan(dest ...any) error }) (LeaseRevocationRow, error) {
	var (
		r                     LeaseRevocationRow
		revokedAt, enforcedAt string
	)
	if err := s.Scan(&r.LeaseID, &r.GrantID, &r.Action, &r.Reason, &r.Actor, &r.ExecutorID, &r.ProjectID,
		&r.Holder, &revokedAt, &enforcedAt, &r.EnforcedBy, &r.Detail); err != nil {
		return LeaseRevocationRow{}, err
	}
	r.RevokedAt = parseOptionalTime(revokedAt)
	r.EnforcedAt = parseOptionalTime(enforcedAt)
	return r, nil
}
