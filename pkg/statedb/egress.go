// Egress-grant storage (Task 20163).
//
// Rows for the scoped Internet-egress grants described in
// migrations/0015_egress_broker.sql. The layering matches the secret broker's:
// this file owns the SQL, pkg/secretstore converts between these rows and
// pkg/egressbroker's domain types, and pkg/egressbroker owns the policy.
//
// Nothing here is a credential. An egress grant brokers a capability rather
// than a token, so unlike broker_secrets there is no sealed payload column to
// protect — which is worth noticing rather than taking for granted, because
// it is the property that makes this the safest of the four grantable
// resources to persist.

package statedb

import (
	"database/sql"
	"fmt"
	"time"
)

// EgressGrantRow is one row of egress_grants. Times are RFC3339 strings,
// matching the rest of the schema.
type EgressGrantRow struct {
	ID           string
	Scope        string
	SubjectType  string
	SubjectValue string
	PolicyJSON   string
	ExpiresAt    string
	CreatedAt    string
	CreatedBy    string
	RevokedAt    string
}

// PutEgressGrant inserts or replaces an egress grant.
func (d *DB) PutEgressGrant(row EgressGrantRow) error {
	if row.ID == "" {
		return fmt.Errorf("statedb: egress grant id is empty")
	}
	if row.SubjectType == "" {
		return fmt.Errorf("statedb: egress grant %s has no subject type", row.ID)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO egress_grants(id, scope, subject_type, subject_value,
		     policy_json, expires_at, created_at, created_by, revoked_at)
		 VALUES (?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   scope=excluded.scope, subject_type=excluded.subject_type,
		   subject_value=excluded.subject_value, policy_json=excluded.policy_json,
		   expires_at=excluded.expires_at, created_at=excluded.created_at,
		   created_by=excluded.created_by, revoked_at=excluded.revoked_at`,
		row.ID, row.Scope, row.SubjectType, row.SubjectValue,
		defaultJSON(row.PolicyJSON), row.ExpiresAt, row.CreatedAt,
		row.CreatedBy, row.RevokedAt,
	); err != nil {
		return fmt.Errorf("statedb: put egress grant %s: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetEgressGrant returns one grant by ID.
func (d *DB) GetEgressGrant(id string) (EgressGrantRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var row EgressGrantRow
	err := d.conn.QueryRow(
		`SELECT id, scope, subject_type, subject_value, policy_json,
		        expires_at, created_at, created_by, revoked_at
		 FROM egress_grants WHERE id = ?`, id,
	).Scan(&row.ID, &row.Scope, &row.SubjectType, &row.SubjectValue,
		&row.PolicyJSON, &row.ExpiresAt, &row.CreatedAt, &row.CreatedBy, &row.RevokedAt)
	if err == sql.ErrNoRows {
		return EgressGrantRow{}, fmt.Errorf("%w: egress grant %q", ErrEgressGrantNotFound, id)
	}
	if err != nil {
		return EgressGrantRow{}, fmt.Errorf("statedb: get egress grant %s: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// ListEgressGrants returns every grant, including revoked and expired ones.
//
// Filtering is the broker's job for the same reason it is in
// ListBrokerGrants: an audit reader asking "who could reach the Internet last
// quarter" needs exactly the rows a policy filter would drop.
func (d *DB) ListEgressGrants() ([]EgressGrantRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, scope, subject_type, subject_value, policy_json,
		        expires_at, created_at, created_by, revoked_at
		 FROM egress_grants ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list egress grants: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []EgressGrantRow
	for rows.Next() {
		var row EgressGrantRow
		if err := rows.Scan(&row.ID, &row.Scope, &row.SubjectType, &row.SubjectValue,
			&row.PolicyJSON, &row.ExpiresAt, &row.CreatedAt,
			&row.CreatedBy, &row.RevokedAt); err != nil {
			return nil, fmt.Errorf("statedb: scan egress grant: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list egress grants: %w", classifyDriverErr(err))
	}
	return out, nil
}

// RevokeEgressGrant stamps a grant revoked.
//
// Conditional on revoked_at being empty, matching RevokeBrokerGrant: the
// moment access was withdrawn is a fact, and a retry must not move it.
// Revoking an already-revoked grant reports success, because the caller's
// desired end state holds.
func (d *DB) RevokeEgressGrant(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	stamp := at.UTC().Format(time.RFC3339Nano)
	res, err := d.conn.Exec(
		`UPDATE egress_grants SET revoked_at = ? WHERE id = ? AND revoked_at = ''`,
		stamp, id)
	if err != nil {
		return fmt.Errorf("statedb: revoke egress grant %s: %w", id, classifyDriverErr(err))
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		var exists int
		if qerr := d.conn.QueryRow(
			`SELECT COUNT(*) FROM egress_grants WHERE id = ?`, id).Scan(&exists); qerr == nil && exists == 0 {
			return fmt.Errorf("%w: egress grant %q", ErrEgressGrantNotFound, id)
		}
	}
	return nil
}
