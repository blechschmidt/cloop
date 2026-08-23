// Secret-broker storage (Task 20159).
//
// Rows for the scoped credential grants described in
// migrations/0012_secret_broker.sql. This file owns the SQL; pkg/secretstore
// converts between these rows and pkg/secretbroker's domain types, and
// pkg/secretbroker owns the policy. The split keeps a storage layer from
// importing crypto and keeps the policy testable without a database file.
//
// The payload column holds an AES-256-GCM envelope and nothing else. Nothing
// in this file decrypts, inspects, or logs it — a storage layer that cannot
// see plaintext cannot leak it, however enthusiastically someone later
// instruments these functions.

package statedb

import (
	"database/sql"
	"fmt"
	"time"
)

// BrokerSecretRow is one row of broker_secrets. Times are RFC3339 strings,
// matching the rest of the schema.
type BrokerSecretRow struct {
	ID      string
	Kind    string
	Name    string
	Payload []byte // ciphertext under this row's DEK; never plaintext
	// KeyID names the KEK that WrappedDEK is sealed under, or "legacy" for
	// rows predating envelope encryption (Task 20181). WrappedDEK is the
	// row's data key, itself sealed. Neither is key material on its own.
	KeyID        string
	WrappedDEK   []byte
	MetadataJSON string
	CreatedAt    string
	CreatedBy    string
}

// BrokerGrantRow is one row of broker_grants.
type BrokerGrantRow struct {
	ID              string
	SecretID        string
	Scope           string
	SubjectType     string
	SubjectValue    string
	ConstraintsJSON string
	ExpiresAt       string
	CreatedAt       string
	CreatedBy       string
	RevokedAt       string
}

// PutBrokerSecret inserts or replaces a secret.
//
// The unique index on name is what makes a duplicate a storage error rather
// than a silently-shadowed second row, so a name collision surfaces here
// even if two processes race past the broker's own check.
func (d *DB) PutBrokerSecret(row BrokerSecretRow) error {
	if row.ID == "" {
		return fmt.Errorf("statedb: broker secret id is empty")
	}
	if len(row.Payload) == 0 {
		return fmt.Errorf("statedb: broker secret %s has an empty payload", row.ID)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO broker_secrets(id, kind, name, payload, key_id, wrapped_dek,
		                            metadata_json, created_at, created_by)
		 VALUES (?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   kind=excluded.kind, name=excluded.name, payload=excluded.payload,
		   key_id=excluded.key_id, wrapped_dek=excluded.wrapped_dek,
		   metadata_json=excluded.metadata_json, created_at=excluded.created_at,
		   created_by=excluded.created_by`,
		row.ID, row.Kind, row.Name, row.Payload,
		defaultString(row.KeyID, "legacy"), row.WrappedDEK,
		defaultJSON(row.MetadataJSON), row.CreatedAt, row.CreatedBy,
	); err != nil {
		return fmt.Errorf("statedb: put broker secret %s: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetBrokerSecret returns one secret by ID.
func (d *DB) GetBrokerSecret(id string) (BrokerSecretRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var row BrokerSecretRow
	err := d.conn.QueryRow(
		`SELECT id, kind, name, payload, key_id, wrapped_dek, metadata_json, created_at, created_by
		 FROM broker_secrets WHERE id = ?`, id,
	).Scan(&row.ID, &row.Kind, &row.Name, &row.Payload, &row.KeyID, &row.WrappedDEK,
		&row.MetadataJSON, &row.CreatedAt, &row.CreatedBy)
	if err == sql.ErrNoRows {
		return BrokerSecretRow{}, fmt.Errorf("%w: broker secret %q", ErrBrokerSecretNotFound, id)
	}
	if err != nil {
		return BrokerSecretRow{}, fmt.Errorf("statedb: get broker secret %s: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// ListBrokerSecrets returns every stored secret, name-ordered.
func (d *DB) ListBrokerSecrets() ([]BrokerSecretRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, kind, name, payload, key_id, wrapped_dek, metadata_json, created_at, created_by
		 FROM broker_secrets ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list broker secrets: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []BrokerSecretRow
	for rows.Next() {
		var row BrokerSecretRow
		if err := rows.Scan(&row.ID, &row.Kind, &row.Name, &row.Payload, &row.KeyID, &row.WrappedDEK,
			&row.MetadataJSON, &row.CreatedAt, &row.CreatedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan broker secret: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list broker secrets: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteBrokerSecret removes a secret. Deleting one that does not exist is
// an error, so a CLI can tell the operator their reference was wrong instead
// of reporting a successful no-op.
func (d *DB) DeleteBrokerSecret(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(`DELETE FROM broker_secrets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("statedb: delete broker secret %s: %w", id, classifyDriverErr(err))
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		return fmt.Errorf("%w: broker secret %q", ErrBrokerSecretNotFound, id)
	}
	return nil
}

// PutBrokerGrant inserts or replaces a grant.
func (d *DB) PutBrokerGrant(row BrokerGrantRow) error {
	if row.ID == "" {
		return fmt.Errorf("statedb: broker grant id is empty")
	}
	if row.SecretID == "" {
		return fmt.Errorf("statedb: broker grant %s has no secret id", row.ID)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO broker_grants(id, secret_id, scope, subject_type, subject_value,
		     constraints_json, expires_at, created_at, created_by, revoked_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   secret_id=excluded.secret_id, scope=excluded.scope,
		   subject_type=excluded.subject_type, subject_value=excluded.subject_value,
		   constraints_json=excluded.constraints_json, expires_at=excluded.expires_at,
		   created_at=excluded.created_at, created_by=excluded.created_by,
		   revoked_at=excluded.revoked_at`,
		row.ID, row.SecretID, row.Scope, row.SubjectType, row.SubjectValue,
		defaultJSON(row.ConstraintsJSON), row.ExpiresAt, row.CreatedAt,
		row.CreatedBy, row.RevokedAt,
	); err != nil {
		return fmt.Errorf("statedb: put broker grant %s: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetBrokerGrant returns one grant by ID.
func (d *DB) GetBrokerGrant(id string) (BrokerGrantRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var row BrokerGrantRow
	err := d.conn.QueryRow(
		`SELECT id, secret_id, scope, subject_type, subject_value, constraints_json,
		        expires_at, created_at, created_by, revoked_at
		 FROM broker_grants WHERE id = ?`, id,
	).Scan(&row.ID, &row.SecretID, &row.Scope, &row.SubjectType, &row.SubjectValue,
		&row.ConstraintsJSON, &row.ExpiresAt, &row.CreatedAt, &row.CreatedBy, &row.RevokedAt)
	if err == sql.ErrNoRows {
		return BrokerGrantRow{}, fmt.Errorf("%w: broker grant %q", ErrBrokerGrantNotFound, id)
	}
	if err != nil {
		return BrokerGrantRow{}, fmt.Errorf("statedb: get broker grant %s: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// ListBrokerGrants returns every grant, including revoked and expired ones.
//
// Filtering is the broker's job, not the store's: an audit UI listing "who
// had access" needs the rows a policy filter would drop, and a store that
// silently hid them would make that question unanswerable.
func (d *DB) ListBrokerGrants() ([]BrokerGrantRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, secret_id, scope, subject_type, subject_value, constraints_json,
		        expires_at, created_at, created_by, revoked_at
		 FROM broker_grants ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list broker grants: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []BrokerGrantRow
	for rows.Next() {
		var row BrokerGrantRow
		if err := rows.Scan(&row.ID, &row.SecretID, &row.Scope, &row.SubjectType,
			&row.SubjectValue, &row.ConstraintsJSON, &row.ExpiresAt,
			&row.CreatedAt, &row.CreatedBy, &row.RevokedAt); err != nil {
			return nil, fmt.Errorf("statedb: scan broker grant: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list broker grants: %w", classifyDriverErr(err))
	}
	return out, nil
}

// RevokeBrokerGrant stamps a grant revoked.
//
// The UPDATE is conditional on revoked_at being empty so a second revoke
// cannot move the timestamp forward. That matters for the audit trail: the
// moment access was withdrawn is a fact, and a retry must not rewrite it.
// Revoking an already-revoked grant is reported as success, because the
// caller's desired end state holds.
func (d *DB) RevokeBrokerGrant(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	stamp := at.UTC().Format(time.RFC3339Nano)
	res, err := d.conn.Exec(
		`UPDATE broker_grants SET revoked_at = ? WHERE id = ? AND revoked_at = ''`,
		stamp, id)
	if err != nil {
		return fmt.Errorf("statedb: revoke broker grant %s: %w", id, classifyDriverErr(err))
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		// Either the grant does not exist or it was already revoked. Only
		// the first is an error.
		var exists int
		if qerr := d.conn.QueryRow(
			`SELECT COUNT(*) FROM broker_grants WHERE id = ?`, id).Scan(&exists); qerr == nil && exists == 0 {
			return fmt.Errorf("%w: broker grant %q", ErrBrokerGrantNotFound, id)
		}
	}
	return nil
}

// BrokerMeta reads a broker-scoped metadata value.
func (d *DB) BrokerMeta(key string) (string, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var value string
	err := d.conn.QueryRow(`SELECT value FROM broker_meta WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("statedb: broker meta %s: %w", key, classifyDriverErr(err))
	}
	return value, true, nil
}

// SetBrokerMeta writes a broker-scoped metadata value.
func (d *DB) SetBrokerMeta(key, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO broker_meta(key, value) VALUES (?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value,
	); err != nil {
		return fmt.Errorf("statedb: set broker meta %s: %w", key, classifyDriverErr(err))
	}
	return nil
}

// defaultJSON substitutes an empty JSON object for an empty string so the
// NOT NULL columns always hold something a decoder accepts.
func defaultJSON(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}
