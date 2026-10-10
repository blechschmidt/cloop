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
	// Owner is the identity that personally owns this secret, or "" for a
	// shared one. See migration 0039.
	Owner string
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
	// Owner is denormalised from the secret this grant points at, so a grant
	// listing can be scoped without resolving each row's secret.
	Owner string
	// RevokedCause is why a revoked grant was revoked — "owner_offboarded",
	// "secret_deleted", or "" — see migration 0062.
	RevokedCause string
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
		                            metadata_json, created_at, created_by, owner)
		 VALUES (?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   kind=excluded.kind, name=excluded.name, payload=excluded.payload,
		   key_id=excluded.key_id, wrapped_dek=excluded.wrapped_dek,
		   metadata_json=excluded.metadata_json, created_at=excluded.created_at,
		   created_by=excluded.created_by, owner=excluded.owner`,
		row.ID, row.Kind, row.Name, row.Payload,
		defaultString(row.KeyID, "legacy"), row.WrappedDEK,
		defaultJSON(row.MetadataJSON), row.CreatedAt, row.CreatedBy, row.Owner,
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
		`SELECT id, kind, name, payload, key_id, wrapped_dek, metadata_json, created_at,
		        created_by, owner
		 FROM broker_secrets WHERE id = ?`, id,
	).Scan(&row.ID, &row.Kind, &row.Name, &row.Payload, &row.KeyID, &row.WrappedDEK,
		&row.MetadataJSON, &row.CreatedAt, &row.CreatedBy, &row.Owner)
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
		`SELECT id, kind, name, payload, key_id, wrapped_dek, metadata_json, created_at,
		        created_by, owner
		 FROM broker_secrets ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list broker secrets: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []BrokerSecretRow
	for rows.Next() {
		var row BrokerSecretRow
		if err := rows.Scan(&row.ID, &row.Kind, &row.Name, &row.Payload, &row.KeyID, &row.WrappedDEK,
			&row.MetadataJSON, &row.CreatedAt, &row.CreatedBy, &row.Owner); err != nil {
			return nil, fmt.Errorf("statedb: scan broker secret: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list broker secrets: %w", classifyDriverErr(err))
	}
	return out, nil
}

// BrokerSecretTombstoneRow is one row of broker_secret_tombstones: what a
// deleted secret was, kept so a grant left pointing at it can still name it
// (migration 0062, Task 20400). Metadata only — nothing sealed survives a
// delete.
type BrokerSecretTombstoneRow struct {
	SecretID  string
	Name      string
	Kind      string
	Owner     string
	DeletedAt string
	DeletedBy string
	// Cause is "deleted" or "offboarded"; see migration 0062.
	Cause  string
	Reason string
}

// DeleteBrokerSecret removes a secret. Deleting one that does not exist is
// an error, so a CLI can tell the operator their reference was wrong instead
// of reporting a successful no-op.
func (d *DB) DeleteBrokerSecret(id string) error {
	return d.deleteBrokerSecret(id, nil)
}

// DeleteBrokerSecretTombstoned removes a secret and records its tombstone in
// the same transaction, so there is no moment at which the row is gone and
// nothing remembers what it was. A tombstone already present for the id — a
// secret deleted, re-minted under the same id by a restore, and deleted
// again — is replaced by the newer one.
func (d *DB) DeleteBrokerSecretTombstoned(id string, tomb BrokerSecretTombstoneRow) error {
	tomb.SecretID = id
	return d.deleteBrokerSecret(id, &tomb)
}

// deleteBrokerSecret scrubs the sealed columns, deletes the row and, when
// asked, writes its tombstone — one transaction.
//
// The scrub is the part a plain DELETE does not do. SQLite unlinks a deleted
// row's cell and leaves its bytes in the page's free space, and an overflow
// page holding the rest of a large payload goes to the freelist intact, until
// something happens to reuse the space. The ciphertext and the wrapped data
// key are sealed under a key the hub still holds, so a copy of state.db taken
// after a delete — a backup, a support bundle — would still open the
// credential the delete was meant to destroy. Rewriting both blobs with
// zeroes of the same length first changes nothing about the record's size,
// which is what lets SQLite overwrite the cell and its overflow chain in
// place, and the pages the transaction commits then carry zeroes where the
// material was.
func (d *DB) deleteBrokerSecret(id string, tomb *BrokerSecretTombstoneRow) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: delete broker secret %s: begin: %w", id, classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.Exec(
		`UPDATE broker_secrets
		    SET payload = zeroblob(length(payload)),
		        wrapped_dek = CASE WHEN wrapped_dek IS NULL THEN NULL
		                           ELSE zeroblob(length(wrapped_dek)) END
		  WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("statedb: scrub broker secret %s: %w", id, classifyDriverErr(err))
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		return fmt.Errorf("%w: broker secret %q", ErrBrokerSecretNotFound, id)
	}
	if _, err := tx.Exec(`DELETE FROM broker_secrets WHERE id = ?`, id); err != nil {
		return fmt.Errorf("statedb: delete broker secret %s: %w", id, classifyDriverErr(err))
	}
	if tomb != nil {
		if _, err := tx.Exec(
			`INSERT INTO broker_secret_tombstones(secret_id, name, kind, owner,
			     deleted_at, deleted_by, cause, reason)
			 VALUES (?,?,?,?,?,?,?,?)
			 ON CONFLICT(secret_id) DO UPDATE SET
			   name=excluded.name, kind=excluded.kind, owner=excluded.owner,
			   deleted_at=excluded.deleted_at, deleted_by=excluded.deleted_by,
			   cause=excluded.cause, reason=excluded.reason`,
			id, tomb.Name, tomb.Kind, tomb.Owner, tomb.DeletedAt, tomb.DeletedBy, tomb.Cause, tomb.Reason,
		); err != nil {
			return fmt.Errorf("statedb: record tombstone for broker secret %s: %w", id, classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: delete broker secret %s: commit: %w", id, classifyDriverErr(err))
	}
	return nil
}

// GetBrokerSecretTombstone returns the tombstone of a deleted secret, or a
// wrapped ErrBrokerSecretNotFound when nothing was recorded for the id — a
// secret deleted before tombstones existed, or one that never existed.
func (d *DB) GetBrokerSecretTombstone(secretID string) (BrokerSecretTombstoneRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var row BrokerSecretTombstoneRow
	err := d.conn.QueryRow(
		`SELECT secret_id, name, kind, owner, deleted_at, deleted_by, cause, reason
		 FROM broker_secret_tombstones WHERE secret_id = ?`, secretID,
	).Scan(&row.SecretID, &row.Name, &row.Kind, &row.Owner, &row.DeletedAt, &row.DeletedBy,
		&row.Cause, &row.Reason)
	if err == sql.ErrNoRows {
		return BrokerSecretTombstoneRow{}, fmt.Errorf("%w: no tombstone for broker secret %q",
			ErrBrokerSecretNotFound, secretID)
	}
	if err != nil {
		return BrokerSecretTombstoneRow{}, fmt.Errorf("statedb: get tombstone for broker secret %s: %w",
			secretID, classifyDriverErr(err))
	}
	return row, nil
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
		     constraints_json, expires_at, created_at, created_by, revoked_at, owner,
		     revoked_cause)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   secret_id=excluded.secret_id, scope=excluded.scope,
		   subject_type=excluded.subject_type, subject_value=excluded.subject_value,
		   constraints_json=excluded.constraints_json, expires_at=excluded.expires_at,
		   created_at=excluded.created_at, created_by=excluded.created_by,
		   revoked_at=excluded.revoked_at, owner=excluded.owner,
		   revoked_cause=excluded.revoked_cause`,
		row.ID, row.SecretID, row.Scope, row.SubjectType, row.SubjectValue,
		defaultJSON(row.ConstraintsJSON), row.ExpiresAt, row.CreatedAt,
		row.CreatedBy, row.RevokedAt, row.Owner, row.RevokedCause,
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
		        expires_at, created_at, created_by, revoked_at, owner, revoked_cause
		 FROM broker_grants WHERE id = ?`, id,
	).Scan(&row.ID, &row.SecretID, &row.Scope, &row.SubjectType, &row.SubjectValue,
		&row.ConstraintsJSON, &row.ExpiresAt, &row.CreatedAt, &row.CreatedBy, &row.RevokedAt,
		&row.Owner, &row.RevokedCause)
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
		        expires_at, created_at, created_by, revoked_at, owner, revoked_cause
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
			&row.CreatedAt, &row.CreatedBy, &row.RevokedAt, &row.Owner, &row.RevokedCause); err != nil {
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
	return d.RevokeBrokerGrantWithCause(id, at, "")
}

// RevokeBrokerGrantWithCause is RevokeBrokerGrant recording why (migration
// 0062). The cause is written only by the revocation that stamps the grant: a
// grant already revoked keeps the cause it was revoked with, as it keeps the
// time.
func (d *DB) RevokeBrokerGrantWithCause(id string, at time.Time, cause string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	stamp := at.UTC().Format(time.RFC3339Nano)
	res, err := d.conn.Exec(
		`UPDATE broker_grants SET revoked_at = ?, revoked_cause = ? WHERE id = ? AND revoked_at = ''`,
		stamp, cause, id)
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
