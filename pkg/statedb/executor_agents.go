// Remote executor enrollment persistence (Task 20158).
//
// Remote agents run on machines this control plane cannot dial, so they enroll
// by connecting outward and presenting a secret. Two secrets are involved,
// with deliberately different lifetimes: a single-use, TTL-bounded enrollment
// token that a human pastes around, and a long-lived per-agent credential
// issued in exchange for it.
//
// Neither secret is stored. Both tables hold a hex SHA-256 of the secret, and
// the hashing happens in pkg/executor/remote — this file only ever sees the
// digest. The row types below are native to this package rather than reusing
// pkg/executor/remote's, so storage does not acquire a dependency on the
// WebSocket stack; pkg/executorstore converts between the two.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors for enrollment persistence. Callers use errors.Is.
var (
	// ErrEnrollmentNotFound: no enrollment token with that ID.
	ErrEnrollmentNotFound = errors.New("statedb: enrollment token not found")
	// ErrAgentCredentialNotFound: no agent credential with that ID.
	ErrAgentCredentialNotFound = errors.New("statedb: agent credential not found")
	// ErrEnrollmentSpent: the token was already redeemed or revoked. This is
	// the replay signal, and it is a distinct error because "someone reused
	// this token" is an operational event worth surfacing, not a generic
	// failure.
	ErrEnrollmentSpent = errors.New("statedb: enrollment token already redeemed or revoked")
)

// EnrollmentTokenRow is one minted enrollment token.
type EnrollmentTokenRow struct {
	ID   string
	Name string
	// SecretHash is hex SHA-256 of the token secret, never the secret.
	SecretHash      string
	WorkDirRoot     string
	Labels          map[string]string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	CreatedBy       string
	RedeemedAt      time.Time
	RedeemedAgentID string
	RevokedAt       time.Time
}

// AgentCredentialRow is one enrolled agent's long-lived credential.
type AgentCredentialRow struct {
	AgentID string
	Name    string
	// SecretHash is hex SHA-256 of the credential secret, never the secret.
	SecretHash   string
	WorkDirRoot  string
	Labels       map[string]string
	CreatedAt    time.Time
	LastSeen     time.Time
	RevokedAt    time.Time
	EnrollmentID string
}

// PutEnrollmentToken inserts or updates a token row.
func (d *DB) PutEnrollmentToken(row EnrollmentTokenRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: enrollment token id is required")
	}
	// An empty hash would make every comparison fail closed, but it would
	// also mean the caller believes it persisted something it did not. Reject
	// it rather than store a row that can never authenticate.
	if strings.TrimSpace(row.SecretHash) == "" {
		return fmt.Errorf("statedb: enrollment token %q has an empty secret hash", row.ID)
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	labels, err := marshalLabelMap(row.Labels)
	if err != nil {
		return fmt.Errorf("statedb: marshal enrollment labels: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err = d.conn.Exec(
		`INSERT INTO executor_enrollment_tokens(id, name, secret_hash, workdir_root, labels_json,
		                                        created_at, expires_at, created_by,
		                                        redeemed_at, redeemed_agent_id, revoked_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   name         = excluded.name,
		   workdir_root = excluded.workdir_root,
		   labels_json  = excluded.labels_json,
		   expires_at   = excluded.expires_at`,
		row.ID, row.Name, row.SecretHash, row.WorkDirRoot, labels,
		row.CreatedAt.UTC().Format(time.RFC3339Nano),
		formatOptionalTime(row.ExpiresAt), row.CreatedBy,
		formatOptionalTime(row.RedeemedAt), row.RedeemedAgentID,
		formatOptionalTime(row.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put enrollment token %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetEnrollmentToken returns one token by ID, or ErrEnrollmentNotFound.
func (d *DB) GetEnrollmentToken(id string) (EnrollmentTokenRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT id, name, secret_hash, workdir_root, labels_json, created_at, expires_at,
		        created_by, redeemed_at, redeemed_agent_id, revoked_at
		 FROM executor_enrollment_tokens WHERE id = ?`, id)
	out, err := scanEnrollmentRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentTokenRow{}, fmt.Errorf("%w: %q", ErrEnrollmentNotFound, id)
	}
	if err != nil {
		return EnrollmentTokenRow{}, fmt.Errorf("statedb: get enrollment token %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// RedeemEnrollmentToken atomically claims a token for agentID.
//
// The single-use guarantee lives entirely in this statement's WHERE clause.
// SQLite serialises writers, so of two concurrent redemptions exactly one
// finds redeemed_at = '' and updates a row; the other matches nothing and gets
// ErrEnrollmentSpent. A read-then-write implementation would let both succeed
// and hand two devices the same identity, which is the precise attack that
// single-use tokens exist to prevent.
func (d *DB) RedeemEnrollmentToken(id, agentID string, at time.Time) error {
	if strings.TrimSpace(agentID) == "" {
		return errors.New("statedb: redeeming agent id is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE executor_enrollment_tokens
		 SET redeemed_at = ?, redeemed_agent_id = ?
		 WHERE id = ? AND redeemed_at = '' AND revoked_at = ''`,
		formatOptionalTime(at), agentID, id)
	if err != nil {
		return fmt.Errorf("statedb: redeem enrollment token %q: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("statedb: redeem enrollment token %q: %w", id, classifyDriverErr(err))
	}
	if n == 0 {
		// Distinguish "no such token" from "already spent": the second is a
		// replay attempt and the operator needs to know which they are
		// looking at.
		var exists int
		if scanErr := d.conn.QueryRow(
			`SELECT COUNT(1) FROM executor_enrollment_tokens WHERE id = ?`, id).Scan(&exists); scanErr == nil && exists == 0 {
			return fmt.Errorf("%w: %q", ErrEnrollmentNotFound, id)
		}
		return fmt.Errorf("%w: %q", ErrEnrollmentSpent, id)
	}
	return nil
}

// RevokeEnrollmentToken marks a token revoked, redeemed or not.
func (d *DB) RevokeEnrollmentToken(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE executor_enrollment_tokens SET revoked_at = ? WHERE id = ?`,
		formatOptionalTime(at), id)
	if err != nil {
		return fmt.Errorf("statedb: revoke enrollment token %q: %w", id, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: %q", ErrEnrollmentNotFound, id)
	}
	return nil
}

// ListEnrollmentTokens returns every token, newest first.
func (d *DB) ListEnrollmentTokens() ([]EnrollmentTokenRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT id, name, secret_hash, workdir_root, labels_json, created_at, expires_at,
		        created_by, redeemed_at, redeemed_agent_id, revoked_at
		 FROM executor_enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list enrollment tokens: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []EnrollmentTokenRow
	for rows.Next() {
		rec, err := scanEnrollmentRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan enrollment token: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list enrollment tokens: %w", classifyDriverErr(err))
	}
	return out, nil
}

// PutAgentCredential inserts or updates an agent credential row.
func (d *DB) PutAgentCredential(row AgentCredentialRow) error {
	if strings.TrimSpace(row.AgentID) == "" {
		return errors.New("statedb: agent id is required")
	}
	if strings.TrimSpace(row.SecretHash) == "" {
		return fmt.Errorf("statedb: agent credential %q has an empty secret hash", row.AgentID)
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	labels, err := marshalLabelMap(row.Labels)
	if err != nil {
		return fmt.Errorf("statedb: marshal agent labels: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err = d.conn.Exec(
		`INSERT INTO executor_agent_credentials(agent_id, name, secret_hash, workdir_root,
		                                        labels_json, created_at, last_seen,
		                                        revoked_at, enrollment_id)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(agent_id) DO UPDATE SET
		   name          = excluded.name,
		   secret_hash   = excluded.secret_hash,
		   workdir_root  = excluded.workdir_root,
		   labels_json   = excluded.labels_json,
		   enrollment_id = excluded.enrollment_id`,
		row.AgentID, row.Name, row.SecretHash, row.WorkDirRoot, labels,
		row.CreatedAt.UTC().Format(time.RFC3339Nano),
		formatOptionalTime(row.LastSeen), formatOptionalTime(row.RevokedAt), row.EnrollmentID,
	)
	if err != nil {
		return fmt.Errorf("statedb: put agent credential %q: %w", row.AgentID, classifyDriverErr(err))
	}
	return nil
}

// GetAgentCredential returns one agent by ID, or ErrAgentCredentialNotFound.
func (d *DB) GetAgentCredential(agentID string) (AgentCredentialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT agent_id, name, secret_hash, workdir_root, labels_json,
		        created_at, last_seen, revoked_at, enrollment_id
		 FROM executor_agent_credentials WHERE agent_id = ?`, agentID)
	out, err := scanAgentCredentialRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentCredentialRow{}, fmt.Errorf("%w: %q", ErrAgentCredentialNotFound, agentID)
	}
	if err != nil {
		return AgentCredentialRow{}, fmt.Errorf("statedb: get agent credential %q: %w", agentID, classifyDriverErr(err))
	}
	return out, nil
}

// RevokeAgentCredential marks an agent's credential revoked.
func (d *DB) RevokeAgentCredential(agentID string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE executor_agent_credentials SET revoked_at = ? WHERE agent_id = ?`,
		formatOptionalTime(at), agentID)
	if err != nil {
		return fmt.Errorf("statedb: revoke agent credential %q: %w", agentID, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: %q", ErrAgentCredentialNotFound, agentID)
	}
	return nil
}

// TouchAgentCredential records a successful authentication.
func (d *DB) TouchAgentCredential(agentID string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`UPDATE executor_agent_credentials SET last_seen = ? WHERE agent_id = ?`,
		formatOptionalTime(at), agentID)
	if err != nil {
		return fmt.Errorf("statedb: touch agent credential %q: %w", agentID, classifyDriverErr(err))
	}
	return nil
}

// ListAgentCredentials returns every enrolled agent, oldest first.
func (d *DB) ListAgentCredentials() ([]AgentCredentialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT agent_id, name, secret_hash, workdir_root, labels_json,
		        created_at, last_seen, revoked_at, enrollment_id
		 FROM executor_agent_credentials ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list agent credentials: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []AgentCredentialRow
	for rows.Next() {
		rec, err := scanAgentCredentialRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan agent credential: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list agent credentials: %w", classifyDriverErr(err))
	}
	return out, nil
}

func scanEnrollmentRow(sc rowScanner) (EnrollmentTokenRow, error) {
	var (
		rec                                         EnrollmentTokenRow
		labels                                      string
		createdAt, expiresAt, redeemedAt, revokedAt string
	)
	if err := sc.Scan(&rec.ID, &rec.Name, &rec.SecretHash, &rec.WorkDirRoot, &labels,
		&createdAt, &expiresAt, &rec.CreatedBy, &redeemedAt, &rec.RedeemedAgentID, &revokedAt); err != nil {
		return EnrollmentTokenRow{}, err
	}
	rec.Labels = unmarshalLabelMap(labels)
	rec.CreatedAt = parseOptionalTime(createdAt)
	rec.ExpiresAt = parseOptionalTime(expiresAt)
	rec.RedeemedAt = parseOptionalTime(redeemedAt)
	rec.RevokedAt = parseOptionalTime(revokedAt)
	return rec, nil
}

func scanAgentCredentialRow(sc rowScanner) (AgentCredentialRow, error) {
	var (
		rec                            AgentCredentialRow
		labels                         string
		createdAt, lastSeen, revokedAt string
	)
	if err := sc.Scan(&rec.AgentID, &rec.Name, &rec.SecretHash, &rec.WorkDirRoot, &labels,
		&createdAt, &lastSeen, &revokedAt, &rec.EnrollmentID); err != nil {
		return AgentCredentialRow{}, err
	}
	rec.Labels = unmarshalLabelMap(labels)
	rec.CreatedAt = parseOptionalTime(createdAt)
	rec.LastSeen = parseOptionalTime(lastSeen)
	rec.RevokedAt = parseOptionalTime(revokedAt)
	return rec, nil
}

func marshalLabelMap(m map[string]string) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// unmarshalLabelMap tolerates malformed JSON by returning nil. Labels are
// advisory scheduler metadata; a corrupt blob must never make an otherwise
// valid credential unauthenticatable.
func unmarshalLabelMap(s string) map[string]string {
	if s == "" || s == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}
