// API token persistence (Task 20175).
//
// The rows behind `cloop hub token` and the PAT authentication path. This file
// owns the SQL and the wire-shaped row type; pkg/apitoken owns minting,
// verification, and the policy that decides what a token may do. The split is
// the same one pkg/secretstore draws over broker_secrets, and for the same
// reason: the package that holds the crypto should not also hold a driver.
//
// Nothing here ever sees a token's plaintext. Row.Hash arrives already derived
// and is compared, never reversed — see pkg/apitoken.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// APITokenRow is one persisted API token.
//
// Roles and ProjectScope are stored as JSON arrays rather than normalized
// child tables: both are short, always read whole with the row, and are
// validated by pkg/apitoken on the way in and on the way out. A join here
// would buy nothing and would put the verification path — which runs on every
// authenticated request — behind three queries instead of one.
type APITokenRow struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Hash         string    `json:"-"` // never serialized: see the migration comment
	Prefix       string    `json:"prefix"`
	Roles        []string  `json:"roles"`
	ProjectScope []string  `json:"project_scope,omitempty"`
	CreatedBy    string    `json:"created_by,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
	RevokedAt    time.Time `json:"revoked_at,omitempty"`

	// Kind labels a hub-issued token; "" is an ordinary PAT (migration 0023).
	Kind string `json:"kind,omitempty"`

	// OwnerJSON is the owning identity's claim bundle, stored opaquely. This
	// layer deliberately does not know its shape: pkg/apitoken owns the
	// encoding, and a second opinion here about what a claim set looks like is
	// how the two drift apart. Never serialized outward for the same reason
	// Hash is not — it carries a user's email and group memberships.
	OwnerJSON string `json:"-"`
}

const apiTokenColumns = `id, name, hash, prefix, roles_json, project_scope_json,
	created_by, created_at, expires_at, last_used_at, revoked_at, kind, owner_json`

// PutAPIToken inserts a token row. It is an insert, not an upsert: a token's
// secret, roles, and scope are fixed at mint time, and silently rewriting an
// existing row would turn "re-run the create call" into an undetectable
// privilege change on a credential already in circulation. Rotating means
// minting a new token and revoking the old one.
func (d *DB) PutAPIToken(row APITokenRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: api token id is required")
	}
	if strings.TrimSpace(row.Hash) == "" {
		return errors.New("statedb: api token hash is required")
	}
	roles, err := marshalStringSlice(row.Roles)
	if err != nil {
		return fmt.Errorf("statedb: marshal api token roles: %w", err)
	}
	scope, err := marshalStringSlice(row.ProjectScope)
	if err != nil {
		return fmt.Errorf("statedb: marshal api token project scope: %w", err)
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err = d.conn.Exec(
		`INSERT INTO api_tokens(`+apiTokenColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.Name, row.Hash, row.Prefix, roles, scope,
		row.CreatedBy,
		row.CreatedAt.UTC().Format(time.RFC3339Nano),
		formatOptionalTime(row.ExpiresAt),
		formatOptionalTime(row.LastUsedAt),
		formatOptionalTime(row.RevokedAt),
		row.Kind, row.OwnerJSON,
	)
	if err != nil {
		return fmt.Errorf("statedb: insert api token %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetAPIToken returns one token by ID, or ErrAPITokenNotFound.
//
// This is the verification path's only read, which is why the lookup is by
// primary key: an authenticated request must not cost a table scan, and a
// scan would additionally make request latency a function of how many tokens
// the hub has ever issued.
func (d *DB) GetAPIToken(id string) (APITokenRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(`SELECT `+apiTokenColumns+` FROM api_tokens WHERE id = ?`, id)
	out, err := scanAPITokenRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return APITokenRow{}, fmt.Errorf("%w: %q", ErrAPITokenNotFound, id)
	}
	if err != nil {
		return APITokenRow{}, fmt.Errorf("statedb: get api token %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// ListAPITokens returns every token, newest first. Revoked and expired rows
// are included: an operator auditing access needs to see what was withdrawn,
// and the caller decides how to present it.
func (d *DB) ListAPITokens() ([]APITokenRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + apiTokenColumns + ` FROM api_tokens ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list api tokens: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	out := []APITokenRow{}
	for rows.Next() {
		item, serr := scanAPITokenRow(rows)
		if serr != nil {
			return nil, fmt.Errorf("statedb: scan api token: %w", classifyDriverErr(serr))
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list api tokens: %w", classifyDriverErr(err))
	}
	return out, nil
}

// RevokeAPIToken stamps a token as revoked. Revoking an already-revoked token
// keeps the original timestamp: the first withdrawal is the one that matters,
// and overwriting it would let a later call quietly move the date an auditor
// reads as "when did this stop working".
//
// Returns ErrAPITokenNotFound when no such token exists, so a caller cannot
// mistake a typo for a successful revocation.
func (d *DB) RevokeAPIToken(id string, at time.Time) error {
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = ''`,
		at.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("statedb: revoke api token %q: %w", id, classifyDriverErr(err))
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n > 0 {
		return nil
	}
	// Nothing updated: either the row is missing or it was already revoked.
	// Distinguish, so "revoke a token that does not exist" is an error and
	// "revoke one that already is" is a no-op success (idempotent).
	var exists int
	if err := d.conn.QueryRow(`SELECT COUNT(1) FROM api_tokens WHERE id = ?`, id).Scan(&exists); err != nil {
		return fmt.Errorf("statedb: revoke api token %q: %w", id, classifyDriverErr(err))
	}
	if exists == 0 {
		return fmt.Errorf("%w: %q", ErrAPITokenNotFound, id)
	}
	return nil
}

// TouchAPIToken records that a token was used. Called off the verification
// path and coalesced by pkg/apitoken, so a failure here is logged by the
// caller and never surfaces as an authentication error — a lost timestamp is
// not a lost authorization decision.
func (d *DB) TouchAPIToken(id string, at time.Time) error {
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("statedb: touch api token %q: %w", id, classifyDriverErr(err))
	}
	return nil
}

// marshalStringSlice encodes a string list for a *_json column, normalizing
// nil to "[]" so the column never holds SQL NULL or the literal "null" — both
// of which would decode to a nil slice that reads as "no restriction", which
// for project_scope_json is the permissive answer.
func marshalStringSlice(in []string) (string, error) {
	if len(in) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalStringSlice decodes a *_json column, returning nil for anything it
// cannot parse. A corrupted scope column therefore reads as "no scope
// recorded"; pkg/apitoken treats that as unrestricted-by-scope, which is why
// the writer above never lets the column reach that state and why the roles
// column — the one that actually confers authority — is separately validated
// against authz.ParseRole on the way out.
func unmarshalStringSlice(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || raw == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// scanAPITokenRow decodes one row from either a *sql.Row or *sql.Rows.
func scanAPITokenRow(sc interface{ Scan(...any) error }) (APITokenRow, error) {
	var (
		out                                     APITokenRow
		rolesJSON, scopeJSON                    string
		createdAt, expiresAt, lastUsed, revoked string
	)
	if err := sc.Scan(&out.ID, &out.Name, &out.Hash, &out.Prefix, &rolesJSON, &scopeJSON,
		&out.CreatedBy, &createdAt, &expiresAt, &lastUsed, &revoked,
		&out.Kind, &out.OwnerJSON); err != nil {
		return APITokenRow{}, err
	}
	out.Roles = unmarshalStringSlice(rolesJSON)
	out.ProjectScope = unmarshalStringSlice(scopeJSON)
	out.CreatedAt = parseOptionalTime(createdAt)
	out.ExpiresAt = parseOptionalTime(expiresAt)
	out.LastUsedAt = parseOptionalTime(lastUsed)
	out.RevokedAt = parseOptionalTime(revoked)
	return out, nil
}
