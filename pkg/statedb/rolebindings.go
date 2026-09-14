package statedb

// Runtime role binding storage (Task 20248). See
// migrations/0033_role_bindings.sql for why this table exists alongside the
// configured bindings and why `effect` is its own column.
//
// Mechanical accessors only. Normalization, precedence and the deny rule all
// live in pkg/authz; the adapter that turns these rows into authz.Binding
// values lives in pkg/rolestore. Storage validates only what it must to keep
// the table readable.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Effect values for RoleBindingRow.Effect.
const (
	RoleEffectAllow = "allow"
	RoleEffectDeny  = "deny"
)

// RoleBindingRow is one row of role_bindings.
type RoleBindingRow struct {
	ID        string
	Effect    string
	Claim     string
	Value     string
	Role      string
	Project   string
	Executor  string
	Reason    string
	CreatedAt time.Time
	CreatedBy string
}

// RoleBindingID derives the deterministic identifier for a binding's identity
// tuple.
//
// Identity is (effect, claim, value, project, executor) and deliberately
// excludes role, reason and provenance: re-granting the same subject a
// different role on the same scope should replace the binding, not leave two
// rows whose winner depends on resolution order. The reason and the actor of
// the most recent write are what the audit trail keeps.
//
// Truncated to 48 bits. This is a content address for deduplication, not a
// security boundary — the values it covers are already visible to anyone who
// can read the table — and a 12-character id is one an operator can retype
// from a terminal during an incident.
func RoleBindingID(effect, claim, value, project, executor string) string {
	sum := sha256.Sum256([]byte(strings.Join(
		[]string{effect, claim, value, project, executor}, "\x00")))
	return "rb_" + hex.EncodeToString(sum[:6])
}

// PutRoleBinding inserts or replaces a binding, returning the row as stored.
//
// The caller supplies already-normalized claim and value: normalization is
// pkg/authz's definition of when two bindings are the same one, and a second
// implementation here would silently disagree with it at exactly the moment
// an operator is trying to override a configured binding.
func (d *DB) PutRoleBinding(row RoleBindingRow) (RoleBindingRow, error) {
	row.Effect = strings.TrimSpace(strings.ToLower(row.Effect))
	if row.Effect == "" {
		row.Effect = RoleEffectAllow
	}
	if row.Effect != RoleEffectAllow && row.Effect != RoleEffectDeny {
		return RoleBindingRow{}, fmt.Errorf("statedb: role binding effect %q must be %q or %q",
			row.Effect, RoleEffectAllow, RoleEffectDeny)
	}
	if strings.TrimSpace(row.Claim) == "" || strings.TrimSpace(row.Value) == "" {
		return RoleBindingRow{}, fmt.Errorf("statedb: role binding claim and value are required")
	}
	if strings.TrimSpace(row.Role) == "" {
		row.Role = "none"
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	row.ID = RoleBindingID(row.Effect, row.Claim, row.Value, row.Project, row.Executor)

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO role_bindings
		     (id, effect, claim, value, role, project, executor, reason, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		     role       = excluded.role,
		     reason     = excluded.reason,
		     created_at = excluded.created_at,
		     created_by = excluded.created_by`,
		row.ID, row.Effect, row.Claim, row.Value, row.Role,
		row.Project, row.Executor, row.Reason,
		formatOptionalTime(row.CreatedAt), row.CreatedBy,
	)
	if err != nil {
		return RoleBindingRow{}, fmt.Errorf("statedb: put role binding %q: %w", row.ID, classifyDriverErr(err))
	}
	return row, nil
}

// ListRoleBindings returns every binding.
//
// Denies sort first so that a human reading the output — and the resolver's
// own scan — meets the rows that take away authority before the rows that
// grant it. Within an effect the order is stable by claim, value and id so
// repeated listings do not shuffle.
func (d *DB) ListRoleBindings() ([]RoleBindingRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT id, effect, claim, value, role, project, executor, reason, created_at, created_by
		   FROM role_bindings
		  ORDER BY CASE effect WHEN 'deny' THEN 0 ELSE 1 END, claim, value, id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list role bindings: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []RoleBindingRow
	for rows.Next() {
		var r RoleBindingRow
		var created string
		if err := rows.Scan(&r.ID, &r.Effect, &r.Claim, &r.Value, &r.Role,
			&r.Project, &r.Executor, &r.Reason, &created, &r.CreatedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan role binding: %w", classifyDriverErr(err))
		}
		r.CreatedAt = parseOptionalTime(created)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list role bindings: %w", classifyDriverErr(err))
	}
	return out, nil
}

// GetRoleBinding returns one binding by id, or ErrRoleBindingNotFound.
func (d *DB) GetRoleBinding(id string) (RoleBindingRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var r RoleBindingRow
	var created string
	err := d.conn.QueryRow(
		`SELECT id, effect, claim, value, role, project, executor, reason, created_at, created_by
		   FROM role_bindings WHERE id = ?`, id).
		Scan(&r.ID, &r.Effect, &r.Claim, &r.Value, &r.Role,
			&r.Project, &r.Executor, &r.Reason, &created, &r.CreatedBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RoleBindingRow{}, fmt.Errorf("%w: %s", ErrRoleBindingNotFound, id)
		}
		return RoleBindingRow{}, fmt.Errorf("statedb: get role binding %q: %w", id, classifyDriverErr(err))
	}
	r.CreatedAt = parseOptionalTime(created)
	return r, nil
}

// DeleteRoleBinding removes a binding, reporting whether a row existed.
func (d *DB) DeleteRoleBinding(id string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM role_bindings WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("statedb: delete role binding %q: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: delete role binding %q: %w", id, classifyDriverErr(err))
	}
	return n > 0, nil
}
