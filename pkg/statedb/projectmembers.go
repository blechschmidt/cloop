package statedb

// Per-project membership storage (Task 20366). See
// migrations/0056_project_members.sql for the table and why it is created the
// way it is.
//
// Mechanical accessors only. What a membership means — that it is unioned with
// the identity's other authority, never above the granter's own role, and how a
// path and an identity key are normalised — belongs to pkg/authz,
// pkg/projectmember and pkg/ui. This layer keeps the table readable and keeps
// every change in the same commit as the audit row that records it: a
// membership is an authorization record, and one that changed with nothing on
// the trail is an access change nobody can review.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProjectMemberRow is one row of project_members.
type ProjectMemberRow struct {
	ID          string
	ProjectPath string
	IdentityKey string
	Role        string
	Reason      string
	GrantedAt   time.Time
	GrantedBy   string
}

// ProjectMemberID derives a new membership's id from the one tuple that
// identifies it: the project and the person. Role is not part of it, so
// changing someone's role replaces their row rather than adding a second one
// whose winner nobody could predict.
//
// 96 bits, because the id is also the primary key that keeps the pair unique —
// the table predates this build and has no UNIQUE constraint on the pair.
// Lookups go by the pair, not the id (PutProjectMember), so a collision fails
// an insert rather than landing on another person's row.
func ProjectMemberID(projectPath, identityKey string) string {
	sum := sha256.Sum256([]byte(projectPath + "\x00" + identityKey))
	return "pjm_" + hex.EncodeToString(sum[:12])
}

// MemberAudit builds the audit events committed together with a membership
// change. prev is the row as it stood before the change and next the row after
// it; either is nil when there was none, so a grant has prev == nil and a
// removal next == nil. Returning an error aborts the change: an authorization
// change with no record is treated as one that did not happen.
type MemberAudit func(prev, next *ProjectMemberRow) ([]*AuditEvent, error)

const projectMemberColumns = `id, project_path, identity_key, role, reason, granted_at, granted_by`

// PutProjectMember inserts or replaces one membership and returns the row as
// stored along with the one it replaced (nil for a new member).
//
// A membership is found by its pair — project and identity — never by its id
// alone, so a row written under another id scheme (a stranded build's) is
// still the one replaced, and a new pair whose derived id is taken fails on
// the primary key instead of overwriting somebody else's row.
//
// The caller passes an already-normalised path and identity key;
// pkg/projectmember is the one definition of when two memberships are the
// same, and a second one here would disagree with it exactly when somebody
// re-grants a role.
func (d *DB) PutProjectMember(row ProjectMemberRow, audit MemberAudit) (ProjectMemberRow, *ProjectMemberRow, error) {
	row.ProjectPath = strings.TrimSpace(row.ProjectPath)
	row.IdentityKey = strings.TrimSpace(row.IdentityKey)
	row.Role = strings.TrimSpace(row.Role)
	if row.ProjectPath == "" || row.IdentityKey == "" {
		return ProjectMemberRow{}, nil, errors.New("statedb: a project member needs a project path and an identity key")
	}
	if row.Role == "" {
		return ProjectMemberRow{}, nil, fmt.Errorf("statedb: project member %q needs a role", row.IdentityKey)
	}
	if row.GrantedAt.IsZero() {
		row.GrantedAt = time.Now()
	}
	row.GrantedAt = row.GrantedAt.UTC()

	var prev *ProjectMemberRow
	err := d.memberTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		existing, found, err := getProjectMemberTx(tx, row.ProjectPath, row.IdentityKey)
		if err != nil {
			return nil, err
		}
		if found {
			prev = &existing
			row.ID = existing.ID
			if _, err := tx.Exec(
				`UPDATE project_members SET role = ?, reason = ?, granted_at = ?, granted_by = ? WHERE id = ?`,
				row.Role, row.Reason, formatOptionalTime(row.GrantedAt), row.GrantedBy, row.ID,
			); err != nil {
				return nil, fmt.Errorf("statedb: update project member %s: %w", row.ID, classifyDriverErr(err))
			}
		} else {
			row.ID = ProjectMemberID(row.ProjectPath, row.IdentityKey)
			if _, err := tx.Exec(
				`INSERT INTO project_members (`+projectMemberColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				row.ID, row.ProjectPath, row.IdentityKey, row.Role, row.Reason,
				formatOptionalTime(row.GrantedAt), row.GrantedBy,
			); err != nil {
				return nil, fmt.Errorf("statedb: insert project member %s: %w", row.ID, classifyDriverErr(err))
			}
		}
		if audit == nil {
			return nil, nil
		}
		stored := row
		return audit(prev, &stored)
	})
	if err != nil {
		return ProjectMemberRow{}, nil, err
	}
	return row, prev, nil
}

// DeleteProjectMember removes one membership and returns the row it removed, or
// nil when there was none — in which case nothing is written and audit is not
// called, because nothing changed.
func (d *DB) DeleteProjectMember(projectPath, identityKey string, audit MemberAudit) (*ProjectMemberRow, error) {
	path, key := strings.TrimSpace(projectPath), strings.TrimSpace(identityKey)
	var removed *ProjectMemberRow
	err := d.memberTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		existing, found, err := getProjectMemberTx(tx, path, key)
		if err != nil || !found {
			return nil, err
		}
		if _, err := tx.Exec(`DELETE FROM project_members WHERE project_path = ? AND identity_key = ?`, path, key); err != nil {
			return nil, fmt.Errorf("statedb: delete project member %s: %w", existing.ID, classifyDriverErr(err))
		}
		removed = &existing
		if audit == nil {
			return nil, nil
		}
		return audit(&existing, nil)
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// DeleteProjectMembersOf removes every membership on one project and returns
// the rows removed. Called when the project leaves the hub: memberships are
// keyed by path, and a roster outliving its project would admit those people to
// whatever is registered at that path next. audit is called once per removed
// row.
func (d *DB) DeleteProjectMembersOf(projectPath string, audit MemberAudit) ([]ProjectMemberRow, error) {
	path := strings.TrimSpace(projectPath)
	if path == "" {
		return nil, errors.New("statedb: a project path is required")
	}
	var removed []ProjectMemberRow
	err := d.memberTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		rows, err := queryProjectMembers(tx, `WHERE project_path = ? ORDER BY identity_key`, path)
		if err != nil || len(rows) == 0 {
			return nil, err
		}
		if _, err := tx.Exec(`DELETE FROM project_members WHERE project_path = ?`, path); err != nil {
			return nil, fmt.Errorf("statedb: delete the members of %s: %w", path, classifyDriverErr(err))
		}
		removed = rows
		var evs []*AuditEvent
		if audit != nil {
			for i := range rows {
				more, err := audit(&rows[i], nil)
				if err != nil {
					return nil, err
				}
				evs = append(evs, more...)
			}
		}
		return evs, nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// ListProjectMembers returns every membership on the hub, ordered by project
// then identity. The whole table, because the authorization path needs all of
// it: pkg/projectmember caches one snapshot and answers both "who is on this
// project" and "what does this person hold" from it. Rows number one per
// person per shared project, so the table stays small.
func (d *DB) ListProjectMembers() ([]ProjectMemberRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryProjectMembers(d.conn, `ORDER BY project_path, identity_key`)
}

// GetProjectMember returns one membership, or an error wrapping
// ErrProjectMemberNotFound.
func (d *DB) GetProjectMember(projectPath, identityKey string) (ProjectMemberRow, error) {
	path, key := strings.TrimSpace(projectPath), strings.TrimSpace(identityKey)
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryProjectMembers(d.conn, `WHERE project_path = ? AND identity_key = ?`, path, key)
	if err != nil {
		return ProjectMemberRow{}, err
	}
	if len(rows) == 0 {
		return ProjectMemberRow{}, fmt.Errorf("%w: %s on %s", ErrProjectMemberNotFound, key, path)
	}
	return rows[0], nil
}

// memberTx runs fn in one write transaction and commits the audit events it
// returns in the same commit.
func (d *DB) memberTx(fn func(tx *sql.Tx) ([]*AuditEvent, error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: project members: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	evs, err := fn(tx)
	if err != nil {
		return err
	}
	if len(evs) > 0 {
		// Checked like every other append (audit_home.go); a mis-route is
		// reported, not dropped.
		d.assertAuditHome(evs)
		if err := appendAuditEventsTx(tx, evs); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: project members: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// memberQuerier is what queryProjectMembers reads through: the connection, or
// a transaction already holding the write lock.
type memberQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func queryProjectMembers(q memberQuerier, where string, args ...any) ([]ProjectMemberRow, error) {
	rows, err := q.Query(`SELECT `+projectMemberColumns+` FROM project_members `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list project members: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ProjectMemberRow
	for rows.Next() {
		var r ProjectMemberRow
		var granted string
		if err := rows.Scan(&r.ID, &r.ProjectPath, &r.IdentityKey, &r.Role,
			&r.Reason, &granted, &r.GrantedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan project member: %w", classifyDriverErr(err))
		}
		r.GrantedAt = parseOptionalTime(granted)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list project members: %w", classifyDriverErr(err))
	}
	return out, nil
}

func getProjectMemberTx(tx *sql.Tx, path, key string) (ProjectMemberRow, bool, error) {
	rows, err := queryProjectMembers(tx, `WHERE project_path = ? AND identity_key = ?`, path, key)
	if err != nil || len(rows) == 0 {
		return ProjectMemberRow{}, false, err
	}
	return rows[0], true, nil
}

// deleteProjectMembersForIdentityTx drops every membership held under any of
// keys and returns the rows it dropped. Without the lock, so offboarding can
// sever memberships in the same commit as sessions and tokens.
//
// A list because one person may be recorded under more than one key: a grant
// made to "sub:<subject>" survives a sweep by email, and a surviving
// membership is live read access to a colleague's project.
func deleteProjectMembersForIdentityTx(tx *sql.Tx, keys []string) ([]ProjectMemberRow, error) {
	var out []ProjectMemberRow
	seen := map[string]bool{}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		// Read, then delete: the report names the projects the person was
		// removed from, which a bare RowsAffected cannot.
		found, err := queryProjectMembers(tx, `WHERE identity_key = ? ORDER BY project_path`, key)
		if err != nil {
			return nil, fmt.Errorf("statedb: offboard: %w", err)
		}
		if len(found) == 0 {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM project_members WHERE identity_key = ?`, key); err != nil {
			return nil, fmt.Errorf("statedb: offboard: delete the memberships of %q: %w", key, classifyDriverErr(err))
		}
		out = append(out, found...)
	}
	return out, nil
}
