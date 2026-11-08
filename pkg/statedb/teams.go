package statedb

// Team storage (Task 20478). See migrations/0098_teams.sql for the tables.
//
// Mechanical accessors, like projectmembers.go: what a team means — who is on
// it through an identity-provider group, that "everyone" is every signed-in
// identity, how slugs and identity keys are normalised — belongs to pkg/team.
// What this layer guarantees is the two invariants only a transaction can:
//
//   - every change commits together with the audit rows that record it, and
//   - no project is shared with a team that does not exist. PutProjectMember
//     refuses a "team:<slug>" grantee whose team is missing, and DeleteTeam
//     removes the team's project shares in the same commit as the team. A
//     share left behind by a deleted team would grant nothing until somebody
//     created another team under the same slug, and then grant its members
//     every project the old team could reach.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TeamKeyPrefix starts the project_members identity key of a share with a team:
// "team:<slug>". An identity key of a person is an email or "sub:<subject>",
// neither of which can begin this way.
const TeamKeyPrefix = "team:"

// EveryoneTeam is the built-in team every signed-in identity belongs to. It
// has no row: sharing a project with it needs nothing to exist.
const EveryoneTeam = "everyone"

// TeamRow is one row of teams.
type TeamRow struct {
	Slug        string
	Name        string
	Description string
	IdPGroup    string
	SCIMGroup   string
	CreatedAt   time.Time
	CreatedBy   string
	UpdatedAt   time.Time
	UpdatedBy   string
}

// TeamMemberRow is one row of team_members.
type TeamMemberRow struct {
	TeamSlug    string
	IdentityKey string
	AddedAt     time.Time
	AddedBy     string
}

// TeamChange is what a team write did, for the audit rows committed with it.
// Exactly the fields the operation touched are set.
type TeamChange struct {
	// Prev and Next are the team row before and after; Prev is nil for a
	// creation and Next for a deletion.
	Prev, Next *TeamRow
	// MemberPrev and MemberNext are the member row before and after an add or
	// a removal.
	MemberPrev, MemberNext *TeamMemberRow
	// RemovedMembers and RemovedShares are what a deletion took with it.
	RemovedMembers []TeamMemberRow
	RemovedShares  []ProjectMemberRow
}

// TeamAudit builds the audit events committed together with a team change.
// Returning an error aborts the change: an access change with no record is
// treated as one that did not happen.
type TeamAudit func(TeamChange) ([]*AuditEvent, error)

// TeamShareKey is the project_members identity key of a share with slug.
func TeamShareKey(slug string) string { return TeamKeyPrefix + slug }

// MaxTeamSlugLen bounds a team slug.
const MaxTeamSlugLen = 63

// ValidTeamSlug reports whether slug is a team slug as stored: lowercase
// letters, digits, "-", "_" and ".", starting with a letter or digit, at most
// MaxTeamSlugLen characters. The one definition, read by pkg/hubteam when a
// team is created and by pkg/projectmember when a project is shared with one,
// so the two can never disagree about which shares name a team.
func ValidTeamSlug(slug string) bool {
	if slug == "" || len(slug) > MaxTeamSlugLen {
		return false
	}
	for i, r := range slug {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '-' || r == '_' || r == '.') && i > 0:
		default:
			return false
		}
	}
	return true
}

// TeamSlugOfKey returns the team a project_members identity key names, and
// whether it names one.
func TeamSlugOfKey(key string) (string, bool) {
	if !strings.HasPrefix(key, TeamKeyPrefix) {
		return "", false
	}
	slug := key[len(TeamKeyPrefix):]
	return slug, slug != ""
}

const teamColumns = `slug, name, description, idp_group, scim_group, created_at, created_by, updated_at, updated_by`
const teamMemberColumns = `team_slug, identity_key, added_at, added_by`

// ListTeams returns every team, ordered by slug.
func (d *DB) ListTeams() ([]TeamRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryTeams(d.conn, `ORDER BY slug`)
}

// ListTeamMembers returns every named team member, ordered by team then
// identity. The whole table, for the cache in pkg/team: one row per person per
// team, so it stays small.
func (d *DB) ListTeamMembers() ([]TeamMemberRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryTeamMembers(d.conn, `ORDER BY team_slug, identity_key`)
}

// CreateTeam inserts a team, refusing a slug already taken with an error
// wrapping ErrTeamExists.
func (d *DB) CreateTeam(row TeamRow, audit TeamAudit) (TeamRow, error) {
	row.Slug = strings.TrimSpace(row.Slug)
	if row.Slug == "" {
		return TeamRow{}, errors.New("statedb: a team needs a slug")
	}
	if row.Slug == EveryoneTeam {
		return TeamRow{}, fmt.Errorf("%w: %q is the built-in team of every signed-in identity", ErrTeamExists, row.Slug)
	}
	now := time.Now().UTC()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	row.CreatedAt = row.CreatedAt.UTC()
	row.UpdatedAt, row.UpdatedBy = row.CreatedAt, row.CreatedBy
	err := d.teamTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		if _, found, err := getTeamTx(tx, row.Slug); err != nil {
			return nil, err
		} else if found {
			return nil, fmt.Errorf("%w: %s", ErrTeamExists, row.Slug)
		}
		if _, err := tx.Exec(`INSERT INTO teams (`+teamColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.Slug, row.Name, row.Description, row.IdPGroup, row.SCIMGroup,
			formatOptionalTime(row.CreatedAt), row.CreatedBy, formatOptionalTime(row.UpdatedAt), row.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("statedb: insert team %s: %w", row.Slug, classifyDriverErr(err))
		}
		if audit == nil {
			return nil, nil
		}
		stored := row
		return audit(TeamChange{Next: &stored})
	})
	if err != nil {
		return TeamRow{}, err
	}
	return row, nil
}

// UpdateTeam replaces a team's name, description and links, returning the row
// as stored and the one it replaced. A missing team is an error wrapping
// ErrTeamNotFound.
func (d *DB) UpdateTeam(row TeamRow, audit TeamAudit) (TeamRow, TeamRow, error) {
	row.Slug = strings.TrimSpace(row.Slug)
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now()
	}
	row.UpdatedAt = row.UpdatedAt.UTC()
	var prev TeamRow
	err := d.teamTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		existing, found, err := getTeamTx(tx, row.Slug)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrTeamNotFound, row.Slug)
		}
		prev = existing
		row.CreatedAt, row.CreatedBy = existing.CreatedAt, existing.CreatedBy
		if _, err := tx.Exec(
			`UPDATE teams SET name = ?, description = ?, idp_group = ?, scim_group = ?, updated_at = ?, updated_by = ? WHERE slug = ?`,
			row.Name, row.Description, row.IdPGroup, row.SCIMGroup, formatOptionalTime(row.UpdatedAt), row.UpdatedBy, row.Slug,
		); err != nil {
			return nil, fmt.Errorf("statedb: update team %s: %w", row.Slug, classifyDriverErr(err))
		}
		if audit == nil {
			return nil, nil
		}
		before, after := existing, row
		return audit(TeamChange{Prev: &before, Next: &after})
	})
	if err != nil {
		return TeamRow{}, TeamRow{}, err
	}
	return row, prev, nil
}

// DeleteTeam removes a team, its named members and every project share naming
// it, in one commit, and reports all three. A missing team is an error
// wrapping ErrTeamNotFound.
func (d *DB) DeleteTeam(slug string, audit TeamAudit) (TeamRow, []TeamMemberRow, []ProjectMemberRow, error) {
	slug = strings.TrimSpace(slug)
	var (
		removed TeamRow
		members []TeamMemberRow
		shares  []ProjectMemberRow
	)
	err := d.teamTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		existing, found, err := getTeamTx(tx, slug)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrTeamNotFound, slug)
		}
		removed = existing
		if members, err = queryTeamMembers(tx, `WHERE team_slug = ? ORDER BY identity_key`, slug); err != nil {
			return nil, err
		}
		if shares, err = queryProjectMembers(tx, `WHERE identity_key = ? ORDER BY project_path`, TeamShareKey(slug)); err != nil {
			return nil, err
		}
		for _, stmt := range []struct{ sql, what string }{
			{`DELETE FROM project_members WHERE identity_key = ?`, "project shares"},
			{`DELETE FROM team_members WHERE team_slug = ?`, "members"},
			{`DELETE FROM teams WHERE slug = ?`, "row"},
		} {
			arg := slug
			if stmt.what == "project shares" {
				arg = TeamShareKey(slug)
			}
			if _, err := tx.Exec(stmt.sql, arg); err != nil {
				return nil, fmt.Errorf("statedb: delete team %s: %s: %w", slug, stmt.what, classifyDriverErr(err))
			}
		}
		if audit == nil {
			return nil, nil
		}
		gone := existing
		return audit(TeamChange{Prev: &gone, RemovedMembers: members, RemovedShares: shares})
	})
	if err != nil {
		return TeamRow{}, nil, nil, err
	}
	return removed, members, shares, nil
}

// AddTeamMember adds one named member to a team and returns the row as stored,
// with existed reporting a member already there (nothing is written then, and
// audit is not called). A missing team is an error wrapping ErrTeamNotFound.
func (d *DB) AddTeamMember(row TeamMemberRow, audit TeamAudit) (TeamMemberRow, bool, error) {
	row.TeamSlug, row.IdentityKey = strings.TrimSpace(row.TeamSlug), strings.TrimSpace(row.IdentityKey)
	if row.TeamSlug == "" || row.IdentityKey == "" {
		return TeamMemberRow{}, false, errors.New("statedb: a team member needs a team and an identity key")
	}
	if row.AddedAt.IsZero() {
		row.AddedAt = time.Now()
	}
	row.AddedAt = row.AddedAt.UTC()
	existed := false
	err := d.teamTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		if _, found, err := getTeamTx(tx, row.TeamSlug); err != nil {
			return nil, err
		} else if !found {
			return nil, fmt.Errorf("%w: %s", ErrTeamNotFound, row.TeamSlug)
		}
		have, err := queryTeamMembers(tx, `WHERE team_slug = ? AND identity_key = ?`, row.TeamSlug, row.IdentityKey)
		if err != nil {
			return nil, err
		}
		if len(have) > 0 {
			existed = true
			row = have[0]
			return nil, nil
		}
		if _, err := tx.Exec(`INSERT INTO team_members (`+teamMemberColumns+`) VALUES (?, ?, ?, ?)`,
			row.TeamSlug, row.IdentityKey, formatOptionalTime(row.AddedAt), row.AddedBy,
		); err != nil {
			return nil, fmt.Errorf("statedb: add %s to team %s: %w", row.IdentityKey, row.TeamSlug, classifyDriverErr(err))
		}
		if audit == nil {
			return nil, nil
		}
		added := row
		return audit(TeamChange{MemberNext: &added})
	})
	if err != nil {
		return TeamMemberRow{}, false, err
	}
	return row, existed, nil
}

// RemoveTeamMember removes one named member and returns the row removed, or
// nil when there was none — nothing is written then and audit is not called.
func (d *DB) RemoveTeamMember(slug, identityKey string, audit TeamAudit) (*TeamMemberRow, error) {
	slug, key := strings.TrimSpace(slug), strings.TrimSpace(identityKey)
	var removed *TeamMemberRow
	err := d.teamTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		have, err := queryTeamMembers(tx, `WHERE team_slug = ? AND identity_key = ?`, slug, key)
		if err != nil || len(have) == 0 {
			return nil, err
		}
		if _, err := tx.Exec(`DELETE FROM team_members WHERE team_slug = ? AND identity_key = ?`, slug, key); err != nil {
			return nil, fmt.Errorf("statedb: remove %s from team %s: %w", key, slug, classifyDriverErr(err))
		}
		removed = &have[0]
		if audit == nil {
			return nil, nil
		}
		return audit(TeamChange{MemberPrev: removed})
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// teamTx runs fn in one write transaction and commits the audit events it
// returns in the same commit.
func (d *DB) teamTx(fn func(tx *sql.Tx) ([]*AuditEvent, error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: teams: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	evs, err := fn(tx)
	if err != nil {
		return err
	}
	if len(evs) > 0 {
		d.assertAuditHome(evs)
		if err := appendAuditEventsTx(tx, evs); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: teams: commit: %w", classifyDriverErr(err))
	}
	return nil
}

func queryTeams(q memberQuerier, where string, args ...any) ([]TeamRow, error) {
	rows, err := q.Query(`SELECT `+teamColumns+` FROM teams `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list teams: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []TeamRow
	for rows.Next() {
		var r TeamRow
		var created, updated string
		if err := rows.Scan(&r.Slug, &r.Name, &r.Description, &r.IdPGroup, &r.SCIMGroup,
			&created, &r.CreatedBy, &updated, &r.UpdatedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan team: %w", classifyDriverErr(err))
		}
		r.CreatedAt, r.UpdatedAt = parseOptionalTime(created), parseOptionalTime(updated)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list teams: %w", classifyDriverErr(err))
	}
	return out, nil
}

func queryTeamMembers(q memberQuerier, where string, args ...any) ([]TeamMemberRow, error) {
	rows, err := q.Query(`SELECT `+teamMemberColumns+` FROM team_members `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list team members: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []TeamMemberRow
	for rows.Next() {
		var r TeamMemberRow
		var added string
		if err := rows.Scan(&r.TeamSlug, &r.IdentityKey, &added, &r.AddedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan team member: %w", classifyDriverErr(err))
		}
		r.AddedAt = parseOptionalTime(added)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list team members: %w", classifyDriverErr(err))
	}
	return out, nil
}

func getTeamTx(tx *sql.Tx, slug string) (TeamRow, bool, error) {
	rows, err := queryTeams(tx, `WHERE slug = ?`, slug)
	if err != nil || len(rows) == 0 {
		return TeamRow{}, false, err
	}
	return rows[0], true, nil
}

// requireTeamForShareTx refuses a project share naming a team that does not
// exist. Inside the share's own transaction, so a team deleted a moment ago
// cannot be named by a grant decided against a cache that still listed it.
func requireTeamForShareTx(tx *sql.Tx, identityKey string) error {
	slug, isTeam := TeamSlugOfKey(identityKey)
	if !isTeam || slug == EveryoneTeam {
		return nil
	}
	if _, found, err := getTeamTx(tx, slug); err != nil {
		return err
	} else if !found {
		return fmt.Errorf("%w: %s", ErrTeamNotFound, slug)
	}
	return nil
}

// deleteTeamMembersForIdentityTx drops every named team membership held under
// any of keys and returns the rows dropped. Without the lock, so offboarding
// severs them in the same commit as sessions, tokens and project memberships:
// a departed engineer still named on the payments team is still on every
// project shared with it.
func deleteTeamMembersForIdentityTx(tx *sql.Tx, keys []string) ([]TeamMemberRow, error) {
	var out []TeamMemberRow
	seen := map[string]bool{}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		found, err := queryTeamMembers(tx, `WHERE identity_key = ? ORDER BY team_slug`, key)
		if err != nil {
			return nil, fmt.Errorf("statedb: offboard: %w", err)
		}
		if len(found) == 0 {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM team_members WHERE identity_key = ?`, key); err != nil {
			return nil, fmt.Errorf("statedb: offboard: remove %q from its teams: %w", key, classifyDriverErr(err))
		}
		out = append(out, found...)
	}
	return out, nil
}
