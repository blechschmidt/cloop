// SCIM provisioning storage (Task 20415, migrations/0067_scim_provisioning.sql).
//
// The accessor layer for the directory an identity provider provisions, the
// credential it presents, and the legal holds an offboarding honours. Like
// sessions.go and offboard.go it holds no policy: which hub identity a
// provisioned user is, what deactivating one severs and what a group grants are
// decided in pkg/provision, which hands this layer resolved rows and ids.
//
// What it does guarantee is that each change to the directory is one
// transaction with everything that follows from it and with its audit rows.
// A deactivation writes the user's new state, the deny bindings, the session
// deletions, the token and glasses revocations and the grant suspensions
// together, or nothing — there is no state in which the provider's "inactive"
// is recorded and the person's API token still works.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Sentinels for the SCIM directory.
var (
	// ErrSCIMNotFound: no provisioned user, group or credential has that id.
	ErrSCIMNotFound = errors.New("statedb: scim resource not found")
	// ErrSCIMVersion: the resource changed since the caller read it.
	ErrSCIMVersion = errors.New("statedb: scim resource was changed concurrently")
)

// SCIMConflict reports that a write would give a provisioned resource a value
// another one already holds.
type SCIMConflict struct {
	// Column is the uniqueness rule broken: user_name_key, email,
	// external_id, external_id_key or display_name_key.
	Column string
	// Label is the caller's name for the rule, for the message.
	Label string
	// Value is the contested value, and OtherID the resource holding it.
	Value   string
	OtherID string
}

func (c *SCIMConflict) Error() string {
	return fmt.Sprintf("statedb: %s %q is already held by provisioned resource %s", c.Label, c.Value, c.OtherID)
}

// SCIMUnique is one uniqueness rule a user write must satisfy: no other user
// may hold Value in Column.
type SCIMUnique struct {
	Column string
	Value  string
	Label  string
}

// scimUserUniqueColumns are the columns a SCIMUnique may name. A column is
// interpolated into SQL, so it is checked against this list first.
var scimUserUniqueColumns = map[string]bool{
	"user_name_key": true, "email": true, "external_id": true, "external_id_key": true,
}

// ── users ───────────────────────────────────────────────────────────────────

// SCIMUserRow is one provisioned user.
type SCIMUserRow struct {
	ID          string
	UserName    string
	ExternalID  string
	DisplayName string
	// Email is the account's address, lowercased (scim.UserFields.Email).
	Email  string
	Active bool
	// ResourceJSON is the resource as provisioned, less id, meta, schemas and
	// any password.
	ResourceJSON string
	Version      int64
	CreatedAt    time.Time
	CreatedBy    string
	UpdatedAt    time.Time
	UpdatedBy    string
	// DeactivatedAt is when the user last went inactive; zero while active.
	DeactivatedAt time.Time
	// Suspension is what the suspension in force wrote (SCIMSuspensionRecord
	// as JSON), or "" when none is.
	Suspension string
	// OffboardedAt is when the full offboarding ran for this user.
	OffboardedAt time.Time
}

// SCIMSuspensionRecord is what a suspension wrote and its lift may take back.
type SCIMSuspensionRecord struct {
	At time.Time `json:"at"`
	By string    `json:"by"`
	// Reason is the reason written on the deny bindings. The lift removes a
	// binding only while it still carries it: one an administrator wrote, or
	// re-wrote, for the same identity is theirs and stays.
	Reason string `json:"reason"`
	// Denies are the deny bindings the suspension created — not ones it
	// found already in force.
	Denies []string `json:"denies,omitempty"`
	// Grants are the grants it suspended.
	Grants []string `json:"grants,omitempty"`
	// Identity, Subjects and Emails are the hub identity it resolved, for the
	// offboarding that may follow.
	Identity string   `json:"identity,omitempty"`
	Subjects []string `json:"subjects,omitempty"`
	Emails   []string `json:"emails,omitempty"`
}

// SuspensionRecord decodes the row's suspension, if one is in force.
func (r SCIMUserRow) SuspensionRecord() (SCIMSuspensionRecord, bool) {
	var rec SCIMSuspensionRecord
	if strings.TrimSpace(r.Suspension) == "" {
		return rec, false
	}
	if err := json.Unmarshal([]byte(r.Suspension), &rec); err != nil {
		return rec, false
	}
	return rec, true
}

const scimUserColumns = `id, user_name, external_id, display_name, email, active, resource_json,
	version, created_at, created_by, updated_at, updated_by, deactivated_at, suspension_json, offboarded_at`

func scanSCIMUser(sc rowScanner) (SCIMUserRow, error) {
	var (
		r                                        SCIMUserRow
		active                                   int
		created, updated, deactivated, offboards string
	)
	if err := sc.Scan(&r.ID, &r.UserName, &r.ExternalID, &r.DisplayName, &r.Email, &active, &r.ResourceJSON,
		&r.Version, &created, &r.CreatedBy, &updated, &r.UpdatedBy, &deactivated, &r.Suspension,
		&offboards); err != nil {
		return SCIMUserRow{}, err
	}
	r.Active = active != 0
	r.CreatedAt = parseOptionalTime(created)
	r.UpdatedAt = parseOptionalTime(updated)
	r.DeactivatedAt = parseOptionalTime(deactivated)
	r.OffboardedAt = parseOptionalTime(offboards)
	return r, nil
}

func collectSCIMUsers(rows *sql.Rows) ([]SCIMUserRow, error) {
	defer rows.Close()
	var out []SCIMUserRow
	for rows.Next() {
		r, err := scanSCIMUser(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan scim user: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list scim users: %w", classifyDriverErr(err))
	}
	return out, nil
}

// GetSCIMUser returns one provisioned user, or an error wrapping
// ErrSCIMNotFound.
func (d *DB) GetSCIMUser(id string) (SCIMUserRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return getSCIMUserTx(d.conn, id)
}

type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

func getSCIMUserTx(q queryRower, id string) (SCIMUserRow, error) {
	r, err := scanSCIMUser(q.QueryRow(`SELECT `+scimUserColumns+` FROM scim_users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SCIMUserRow{}, fmt.Errorf("%w: user %q", ErrSCIMNotFound, id)
	}
	if err != nil {
		return SCIMUserRow{}, fmt.Errorf("statedb: get scim user: %w", classifyDriverErr(err))
	}
	return r, nil
}

// ListSCIMUsers returns every provisioned user, oldest first.
func (d *DB) ListSCIMUsers() ([]SCIMUserRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + scimUserColumns + ` FROM scim_users ORDER BY created_at, rowid`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list scim users: %w", classifyDriverErr(err))
	}
	return collectSCIMUsers(rows)
}

// FindSCIMUsers returns the users whose column equals value: user_name_key or
// external_id_key compare lowercased values, external_id and email as given.
func (d *DB) FindSCIMUsers(column, value string) ([]SCIMUserRow, error) {
	if !scimUserUniqueColumns[column] {
		return nil, fmt.Errorf("statedb: scim users cannot be looked up by %q", column)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+scimUserColumns+` FROM scim_users WHERE `+column+` = ? ORDER BY created_at, rowid`,
		value)
	if err != nil {
		return nil, fmt.Errorf("statedb: find scim users: %w", classifyDriverErr(err))
	}
	return collectSCIMUsers(rows)
}

// PendingSCIMOffboards returns the users inactive since before cutoff whose
// full offboarding has not run.
func (d *DB) PendingSCIMOffboards(cutoff time.Time) ([]SCIMUserRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+scimUserColumns+` FROM scim_users
		 WHERE active = 0 AND offboarded_at = '' AND deactivated_at <> '' AND deactivated_at <= ?
		 ORDER BY deactivated_at, id`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("statedb: pending scim offboards: %w", classifyDriverErr(err))
	}
	return collectSCIMUsers(rows)
}

// SCIMUserWrite is one change to a provisioned user, with everything that
// follows from it.
type SCIMUserWrite struct {
	// Row is the user as it is to be stored. Row.Version is ignored: the
	// stored version becomes ExpectVersion+1, or 1 on create.
	Row SCIMUserRow
	// Create inserts; otherwise the row is updated, and only while its stored
	// version is ExpectVersion.
	Create        bool
	ExpectVersion int64
	// Unique are the rules no other user may break.
	Unique []SCIMUnique
	// Suspend, when set, is written with the change; Lift likewise.
	Suspend *SCIMSuspendWrite
	Lift    bool
	// At stamps the change. Zero means now.
	At time.Time
	// Audit builds the audit rows from what was applied, chained into the
	// same commit. An error aborts the write.
	Audit func(SCIMUserApplied) ([]*AuditEvent, error)
}

// SCIMSuspendWrite is what deactivating a user severs in the hub's own
// database: resolved by pkg/provision, written here in one transaction.
type SCIMSuspendWrite struct {
	// Denies are written when no binding with their id exists; a binding
	// already in force — an administrator's — is left as it is.
	Denies []RoleBindingRow
	// SessionIDs are hashed session ids to delete.
	SessionIDs []string
	// TokenIDs and GlassesIDs are api_tokens rows to revoke.
	TokenIDs   []string
	GlassesIDs []string
	// GrantIDs are grants to suspend, when they stand and are not suspended.
	GrantIDs []string
	// Record is what the user's suspension record will say about the
	// identity; the ids written are filled in here.
	Record SCIMSuspensionRecord
}

// SCIMUserApplied reports what a user write changed.
type SCIMUserApplied struct {
	Row SCIMUserRow
	// Suspended: the denies written, sessions deleted, tokens, glasses
	// links and grants severed.
	DeniesWritten   []string
	DeniesInForce   []string
	SessionsDeleted []string
	TokensRevoked   []string
	GlassesRevoked  []string
	GrantsSuspended []string
	// Lifted: the denies removed and grants restored, and the ones left
	// because they were no longer the suspension's.
	DeniesLifted  []string
	DeniesKept    []string
	GrantsResumed []string
	At            time.Time
}

// WriteSCIMUser applies one change to a provisioned user, in one transaction
// with its uniqueness checks, its suspension or lift, its audit rows, and the
// directory version bump other hub members' caches read.
func (d *DB) WriteSCIMUser(w SCIMUserWrite) (SCIMUserApplied, error) {
	at := w.At
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	row := w.Row
	if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.UserName) == "" {
		return SCIMUserApplied{}, errors.New("statedb: a scim user needs an id and a userName")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return SCIMUserApplied{}, fmt.Errorf("statedb: scim user: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	for _, u := range w.Unique {
		if !scimUserUniqueColumns[u.Column] || strings.TrimSpace(u.Value) == "" {
			continue
		}
		var other string
		err := tx.QueryRow(`SELECT id FROM scim_users WHERE `+u.Column+` = ? AND id <> ? LIMIT 1`,
			u.Value, row.ID).Scan(&other)
		switch {
		case err == nil:
			return SCIMUserApplied{}, &SCIMConflict{Column: u.Column, Label: u.Label, Value: u.Value, OtherID: other}
		case !errors.Is(err, sql.ErrNoRows):
			return SCIMUserApplied{}, fmt.Errorf("statedb: scim uniqueness: %w", classifyDriverErr(err))
		}
	}

	applied := SCIMUserApplied{At: at}
	if w.Create {
		row.Version = 1
		row.CreatedAt, row.UpdatedAt = at, at
		if row.CreatedBy == "" {
			row.CreatedBy = row.UpdatedBy
		}
		if !row.Active && row.DeactivatedAt.IsZero() {
			row.DeactivatedAt = at
		}
	} else {
		stored, err := getSCIMUserTx(tx, row.ID)
		if err != nil {
			return SCIMUserApplied{}, err
		}
		if stored.Version != w.ExpectVersion {
			return SCIMUserApplied{}, fmt.Errorf("%w: user %s is at version %d, not %d",
				ErrSCIMVersion, row.ID, stored.Version, w.ExpectVersion)
		}
		row.Version = stored.Version + 1
		row.CreatedAt, row.CreatedBy = stored.CreatedAt, stored.CreatedBy
		row.UpdatedAt = at
		row.OffboardedAt = stored.OffboardedAt
		row.Suspension = stored.Suspension
		switch {
		case stored.Active && !row.Active:
			row.DeactivatedAt = at
		case !row.Active:
			row.DeactivatedAt = stored.DeactivatedAt
		default:
			row.DeactivatedAt = time.Time{}
		}
	}

	if w.Suspend != nil {
		rec := w.Suspend.Record
		rec.At = at
		for _, b := range w.Suspend.Denies {
			id := RoleBindingID(b.Effect, b.Claim, b.Value, b.Project, b.Executor)
			var exists int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM role_bindings WHERE id = ?`, id).Scan(&exists); err != nil {
				return SCIMUserApplied{}, fmt.Errorf("statedb: scim suspend: %w", classifyDriverErr(err))
			}
			if exists > 0 {
				applied.DeniesInForce = append(applied.DeniesInForce, id)
				continue
			}
			if _, err := putRoleBindingTx(tx, b); err != nil {
				return SCIMUserApplied{}, err
			}
			applied.DeniesWritten = append(applied.DeniesWritten, id)
		}
		if applied.SessionsDeleted, err = deleteSessionsTx(tx, w.Suspend.SessionIDs); err != nil {
			return SCIMUserApplied{}, err
		}
		if applied.TokensRevoked, err = revokeAPITokensTx(tx, w.Suspend.TokenIDs, at); err != nil {
			return SCIMUserApplied{}, err
		}
		if applied.GlassesRevoked, err = revokeAPITokensTx(tx, w.Suspend.GlassesIDs, at); err != nil {
			return SCIMUserApplied{}, err
		}
		stamp := at.Format(time.RFC3339Nano)
		for _, id := range w.Suspend.GrantIDs {
			res, err := tx.Exec(`UPDATE broker_grants SET suspended_at = ?, suspended_by = ?
				 WHERE id = ? AND revoked_at = '' AND suspended_at = ''`, stamp, rec.By, id)
			if err != nil {
				return SCIMUserApplied{}, fmt.Errorf("statedb: suspend grant %s: %w", id, classifyDriverErr(err))
			}
			if n, aerr := res.RowsAffected(); aerr == nil && n > 0 {
				applied.GrantsSuspended = append(applied.GrantsSuspended, id)
			}
		}
		// What a suspension already in force wrote stays its own: a second
		// deactivation adds to the record, it does not forget the first.
		if prev, ok := row.SuspensionRecord(); ok {
			rec.Denies = unionStrings(prev.Denies, applied.DeniesWritten)
			rec.Grants = unionStrings(prev.Grants, applied.GrantsSuspended)
			if !prev.At.IsZero() {
				rec.At = prev.At
			}
			if rec.Reason == "" {
				rec.Reason = prev.Reason
			}
		} else {
			rec.Denies = applied.DeniesWritten
			rec.Grants = applied.GrantsSuspended
		}
		blob, err := json.Marshal(rec)
		if err != nil {
			return SCIMUserApplied{}, fmt.Errorf("statedb: encode scim suspension: %w", err)
		}
		row.Suspension = string(blob)
	}

	if w.Lift {
		if rec, ok := row.SuspensionRecord(); ok {
			for _, id := range rec.Denies {
				res, err := tx.Exec(`DELETE FROM role_bindings WHERE id = ? AND effect = ? AND reason = ? AND created_by = ?`,
					id, RoleEffectDeny, rec.Reason, rec.By)
				if err != nil {
					return SCIMUserApplied{}, fmt.Errorf("statedb: lift scim deny %s: %w", id, classifyDriverErr(err))
				}
				if n, aerr := res.RowsAffected(); aerr == nil && n > 0 {
					applied.DeniesLifted = append(applied.DeniesLifted, id)
				} else {
					applied.DeniesKept = append(applied.DeniesKept, id)
				}
			}
			for _, id := range rec.Grants {
				res, err := tx.Exec(`UPDATE broker_grants SET suspended_at = '', suspended_by = ''
					 WHERE id = ? AND suspended_by = ?`, id, rec.By)
				if err != nil {
					return SCIMUserApplied{}, fmt.Errorf("statedb: resume grant %s: %w", id, classifyDriverErr(err))
				}
				if n, aerr := res.RowsAffected(); aerr == nil && n > 0 {
					applied.GrantsResumed = append(applied.GrantsResumed, id)
				}
			}
		}
		row.Suspension = ""
	}

	active := 0
	if row.Active {
		active = 1
	}
	if w.Create {
		if _, err := tx.Exec(`INSERT INTO scim_users (id, user_name, user_name_key, external_id, external_id_key,
			     display_name, email, active, resource_json, version, created_at, created_by, updated_at,
			     updated_by, deactivated_at, suspension_json, offboarded_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			row.ID, row.UserName, strings.ToLower(row.UserName), row.ExternalID, strings.ToLower(row.ExternalID),
			row.DisplayName, row.Email, active, defaultString(row.ResourceJSON, "{}"), row.Version,
			formatOptionalTime(row.CreatedAt), row.CreatedBy, formatOptionalTime(row.UpdatedAt), row.UpdatedBy,
			formatOptionalTime(row.DeactivatedAt), row.Suspension, formatOptionalTime(row.OffboardedAt)); err != nil {
			return SCIMUserApplied{}, fmt.Errorf("statedb: insert scim user: %w", classifyDriverErr(err))
		}
	} else {
		res, err := tx.Exec(`UPDATE scim_users SET user_name = ?, user_name_key = ?, external_id = ?,
			     external_id_key = ?, display_name = ?, email = ?, active = ?, resource_json = ?, version = ?,
			     updated_at = ?, updated_by = ?, deactivated_at = ?, suspension_json = ?
			 WHERE id = ? AND version = ?`,
			row.UserName, strings.ToLower(row.UserName), row.ExternalID, strings.ToLower(row.ExternalID),
			row.DisplayName, row.Email, active, defaultString(row.ResourceJSON, "{}"), row.Version,
			formatOptionalTime(row.UpdatedAt), row.UpdatedBy, formatOptionalTime(row.DeactivatedAt), row.Suspension,
			row.ID, w.ExpectVersion)
		if err != nil {
			return SCIMUserApplied{}, fmt.Errorf("statedb: update scim user: %w", classifyDriverErr(err))
		}
		if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
			return SCIMUserApplied{}, fmt.Errorf("%w: user %s", ErrSCIMVersion, row.ID)
		}
	}
	applied.Row = row

	if w.Audit != nil {
		evs, err := w.Audit(applied)
		if err != nil {
			return SCIMUserApplied{}, fmt.Errorf("statedb: scim user: build audit: %w", err)
		}
		if err := appendAuditEventsTx(tx, evs); err != nil {
			return SCIMUserApplied{}, err
		}
	}
	if err := bumpSCIMVersionTx(tx); err != nil {
		return SCIMUserApplied{}, err
	}
	if err := tx.Commit(); err != nil {
		return SCIMUserApplied{}, fmt.Errorf("statedb: scim user: commit: %w", classifyDriverErr(err))
	}
	return applied, nil
}

// DeleteSCIMUser removes a provisioned user and its group memberships, with
// its audit rows, after the offboarding that deleting one runs.
func (d *DB) DeleteSCIMUser(id string, audit []*AuditEvent) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: delete scim user: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`DELETE FROM scim_users WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("statedb: delete scim user: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if _, err := tx.Exec(`DELETE FROM scim_group_members WHERE user_id = ?`, id); err != nil {
		return false, fmt.Errorf("statedb: delete scim memberships: %w", classifyDriverErr(err))
	}
	if err := appendAuditEventsTx(tx, audit); err != nil {
		return false, err
	}
	if err := bumpSCIMVersionTx(tx); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: delete scim user: commit: %w", classifyDriverErr(err))
	}
	return true, nil
}

// MarkSCIMUserOffboarded records that the full offboarding ran for a user and
// clears its suspension record: what an offboarding destroyed is never
// restored, so a later reactivation must find nothing to lift. It reports
// false when the user is gone, active again, or already marked.
func (d *DB) MarkSCIMUserOffboarded(id string, at time.Time, audit []*AuditEvent) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: mark scim offboarded: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`UPDATE scim_users SET offboarded_at = ?, suspension_json = '', version = version + 1
		 WHERE id = ? AND offboarded_at = ''`, at.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return false, fmt.Errorf("statedb: mark scim offboarded: %w", classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if err := appendAuditEventsTx(tx, audit); err != nil {
		return false, err
	}
	if err := bumpSCIMVersionTx(tx); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: mark scim offboarded: commit: %w", classifyDriverErr(err))
	}
	return true, nil
}

// ── groups ──────────────────────────────────────────────────────────────────

// SCIMGroupRow is one provisioned group.
type SCIMGroupRow struct {
	ID           string
	DisplayName  string
	ExternalID   string
	ResourceJSON string
	Version      int64
	CreatedAt    time.Time
	CreatedBy    string
	UpdatedAt    time.Time
	UpdatedBy    string
	// Members are the member user ids, sorted.
	Members []string
}

const scimGroupColumns = `id, display_name, external_id, resource_json, version, created_at, created_by,
	updated_at, updated_by`

func scanSCIMGroup(sc rowScanner) (SCIMGroupRow, error) {
	var (
		g                SCIMGroupRow
		created, updated string
	)
	if err := sc.Scan(&g.ID, &g.DisplayName, &g.ExternalID, &g.ResourceJSON, &g.Version, &created, &g.CreatedBy,
		&updated, &g.UpdatedBy); err != nil {
		return SCIMGroupRow{}, err
	}
	g.CreatedAt = parseOptionalTime(created)
	g.UpdatedAt = parseOptionalTime(updated)
	return g, nil
}

type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func groupMembersTx(q queryer, groupID string) ([]string, error) {
	rows, err := q.Query(`SELECT user_id FROM scim_group_members WHERE group_id = ? ORDER BY user_id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("statedb: scim group members: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("statedb: scan scim group member: %w", classifyDriverErr(err))
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// GetSCIMGroup returns one provisioned group with its members.
func (d *DB) GetSCIMGroup(id string) (SCIMGroupRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	g, err := scanSCIMGroup(d.conn.QueryRow(`SELECT `+scimGroupColumns+` FROM scim_groups WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SCIMGroupRow{}, fmt.Errorf("%w: group %q", ErrSCIMNotFound, id)
	}
	if err != nil {
		return SCIMGroupRow{}, fmt.Errorf("statedb: get scim group: %w", classifyDriverErr(err))
	}
	if g.Members, err = groupMembersTx(d.conn, id); err != nil {
		return SCIMGroupRow{}, err
	}
	return g, nil
}

// ListSCIMGroups returns every provisioned group, oldest first, with members
// when withMembers is set.
func (d *DB) ListSCIMGroups(withMembers bool) ([]SCIMGroupRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + scimGroupColumns + ` FROM scim_groups ORDER BY created_at, rowid`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list scim groups: %w", classifyDriverErr(err))
	}
	var out []SCIMGroupRow
	for rows.Next() {
		g, err := scanSCIMGroup(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("statedb: scan scim group: %w", classifyDriverErr(err))
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("statedb: list scim groups: %w", classifyDriverErr(err))
	}
	rows.Close()
	if withMembers {
		members, err := allGroupMembers(d.conn)
		if err != nil {
			return nil, err
		}
		for i := range out {
			out[i].Members = members[out[i].ID]
		}
	}
	return out, nil
}

func allGroupMembers(q queryer) (map[string][]string, error) {
	rows, err := q.Query(`SELECT group_id, user_id FROM scim_group_members ORDER BY group_id, user_id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: scim group members: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g, u string
		if err := rows.Scan(&g, &u); err != nil {
			return nil, fmt.Errorf("statedb: scan scim group member: %w", classifyDriverErr(err))
		}
		out[g] = append(out[g], u)
	}
	return out, rows.Err()
}

// SCIMGroupsOf returns the ids of the groups a user belongs to.
func (d *DB) SCIMGroupsOf(userID string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT group_id FROM scim_group_members WHERE user_id = ? ORDER BY group_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("statedb: scim groups of user: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("statedb: scan scim group: %w", classifyDriverErr(err))
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// FindSCIMGroups returns the groups whose display name is name, compared
// lowercased, or whose external id is name, exactly.
func (d *DB) FindSCIMGroups(byDisplayName bool, value string) ([]SCIMGroupRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	col, arg := "external_id", value
	if byDisplayName {
		col, arg = "display_name_key", strings.ToLower(value)
	}
	rows, err := d.conn.Query(`SELECT `+scimGroupColumns+` FROM scim_groups WHERE `+col+` = ? ORDER BY created_at, rowid`,
		arg)
	if err != nil {
		return nil, fmt.Errorf("statedb: find scim groups: %w", classifyDriverErr(err))
	}
	var out []SCIMGroupRow
	for rows.Next() {
		g, err := scanSCIMGroup(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("statedb: scan scim group: %w", classifyDriverErr(err))
		}
		out = append(out, g)
	}
	rows.Close()
	for i := range out {
		if out[i].Members, err = groupMembersTx(d.conn, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SCIMGroupWrite is one change to a provisioned group.
type SCIMGroupWrite struct {
	Row           SCIMGroupRow
	Create        bool
	ExpectVersion int64
	// SetMembers replaces the membership with Row.Members. Without it the
	// membership is left as it is.
	SetMembers bool
	At         time.Time
	Audit      func(SCIMGroupApplied) ([]*AuditEvent, error)
}

// SCIMGroupApplied reports what a group write changed.
type SCIMGroupApplied struct {
	Row SCIMGroupRow
	// Added and Removed are the membership changes; Unknown the member ids
	// asked for that name no provisioned user, which were not stored.
	Added   []string
	Removed []string
	Unknown []string
	At      time.Time
}

// WriteSCIMGroup applies one change to a provisioned group in one
// transaction: its uniqueness check on the display name, its membership, its
// audit rows and the directory version bump.
func (d *DB) WriteSCIMGroup(w SCIMGroupWrite) (SCIMGroupApplied, error) {
	at := w.At
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	g := w.Row
	if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.DisplayName) == "" {
		return SCIMGroupApplied{}, errors.New("statedb: a scim group needs an id and a displayName")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return SCIMGroupApplied{}, fmt.Errorf("statedb: scim group: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	var other string
	err = tx.QueryRow(`SELECT id FROM scim_groups WHERE display_name_key = ? AND id <> ? LIMIT 1`,
		strings.ToLower(g.DisplayName), g.ID).Scan(&other)
	switch {
	case err == nil:
		return SCIMGroupApplied{}, &SCIMConflict{Column: "display_name_key", Label: "displayName",
			Value: g.DisplayName, OtherID: other}
	case !errors.Is(err, sql.ErrNoRows):
		return SCIMGroupApplied{}, fmt.Errorf("statedb: scim group uniqueness: %w", classifyDriverErr(err))
	}

	applied := SCIMGroupApplied{At: at}
	if w.Create {
		g.Version = 1
		g.CreatedAt, g.UpdatedAt = at, at
		if g.CreatedBy == "" {
			g.CreatedBy = g.UpdatedBy
		}
		if _, err := tx.Exec(`INSERT INTO scim_groups (id, display_name, display_name_key, external_id,
			     resource_json, version, created_at, created_by, updated_at, updated_by)
			 VALUES (?,?,?,?,?,?,?,?,?,?)`,
			g.ID, g.DisplayName, strings.ToLower(g.DisplayName), g.ExternalID, defaultString(g.ResourceJSON, "{}"),
			g.Version, formatOptionalTime(g.CreatedAt), g.CreatedBy, formatOptionalTime(g.UpdatedAt),
			g.UpdatedBy); err != nil {
			return SCIMGroupApplied{}, fmt.Errorf("statedb: insert scim group: %w", classifyDriverErr(err))
		}
	} else {
		stored, err := scanSCIMGroup(tx.QueryRow(`SELECT `+scimGroupColumns+` FROM scim_groups WHERE id = ?`, g.ID))
		if errors.Is(err, sql.ErrNoRows) {
			return SCIMGroupApplied{}, fmt.Errorf("%w: group %q", ErrSCIMNotFound, g.ID)
		}
		if err != nil {
			return SCIMGroupApplied{}, fmt.Errorf("statedb: get scim group: %w", classifyDriverErr(err))
		}
		if stored.Version != w.ExpectVersion {
			return SCIMGroupApplied{}, fmt.Errorf("%w: group %s is at version %d, not %d",
				ErrSCIMVersion, g.ID, stored.Version, w.ExpectVersion)
		}
		g.Version = stored.Version + 1
		g.CreatedAt, g.CreatedBy, g.UpdatedAt = stored.CreatedAt, stored.CreatedBy, at
		res, err := tx.Exec(`UPDATE scim_groups SET display_name = ?, display_name_key = ?, external_id = ?,
			     resource_json = ?, version = ?, updated_at = ?, updated_by = ?
			 WHERE id = ? AND version = ?`,
			g.DisplayName, strings.ToLower(g.DisplayName), g.ExternalID, defaultString(g.ResourceJSON, "{}"),
			g.Version, formatOptionalTime(g.UpdatedAt), g.UpdatedBy, g.ID, w.ExpectVersion)
		if err != nil {
			return SCIMGroupApplied{}, fmt.Errorf("statedb: update scim group: %w", classifyDriverErr(err))
		}
		if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
			return SCIMGroupApplied{}, fmt.Errorf("%w: group %s", ErrSCIMVersion, g.ID)
		}
	}

	current, err := groupMembersTx(tx, g.ID)
	if err != nil {
		return SCIMGroupApplied{}, err
	}
	if w.SetMembers {
		want := map[string]bool{}
		for _, id := range g.Members {
			id = strings.TrimSpace(id)
			if id == "" || want[id] {
				continue
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM scim_users WHERE id = ?`, id).Scan(&n); err != nil {
				return SCIMGroupApplied{}, fmt.Errorf("statedb: scim member %s: %w", id, classifyDriverErr(err))
			}
			if n == 0 {
				applied.Unknown = append(applied.Unknown, id)
				continue
			}
			want[id] = true
		}
		// The new members first, then the ones going away: a member who
		// stays is never touched, and no row is deleted to make room for
		// one written in its place (tests/arch/rowreplace_test.go).
		have := map[string]bool{}
		for _, id := range current {
			have[id] = true
		}
		for id := range want {
			if have[id] {
				continue
			}
			if _, err := tx.Exec(`INSERT INTO scim_group_members (group_id, user_id, added_at) VALUES (?,?,?)`,
				g.ID, id, at.Format(time.RFC3339Nano)); err != nil {
				return SCIMGroupApplied{}, fmt.Errorf("statedb: add scim member: %w", classifyDriverErr(err))
			}
			applied.Added = append(applied.Added, id)
		}
		for _, id := range current {
			if want[id] {
				continue
			}
			if _, err := tx.Exec(`DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?`,
				g.ID, id); err != nil {
				return SCIMGroupApplied{}, fmt.Errorf("statedb: remove scim member: %w", classifyDriverErr(err))
			}
			applied.Removed = append(applied.Removed, id)
		}
		sort.Strings(applied.Added)
		sort.Strings(applied.Removed)
		current, err = groupMembersTx(tx, g.ID)
		if err != nil {
			return SCIMGroupApplied{}, err
		}
	}
	g.Members = current
	applied.Row = g

	if w.Audit != nil {
		evs, err := w.Audit(applied)
		if err != nil {
			return SCIMGroupApplied{}, fmt.Errorf("statedb: scim group: build audit: %w", err)
		}
		if err := appendAuditEventsTx(tx, evs); err != nil {
			return SCIMGroupApplied{}, err
		}
	}
	if err := bumpSCIMVersionTx(tx); err != nil {
		return SCIMGroupApplied{}, err
	}
	if err := tx.Commit(); err != nil {
		return SCIMGroupApplied{}, fmt.Errorf("statedb: scim group: commit: %w", classifyDriverErr(err))
	}
	return applied, nil
}

// DeleteSCIMGroup removes a provisioned group and its memberships.
func (d *DB) DeleteSCIMGroup(id string, audit []*AuditEvent) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: delete scim group: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`DELETE FROM scim_groups WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("statedb: delete scim group: %w", classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.Exec(`DELETE FROM scim_group_members WHERE group_id = ?`, id); err != nil {
		return false, fmt.Errorf("statedb: delete scim group members: %w", classifyDriverErr(err))
	}
	if err := appendAuditEventsTx(tx, audit); err != nil {
		return false, err
	}
	if err := bumpSCIMVersionTx(tx); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: delete scim group: commit: %w", classifyDriverErr(err))
	}
	return true, nil
}

// ── the directory, for the authorization cache ──────────────────────────────

// SCIMDirectory is what the authorization path needs of the directory: every
// user's identifiers and state, and the groups each belongs to.
type SCIMDirectory struct {
	Version int64
	Users   []SCIMDirectoryUser
	// Groups maps a group id to its display name and external id.
	Groups map[string]SCIMDirectoryGroup
}

// SCIMDirectoryUser is one user, without its resource.
type SCIMDirectoryUser struct {
	ID         string
	UserName   string
	ExternalID string
	Email      string
	Active     bool
	GroupIDs   []string
}

// SCIMDirectoryGroup is one group's names.
type SCIMDirectoryGroup struct {
	DisplayName string
	ExternalID  string
}

// LoadSCIMDirectory reads the whole directory at one version.
func (d *DB) LoadSCIMDirectory() (SCIMDirectory, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return SCIMDirectory{}, fmt.Errorf("statedb: load scim directory: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	dir := SCIMDirectory{Groups: map[string]SCIMDirectoryGroup{}}
	if dir.Version, err = scimVersionTx(tx); err != nil {
		return SCIMDirectory{}, err
	}
	members := map[string][]string{} // user -> groups
	rows, err := tx.Query(`SELECT group_id, user_id FROM scim_group_members`)
	if err != nil {
		return SCIMDirectory{}, fmt.Errorf("statedb: load scim memberships: %w", classifyDriverErr(err))
	}
	for rows.Next() {
		var g, u string
		if err := rows.Scan(&g, &u); err != nil {
			rows.Close()
			return SCIMDirectory{}, fmt.Errorf("statedb: scan scim membership: %w", classifyDriverErr(err))
		}
		members[u] = append(members[u], g)
	}
	rows.Close()
	rows, err = tx.Query(`SELECT id, display_name, external_id FROM scim_groups`)
	if err != nil {
		return SCIMDirectory{}, fmt.Errorf("statedb: load scim groups: %w", classifyDriverErr(err))
	}
	for rows.Next() {
		var id string
		var g SCIMDirectoryGroup
		if err := rows.Scan(&id, &g.DisplayName, &g.ExternalID); err != nil {
			rows.Close()
			return SCIMDirectory{}, fmt.Errorf("statedb: scan scim group: %w", classifyDriverErr(err))
		}
		dir.Groups[id] = g
	}
	rows.Close()
	rows, err = tx.Query(`SELECT id, user_name, external_id, email, active FROM scim_users`)
	if err != nil {
		return SCIMDirectory{}, fmt.Errorf("statedb: load scim users: %w", classifyDriverErr(err))
	}
	for rows.Next() {
		var u SCIMDirectoryUser
		var active int
		if err := rows.Scan(&u.ID, &u.UserName, &u.ExternalID, &u.Email, &active); err != nil {
			rows.Close()
			return SCIMDirectory{}, fmt.Errorf("statedb: scan scim user: %w", classifyDriverErr(err))
		}
		u.Active = active != 0
		u.GroupIDs = members[u.ID]
		dir.Users = append(dir.Users, u)
	}
	rows.Close()
	return dir, nil
}

// SCIMDirectoryVersion reads the directory's version: one row, for a cache
// deciding whether to reload.
func (d *DB) SCIMDirectoryVersion() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return scimVersionTx(d.conn)
}

func scimVersionTx(q queryRower) (int64, error) {
	var v string
	err := q.QueryRow(`SELECT value FROM scim_meta WHERE key = 'version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("statedb: scim directory version: %w", classifyDriverErr(err))
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n, nil
}

func bumpSCIMVersionTx(tx *sql.Tx) error {
	if _, err := tx.Exec(`INSERT INTO scim_meta (key, value) VALUES ('version', '1')
		 ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)`); err != nil {
		return fmt.Errorf("statedb: bump scim directory version: %w", classifyDriverErr(err))
	}
	return nil
}

// ── credentials ─────────────────────────────────────────────────────────────

// SCIMCredentialRow is one SCIM bearer credential. Only HMACs of its secret
// are stored.
type SCIMCredentialRow struct {
	ID                string
	Name              string
	SecretHash        string
	PreviousHash      string
	PreviousExpiresAt time.Time
	CreatedAt         time.Time
	CreatedBy         string
	RotatedAt         time.Time
	RotatedBy         string
	RevokedAt         time.Time
	RevokedBy         string
	LastUsedAt        time.Time
}

// Revoked reports whether the credential was revoked.
func (c SCIMCredentialRow) Revoked() bool { return !c.RevokedAt.IsZero() }

const scimCredentialColumns = `id, name, secret_hash, previous_hash, previous_expires_at, created_at, created_by,
	rotated_at, rotated_by, revoked_at, revoked_by, last_used_at`

func scanSCIMCredential(sc rowScanner) (SCIMCredentialRow, error) {
	var (
		c                                        SCIMCredentialRow
		prevExp, created, rotated, revoked, used string
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.SecretHash, &c.PreviousHash, &prevExp, &created, &c.CreatedBy,
		&rotated, &c.RotatedBy, &revoked, &c.RevokedBy, &used); err != nil {
		return SCIMCredentialRow{}, err
	}
	c.PreviousExpiresAt = parseOptionalTime(prevExp)
	c.CreatedAt = parseOptionalTime(created)
	c.RotatedAt = parseOptionalTime(rotated)
	c.RevokedAt = parseOptionalTime(revoked)
	c.LastUsedAt = parseOptionalTime(used)
	return c, nil
}

// GetSCIMCredential returns one credential by id.
func (d *DB) GetSCIMCredential(id string) (SCIMCredentialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := scanSCIMCredential(d.conn.QueryRow(`SELECT `+scimCredentialColumns+` FROM scim_credentials WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SCIMCredentialRow{}, fmt.Errorf("%w: credential %q", ErrSCIMNotFound, id)
	}
	if err != nil {
		return SCIMCredentialRow{}, fmt.Errorf("statedb: get scim credential: %w", classifyDriverErr(err))
	}
	return c, nil
}

// ListSCIMCredentials returns every credential, revoked ones included, newest
// first.
func (d *DB) ListSCIMCredentials() ([]SCIMCredentialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + scimCredentialColumns + ` FROM scim_credentials ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list scim credentials: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []SCIMCredentialRow
	for rows.Next() {
		c, err := scanSCIMCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan scim credential: %w", classifyDriverErr(err))
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertSCIMCredential stores a new credential, refusing a name a live one
// already has, in one transaction with its audit row.
func (d *DB) InsertSCIMCredential(c SCIMCredentialRow, audit *AuditEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: insert scim credential: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	var other string
	err = tx.QueryRow(`SELECT id FROM scim_credentials WHERE name = ? AND revoked_at = '' LIMIT 1`, c.Name).Scan(&other)
	switch {
	case err == nil:
		return &SCIMConflict{Column: "name", Label: "credential name", Value: c.Name, OtherID: other}
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("statedb: scim credential name: %w", classifyDriverErr(err))
	}
	if _, err := tx.Exec(`INSERT INTO scim_credentials (`+scimCredentialColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Name, c.SecretHash, c.PreviousHash, formatOptionalTime(c.PreviousExpiresAt),
		formatOptionalTime(c.CreatedAt), c.CreatedBy, formatOptionalTime(c.RotatedAt), c.RotatedBy,
		formatOptionalTime(c.RevokedAt), c.RevokedBy, formatOptionalTime(c.LastUsedAt)); err != nil {
		return fmt.Errorf("statedb: insert scim credential: %w", classifyDriverErr(err))
	}
	if audit != nil {
		if err := appendAuditEventsTx(tx, []*AuditEvent{audit}); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: insert scim credential: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// RotateSCIMCredential replaces a live credential's secret. The secret it
// replaces stays valid until previousExpires — zero ends it at once.
func (d *DB) RotateSCIMCredential(id, secretHash, previousHash string, previousExpires, at time.Time, by string,
	audit *AuditEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: rotate scim credential: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	if previousExpires.IsZero() {
		previousHash = ""
	}
	res, err := tx.Exec(`UPDATE scim_credentials SET secret_hash = ?, previous_hash = ?, previous_expires_at = ?,
		     rotated_at = ?, rotated_by = ?
		 WHERE id = ? AND revoked_at = ''`,
		secretHash, previousHash, formatOptionalTime(previousExpires), at.UTC().Format(time.RFC3339Nano), by, id)
	if err != nil {
		return fmt.Errorf("statedb: rotate scim credential: %w", classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: no live credential %q", ErrSCIMNotFound, id)
	}
	if audit != nil {
		if err := appendAuditEventsTx(tx, []*AuditEvent{audit}); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: rotate scim credential: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// RevokeSCIMCredential revokes a credential, both its secrets at once. A
// credential already revoked keeps the time it was revoked at and reports
// false.
func (d *DB) RevokeSCIMCredential(id string, at time.Time, by string, audit *AuditEvent) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: revoke scim credential: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`UPDATE scim_credentials SET revoked_at = ?, revoked_by = ?, previous_hash = '',
		     previous_expires_at = ''
		 WHERE id = ? AND revoked_at = ''`, at.UTC().Format(time.RFC3339Nano), by, id)
	if err != nil {
		return false, fmt.Errorf("statedb: revoke scim credential: %w", classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var exists int
		if qerr := tx.QueryRow(`SELECT COUNT(*) FROM scim_credentials WHERE id = ?`, id).Scan(&exists); qerr == nil &&
			exists == 0 {
			return false, fmt.Errorf("%w: credential %q", ErrSCIMNotFound, id)
		}
		return false, nil
	}
	if audit != nil {
		if err := appendAuditEventsTx(tx, []*AuditEvent{audit}); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: revoke scim credential: commit: %w", classifyDriverErr(err))
	}
	return true, nil
}

// TouchSCIMCredential records a use, moving last_used_at forward only.
func (d *DB) TouchSCIMCredential(id string, at time.Time) error {
	stamp := at.UTC().Format(time.RFC3339Nano)
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE scim_credentials SET last_used_at = ? WHERE id = ? AND last_used_at < ?`,
		stamp, id, stamp); err != nil {
		return fmt.Errorf("statedb: touch scim credential: %w", classifyDriverErr(err))
	}
	return nil
}

// ── legal holds ─────────────────────────────────────────────────────────────

// LegalHoldRow is one identity under a legal hold.
type LegalHoldRow struct {
	Identity string
	Reason   string
	PlacedAt time.Time
	PlacedBy string
}

// PutLegalHold places a hold, or restates one already placed — its reason and
// who placed it are replaced, its first placement time kept.
func (d *DB) PutLegalHold(h LegalHoldRow, audit *AuditEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: legal hold: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`INSERT INTO legal_holds (identity, reason, placed_at, placed_by) VALUES (?,?,?,?)
		 ON CONFLICT(identity) DO UPDATE SET reason = excluded.reason, placed_by = excluded.placed_by`,
		h.Identity, h.Reason, formatOptionalTime(h.PlacedAt), h.PlacedBy); err != nil {
		return fmt.Errorf("statedb: put legal hold: %w", classifyDriverErr(err))
	}
	if audit != nil {
		if err := appendAuditEventsTx(tx, []*AuditEvent{audit}); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: legal hold: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// DeleteLegalHold releases a hold, reporting whether one was placed.
func (d *DB) DeleteLegalHold(identity string, audit *AuditEvent) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: release legal hold: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`DELETE FROM legal_holds WHERE identity = ?`, identity)
	if err != nil {
		return false, fmt.Errorf("statedb: release legal hold: %w", classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if audit != nil {
		if err := appendAuditEventsTx(tx, []*AuditEvent{audit}); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: release legal hold: commit: %w", classifyDriverErr(err))
	}
	return true, nil
}

// ListLegalHolds returns every hold.
func (d *DB) ListLegalHolds() ([]LegalHoldRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT identity, reason, placed_at, placed_by FROM legal_holds ORDER BY identity`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list legal holds: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []LegalHoldRow
	for rows.Next() {
		var h LegalHoldRow
		var placed string
		if err := rows.Scan(&h.Identity, &h.Reason, &placed, &h.PlacedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan legal hold: %w", classifyDriverErr(err))
		}
		h.PlacedAt = parseOptionalTime(placed)
		out = append(out, h)
	}
	return out, rows.Err()
}

// LegalHoldFor returns the hold placed on any of identities, if there is one.
func (d *DB) LegalHoldFor(identities []string) (LegalHoldRow, bool, error) {
	if len(identities) == 0 {
		return LegalHoldRow{}, false, nil
	}
	holds, err := d.ListLegalHolds()
	if err != nil {
		return LegalHoldRow{}, false, err
	}
	want := map[string]bool{}
	for _, id := range identities {
		want[strings.ToLower(strings.TrimSpace(id))] = true
	}
	for _, h := range holds {
		if want[strings.ToLower(h.Identity)] {
			return h, true, nil
		}
	}
	return LegalHoldRow{}, false, nil
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
