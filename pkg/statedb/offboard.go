// Offboarding: sever every durable credential one identity holds, atomically
// (Task 20261).
//
// The surfaces a departing user keeps are stored in three unrelated tables —
// sessions, api_tokens, role_bindings — and before this they were severed by
// three commands run in sequence. That sequence has a failure mode an operator
// cannot see: the second command fails, the first already succeeded, and the
// hub is left in a state nobody described. The account's sessions are gone so
// it looks handled, while a personal access token minted from the same account
// keeps working until its ExpiresAt.
//
// So the write is one transaction. Either the person is out of all three or
// the operator gets an error and the hub is exactly as it was. There is no
// partially-offboarded state to discover later.
//
// What this file deliberately does NOT do is decide *which* rows match the
// person. Token ownership is a claim bundle whose shape belongs to
// pkg/apitoken (see APITokenRow.OwnerJSON), and a second opinion about it here
// is how the two drift apart — in the direction where a token silently fails
// to match and survives the offboarding. Resolution happens in pkg/offboard;
// this layer takes resolved ids and writes them.

package statedb

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// OffboardWrite is the resolved set of rows to sever, plus the deny binding to
// write. Every field is optional: an identity with no API tokens simply passes
// an empty TokenIDs.
type OffboardWrite struct {
	// IdentityKey labels the person in the audit trail. Free-form; pkg/offboard
	// passes the canonical owner key (lowercased email, or "sub:"+subject).
	IdentityKey string

	// SessionIDs are hashed session ids, as stored in sessions.id.
	SessionIDs []string

	// TokenIDs and GlassesIDs both address api_tokens.id. They are separate
	// fields rather than one list because they are separate *surfaces* to an
	// operator — "their PAT still works" and "their glasses link still works"
	// are different incidents — and the audit trail records them separately.
	TokenIDs   []string
	GlassesIDs []string

	// DenyBindings are written in the same transaction. They are what keep the
	// account out if the IdP later hands it a fresh session: revoking sessions
	// alone is undone by the next successful sign-in.
	//
	// It is a list because one identity can be addressed by more than one
	// claim. Denying only the email leaves a re-issued session that carries the
	// same subject and no email claim — which several IdPs do once an account
	// is disabled — matching nothing. pkg/offboard writes one per identifier it
	// resolved.
	DenyBindings []RoleBindingRow

	// At stamps revoked_at. Zero means now.
	At time.Time

	// Audit builds the events to chain into this same commit. It is a callback
	// rather than a slice because it must describe what the transaction
	// actually changed, which is not known until the writes have run: rows
	// disappear between planning and committing (a session expires, a token was
	// already revoked), and an audit trail that reports the plan instead of the
	// outcome is one that overstates containment.
	//
	// Returning no events is allowed. An error aborts the whole transaction —
	// an unrecorded severing of authority is treated as a failed severing,
	// because the operator can safely re-run but cannot recover the record.
	Audit func(OffboardApplied) ([]*AuditEvent, error)
}

// OffboardApplied reports what the transaction actually changed, as opposed to
// what it was asked to change.
type OffboardApplied struct {
	// Sessions, Tokens and Glasses are the ids that really changed state:
	// sessions that existed and were deleted, tokens that were live and are now
	// stamped revoked. Ids that were already gone or already revoked are
	// omitted — they are not this operator's action.
	Sessions []string
	Tokens   []string
	Glasses  []string

	// DenyBindingIDs are the ids of the bindings written.
	DenyBindingIDs []string

	// At is the timestamp stamped on the revocations.
	At time.Time
}

// Severed reports whether anything at all changed.
func (a OffboardApplied) Severed() bool {
	return len(a.Sessions) > 0 || len(a.Tokens) > 0 ||
		len(a.Glasses) > 0 || len(a.DenyBindingIDs) > 0
}

// OffboardIdentity severs the listed sessions and tokens and writes the deny
// binding, in one transaction, chaining the caller's audit events into the same
// commit.
//
// Ordering inside the transaction is deliberate: the deny binding is written
// first. Within a transaction the order is invisible to other readers, but it
// is not invisible to a crash-and-retry: if the commit is lost and the operator
// re-runs, the surface that matters most for a *future* sign-in is the one
// already expressed in the row they will re-write identically (the binding id
// is content-addressed, so re-writing is idempotent).
func (d *DB) OffboardIdentity(w OffboardWrite) (OffboardApplied, error) {
	at := w.At
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return OffboardApplied{}, fmt.Errorf("statedb: offboard: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	applied := OffboardApplied{At: at}

	for _, b := range w.DenyBindings {
		id, err := putRoleBindingTx(tx, b)
		if err != nil {
			return OffboardApplied{}, err
		}
		applied.DenyBindingIDs = append(applied.DenyBindingIDs, id)
	}

	applied.Sessions, err = deleteSessionsTx(tx, w.SessionIDs)
	if err != nil {
		return OffboardApplied{}, err
	}
	applied.Tokens, err = revokeAPITokensTx(tx, w.TokenIDs, at)
	if err != nil {
		return OffboardApplied{}, err
	}
	applied.Glasses, err = revokeAPITokensTx(tx, w.GlassesIDs, at)
	if err != nil {
		return OffboardApplied{}, err
	}

	if w.Audit != nil {
		evs, err := w.Audit(applied)
		if err != nil {
			return OffboardApplied{}, fmt.Errorf("statedb: offboard: build audit: %w", err)
		}
		if err := appendAuditEventsTx(tx, evs); err != nil {
			return OffboardApplied{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return OffboardApplied{}, fmt.Errorf("statedb: offboard: commit: %w", classifyDriverErr(err))
	}
	return applied, nil
}

// deleteSessionsTx removes each id, reporting the ones that existed.
func deleteSessionsTx(tx *sql.Tx, ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			continue
		}
		res, err := tx.Exec(`DELETE FROM sessions WHERE id = ?`, id)
		if err != nil {
			return nil, fmt.Errorf("statedb: offboard: delete session %q: %w", id, classifyDriverErr(err))
		}
		if n, aerr := res.RowsAffected(); aerr == nil && n > 0 {
			out = append(out, id)
		}
	}
	return out, nil
}

// revokeAPITokensTx stamps revoked_at on each id, reporting the ones that were
// still live.
//
// A token that is already revoked is skipped rather than re-stamped, matching
// RevokeAPIToken: the first withdrawal is the date an auditor reads as "when
// did this stop working", and an offboarding run months later must not move it.
// A token id that does not exist at all is likewise not an error here — unlike
// the single-token command, where a typo must be caught, the ids in an
// offboarding batch were resolved from a listing seconds earlier, and one
// vanishing in between means it was revoked concurrently, not mistyped.
func revokeAPITokensTx(tx *sql.Tx, ids []string, at time.Time) ([]string, error) {
	out := make([]string, 0, len(ids))
	stamp := at.UTC().Format(time.RFC3339Nano)
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			continue
		}
		res, err := tx.Exec(
			`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = ''`, stamp, id)
		if err != nil {
			return nil, fmt.Errorf("statedb: offboard: revoke api token %q: %w", id, classifyDriverErr(err))
		}
		if n, aerr := res.RowsAffected(); aerr == nil && n > 0 {
			out = append(out, id)
		}
	}
	return out, nil
}

// putRoleBindingTx is PutRoleBinding's write, without the lock, so it can join
// a transaction the caller already holds.
func putRoleBindingTx(tx *sql.Tx, row RoleBindingRow) (string, error) {
	row.Effect = strings.TrimSpace(strings.ToLower(row.Effect))
	if row.Effect == "" {
		row.Effect = RoleEffectAllow
	}
	if row.Effect != RoleEffectAllow && row.Effect != RoleEffectDeny {
		return "", fmt.Errorf("statedb: role binding effect %q must be %q or %q",
			row.Effect, RoleEffectAllow, RoleEffectDeny)
	}
	if strings.TrimSpace(row.Claim) == "" || strings.TrimSpace(row.Value) == "" {
		return "", fmt.Errorf("statedb: role binding claim and value are required")
	}
	if strings.TrimSpace(row.Role) == "" {
		row.Role = "none"
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	row.ID = RoleBindingID(row.Effect, row.Claim, row.Value, row.Project, row.Executor)

	if _, err := tx.Exec(
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
	); err != nil {
		return "", fmt.Errorf("statedb: offboard: put role binding %q: %w", row.ID, classifyDriverErr(err))
	}
	return row.ID, nil
}
