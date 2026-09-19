// executoraudience.go stores who may run work on one executor.
//
// See migrations/0046_executor_audience.sql for why this is a table rather
// than a set of role bindings, and pkg/authz/audience.go for the matching
// semantics. This file is storage only: it does not know who is asking, and
// deliberately does not decide anything.
package statedb

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// ExecutorAudienceEntry is one principal admitted to one executor, plus its
// provenance.
type ExecutorAudienceEntry struct {
	ExecutorID string    `json:"executor_id"`
	Kind       string    `json:"kind"`  // "user" | "group" | "role"
	Value      string    `json:"value"` // as the admin typed it
	AddedAt    time.Time `json:"added_at,omitempty"`
	AddedBy    string    `json:"added_by,omitempty"`
}

// Member renders the entry as the claim predicate pkg/authz matches on.
func (e ExecutorAudienceEntry) Member() authz.AudienceMember {
	return authz.AudienceMemberFor(e.Kind, e.Value)
}

// validAudienceKinds are the principal kinds this binary understands. A row
// naming anything else is stored (it may have been written by a newer binary)
// but never admitted — see authz.AudienceMemberFor, which yields a member that
// matches nothing.
var validAudienceKinds = map[string]bool{"user": true, "group": true, "role": true}

// AddExecutorAudience admits a principal to an executor. Adding one that is
// already admitted refreshes its provenance rather than failing, so the UI's
// "add" button is idempotent.
//
// Note what the first successful call does: it turns the gate on for that
// executor, because an executor with no rows is unrestricted. The caller is
// responsible for not locking the fleet out of itself — see
// pkg/ui/executoraudience.go, which refuses an add that would leave the
// calling admin unable to reach the executor they just restricted.
func (d *DB) AddExecutorAudience(executorID, kind, value, addedBy string) error {
	executorID = strings.TrimSpace(executorID)
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	if executorID == "" {
		return errors.New("statedb: executor id is required")
	}
	if value == "" {
		return errors.New("statedb: audience principal value is required")
	}
	if !validAudienceKinds[kind] {
		return fmt.Errorf("statedb: audience principal kind %q is not one of user, group, role", kind)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(
		`INSERT INTO executor_audience(
		     executor_id, principal_kind, principal_value, added_at, added_by)
		 VALUES(?,?,?,?,?)
		 ON CONFLICT(executor_id, principal_kind, principal_value) DO UPDATE SET
		   added_at = excluded.added_at,
		   added_by = excluded.added_by`,
		executorID, kind, value, time.Now().UTC().Format(time.RFC3339Nano), addedBy)
	if err != nil {
		return fmt.Errorf("statedb: admit %s %q to executor %q: %w",
			kind, value, executorID, classifyDriverErr(err))
	}
	return nil
}

// RemoveExecutorAudience withdraws a principal. Removing one that was never
// admitted is not an error.
//
// Removing the *last* principal makes the executor unrestricted again, which is
// a widening of access rather than a narrowing. That is the correct reading of
// "the list is now empty" and it is why the REST layer audits a removal that
// empties the list distinctly from one that does not.
func (d *DB) RemoveExecutorAudience(executorID, kind, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`DELETE FROM executor_audience
		  WHERE executor_id = ? AND principal_kind = ? AND principal_value = ?`,
		strings.TrimSpace(executorID),
		strings.ToLower(strings.TrimSpace(kind)),
		strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("statedb: withdraw %s %q from executor %q: %w",
			kind, value, executorID, classifyDriverErr(err))
	}
	return nil
}

// ClearExecutorAudience removes every principal, making the executor
// unrestricted. It is what executor deletion calls, so a re-enrolled executor
// reusing an ID does not inherit a stale allowlist.
func (d *DB) ClearExecutorAudience(executorID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`DELETE FROM executor_audience WHERE executor_id = ?`,
		strings.TrimSpace(executorID))
	if err != nil {
		return fmt.Errorf("statedb: clear audience for executor %q: %w",
			executorID, classifyDriverErr(err))
	}
	return nil
}

// ExecutorAudience returns the principals admitted to executorID, oldest first
// so the panel's order is stable as entries are added.
//
// An empty slice with a nil error means the executor is unrestricted. An error
// means the question could not be answered, which callers must not read as
// "unrestricted" — see pkg/ui/executoraudience.go for the failure posture a
// gate requires, which is the opposite of the one a ceiling requires.
func (d *DB) ExecutorAudience(executorID string) ([]ExecutorAudienceEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT executor_id, principal_kind, principal_value, added_at, added_by
		   FROM executor_audience WHERE executor_id = ?
		  ORDER BY added_at ASC, principal_kind ASC, principal_value ASC`,
		strings.TrimSpace(executorID))
	if err != nil {
		return nil, fmt.Errorf("statedb: audience for executor %q: %w",
			executorID, classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ExecutorAudienceEntry
	for rows.Next() {
		var (
			e       ExecutorAudienceEntry
			addedAt string
		)
		if err := rows.Scan(&e.ExecutorID, &e.Kind, &e.Value, &addedAt, &e.AddedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan audience entry: %w", classifyDriverErr(err))
		}
		if t, err := time.Parse(time.RFC3339Nano, addedAt); err == nil {
			e.AddedAt = t
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: audience for executor %q: %w",
			executorID, classifyDriverErr(err))
	}
	return out, nil
}

// AllExecutorAudiences returns every audience row keyed by executor ID.
//
// One query rather than one per executor, because the fleet list renders an
// "available to" summary for every card and the per-executor form would make
// that N+1 round trips against a database the dispatch path also uses.
func (d *DB) AllExecutorAudiences() (map[string][]ExecutorAudienceEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT executor_id, principal_kind, principal_value, added_at, added_by
		   FROM executor_audience
		  ORDER BY executor_id ASC, added_at ASC, principal_kind ASC, principal_value ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor audiences: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	out := map[string][]ExecutorAudienceEntry{}
	for rows.Next() {
		var (
			e       ExecutorAudienceEntry
			addedAt string
		)
		if err := rows.Scan(&e.ExecutorID, &e.Kind, &e.Value, &addedAt, &e.AddedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan audience entry: %w", classifyDriverErr(err))
		}
		if t, err := time.Parse(time.RFC3339Nano, addedAt); err == nil {
			e.AddedAt = t
		}
		out[e.ExecutorID] = append(out[e.ExecutorID], e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor audiences: %w", classifyDriverErr(err))
	}
	return out, nil
}
