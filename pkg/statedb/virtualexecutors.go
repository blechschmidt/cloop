// virtualexecutors.go stores virtual executors: named sub-executors of an
// enrolled device, each with its own sandbox configuration (Task 20345).
//
// See migrations/0049_virtual_executors.sql for what the row holds and why
// everything else a virtual executor has — ceilings, access list, bindings —
// lives in the per-executor tables it shares with every other executor.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ErrVirtualExecutorNotFound reports an unknown virtual executor ID.
var ErrVirtualExecutorNotFound = errors.New("statedb: virtual executor not found")

// ErrVirtualExecutorExists reports a create for an ID already in use — by a
// virtual executor or by any other executor the control plane has recorded.
var ErrVirtualExecutorExists = errors.New("statedb: an executor with this id already exists")

// VirtualExecutor is one stored virtual executor.
type VirtualExecutor struct {
	ID       string               `json:"id"`
	ParentID string               `json:"parent_id"`
	Name     string               `json:"name"`
	Spec     executor.VirtualSpec `json:"spec"`
	// CreatedAt/By and UpdatedAt/By are provenance for the panel; the audit
	// trail carries the full history.
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// maxVirtualExecutorName bounds the operator-facing label.
const maxVirtualExecutorName = 64

// normalizeVirtualExecutor validates a row before it is written. The spec is
// stored in normalized form, so what the panel shows after a save is what will
// be sent to the device, not what was typed.
func normalizeVirtualExecutor(v VirtualExecutor) (VirtualExecutor, error) {
	v.ID = strings.TrimSpace(v.ID)
	v.ParentID = strings.TrimSpace(v.ParentID)
	v.Name = strings.TrimSpace(v.Name)
	if v.ID == "" || v.ParentID == "" {
		return VirtualExecutor{}, errors.New("statedb: a virtual executor needs an id and a parent")
	}
	if v.ID == v.ParentID {
		return VirtualExecutor{}, errors.New("statedb: a virtual executor cannot be its own parent")
	}
	if len(v.Name) > maxVirtualExecutorName || strings.ContainsAny(v.Name, "\n\r\t\x00") {
		return VirtualExecutor{}, fmt.Errorf("statedb: virtual executor name must be one line of at most %d "+
			"characters", maxVirtualExecutorName)
	}
	spec, err := v.Spec.Normalize()
	if err != nil {
		return VirtualExecutor{}, err
	}
	v.Spec = spec
	return v, nil
}

// CreateVirtualExecutor records a new virtual executor and the executors-table
// row that makes it bindable, in one transaction.
//
// The ID must be free across *every* executor the control plane knows: a
// virtual executor that shared an ID with a device would inherit that device's
// bindings, ceiling and access list, and a binding meant for one would run on
// the other.
func (d *DB) CreateVirtualExecutor(v VirtualExecutor) error {
	v, err := normalizeVirtualExecutor(v)
	if err != nil {
		return err
	}
	specJSON, err := json.Marshal(v.Spec)
	if err != nil {
		return fmt.Errorf("statedb: encode virtual executor %q: %w", v.ID, err)
	}
	now := time.Now().UTC()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	stamp := v.CreatedAt.UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: create virtual executor %q: begin: %w", v.ID, classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck — no-op once Commit succeeds

	var one int
	switch err := tx.QueryRow(`SELECT 1 FROM executors WHERE id = ?
		UNION SELECT 1 FROM virtual_executors WHERE id = ?`, v.ID, v.ID).Scan(&one); {
	case err == nil:
		return fmt.Errorf("%w: %q", ErrVirtualExecutorExists, v.ID)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("statedb: create virtual executor %q: %w", v.ID, classifyDriverErr(err))
	}
	switch err := tx.QueryRow(`SELECT 1 FROM executors WHERE id = ? AND kind = ?`,
		v.ParentID, executor.KindRemoteAgent).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: parent %q is not an enrolled device", ErrExecutorNotFound, v.ParentID)
	case err != nil:
		return fmt.Errorf("statedb: create virtual executor %q: %w", v.ID, classifyDriverErr(err))
	}

	if _, err := tx.Exec(`INSERT INTO virtual_executors
		(id, parent_id, name, spec_json, created_at, created_by, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.ParentID, v.Name, string(specJSON), stamp, v.CreatedBy, stamp, v.CreatedBy); err != nil {
		return fmt.Errorf("statedb: create virtual executor %q: %w", v.ID, classifyDriverErr(err))
	}
	labels, _ := json.Marshal(map[string]string{"parent": v.ParentID})
	if _, err := tx.Exec(`INSERT INTO executors (id, name, kind, endpoint, status, capabilities_json,
		labels_json, last_heartbeat, created_at, enrolled_by)
		VALUES (?, ?, ?, '', ?, '{}', ?, '', ?, ?)`,
		v.ID, v.Name, executor.KindVirtual, ExecutorStatusUnknown, string(labels), stamp, v.CreatedBy); err != nil {
		return fmt.Errorf("statedb: record virtual executor %q: %w", v.ID, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: create virtual executor %q: commit: %w", v.ID, classifyDriverErr(err))
	}
	return nil
}

// UpdateVirtualExecutor replaces a virtual executor's name and configuration.
// The parent is fixed at creation: moving a sub-executor to another machine
// would carry its bindings and access list to hardware nobody approved them for.
func (d *DB) UpdateVirtualExecutor(id, name string, spec executor.VirtualSpec, by string) error {
	cur, ok, err := d.VirtualExecutor(id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %q", ErrVirtualExecutorNotFound, id)
	}
	cur.Name, cur.Spec = name, spec
	v, err := normalizeVirtualExecutor(cur)
	if err != nil {
		return err
	}
	specJSON, err := json.Marshal(v.Spec)
	if err != nil {
		return fmt.Errorf("statedb: encode virtual executor %q: %w", id, err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: update virtual executor %q: begin: %w", id, classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck — no-op once Commit succeeds
	res, err := tx.Exec(`UPDATE virtual_executors SET name = ?, spec_json = ?, updated_at = ?, updated_by = ?
		WHERE id = ?`, v.Name, string(specJSON), stamp, by, v.ID)
	if err != nil {
		return fmt.Errorf("statedb: update virtual executor %q: %w", id, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %q", ErrVirtualExecutorNotFound, id)
	}
	if _, err := tx.Exec(`UPDATE executors SET name = ? WHERE id = ?`, v.Name, v.ID); err != nil {
		return fmt.Errorf("statedb: rename virtual executor %q: %w", id, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: update virtual executor %q: commit: %w", id, classifyDriverErr(err))
	}
	return nil
}

// VirtualExecutor reads one virtual executor.
func (d *DB) VirtualExecutor(id string) (VirtualExecutor, bool, error) {
	rows, err := d.queryVirtualExecutors(`WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return VirtualExecutor{}, false, err
	}
	if len(rows) == 0 {
		return VirtualExecutor{}, false, nil
	}
	return rows[0], true, nil
}

// ListVirtualExecutors returns every virtual executor, ordered by parent and
// then name.
func (d *DB) ListVirtualExecutors() ([]VirtualExecutor, error) {
	return d.queryVirtualExecutors(`ORDER BY parent_id, name, id`)
}

func (d *DB) queryVirtualExecutors(where string, args ...any) ([]VirtualExecutor, error) {
	rows, err := d.conn.Query(`SELECT id, parent_id, name, spec_json, created_at, created_by,
		updated_at, updated_by FROM virtual_executors `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: read virtual executors: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []VirtualExecutor
	for rows.Next() {
		var v VirtualExecutor
		var specJSON, created, updated string
		if err := rows.Scan(&v.ID, &v.ParentID, &v.Name, &specJSON, &created, &v.CreatedBy,
			&updated, &v.UpdatedBy); err != nil {
			return nil, fmt.Errorf("statedb: read virtual executor: %w", classifyDriverErr(err))
		}
		// A row that no longer decodes is reported, not skipped: skipping
		// would make a virtual executor that projects are bound to vanish
		// from the panel while dispatch keeps refusing to find it.
		if err := json.Unmarshal([]byte(specJSON), &v.Spec); err != nil {
			return nil, fmt.Errorf("statedb: virtual executor %q has an unreadable configuration: %w", v.ID, err)
		}
		v.CreatedAt = parseOptionalTime(created)
		v.UpdatedAt = parseOptionalTime(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteVirtualExecutor removes a virtual executor and everything keyed by its
// ID: its executors-table row, the projects bound to it, and its sandbox,
// ceiling and access-list rows. One transaction, because a half-deleted
// virtual executor whose access list survived would, if the ID were ever
// reused, hand the new one an audience nobody chose for it.
func (d *DB) DeleteVirtualExecutor(id string) error {
	id = strings.TrimSpace(id)
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: delete virtual executor %q: begin: %w", id, classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck — no-op once Commit succeeds
	res, err := tx.Exec(`DELETE FROM virtual_executors WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("statedb: delete virtual executor %q: %w", id, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %q", ErrVirtualExecutorNotFound, id)
	}
	for _, stmt := range []string{
		`DELETE FROM project_executors WHERE executor_id = ?`,
		`DELETE FROM executor_sandbox WHERE executor_id = ?`,
		`DELETE FROM executor_resource_limits WHERE executor_id = ?`,
		`DELETE FROM executor_audience WHERE executor_id = ?`,
		`DELETE FROM executors WHERE id = ? AND kind = '` + executor.KindVirtual + `'`,
	} {
		if _, err := tx.Exec(stmt, id); err != nil {
			return fmt.Errorf("statedb: delete virtual executor %q: %w", id, classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: delete virtual executor %q: commit: %w", id, classifyDriverErr(err))
	}
	return nil
}
