// executorlimits.go stores the per-executor resource ceiling.
//
// The sibling of projectlimits.go, field for field and failure for failure. The
// two exist separately because they answer questions that do not reduce to each
// other: a project's cap travels with the project wherever it is placed, and an
// executor's cap holds whatever lands on it. See
// migrations/0045_executor_resource_limits.sql for why neither the fleet
// ceiling nor the project ceiling can express the second one.
package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ExecutorResourceLimit is one executor's ceiling plus its provenance.
type ExecutorResourceLimit struct {
	ExecutorID string                   `json:"executor_id"`
	Ceiling    executor.ResourceCeiling `json:"ceiling"`
	SetAt      time.Time                `json:"set_at,omitempty"`
	SetBy      string                   `json:"set_by,omitempty"`
}

// SetExecutorResourceLimit records a ceiling for executorID, replacing any
// previous one. setBy is the identity that set it, for the audit trail.
//
// A zero ceiling is stored rather than rejected, for the reason its project
// counterpart is: "considered and capped at nothing" and "never considered"
// are the same to the dispatch path and different to the admin reading the
// panel. Callers that mean "remove the policy" call ClearExecutorResourceLimit.
func (d *DB) SetExecutorResourceLimit(executorID string, c executor.ResourceCeiling, setBy string) error {
	if strings.TrimSpace(executorID) == "" {
		return errors.New("statedb: executor id is required")
	}
	// Validated here as well as at the HTTP boundary, because this is the last
	// point before the value becomes durable. A negative cap read back out of
	// the database would be a ceiling meaning "unlimited" — the one thing a
	// ceiling may never silently mean.
	if err := c.Validate(); err != nil {
		return fmt.Errorf("statedb: executor resource limit for %q: %w", executorID, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(
		`INSERT INTO executor_resource_limits(
		     executor_id, cpu_millis, memory_mb, disk_mb, pids, set_at, set_by)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(executor_id) DO UPDATE SET
		   cpu_millis = excluded.cpu_millis,
		   memory_mb  = excluded.memory_mb,
		   disk_mb    = excluded.disk_mb,
		   pids       = excluded.pids,
		   set_at     = excluded.set_at,
		   set_by     = excluded.set_by`,
		executorID, c.CPUMillis, c.MemoryMB, c.DiskMB, c.PIDs,
		time.Now().UTC().Format(time.RFC3339Nano), setBy)
	if err != nil {
		return fmt.Errorf("statedb: set executor resource limit for %q: %w",
			executorID, classifyDriverErr(err))
	}
	return nil
}

// ClearExecutorResourceLimit removes the ceiling for executorID. Clearing an
// executor that was never capped is not an error.
func (d *DB) ClearExecutorResourceLimit(executorID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`DELETE FROM executor_resource_limits WHERE executor_id = ?`, executorID)
	if err != nil {
		return fmt.Errorf("statedb: clear executor resource limit for %q: %w",
			executorID, classifyDriverErr(err))
	}
	return nil
}

// ExecutorResourceCeiling returns the ceiling for executorID.
//
// The boolean is false when the executor has no ceiling, which the dispatch path
// reads as "the fleet and project ceilings alone apply" — deliberately distinct
// from an error, which means the lookup failed and must not be read as
// "uncapped". A storage fault that silently became "no limit" would remove the
// policy exactly when the hub is least healthy.
func (d *DB) ExecutorResourceCeiling(executorID string) (executor.ResourceCeiling, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var c executor.ResourceCeiling
	err := d.conn.QueryRow(
		`SELECT cpu_millis, memory_mb, disk_mb, pids
		   FROM executor_resource_limits WHERE executor_id = ?`, executorID,
	).Scan(&c.CPUMillis, &c.MemoryMB, &c.DiskMB, &c.PIDs)
	if errors.Is(err, sql.ErrNoRows) {
		return executor.ResourceCeiling{}, false, nil
	}
	if err != nil {
		return executor.ResourceCeiling{}, false, fmt.Errorf(
			"statedb: executor resource ceiling for %q: %w", executorID, classifyDriverErr(err))
	}
	return c, true, nil
}

// ListExecutorResourceLimits returns every recorded executor ceiling, newest
// first, for the admin-facing panel.
func (d *DB) ListExecutorResourceLimits() ([]ExecutorResourceLimit, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT executor_id, cpu_millis, memory_mb, disk_mb, pids, set_at, set_by
		   FROM executor_resource_limits ORDER BY set_at DESC, executor_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor resource limits: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ExecutorResourceLimit
	for rows.Next() {
		var (
			l     ExecutorResourceLimit
			setAt string
		)
		if err := rows.Scan(&l.ExecutorID, &l.Ceiling.CPUMillis, &l.Ceiling.MemoryMB,
			&l.Ceiling.DiskMB, &l.Ceiling.PIDs, &setAt, &l.SetBy); err != nil {
			return nil, fmt.Errorf("statedb: scan executor resource limit: %w", classifyDriverErr(err))
		}
		if t, err := time.Parse(time.RFC3339Nano, setAt); err == nil {
			l.SetAt = t
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor resource limits: %w", classifyDriverErr(err))
	}
	return out, nil
}
