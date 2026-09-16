// projectlimits.go stores the per-project resource ceiling.
//
// The companion to executors.go's project_executors: both record an operator's
// policy *about* a project rather than a fact belonging to it, which is why
// both live in the control plane and neither is readable from the repository
// the project's developers control.
package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ProjectResourceLimit is one project's ceiling plus its provenance.
type ProjectResourceLimit struct {
	ProjectPath string                   `json:"project_path"`
	Ceiling     executor.ResourceCeiling `json:"ceiling"`
	SetAt       time.Time                `json:"set_at,omitempty"`
	SetBy       string                   `json:"set_by,omitempty"`
}

// SetProjectResourceLimit records a ceiling for projectPath, replacing any
// previous one. setBy is the identity that set it, for the audit trail.
//
// A zero ceiling is stored rather than rejected: "capped at nothing on every
// resource" and "no row" mean the same thing to the dispatch path, but they
// mean different things to the operator reading the panel, who wants to see
// that someone considered this project and decided it needed no cap. Callers
// that mean "remove the policy" call ClearProjectResourceLimit.
func (d *DB) SetProjectResourceLimit(projectPath string, c executor.ResourceCeiling, setBy string) error {
	if strings.TrimSpace(projectPath) == "" {
		return errors.New("statedb: project path is required")
	}
	// Validated here as well as at the HTTP boundary, because this is the last
	// point before the value becomes durable. A negative cap read back out of
	// the database would be a ceiling meaning "unlimited" — the one thing a
	// ceiling may never silently mean.
	if err := c.Validate(); err != nil {
		return fmt.Errorf("statedb: project resource limit for %q: %w", projectPath, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(
		`INSERT INTO project_resource_limits(
		     project_path, cpu_millis, memory_mb, disk_mb, pids, set_at, set_by)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(project_path) DO UPDATE SET
		   cpu_millis = excluded.cpu_millis,
		   memory_mb  = excluded.memory_mb,
		   disk_mb    = excluded.disk_mb,
		   pids       = excluded.pids,
		   set_at     = excluded.set_at,
		   set_by     = excluded.set_by`,
		projectPath, c.CPUMillis, c.MemoryMB, c.DiskMB, c.PIDs,
		time.Now().UTC().Format(time.RFC3339Nano), setBy)
	if err != nil {
		return fmt.Errorf("statedb: set resource limit for %q: %w", projectPath, classifyDriverErr(err))
	}
	return nil
}

// ClearProjectResourceLimit removes the ceiling for projectPath. Clearing a
// project that was never capped is not an error.
func (d *DB) ClearProjectResourceLimit(projectPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`DELETE FROM project_resource_limits WHERE project_path = ?`, projectPath)
	if err != nil {
		return fmt.Errorf("statedb: clear resource limit for %q: %w", projectPath, classifyDriverErr(err))
	}
	return nil
}

// ProjectResourceCeiling returns the ceiling for projectPath.
//
// The boolean is false when the project has no ceiling, which the dispatch path
// reads as "the fleet ceiling alone applies" — deliberately distinct from an
// error, which means the lookup failed and must not be read as "uncapped". A
// storage fault that silently became "no limit" would remove the policy exactly
// when the hub is least healthy.
func (d *DB) ProjectResourceCeiling(projectPath string) (executor.ResourceCeiling, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var c executor.ResourceCeiling
	err := d.conn.QueryRow(
		`SELECT cpu_millis, memory_mb, disk_mb, pids
		   FROM project_resource_limits WHERE project_path = ?`, projectPath,
	).Scan(&c.CPUMillis, &c.MemoryMB, &c.DiskMB, &c.PIDs)
	if errors.Is(err, sql.ErrNoRows) {
		return executor.ResourceCeiling{}, false, nil
	}
	if err != nil {
		return executor.ResourceCeiling{}, false, fmt.Errorf(
			"statedb: resource ceiling for %q: %w", projectPath, classifyDriverErr(err))
	}
	return c, true, nil
}

// ListProjectResourceLimits returns every recorded ceiling, newest first, for
// the operator-facing panel.
func (d *DB) ListProjectResourceLimits() ([]ProjectResourceLimit, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT project_path, cpu_millis, memory_mb, disk_mb, pids, set_at, set_by
		   FROM project_resource_limits ORDER BY set_at DESC, project_path ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list resource limits: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ProjectResourceLimit
	for rows.Next() {
		var (
			l     ProjectResourceLimit
			setAt string
		)
		if err := rows.Scan(&l.ProjectPath, &l.Ceiling.CPUMillis, &l.Ceiling.MemoryMB,
			&l.Ceiling.DiskMB, &l.Ceiling.PIDs, &setAt, &l.SetBy); err != nil {
			return nil, fmt.Errorf("statedb: scan resource limit: %w", classifyDriverErr(err))
		}
		if t, err := time.Parse(time.RFC3339Nano, setAt); err == nil {
			l.SetAt = t
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list resource limits: %w", classifyDriverErr(err))
	}
	return out, nil
}
