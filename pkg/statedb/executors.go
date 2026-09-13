// Executor registry persistence (Task 20156).
//
// The control plane keeps a durable record of every execution backend it
// knows about — the local host, container runtimes, enrolled remote agents —
// plus which executor each project is pinned to. pkg/executor holds the live
// registry; this file is its storage.
//
// Capabilities and labels are stored as JSON blobs rather than normalized
// columns on purpose: they are driver-defined, evolve independently of the
// schema, and are only ever read whole.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Executor health states as persisted in the status column.
const (
	ExecutorStatusOnline   = "online"
	ExecutorStatusOffline  = "offline"
	ExecutorStatusDegraded = "degraded"
	ExecutorStatusUnknown  = "unknown"
)

// ExecutorRow is one persisted execution backend.
type ExecutorRow struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	Endpoint      string            `json:"endpoint,omitempty"`
	Status        string            `json:"status"`
	Capabilities  json.RawMessage   `json:"capabilities,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	LastHeartbeat time.Time         `json:"last_heartbeat,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	EnrolledBy    string            `json:"enrolled_by,omitempty"`
	// Inventory is the parsed, queryable subset of what a device advertised.
	// Zero for backends that were configured rather than enrolled: a container
	// driver has no build version of its own, it runs this one.
	Inventory ExecutorInventory `json:"inventory,omitzero"`
}

// ExecutorInventory is what an edge device reported about itself, parsed out of
// its capability advertisement into typed, individually-queryable fields.
//
// It is a nested struct rather than eight more fields on ExecutorRow because
// these travel together: they are refreshed as a set on every connect, they are
// all empty for a non-enrolled backend, and grouping them keeps "is this row's
// device inventory known" a single question.
//
// Capabilities on ExecutorRow still holds the full advertisement. This is not a
// replacement for it but a projection of the parts that have to be selectable —
// see migration 0030 for why both exist.
type ExecutorInventory struct {
	// AgentVersion is the cloop build the device reported at its last connect.
	// Empty means it reported none; the literal "1" means the placeholder that
	// pre-inventory agents sent. Both are "unknown", but only the second tells
	// an operator the device is definitely old.
	AgentVersion string `json:"agent_version,omitempty"`
	// OS and Arch are the device's GOOS/GOARCH.
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	// CPUs and MemoryMB are logical cores and total memory. Zero means the
	// agent could not detect it, which is never "too small".
	CPUs     int `json:"cpus,omitempty"`
	MemoryMB int `json:"memory_mb,omitempty"`
	// Harnesses are the agent CLIs on the device's PATH ("claude", "codex").
	Harnesses []string `json:"harnesses,omitempty"`
	// ContainerRuntimes are the container runtimes it can drive.
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
	// WorkDirRoot is the directory the agent confines every workload beneath.
	WorkDirRoot string `json:"workdir_root,omitempty"`
}

// Known reports whether anything was actually advertised. Used to decide
// between rendering an inventory and rendering nothing at all — a panel that
// showed "0 CPUs, no harnesses" for a device that never reported would be
// inventing a fault.
func (i ExecutorInventory) Known() bool {
	return i.AgentVersion != "" || i.OS != "" || i.Arch != "" ||
		i.CPUs > 0 || i.MemoryMB > 0 || i.WorkDirRoot != "" ||
		len(i.Harnesses) > 0 || len(i.ContainerRuntimes) > 0
}

// ProjectExecutorBinding pins one project directory to one executor.
type ProjectExecutorBinding struct {
	ProjectPath string    `json:"project_path"`
	ExecutorID  string    `json:"executor_id"`
	BoundAt     time.Time `json:"bound_at"`
	BoundBy     string    `json:"bound_by,omitempty"`
}

// UpsertExecutor inserts or updates an executor row keyed by ID. CreatedAt is
// preserved on update: re-enrolling an agent must not rewrite its enrollment
// date.
func (d *DB) UpsertExecutor(row ExecutorRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: executor id is required")
	}
	if strings.TrimSpace(row.Kind) == "" {
		return errors.New("statedb: executor kind is required")
	}
	if row.Status == "" {
		row.Status = ExecutorStatusUnknown
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	caps := "{}"
	if len(row.Capabilities) > 0 {
		caps = string(row.Capabilities)
	}
	labels := "{}"
	if len(row.Labels) > 0 {
		encoded, err := json.Marshal(row.Labels)
		if err != nil {
			return fmt.Errorf("statedb: marshal executor labels: %w", err)
		}
		labels = string(encoded)
	}

	harnesses, err := marshalStringList(row.Inventory.Harnesses)
	if err != nil {
		return fmt.Errorf("statedb: marshal executor harnesses: %w", err)
	}
	runtimes, err := marshalStringList(row.Inventory.ContainerRuntimes)
	if err != nil {
		return fmt.Errorf("statedb: marshal executor container runtimes: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err = d.conn.Exec(
		`INSERT INTO executors(id, name, kind, endpoint, status, capabilities_json,
		                       labels_json, last_heartbeat, created_at, enrolled_by,
		                       agent_version, agent_os, agent_arch, agent_cpus,
		                       agent_memory_mb, agent_harnesses, agent_runtimes,
		                       agent_workdir_root)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   name               = excluded.name,
		   kind               = excluded.kind,
		   endpoint           = excluded.endpoint,
		   status             = excluded.status,
		   capabilities_json  = excluded.capabilities_json,
		   labels_json        = excluded.labels_json,
		   last_heartbeat     = excluded.last_heartbeat,
		   enrolled_by        = excluded.enrolled_by,
		   agent_version      = excluded.agent_version,
		   agent_os           = excluded.agent_os,
		   agent_arch         = excluded.agent_arch,
		   agent_cpus         = excluded.agent_cpus,
		   agent_memory_mb    = excluded.agent_memory_mb,
		   agent_harnesses    = excluded.agent_harnesses,
		   agent_runtimes     = excluded.agent_runtimes,
		   agent_workdir_root = excluded.agent_workdir_root`,
		row.ID, row.Name, row.Kind, row.Endpoint, row.Status, caps, labels,
		formatOptionalTime(row.LastHeartbeat),
		row.CreatedAt.UTC().Format(time.RFC3339Nano),
		row.EnrolledBy,
		row.Inventory.AgentVersion, row.Inventory.OS, row.Inventory.Arch,
		row.Inventory.CPUs, row.Inventory.MemoryMB, harnesses, runtimes,
		row.Inventory.WorkDirRoot,
	)
	if err != nil {
		return fmt.Errorf("statedb: upsert executor %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// executorColumns is the select list for a full executor row, shared by
// GetExecutor and ListExecutors so the two cannot drift out of step with
// scanExecutorRow's argument order — which is the failure mode that a new
// column on this table invites, and which SQLite reports only as a scan type
// error at runtime.
const executorColumns = `id, name, kind, endpoint, status, capabilities_json, labels_json,
	        last_heartbeat, created_at, enrolled_by, agent_version, agent_os,
	        agent_arch, agent_cpus, agent_memory_mb, agent_harnesses,
	        agent_runtimes, agent_workdir_root`

// marshalStringList encodes a list for storage, normalising nil and empty to
// "[]" so a reader never has to distinguish them.
func marshalStringList(v []string) (string, error) {
	if len(v) == 0 {
		return "[]", nil
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// unmarshalStringList decodes a stored list, treating a malformed blob as
// absent.
//
// Advisory inventory must not be able to fail a listing: a device whose
// harness list somehow got corrupted is still a device an operator needs to see
// in the panel, and returning an error here would take the whole fleet view
// down with it. The same reasoning the labels decode already uses.
func unmarshalStringList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// GetExecutor returns one executor by ID, or ErrExecutorNotFound.
func (d *DB) GetExecutor(id string) (ExecutorRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT `+executorColumns+`
		 FROM executors WHERE id = ?`, id)
	out, err := scanExecutorRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorRow{}, fmt.Errorf("%w: %q", ErrExecutorNotFound, id)
	}
	if err != nil {
		return ExecutorRow{}, fmt.Errorf("statedb: get executor %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// ListExecutors returns every persisted executor ordered by ID.
func (d *DB) ListExecutors() ([]ExecutorRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT ` + executorColumns + `
		 FROM executors ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executors: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ExecutorRow
	for rows.Next() {
		rec, err := scanExecutorRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan executor: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executors: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteExecutor removes an executor and every project binding that pointed
// at it. Both happen in one transaction so a project can never be left
// pinned to an executor that no longer exists — such a project would fail
// every Resolve until an operator noticed.
func (d *DB) DeleteExecutor(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: delete executor %q: begin: %w", id, classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck — no-op once Commit succeeds

	if _, err := tx.Exec(`DELETE FROM project_executors WHERE executor_id = ?`, id); err != nil {
		return fmt.Errorf("statedb: delete executor %q bindings: %w", id, classifyDriverErr(err))
	}
	if _, err := tx.Exec(`DELETE FROM executors WHERE id = ?`, id); err != nil {
		return fmt.Errorf("statedb: delete executor %q: %w", id, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: delete executor %q: commit: %w", id, classifyDriverErr(err))
	}
	return nil
}

// TouchExecutorHeartbeat records liveness for an enrolled executor and
// updates its status. Returns ErrExecutorNotFound when the ID is unknown, so
// a stale agent cannot resurrect a de-enrolled record by heartbeating.
func (d *DB) TouchExecutorHeartbeat(id, status string, at time.Time) error {
	if status == "" {
		status = ExecutorStatusOnline
	}
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE executors SET last_heartbeat = ?, status = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339Nano), status, id)
	if err != nil {
		return fmt.Errorf("statedb: heartbeat executor %q: %w", id, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: %q", ErrExecutorNotFound, id)
	}
	return nil
}

// BindProjectExecutor pins projectPath to executorID. The executor must
// already exist, so a typo cannot strand a project on a nonexistent backend.
func (d *DB) BindProjectExecutor(projectPath, executorID, boundBy string) error {
	if strings.TrimSpace(projectPath) == "" {
		return errors.New("statedb: project path is required")
	}
	if strings.TrimSpace(executorID) == "" {
		return errors.New("statedb: executor id is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	var exists int
	err := d.conn.QueryRow(`SELECT 1 FROM executors WHERE id = ?`, executorID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %q", ErrExecutorNotFound, executorID)
	}
	if err != nil {
		return fmt.Errorf("statedb: bind project executor: %w", classifyDriverErr(err))
	}

	_, err = d.conn.Exec(
		`INSERT INTO project_executors(project_path, executor_id, bound_at, bound_by)
		 VALUES(?,?,?,?)
		 ON CONFLICT(project_path) DO UPDATE SET
		   executor_id = excluded.executor_id,
		   bound_at    = excluded.bound_at,
		   bound_by    = excluded.bound_by`,
		projectPath, executorID, time.Now().UTC().Format(time.RFC3339Nano), boundBy)
	if err != nil {
		return fmt.Errorf("statedb: bind project %q to executor %q: %w",
			projectPath, executorID, classifyDriverErr(err))
	}
	return nil
}

// UnbindProjectExecutor removes the binding for projectPath. Unbinding a
// project that was never bound is not an error.
func (d *DB) UnbindProjectExecutor(projectPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM project_executors WHERE project_path = ?`, projectPath); err != nil {
		return fmt.Errorf("statedb: unbind project %q: %w", projectPath, classifyDriverErr(err))
	}
	return nil
}

// ProjectExecutor returns the executor ID bound to projectPath. The boolean
// is false when the project has no binding, which callers treat as "use the
// registry default" — distinct from an error, which means the lookup itself
// failed and must not be interpreted as "unbound".
func (d *DB) ProjectExecutor(projectPath string) (string, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var id string
	err := d.conn.QueryRow(
		`SELECT executor_id FROM project_executors WHERE project_path = ?`, projectPath).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("statedb: project executor for %q: %w", projectPath, classifyDriverErr(err))
	}
	return id, true, nil
}

// ListProjectExecutorBindings returns every project→executor binding,
// ordered by project path.
func (d *DB) ListProjectExecutorBindings() ([]ProjectExecutorBinding, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT project_path, executor_id, bound_at, bound_by
		 FROM project_executors ORDER BY project_path ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list project executor bindings: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ProjectExecutorBinding
	for rows.Next() {
		var (
			b          ProjectExecutorBinding
			boundAtStr string
		)
		if err := rows.Scan(&b.ProjectPath, &b.ExecutorID, &boundAtStr, &b.BoundBy); err != nil {
			return nil, fmt.Errorf("statedb: scan project executor binding: %w", err)
		}
		b.BoundAt = parseOptionalTime(boundAtStr)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list project executor bindings: %w", classifyDriverErr(err))
	}
	return out, nil
}

// rowScanner unifies *sql.Row and *sql.Rows for scanExecutorRow.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanExecutorRow(sc rowScanner) (ExecutorRow, error) {
	var (
		row       ExecutorRow
		caps      string
		labels    string
		heartbeat string
		created   string
		harnesses string
		runtimes  string
	)
	// Argument order must match executorColumns exactly.
	if err := sc.Scan(&row.ID, &row.Name, &row.Kind, &row.Endpoint, &row.Status,
		&caps, &labels, &heartbeat, &created, &row.EnrolledBy,
		&row.Inventory.AgentVersion, &row.Inventory.OS, &row.Inventory.Arch,
		&row.Inventory.CPUs, &row.Inventory.MemoryMB, &harnesses, &runtimes,
		&row.Inventory.WorkDirRoot); err != nil {
		return ExecutorRow{}, err
	}
	row.Inventory.Harnesses = unmarshalStringList(harnesses)
	row.Inventory.ContainerRuntimes = unmarshalStringList(runtimes)
	if caps != "" && caps != "{}" {
		row.Capabilities = json.RawMessage(caps)
	}
	if labels != "" && labels != "{}" {
		// A malformed blob must not fail the whole listing: labels are
		// advisory metadata, so we drop them and keep the executor usable.
		decoded := map[string]string{}
		if err := json.Unmarshal([]byte(labels), &decoded); err == nil {
			row.Labels = decoded
		}
	}
	row.LastHeartbeat = parseOptionalTime(heartbeat)
	row.CreatedAt = parseOptionalTime(created)
	return row, nil
}

// formatOptionalTime renders t as RFC3339Nano, or "" when zero, so an
// absent heartbeat is stored as an empty string rather than year 1.
func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// parseOptionalTime parses an RFC3339Nano timestamp, returning the zero time
// for empty or unparseable input.
func parseOptionalTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}
