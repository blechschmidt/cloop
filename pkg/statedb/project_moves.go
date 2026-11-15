package statedb

// Rows for migrations/0102_project_moves.sql: the journal of project moves
// (Task 20494). See that file for the columns, and pkg/projectmove for the
// state machine the rows record.
//
// Every write is a compare-and-swap on (id, phase, version). That is what
// makes the journal safe to drive from more than one place: a hub that was
// paused past its lease and comes back to write a phase its successor has
// already moved past matches no row, learns it lost, and stops — the same
// discipline hub_instances uses for renewal. The rows are only ever inserted
// and updated in place; nothing here deletes or replaces one.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrProjectMoveNotFound is returned for a move id with no row.
var ErrProjectMoveNotFound = errors.New("statedb: no such project move")

// ErrProjectMoveOpen refuses a second open move of one project.
var ErrProjectMoveOpen = errors.New("statedb: the project already has a move in progress")

// ErrProjectMoveChanged is the compare-and-swap's refusal: the row is no longer
// at the phase and version the writer read. Whoever wrote it in between owns
// what happens next.
var ErrProjectMoveChanged = errors.New("statedb: the project move changed under the write")

// Closed project-move phases, mirrored from pkg/projectmove (which imports
// this package, not the other way round). The migration's partial index names
// the same three.
var closedMovePhases = []string{"done", "failed", "rolled_back"}

// ProjectMoveRow is one row of project_moves.
type ProjectMoveRow struct {
	ID            string
	ProjectPath   string
	ProjectName   string
	SourceBinding string
	TargetBinding string
	Phase         string
	FailedPhase   string
	Error         string
	AbandonSource bool
	StartedBy     string
	Version       int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	FinishedAt    time.Time
	// DetailJSON is the move's detail document, a JSON object.
	DetailJSON string
}

// Open reports whether the move has not reached a closed phase.
func (r ProjectMoveRow) Open() bool {
	for _, p := range closedMovePhases {
		if r.Phase == p {
			return false
		}
	}
	return true
}

const projectMoveColumns = `id, project_path, project_name, source_binding, target_binding, phase,
	failed_phase, error, abandon_source, started_by, version, created_at, updated_at, finished_at, detail_json`

func scanProjectMove(sc rowScanner) (ProjectMoveRow, error) {
	var (
		r                            ProjectMoveRow
		abandon                      int
		created, updated, finishedAt string
	)
	if err := sc.Scan(&r.ID, &r.ProjectPath, &r.ProjectName, &r.SourceBinding, &r.TargetBinding, &r.Phase,
		&r.FailedPhase, &r.Error, &abandon, &r.StartedBy, &r.Version, &created, &updated, &finishedAt, &r.DetailJSON); err != nil {
		return ProjectMoveRow{}, err
	}
	r.AbandonSource = abandon != 0
	r.CreatedAt = parseOptionalTime(created)
	r.UpdatedAt = parseOptionalTime(updated)
	r.FinishedAt = parseOptionalTime(finishedAt)
	return r, nil
}

// closedPhaseSQL renders the closed phases for an IN list.
func closedPhaseSQL() string {
	q := make([]string, len(closedMovePhases))
	for i, p := range closedMovePhases {
		q[i] = "'" + p + "'"
	}
	return strings.Join(q, ", ")
}

// CreateProjectMove records a new move. It refuses with ErrProjectMoveOpen,
// returning the open move, when the project already has one: the check and the
// insert are one transaction, and the migration's partial unique index is the
// backstop if two hub processes race past both.
func (d *DB) CreateProjectMove(row ProjectMoveRow) (ProjectMoveRow, error) {
	row.ID = strings.TrimSpace(row.ID)
	row.ProjectPath = strings.TrimSpace(row.ProjectPath)
	switch {
	case row.ID == "":
		return ProjectMoveRow{}, errors.New("statedb: a project move needs an id")
	case row.ProjectPath == "":
		return ProjectMoveRow{}, errors.New("statedb: a project move needs the project's path")
	case strings.TrimSpace(row.Phase) == "":
		return ProjectMoveRow{}, errors.New("statedb: a project move needs a phase")
	case !row.Open():
		return ProjectMoveRow{}, fmt.Errorf("statedb: a project move cannot start %s", row.Phase)
	}
	if strings.TrimSpace(row.DetailJSON) == "" {
		row.DetailJSON = "{}"
	}
	now := time.Now().UTC()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	row.UpdatedAt = row.CreatedAt
	row.Version = 1
	row.FinishedAt = time.Time{}

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return ProjectMoveRow{}, fmt.Errorf("statedb: record a project move: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds
	if open, ok, err := openProjectMoveOn(tx, row.ProjectPath); err != nil {
		return ProjectMoveRow{}, err
	} else if ok {
		return open, fmt.Errorf("%w (move %s, at %s)", ErrProjectMoveOpen, open.ID, open.Phase)
	}
	abandon := 0
	if row.AbandonSource {
		abandon = 1
	}
	_, err = tx.Exec(`INSERT INTO project_moves(`+projectMoveColumns+`)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.ProjectPath, row.ProjectName, row.SourceBinding, row.TargetBinding, row.Phase,
		row.FailedPhase, row.Error, abandon, row.StartedBy, row.Version,
		formatOptionalTime(row.CreatedAt), formatOptionalTime(row.UpdatedAt), "", row.DetailJSON)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ProjectMoveRow{}, fmt.Errorf("%w: %v", ErrProjectMoveOpen, err)
		}
		return ProjectMoveRow{}, fmt.Errorf("statedb: record a project move: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return ProjectMoveRow{}, fmt.Errorf("statedb: record a project move: commit: %w", classifyDriverErr(err))
	}
	return row, nil
}

// GetProjectMove reads one move.
func (d *DB) GetProjectMove(id string) (ProjectMoveRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row, err := scanProjectMove(d.conn.QueryRow(`SELECT `+projectMoveColumns+` FROM project_moves WHERE id = ?`,
		strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectMoveRow{}, fmt.Errorf("%w: %q", ErrProjectMoveNotFound, id)
	}
	if err != nil {
		return ProjectMoveRow{}, fmt.Errorf("statedb: read project move %q: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// OpenProjectMove returns the project's open move, if it has one. Every
// dispatch of the project asks: a run must not start while one is open.
func (d *DB) OpenProjectMove(projectPath string) (ProjectMoveRow, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return openProjectMoveOn(d.conn, strings.TrimSpace(projectPath))
}

func openProjectMoveOn(q queryRower, projectPath string) (ProjectMoveRow, bool, error) {
	row, err := scanProjectMove(q.QueryRow(`SELECT `+projectMoveColumns+` FROM project_moves
		WHERE project_path = ? AND phase NOT IN (`+closedPhaseSQL()+`)
		ORDER BY created_at DESC LIMIT 1`, projectPath))
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectMoveRow{}, false, nil
	}
	if err != nil {
		return ProjectMoveRow{}, false, fmt.Errorf("statedb: read the open move of %q: %w", projectPath, classifyDriverErr(err))
	}
	return row, true, nil
}

// ProjectMoveFilter narrows ListProjectMoves.
type ProjectMoveFilter struct {
	// ProjectPath keeps one project's moves.
	ProjectPath string
	// OpenOnly keeps the moves that have not reached a closed phase.
	OpenOnly bool
	// Limit bounds the rows returned, newest first; zero means 100.
	Limit int
}

// ListProjectMoves lists moves, newest first.
func (d *DB) ListProjectMoves(f ProjectMoveFilter) ([]ProjectMoveRow, error) {
	var (
		where []string
		args  []any
	)
	if p := strings.TrimSpace(f.ProjectPath); p != "" {
		where = append(where, "project_path = ?")
		args = append(args, p)
	}
	if f.OpenOnly {
		where = append(where, "phase NOT IN ("+closedPhaseSQL()+")")
	}
	q := `SELECT ` + projectMoveColumns + ` FROM project_moves`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT %d", limit)

	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list project moves: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ProjectMoveRow
	for rows.Next() {
		r, err := scanProjectMove(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: list project moves: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list project moves: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ProjectMoveUpdate is one compare-and-swap on a move: from the phase and
// version the writer read, to the phase it decided on.
type ProjectMoveUpdate struct {
	ID string
	// FromPhase and FromVersion are what the writer read; the update matches
	// no row unless the move is still there.
	FromPhase   string
	FromVersion int64
	// Phase is the phase the move goes to; FailedPhase and Error say why when
	// it is failed or rolled_back.
	Phase       string
	FailedPhase string
	Error       string
	// DetailJSON replaces the detail document when non-empty.
	DetailJSON string
	// At is the write's time; zero means now.
	At time.Time
}

// AdvanceProjectMove applies one compare-and-swap, returning the row as it now
// is, or ErrProjectMoveChanged when the move is no longer where the writer
// read it.
func (d *DB) AdvanceProjectMove(u ProjectMoveUpdate) (ProjectMoveRow, error) {
	return d.transitionProjectMove(u, nil, nil)
}

// ProjectBinding is the binding a switch writes, in the same transaction as
// the move's phase.
type ProjectBinding struct {
	ProjectPath string
	// Binding is an executor ID, pool:<id>, or "" for no binding (the hub's
	// default executor).
	Binding string
	BoundBy string
}

// SwitchProjectMove applies a compare-and-swap on a move together with the
// project's binding and whatever fn writes through the firewall transaction —
// the path-keyed rows a binding change touches — as one transaction: either
// the move advances and the project is bound where it says, or neither. The
// move engine switches with it, and rolls a failed move back with it.
func (d *DB) SwitchProjectMove(u ProjectMoveUpdate, b ProjectBinding, fn func(*FirewallTx) error) (ProjectMoveRow, error) {
	if strings.TrimSpace(b.ProjectPath) == "" {
		return ProjectMoveRow{}, errors.New("statedb: a switch needs the project's path")
	}
	return d.transitionProjectMove(u, &b, fn)
}

func (d *DB) transitionProjectMove(u ProjectMoveUpdate, b *ProjectBinding, fn func(*FirewallTx) error) (ProjectMoveRow, error) {
	u.ID = strings.TrimSpace(u.ID)
	if u.ID == "" || strings.TrimSpace(u.FromPhase) == "" || strings.TrimSpace(u.Phase) == "" || u.FromVersion <= 0 {
		return ProjectMoveRow{}, errors.New("statedb: a project move update needs the id, the phase and version it was read at, and the phase it goes to")
	}
	at := u.At
	if at.IsZero() {
		at = time.Now()
	}
	finished := ""
	if !(ProjectMoveRow{Phase: u.Phase}).Open() {
		finished = formatOptionalTime(at)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return ProjectMoveRow{}, fmt.Errorf("statedb: update project move %s: %w", u.ID, classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	// finished_at records the first closed write: a later one — the cleanup
	// recording what it removed — keeps when the move ended.
	set := `phase = ?, failed_phase = ?, error = ?, version = version + 1, updated_at = ?,
		finished_at = CASE WHEN finished_at = '' THEN ? ELSE finished_at END`
	args := []any{u.Phase, u.FailedPhase, u.Error, formatOptionalTime(at), finished}
	if strings.TrimSpace(u.DetailJSON) != "" {
		set += `, detail_json = ?`
		args = append(args, u.DetailJSON)
	}
	args = append(args, u.ID, u.FromPhase, u.FromVersion)
	res, err := tx.Exec(`UPDATE project_moves SET `+set+` WHERE id = ? AND phase = ? AND version = ?`, args...)
	if err != nil {
		return ProjectMoveRow{}, fmt.Errorf("statedb: update project move %s: %w", u.ID, classifyDriverErr(err))
	}
	changed, err := rowsChanged(res)
	if err != nil {
		return ProjectMoveRow{}, err
	}
	if !changed {
		return ProjectMoveRow{}, fmt.Errorf("%w: move %s is no longer at %s (version %d)", ErrProjectMoveChanged, u.ID, u.FromPhase, u.FromVersion)
	}

	if b != nil {
		if err := bindProjectOn(tx, *b, at); err != nil {
			return ProjectMoveRow{}, err
		}
		if fn != nil {
			if err := fn(&FirewallTx{tx: tx}); err != nil {
				return ProjectMoveRow{}, err
			}
		}
	}

	row, err := scanProjectMove(tx.QueryRow(`SELECT `+projectMoveColumns+` FROM project_moves WHERE id = ?`, u.ID))
	if err != nil {
		return ProjectMoveRow{}, fmt.Errorf("statedb: read back project move %s: %w", u.ID, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return ProjectMoveRow{}, fmt.Errorf("statedb: update project move %s: commit: %w", u.ID, classifyDriverErr(err))
	}
	return row, nil
}

// bindProjectOn writes a project's binding inside tx, with the checks
// BindProjectExecutor and BindProjectPool make: an executor binding names a
// recorded executor, a pool binding a pool that was not revoked. An empty
// binding removes the row: the project runs on the hub's default executor.
func bindProjectOn(tx *sql.Tx, b ProjectBinding, at time.Time) error {
	path := strings.TrimSpace(b.ProjectPath)
	binding := strings.TrimSpace(b.Binding)
	if binding == "" {
		if _, err := tx.Exec(`DELETE FROM project_executors WHERE project_path = ?`, path); err != nil {
			return fmt.Errorf("statedb: unbind project %q: %w", path, classifyDriverErr(err))
		}
		return nil
	}
	if poolID, ok := strings.CutPrefix(binding, "pool:"); ok {
		pool, err := getExecutorPool(tx, strings.TrimSpace(poolID))
		if err != nil {
			return err
		}
		if pool.Revoked() {
			return fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, poolID)
		}
		binding = poolBindingValue(poolID)
	} else {
		var exists int
		err := tx.QueryRow(`SELECT 1 FROM executors WHERE id = ?`, binding).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %q", ErrExecutorNotFound, binding)
		}
		if err != nil {
			return fmt.Errorf("statedb: bind project executor: %w", classifyDriverErr(err))
		}
	}
	if _, err := tx.Exec(`INSERT INTO project_executors(project_path, executor_id, bound_at, bound_by)
		VALUES(?,?,?,?)
		ON CONFLICT(project_path) DO UPDATE SET
		  executor_id = excluded.executor_id, bound_at = excluded.bound_at, bound_by = excluded.bound_by`,
		path, binding, formatOptionalTime(at), b.BoundBy); err != nil {
		return fmt.Errorf("statedb: bind project %q to %q: %w", path, binding, classifyDriverErr(err))
	}
	return nil
}
