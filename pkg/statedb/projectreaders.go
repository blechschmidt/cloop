package statedb

// Per-project readers lists (Task 20498). See
// migrations/0103_project_readers.sql for the table.
//
// Mechanical accessors only. What a row means — that a project may read
// another only when the other lists it, that a project never lists itself and
// a feature is never listed — and how paths are normalised belong to
// pkg/projectreaders; who may change a list belongs to pkg/ui. This layer keeps
// each change in the same commit as the audit row recording it: a readers list
// is an authorization record, and one that changed with nothing on the trail is
// an access change nobody can review.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProjectReaderRow is one row of project_readers: ReaderPath may read
// ProjectPath.
type ProjectReaderRow struct {
	ID          string
	ProjectPath string
	ReaderPath  string
	AddedBy     string
	AddedAt     time.Time
}

// ReaderAudit builds the audit events committed together with a readers-list
// change. prev is the row before the change and next the row after it; either
// is nil when there was none, so an addition has prev == nil and a removal
// next == nil. Returning an error aborts the change: an access change with no
// record is treated as one that did not happen.
type ReaderAudit func(prev, next *ProjectReaderRow) ([]*AuditEvent, error)

const projectReaderColumns = `id, project_path, reader_path, added_by, added_at`

// newProjectReaderID returns a fresh row id. Random rather than derived from
// the pair, so an id handed to someone who cannot see the reader says nothing
// about which project it is.
func newProjectReaderID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("statedb: project reader id: %w", err)
	}
	return "prd_" + hex.EncodeToString(b[:]), nil
}

// checkReaderPair refuses a pair no list may hold. pkg/projectreaders is where
// a pair is judged; this is the floor under it, so a caller that skipped that
// cannot store a row that names nothing or lets a project list itself.
func checkReaderPair(projectPath, readerPath string) error {
	switch {
	case projectPath == "" || readerPath == "":
		return errors.New("statedb: a project reader needs a project path and a reader path")
	case projectPath == readerPath:
		return fmt.Errorf("statedb: project %s cannot list itself as a reader", projectPath)
	}
	return nil
}

// AddProjectReader records that row.ReaderPath may read row.ProjectPath and
// returns the row as stored. added is false when the pair was listed already;
// then nothing is written, audit is not called, and the row returned is the
// one that was there.
//
// The caller passes normalised paths; pkg/projectreaders is the one definition
// of when two paths are the same project.
func (d *DB) AddProjectReader(row ProjectReaderRow, audit ReaderAudit) (ProjectReaderRow, bool, error) {
	row.ProjectPath = strings.TrimSpace(row.ProjectPath)
	row.ReaderPath = strings.TrimSpace(row.ReaderPath)
	row.AddedBy = strings.TrimSpace(row.AddedBy)
	if err := checkReaderPair(row.ProjectPath, row.ReaderPath); err != nil {
		return ProjectReaderRow{}, false, err
	}
	if row.AddedAt.IsZero() {
		row.AddedAt = time.Now()
	}
	row.AddedAt = row.AddedAt.UTC()

	added := false
	err := d.readerTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		existing, found, err := getProjectReaderTx(tx, row.ProjectPath, row.ReaderPath)
		if err != nil {
			return nil, err
		}
		if found {
			row = existing
			return nil, nil
		}
		id, err := newProjectReaderID()
		if err != nil {
			return nil, err
		}
		row.ID = id
		if _, err := tx.Exec(
			`INSERT INTO project_readers (`+projectReaderColumns+`) VALUES (?, ?, ?, ?, ?)`,
			row.ID, row.ProjectPath, row.ReaderPath, row.AddedBy, formatOptionalTime(row.AddedAt),
		); err != nil {
			return nil, fmt.Errorf("statedb: insert project reader %s: %w", row.ID, classifyDriverErr(err))
		}
		added = true
		if audit == nil {
			return nil, nil
		}
		stored := row
		return audit(nil, &stored)
	})
	if err != nil {
		return ProjectReaderRow{}, false, err
	}
	return row, added, nil
}

// RemoveProjectReader removes the row saying readerPath may read projectPath
// and returns it, or nil when there was none — in which case nothing is
// written and audit is not called.
func (d *DB) RemoveProjectReader(projectPath, readerPath string, audit ReaderAudit) (*ProjectReaderRow, error) {
	path, reader := strings.TrimSpace(projectPath), strings.TrimSpace(readerPath)
	if path == "" || reader == "" {
		return nil, errors.New("statedb: a project path and a reader path are required")
	}
	return d.removeProjectReader(audit, `WHERE project_path = ? AND reader_path = ?`, path, reader)
}

// RemoveProjectReaderByID removes the row with id on projectPath's list and
// returns it, or nil when that list has no such row. An id from another
// project's list is not found here: the id alone never names what a caller
// may remove.
func (d *DB) RemoveProjectReaderByID(projectPath, id string, audit ReaderAudit) (*ProjectReaderRow, error) {
	path, id := strings.TrimSpace(projectPath), strings.TrimSpace(id)
	if path == "" || id == "" {
		return nil, errors.New("statedb: a project path and a reader id are required")
	}
	return d.removeProjectReader(audit, `WHERE project_path = ? AND id = ?`, path, id)
}

func (d *DB) removeProjectReader(audit ReaderAudit, where string, args ...any) (*ProjectReaderRow, error) {
	var removed *ProjectReaderRow
	err := d.readerTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		rows, err := queryProjectReaders(tx, where, args...)
		if err != nil || len(rows) == 0 {
			return nil, err
		}
		existing := rows[0]
		if _, err := tx.Exec(`DELETE FROM project_readers WHERE id = ?`, existing.ID); err != nil {
			return nil, fmt.Errorf("statedb: delete project reader %s: %w", existing.ID, classifyDriverErr(err))
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

// DeleteProjectReadersOf removes every row naming path on either side — the
// projects that could read it, and the projects it could read — and returns
// the rows removed. Called when the project leaves the hub: rows are keyed by
// path, and one outliving its project would hand its access to whatever is
// registered at that path next. audit is called once per removed row.
func (d *DB) DeleteProjectReadersOf(path string, audit ReaderAudit) ([]ProjectReaderRow, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("statedb: a project path is required")
	}
	var removed []ProjectReaderRow
	err := d.readerTx(func(tx *sql.Tx) ([]*AuditEvent, error) {
		rows, err := queryProjectReaders(tx, `WHERE project_path = ? OR reader_path = ? ORDER BY project_path, reader_path`, path, path)
		if err != nil || len(rows) == 0 {
			return nil, err
		}
		if _, err := tx.Exec(`DELETE FROM project_readers WHERE project_path = ? OR reader_path = ?`, path, path); err != nil {
			return nil, fmt.Errorf("statedb: delete the readers of %s: %w", path, classifyDriverErr(err))
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

// ListProjectReaders returns every row of every readers list, ordered by
// project then reader. The whole table, because answering "what may this
// project read" needs the other side of every list; rows number at most one
// per pair of projects, so it stays small.
func (d *DB) ListProjectReaders() ([]ProjectReaderRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryProjectReaders(d.conn, `ORDER BY project_path, reader_path`)
}

// readerTx runs fn in one write transaction and commits the audit events it
// returns in the same commit.
func (d *DB) readerTx(fn func(tx *sql.Tx) ([]*AuditEvent, error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: project readers: begin: %w", classifyDriverErr(err))
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
		return fmt.Errorf("statedb: project readers: commit: %w", classifyDriverErr(err))
	}
	return nil
}

func queryProjectReaders(q memberQuerier, where string, args ...any) ([]ProjectReaderRow, error) {
	rows, err := q.Query(`SELECT `+projectReaderColumns+` FROM project_readers `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list project readers: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ProjectReaderRow
	for rows.Next() {
		var r ProjectReaderRow
		var added string
		if err := rows.Scan(&r.ID, &r.ProjectPath, &r.ReaderPath, &r.AddedBy, &added); err != nil {
			return nil, fmt.Errorf("statedb: scan project reader: %w", classifyDriverErr(err))
		}
		r.AddedAt = parseOptionalTime(added)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list project readers: %w", classifyDriverErr(err))
	}
	return out, nil
}

func getProjectReaderTx(tx *sql.Tx, path, reader string) (ProjectReaderRow, bool, error) {
	rows, err := queryProjectReaders(tx, `WHERE project_path = ? AND reader_path = ?`, path, reader)
	if err != nil || len(rows) == 0 {
		return ProjectReaderRow{}, false, err
	}
	return rows[0], true, nil
}
