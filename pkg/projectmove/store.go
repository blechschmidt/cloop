package projectmove

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// DBStore journals moves in the control plane's project_moves table
// (migration 0102).
type DBStore struct {
	// Open opens the control plane's database. The store closes each handle
	// it opens before returning.
	Open func() (*statedb.DB, error)
}

var _ Store = DBStore{}

func (s DBStore) db() (*statedb.DB, error) {
	if s.Open == nil {
		return nil, errors.New("projectmove: no control-plane database")
	}
	return s.Open()
}

// Create implements Store.
func (s DBStore) Create(_ context.Context, m Move) (Move, error) {
	row, err := rowFromMove(m)
	if err != nil {
		return Move{}, err
	}
	db, err := s.db()
	if err != nil {
		return Move{}, err
	}
	defer db.Close()
	out, err := db.CreateProjectMove(row)
	if err != nil {
		if errors.Is(err, statedb.ErrProjectMoveOpen) {
			open, _ := MoveFromRow(out)
			return open, fmt.Errorf("%w: %v", ErrMoveOpen, err)
		}
		return Move{}, err
	}
	return MoveFromRow(out)
}

// Get implements Store.
func (s DBStore) Get(_ context.Context, id string) (Move, error) {
	db, err := s.db()
	if err != nil {
		return Move{}, err
	}
	defer db.Close()
	row, err := db.GetProjectMove(id)
	if errors.Is(err, statedb.ErrProjectMoveNotFound) {
		return Move{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Move{}, err
	}
	return MoveFromRow(row)
}

// Advance implements Store.
func (s DBStore) Advance(_ context.Context, m Move, to Phase) (Move, error) {
	u, err := updateFor(m, to)
	if err != nil {
		return Move{}, err
	}
	db, err := s.db()
	if err != nil {
		return Move{}, err
	}
	defer db.Close()
	row, err := db.AdvanceProjectMove(u)
	if err != nil {
		return Move{}, mapChanged(err)
	}
	return MoveFromRow(row)
}

// SwitchOn writes m at phase to together with the project's binding and
// whatever fn writes through the firewall transaction, as one transaction on
// db: how a hub's Driver implements Switch and RollBack.
func SwitchOn(db *statedb.DB, m Move, to Phase, binding, boundBy string, fn func(*statedb.FirewallTx) error) (Move, error) {
	u, err := updateFor(m, to)
	if err != nil {
		return Move{}, err
	}
	row, err := db.SwitchProjectMove(u, statedb.ProjectBinding{ProjectPath: m.Project.Path, Binding: binding, BoundBy: boundBy}, fn)
	if err != nil {
		return Move{}, mapChanged(err)
	}
	return MoveFromRow(row)
}

// OpenMove returns the project's open move, if it has one.
func OpenMove(db *statedb.DB, projectPath string) (Move, bool, error) {
	row, ok, err := db.OpenProjectMove(projectPath)
	if err != nil || !ok {
		return Move{}, ok, err
	}
	m, err := MoveFromRow(row)
	return m, err == nil, err
}

// ListMoves lists moves, newest first.
func ListMoves(db *statedb.DB, f statedb.ProjectMoveFilter) ([]Move, error) {
	rows, err := db.ListProjectMoves(f)
	if err != nil {
		return nil, err
	}
	out := make([]Move, 0, len(rows))
	for _, r := range rows {
		m, err := MoveFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func mapChanged(err error) error {
	if errors.Is(err, statedb.ErrProjectMoveChanged) {
		return fmt.Errorf("%w: %v", ErrChanged, err)
	}
	return err
}

func updateFor(m Move, to Phase) (statedb.ProjectMoveUpdate, error) {
	detail, err := json.Marshal(m.Detail)
	if err != nil {
		return statedb.ProjectMoveUpdate{}, fmt.Errorf("projectmove: encode move %s: %w", m.ID, err)
	}
	u := statedb.ProjectMoveUpdate{
		ID: m.ID, FromPhase: string(m.Phase), FromVersion: m.Version,
		Phase: string(to), DetailJSON: string(detail),
	}
	if !to.Open() && to != PhaseDone {
		u.FailedPhase, u.Error = string(m.FailedPhase), m.Error
	}
	return u, nil
}

// MoveFromRow decodes a journalled move.
func MoveFromRow(r statedb.ProjectMoveRow) (Move, error) {
	m := Move{
		ID: r.ID, Project: Project{Name: r.ProjectName, Path: r.ProjectPath},
		Source: r.SourceBinding, Target: r.TargetBinding,
		Phase: Phase(r.Phase), FailedPhase: Phase(r.FailedPhase), Error: r.Error,
		AbandonSource: r.AbandonSource, StartedBy: r.StartedBy, Version: r.Version,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, FinishedAt: r.FinishedAt,
	}
	if r.DetailJSON != "" {
		if err := json.Unmarshal([]byte(r.DetailJSON), &m.Detail); err != nil {
			return m, fmt.Errorf("projectmove: move %s's detail does not decode: %w", r.ID, err)
		}
	}
	return m, nil
}

func rowFromMove(m Move) (statedb.ProjectMoveRow, error) {
	detail, err := json.Marshal(m.Detail)
	if err != nil {
		return statedb.ProjectMoveRow{}, fmt.Errorf("projectmove: encode move %s: %w", m.ID, err)
	}
	return statedb.ProjectMoveRow{
		ID: m.ID, ProjectPath: m.Project.Path, ProjectName: m.Project.Name,
		SourceBinding: m.Source, TargetBinding: m.Target, Phase: string(m.Phase),
		FailedPhase: string(m.FailedPhase), Error: m.Error, AbandonSource: m.AbandonSource,
		StartedBy: m.StartedBy, CreatedAt: m.CreatedAt, DetailJSON: string(detail),
	}, nil
}
