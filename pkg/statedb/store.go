// Package statedb — Store interface for the relational data layer.
// The DB struct (SQLite) implements Store. A future PostgreSQL driver need
// only implement this interface to be used as a drop-in replacement.
package statedb

import (
	"context"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Store is the abstract data-access interface for cloop project state.
// All methods must be safe for concurrent use.
//
// SQLite implementation: DB (this package).
// PostgreSQL: implement this interface with a pgx/pgxpool-backed struct.
type Store interface {
	// ── State ──────────────────────────────────────────────────────────────

	// SaveState atomically persists the full project state (metadata, tasks,
	// steps). Existing tasks are replaced; steps are upserted (never deleted).
	SaveState(s *State) error

	// LoadState reads back the complete project state. Returns a zero-value
	// State (not an error) when the database exists but has no rows yet.
	LoadState() (*State, error)

	// ── Incremental task updates ───────────────────────────────────────────

	// UpsertTask inserts or replaces a single task row. Useful for
	// status-only updates without a full SaveState round-trip.
	UpsertTask(t *pm.Task) error

	// LoadTask returns a single task by id. Returns ErrTaskNotFound when
	// the row does not exist; callers should test with errors.Is.
	LoadTask(id int) (*pm.Task, error)

	// ── Steps ─────────────────────────────────────────────────────────────

	// AppendStep inserts a step row. Idempotent on step number (upsert).
	AppendStep(row StepRow) error

	// ── Cost ledger ────────────────────────────────────────────────────────

	// AppendCost appends a single cost entry for the current project.
	AppendCost(entry CostEntry) error

	// ReadCosts returns all cost entries in chronological order.
	ReadCosts() ([]CostEntry, error)

	// ReadCostsSince returns cost entries with timestamp >= since.
	ReadCostsSince(since time.Time) ([]CostEntry, error)

	// MonthlyCosts returns cost entries for the given UTC year/month.
	MonthlyCosts(year, month int) ([]CostEntry, error)

	// ── Stuck-task forensics (Task 20088) ──────────────────────────────────

	// AppendStuck records one watchdog stuck-task detection. Returns the
	// inserted row's auto-increment id.
	AppendStuck(e StuckEvent) (int64, error)

	// ReadStuck returns the most recent N stuck events, newest first. Pass
	// 0 for unbounded.
	ReadStuck(limit int) ([]StuckEvent, error)

	// ReadStuckSince returns stuck events with detected_at >= since.
	ReadStuckSince(since time.Time) ([]StuckEvent, error)

	// ── Lifecycle ─────────────────────────────────────────────────────────

	// PingContext verifies the underlying store is reachable by issuing a
	// trivial query. Used by readiness probes; ctx bounds wait time on a
	// busy connection.
	PingContext(ctx context.Context) error

	// Close releases the underlying connection.
	Close() error
}
