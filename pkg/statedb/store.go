// Package statedb — Store interface for the relational data layer.
// The DB struct (SQLite) implements Store. A future PostgreSQL driver need
// only implement this interface to be used as a drop-in replacement.
package statedb

import (
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

	// ── Lifecycle ─────────────────────────────────────────────────────────

	// Close releases the underlying connection.
	Close() error
}
