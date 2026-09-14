package statedb

// The hub's booking position in each project's cost ledger (Task 20264).
//
// Spend is written by the orchestrator, into the project's own database, one
// row per finished task. It is *charged* by the hub, against an in-memory
// quota enforcer that lives in a different process. This table is what joins
// the two across a restart: which identity to bill, and how far the billing has
// got. See migration 0036 for why the identity is held here rather than read
// back from the cost row it is charging.

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SpendCursor is the hub's booking position for one project.
type SpendCursor struct {
	ProjectPath string
	// Identity is who the hub resolved when it dispatched the current run.
	// The only identity this project's spend is ever charged to.
	Identity string
	// LastCostRowID is the highest costs.id already charged.
	LastCostRowID int64
	UpdatedAt     time.Time
}

// OpenSpendCursor records who is paying for the run about to start and where
// its billing begins, replacing any previous cursor for the project.
//
// startAt is the project ledger's current MAX(id) — everything already there
// belongs to an earlier run and must not be charged to this one. Passing it in
// rather than reading it here keeps this package free of any assumption about
// which database the cost rows live in: the control plane holds the cursor, the
// project holds the ledger, and they are different files.
func (d *DB) OpenSpendCursor(projectPath, identity string, startAt int64) error {
	if projectPath == "" {
		return fmt.Errorf("statedb: spend cursor needs a project path")
	}
	if startAt < 0 {
		startAt = 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		INSERT INTO project_spend_cursor(project_path, identity, last_cost_row_id, updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(project_path) DO UPDATE SET
			identity=excluded.identity,
			last_cost_row_id=excluded.last_cost_row_id,
			updated_at=excluded.updated_at`,
		projectPath, identity, startAt, time.Now().UTC().Format(time.RFC3339Nano),
	)
	return classifyDriverErr(err)
}

// LoadSpendCursor returns the cursor for projectPath, or ok=false when the hub
// has never dispatched a run for it.
//
// ok=false is not an error: it is the normal state of a project the hub only
// reads, and of every project on a hub that has just been upgraded. The caller
// charges nothing until a dispatch opens a cursor, which is the safe direction
// — the alternative would be charging an identity the hub had to guess.
func (d *DB) LoadSpendCursor(projectPath string) (SpendCursor, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var (
		c  SpendCursor
		ts string
	)
	err := d.conn.QueryRow(`
		SELECT project_path, identity, last_cost_row_id, updated_at
		FROM project_spend_cursor WHERE project_path = ?`, projectPath,
	).Scan(&c.ProjectPath, &c.Identity, &c.LastCostRowID, &ts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SpendCursor{}, false, nil
		}
		return SpendCursor{}, false, classifyDriverErr(err)
	}
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return c, true, nil
}

// AdvanceSpendCursor moves the booking position from `from` to `to`, and
// reports whether this caller was the one that moved it.
//
// It is a compare-and-swap, not a plain update, and the caller must book the
// spend only when it returns won=true. That is what makes the claim to charge
// each row exactly once true rather than merely likely:
//
//   - Across processes. Two hubs run from this repository (ports 8080 and
//     8888) and share one control-plane database. A plain monotonic update
//     ("only move forward") does not help: both can read cursor=100, both
//     read rows 101-110, and both charge them — the guard fires after the
//     double-book, on the second write, too late to matter. With a CAS only
//     one UPDATE matches, so only one of them books.
//
//   - On failure. Booking first and advancing second means a failed advance
//     re-presents the same rows on the next tick, and a control plane that
//     stays unwritable (SQLITE_BUSY past the busy timeout, a read-only mount,
//     a full disk) inflates the tenant's counter by that batch every thirty
//     seconds until the budget is spent and the run is killed on arithmetic
//     that never happened. Advancing first converts that unbounded failure
//     into a bounded one: a process that dies between the CAS and the booking
//     loses exactly one batch, once.
//
// Under-billing a bounded amount once is a cost; over-billing repeatedly stops
// work that should be running. The order is chosen accordingly.
func (d *DB) AdvanceSpendCursor(projectPath string, from, to int64) (won bool, err error) {
	if to <= from {
		return false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(`
		UPDATE project_spend_cursor SET last_cost_row_id = ?, updated_at = ?
		WHERE project_path = ? AND last_cost_row_id = ?`,
		to, time.Now().UTC().Format(time.RFC3339Nano), projectPath, from,
	)
	if err != nil {
		return false, classifyDriverErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The write may well have landed, and booking on a maybe is exactly
		// the double-charge this function exists to prevent.
		return false, classifyDriverErr(err)
	}
	return n > 0, nil
}
