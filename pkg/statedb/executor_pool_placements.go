package statedb

// executor_pool_placements.go: which pool, and which of its runners, a run of
// this project was handed (Task 20486; migrations/0101_executor_pool_dashboard.sql).
//
// A task records the executor it ran on (Task 20244). For a pool runner that
// executor is an ephemeral agent with a random id, and the control plane
// forgets it soon after it is retired. So the hub writes this row into the
// project's own database as it hands a run to a runner, and every task reader
// joins it in by executor id: a task that ran on a pool says so, by name, for
// as long as the project keeps the task.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// PoolPlacementRow names the pool and the runner behind a runner's executor id.
type PoolPlacementRow struct {
	ExecutorID string
	PoolID     string
	PoolName   string
	RunnerName string
	RecordedAt time.Time
}

// placementSep separates the pool's name from the runner's in the task
// readers' joined column: a unit separator, which neither name may contain.
const placementSep = "\x1f"

// placementSelect is the task readers' subquery: "<pool>\x1f<runner>" for a
// task whose executor was a pool's runner, "" otherwise.
const placementSelect = `COALESCE((SELECT pp.pool_name || char(31) || pp.runner_name FROM executor_pool_placements pp
		WHERE pp.executor_id = plan_tasks.executor_id AND plan_tasks.executor_id != ''), '')`

// splitPlacement reads placementSelect's column.
func splitPlacement(v string) (pool, runner string) {
	if v == "" {
		return "", ""
	}
	pool, runner, _ = strings.Cut(v, placementSep)
	return pool, runner
}

// RecordPoolPlacement records that the runner whose agent is row.ExecutorID
// belongs to row.PoolName's pool and is called row.RunnerName. Writing the
// same executor again updates its row in place.
func (d *DB) RecordPoolPlacement(row PoolPlacementRow) error {
	row.ExecutorID = strings.TrimSpace(row.ExecutorID)
	if row.ExecutorID == "" || strings.TrimSpace(row.PoolName) == "" {
		return errors.New("statedb: a pool placement needs the runner's executor id and its pool's name")
	}
	if strings.Contains(row.PoolName+row.RunnerName, placementSep) {
		return errors.New("statedb: a pool or runner name cannot contain a unit separator")
	}
	if row.RecordedAt.IsZero() {
		row.RecordedAt = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`INSERT INTO executor_pool_placements(executor_id, pool_id, pool_name, runner_name, recorded_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(executor_id) DO UPDATE SET pool_id = excluded.pool_id, pool_name = excluded.pool_name,
		  runner_name = excluded.runner_name, recorded_at = excluded.recorded_at`,
		row.ExecutorID, strings.TrimSpace(row.PoolID), strings.TrimSpace(row.PoolName), strings.TrimSpace(row.RunnerName),
		formatOptionalTime(row.RecordedAt)); err != nil {
		return fmt.Errorf("statedb: record the pool placement of %q: %w", row.ExecutorID, classifyDriverErr(err))
	}
	return nil
}
