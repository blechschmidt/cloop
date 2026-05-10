// Package dbmaintain implements VACUUM + ANALYZE maintenance for the cloop
// state database (Task 20107).
//
// It complements pkg/dbverify (Task 20094 — integrity checking) and the
// statedb migration framework (Task 20101 — schema lifecycle) to round out
// the database lifecycle management story:
//
//	cloop db verify   → detect on-disk corruption (PRAGMA integrity_check)
//	cloop migrate     → bring schema up to current binary's version
//	cloop db maintain → reclaim freelist + refresh planner stats (this pkg)
//
// Operations performed:
//
//   - VACUUM: rewrites the database file with no free space, returning
//     reclaimed pages to the filesystem. Required after large deletes such
//     as `cloop compact` or step-history pruning, otherwise the file keeps
//     its peak size forever.
//   - ANALYZE: refreshes per-index statistics so the query planner picks
//     good plans as table sizes change. Cheap; we always run it after a
//     successful VACUUM.
//
// Auto-mode logic: if the current page_count exceeds AutoGrowthThreshold
// times the page_count recorded after the last vacuum, run; otherwise skip.
// First-ever invocation always runs (there is no prior baseline to compare
// against).
package dbmaintain

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// AutoGrowthThreshold gates --auto runs: vacuum only when the current
// page_count exceeds threshold × last_vacuum.page_count_after. 1.20 = "must
// have grown at least 20% since the last vacuum".
const AutoGrowthThreshold = 1.20

// Options configures Run.
type Options struct {
	// DryRun reports estimated reclaimable bytes (freelist_count × page_size)
	// without performing VACUUM or ANALYZE. Nothing is written to the DB —
	// not even a maintenance_log row.
	DryRun bool

	// Auto enables growth-gated execution. When set and a prior vacuum exists,
	// Run is a no-op unless the DB has grown >AutoGrowthThreshold since.
	// If no prior vacuum exists, Auto behaves as a normal run (so cron-style
	// usage from a fresh project does the right thing on first call).
	Auto bool

	// SkipAnalyze runs only VACUUM. Useful in tests; not exposed via CLI.
	SkipAnalyze bool
}

// Report summarises a maintain run.
type Report struct {
	DBPath string

	DryRun      bool
	AutoSkipped bool

	// Reason carries human-readable rationale for the auto-mode decision
	// ("auto: no prior vacuum recorded", "auto: page_count 12345 > 1.20×8000
	// last vacuum", "auto: skipped — DB has grown only 5% since last vacuum").
	Reason string

	Before     statedb.SizeStats
	After      statedb.SizeStats
	BytesFreed int64

	// Operations lists the actions performed in order, e.g. ["VACUUM",
	// "ANALYZE"]. Empty for dry-run or auto-skipped runs.
	Operations []string

	// LastEntry is the most recent maintenance_log row prior to this run,
	// or nil if no maintenance has been recorded before. Populated for both
	// dry-run and real runs so the UI/CLI can surface "last maintained N ago".
	LastEntry *statedb.MaintenanceLogEntry

	// EstimatedReclaim is the dry-run estimate of bytes that VACUUM could
	// reclaim, derived from freelist_count × page_size. Only populated when
	// DryRun is true.
	EstimatedReclaim int64
}

// Run opens the database at dbPath, performs the requested maintenance, and
// returns a Report. The connection is opened via statedb.Open so any pending
// schema migrations (including 0002_maintenance_log) run first.
func Run(dbPath string, opts Options) (*Report, error) {
	if dbPath == "" {
		return nil, errors.New("dbmaintain: empty database path")
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("dbmaintain: database not found: %s", dbPath)
		}
		return nil, fmt.Errorf("dbmaintain: stat %s: %w", dbPath, err)
	}

	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("dbmaintain: open: %w", err)
	}
	defer db.Close()

	return runOnDB(db, dbPath, opts)
}

// runOnDB is the work loop, separated from Run so tests can drive an existing
// *statedb.DB without re-opening the file.
func runOnDB(db *statedb.DB, dbPath string, opts Options) (*Report, error) {
	rep := &Report{DBPath: dbPath, DryRun: opts.DryRun}

	before, err := db.SizeStats()
	if err != nil {
		return rep, fmt.Errorf("dbmaintain: collect pre-stats: %w", err)
	}
	rep.Before = before
	rep.After = before // overwritten on real runs

	last, err := db.LastMaintenanceLog()
	if err != nil {
		return rep, fmt.Errorf("dbmaintain: read last maintenance_log: %w", err)
	}
	rep.LastEntry = last

	if opts.Auto {
		switch {
		case last == nil:
			rep.Reason = "auto: no prior vacuum recorded — running"
		case last.PageCountAfter <= 0:
			// Defensive: a corrupt log row would otherwise cause divide-by-zero
			// reasoning. Treat as "no baseline" and just run.
			rep.Reason = "auto: prior vacuum baseline missing — running"
		default:
			threshold := int64(float64(last.PageCountAfter) * AutoGrowthThreshold)
			if before.PageCount <= threshold {
				rep.AutoSkipped = true
				rep.Reason = fmt.Sprintf(
					"auto: page_count %d ≤ %d threshold (%.0f%% growth limit since last vacuum %d)",
					before.PageCount, threshold,
					(AutoGrowthThreshold-1)*100, last.PageCountAfter,
				)
				return rep, nil
			}
			rep.Reason = fmt.Sprintf(
				"auto: page_count %d > %d threshold — running",
				before.PageCount, threshold,
			)
		}
	}

	if opts.DryRun {
		rep.EstimatedReclaim = before.FreelistBytes()
		return rep, nil
	}

	started := time.Now().UTC()

	if err := db.Vacuum(); err != nil {
		return rep, fmt.Errorf("dbmaintain: VACUUM: %w", err)
	}
	rep.Operations = append(rep.Operations, "VACUUM")

	if !opts.SkipAnalyze {
		if err := db.Analyze(); err != nil {
			// VACUUM already succeeded — return that progress to the caller
			// rather than swallowing it. Operations still records the VACUUM.
			return rep, fmt.Errorf("dbmaintain: ANALYZE: %w", err)
		}
		rep.Operations = append(rep.Operations, "ANALYZE")
	}

	completed := time.Now().UTC()

	after, err := db.SizeStats()
	if err != nil {
		return rep, fmt.Errorf("dbmaintain: collect post-stats: %w", err)
	}
	rep.After = after
	if before.Bytes > after.Bytes {
		rep.BytesFreed = before.Bytes - after.Bytes
	}

	logEntry := statedb.MaintenanceLogEntry{
		Operation:       strings.ToLower(strings.Join(rep.Operations, "+")),
		StartedAt:       started,
		CompletedAt:     completed,
		PageCountBefore: before.PageCount,
		PageCountAfter:  after.PageCount,
		PageSize:        before.PageSize,
		BytesBefore:     before.Bytes,
		BytesAfter:      after.Bytes,
		Note:            rep.Reason,
	}
	if _, err := db.AppendMaintenanceLog(logEntry); err != nil {
		// Maintenance succeeded; persisting the log row failed. Surface as
		// an error so the operator knows the auto-mode baseline did not
		// update — but the DB itself is in a fine state.
		return rep, fmt.Errorf("dbmaintain: persist maintenance_log: %w", err)
	}
	return rep, nil
}
