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

	"github.com/blechschmidt/cloop/pkg/auditretention"
	"github.com/blechschmidt/cloop/pkg/hublease"
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

	// Retention, when non-nil, applies the audit-trail retention window
	// before vacuuming (Task 20218). Pruning without a VACUUM leaves the
	// freed pages on the freelist, so the database on disk does not shrink;
	// doing both in one pass is the only way an operator sees the 2.4 GB come
	// back. Nil disables it, which is the default and what every caller that
	// has not opted into retention gets.
	//
	// The prune runs first and its outcome is reported even when the
	// subsequent VACUUM fails — the rows really were sealed and removed, and
	// a report that hid that would send an operator looking for them.
	Retention *RetentionOptions

	// AllowConcurrentHub skips the live-peer check before VACUUM. It exists
	// for tests and for an operator who knows the lease row is stale in a way
	// the probe cannot see; it is not exposed as a plain --force because the
	// failure it unblocks is rewriting a database file underneath a running
	// hub's open connections.
	AllowConcurrentHub bool
}

// RetentionOptions is the audit-retention half of a maintain run.
type RetentionOptions struct {
	// Days is the retention window. Rows older than this are sealed and
	// removed. Must be positive; zero means the caller did not want
	// retention and should have left Options.Retention nil.
	Days int

	// ExportDir is where sealed prefixes are written.
	ExportDir string

	// Actor is recorded on the anchor.
	Actor string
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

	// Retention is the audit-prune outcome when Options.Retention was set,
	// nil otherwise. Populated for dry runs too, where it describes what
	// would have been sealed.
	Retention *auditretention.Report

	// AfterPrune is the size measured between the prune and the VACUUM. It
	// exists so an operator can see which of the two did the work: the prune
	// moves rows to the freelist, only the VACUUM returns pages to the
	// filesystem. Zero when no prune ran.
	AfterPrune statedb.SizeStats

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
		if opts.Retention != nil {
			pr, err := pruneAudit(db, *opts.Retention, true)
			if err != nil {
				return rep, err
			}
			rep.Retention = pr
		}
		return rep, nil
	}

	if opts.Retention != nil {
		pr, err := pruneAudit(db, *opts.Retention, false)
		if err != nil {
			return rep, err
		}
		rep.Retention = pr
		// The prune freed pages onto the freelist. Re-read the baseline so
		// BytesFreed below attributes the reclaim to this run as a whole
		// rather than reporting only what VACUUM found beyond the prune.
		if refreshed, rerr := db.SizeStats(); rerr == nil {
			rep.AfterPrune = refreshed
		}
	}

	// VACUUM rewrites the entire database file. A second hub with the file
	// open is exactly what makes that unsafe, and this control plane is known
	// to have two writers — :8080 and :8888 both run from the same directory.
	// Task 20214's lease already knows who is live; refuse rather than find
	// out afterwards.
	if !opts.AllowConcurrentHub {
		if err := refusePeerHub(dbPath); err != nil {
			return rep, err
		}
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

// pruneAudit applies the retention window, translating dbmaintain's options
// into an auditretention run.
func pruneAudit(db *statedb.DB, ro RetentionOptions, dryRun bool) (*auditretention.Report, error) {
	if ro.Days <= 0 {
		return nil, fmt.Errorf("dbmaintain: retention requested with a non-positive window (%d days)", ro.Days)
	}
	rep, err := auditretention.Prune(db, auditretention.Options{
		Before:    auditretention.ResolveCutoff(ro.Days, time.Now().UTC()),
		ExportDir: ro.ExportDir,
		Actor:     ro.Actor,
		DryRun:    dryRun,
	})
	if err != nil {
		return nil, fmt.Errorf("dbmaintain: audit retention: %w", err)
	}
	return rep, nil
}

// ErrPeerHubLive is returned when a VACUUM is refused because another hub
// holds the control-plane lease. Callers match on it to print advice rather
// than a stack of wrapped errors.
var ErrPeerHubLive = errors.New("dbmaintain: another hub instance is live")

// refusePeerHub fails when Task 20214's lease says a hub is running against
// this database.
//
// VACUUM rebuilds the file from scratch. SQLite's locking makes that safe
// against concurrent *transactions*, but a hub is more than a transaction: it
// caches project status, holds WebSocket clients and runs background sweeps
// against state it expects to stay put, and rewriting several gigabytes
// underneath it stalls every one of those for the duration. The lease already
// answers "is a hub live" precisely — including the case where the recorded
// pid belongs to a different boot — so there is no reason to guess.
//
// A lapsed lease is not an obstacle: Inspect reports it as not live, and the
// maintain proceeds.
func refusePeerHub(dbPath string) error {
	st, err := hublease.Inspect(hublease.Options{DBPath: dbPath})
	if err != nil {
		// The probe itself failing is not evidence of a peer, and refusing on
		// it would make maintenance impossible on a database whose lease table
		// is unreadable for an unrelated reason. Say so and continue.
		return nil //nolint:nilerr // deliberately non-fatal; see comment
	}
	if !st.Live {
		return nil
	}
	return fmt.Errorf("%w: %s (pid %d) has held the lease since %s — stop it, or re-run once its lease lapses (%s)",
		ErrPeerHubLive, st.Row.Hostname, st.Row.PID,
		st.Row.AcquiredAt.Format(time.RFC3339), st.TTL)
}
