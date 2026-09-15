package janitor

// Row retention: the half of a pass that reaches inside the database
// (Task 20291).
//
// Task 20229 shipped the janitor with three steps — plan history, audit seals,
// VACUUM — and every one of the first two operates on files. Nothing pruned a
// row, which made the VACUUM largely ornamental: it reclaims free pages, and
// only a delete creates one. On this repository's control plane that showed up
// as provider_calls holding 47.5 MB in 265 rows, 14% of all live data in the
// file, with no mechanism anywhere in the tree that would ever remove it.
//
// These steps run before the VACUUM for exactly that reason. The order is the
// point: deletes convert live pages into freelist pages, and the VACUUM then
// hands them back to the filesystem. Run the other way round they would be two
// separate passes, a day apart, and the first would appear to reclaim nothing.

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// rowGroupUnavailable is what the later row steps say when the database could
// not be opened at all. The error itself is reported once, on the first step,
// rather than five times over.
const rowGroupUnavailable = "state.db unavailable; see the provider-calls step"

// rowRetention is the row half of a normalised Policy, resolved once per pass.
type rowRetention struct {
	providerCalls statedb.ProviderCallRetention
	steps         statedb.RowRetention
	events        statedb.RowRetention
	costs         statedb.RowRetention
	telemetry     statedb.RowRetention
}

func (p Policy) rowRetention() rowRetention {
	return rowRetention{
		providerCalls: statedb.ProviderCallRetention{
			BodyMaxAge: p.ProviderCallBodyMaxAge,
			Rows:       statedb.RowRetention{MaxRows: p.ProviderCallMaxRows},
		},
		steps:     statedb.RowRetention{MaxRows: p.StepMaxRows},
		events:    statedb.RowRetention{MaxRows: p.EventMaxRows},
		costs:     statedb.RowRetention{MaxRows: p.CostMaxRows},
		telemetry: statedb.RowRetention{MaxAge: p.TelemetryMaxAge},
	}
}

func (r rowRetention) active() bool {
	return r.providerCalls.Active() || r.steps.Active() || r.events.Active() ||
		r.costs.Active() || r.telemetry.Active()
}

// pruneRowTables applies row retention to every covered table, writing the
// per-table outcomes into rep.
//
// It opens the database once for all five: opening runs the migration check and
// is the expensive part, so five opens would cost more than the pruning.
func pruneRowTables(opts Options, pol Policy, rep *Report) {
	ret := pol.rowRetention()
	if !ret.active() {
		setRowSteps(rep, StepResult{Reason: "disabled (no row limits set)"})
		return
	}

	dbPath := filepath.Join(opts.WorkDir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); err != nil {
		// A project that has never run has no database, which is a reason
		// rather than a fault. Anything else is a real problem an operator
		// should see instead of having it paraphrased as "no database".
		if os.IsNotExist(err) {
			setRowSteps(rep, StepResult{Reason: "no state.db"})
			return
		}
		setRowGroupError(rep, fmt.Errorf("janitor: stat state.db: %w", err))
		return
	}

	db, err := statedb.Open(dbPath)
	if err != nil {
		setRowGroupError(rep, fmt.Errorf("janitor: open state.db for row retention: %w", err))
		return
	}
	defer db.Close() //nolint:errcheck // a failed close on a prune-only handle changes nothing already committed

	now := opts.now()
	rep.ProviderCalls = pruneProviderCalls(db, ret.providerCalls, now, opts.DryRun)
	rep.Steps = pruneSteps(db, ret.steps, now, opts)
	rep.Events = pruneRowTable(db.PruneEvents, "event", ret.events, now, opts.DryRun)
	rep.Costs = pruneRowTable(db.PruneCosts, "cost row", ret.costs, now, opts.DryRun)
	rep.Telemetry = pruneRowTable(db.PruneTelemetryRows, "telemetry event", ret.telemetry, now, opts.DryRun)
}

// setRowSteps gives every row step the same outcome, for the cases where the
// group as a whole could not run.
func setRowSteps(rep *Report, res StepResult) {
	rep.ProviderCalls, rep.Steps, rep.Events = res, res, res
	rep.Costs, rep.Telemetry = res, res
}

// setRowGroupError records a failure of the whole group: the error once, on the
// first step, and a pointer to it on the rest.
//
// Five copies of one open failure tell an operator nothing the first copy did
// not, and Report.Errs would return all five to a cron wrapper that reports
// them individually.
func setRowGroupError(rep *Report, err error) {
	setRowSteps(rep, StepResult{Reason: rowGroupUnavailable})
	rep.ProviderCalls = StepResult{Err: err}
}

// pruneFn is the shape the three plain row tables share.
type pruneFn func(statedb.RowRetention, time.Time, bool) (statedb.RowPruneResult, error)

// pruneRowTable runs one plain table's prune and renders its outcome.
func pruneRowTable(fn pruneFn, noun string, p statedb.RowRetention, now time.Time, dryRun bool) StepResult {
	if !p.Active() {
		return StepResult{Reason: "disabled (no limit set)"}
	}
	res, err := fn(p, now, dryRun)
	out := StepResult{
		Ran:           true,
		Deleted:       int(res.Deleted),
		BytesReleased: res.BytesReleased,
		Reason:        rowReason(noun, res),
	}
	if err != nil {
		out.Err = err
	}
	return out
}

// pruneSteps is the one row table that cannot be pruned under a live run.
//
// A running orchestrator holds the project's whole step history in memory —
// state.Load reads every row — and saveStateLocked upserts all of it on each
// save. Rows deleted underneath it therefore reappear at its next write, so the
// prune would be pure I/O with no effect, and would race the writer for the
// lock while achieving it. Deferring to the next pass costs a day.
func pruneSteps(db *statedb.DB, p statedb.RowRetention, now time.Time, opts Options) StepResult {
	if !p.Active() {
		return StepResult{Reason: "disabled (no limit set)"}
	}
	if opts.RunActive {
		reason := opts.RunActiveReason
		if reason == "" {
			reason = "a task is running"
		}
		return StepResult{Skipped: true, Reason: reason + "; a live run rewrites its own step history"}
	}
	return pruneRowTable(db.PruneSteps, "step", p, now, opts.DryRun)
}

// pruneProviderCalls renders the two-limit provider-call outcome.
func pruneProviderCalls(db *statedb.DB, p statedb.ProviderCallRetention, now time.Time, dryRun bool) StepResult {
	if !p.Active() {
		return StepResult{Reason: "disabled (no body age or row limit set)"}
	}
	res, err := db.PruneProviderCalls(p, now, dryRun)

	out := StepResult{
		Ran:           true,
		Deleted:       int(res.Deleted),
		BytesReleased: res.BytesReleased + res.StrippedBytes,
	}
	switch {
	case res.Stripped > 0 && res.Deleted > 0:
		out.Reason = fmt.Sprintf("stripped %d bod%s (%s) and deleted %d row(s); %d remain",
			res.Stripped, plural(res.Stripped, "y", "ies"), diskusage.HumanBytes(res.StrippedBytes),
			res.Deleted, res.Remaining)
	case res.Stripped > 0:
		out.Reason = fmt.Sprintf("stripped %d bod%s (%s) from %d row(s)",
			res.Stripped, plural(res.Stripped, "y", "ies"),
			diskusage.HumanBytes(res.StrippedBytes), res.Remaining)
	default:
		out.Reason = rowReason("call", res.RowPruneResult)
	}
	if err != nil {
		out.Err = err
	}
	return out
}

// RowTableStats measures the row tables without pruning anything.
//
// Returns an error wrapping os.ErrNotExist when the project has no database,
// which lets a caller distinguish "nothing to report" from "could not read it".
func RowTableStats(workDir string) ([]statedb.TableStat, error) {
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("janitor: state.db: %w", err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("janitor: open state.db: %w", err)
	}
	defer db.Close() //nolint:errcheck // read-only probe
	return db.GrowthTableStats()
}

// TableBounded reports whether pol puts a ceiling on the named table's size.
//
// A ceiling, specifically: an age limit is not one. A table pruned only by age
// still grows without bound under an unbounded write rate, and the question the
// hub doctor is asking — "will this hub still have a disk" — is answered by the
// ceiling or not at all. provider_calls is the exception worth stating: its
// body strip is an age limit and is not what makes it bounded; its row ceiling
// is.
//
// An unknown table name is reported as unbounded, so a table added to
// statedb.GrowthTables without a matching policy knob shows up in the doctor
// rather than passing quietly.
func TableBounded(pol Policy, table string) bool {
	if !pol.Enabled {
		return false
	}
	p := pol.normalise()
	switch table {
	case "provider_calls":
		return p.ProviderCallMaxRows > 0
	case "steps":
		return p.StepMaxRows > 0
	case "events":
		return p.EventMaxRows > 0
	case "costs":
		return p.CostMaxRows > 0
	case "telemetry_events":
		// The one table bounded without a janitor knob: statedb caps it on the
		// write path, because a public ingest endpoint must not be able to fill
		// a disk between two passes.
		return statedb.TelemetryMaxRows > 0
	default:
		return false
	}
}

func rowReason(noun string, res statedb.RowPruneResult) string {
	if res.Deleted == 0 {
		return fmt.Sprintf("%d %s(s), within limits", res.Remaining, noun)
	}
	return fmt.Sprintf("deleted %d %s(s) holding %s; %d remain",
		res.Deleted, noun, diskusage.HumanBytes(res.BytesReleased), res.Remaining)
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
