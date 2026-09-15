// Package janitor bounds a project's .cloop directory automatically
// (Task 20229).
//
// cloop had three retention mechanisms before this package and ran none of
// them on its own: `cloop compact` prunes snapshots and artifacts, `cloop db
// maintain` vacuums the database, and `cloop hub audit prune` seals and trims
// the audit trail. All three are operator-invoked. A hub nobody is babysitting
// therefore grows until the disk fills — measured on this repository's own
// control plane at 4.9 GB, of which roughly 4.3 GB was reclaimable: 2 GB of
// SQLite freelist that no `du` reports, and 2 GB of plan history in 3,983
// files. That is an availability defect, not housekeeping, so the fix belongs
// inside the hub process rather than in a runbook.
//
// What a pass does, in order:
//
//  1. Bound .cloop/plan-history to the configured keep-count. This is a
//     catch-up pass: pm.SaveSnapshot enforces the same bound at write time, so
//     steady-state history never exceeds it between passes. The janitor exists
//     to reclaim installs that predate the write-time bound, and to apply a
//     keep-count an operator has since lowered.
//  2. Apply size-and-age retention to .cloop/audit-archive.
//  3. VACUUM the database, but only when the freelist is large enough in
//     proportion to the file to be worth it.
//
// Every step is individually skippable and none of them aborts the others: a
// pass that cannot read the archive directory still vacuums.
//
// # Why the VACUUM is conditional
//
// VACUUM rewrites the entire database file and needs free space to do it —
// SQLite copies the live pages out and writes them back through the journal,
// so it consumes space before it returns any. That is the exact thing you
// cannot afford on a disk that is nearly full, which is when a janitor is most
// likely to want it. Running it daily regardless of need would be a worse
// defect than the one it fixes. So the janitor reads freelist_count and
// page_count (both O(1) header reads, unlike dbstat, which scans every page)
// and vacuums only when the free fraction crosses a threshold, only when the
// filesystem has room for the rebuild, and only after the file-level steps
// above have released what they can.
//
// # Why it takes the lease, and why it still declines
//
// VACUUM rebuilds the file underneath every open connection. Task 20214's hub
// lease already answers "is another hub live against this database" exactly,
// so the janitor refuses to vacuum unless the live lease holder is the process
// it is running inside. Two hubs sharing a directory — which this deployment
// has had — cannot both decide to rewrite the file.
//
// Owning the lease is necessary but not sufficient. The lease *lives in the
// database being rewritten*, so a VACUUM long enough to outlast its TTL
// starves the heartbeat and the hub stands down believing a peer took over.
// DefaultVacuumMaxInlineBytes is the ceiling that prevents it; past that the
// rewrite belongs to `cloop hub retention --apply` with the hub stopped, which
// has no heartbeat to lose.
package janitor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/dbmaintain"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Defaults for a policy an operator has not configured. Plan-history and
// VACUUM default on because both grow on every install; audit-archive
// retention defaults off — see Policy.ArchiveMaxBytes.
const (
	// DefaultInterval is how often the hub runs a pass. Daily: the growth
	// this bounds is measured in days, and a shorter interval would spend
	// I/O re-reading directories that have not changed.
	DefaultInterval = 24 * time.Hour

	// DefaultVacuumFreeRatio is the freelist fraction at which a VACUUM
	// becomes worth its cost. At 0.30, a database is rewritten only once
	// nearly a third of it is dead space — well above the 0.25 that `cloop
	// doctor` has always used to *warn*, so the janitor acts strictly after
	// the point an operator was already being told to act.
	DefaultVacuumFreeRatio = 0.30

	// DefaultVacuumMinFreeBytes stops the ratio triggering pointless work on
	// a small database. A fresh project can be 90% freelist and still only
	// waste a few hundred kilobytes; rewriting it every day to reclaim that
	// is cost without benefit.
	DefaultVacuumMinFreeBytes int64 = 64 << 20 // 64 MiB

	// DefaultVacuumMaxInlineBytes bounds how much *live* data the in-hub
	// janitor will rewrite without stopping the hub, and it exists because
	// the obvious implementation takes the hub down.
	//
	// VACUUM holds a write lock for its whole duration, and the control-plane
	// database is where the hub's own lease lives. So a VACUUM that outlasts
	// the lease TTL (hublease.DefaultTTL, 60s) starves the heartbeat, the hub
	// concludes a peer took the fence, and Run returns "standing down" — a
	// self-inflicted outage misreported as a second instance. Worse, it would
	// repeat: the pass runs 30s after startup, so a hub whose database is
	// large enough never stays up.
	//
	// The bound is on live bytes rather than file size because live bytes are
	// what VACUUM copies — a 2.3 GB file holding 290 MB of real data is a
	// sub-second rewrite, and gating on 2.3 GB would refuse exactly the
	// mostly-empty databases that most need reclaiming. 1 GiB at a
	// conservative 100 MB/s is ~10s: longer than one 20s renewal interval can
	// absorb without a retry, comfortably inside the 60s that would actually
	// lose the fence.
	//
	// Above the bound the janitor declines and says so; `cloop hub retention
	// --apply` with the hub stopped has no lease to lose and no ceiling.
	DefaultVacuumMaxInlineBytes int64 = 1 << 30 // 1 GiB of live data
)

// Defaults for the row tables (Task 20291). Every one of these is on by
// default, because unlike the audit archive these tables hold derived
// observability data with a second copy or no lasting value, and unlike plan
// history nothing bounded them at write time.
//
// The numbers come from measuring this repository's control plane, where
// provider_calls held 47.5 MB in 265 rows — 14% of everything live in a 2.4 GB
// file — and steps held 5,152 rows after four and a half months.
const (
	// DefaultProviderCallBodyMaxAge is when a recorded prompt and response are
	// cleared, leaving the row's metadata behind.
	//
	// Thirty days is chosen from what the bodies are for. The inspector's
	// per-call modal and its replay button are debugging tools aimed at a call
	// you are currently reasoning about; their value decays in hours, while the
	// row's timestamp, model, token counts and latency keep feeding the list
	// and every cost-shaped report indefinitely. At the measured 178 KB per row
	// this is the single largest reclaim in the whole janitor.
	DefaultProviderCallBodyMaxAge = 30 * 24 * time.Hour

	// DefaultProviderCallMaxRows bounds the table itself. A stripped row costs
	// roughly 200 bytes, so ten thousand of them is about 2 MB — small enough
	// to keep a long history, finite enough that the table is bounded.
	DefaultProviderCallMaxRows = 10000

	// DefaultStepMaxRows bounds the step history. Steps are loaded in full by
	// state.Load, so this ceiling is also a bound on a run's resident memory;
	// at the measured average of roughly 450 bytes of output per step, twenty
	// thousand is about 9 MB.
	DefaultStepMaxRows = 20000

	// DefaultEventMaxRows bounds the unified event journal, which the dashboard
	// pages through newest-first and never reads whole.
	DefaultEventMaxRows = 20000

	// DefaultCostMaxRows bounds the cost ledger, and is deliberately the
	// loosest of these: a cost row is tiny, `cloop cost report` aggregates over
	// the entire table, and the hub's spend enforcement reads forward from a
	// stored cursor. At the measured rate this ceiling is decades away, which
	// is the intent — it exists so the table is bounded, not so it is pruned.
	DefaultCostMaxRows = 50000

	// DefaultTelemetryMaxAge ages out browser diagnostic trails. The write path
	// already caps the table at statedb.TelemetryMaxRows — a public ingest
	// endpoint must not be able to fill a disk between two passes — so this is
	// the half no write-time cap can express: a trail nobody came back for.
	DefaultTelemetryMaxAge = 30 * 24 * time.Hour
)

// Policy is the retention configuration for one pass.
type Policy struct {
	// Enabled gates the whole janitor. False means the hub starts no
	// background pass at all — the documented opt-out.
	Enabled bool

	// Interval is how often the hub runs a pass. Zero selects
	// DefaultInterval.
	Interval time.Duration

	// KeepSnapshots bounds .cloop/plan-history. Zero or less disables
	// plan-history pruning and keeps everything.
	KeepSnapshots int

	// ArchiveMaxBytes caps the total size of .cloop/audit-archive; the
	// oldest seals are deleted until the directory fits. Zero disables the
	// size cap.
	//
	// Both archive limits default to off, and deliberately so. A seal is the
	// only copy of audit rows that have already been deleted from the
	// database — deleting one destroys the record rather than relocating it,
	// which is the opposite of what the rest of the audit path does. It is
	// also not a default-install problem: archives exist only if the operator
	// opted into audit retention in the first place (config audit.retention_days
	// is itself zero by default), so an operator who has seals has already
	// made a retention decision and is the right person to make this one too.
	// `cloop doctor` reports the directory's size so that decision is
	// prompted by data rather than by a full disk.
	ArchiveMaxBytes int64

	// ArchiveMaxAgeDays deletes seals older than this many days. Zero
	// disables the age limit. See ArchiveMaxBytes for why this is opt-in.
	ArchiveMaxAgeDays int

	// VacuumFreeRatio is the freelist fraction at or above which the janitor
	// vacuums. Zero selects DefaultVacuumFreeRatio; a value >= 1 disables
	// vacuuming, since no database can be more than entirely free.
	VacuumFreeRatio float64

	// VacuumMinFreeBytes is an absolute floor beneath which the ratio is
	// ignored. Zero selects DefaultVacuumMinFreeBytes; negative disables the
	// floor.
	VacuumMinFreeBytes int64

	// VacuumMaxInlineBytes caps the live data an *in-process* VACUUM will
	// rewrite, protecting the hub's own lease heartbeat from a rewrite that
	// outlasts it. Zero selects DefaultVacuumMaxInlineBytes; negative removes
	// the cap. It applies only when Options.InstanceID is set — a caller with
	// no lease at stake has nothing to protect.
	VacuumMaxInlineBytes int64

	// ── Row tables (Task 20291) ──
	//
	// Zero selects the package default for each; negative disables the limit
	// and keeps everything, which is how an operator opts a table out.

	// ProviderCallBodyMaxAge clears the prompt, system prompt and response of
	// provider_calls rows older than this, keeping the row. See
	// DefaultProviderCallBodyMaxAge for why the bodies and the row have
	// different lifetimes.
	ProviderCallBodyMaxAge time.Duration

	// ProviderCallMaxRows, StepMaxRows, EventMaxRows and CostMaxRows are the
	// per-table row ceilings; the newest rows survive.
	ProviderCallMaxRows int
	StepMaxRows         int
	EventMaxRows        int
	CostMaxRows         int

	// TelemetryMaxAge deletes browser telemetry older than this. Age rather
	// than count because the table already has a write-time row cap; what it
	// lacks is a way for a quiet trail to expire.
	TelemetryMaxAge time.Duration

	// ArchiveDir is the directory holding sealed audit exports. Empty means
	// <workDir>/.cloop/audit-archive, which is auditretention's default — but
	// a real deployment is advised to point audit.export_dir at storage the
	// hub does not otherwise own, and retention has to follow the seals there
	// or it silently bounds an empty directory while the real one grows.
	ArchiveDir string
}

// DefaultPolicy returns the policy a hub uses when config says nothing.
func DefaultPolicy() Policy {
	return Policy{
		Enabled:                true,
		Interval:               DefaultInterval,
		KeepSnapshots:          pm.DefaultSnapshotRetention,
		VacuumFreeRatio:        DefaultVacuumFreeRatio,
		VacuumMinFreeBytes:     DefaultVacuumMinFreeBytes,
		VacuumMaxInlineBytes:   DefaultVacuumMaxInlineBytes,
		ProviderCallBodyMaxAge: DefaultProviderCallBodyMaxAge,
		ProviderCallMaxRows:    DefaultProviderCallMaxRows,
		StepMaxRows:            DefaultStepMaxRows,
		EventMaxRows:           DefaultEventMaxRows,
		CostMaxRows:            DefaultCostMaxRows,
		TelemetryMaxAge:        DefaultTelemetryMaxAge,
	}
}

// PolicyFromConfig translates the operator-facing config section into a
// policy. A nil config yields the defaults, so a caller that failed to load
// config.yaml still gets a hub that bounds its disk.
//
// Config expresses the two byte-valued limits in megabytes because that is
// what an operator writes; the conversion lives here rather than in pkg/config
// so the config struct stays a faithful record of the file.
func PolicyFromConfig(cfg *config.Config) Policy {
	p := DefaultPolicy()
	if cfg == nil {
		return p
	}
	rc := cfg.Retention
	p.Enabled = rc.RetentionEnabled()
	if rc.IntervalHours > 0 {
		p.Interval = time.Duration(rc.IntervalHours) * time.Hour
	}
	if rc.KeepSnapshots > 0 {
		p.KeepSnapshots = rc.KeepSnapshots
	}
	if rc.ArchiveMaxMB > 0 {
		p.ArchiveMaxBytes = int64(rc.ArchiveMaxMB) << 20
	}
	if rc.ArchiveMaxAgeDays > 0 {
		p.ArchiveMaxAgeDays = rc.ArchiveMaxAgeDays
	}
	if rc.VacuumFreeRatio > 0 {
		p.VacuumFreeRatio = rc.VacuumFreeRatio
	}
	if rc.VacuumMinFreeMB > 0 {
		p.VacuumMinFreeBytes = int64(rc.VacuumMinFreeMB) << 20
	}
	if rc.VacuumMaxInlineMB > 0 {
		p.VacuumMaxInlineBytes = int64(rc.VacuumMaxInlineMB) << 20
	}
	// Row tables: config says days and rows, and a negative value is the
	// operator's way of saying "keep everything in this table". normalise
	// turns that back into a zero the prune reads as disabled, so the negative
	// has to survive the copy rather than be filtered out here.
	if rc.ProviderCallBodyAgeDays != 0 {
		p.ProviderCallBodyMaxAge = days(rc.ProviderCallBodyAgeDays)
	}
	if rc.ProviderCallMaxRows != 0 {
		p.ProviderCallMaxRows = rc.ProviderCallMaxRows
	}
	if rc.StepMaxRows != 0 {
		p.StepMaxRows = rc.StepMaxRows
	}
	if rc.EventMaxRows != 0 {
		p.EventMaxRows = rc.EventMaxRows
	}
	if rc.CostMaxRows != 0 {
		p.CostMaxRows = rc.CostMaxRows
	}
	if rc.TelemetryMaxAgeDays != 0 {
		p.TelemetryMaxAge = days(rc.TelemetryMaxAgeDays)
	}
	// Seals follow audit.export_dir when the operator moved them. Without
	// this the janitor bounds .cloop/audit-archive — which in that
	// configuration is empty — while the directory actually filling up is
	// somewhere else entirely.
	p.ArchiveDir = cfg.Audit.ExportDir
	return p
}

// normalise resolves zero values to their defaults.
func (p Policy) normalise() Policy {
	if p.Interval <= 0 {
		p.Interval = DefaultInterval
	}
	if p.VacuumFreeRatio == 0 {
		p.VacuumFreeRatio = DefaultVacuumFreeRatio
	}
	if p.VacuumMinFreeBytes == 0 {
		p.VacuumMinFreeBytes = DefaultVacuumMinFreeBytes
	}
	if p.VacuumMinFreeBytes < 0 {
		p.VacuumMinFreeBytes = 0
	}
	if p.VacuumMaxInlineBytes == 0 {
		p.VacuumMaxInlineBytes = DefaultVacuumMaxInlineBytes
	}
	// Row limits: zero means "use the default", negative means "keep
	// everything". The prune layer reads any non-positive value as disabled, so
	// collapsing negatives to zero here is what makes the opt-out work without
	// every call site having to know the convention.
	p.ProviderCallBodyMaxAge = normaliseDuration(p.ProviderCallBodyMaxAge, DefaultProviderCallBodyMaxAge)
	p.TelemetryMaxAge = normaliseDuration(p.TelemetryMaxAge, DefaultTelemetryMaxAge)
	p.ProviderCallMaxRows = normaliseLimit(p.ProviderCallMaxRows, DefaultProviderCallMaxRows)
	p.StepMaxRows = normaliseLimit(p.StepMaxRows, DefaultStepMaxRows)
	p.EventMaxRows = normaliseLimit(p.EventMaxRows, DefaultEventMaxRows)
	p.CostMaxRows = normaliseLimit(p.CostMaxRows, DefaultCostMaxRows)
	return p
}

// normaliseLimit resolves the zero-is-default, negative-is-off convention the
// row limits share.
func normaliseLimit(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}

func normaliseDuration(v, def time.Duration) time.Duration {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}

// days converts an operator-facing day count, preserving the negative that
// means "disabled".
func days(n int) time.Duration {
	if n < 0 {
		return -1
	}
	return time.Duration(n) * 24 * time.Hour
}

// Options configures a single pass.
type Options struct {
	// WorkDir is the project root; the janitor operates on WorkDir/.cloop.
	WorkDir string
	Policy  Policy

	// DryRun reports what a pass would reclaim without deleting or vacuuming.
	DryRun bool

	// InstanceID is the hub lease identity of the process running this pass.
	// When empty, the VACUUM step refuses if *any* hub holds the lease — the
	// correct behaviour for an out-of-process caller such as the CLI. When
	// set, it refuses only if the holder is somebody else.
	InstanceID string

	// SkipVacuum suppresses the VACUUM regardless of the freelist, and
	// SkipVacuumReason says why. The hub sets this for a project that is
	// currently executing a task: SQLite would serialise the rewrite against
	// the orchestrator's writes rather than corrupt anything, but stalling a
	// live run for the minutes a multi-gigabyte rewrite takes is not a
	// trade the janitor gets to make unprompted. The file-level steps still
	// run — pruning old snapshots is safe under a live writer.
	SkipVacuum       bool
	SkipVacuumReason string

	// RunActive tells the pass that this project is currently executing a
	// task, and RunActiveReason says how the caller knows. It suppresses the
	// steps prune only.
	//
	// Separate from SkipVacuum because it protects against a different thing.
	// SkipVacuum is about latency: a rewrite would stall a live run's writes.
	// This is about correctness: a run keeps the whole step history in memory
	// and upserts all of it on every save, so rows deleted underneath it come
	// back. Every other row table here is append-only and safe to prune while a
	// task runs.
	RunActive       bool
	RunActiveReason string

	// Now is the clock, injectable for tests. Nil means time.Now.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// ApplySnapshotRetention pushes the configured plan-history keep-count into
// pkg/pm, which enforces it inside SaveSnapshot.
//
// This is what stops history outrunning the janitor between passes: a busy
// project writes a full plan copy on every mutation, so thousands of snapshots
// can accumulate inside a single daily interval. Binding the value at process
// start means every writer — the hub's UI mutations and the orchestrator
// subprocess alike — honours the operator's policy, without threading it
// through SaveSnapshot's dozen call sites.
//
// A disabled janitor disables the write-time bound too: an operator who turned
// retention off asked for their history to be kept.
func ApplySnapshotRetention(cfg *config.Config) {
	pol := PolicyFromConfig(cfg)
	if !pol.Enabled {
		pm.SetSnapshotRetention(0)
		return
	}
	pm.SetSnapshotRetention(pol.KeepSnapshots)
}

// StepResult is the outcome of one retention step.
type StepResult struct {
	// Ran is false when the step was disabled or had nothing to do; Reason
	// then says which.
	Ran bool
	// Skipped marks a step that was applicable but deliberately not run —
	// principally the VACUUM below its threshold. Distinguished from "ran and
	// found nothing" so an operator can tell a working threshold from a
	// broken step.
	Skipped bool
	Reason  string
	Deleted int
	// BytesFreed is space returned to the filesystem — files removed, or the
	// shrink a VACUUM achieved.
	BytesFreed int64
	// BytesReleased is space returned to the *database freelist* by deleting
	// rows. The file does not shrink until the VACUUM step runs, which is why
	// this is reported separately and is deliberately excluded from
	// Report.BytesFreed: adding both would count the same bytes twice, once
	// when the rows went and again when the rewrite handed the pages back.
	BytesReleased int64
	Err           error
}

// Report describes a completed pass.
type Report struct {
	WorkDir     string        `json:"work_dir"`
	StartedAt   time.Time     `json:"started_at"`
	Duration    time.Duration `json:"duration"`
	DryRun      bool          `json:"dry_run"`
	PlanHistory StepResult    `json:"plan_history"`
	Archive     StepResult    `json:"audit_archive"`
	// The row tables (Task 20291), pruned before the VACUUM so it has
	// something to reclaim.
	ProviderCalls StepResult `json:"provider_calls"`
	Steps         StepResult `json:"steps"`
	Events        StepResult `json:"events"`
	Costs         StepResult `json:"costs"`
	Telemetry     StepResult `json:"telemetry"`
	Vacuum        StepResult `json:"vacuum"`
	// Before and After are the .cloop breakdowns either side of the pass.
	// After is nil for a dry run, which changes nothing.
	Before *diskusage.Usage `json:"before,omitempty"`
	After  *diskusage.Usage `json:"after,omitempty"`
}

// rowSteps returns the row-table steps in report order.
func (r *Report) rowSteps() []StepResult {
	if r == nil {
		return nil
	}
	return []StepResult{r.ProviderCalls, r.Steps, r.Events, r.Costs, r.Telemetry}
}

// BytesFreed totals what the pass returned to the filesystem.
//
// Row pruning is not in this sum: deleting a row frees a database page, not a
// byte of disk, and the VACUUM step below already reports the shrink those
// pages made possible. See BytesReleased.
func (r *Report) BytesFreed() int64 {
	if r == nil {
		return 0
	}
	return r.PlanHistory.BytesFreed + r.Archive.BytesFreed + r.Vacuum.BytesFreed
}

// BytesReleased totals what row pruning returned to the database freelist,
// which the VACUUM step reclaims if it runs.
func (r *Report) BytesReleased() int64 {
	var n int64
	for _, s := range r.rowSteps() {
		n += s.BytesReleased
	}
	return n
}

// RowsDeleted totals the rows removed across every table.
func (r *Report) RowsDeleted() int {
	var n int
	for _, s := range r.rowSteps() {
		n += s.Deleted
	}
	return n
}

// Errs collects the per-step failures, if any.
func (r *Report) Errs() []error {
	if r == nil {
		return nil
	}
	var out []error
	steps := append([]StepResult{r.PlanHistory, r.Archive}, r.rowSteps()...)
	for _, s := range append(steps, r.Vacuum) {
		if s.Err != nil {
			out = append(out, s.Err)
		}
	}
	return out
}

// Summary renders a one-line operator-facing description of the pass.
func (r *Report) Summary() string {
	if r == nil {
		return "no pass"
	}
	verb := "reclaimed"
	if r.DryRun {
		verb = "would reclaim"
	}
	parts := []string{fmt.Sprintf("%s %s", verb, diskusage.HumanBytes(r.BytesFreed()))}
	if r.PlanHistory.Deleted > 0 {
		parts = append(parts, fmt.Sprintf("%d snapshots", r.PlanHistory.Deleted))
	}
	if r.Archive.Deleted > 0 {
		parts = append(parts, fmt.Sprintf("%d seals", r.Archive.Deleted))
	}
	// Rows are reported as their own clause rather than folded into the byte
	// total: the bytes they released are still inside the file until the
	// VACUUM runs, and a summary that implied otherwise would be wrong on
	// every pass where the freelist stayed below the threshold.
	if n := r.RowsDeleted(); n > 0 {
		parts = append(parts, fmt.Sprintf("%d rows (%s to the freelist)", n, diskusage.HumanBytes(r.BytesReleased())))
	} else if b := r.BytesReleased(); b > 0 {
		parts = append(parts, fmt.Sprintf("%s of call bodies to the freelist", diskusage.HumanBytes(b)))
	}
	switch {
	case r.Vacuum.Ran:
		parts = append(parts, "vacuumed")
	case r.Vacuum.Skipped:
		parts = append(parts, "vacuum skipped ("+r.Vacuum.Reason+")")
	}
	return strings.Join(parts, ", ")
}

// RunOnce performs a single retention pass. It returns a Report even when
// individual steps fail; the error return is reserved for a failure that
// prevented the pass from being attempted at all.
func RunOnce(opts Options) (*Report, error) {
	if opts.WorkDir == "" {
		return nil, errors.New("janitor: empty work dir")
	}
	pol := opts.Policy.normalise()
	start := opts.now()
	if _, err := os.Stat(filepath.Join(opts.WorkDir, ".cloop")); err != nil {
		// Nothing to retain, and creating the directory to say so would make a
		// read-only-looking pass the thing that litters every directory the
		// hub has ever been pointed at.
		return nil, fmt.Errorf("janitor: no .cloop in %s: %w", opts.WorkDir, err)
	}
	rep := &Report{WorkDir: opts.WorkDir, StartedAt: start, DryRun: opts.DryRun}

	before, err := diskusage.Measure(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("janitor: measure %s: %w", opts.WorkDir, err)
	}
	rep.Before = before

	rep.PlanHistory = prunePlanHistory(opts.WorkDir, pol.KeepSnapshots, opts.DryRun)
	rep.Archive = pruneArchive(resolveArchiveDir(opts.WorkDir, pol), pol, opts.now(), opts.DryRun)
	// Rows before the VACUUM, so the pages those deletes free are on the
	// freelist by the time the VACUUM decides whether the file is worth
	// rewriting — and are reclaimed by the same pass rather than the next one.
	pruneRowTables(opts, pol, rep)
	// Re-measure: `before` was taken before the row prunes, and the VACUUM
	// thresholds are read off the freelist those prunes just grew. Using the
	// stale reading would make a pass that freed a gigabyte of pages decline to
	// reclaim it, which is the exact ordering bug this step exists to fix.
	if !opts.DryRun && rep.BytesReleased() > 0 {
		if after, err := diskusage.Measure(opts.WorkDir); err == nil {
			before = after
		}
	}
	rep.Vacuum = maybeVacuum(opts, pol, before)

	if !opts.DryRun {
		if after, err := diskusage.Measure(opts.WorkDir); err == nil {
			rep.After = after
		}
	}
	rep.Duration = opts.now().Sub(start)
	return rep, nil
}

// archiveDir is where auditretention writes sealed prefixes by default.
func archiveDir(workDir string) string {
	return filepath.Join(workDir, ".cloop", "audit-archive")
}

// resolveArchiveDir picks the directory holding sealed audit exports: the
// operator's audit.export_dir when set, otherwise auditretention's default
// beneath .cloop. Mirrors cmd/hub_audit_cmd.go's resolveAuditExportDir so the
// janitor prunes the same files `cloop hub audit prune` writes.
func resolveArchiveDir(workDir string, pol Policy) string {
	if pol.ArchiveDir != "" {
		return pol.ArchiveDir
	}
	return archiveDir(workDir)
}

// StampPath is where the hub records the completion time of the last pass, so
// the daily cadence survives a restart and `cloop hub doctor` can report it.
//
// A file rather than a row in state.db, and deliberately: the janitor has to
// work on a project whose database is the thing that is broken. The stamp is
// advisory — losing it costs one extra pass, which is idempotent and cheap.
func StampPath(workDir string) string {
	return filepath.Join(workDir, ".cloop", "retention-last-run")
}

// LastRun reports when the last pass completed. ok is false when no pass has
// been recorded, which is not an error: it is what a hub that has just started
// for the first time looks like.
func LastRun(workDir string) (t time.Time, ok bool) {
	fi, err := os.Stat(StampPath(workDir))
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// MarkRun records that a pass just completed. Best-effort by contract: a
// failure here means the next sweep repeats the pass, which is harmless, and
// must not be mistaken for the pass itself having failed.
func MarkRun(workDir string, now time.Time) error {
	path := StampPath(workDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("janitor: record run stamp: %w", err)
	}
	if err := os.WriteFile(path, []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return fmt.Errorf("janitor: record run stamp: %w", err)
	}
	// LastRun reads mtime; WriteFile already leaves it at "now", but be
	// explicit rather than depend on that across filesystems.
	if err := os.Chtimes(path, now, now); err != nil {
		return fmt.Errorf("janitor: stamp mtime: %w", err)
	}
	return nil
}

// Due reports whether interval has elapsed since the last recorded pass. No
// stamp means due, so a fresh project is cleaned shortly after the hub starts.
func Due(workDir string, interval time.Duration, now time.Time) bool {
	last, ok := LastRun(workDir)
	if !ok {
		return true
	}
	return now.Sub(last) >= interval
}

func prunePlanHistory(workDir string, keep int, dryRun bool) StepResult {
	if keep <= 0 {
		return StepResult{Reason: "disabled (keep_snapshots is 0)"}
	}
	st, err := pm.PruneSnapshots(workDir, keep, dryRun)
	total := st.Remaining + st.Deleted
	reason := fmt.Sprintf("keeping %d of %d snapshots", keep, total)
	if total == 0 {
		reason = "no plan history"
	}
	res := StepResult{
		Ran:        true,
		Deleted:    st.Deleted,
		BytesFreed: st.BytesFreed,
		Reason:     reason,
	}
	if err != nil {
		res.Err = fmt.Errorf("janitor: prune plan-history: %w", err)
	}
	return res
}

// seal is one file in the archive directory.
type seal struct {
	name    string
	path    string
	size    int64
	modTime time.Time
}

// pruneArchive applies age and size limits to the sealed audit archives.
//
// Age is applied first, then size, and the newest seal is never deleted by
// either. That last rule is a deliberate floor: a size cap smaller than a
// single seal would otherwise empty the directory completely, turning a
// mis-typed limit into total destruction of the archive.
func pruneArchive(dir string, pol Policy, now time.Time, dryRun bool) StepResult {
	if pol.ArchiveMaxBytes <= 0 && pol.ArchiveMaxAgeDays <= 0 {
		return StepResult{Reason: "disabled (no archive size or age limit set)"}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return StepResult{Ran: true, Reason: "no archive directory"}
		}
		return StepResult{Err: fmt.Errorf("janitor: read audit-archive: %w", err)}
	}

	var seals []seal
	var total int64
	for _, e := range entries {
		if e.IsDir() || !isSealName(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		seals = append(seals, seal{name: e.Name(), path: filepath.Join(dir, e.Name()), size: fi.Size(), modTime: fi.ModTime()})
		total += fi.Size()
	}
	if len(seals) <= 1 {
		return StepResult{Ran: true, Reason: fmt.Sprintf("%d seal(s), nothing to prune", len(seals))}
	}

	// Oldest first; the tail of this slice is what we protect.
	sort.Slice(seals, func(i, j int) bool {
		if !seals[i].modTime.Equal(seals[j].modTime) {
			return seals[i].modTime.Before(seals[j].modTime)
		}
		return seals[i].name < seals[j].name
	})

	doomed := map[string]bool{}
	if pol.ArchiveMaxAgeDays > 0 {
		cutoff := now.Add(-time.Duration(pol.ArchiveMaxAgeDays) * 24 * time.Hour)
		for _, s := range seals[:len(seals)-1] { // never the newest
			if s.modTime.Before(cutoff) {
				doomed[s.name] = true
				total -= s.size
			}
		}
	}
	if pol.ArchiveMaxBytes > 0 {
		for _, s := range seals[:len(seals)-1] {
			if total <= pol.ArchiveMaxBytes {
				break
			}
			if doomed[s.name] {
				continue
			}
			doomed[s.name] = true
			total -= s.size
		}
	}

	res := StepResult{Ran: true}
	var firstErr error
	for _, s := range seals {
		if !doomed[s.name] {
			continue
		}
		if !dryRun {
			if err := os.Remove(s.path); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("janitor: remove seal %s: %w", s.name, err)
				}
				continue
			}
		}
		res.Deleted++
		res.BytesFreed += s.size
	}
	res.Err = firstErr
	res.Reason = fmt.Sprintf("%d seal(s) retained, %s remaining", len(seals)-res.Deleted, diskusage.HumanBytes(total))
	return res
}

// isSealName matches the filenames auditretention.Prune writes:
// audit-<first>-<through>-<timestamp>.jsonl[.gz].
//
// Matching a shape rather than deleting every file keeps an operator's notes,
// checksums and unrelated exports out of the janitor's reach. It is a shape,
// not a proof of authorship — a hand-made export named audit-*.jsonl would
// match — so the directory is for seals, and anything else put there should
// not share their naming.
func isSealName(name string) bool {
	if !strings.HasPrefix(name, "audit-") {
		return false
	}
	return strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.gz")
}

// maybeVacuum decides whether the database is wasteful enough to rewrite, and
// rewrites it if so.
func maybeVacuum(opts Options, pol Policy, before *diskusage.Usage) StepResult {
	if pol.VacuumFreeRatio >= 1 {
		return StepResult{Reason: "disabled (vacuum_free_ratio >= 1)"}
	}
	if opts.SkipVacuum {
		reason := opts.SkipVacuumReason
		if reason == "" {
			reason = "suppressed by caller"
		}
		return StepResult{Skipped: true, Reason: reason}
	}
	dbPath := filepath.Join(opts.WorkDir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); err != nil {
		// Absent is a normal state (a project that has never run); anything
		// else is a real problem an operator should see rather than have
		// paraphrased as "no database".
		if os.IsNotExist(err) {
			return StepResult{Reason: "no state.db"}
		}
		return StepResult{Err: fmt.Errorf("janitor: stat state.db: %w", err)}
	}
	if before != nil && before.DBError != "" {
		return StepResult{Reason: "database statistics unavailable: " + before.DBError}
	}
	if before == nil || before.DBBytes == 0 {
		return StepResult{Reason: "database statistics unavailable"}
	}

	reclaimable, ratio := before.ReclaimableBytes, before.FreeRatio
	pct := ratio * 100
	switch {
	case reclaimable < pol.VacuumMinFreeBytes:
		return StepResult{
			Skipped: true,
			Reason: fmt.Sprintf("%s reclaimable is below the %s floor",
				diskusage.HumanBytes(reclaimable), diskusage.HumanBytes(pol.VacuumMinFreeBytes)),
		}
	case ratio < pol.VacuumFreeRatio:
		return StepResult{
			Skipped: true,
			Reason:  fmt.Sprintf("freelist is %.0f%% of the file, below the %.0f%% threshold", pct, pol.VacuumFreeRatio*100),
		}
	}

	if err := checkLeaseOwnership(dbPath, opts.InstanceID); err != nil {
		return StepResult{Skipped: true, Reason: err.Error()}
	}

	// An in-process VACUUM competes with the hub's own lease heartbeat for the
	// same write lock. Past a certain size the rewrite outlasts the lease TTL,
	// the hub concludes a peer took the fence, and it stands down — so the
	// ceiling is what keeps the janitor from being an outage. It applies only
	// when there is a lease at stake: InstanceID is set exactly when this pass
	// runs inside the hub that holds it.
	// Same fallback as VacuumHeadroom: page arithmetic sampled while a writer
	// extends the file can put the freelist above the recorded size, and the
	// conservative reading of "I cannot tell how much live data there is" is
	// the whole file — not a negative number that would slip under any
	// ceiling.
	live := before.DBBytes - before.ReclaimableBytes
	if live < 0 {
		live = before.DBBytes
	}
	if opts.InstanceID != "" && pol.VacuumMaxInlineBytes > 0 && live > pol.VacuumMaxInlineBytes {
		return StepResult{
			Skipped: true,
			Reason: fmt.Sprintf("%s of live data exceeds the %s in-process limit; run `cloop hub retention --apply` with the hub stopped",
				diskusage.HumanBytes(live), diskusage.HumanBytes(pol.VacuumMaxInlineBytes)),
		}
	}

	// Free space is checked here, last, and deliberately: the file-level steps
	// above have already run, so this sees the space they just reclaimed
	// rather than the space the pass started with. On the hub that motivated
	// this package, that is the difference between a VACUUM that cannot run
	// and one that can — plan-history pruning released 1.95 GB on a disk that
	// was at 100%.
	//
	// A statfs that fails is not evidence of a full disk; proceed and let
	// SQLite report the real error, as with the lease probe above.
	if free, err := freeBytes(filepath.Dir(dbPath)); err == nil {
		if need := before.VacuumHeadroom(); free < need {
			return StepResult{
				Skipped: true,
				Reason: fmt.Sprintf("only %s free, and a rebuild of this database needs about %s",
					diskusage.HumanBytes(free), diskusage.HumanBytes(need)),
			}
		}
	}

	if opts.DryRun {
		return StepResult{
			Skipped:    true,
			BytesFreed: reclaimable,
			Reason:     fmt.Sprintf("dry run: freelist is %.0f%% of the file, would reclaim %s", pct, diskusage.HumanBytes(reclaimable)),
		}
	}

	// AllowConcurrentHub is correct *because* checkLeaseOwnership just
	// passed. dbmaintain's own guard refuses whenever any hub holds the
	// lease, which for an in-process janitor is always true and always
	// itself; the check above is the same guard with "unless it is me".
	rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{AllowConcurrentHub: true})
	res := StepResult{Ran: true}
	if rep != nil {
		res.BytesFreed = rep.BytesFreed
		res.Reason = fmt.Sprintf("freelist was %.0f%% of the file; %s → %s", pct,
			diskusage.HumanBytes(rep.Before.Bytes), diskusage.HumanBytes(rep.After.Bytes))
	}
	if err != nil {
		res.Err = fmt.Errorf("janitor: vacuum: %w", err)
		// dbmaintain runs VACUUM then ANALYZE and reports which completed. A
		// failed ANALYZE leaves a successfully rewritten file behind, and
		// calling the whole step a failure would hide a multi-gigabyte reclaim
		// that really happened — and, worse, invite an operator to run it
		// again. Ran reflects whether the rewrite occurred, not whether every
		// statement did.
		res.Ran = rep != nil && len(rep.Operations) > 0
		if res.Ran {
			// BytesFreed is only computed after the post-vacuum stats, which a
			// mid-sequence failure skipped. Measure it here so the reclaim is
			// still reported.
			if after, serr := SizeStatsFor(opts.WorkDir); serr == nil && rep.Before.Bytes > after.Bytes {
				res.BytesFreed = rep.Before.Bytes - after.Bytes
			}
			res.Reason = fmt.Sprintf("%s completed; %v", strings.Join(rep.Operations, "+"), err)
		}
	}
	return res
}

// freeBytes is diskusage.FreeBytes behind a seam, so tests can describe a full
// or empty disk instead of inheriting whatever the machine running them
// happens to have. Without it the VACUUM tests pass or fail on the CI runner's
// spare capacity, which is not what they are about.
var freeBytes = diskusage.FreeBytes

// checkLeaseOwnership refuses a VACUUM that would rewrite the file underneath
// another live hub. An instanceID matching the lease holder is permission to
// proceed: that holder is this process.
func checkLeaseOwnership(dbPath, instanceID string) error {
	st, err := hublease.Inspect(hublease.Options{DBPath: dbPath})
	if err != nil {
		// The probe failing is not evidence of a peer, and refusing on it
		// would make the janitor permanently inert on a database whose lease
		// table is unreadable for an unrelated reason. dbmaintain's guard
		// makes the same call for the same reason.
		return nil //nolint:nilerr // deliberately non-fatal; see comment
	}
	if !st.Live {
		return nil
	}
	if instanceID != "" && st.Row.InstanceID == instanceID {
		return nil
	}
	return fmt.Errorf("another hub holds the control-plane lease (%s pid %d)", st.Row.Hostname, st.Row.PID)
}

// SizeStatsFor reads the database's page statistics without a full disk walk.
// Exposed for callers that want the VACUUM threshold inputs alone.
func SizeStatsFor(workDir string) (statedb.SizeStats, error) {
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		return statedb.SizeStats{}, fmt.Errorf("janitor: open state.db: %w", err)
	}
	defer db.Close() //nolint:errcheck // read-only probe
	return db.SizeStats()
}
