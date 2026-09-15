package janitor

// Tests for the row-retention steps added in Task 20291.
//
// The statedb tests cover the prune primitives; these cover the janitor's
// contract around them — that a pass bounds every row table, that a dry run
// deletes nothing, that a live run protects the one table a live run rewrites,
// and that row bytes are reported separately from bytes actually returned to
// the filesystem.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedRowTables fills the four per-run tables of a project's state.db.
// providerBodyKB sizes each recorded prompt; providerAge is how far back the
// oldest provider call sits.
func seedRowTables(t *testing.T, workDir string, rows int, providerBodyKB int, providerAge time.Duration) {
	t.Helper()
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close() //nolint:errcheck

	body := strings.Repeat("p", providerBodyKB*1024)
	for i := 0; i < rows; i++ {
		if err := db.AppendStep(statedb.StepRow{
			Step: i + 1, Task: "fixture", Output: strings.Repeat("o", 512),
			Duration: "1s", Time: time.Now().Add(-time.Duration(rows-i) * time.Minute),
		}); err != nil {
			t.Fatalf("AppendStep %d: %v", i, err)
		}
		if err := db.RecordEvent(statedb.EventRow{
			Timestamp: time.Now().Add(-time.Duration(rows-i) * time.Minute),
			Type:      "task_started", TaskID: i + 1, Step: -1, Message: "seeded",
		}); err != nil {
			t.Fatalf("RecordEvent %d: %v", i, err)
		}
		if err := db.AppendCost(statedb.CostEntry{
			Timestamp: time.Now().Add(-time.Duration(rows-i) * time.Minute),
			TaskID:    i + 1, Provider: "anthropic", Model: "claude-opus-4-8",
			InputTokens: 10, OutputTokens: 5, EstimatedUSD: 0.01,
		}); err != nil {
			t.Fatalf("AppendCost %d: %v", i, err)
		}
		if _, err := db.AppendProviderCall(statedb.ProviderCallRow{
			Timestamp: time.Now().Add(-providerAge - time.Duration(rows-i)*time.Minute),
			Provider:  "anthropic", Model: "claude-opus-4-8", TaskID: i + 1,
			Prompt: body, Response: "ok", Status: "ok", Headers: `{"max_tokens":4096}`,
			InputTokens: 100, OutputTokens: 7, LatencyMs: 1234,
		}); err != nil {
			t.Fatalf("AppendProviderCall %d: %v", i, err)
		}
	}
}

// tableRows reads one table's current row count through the public stats path.
func tableRows(t *testing.T, workDir, table string) int64 {
	t.Helper()
	stats, err := RowTableStats(workDir)
	if err != nil {
		t.Fatalf("RowTableStats: %v", err)
	}
	for _, s := range stats {
		if s.Name == table {
			return s.Rows
		}
	}
	t.Fatalf("%s missing from RowTableStats", table)
	return 0
}

// rowPolicy is a policy with tight row limits and everything file-level off, so
// a test asserts only the steps it is about.
func rowPolicy(maxRows int, bodyAge time.Duration) Policy {
	p := DefaultPolicy()
	p.KeepSnapshots = 0   // no plan history in these fixtures
	p.VacuumFreeRatio = 1 // never vacuum: these tests are about rows
	p.ProviderCallMaxRows = maxRows
	p.StepMaxRows = maxRows
	p.EventMaxRows = maxRows
	p.CostMaxRows = maxRows
	p.ProviderCallBodyMaxAge = bodyAge
	return p
}

// ─── spec-required: a pass bounds each row table ─────────────────────────────

// TestRunOnce_BoundsEachRowTable is the counterpart to
// TestRunOnce_BoundsEachDirectory: a pass must leave every row table within its
// ceiling, from a project seeded well past every one of them.
func TestRunOnce_BoundsEachRowTable(t *testing.T) {
	dir := newProject(t)
	seedRowTables(t, dir, 40, 4, 90*24*time.Hour)

	const keep = 10
	rep, err := RunOnce(Options{WorkDir: dir, Policy: rowPolicy(keep, 30*24*time.Hour)})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	for _, e := range rep.Errs() {
		t.Fatalf("step error: %v", e)
	}

	for _, table := range []string{"provider_calls", "steps", "events", "costs"} {
		if got := tableRows(t, dir, table); got != keep {
			t.Errorf("%s has %d rows after a pass, want %d", table, got, keep)
		}
	}

	steps := map[string]StepResult{
		"provider_calls": rep.ProviderCalls,
		"steps":          rep.Steps,
		"events":         rep.Events,
		"costs":          rep.Costs,
	}
	for name, res := range steps {
		if !res.Ran {
			t.Errorf("%s step did not run: %s", name, res.Reason)
		}
		if res.Deleted != 30 {
			t.Errorf("%s step deleted %d rows, want 30", name, res.Deleted)
		}
	}

	// The bodies went too, and they are the bulk of what was released.
	if rep.ProviderCalls.BytesReleased < 30*4*1024 {
		t.Errorf("provider-call step released %d bytes, want at least %d",
			rep.ProviderCalls.BytesReleased, 30*4*1024)
	}
}

// TestRunOnce_RowBytesAreNotCountedAsReclaimed pins the distinction the report
// makes between a page freed inside the file and a byte returned to the
// filesystem. Summing both would tell an operator the same space was recovered
// twice.
func TestRunOnce_RowBytesAreNotCountedAsReclaimed(t *testing.T) {
	dir := newProject(t)
	seedRowTables(t, dir, 30, 8, 90*24*time.Hour)

	rep, err := RunOnce(Options{WorkDir: dir, Policy: rowPolicy(5, 30*24*time.Hour)})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.BytesReleased() <= 0 {
		t.Fatalf("BytesReleased = %d, want > 0", rep.BytesReleased())
	}
	// VacuumFreeRatio is 1 in rowPolicy, so nothing was returned to the disk.
	if rep.BytesFreed() != 0 {
		t.Errorf("BytesFreed = %d, want 0 — no file was deleted and no VACUUM ran",
			rep.BytesFreed())
	}
	if !strings.Contains(rep.Summary(), "freelist") {
		t.Errorf("Summary must say where the bytes went, got %q", rep.Summary())
	}
}

// ─── spec-required: dry run ──────────────────────────────────────────────────

// TestRunOnce_DryRunDeletesNoRows is the spec-required dry-run test: a preview
// pass reports what would go and changes nothing.
func TestRunOnce_DryRunDeletesNoRows(t *testing.T) {
	dir := newProject(t)
	seedRowTables(t, dir, 30, 4, 90*24*time.Hour)

	before := map[string]int64{}
	for _, table := range statedb.GrowthTables() {
		before[table] = tableRows(t, dir, table)
	}

	rep, err := RunOnce(Options{WorkDir: dir, Policy: rowPolicy(5, 30*24*time.Hour), DryRun: true})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	for _, e := range rep.Errs() {
		t.Fatalf("step error: %v", e)
	}

	// It still has to say what it would do, or it is useless for previewing.
	if rep.RowsDeleted() != 4*25 {
		t.Errorf("dry run reported %d rows, want %d", rep.RowsDeleted(), 4*25)
	}
	for _, table := range statedb.GrowthTables() {
		if got := tableRows(t, dir, table); got != before[table] {
			t.Errorf("dry run changed %s: %d rows, want %d", table, got, before[table])
		}
	}

	// And it must not have stripped any bodies either — a dry run that quietly
	// destroyed the prompts while leaving the rows would be the worst of both.
	dbPath := filepath.Join(dir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close() //nolint:errcheck
	row, err := db.LoadProviderCall(1)
	if err != nil {
		t.Fatalf("LoadProviderCall: %v", err)
	}
	if len(row.Prompt) != 4*1024 {
		t.Errorf("dry run stripped a body: prompt is %d bytes, want %d", len(row.Prompt), 4*1024)
	}
}

// ─── a live run protects its own step history ────────────────────────────────

// TestRunOnce_SkipsStepPruneWhileARunIsActive covers the one row table that is
// not append-only. A running orchestrator holds every step in memory and
// upserts all of them on each save, so pruning underneath it achieves nothing
// and races the writer while failing to.
func TestRunOnce_SkipsStepPruneWhileARunIsActive(t *testing.T) {
	dir := newProject(t)
	seedRowTables(t, dir, 30, 1, 0)

	rep, err := RunOnce(Options{
		WorkDir:         dir,
		Policy:          rowPolicy(5, 0),
		RunActive:       true,
		RunActiveReason: "a task is running",
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if !rep.Steps.Skipped {
		t.Errorf("steps step was not skipped: ran=%v reason=%q", rep.Steps.Ran, rep.Steps.Reason)
	}
	if rep.Steps.Deleted != 0 {
		t.Errorf("steps step deleted %d rows while a run was active", rep.Steps.Deleted)
	}
	if !strings.Contains(rep.Steps.Reason, "a task is running") {
		t.Errorf("skip reason should name the cause, got %q", rep.Steps.Reason)
	}
	if got := tableRows(t, dir, "steps"); got != 30 {
		t.Errorf("steps has %d rows, want 30 untouched", got)
	}

	// Everything else is append-only and must still have been bounded — a live
	// run is a reason to protect one table, not to skip the pass.
	for _, table := range []string{"provider_calls", "events", "costs"} {
		if got := tableRows(t, dir, table); got != 5 {
			t.Errorf("%s has %d rows, want 5 — an active run must not exempt it", table, got)
		}
	}
}

// ─── body stripping keeps the row ────────────────────────────────────────────

// TestRunOnce_StripsBodiesButKeepsProviderCallRows covers the case the design
// exists for: bodies aged out while the rows, and everything the inspector list
// reads from them, stay.
func TestRunOnce_StripsBodiesButKeepsProviderCallRows(t *testing.T) {
	dir := newProject(t)
	seedRowTables(t, dir, 10, 16, 60*24*time.Hour)

	pol := rowPolicy(0, 30*24*time.Hour) // no row ceilings, bodies only
	pol.ProviderCallMaxRows = -1
	pol.StepMaxRows = -1
	pol.EventMaxRows = -1
	pol.CostMaxRows = -1

	rep, err := RunOnce(Options{WorkDir: dir, Policy: pol})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.ProviderCalls.Deleted != 0 {
		t.Errorf("deleted %d rows, want 0 — only the bodies were meant to go", rep.ProviderCalls.Deleted)
	}
	if got := tableRows(t, dir, "provider_calls"); got != 10 {
		t.Errorf("provider_calls has %d rows, want 10", got)
	}
	if rep.ProviderCalls.BytesReleased < 10*16*1024 {
		t.Errorf("released %d bytes, want at least %d", rep.ProviderCalls.BytesReleased, 10*16*1024)
	}
	if !strings.Contains(rep.ProviderCalls.Reason, "stripped") {
		t.Errorf("reason should say what happened, got %q", rep.ProviderCalls.Reason)
	}

	// A negative limit is the documented opt-out, and the other tables must
	// have honoured it rather than falling back to a default.
	for _, table := range []string{"steps", "events", "costs"} {
		if got := tableRows(t, dir, table); got != 10 {
			t.Errorf("%s has %d rows, want 10 — a limit of -1 keeps everything", table, got)
		}
	}
}

// ─── policy plumbing ─────────────────────────────────────────────────────────

func TestPolicyFromConfig_RowLimits(t *testing.T) {
	cfg := &config.Config{}
	cfg.Retention.ProviderCallBodyAgeDays = 7
	cfg.Retention.ProviderCallMaxRows = 500
	cfg.Retention.StepMaxRows = config.RetentionKeepEverything
	cfg.Retention.EventMaxRows = 1500
	cfg.Retention.CostMaxRows = 2500
	cfg.Retention.TelemetryMaxAgeDays = config.RetentionKeepEverything

	pol := PolicyFromConfig(cfg).normalise()

	if pol.ProviderCallBodyMaxAge != 7*24*time.Hour {
		t.Errorf("ProviderCallBodyMaxAge = %s, want 168h", pol.ProviderCallBodyMaxAge)
	}
	if pol.ProviderCallMaxRows != 500 {
		t.Errorf("ProviderCallMaxRows = %d, want 500", pol.ProviderCallMaxRows)
	}
	// -1 in config has to survive into "no limit", not fall back to the
	// default. Getting this backwards would silently prune a table an operator
	// explicitly exempted.
	if pol.StepMaxRows != 0 {
		t.Errorf("StepMaxRows = %d, want 0 (keep everything)", pol.StepMaxRows)
	}
	if pol.TelemetryMaxAge != 0 {
		t.Errorf("TelemetryMaxAge = %s, want 0 (keep everything)", pol.TelemetryMaxAge)
	}
	if pol.EventMaxRows != 1500 || pol.CostMaxRows != 2500 {
		t.Errorf("EventMaxRows/CostMaxRows = %d/%d, want 1500/2500", pol.EventMaxRows, pol.CostMaxRows)
	}
}

// TestDefaultPolicyBoundsEveryRowTable is the guard against a table being added
// to statedb.GrowthTables with no policy behind it: the default install must
// bound all of them.
func TestDefaultPolicyBoundsEveryRowTable(t *testing.T) {
	pol := DefaultPolicy()
	for _, table := range statedb.GrowthTables() {
		if !TableBounded(pol, table) {
			t.Errorf("%s is unbounded under the default policy", table)
		}
	}
	// And a disabled janitor bounds nothing, which is what the hub doctor
	// reports.
	pol.Enabled = false
	for _, table := range statedb.GrowthTables() {
		if TableBounded(pol, table) {
			t.Errorf("%s reported bounded with the janitor disabled", table)
		}
	}
}

func TestTableBoundedRejectsUnknownTables(t *testing.T) {
	if TableBounded(DefaultPolicy(), "audit_events") {
		t.Error("an unknown table must report unbounded, so a new one shows up in the doctor")
	}
}

// TestRunOnce_NoDatabaseIsNotAnError covers a project that has never run: the
// row steps report why they did nothing rather than failing the pass.
func TestRunOnce_NoDatabaseIsNotAnError(t *testing.T) {
	dir := newProject(t)

	rep, err := RunOnce(Options{WorkDir: dir, Policy: rowPolicy(10, time.Hour)})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if errs := rep.Errs(); len(errs) > 0 {
		t.Fatalf("a project with no state.db produced errors: %v", errs)
	}
	for name, res := range map[string]StepResult{
		"provider_calls": rep.ProviderCalls, "steps": rep.Steps,
		"events": rep.Events, "costs": rep.Costs, "telemetry": rep.Telemetry,
	} {
		if res.Ran {
			t.Errorf("%s ran without a database", name)
		}
		if res.Reason == "" {
			t.Errorf("%s gave no reason for doing nothing", name)
		}
	}
}

// TestRunOnce_RowLimitsOffReportsDisabled covers the fully opted-out policy:
// every step says so rather than silently reporting success.
func TestRunOnce_RowLimitsOffReportsDisabled(t *testing.T) {
	dir := newProject(t)
	seedRowTables(t, dir, 5, 1, 0)

	pol := DefaultPolicy()
	pol.KeepSnapshots = 0
	pol.VacuumFreeRatio = 1
	pol.ProviderCallBodyMaxAge = -1
	pol.ProviderCallMaxRows = -1
	pol.StepMaxRows = -1
	pol.EventMaxRows = -1
	pol.CostMaxRows = -1
	pol.TelemetryMaxAge = -1

	rep, err := RunOnce(Options{WorkDir: dir, Policy: pol})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.RowsDeleted() != 0 {
		t.Errorf("deleted %d rows under a fully disabled policy", rep.RowsDeleted())
	}
	for name, res := range map[string]StepResult{
		"provider_calls": rep.ProviderCalls, "steps": rep.Steps,
		"events": rep.Events, "costs": rep.Costs, "telemetry": rep.Telemetry,
	} {
		if !strings.Contains(res.Reason, "disabled") {
			t.Errorf("%s reason = %q, want it to say disabled", name, res.Reason)
		}
	}
	if got := tableRows(t, dir, "steps"); got != 5 {
		t.Errorf("steps has %d rows, want 5", got)
	}
}

// TestRunOnce_RowPruneFeedsTheVacuum is the ordering claim: the pages the row
// prune frees are visible to the VACUUM decision in the same pass, not the next
// one. Without the re-measure between the two steps, a pass that released a
// large fraction of the file would still read the pre-prune freelist and
// decline to reclaim what it had just created.
func TestRunOnce_RowPruneFeedsTheVacuum(t *testing.T) {
	dir := newProject(t)
	// Enough body text that deleting it crosses the vacuum threshold.
	seedRowTables(t, dir, 60, 64, 90*24*time.Hour)
	withFreeSpace(t, plentyOfSpace)

	dbPath := filepath.Join(dir, ".cloop", "state.db")
	sizeBefore := mustSize(t, dbPath)

	pol := rowPolicy(5, 30*24*time.Hour)
	pol.VacuumFreeRatio = DefaultVacuumFreeRatio
	pol.VacuumMinFreeBytes = 1 // any freelist worth having, on a small fixture

	rep, err := RunOnce(Options{WorkDir: dir, Policy: pol})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	for _, e := range rep.Errs() {
		t.Fatalf("step error: %v", e)
	}
	if !rep.Vacuum.Ran {
		t.Fatalf("VACUUM did not run after %s was released: %s",
			fmt.Sprint(rep.BytesReleased()), rep.Vacuum.Reason)
	}
	if sizeAfter := mustSize(t, dbPath); sizeAfter >= sizeBefore {
		t.Errorf("state.db is %d bytes, was %d — the pass reclaimed nothing", sizeAfter, sizeBefore)
	}
}
