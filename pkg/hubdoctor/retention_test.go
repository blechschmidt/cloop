package hubdoctor

// Tests for the row-table retention finding (Task 20291).
//
// The finding exists because no other surface can answer the question. `du`
// sees one state.db; the freelist finding sees how much of it is dead; neither
// can say that 14% of the live data is a few hundred provider-call rows
// carrying whole LLM prompts, which is what measuring this project's own
// control plane actually found.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/janitor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// collect runs checkRetentionTables and returns the findings it emitted.
func collect(dir string, pol janitor.Policy) []Finding {
	var out []Finding
	checkRetentionTables(dir, pol, func(f Finding) { out = append(out, f) })
	return out
}

func tablesFinding(t *testing.T, found []Finding) Finding {
	t.Helper()
	for _, f := range found {
		if f.Check == "retention.tables" {
			return f
		}
	}
	t.Fatalf("no retention.tables finding in %+v", found)
	return Finding{}
}

// seedRows puts a known number of rows in two of the covered tables, so the
// finding has something to count.
func seedRows(t *testing.T, dir string, n int) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close() //nolint:errcheck
	for i := 0; i < n; i++ {
		if err := db.RecordEvent(statedb.EventRow{
			Timestamp: time.Now(), Type: "task_started", TaskID: i + 1, Step: -1,
		}); err != nil {
			t.Fatalf("RecordEvent: %v", err)
		}
		if _, err := db.AppendProviderCall(statedb.ProviderCallRow{
			Timestamp: time.Now(), Provider: "anthropic", Model: "claude-opus-4-8",
			Prompt: strings.Repeat("p", 2048), Status: "ok",
		}); err != nil {
			t.Fatalf("AppendProviderCall: %v", err)
		}
	}
}

func TestCheckRetentionTables_ReportsRowCounts(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	seedRows(t, dir, 6)

	f := tablesFinding(t, collect(dir, janitor.DefaultPolicy()))
	if f.Severity != SeverityPass {
		t.Errorf("Severity = %v, want pass under the default policy: %s", f.Severity, f.Message)
	}
	// Per-table counts are the substance of the finding, not the total.
	for _, table := range statedb.GrowthTables() {
		if _, ok := f.Details[table]; !ok {
			t.Errorf("finding does not report %s: %+v", table, f.Details)
		}
	}
	if got := f.Details["events"]; !strings.HasPrefix(got.(string), "6 rows") {
		t.Errorf("events detail = %q, want it to start with 6 rows", got)
	}
	if !strings.Contains(f.Message, "all bounded") {
		t.Errorf("Message = %q, want it to say the tables are bounded", f.Message)
	}
}

// TestCheckRetentionTables_NamesUnboundedTables is the point of the check: a
// table an operator exempted is invisible until it is the reason a disk filled,
// so the exemption is reported with the table's current size attached.
func TestCheckRetentionTables_NamesUnboundedTables(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	seedRows(t, dir, 3)

	pol := janitor.DefaultPolicy()
	pol.StepMaxRows = -1 // the documented opt-out
	pol.CostMaxRows = -1

	f := tablesFinding(t, collect(dir, pol))
	if f.Severity != SeverityWarn {
		t.Errorf("Severity = %v, want warn", f.Severity)
	}
	for _, want := range []string{"steps", "costs"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("Message = %q, want it to name %s", f.Message, want)
		}
	}
	if strings.Contains(f.Message, "events") {
		t.Errorf("Message = %q names a table that is bounded", f.Message)
	}
	if f.Remediation == "" {
		t.Error("an unbounded table must come with a remediation")
	}
	unbounded, ok := f.Details["unbounded"].([]string)
	if !ok || len(unbounded) != 2 {
		t.Errorf("Details[unbounded] = %v, want two table names", f.Details["unbounded"])
	}
}

// TestCheckRetentionTables_DisabledJanitorBoundsNothing covers the whole-policy
// opt-out: with no pass running, every table is unbounded regardless of the
// limits configured for it.
func TestCheckRetentionTables_DisabledJanitorBoundsNothing(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)

	pol := janitor.DefaultPolicy()
	pol.Enabled = false

	f := tablesFinding(t, collect(dir, pol))
	if f.Severity != SeverityWarn {
		t.Errorf("Severity = %v, want warn", f.Severity)
	}
	// It must not repeat "turn the janitor back on" per table — the janitor's
	// own finding already says that once.
	if !strings.Contains(f.Remediation, "Re-enable") {
		t.Errorf("Remediation = %q, want it to point at the janitor itself", f.Remediation)
	}
}

// TestCheckRetentionTables_NoDatabaseIsSilent covers a project that has never
// run: nothing to report is not a finding.
func TestCheckRetentionTables_NoDatabaseIsSilent(t *testing.T) {
	dir := t.TempDir()
	if found := collect(dir, janitor.DefaultPolicy()); len(found) != 0 {
		t.Errorf("a project with no state.db produced %d findings: %+v", len(found), found)
	}
}

// TestCheckRetention_IncludesTheTables wires the check into the section the
// hub doctor actually calls, so a future refactor that drops the call is caught
// here rather than by an operator with a full disk.
func TestCheckRetention_IncludesTheTables(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)

	var checks []string
	checkRetention(dir, &config.Config{}, func(f Finding) { checks = append(checks, f.Check) })

	var found bool
	for _, c := range checks {
		if c == "retention.tables" {
			found = true
		}
	}
	if !found {
		t.Errorf("checkRetention emitted %v, with no retention.tables", checks)
	}
}
