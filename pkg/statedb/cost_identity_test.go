package statedb

// Migration 0035/0036 and the per-identity cost accounting they enable
// (Task 20264).
//
// The load-bearing case is upgrade, not fresh install. Every hub that will ever
// run this code already has a state.db with cost rows in it, so the question
// that matters is whether adding a column to a table that has been written to
// since migration 0001 opens cleanly and leaves the existing rows readable and
// intact. A migration that only works on an empty database is a migration that
// works on nobody's.

import (
	"path/filepath"
	"testing"
	"time"
)

// openAt opens a statedb at dir/state.db, running migrations.
func openAt(t *testing.T, dir string) *DB {
	t.Helper()
	db, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// ── the upgrade path ────────────────────────────────────────────────────────

// TestCostIdentityMigrationOpensAnExistingDBWithoutLoss seeds a database at the
// schema *before* 0035, writes cost rows through it, then reopens it with the
// full migration set and asserts every row survived with its numbers intact.
//
// Seeding by running the embedded migrations up to 0034 rather than by
// hand-writing a CREATE TABLE is deliberate: a hand-written schema drifts from
// the real one, and then this test proves an upgrade from a database shape that
// never existed.
func TestCostIdentityMigrationOpensAnExistingDBWithoutLoss(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	embedded, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	// Build the pre-0035 database directly, stopping one migration short of
	// the one under test.
	conn := openRaw(t, path)
	if err := ensureMigrationsTable(conn); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}
	var applied int
	for _, m := range embedded {
		if m.Version >= 35 {
			break
		}
		if err := applyOne(conn, m); err != nil {
			t.Fatalf("seed migration %d: %v", m.Version, err)
		}
		applied = m.Version
	}
	if applied < 34 {
		t.Fatalf("seeded only up to migration %d; this test needs the pre-0035 schema", applied)
	}

	// Write cost rows the old way — no identity column exists yet, so this is
	// exactly the INSERT the previous binary issued.
	seeded := []struct {
		ts    string
		task  int
		title string
		in    int
		out   int
		usd   float64
	}{
		{"2026-09-10T08:00:00Z", 1, "older work", 1000, 200, 0.25},
		{"2026-09-11T09:30:00Z", 2, "more work", 4000, 900, 1.50},
	}
	for _, s := range seeded {
		if _, err := conn.Exec(`
			INSERT INTO costs(timestamp, task_id, task_title, provider, model,
				input_tokens, output_tokens, thinking_tokens, estimated_usd)
			VALUES(?,?,?,?,?,?,?,?,?)`,
			s.ts, s.task, s.title, "anthropic", "claude", s.in, s.out, 0, s.usd,
		); err != nil {
			t.Fatalf("seed cost row: %v", err)
		}
	}
	_ = conn.Close()

	// The upgrade itself: the same file, opened by this binary.
	db := openAt(t, dir)

	rows, err := db.ReadCosts()
	if err != nil {
		t.Fatalf("ReadCosts after migration: %v", err)
	}
	if len(rows) != len(seeded) {
		t.Fatalf("read %d cost rows after migration, want %d — the upgrade lost data",
			len(rows), len(seeded))
	}
	for i, got := range rows {
		want := seeded[i]
		if got.TaskID != want.task || got.TaskTitle != want.title {
			t.Errorf("row %d = task %d %q, want task %d %q",
				i, got.TaskID, got.TaskTitle, want.task, want.title)
		}
		if got.InputTokens != want.in || got.OutputTokens != want.out {
			t.Errorf("row %d tokens = %d/%d, want %d/%d",
				i, got.InputTokens, got.OutputTokens, want.in, want.out)
		}
		if got.EstimatedUSD != want.usd {
			t.Errorf("row %d usd = %v, want %v", i, got.EstimatedUSD, want.usd)
		}
		// Pre-existing rows are unattributed, not "local". Inventing an owner
		// for history would put spend on a name that cannot be shown to have
		// incurred it.
		if got.Identity != "" {
			t.Errorf("row %d identity = %q, want empty — the migration invented an owner",
				i, got.Identity)
		}
		if got.RowID == 0 {
			t.Errorf("row %d has no RowID; the drain watermark depends on it", i)
		}
	}

	// And the new column is usable on the upgraded database, not merely
	// present: an upgrade that opens but cannot be written to is not an
	// upgrade anyone can use.
	if err := db.AppendCost(CostEntry{
		Timestamp: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		TaskID:    3, TaskTitle: "attributed work", Provider: "anthropic",
		Model: "claude", InputTokens: 100, OutputTokens: 50, EstimatedUSD: 0.10,
		Identity: "alice@example.com",
	}); err != nil {
		t.Fatalf("AppendCost on the upgraded database: %v", err)
	}
	spend, err := db.SpendByIdentity(time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("SpendByIdentity: %v", err)
	}
	byID := map[string]IdentitySpend{}
	for _, s := range spend {
		byID[s.Identity] = s
	}
	if got := byID["alice@example.com"]; got.Entries != 1 || got.EstimatedUSD != 0.10 {
		t.Errorf("alice = %+v, want 1 entry at $0.10", got)
	}
	if got := byID[""]; got.Entries != 2 {
		t.Errorf("unattributed = %d entries, want the 2 pre-migration rows", got.Entries)
	}
}

// ── aggregation ─────────────────────────────────────────────────────────────

// TestSpendByIdentityWindowsOnUTCBoundaries checks the query the report and the
// budget both read through. The window has to line up with the quota enforcer's
// UTC day bucket, or a tenant sees a figure under their cap while being refused
// against it.
func TestSpendByIdentityWindowsOnUTCBoundaries(t *testing.T) {
	db := openAt(t, t.TempDir())

	midnight := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	write := func(ts time.Time, identity string, tokens int, usd float64) {
		t.Helper()
		if err := db.AppendCost(CostEntry{
			Timestamp: ts, TaskID: 1, Provider: "anthropic", Model: "claude",
			InputTokens: tokens, EstimatedUSD: usd, Identity: identity,
		}); err != nil {
			t.Fatalf("AppendCost: %v", err)
		}
	}

	// One second before the boundary, and one second after.
	write(midnight.Add(-time.Second), "alice@example.com", 500, 5.00)
	write(midnight.Add(time.Second), "alice@example.com", 100, 1.00)
	write(midnight.Add(time.Hour), "bob@example.com", 300, 3.00)

	today, err := db.SpendByIdentity(midnight, time.Time{})
	if err != nil {
		t.Fatalf("SpendByIdentity: %v", err)
	}
	got := map[string]IdentitySpend{}
	for _, s := range today {
		got[s.Identity] = s
	}
	if a := got["alice@example.com"]; a.InputTokens != 100 || a.EstimatedUSD != 1.00 {
		t.Errorf("alice today = %d tokens/$%.2f, want 100/$1.00 — yesterday's spend leaked in",
			a.InputTokens, a.EstimatedUSD)
	}
	if b := got["bob@example.com"]; b.InputTokens != 300 {
		t.Errorf("bob today = %d tokens, want 300", b.InputTokens)
	}

	// An open window sees everything, including the row before midnight.
	all, err := db.SpendByIdentity(time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("SpendByIdentity(all): %v", err)
	}
	var total int
	for _, s := range all {
		total += s.InputTokens
	}
	if total != 900 {
		t.Errorf("all-time tokens = %d, want 900", total)
	}
}

// ── the drain watermark ─────────────────────────────────────────────────────

// TestOnlyOneDrainerClaimsABatch is the property that stops a tenant being
// billed twice for one task.
//
// Two hub processes share one control-plane database in this deployment, and
// both can read the same cursor before either advances it. A merely monotonic
// update would not help: both would have already charged the rows by the time
// the second write was rejected. The compare-and-swap is what makes exactly one
// of them the booker, and the caller books only when it won.
func TestOnlyOneDrainerClaimsABatch(t *testing.T) {
	db := openAt(t, t.TempDir())

	const project = "/srv/projects/api"
	if err := db.OpenSpendCursor(project, "alice@example.com", 10); err != nil {
		t.Fatalf("OpenSpendCursor: %v", err)
	}

	// Both drainers observed cursor=10 and read rows 11..42.
	won, err := db.AdvanceSpendCursor(project, 10, 42)
	if err != nil {
		t.Fatalf("AdvanceSpendCursor: %v", err)
	}
	if !won {
		t.Fatal("the first claim on an unclaimed batch lost")
	}

	// The second arrives with the same stale `from` and must lose, so its
	// caller books nothing.
	won, err = db.AdvanceSpendCursor(project, 10, 42)
	if err != nil {
		t.Fatalf("AdvanceSpendCursor(second): %v", err)
	}
	if won {
		t.Fatal("two drainers both claimed one batch — the tenant is billed twice")
	}

	// A rewind cannot win either.
	if won, err := db.AdvanceSpendCursor(project, 42, 20); err != nil || won {
		t.Errorf("a backwards claim won (won=%v err=%v)", won, err)
	}

	cur, ok, err := db.LoadSpendCursor(project)
	if err != nil || !ok {
		t.Fatalf("LoadSpendCursor: ok=%v err=%v", ok, err)
	}
	if cur.LastCostRowID != 42 {
		t.Errorf("cursor is at %d, want 42", cur.LastCostRowID)
	}
	if cur.Identity != "alice@example.com" {
		t.Errorf("cursor identity = %q, want alice@example.com", cur.Identity)
	}
}

// TestSpendCursorSeedsAtLedgerEndForANewRun: a hub adopting a project that
// already has history must charge the next run for what it spends, not for
// everything that was there when it arrived.
func TestSpendCursorSeedsAtLedgerEndForANewRun(t *testing.T) {
	dir := t.TempDir()
	db := openAt(t, dir)

	for i := 0; i < 3; i++ {
		if err := db.AppendCost(CostEntry{
			Timestamp: time.Now().UTC(), TaskID: i, Provider: "anthropic",
			Model: "claude", InputTokens: 1000, EstimatedUSD: 1.00,
			Identity: "previous@example.com",
		}); err != nil {
			t.Fatalf("AppendCost: %v", err)
		}
	}
	maxID, err := db.MaxCostRowID()
	if err != nil {
		t.Fatalf("MaxCostRowID: %v", err)
	}
	if maxID != 3 {
		t.Fatalf("MaxCostRowID = %d, want 3", maxID)
	}

	if err := db.OpenSpendCursor(dir, "newcomer@example.com", maxID); err != nil {
		t.Fatalf("OpenSpendCursor: %v", err)
	}
	unbooked, err := db.ReadCostsAfterID(maxID, 100)
	if err != nil {
		t.Fatalf("ReadCostsAfterID: %v", err)
	}
	if len(unbooked) != 0 {
		t.Fatalf("a freshly seeded cursor sees %d unbooked rows; the newcomer "+
			"would be charged for the previous tenant's history", len(unbooked))
	}

	// The next task's row is the first thing it does see.
	if err := db.AppendCost(CostEntry{
		Timestamp: time.Now().UTC(), TaskID: 9, Provider: "anthropic",
		Model: "claude", InputTokens: 7, EstimatedUSD: 0.07,
		Identity: "newcomer@example.com",
	}); err != nil {
		t.Fatalf("AppendCost: %v", err)
	}
	unbooked, err = db.ReadCostsAfterID(maxID, 100)
	if err != nil {
		t.Fatalf("ReadCostsAfterID: %v", err)
	}
	if len(unbooked) != 1 || unbooked[0].InputTokens != 7 {
		t.Fatalf("after one new task the drain sees %d rows, want exactly the new one", len(unbooked))
	}
}
