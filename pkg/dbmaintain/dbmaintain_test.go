package dbmaintain_test

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/dbmaintain"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fillSteps inserts n step rows of payloadKB KB each so the DB grows
// substantially. Returns nothing — failures fail the test.
func fillSteps(t *testing.T, dbPath string, n, payloadKB int) {
	t.Helper()
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	payload := strings.Repeat("x", payloadKB*1024)
	for i := 0; i < n; i++ {
		if err := db.AppendStep(statedb.StepRow{
			Step:     i,
			Task:     "fill",
			Output:   payload,
			Duration: "0s",
			Time:     time.Now(),
		}); err != nil {
			t.Fatalf("AppendStep %d: %v", i, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// rawExec runs SQL through a fresh *sql.DB so the test can mutate the file
// outside the statedb mutex (and force a WAL checkpoint).
func rawExec(t *testing.T, dbPath, query string) {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(query); err != nil {
		t.Fatalf("Exec %q: %v", query, err)
	}
}

func mustSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// TestRun_ShrinksFileSize is the spec-required regression test: a database
// with many deleted rows must measurably shrink after maintain runs.
func TestRun_ShrinksFileSize(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	// Insert 2 MB of step data (2000 rows × 1 KB).
	fillSteps(t, dbPath, 2000, 1)

	// Delete every row, then force a WAL checkpoint so the main DB file
	// reflects the state we want maintain to operate on.
	rawExec(t, dbPath, `DELETE FROM steps`)
	rawExec(t, dbPath, `PRAGMA wal_checkpoint(TRUNCATE)`)

	sizeBefore := mustSize(t, dbPath)

	rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.DryRun {
		t.Errorf("DryRun = true on real run")
	}
	if rep.AutoSkipped {
		t.Errorf("AutoSkipped = true with no Auto flag")
	}
	if len(rep.Operations) < 2 {
		t.Errorf("Operations = %v, want VACUUM + ANALYZE", rep.Operations)
	}

	// Force WAL checkpoint again so the post-VACUUM size is observable.
	rawExec(t, dbPath, `PRAGMA wal_checkpoint(TRUNCATE)`)
	sizeAfter := mustSize(t, dbPath)

	if sizeAfter >= sizeBefore {
		t.Errorf("expected file to shrink: before=%d after=%d", sizeBefore, sizeAfter)
	}
	if rep.BytesFreed <= 0 {
		t.Errorf("BytesFreed = %d, want > 0", rep.BytesFreed)
	}

	// maintenance_log should contain exactly one row matching this run.
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer db.Close()
	last, err := db.LastMaintenanceLog()
	if err != nil {
		t.Fatalf("LastMaintenanceLog: %v", err)
	}
	if last == nil {
		t.Fatalf("expected a maintenance_log row, got nil")
	}
	if last.PageCountBefore <= last.PageCountAfter {
		t.Errorf("page_count_before (%d) should exceed after (%d)",
			last.PageCountBefore, last.PageCountAfter)
	}
	if last.Operation != "vacuum+analyze" {
		t.Errorf("operation = %q, want vacuum+analyze", last.Operation)
	}
}

// TestRun_DryRunDoesNotMutate verifies --dry-run leaves the file untouched
// and never writes a maintenance_log row.
func TestRun_DryRunDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	fillSteps(t, dbPath, 500, 1)
	rawExec(t, dbPath, `DELETE FROM steps`)
	rawExec(t, dbPath, `PRAGMA wal_checkpoint(TRUNCATE)`)

	sizeBefore := mustSize(t, dbPath)

	rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{DryRun: true})
	if err != nil {
		t.Fatalf("Run dry: %v", err)
	}
	if !rep.DryRun {
		t.Errorf("DryRun = false in dry-run run")
	}
	if len(rep.Operations) != 0 {
		t.Errorf("Operations = %v, want empty for dry-run", rep.Operations)
	}
	if rep.EstimatedReclaim <= 0 {
		t.Errorf("EstimatedReclaim = %d, want > 0 (freelist had pages)", rep.EstimatedReclaim)
	}

	rawExec(t, dbPath, `PRAGMA wal_checkpoint(TRUNCATE)`)
	sizeAfter := mustSize(t, dbPath)
	if sizeBefore != sizeAfter {
		t.Errorf("dry-run changed file size: before=%d after=%d", sizeBefore, sizeAfter)
	}

	// No maintenance_log row should have been written.
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer db.Close()
	last, err := db.LastMaintenanceLog()
	if err != nil {
		t.Fatalf("LastMaintenanceLog: %v", err)
	}
	if last != nil {
		t.Errorf("dry-run wrote a maintenance_log row: %+v", last)
	}
}

// TestRun_AutoSkipsBelowThreshold verifies --auto skips the run when the DB
// has not grown enough since the last vacuum.
func TestRun_AutoSkipsBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	fillSteps(t, dbPath, 200, 1)

	// First run: no prior log, so auto must execute.
	rep1, err := dbmaintain.Run(dbPath, dbmaintain.Options{Auto: true})
	if err != nil {
		t.Fatalf("first auto run: %v", err)
	}
	if rep1.AutoSkipped {
		t.Errorf("first auto run skipped; expected to execute (no baseline)")
	}

	// Immediately follow up with another auto run. DB hasn't grown at all
	// since the previous vacuum, so it must skip.
	rep2, err := dbmaintain.Run(dbPath, dbmaintain.Options{Auto: true})
	if err != nil {
		t.Fatalf("second auto run: %v", err)
	}
	if !rep2.AutoSkipped {
		t.Errorf("second auto run executed; expected skip (no growth since last vacuum)")
	}
	if rep2.LastEntry == nil {
		t.Errorf("LastEntry not populated on skipped auto run")
	}
}

// TestRun_AutoRunsAboveThreshold verifies --auto proceeds when the DB has
// grown more than AutoGrowthThreshold since the last vacuum.
func TestRun_AutoRunsAboveThreshold(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	// First vacuum baseline.
	fillSteps(t, dbPath, 50, 1)
	rawExec(t, dbPath, `DELETE FROM steps`)
	if _, err := dbmaintain.Run(dbPath, dbmaintain.Options{}); err != nil {
		t.Fatalf("baseline vacuum: %v", err)
	}

	// Now grow the DB substantially (more than the 20% threshold).
	fillSteps(t, dbPath, 1500, 1)

	rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{Auto: true})
	if err != nil {
		t.Fatalf("auto run after growth: %v", err)
	}
	if rep.AutoSkipped {
		t.Errorf("auto run skipped; DB grew well beyond threshold (reason: %s)", rep.Reason)
	}
	if len(rep.Operations) == 0 {
		t.Errorf("expected operations to run, got none")
	}
}

// TestRun_MissingFile returns an explicit error.
func TestRun_MissingFile(t *testing.T) {
	_, err := dbmaintain.Run(filepath.Join(t.TempDir(), "nope.db"), dbmaintain.Options{})
	if err == nil {
		t.Fatal("expected error for missing DB, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q does not mention not found", err.Error())
	}
}

// TestRun_EmptyPath returns an explicit error.
func TestRun_EmptyPath(t *testing.T) {
	_, err := dbmaintain.Run("", dbmaintain.Options{})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestSizeStats_PreservesNonZero sanity-checks the helper directly so a
// regression in pkg/statedb surfaces here too (cheap and focused).
func TestSizeStats_NonZero(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	s, err := db.SizeStats()
	if err != nil {
		t.Fatalf("SizeStats: %v", err)
	}
	if s.PageSize <= 0 {
		t.Errorf("page_size = %d, want > 0", s.PageSize)
	}
	if s.PageCount <= 0 {
		t.Errorf("page_count = %d, want > 0 after migrations", s.PageCount)
	}
	if s.Bytes != s.PageCount*s.PageSize {
		t.Errorf("Bytes mismatch: %d != %d * %d", s.Bytes, s.PageCount, s.PageSize)
	}
}

// TestLastMaintenanceLog_NilWhenEmpty ensures the helper returns (nil, nil)
// before any maintenance has been recorded — callers depend on this.
func TestLastMaintenanceLog_NilWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	last, err := db.LastMaintenanceLog()
	if err != nil {
		t.Fatalf("LastMaintenanceLog: %v", err)
	}
	if last != nil {
		t.Errorf("expected nil for empty maintenance_log, got %+v", last)
	}
}

// TestAppendMaintenanceLog_RoundTrip verifies a written row reads back
// identically (modulo time-zone normalisation to UTC).
func TestAppendMaintenanceLog_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	want := statedb.MaintenanceLogEntry{
		Operation:       "vacuum+analyze",
		StartedAt:       now,
		CompletedAt:     now.Add(2 * time.Second),
		PageCountBefore: 1234,
		PageCountAfter:  900,
		PageSize:        4096,
		BytesBefore:     1234 * 4096,
		BytesAfter:      900 * 4096,
		Note:            "manual run",
	}
	id, err := db.AppendMaintenanceLog(want)
	if err != nil {
		t.Fatalf("AppendMaintenanceLog: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected positive row id, got %d", id)
	}

	got, err := db.LastMaintenanceLog()
	if err != nil {
		t.Fatalf("LastMaintenanceLog: %v", err)
	}
	if got == nil {
		t.Fatalf("LastMaintenanceLog: nil after insert")
	}
	if got.Operation != want.Operation ||
		got.PageCountBefore != want.PageCountBefore ||
		got.PageCountAfter != want.PageCountAfter ||
		got.PageSize != want.PageSize ||
		got.BytesBefore != want.BytesBefore ||
		got.BytesAfter != want.BytesAfter ||
		got.Note != want.Note {
		t.Errorf("round-trip mismatch:\n got = %+v\nwant = %+v", *got, want)
	}
	if got.BytesFreed() != want.BytesBefore-want.BytesAfter {
		t.Errorf("BytesFreed = %d, want %d", got.BytesFreed(), want.BytesBefore-want.BytesAfter)
	}

	// And ensure ErrNoRows is not leaking out as a real error.
	if errors.Is(err, sql.ErrNoRows) {
		t.Errorf("LastMaintenanceLog returned ErrNoRows; should be swallowed to (nil, nil)")
	}
}
