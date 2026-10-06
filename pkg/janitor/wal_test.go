package janitor

// The pass ends by truncating the write-ahead log (Task 20392).

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// walFixture is a migrated project database with a policy handle for the test
// to write through, and a second handle held open for the test's duration,
// as a hub holds one: the log must come down because the pass truncated it,
// not because the last connection closed and SQLite deleted it.
func walFixture(t *testing.T) (dir, dbPath string, conn *sql.DB) {
	t.Helper()
	dir = newProject(t)
	dbPath = filepath.Join(dir, ".cloop", "state.db")
	statedbtest.Seed(t, dbPath)
	conn, err := statedb.OpenConn(dbPath, statedb.ReadWrite)
	if err != nil {
		t.Fatalf("OpenConn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return dir, dbPath, conn
}

func holdOpen(t *testing.T, dbPath string) {
	t.Helper()
	hub, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { hub.Close() })
}

func execAll(t *testing.T, conn *sql.DB, queries ...string) {
	t.Helper()
	for _, q := range queries {
		if _, err := conn.Exec(q); err != nil {
			t.Fatalf("Exec %.60q: %v", q, err)
		}
	}
}

func walBytes(t *testing.T, dbPath string) int64 {
	t.Helper()
	n, err := statedb.WALSize(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A bulk delete grows the log past the limit, and the pass brings it back.
//
// The delete is the shape row retention and audit pruning take on a real hub:
// one transaction touching most of a large table's pages, every one of which
// goes into the log. Its own commit cannot trim the log — journal_size_limit
// never cuts below the transaction that just wrote it — so without the pass's
// last step the file stays at that size until some later write starts the log
// over, and indefinitely if the writers that do are older builds.
func TestRunOnce_TruncatesTheLogABulkDeleteGrew(t *testing.T) {
	withFreeSpace(t, plentyOfSpace)
	dir, dbPath, conn := walFixture(t)

	// About 70 MB, two rows to a page. Filled with the journal off: the fill
	// is fixture rather than subject, and through the log it would cost a
	// race-instrumented run several more seconds.
	execAll(t, conn,
		`PRAGMA journal_mode=OFF`,
		`CREATE TABLE bulk (id INTEGER PRIMARY KEY, payload BLOB)`,
		`WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 36000)
			INSERT INTO bulk(id, payload) SELECT x, zeroblob(1800) FROM c`,
		`PRAGMA journal_mode=WAL`,
	)
	holdOpen(t, dbPath)

	before := walBytes(t, dbPath)
	// Every other row: each page loses one of its two, so every page is
	// rewritten into the log.
	execAll(t, conn, `DELETE FROM bulk WHERE id % 2 = 0`)
	grown := walBytes(t, dbPath)
	if grown <= statedb.JournalSizeLimitBytes {
		t.Fatalf("the bulk delete grew the log from %d to %d bytes, not past the %d limit; "+
			"the fixture no longer builds the log this test is about", before, grown, statedb.JournalSizeLimitBytes)
	}

	rep, err := RunOnce(Options{WorkDir: dir, Policy: DefaultPolicy()})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if errs := rep.Errs(); len(errs) > 0 {
		t.Fatalf("pass errors: %v", errs)
	}
	if !rep.WAL.Ran || rep.WAL.BytesFreed <= 0 {
		t.Fatalf("WAL step = %+v, want it to have truncated the log", rep.WAL)
	}
	if after := walBytes(t, dbPath); after > statedb.JournalSizeLimitBytes || after != 0 {
		t.Errorf("after the pass the log is %d bytes (was %d); want it truncated, under the %d limit",
			after, grown, statedb.JournalSizeLimitBytes)
	}
	if rep.BytesFreed() < rep.WAL.BytesFreed {
		t.Errorf("the pass reclaimed %d in all, less than the %d its WAL step freed", rep.BytesFreed(), rep.WAL.BytesFreed)
	}
	if !strings.Contains(rep.Summary(), "write-ahead log truncated") {
		t.Errorf("summary %q does not mention the truncated log", rep.Summary())
	}
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM bulk`).Scan(&n); err != nil || n != 18000 {
		t.Errorf("rows after the pass: %d (%v), want 18000", n, err)
	}
}

// A reader still using the log makes the checkpoint report busy. The pass
// records that as a skipped step, not a failure, and leaves the log alone;
// the next attempt gets through once the reader has gone.
func TestRunOnce_ABusyLogIsRecordedAndLeftForTheNextAttempt(t *testing.T) {
	dir, dbPath, conn := walFixture(t)
	holdOpen(t, dbPath)
	execAll(t, conn, `CREATE TABLE t (n INTEGER)`, `INSERT INTO t VALUES (1)`)

	reader, err := statedb.OpenConn(dbPath, statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	execAll(t, conn, `INSERT INTO t VALUES (2)`) // a frame the reader's snapshot predates
	held := walBytes(t, dbPath)

	rep, err := RunOnce(Options{WorkDir: dir, Policy: Policy{Enabled: true}})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.WAL.Err != nil || rep.WAL.Ran || !rep.WAL.Skipped || !strings.Contains(rep.WAL.Reason, "busy") {
		t.Fatalf("WAL step beside an open read = %+v, want it skipped as busy", rep.WAL)
	}
	if got := walBytes(t, dbPath); got < held {
		t.Errorf("a busy checkpoint shrank the log from %d to %d bytes", held, got)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	rep, err = RunOnce(Options{WorkDir: dir, Policy: Policy{Enabled: true}})
	if err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if !rep.WAL.Ran || walBytes(t, dbPath) != 0 {
		t.Errorf("WAL step once the reader had gone = %+v with %d bytes left, want the log truncated",
			rep.WAL, walBytes(t, dbPath))
	}
}

func TestRunOnce_DryRunLeavesTheLog(t *testing.T) {
	dir, dbPath, conn := walFixture(t)
	holdOpen(t, dbPath)
	execAll(t, conn, `CREATE TABLE t (n INTEGER)`, `INSERT INTO t VALUES (1)`)
	size := walBytes(t, dbPath)
	if size == 0 {
		t.Fatal("the fixture left no log")
	}

	rep, err := RunOnce(Options{WorkDir: dir, DryRun: true, Policy: Policy{Enabled: true}})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !rep.WAL.Skipped || rep.WAL.BytesFreed != size || !strings.Contains(rep.WAL.Reason, "dry run") {
		t.Errorf("dry-run WAL step = %+v, want it to report the %d-byte log it would truncate", rep.WAL, size)
	}
	if got := walBytes(t, dbPath); got != size {
		t.Errorf("a dry run changed the log from %d to %d bytes", size, got)
	}
}

func TestRunOnce_NoDatabaseHasNoLogToTruncate(t *testing.T) {
	rep, err := RunOnce(Options{WorkDir: newProject(t), Policy: Policy{Enabled: true}})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.WAL.Err != nil || rep.WAL.Ran || rep.WAL.Reason == "" {
		t.Errorf("WAL step with no database = %+v, want a reason and no error", rep.WAL)
	}
}
