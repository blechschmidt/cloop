package dbmaintain_test

// A maintain run reports the write-ahead log before and after, and ends by
// truncating it (Task 20392).

import (
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/dbmaintain"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// walFixture builds a database with deleted rows and a handle held open, as a
// hub holds one — so the log is still there when Run starts, and is gone at
// the end because Run truncated it rather than because the last connection
// closed.
func walFixture(t *testing.T) (dbPath string, hub *statedb.DB) {
	t.Helper()
	dbPath = filepath.Join(t.TempDir(), "state.db")
	fillSteps(t, dbPath, 400, 1)
	hub, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { hub.Close() })
	rawExec(t, dbPath, `DELETE FROM steps`)
	return dbPath, hub
}

func walSize(t *testing.T, dbPath string) int64 {
	t.Helper()
	n, err := statedb.WALSize(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRun_TruncatesTheLogItWroteThrough(t *testing.T) {
	dbPath, _ := walFixture(t)
	before := walSize(t, dbPath)
	if before == 0 {
		t.Fatal("the fixture left no log")
	}

	rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{AllowConcurrentHub: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.WALBefore != before {
		t.Errorf("WALBefore = %d, want %d", rep.WALBefore, before)
	}
	if rep.WALCheckpoint == nil || rep.WALCheckpoint.Busy || !rep.WALCheckpoint.Truncated() {
		t.Fatalf("WALCheckpoint = %+v, want a completed truncate", rep.WALCheckpoint)
	}
	// The VACUUM wrote every page of the database through the log, so a run
	// that stopped there would report a log at least the size of the file.
	if rep.WALAfter != 0 || walSize(t, dbPath) != 0 {
		t.Errorf("WALAfter = %d and the file is %d bytes, want both 0", rep.WALAfter, walSize(t, dbPath))
	}
}

func TestRun_DryRunReportsTheLogAndLeavesIt(t *testing.T) {
	dbPath, _ := walFixture(t)
	before := walSize(t, dbPath)

	rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{DryRun: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.WALCheckpoint != nil {
		t.Errorf("a dry run checkpointed the log: %+v", rep.WALCheckpoint)
	}
	if rep.WALBefore != before || rep.WALAfter != before || walSize(t, dbPath) != before {
		t.Errorf("dry run: WALBefore=%d WALAfter=%d file=%d, want all %d",
			rep.WALBefore, rep.WALAfter, walSize(t, dbPath), before)
	}
}

// A reader still using the log leaves it as it was. The run says so, and does
// not call itself failed: the VACUUM and ANALYZE happened.
func TestRun_ABusyLogIsReportedNotFailed(t *testing.T) {
	dbPath, _ := walFixture(t)

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
	if err := tx.QueryRow(`SELECT COUNT(*) FROM steps`).Scan(&n); err != nil {
		t.Fatal(err)
	}

	rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{AllowConcurrentHub: true})
	if err != nil {
		t.Fatalf("Run beside an open read: %v", err)
	}
	if len(rep.Operations) == 0 {
		t.Fatalf("no maintenance ran: %+v", rep)
	}
	if rep.WALCheckpoint == nil || !rep.WALCheckpoint.Busy {
		t.Fatalf("WALCheckpoint beside an open read = %+v, want it busy", rep.WALCheckpoint)
	}
	if rep.WALAfter == 0 || rep.WALAfter != walSize(t, dbPath) {
		t.Errorf("WALAfter = %d with the file at %d bytes; a busy checkpoint leaves the log, and the report should say how large",
			rep.WALAfter, walSize(t, dbPath))
	}
}
