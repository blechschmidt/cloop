package ui

// The leader's check of the control plane's write-ahead log, and the gauge
// that reports it (Task 20392).

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// walControlPlane is a hub directory whose database has a log, with a handle
// held open as a running hub holds one — the log outlives any one connection
// closing — and a writer for the test.
func walControlPlane(t *testing.T) (*Server, string, *sql.DB, *captureLogger) {
	t.Helper()
	dir := statedbtest.Dir(t)
	dbPath := state.DBPath(dir)
	hub, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { hub.Close() })
	conn, err := statedb.OpenConn(dbPath, statedb.ReadWrite)
	if err != nil {
		t.Fatalf("OpenConn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Exec(`CREATE TABLE wal_fixture (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	cap := &captureLogger{}
	return &Server{WorkDir: dir, Log: cap}, dbPath, conn, cap
}

// pastTheLimit extends the log with zeros to 100 MiB: a log at a high-water
// mark a burst left, which SQLite has since started over from its beginning.
// It reads frames up to the count in its index and ignores the tail.
func pastTheLimit(t *testing.T, dbPath string) int64 {
	t.Helper()
	const size = 100 << 20
	if err := os.Truncate(statedb.WALPath(dbPath), size); err != nil {
		t.Fatal(err)
	}
	return size
}

func walFileSize(t *testing.T, dbPath string) int64 {
	t.Helper()
	n, err := statedb.WALSize(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func entriesContaining(c *captureLogger, substr string) int {
	n := 0
	for _, e := range c.snapshot() {
		if strings.Contains(e.Message, substr) {
			n++
		}
	}
	return n
}

func TestControlPlaneWALCheck_TruncatesALogPastTheLimit(t *testing.T) {
	srv, dbPath, conn, cap := walControlPlane(t)
	if _, err := conn.Exec(`INSERT INTO wal_fixture VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	size := pastTheLimit(t, dbPath)

	out := srv.checkControlPlaneWAL()
	if out.Err != nil || !out.Attempted || !out.Checkpoint.Truncated() {
		t.Fatalf("check of a %d-byte log = %+v, want it truncated", size, out)
	}
	if out.Size != size || walFileSize(t, dbPath) != 0 {
		t.Errorf("check saw %d bytes and left %d; want %d and 0", out.Size, walFileSize(t, dbPath), size)
	}
	if entriesContaining(cap, "truncated the write-ahead log") != 1 {
		t.Errorf("a truncation should be logged once; got %+v", cap.snapshot())
	}
}

func TestControlPlaneWALCheck_LeavesALogUnderTheLimitAlone(t *testing.T) {
	srv, dbPath, conn, cap := walControlPlane(t)
	if _, err := conn.Exec(`INSERT INTO wal_fixture VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	size := walFileSize(t, dbPath)
	if size == 0 || size > statedb.JournalSizeLimitBytes {
		t.Fatalf("fixture log is %d bytes, want a small one", size)
	}

	out := srv.checkControlPlaneWAL()
	if out.Err != nil || out.Attempted {
		t.Fatalf("check of a %d-byte log = %+v, want nothing attempted", size, out)
	}
	if got := walFileSize(t, dbPath); got != size {
		t.Errorf("the log went from %d to %d bytes under the limit", size, got)
	}
	if n := len(cap.snapshot()); n != 0 {
		t.Errorf("a log under the limit was worth %d log lines: %+v", n, cap.snapshot())
	}
}

// A reader still using the log makes the check's checkpoint busy: recorded,
// logged once rather than every minute, and tried again on the next check,
// which gets through once the reader has gone.
func TestControlPlaneWALCheck_RecordsABusyLogAndRetries(t *testing.T) {
	srv, dbPath, conn, cap := walControlPlane(t)
	if _, err := conn.Exec(`INSERT INTO wal_fixture VALUES (1)`); err != nil {
		t.Fatal(err)
	}
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
	if err := tx.QueryRow(`SELECT COUNT(*) FROM wal_fixture`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO wal_fixture VALUES (2)`); err != nil {
		t.Fatal(err)
	}
	size := pastTheLimit(t, dbPath)

	for i := 1; i <= 2; i++ {
		out := srv.checkControlPlaneWAL()
		if out.Err != nil || !out.Attempted || !out.Checkpoint.Busy || out.BusyStreak != i {
			t.Fatalf("check %d beside an open read = %+v, want busy with a streak of %d", i, out, i)
		}
		if got := walFileSize(t, dbPath); got != size {
			t.Fatalf("a busy check changed the log from %d to %d bytes", size, got)
		}
	}
	if got := entriesContaining(cap, "another connection was still using it"); got != 1 {
		t.Errorf("two busy checks in a row logged %d lines about it, want 1: %+v", got, cap.snapshot())
	}

	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	out := srv.checkControlPlaneWAL()
	if out.Err != nil || !out.Checkpoint.Truncated() || out.BusyStreak != 0 {
		t.Fatalf("check once the reader had gone = %+v, want the log truncated and the streak over", out)
	}
	if got := walFileSize(t, dbPath); got != 0 {
		t.Errorf("the log is %d bytes after the check that got through", got)
	}
	if entriesContaining(cap, "after 2 busy attempt(s)") != 1 {
		t.Errorf("the truncation should say how long the log was held: %+v", cap.snapshot())
	}
}

func TestControlPlaneWALCheck_NoDatabaseIsNothingToDo(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir(), Log: &captureLogger{}}
	if out := srv.checkControlPlaneWAL(); out.Err != nil || out.Attempted {
		t.Fatalf("check with no database = %+v, want nothing", out)
	}
	if _, err := os.Stat(filepath.Join(srv.WorkDir, ".cloop")); !os.IsNotExist(err) {
		t.Errorf("the check created %s", filepath.Join(srv.WorkDir, ".cloop"))
	}
}

// The gauge is the control plane's log, read at scrape time; a hub with no
// database reports none. (That only the leader exports it is
// TestMetricsSharedGaugesComeFromTheLeaderOnly's.)
func TestStateDBWALGaugeIsTheControlPlaneLog(t *testing.T) {
	srv, dbPath, conn, _ := walControlPlane(t)
	if _, err := conn.Exec(`INSERT INTO wal_fixture VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	size := pastTheLimit(t, dbPath)

	v, ok := sample(srv.gatherMetrics(), "cloop_statedb_wal_bytes")
	if !ok || int64(v) != size {
		t.Fatalf("cloop_statedb_wal_bytes = %v (present: %v), want %d", v, ok, size)
	}

	if out := srv.checkControlPlaneWAL(); !out.Checkpoint.Truncated() {
		t.Fatalf("check = %+v", out)
	}
	if v, ok := sample(srv.gatherMetrics(), "cloop_statedb_wal_bytes"); !ok || int64(v) != walFileSize(t, dbPath) {
		t.Errorf("after the truncation cloop_statedb_wal_bytes = %v (present: %v), want %d", v, ok, walFileSize(t, dbPath))
	}

	empty := &Server{WorkDir: t.TempDir()}
	if v, ok := sample(empty.gatherMetrics(), "cloop_statedb_wal_bytes"); ok {
		t.Errorf("a hub with no database exports cloop_statedb_wal_bytes = %v", v)
	}
}
