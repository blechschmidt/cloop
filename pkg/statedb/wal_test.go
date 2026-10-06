package statedb_test

// The write-ahead log stays bounded (Task 20392).

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// walDB creates a WAL-mode database at a fresh path with a table t holding a
// few rows, and returns its path and a read-write handle under the policy.
func walDB(t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	conn, err := statedb.OpenConn(path, statedb.ReadWrite)
	if err != nil {
		t.Fatalf("OpenConn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	var mode string
	if err := conn.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode=WAL: %q %v", mode, err)
	}
	if _, err := conn.Exec(`CREATE TABLE t (n INTEGER, pad BLOB)`); err != nil {
		t.Fatal(err)
	}
	insertRows(t, conn, 50)
	return path, conn
}

func insertRows(t *testing.T, conn *sql.DB, n int) {
	t.Helper()
	if _, err := conn.Exec(`WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < ?)
		INSERT INTO t(n, pad) SELECT x, zeroblob(2000) FROM c`, n); err != nil {
		t.Fatalf("insert %d rows: %v", n, err)
	}
}

func walSize(t *testing.T, path string) int64 {
	t.Helper()
	n, err := statedb.WALSize(path)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// growLogFile extends the log file to size with zeros, past the frames it
// holds — a log at a high-water mark that SQLite has since started over from
// its beginning. SQLite reads frames up to the count in its index and stops,
// so the tail is dead space, as the live hub's 340 MB was.
func growLogFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.Truncate(statedb.WALPath(path), size); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyHandlesSetNoJournalSizeLimit(t *testing.T) {
	path, _ := walDB(t)
	reader, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var limit int64
	if err := reader.QueryRow(`PRAGMA journal_size_limit`).Scan(&limit); err != nil {
		t.Fatal(err)
	}
	if limit != -1 {
		t.Errorf("a read-only handle has journal_size_limit %d; it never writes the log, so it should keep SQLite's -1", limit)
	}
}

// journal_size_limit is what lets whichever connection restarts the log trim
// it. Restarting is the first write after a checkpoint has copied every frame
// back; SQLite reuses the file from its start and, without the limit, keeps
// all of it.
func TestAWriterUnderThePolicyTrimsTheLogWhenItRestartsIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy bool
		want   int64
	}{
		{"under the policy", true, statedb.JournalSizeLimitBytes},
		// The control: the same write from a connection with no limit, which
		// is what every writer was before — and what the older binaries
		// sharing a hub's database still are.
		{"with no limit", false, 100 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, conn := walDB(t)
			writer := conn
			if !tc.policy {
				bare, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer bare.Close()
				bare.SetMaxOpenConns(1)
				writer = bare
			}
			// Copy every frame back, so the next write starts the log over.
			var busy, logFrames, ckpt int
			if err := conn.QueryRow(`PRAGMA wal_checkpoint(PASSIVE)`).Scan(&busy, &logFrames, &ckpt); err != nil {
				t.Fatal(err)
			}
			if busy != 0 || logFrames != ckpt {
				t.Fatalf("checkpoint did not copy the log back: busy=%d log=%d checkpointed=%d", busy, logFrames, ckpt)
			}
			growLogFile(t, path, 100<<20)

			if _, err := writer.Exec(`INSERT INTO t(n) VALUES (-1)`); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := walSize(t, path); got != tc.want {
				t.Errorf("after a write restarted the log it is %d bytes, want %d", got, tc.want)
			}
			var n int
			if err := conn.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil || n != 51 {
				t.Errorf("rows after the restart: %d (%v), want 51", n, err)
			}
		})
	}
}

func TestCheckpointWALTruncatesTheLog(t *testing.T) {
	path, conn := walDB(t)
	// A second handle open throughout, as a hub keeps one: the log must come
	// back because the checkpoint truncated it, not because the last
	// connection closed and SQLite deleted it.
	hub, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	insertRows(t, conn, 200)
	before := walSize(t, path)
	if before == 0 {
		t.Fatal("the writes left no log to truncate")
	}

	cp, err := statedb.CheckpointWAL(path, 0)
	if err != nil {
		t.Fatalf("CheckpointWAL: %v", err)
	}
	if cp.Busy || !cp.Truncated() {
		t.Fatalf("checkpoint = %+v, want it truncated", cp)
	}
	if cp.BytesBefore != before || cp.BytesAfter != 0 || walSize(t, path) != 0 {
		t.Errorf("checkpoint = %+v with %d bytes before; want %d → 0, and the file at 0 (it is %d)",
			cp, before, before, walSize(t, path))
	}
	if cp.BytesFreed() != before {
		t.Errorf("BytesFreed = %d, want %d", cp.BytesFreed(), before)
	}
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil || n != 250 {
		t.Errorf("rows after the checkpoint: %d (%v), want 250", n, err)
	}
}

func TestCheckpointWALNeverCreatesADatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "state.db")
	if _, err := statedb.CheckpointWAL(missing, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CheckpointWAL on a missing database: %v, want an error wrapping os.ErrNotExist", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CheckpointWAL created %s", missing)
	}
}

// A TRUNCATE checkpoint holds the write lock while it waits on a reader, so
// the time it may wait is time every writer waits too. A reader that holds a
// snapshot open must make it report busy within its own short timeout — not
// keep a concurrent writer waiting until that writer's 5 s busy timeout fails
// it, as a checkpoint under the policy's timeout would.
func TestCheckpointWALReportsBusyWithoutHoldingUpAWriter(t *testing.T) {
	path, conn := walDB(t)

	reader, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	var seen int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	// Frames the reader's snapshot predates: the log cannot be reset past them
	// while it reads.
	insertRows(t, conn, 100)
	before := walSize(t, path)

	type result struct {
		cp  statedb.WALCheckpoint
		err error
	}
	done := make(chan result, 1)
	started := time.Now()
	go func() {
		cp, err := statedb.CheckpointWAL(path, 0)
		done <- result{cp, err}
	}()

	// Write while the checkpoint is waiting on the reader, holding the write
	// lock: the writer waits on it, under the policy's 5 s busy timeout.
	time.Sleep(statedb.WALCheckpointBusyTimeout / 4)
	writeStart := time.Now()
	_, writeErr := conn.Exec(`INSERT INTO t(n) VALUES (-1)`)
	writeWait := time.Since(writeStart)

	r := <-done
	if r.err != nil {
		t.Fatalf("CheckpointWAL: %v", r.err)
	}
	if !r.cp.Busy || r.cp.Truncated() {
		t.Fatalf("checkpoint beside an open read = %+v, want it busy", r.cp)
	}
	if r.cp.BytesBefore != before || walSize(t, path) < before {
		t.Errorf("a busy checkpoint changed the log: %+v, %d bytes before, %d now", r.cp, before, walSize(t, path))
	}
	// Generous bounds for a loaded machine, and still far from what the
	// policy's timeout would cost: 5 s for the checkpoint, and a writer that
	// started waiting behind it failing outright.
	const bound = 2 * time.Second
	if r.cp.Duration > bound || time.Since(started) > bound+time.Second {
		t.Errorf("the checkpoint ran %v (%v in all); a busy one should give up after about %v",
			r.cp.Duration, time.Since(started), statedb.WALCheckpointBusyTimeout)
	}
	if writeErr != nil {
		t.Fatalf("a write beside the checkpoint failed: %v", writeErr)
	}
	if writeWait > bound {
		t.Errorf("a write beside the checkpoint waited %v; the checkpoint should hold it up for at most about %v",
			writeWait, statedb.WALCheckpointBusyTimeout)
	}

	// The reader goes, and the next attempt — the janitor's next tick — gets
	// through.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	cp, err := statedb.CheckpointWAL(path, 0)
	if err != nil {
		t.Fatalf("CheckpointWAL after the read ended: %v", err)
	}
	if cp.Busy || cp.BytesAfter != 0 {
		t.Errorf("checkpoint after the read ended = %+v, want the log truncated", cp)
	}
}

func TestWALSizeOfAMissingLogIsZero(t *testing.T) {
	n, err := statedb.WALSize(filepath.Join(t.TempDir(), "state.db"))
	if err != nil || n != 0 {
		t.Fatalf("WALSize with no log = %d, %v; want 0, nil", n, err)
	}
}
