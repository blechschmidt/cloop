package statedb

// Two SQLite busy traps busy_timeout did not cover (Task 20349): an open racing
// another connection's exclusive lock, and a deferred read-then-write
// transaction racing another handle's commit.

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestOpenWaitsOutAnExclusiveLock is the open race. The last close of a WAL
// database checkpoints under an exclusive lock, and `PRAGMA journal_mode=WAL`
// used to run before busy_timeout was set: a hub opening a project's database
// just as a `cloop run` closed it failed at once with "enable WAL mode:
// database is locked". A holder in exclusive locking mode stands in for that
// checkpoint, deterministically.
func TestOpenWaitsOutAnExclusiveLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := Open(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	holder, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("holder open: %v", err)
	}
	holder.SetMaxOpenConns(1)
	defer holder.Close()
	for _, stmt := range []string{
		`PRAGMA locking_mode=EXCLUSIVE`,
		`CREATE TABLE IF NOT EXISTS busy_probe (n INTEGER)`,
		`INSERT INTO busy_probe (n) VALUES (1)`,
	} {
		if _, err := holder.Exec(stmt); err != nil {
			t.Fatalf("holder %q: %v", stmt, err)
		}
	}

	const hold = 400 * time.Millisecond
	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(hold)
		_ = holder.Close()
	}()

	start := time.Now()
	db, err := Open(path)
	waited := time.Since(start)
	<-released
	if err != nil {
		t.Fatalf("Open failed instead of waiting out the lock (%s in): %v", waited, err)
	}
	defer db.Close()
	if waited < hold/2 {
		t.Errorf("Open returned after %s, before the holder let go at %s — the lock was not held, "+
			"so this test proves nothing", waited, hold)
	}
}

// TestReadThenWriteSurvivesAConcurrentCommit is the snapshot trap. A deferred
// transaction that reads and then writes fails instantly with
// SQLITE_BUSY_SNAPSHOT (517) — no busy handler, no retry — when another handle
// commits between the two. With transactions taking the write lock at BEGIN,
// the other writer waits instead, and both land.
func TestReadThenWriteSurvivesAConcurrentCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	a, err := Open(path)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer b.Close()
	if _, err := a.conn.Exec(`CREATE TABLE counter (n INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := a.conn.Exec(`INSERT INTO counter (n) VALUES (0)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// a reads, then b commits, then a writes: the interleaving that fails a
	// deferred transaction with 517.
	tx, err := a.conn.Begin()
	if err != nil {
		t.Fatalf("a begin: %v", err)
	}
	var n int
	if err := tx.QueryRow(`SELECT n FROM counter`).Scan(&n); err != nil {
		t.Fatalf("a read: %v", err)
	}

	var (
		wg   sync.WaitGroup
		bErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, bErr = b.conn.Exec(`UPDATE counter SET n = n + 100`)
	}()
	// Give b's write the chance to land first, as it would against a deferred
	// transaction; with the write lock taken at BEGIN it has to wait for a.
	time.Sleep(150 * time.Millisecond)

	if _, err := tx.Exec(`UPDATE counter SET n = ?`, n+1); err != nil {
		_ = tx.Rollback()
		wg.Wait()
		t.Fatalf("a's write after b's commit failed — a read-then-write transaction lost to a "+
			"concurrent commit: %v", err)
	}
	if err := tx.Commit(); err != nil {
		wg.Wait()
		t.Fatalf("a commit: %v", err)
	}
	wg.Wait()
	if bErr != nil {
		t.Fatalf("b's write did not wait for a's transaction: %v", bErr)
	}

	if err := a.conn.QueryRow(`SELECT n FROM counter`).Scan(&n); err != nil {
		t.Fatalf("final read: %v", err)
	}
	if n != 101 {
		t.Errorf("counter = %d, want 101: both writes, serialised, a's first", n)
	}
}
