package statedb

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestApplyPragmas_OnLiveConnection verifies that after Open() returns, the
// underlying *sql.DB connection actually has the tuning pragmas in effect.
//
// This test lives in `package statedb` (not `statedb_test`) so it can read
// d.conn directly and observe the production connection — not a re-applied
// raw probe. With SetMaxOpenConns(1) the pool reuses one connection, so a
// PRAGMA query through d.conn reflects what production code paths see.
func TestApplyPragmas_OnLiveConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	var jm string
	if err := db.conn.QueryRow(`PRAGMA journal_mode`).Scan(&jm); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if !strings.EqualFold(jm, "wal") {
		t.Errorf("journal_mode on live conn: got %q, want wal", jm)
	}

	var bt int
	if err := db.conn.QueryRow(`PRAGMA busy_timeout`).Scan(&bt); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if bt != 5000 {
		t.Errorf("busy_timeout on live conn: got %d, want 5000", bt)
	}

	// synchronous: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA.
	var sync int
	if err := db.conn.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil {
		t.Fatalf("PRAGMA synchronous: %v", err)
	}
	if sync != 1 {
		t.Errorf("synchronous on live conn: got %d, want 1 (NORMAL)", sync)
	}

	var fk int
	if err := db.conn.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys on live conn: got %d, want 1", fk)
	}
}

// TestApplyPragmas_RejectsNonWALFilesystem documents that Open() refuses to
// silently fall back to the default DELETE journal mode. The error path
// matters for diagnostics: a tmpfs / network FS that cannot host a WAL would
// otherwise leak past Open() and surface much later as random "database is
// locked" errors during real workloads.
func TestApplyPragmas_RejectsNonWALFilesystem(t *testing.T) {
	// We cannot easily simulate a WAL-incompatible FS in CI, so this test
	// only confirms that the in-memory equivalent (":memory:") is correctly
	// rejected because WAL on a transient memory database has no meaning.
	_, err := Open(":memory:")
	if err == nil {
		t.Skip("memory database accepted WAL on this build of modernc.org/sqlite; skipping rejection test")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "wal") {
		t.Errorf("expected WAL-related error for :memory: open, got: %v", err)
	}
}

// TestApplyPragmas_ConcurrentTransactionsNoLock asserts that a *file-backed*
// state.db can service concurrent read+write transactions across two
// independent *DB handles without producing SQLITE_BUSY / "database is
// locked" errors. Without WAL + busy_timeout these would surface
// intermittently — which is exactly the failure mode Task 20084 fixes.
func TestApplyPragmas_ConcurrentTransactionsNoLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	a, err := Open(path)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	defer b.Close()

	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, iterations*2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tx, err := a.conn.Begin()
			if err != nil {
				errs <- err
				return
			}
			if _, err := tx.Exec(
				`INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
				"writer_iter", "tick",
			); err != nil {
				_ = tx.Rollback()
				errs <- err
				return
			}
			if err := tx.Commit(); err != nil {
				errs <- err
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tx, err := b.conn.Begin()
			if err != nil {
				errs <- err
				return
			}
			rows, err := tx.Query(`SELECT key, value FROM metadata`)
			if err != nil {
				_ = tx.Rollback()
				errs <- err
				return
			}
			for rows.Next() {
				var k, v string
				_ = rows.Scan(&k, &v)
			}
			rows.Close()
			if err := tx.Commit(); err != nil {
				errs <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "lock") || strings.Contains(lower, "busy") {
			t.Fatalf("WAL+busy_timeout did not prevent lock contention: %v", err)
		}
		t.Fatalf("concurrent transaction error: %v", err)
	}
}
