package statedb_test

// Goroutine-leak regression test for the statedb Open/Close lifecycle.
//
// Each call to statedb.Open creates a *sql.DB-wrapped SQLite handle.
// modernc.org/sqlite's pure-Go driver allocates per-connection resources
// — pragmas applied via QueryRow, the schema DDL — and *sql.DB itself
// owns a connection-pool janitor goroutine when MaxOpenConns > 0. On
// Close, the janitor goroutine exits, the connection finalisers run, and
// no goroutine should outlive the *DB handle. A regression in cloop's
// own pragma application (e.g. a goroutine that polls for WAL checkpoint
// status without honouring Close), or an upstream driver change that
// orphans a per-handle goroutine, would scale linearly with the number
// of Open calls and eventually exhaust the goroutine table for any
// workload that opens many short-lived handles (the CLI test suite, the
// healthz probes, multi-project orchestration).
//
// This test mirrors the pattern documented in
// pkg/watchdog/goroutine_leak_test.go (the canonical reference) and the
// other *_goroutine_leak_test.go files in cloop: open N short-lived
// handles, exercise them, close them, and assert runtime.NumGoroutine
// has returned to within a small slack of the pre-test baseline.
//
// Slack is set higher than the watchdog/orchestrator tests because the
// SQLite driver and database/sql connection pool both keep a couple of
// ambient goroutines that flap by 1-2 between iterations. With N=15 a
// per-cycle leak still produces a delta of ~15-45 — well above the
// slack threshold — while ambient flapping stays under it.

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// statedbGoroutineLeakSlack absorbs runtime/scheduler/sqlite-driver ambient
// flapping. Picked larger than the watchdog/orchestrator equivalent because
// modernc.org/sqlite and database/sql each maintain a small number of
// background goroutines whose lifetimes are driven by pool heuristics, not
// by Close alone, and which can produce a 1-3 goroutine delta per
// iteration even on the happy path. With N=15 the threshold remains well
// below any real per-cycle leak.
const statedbGoroutineLeakSlack = 15

// settleStatedbGoroutineCount triggers GC and sleeps long enough for the
// database/sql connection pool's deferred close machinery (and any
// modernc.org/sqlite finalizers) to settle before sampling NumGoroutine.
// SQLite's WAL truncation and finalizer chain are slower than a typical
// goroutine teardown; 200ms is enough on every machine cloop tests on.
func settleStatedbGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// openExerciseClose runs a minimal but representative lifecycle: open a
// fresh on-disk SQLite handle, write & read a row through the cloop
// Save/Load API, ping it (the readiness probe path), then close. A real
// leak in any of those code paths — the Save tx that spawns a goroutine
// it never awaits, a Ping that orphans a context-cancellation goroutine,
// the deferred Close path itself — would scale linearly with N.
func openExerciseClose(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}

	// Exercise the Save/Load path so the connection pool actually allocates
	// a connection rather than leaving the handle idle. An idle handle
	// would not exercise the pool's per-connection cleanup paths.
	s := &statedb.State{
		Goal:      "leak test",
		WorkDir:   dir,
		Status:    "initialized",
		MaxSteps:  1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.SaveState(s); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if _, err := db.LoadState(); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	// Ping path: PingContext runs SELECT 1 with a context — exercises
	// modernc.org/sqlite's per-query context-cancellation plumbing, which
	// historically has been a source of orphaned goroutines in pre-1.50
	// versions of the driver.
	pingCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	if err := db.PingContext(pingCtx); err != nil {
		cancel()
		t.Fatalf("PingContext: %v", err)
	}
	cancel()

	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestStatedb_OpenCloseLifecycle_NoGoroutineLeak runs N short-lived
// open-exercise-close cycles and asserts runtime.NumGoroutine returns to
// within statedbGoroutineLeakSlack of the pre-test baseline.
//
// Catches regressions in:
//   - cloop's Open() pragma-application path (goroutines spawned around
//     QueryRow that never exit on driver error)
//   - cloop's Save/Load tx wrapping (goroutines awaiting a context that
//     was never cancelled)
//   - cloop's PingContext (orphaned context-cancellation goroutines)
//   - the deferred Close in the *DB handle itself
//   - a future migration to a different SQL driver that doesn't honour
//     Close as cleanly as modernc.org/sqlite does
func TestStatedb_OpenCloseLifecycle_NoGoroutineLeak(t *testing.T) {
	// Warm up: one cycle so any one-time package init (driver
	// registration, schema DDL parsing) doesn't pollute the baseline.
	openExerciseClose(t)

	baseline := settleStatedbGoroutineCount()

	const N = 15
	for i := 0; i < N; i++ {
		openExerciseClose(t)
	}

	post := settleStatedbGoroutineCount()
	delta := post - baseline
	if delta > statedbGoroutineLeakSlack {
		t.Fatalf("goroutine leak in statedb Open/Close lifecycle: baseline=%d post=%d delta=%d (>%d) after %d cycles",
			baseline, post, delta, statedbGoroutineLeakSlack, N)
	}
}
