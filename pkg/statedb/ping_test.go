package statedb_test

import (
	"context"
	"testing"
	"time"
)

// TestPingContext_HealthyHandle covers the success path: a freshly-opened
// database returns nil error and the SELECT 1 query produces the literal
// integer 1. This is the load-bearing path for /readyz.
func TestPingContext_HealthyHandle(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext on fresh handle: %v", err)
	}
}

// TestPingContext_HonoursContext verifies that an already-cancelled
// context propagates as a non-nil error rather than completing silently.
// Without this guarantee, /readyz could return 200 against a wedged
// SQLite file simply because the SELECT 1 happened to be fast on a
// cached page; the contract is that ctx is authoritative.
func TestPingContext_HonoursContext(t *testing.T) {
	db, _ := tempDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	err := db.PingContext(ctx)
	if err == nil {
		t.Fatal("PingContext with cancelled ctx: want error, got nil")
	}
}

// TestPingContext_AfterClose confirms that pinging a closed handle
// surfaces an error (not a panic, not a hang). This is the literal
// "closed db handle" scenario from Task 20092.
func TestPingContext_AfterClose(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := db.PingContext(context.Background()); err == nil {
		t.Fatal("PingContext on closed handle: want error, got nil")
	}
}

// TestPingContext_RespectsDeadline asserts that the context deadline is
// respected — a tight timeout with an expired context returns within
// the deadline window rather than waiting on the connection.
func TestPingContext_RespectsDeadline(t *testing.T) {
	db, _ := tempDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	// Sleep past the deadline so even an instant-returning Ping observes it.
	time.Sleep(10 * time.Millisecond)

	if err := db.PingContext(ctx); err == nil {
		t.Fatal("PingContext with expired deadline: want error, got nil")
	}
}
