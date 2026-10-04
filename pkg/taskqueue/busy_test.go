package taskqueue

// MarkDone and a writer holding the lock (Task 20374).

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// forceNewConnection makes the pool discard its connection and open another,
// as database/sql does by itself after a driver error or at a lifetime limit.
func forceNewConnection(t *testing.T, q *Queue) {
	t.Helper()
	q.conn.SetConnMaxLifetime(time.Nanosecond)
	time.Sleep(time.Millisecond)
	var one int
	if err := q.conn.QueryRow(`SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("query on a fresh connection: %v", err)
	}
	q.conn.SetConnMaxLifetime(0)
}

// holdWriteLock takes the database's write lock with BEGIN IMMEDIATE on a
// connection of its own and releases it after hold.
func holdWriteLock(t *testing.T, path string, hold time.Duration) <-chan struct{} {
	t.Helper()
	holder, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { holder.Close() })
	ctx := context.Background()
	c, err := holder.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}
	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(hold)
		_, _ = c.ExecContext(ctx, `ROLLBACK`)
		_ = c.Close()
	}()
	return released
}

// Before Task 20374 taskqueue opened state.db with a bare sql.Open and issued
// `PRAGMA busy_timeout=5000` with Exec, which set it on the one connection that
// ran it. Once the pool replaced that connection, MarkDone met a writer's lock
// with a busy timeout of zero and failed on the spot:
//
//	queue complete 1: database is locked (5) (SQLITE_BUSY)
//
// Under the connection policy every connection the pool opens waits.
func TestMarkDoneWaitsOutAHeldWriteLock(t *testing.T) {
	q, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	id, err := q.Enqueue(Entry{Kind: KindTask, TaskID: 1, Title: "a task"})
	if err != nil {
		t.Fatal(err)
	}

	forceNewConnection(t, q)
	var busy int
	if err := q.conn.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if busy != statedb.BusyTimeoutMillis {
		t.Errorf("busy_timeout on a connection the pool opened later = %d, want %d", busy, statedb.BusyTimeoutMillis)
	}

	const hold = 300 * time.Millisecond
	released := holdWriteLock(t, q.Path(), hold)

	start := time.Now()
	err = q.MarkDone(id, "finished")
	waited := time.Since(start)
	<-released
	if err != nil {
		if strings.Contains(err.Error(), "SQLITE_BUSY") || strings.Contains(err.Error(), "locked") {
			t.Fatalf("MarkDone failed with SQLITE_BUSY after %s instead of waiting out the lock: %v", waited, err)
		}
		t.Fatalf("MarkDone: %v", err)
	}
	if waited < hold/2 {
		t.Fatalf("MarkDone returned after %s, before the writer released its lock (%s)", waited, hold)
	}

	entries, err := q.List(ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Status != StatusDone || entries[0].OutputSummary != "finished" {
		t.Fatalf("entry after MarkDone = %+v", entries)
	}
}
