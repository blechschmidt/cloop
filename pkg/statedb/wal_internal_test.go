package statedb

import (
	"path/filepath"
	"testing"
)

// The checkpoint's short busy timeout belongs to the checkpoint (Task 20392).
// The backup path runs it on a handle's own pooled connection, and must hand
// that connection back waiting the policy's 5 s again: one left at a quarter
// of a second would give up on the next writer it met.
func TestWALCheckpointTruncateLeavesTheHandlesBusyTimeoutAsItWas(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if msg, err := db.WALCheckpointTruncate(); err != nil {
		t.Fatalf("WALCheckpointTruncate: %v", err)
	} else if msg == "" {
		t.Fatal("WALCheckpointTruncate reported nothing")
	}
	var busy int
	if err := db.conn.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busy != BusyTimeoutMillis {
		t.Errorf("after a checkpoint the handle's busy_timeout is %d, want %d", busy, BusyTimeoutMillis)
	}
}
