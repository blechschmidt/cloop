package statedb

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRequestKill_RoundTrip(t *testing.T) {
	db := openTestDB(t)

	// Empty initially.
	if rows, err := db.PendingKills(); err != nil || len(rows) != 0 {
		t.Fatalf("PendingKills empty: got %v err=%v", rows, err)
	}

	// Insert one row.
	now := time.Now()
	if err := db.RequestKill(KillRequest{
		TaskID: 7, TargetStatus: "done", RequestedBy: "ui", RequestedAt: now,
	}); err != nil {
		t.Fatalf("RequestKill: %v", err)
	}
	rows, err := db.PendingKills()
	if err != nil {
		t.Fatalf("PendingKills: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.TaskID != 7 || got.TargetStatus != "done" || got.RequestedBy != "ui" {
		t.Errorf("row mismatch: %+v", got)
	}

	// Lookup by ID.
	r, ok, err := db.LookupKill(7)
	if err != nil || !ok || r.TaskID != 7 {
		t.Errorf("LookupKill(7) = (%+v, %v, %v)", r, ok, err)
	}

	// Lookup miss.
	if _, ok, err := db.LookupKill(99); err != nil || ok {
		t.Errorf("LookupKill(99) = (_, %v, %v); want (_, false, nil)", ok, err)
	}

	// Clear.
	if err := db.ClearKill(7); err != nil {
		t.Fatalf("ClearKill: %v", err)
	}
	if rows, _ := db.PendingKills(); len(rows) != 0 {
		t.Errorf("PendingKills after clear: %v", rows)
	}

	// Idempotent clear.
	if err := db.ClearKill(7); err != nil {
		t.Errorf("idempotent ClearKill: %v", err)
	}
}

func TestRequestKill_UpsertOverwrites(t *testing.T) {
	db := openTestDB(t)

	if err := db.RequestKill(KillRequest{TaskID: 3, TargetStatus: "skipped", RequestedBy: "alice"}); err != nil {
		t.Fatalf("first RequestKill: %v", err)
	}
	if err := db.RequestKill(KillRequest{TaskID: 3, TargetStatus: "done", RequestedBy: "bob"}); err != nil {
		t.Fatalf("second RequestKill: %v", err)
	}
	rows, _ := db.PendingKills()
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1 (upsert collapsed)", len(rows))
	}
	if rows[0].TargetStatus != "done" || rows[0].RequestedBy != "bob" {
		t.Errorf("upsert did not overwrite: %+v", rows[0])
	}
}

func TestRequestKill_RejectsZeroTaskID(t *testing.T) {
	db := openTestDB(t)
	if err := db.RequestKill(KillRequest{TaskID: 0}); err == nil {
		t.Error("RequestKill(0) should fail; got nil")
	}
}

func TestPendingKills_OrderOldestFirst(t *testing.T) {
	db := openTestDB(t)

	// Two rows with explicit timestamps so the test is deterministic on hosts
	// where time.Now() resolution might collapse two back-to-back inserts.
	older := time.Now().Add(-10 * time.Second)
	newer := time.Now()
	if err := db.RequestKill(KillRequest{TaskID: 2, TargetStatus: "done", RequestedAt: newer}); err != nil {
		t.Fatalf("insert newer: %v", err)
	}
	if err := db.RequestKill(KillRequest{TaskID: 1, TargetStatus: "skipped", RequestedAt: older}); err != nil {
		t.Fatalf("insert older: %v", err)
	}
	rows, err := db.PendingKills()
	if err != nil {
		t.Fatalf("PendingKills: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].TaskID != 1 {
		t.Errorf("first row task_id = %d, want 1 (oldest first)", rows[0].TaskID)
	}
}

// TestKillRequest_Sentinels confirms LookupKill returns (zero, false, nil) on
// miss and that the wrapper does not surface sql.ErrNoRows. This guards
// against future refactors leaking the driver-level sentinel through the
// statedb API surface.
func TestKillRequest_Sentinels(t *testing.T) {
	db := openTestDB(t)
	_, ok, err := db.LookupKill(42)
	if err != nil {
		t.Fatalf("LookupKill miss should return nil err; got %v", err)
	}
	if ok {
		t.Error("LookupKill miss should return ok=false")
	}
	// Make sure none of the sentinel errors leak from the public API.
	for _, sentinel := range []error{ErrTaskNotFound, ErrProjectNotFound, ErrStaleVersion, ErrDBLocked, ErrSchemaMismatch} {
		if errors.Is(err, sentinel) {
			t.Errorf("LookupKill miss should not wrap sentinel %v", sentinel)
		}
	}
}
