package executorstore

// Tests for durable handle identity (Task 20191).
//
// These run against a real SQLite file, not a fake, because the property under
// test is exactly the one a fake cannot have: that a row written by one
// process is readable by the next one. The bug this table fixes was that no
// row existed at all, so a test whose store lived in the test's own memory
// would be asserting the only thing that was never in doubt.

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// openHandles returns a Handles store over a fresh database in dir, plus the
// path, so a test can close and reopen to simulate a restart.
func openHandles(t *testing.T) (*Handles, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h, err := NewHandles(db)
	if err != nil {
		t.Fatalf("new handles: %v", err)
	}
	return h, path
}

func sampleRecord() executor.HandleRecord {
	return executor.HandleRecord{
		HandleID:    "h-1",
		ExecutorID:  "container",
		Driver:      executor.KindContainer,
		ExternalID:  "cloop-myproj-abc123",
		ProjectPath: "/srv/projects/myproj",
		TaskID:      42,
		Image:       "ghcr.io/example/sandbox@sha256:deadbeef",
		StartedAt:   time.Date(2026, 8, 23, 4, 5, 6, 0, time.UTC),
		Deadline:    time.Date(2026, 8, 23, 5, 5, 6, 0, time.UTC),
		Meta:        map[string]string{"runtime": "podman"},
	}
}

// TestHandleSurvivesAProcessRestart is the property the whole table exists
// for: the row is written, every handle onto the database is closed, and a
// fresh one reads back an identical record. Anything less than "identical"
// means a driver rehydrates against partial identity, which is how a sweep
// ends up unable to reattach to a container it can see.
func TestHandleSurvivesAProcessRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	want := sampleRecord()

	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	h, err := NewHandles(db)
	if err != nil {
		t.Fatalf("new handles: %v", err)
	}
	if err := h.PutHandle(want); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The restart.
	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	h2, err := NewHandles(db2)
	if err != nil {
		t.Fatalf("new handles after restart: %v", err)
	}

	got, err := h2.ListHandles("container")
	if err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 handle after restart, got %d", len(got))
	}
	g := got[0]
	if g.HandleID != want.HandleID || g.ExecutorID != want.ExecutorID ||
		g.Driver != want.Driver || g.ExternalID != want.ExternalID ||
		g.ProjectPath != want.ProjectPath || g.TaskID != want.TaskID ||
		g.Image != want.Image {
		t.Fatalf("record did not round-trip:\n got %+v\nwant %+v", g, want)
	}
	if !g.StartedAt.Equal(want.StartedAt) {
		t.Errorf("StartedAt: got %v want %v", g.StartedAt, want.StartedAt)
	}
	// The deadline is what a restart re-arms the timeout from. Losing it turns
	// an adopted workload into an unbounded one that no orphan sweep will ever
	// collect, because an adopted workload is tracked.
	if !g.Deadline.Equal(want.Deadline) {
		t.Errorf("Deadline: got %v want %v", g.Deadline, want.Deadline)
	}
	// Meta is what carries a Kubernetes NetworkPolicy name and a container's
	// runtime; losing it means a rehydrated handle cannot finish cleaning up.
	if g.Meta["runtime"] != "podman" {
		t.Errorf("Meta did not round-trip: got %v", g.Meta)
	}
}

// TestUnboundedHandleRoundTripsAsZero: an untimed workload must not acquire a
// deadline by being written and read back. A zero time that came back as the
// Unix epoch would arm an already-expired timer on adoption and kill every
// deliberately-uncapped run on the first restart.
func TestUnboundedHandleRoundTripsAsZero(t *testing.T) {
	h, _ := openHandles(t)
	rec := sampleRecord()
	rec.Deadline = time.Time{}
	if err := h.PutHandle(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := h.ListHandles("container")
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %d rows, err=%v", len(got), err)
	}
	if !got[0].Deadline.IsZero() {
		t.Fatalf("a zero deadline must round-trip as zero, got %v", got[0].Deadline)
	}
}

// TestListHandlesIsScopedByExecutor: rehydration adopts only its own rows.
// Without this, two container executors configured against one runtime would
// each adopt the other's containers and both would try to reap them.
func TestListHandlesIsScopedByExecutor(t *testing.T) {
	h, _ := openHandles(t)
	mine := sampleRecord()
	theirs := sampleRecord()
	theirs.HandleID = "h-2"
	theirs.ExecutorID = "container-b"
	theirs.ExternalID = "cloop-other-xyz"

	for _, rec := range []executor.HandleRecord{mine, theirs} {
		if err := h.PutHandle(rec); err != nil {
			t.Fatalf("put %s: %v", rec.HandleID, err)
		}
	}

	got, err := h.ListHandles("container")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].HandleID != "h-1" {
		t.Fatalf("scoping failed: got %+v", got)
	}

	// "" is the cross-driver sweep's view and must see both.
	all, err := h.ListHandles("")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("want both rows for the unscoped listing, got %d", len(all))
	}
}

// TestListHandlesIsOldestFirst: the orphan sweep applies a grace period to
// started_at, so dispatch order is the order in which rows age past it.
func TestListHandlesIsOldestFirst(t *testing.T) {
	h, _ := openHandles(t)
	base := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	for i, offset := range []time.Duration{2 * time.Hour, 0, time.Hour} {
		rec := sampleRecord()
		rec.HandleID = string(rune('a' + i))
		rec.StartedAt = base.Add(offset)
		if err := h.PutHandle(rec); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	got, err := h.ListHandles("container")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].StartedAt.Before(got[i-1].StartedAt) {
			t.Fatalf("not oldest-first: %v then %v", got[i-1].StartedAt, got[i].StartedAt)
		}
	}
}

// TestPutHandleIsAnUpsert: rehydration re-writes the rows it adopts so
// updated_at names the adopting control plane, and a Start that retries
// against the same handle id must not fail on a duplicate key.
func TestPutHandleIsAnUpsert(t *testing.T) {
	h, _ := openHandles(t)
	rec := sampleRecord()
	if err := h.PutHandle(rec); err != nil {
		t.Fatalf("first put: %v", err)
	}
	rec.ExternalID = "cloop-myproj-renamed"
	if err := h.PutHandle(rec); err != nil {
		t.Fatalf("second put: %v", err)
	}
	got, err := h.ListHandles("container")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("upsert produced %d rows", len(got))
	}
	if got[0].ExternalID != "cloop-myproj-renamed" {
		t.Fatalf("upsert did not update: %+v", got[0])
	}
}

// TestPutHandleRefusesAnEmptyExternalID is the one failure this table cannot
// tolerate: a row with no external id is visible to a sweep that can never act
// on it, which is worse than no row because it looks like coverage.
func TestPutHandleRefusesAnEmptyExternalID(t *testing.T) {
	h, _ := openHandles(t)
	rec := sampleRecord()
	rec.ExternalID = "   "
	if err := h.PutHandle(rec); err == nil {
		t.Fatal("want an error for a record with no external id")
	}
	if got, _ := h.ListHandles(""); len(got) != 0 {
		t.Fatalf("a refused record must not be stored, got %+v", got)
	}
}

// TestDeleteHandleIsIdempotent: a terminal transition can be recorded twice —
// once by the log pump, once by an explicit reap — and neither call may fail.
func TestDeleteHandleIsIdempotent(t *testing.T) {
	h, _ := openHandles(t)
	if err := h.PutHandle(sampleRecord()); err != nil {
		t.Fatalf("put: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := h.DeleteHandle("h-1"); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	if err := h.DeleteHandle("never-existed"); err != nil {
		t.Fatalf("deleting an absent handle must not fail: %v", err)
	}
	if got, _ := h.ListHandles(""); len(got) != 0 {
		t.Fatalf("want no rows, got %+v", got)
	}
}

// TestGetExecutorHandleReportsAbsence pins the sentinel, so a caller can tell
// "no such handle" from "the database is broken" with errors.Is.
func TestGetExecutorHandleReportsAbsence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.GetExecutorHandle("nope"); !errors.Is(err, statedb.ErrExecutorHandleNotFound) {
		t.Fatalf("want ErrExecutorHandleNotFound, got %v", err)
	}
}

// TestHandleMetaRoundTrip covers the column's two spellings of "empty": the
// column default is '{}' and a caller may write ”, and a reader that
// special-cased only one would return a map with a phantom entry.
func TestHandleMetaRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   map[string]string
	}{
		{"nil", nil},
		{"empty", map[string]string{}},
		{"one", map[string]string{"network_policy": "cloop-h1"}},
		{"several", map[string]string{"a": "1", "b": "2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := statedb.MarshalHandleMeta(tc.in)
			got := statedb.UnmarshalHandleMeta(s)
			if len(tc.in) == 0 {
				if got != nil {
					t.Fatalf("empty metadata must decode to nil, got %v", got)
				}
				return
			}
			for k, v := range tc.in {
				if got[k] != v {
					t.Fatalf("meta[%q]: got %q want %q", k, got[k], v)
				}
			}
		})
	}

	// Corrupt metadata is dropped, not propagated: the extras are advisory,
	// and refusing to rehydrate a running container to protect a label would
	// strand the workload this table exists to recover.
	if got := statedb.UnmarshalHandleMeta("{not json"); got != nil {
		t.Fatalf("unparsable metadata must decode to nil, got %v", got)
	}
}

// TestNilStoreIsRefusedNotPanicked: NewHandles is called on paths where the
// database may be unavailable, and the failure must be an error a caller can
// log rather than a panic that takes the hub down.
func TestNilStoreIsRefusedNotPanicked(t *testing.T) {
	if _, err := NewHandles(nil); err == nil {
		t.Fatal("want an error for a nil database")
	}
	var h *Handles
	if err := h.PutHandle(sampleRecord()); err == nil {
		t.Error("nil receiver must refuse PutHandle")
	}
	if _, err := h.ListHandles(""); err == nil {
		t.Error("nil receiver must refuse ListHandles")
	}
	if err := h.DeleteHandle("x"); err == nil {
		t.Error("nil receiver must refuse DeleteHandle")
	}
}
