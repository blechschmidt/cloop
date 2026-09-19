package statedb

// Tests for the two per-executor policy tables (Task 20310): the resource
// ceiling and the access list.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestExecutorResourceLimit_RoundTrip(t *testing.T) {
	db := openTestDB(t)

	// Absent means uncapped, and is not an error — the state of every executor
	// before an admin sets one, which is what makes the migration a no-op.
	if c, ok, err := db.ExecutorResourceCeiling("edge-1"); err != nil || ok || !c.IsZero() {
		t.Fatalf("unconfigured executor: ceiling=%+v ok=%v err=%v; want zero,false,nil", c, ok, err)
	}

	want := executor.ResourceCeiling{CPUMillis: 2000, MemoryMB: 4096, DiskMB: 20480, PIDs: 512}
	if err := db.SetExecutorResourceLimit("edge-1", want, "admin@example.com"); err != nil {
		t.Fatalf("SetExecutorResourceLimit: %v", err)
	}

	got, ok, err := db.ExecutorResourceCeiling("edge-1")
	if err != nil || !ok {
		t.Fatalf("read back: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}

	rows, err := db.ListExecutorResourceLimits()
	if err != nil {
		t.Fatalf("ListExecutorResourceLimits: %v", err)
	}
	if len(rows) != 1 || rows[0].ExecutorID != "edge-1" {
		t.Fatalf("list = %+v, want one row for edge-1", rows)
	}
	if rows[0].SetBy != "admin@example.com" {
		t.Errorf("set_by = %q, want the identity that wrote it", rows[0].SetBy)
	}
	if rows[0].SetAt.IsZero() {
		t.Error("set_at is zero; provenance must record when")
	}
}

func TestExecutorResourceLimit_ReplacesRatherThanAccumulates(t *testing.T) {
	db := openTestDB(t)

	if err := db.SetExecutorResourceLimit("edge-1",
		executor.ResourceCeiling{MemoryMB: 4096, PIDs: 512}, "a@x"); err != nil {
		t.Fatalf("first set: %v", err)
	}
	// The second write names only memory. The whole record is replaced, so the
	// PID cap goes away — an admin who cleared that field meant to clear it.
	if err := db.SetExecutorResourceLimit("edge-1",
		executor.ResourceCeiling{MemoryMB: 1024}, "b@x"); err != nil {
		t.Fatalf("second set: %v", err)
	}

	got, _, err := db.ExecutorResourceCeiling("edge-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.MemoryMB != 1024 || got.PIDs != 0 {
		t.Errorf("got %+v, want memory 1024 and pids cleared", got)
	}
}

func TestExecutorResourceLimit_RejectsANegativeCeiling(t *testing.T) {
	db := openTestDB(t)
	// A negative cap is the runtimes' "unlimited" sentinel. A ceiling that
	// silently meant unlimited is the one thing a ceiling may never mean, so
	// this is refused at the last point before it becomes durable.
	err := db.SetExecutorResourceLimit("edge-1", executor.ResourceCeiling{MemoryMB: -1}, "a@x")
	if err == nil {
		t.Fatal("a negative ceiling was accepted")
	}
	if !strings.Contains(err.Error(), "memory_mb") {
		t.Errorf("error %q does not name the offending field", err)
	}
}

func TestExecutorResourceLimit_ClearIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := db.ClearExecutorResourceLimit("never-set"); err != nil {
		t.Errorf("clearing an uncapped executor errored: %v", err)
	}
	if err := db.SetExecutorResourceLimit("edge-1",
		executor.ResourceCeiling{MemoryMB: 2048}, "a@x"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := db.ClearExecutorResourceLimit("edge-1"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok, _ := db.ExecutorResourceCeiling("edge-1"); ok {
		t.Error("the ceiling survived a clear")
	}
}

// ─── audience ────────────────────────────────────────────────────────────────

func TestExecutorAudience_EmptyMeansUnrestricted(t *testing.T) {
	db := openTestDB(t)
	got, err := db.ExecutorAudience("edge-1")
	if err != nil {
		t.Fatalf("ExecutorAudience: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a never-restricted executor returned %+v, want no rows", got)
	}
}

func TestExecutorAudience_RoundTripAndIdempotentAdd(t *testing.T) {
	db := openTestDB(t)

	if err := db.AddExecutorAudience("edge-1", "group", "platform-team", "admin@x"); err != nil {
		t.Fatalf("AddExecutorAudience: %v", err)
	}
	// Re-admitting the same principal refreshes provenance rather than
	// producing a second row, so a double-clicked button cannot leave a
	// duplicate that one DELETE would only half-remove.
	if err := db.AddExecutorAudience("edge-1", "group", "platform-team", "other@x"); err != nil {
		t.Fatalf("re-add: %v", err)
	}

	got, err := db.ExecutorAudience("edge-1")
	if err != nil {
		t.Fatalf("ExecutorAudience: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1 after re-admitting the same principal: %+v", len(got), got)
	}
	if got[0].Kind != "group" || got[0].Value != "platform-team" {
		t.Errorf("row = %+v, want group/platform-team", got[0])
	}
	if got[0].AddedBy != "other@x" {
		t.Errorf("added_by = %q, want the most recent writer", got[0].AddedBy)
	}
	if got[0].AddedAt.IsZero() {
		t.Error("added_at is zero; provenance must record when")
	}
}

func TestExecutorAudience_RejectsUnknownKindAndEmptyValue(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddExecutorAudience("edge-1", "wardrobe", "narnia", "a@x"); err == nil {
		t.Error("an unrecognised principal kind was stored")
	}
	if err := db.AddExecutorAudience("edge-1", "group", "   ", "a@x"); err == nil {
		t.Error("a blank principal value was stored")
	}
	// A blank value is the dangerous one: stored, it would be a list entry that
	// matches an identity whose provider emits an empty group — "restricted"
	// that admits strangers.
	if got, _ := db.ExecutorAudience("edge-1"); len(got) != 0 {
		t.Errorf("rejected writes still produced rows: %+v", got)
	}
}

func TestExecutorAudience_RemoveIsIdempotentAndScoped(t *testing.T) {
	db := openTestDB(t)
	for _, v := range []string{"platform-team", "sre"} {
		if err := db.AddExecutorAudience("edge-1", "group", v, "a@x"); err != nil {
			t.Fatalf("add %s: %v", v, err)
		}
	}
	if err := db.AddExecutorAudience("edge-2", "group", "platform-team", "a@x"); err != nil {
		t.Fatalf("add on edge-2: %v", err)
	}

	// Withdrawing someone absent is a no-op, not an error.
	if err := db.RemoveExecutorAudience("edge-1", "group", "nobody"); err != nil {
		t.Errorf("withdrawing an absent principal errored: %v", err)
	}
	if err := db.RemoveExecutorAudience("edge-1", "group", "sre"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	got, _ := db.ExecutorAudience("edge-1")
	if len(got) != 1 || got[0].Value != "platform-team" {
		t.Errorf("edge-1 = %+v, want platform-team alone", got)
	}
	// The other executor's identical entry must be untouched: an access list
	// that leaked across devices would be the worst bug this table could have.
	other, _ := db.ExecutorAudience("edge-2")
	if len(other) != 1 {
		t.Errorf("edge-2 = %+v, want its own entry untouched", other)
	}
}

func TestExecutorAudience_ClearRemovesEverythingForOneExecutor(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddExecutorAudience("edge-1", "group", "a", "x@x"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := db.AddExecutorAudience("edge-2", "group", "a", "x@x"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := db.ClearExecutorAudience("edge-1"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got, _ := db.ExecutorAudience("edge-1"); len(got) != 0 {
		t.Errorf("edge-1 still restricted: %+v", got)
	}
	if got, _ := db.ExecutorAudience("edge-2"); len(got) != 1 {
		t.Errorf("clear reached edge-2: %+v", got)
	}
}

func TestAllExecutorAudiences_GroupsByExecutor(t *testing.T) {
	db := openTestDB(t)
	for _, e := range []struct{ id, v string }{
		{"edge-1", "platform"}, {"edge-1", "sre"}, {"edge-2", "data"},
	} {
		if err := db.AddExecutorAudience(e.id, "group", e.v, "a@x"); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	all, err := db.AllExecutorAudiences()
	if err != nil {
		t.Fatalf("AllExecutorAudiences: %v", err)
	}
	if len(all["edge-1"]) != 2 || len(all["edge-2"]) != 1 {
		t.Errorf("grouping = %+v, want 2 for edge-1 and 1 for edge-2", all)
	}
}

// TestExecutorAudienceEntry_MemberMatchesAuthz ties the storage row to the gate
// predicate. They are in different packages and a drift between them would be a
// list that displays correctly and admits the wrong people.
func TestExecutorAudienceEntry_MemberMatchesAuthz(t *testing.T) {
	e := ExecutorAudienceEntry{Kind: "group", Value: "/platform-team"}
	m := e.Member()
	if m.Value != "platform-team" {
		t.Errorf("Member() = %+v, want the leading slash normalised away", m)
	}
}
