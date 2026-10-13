package statedb

import (
	"errors"
	"testing"
	"time"
)

// A cursor moves only from the position it was read at: a leader that lost
// its lease mid-send cannot move a cursor its successor already moved, and an
// acknowledgement clears the failure record (Task 20426).
func TestAuditForwardCursorMovesByCompareAndSwap(t *testing.T) {
	db := openFresh(t)
	now := time.Now().UTC()
	c, err := db.InitAuditForwardCursor(AuditForwardCursor{
		Sink: "siem", Chain: "/hub/.cloop/state.db", Source: "control-plane", Dir: "/hub",
		AckedID: 0, AckedHash: AuditGenesisHash,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.AckedID != 0 || c.AckedHash != AuditGenesisHash || c.Retired() {
		t.Fatalf("new cursor = %+v", c)
	}
	// A second leader creating the same cursor gets the stored one, untouched.
	if err := db.AdvanceAuditForwardCursor("siem", c.Chain, AuditForwardAdvance{
		FromID: 0, FromHash: AuditGenesisHash, ToID: 10, ToHash: "h10", ToRowAt: now, Delivered: 10, At: now,
	}); err != nil {
		t.Fatal(err)
	}
	again, err := db.InitAuditForwardCursor(AuditForwardCursor{
		Sink: "siem", Chain: c.Chain, Source: "control-plane", Dir: "/hub", AckedID: 0, AckedHash: AuditGenesisHash,
	}, now)
	if err != nil || again.AckedID != 10 || again.Delivered != 10 {
		t.Fatalf("re-init = %+v, %v; want the advanced cursor kept", again, err)
	}

	// A stale leader advancing from where the cursor used to be is refused.
	err = db.AdvanceAuditForwardCursor("siem", c.Chain, AuditForwardAdvance{
		FromID: 0, FromHash: AuditGenesisHash, ToID: 20, ToHash: "h20", Delivered: 20, At: now,
	})
	if !errors.Is(err, ErrAuditForwardCursorMoved) {
		t.Fatalf("a stale advance = %v, want ErrAuditForwardCursorMoved", err)
	}

	if err := db.NoteAuditForwardFailure("siem", c.Chain, "connection refused", now); err != nil {
		t.Fatal(err)
	}
	failed, _, _ := db.AuditForwardCursorFor("siem", c.Chain)
	if failed.LastError != "connection refused" || failed.Failures != 1 {
		t.Fatalf("after a failure = %+v", failed)
	}
	if err := db.AdvanceAuditForwardCursor("siem", c.Chain, AuditForwardAdvance{
		FromID: 10, FromHash: "h10", ToID: 15, ToHash: "h15", Delivered: 5, At: now,
	}); err != nil {
		t.Fatal(err)
	}
	ok, _, _ := db.AuditForwardCursorFor("siem", c.Chain)
	if ok.LastError != "" || ok.Failures != 0 || ok.Delivered != 15 {
		t.Fatalf("after an acknowledgement = %+v; the failure should be cleared", ok)
	}
	if len(ok.Marks) != 1 || ok.Marks[0] != (AuditForwardMark{ID: 10, Hash: "h10"}) {
		t.Fatalf("marks = %+v, want the position it advanced from", ok.Marks)
	}
}

// The hold on a chain is its slowest live cursor; retired cursors hold
// nothing, and a retired cursor's sink coming back resumes it.
func TestAuditForwardHoldIsTheSlowestLiveCursor(t *testing.T) {
	db := openFresh(t)
	now := time.Now().UTC()
	chain := "/p/.cloop/state.db"
	for _, s := range []struct {
		sink string
		at   int64
	}{{"fast", 90}, {"slow", 12}, {"other-chain", 1}} {
		ch := chain
		if s.sink == "other-chain" {
			ch = "/q/.cloop/state.db"
		}
		if _, err := db.InitAuditForwardCursor(AuditForwardCursor{Sink: s.sink, Chain: ch, AckedID: s.at, AckedHash: "x"}, now); err != nil {
			t.Fatal(err)
		}
	}
	h, ok, err := db.AuditForwardHoldFor(chain)
	if err != nil || !ok || h.Sink != "slow" || h.ThroughID != 12 || len(h.Sinks) != 2 {
		t.Fatalf("hold = %+v, %v, %v; want slow at 12 of two sinks", h, ok, err)
	}
	retired, restored, err := db.SyncAuditForwardCursors([]AuditForwardKey{{Sink: "fast", Chain: chain}}, now)
	if err != nil || retired != 2 || restored != 0 {
		t.Fatalf("sync retired %d, restored %d, %v; want slow and other-chain retired", retired, restored, err)
	}
	if h, _, _ := db.AuditForwardHoldFor(chain); h.Sink != "fast" || h.ThroughID != 90 {
		t.Fatalf("hold after retiring slow = %+v, want fast", h)
	}
	// Nothing differs: nothing is written.
	if r, s, err := db.SyncAuditForwardCursors([]AuditForwardKey{{Sink: "fast", Chain: chain}}, now); err != nil || r+s != 0 {
		t.Fatalf("an unchanged sync wrote %d+%d, %v", r, s, err)
	}
	// Live again: back in service where it was, whatever a forwarder cached.
	_, restored, err = db.SyncAuditForwardCursors([]AuditForwardKey{{Sink: "fast", Chain: chain}, {Sink: "slow", Chain: chain}}, now)
	if err != nil || restored != 1 {
		t.Fatalf("restored %d, %v; want slow", restored, err)
	}
	back, _, _ := db.AuditForwardCursorFor("slow", chain)
	if back.Retired() || back.AckedID != 12 {
		t.Fatalf("returning sink = %+v; want its cursor back in service where it was", back)
	}
	if err := db.AdvanceAuditForwardCursor("gone", chain, AuditForwardAdvance{}); !errors.Is(err, ErrAuditForwardCursorMissing) {
		t.Errorf("advancing a cursor that does not exist = %v, want ErrAuditForwardCursorMissing", err)
	}
	if _, ok, _ := db.AuditForwardHoldFor("/nowhere"); ok {
		t.Error("a chain no cursor names is held")
	}
}

// Marks thin to roughly exponential spacing below the head: dense where a
// resume is likely, reaching far back in a few dozen entries.
func TestAuditForwardMarksThinExponentially(t *testing.T) {
	var marks []AuditForwardMark
	for id := int64(1); id <= 1_000_000; id *= 2 {
		for step := id; step < id*2 && step <= 1_000_000; step += max(id/64, 1) {
			marks = append(marks, AuditForwardMark{ID: step, Hash: "h"})
		}
	}
	thin := ThinAuditForwardMarks(marks, 1_000_001)
	if len(thin) > auditForwardMarksMax {
		t.Fatalf("%d marks survive, bound %d", len(thin), auditForwardMarksMax)
	}
	for i := 1; i < len(thin); i++ {
		if thin[i].ID <= thin[i-1].ID {
			t.Fatalf("marks not ascending: %v", thin)
		}
	}
	// One mark per power-of-two band of distance from the head: the farthest
	// is the newest mark of the widest band, half the chain back, and the
	// count is about log2 of the distance covered.
	if back := int64(1_000_001) - thin[0].ID; back < 1_000_001/4 {
		t.Errorf("the oldest surviving mark is %d, only %d rows back; the ladder should reach half the chain", thin[0].ID, back)
	}
	if len(thin) > 4+21 {
		t.Errorf("%d marks survive; one per band and the newest four is at most 25", len(thin))
	}
	if got := ThinAuditForwardMarks([]AuditForwardMark{{ID: 5, Hash: "a"}, {ID: 9, Hash: "b"}}, 7); len(got) != 1 || got[0].ID != 5 {
		t.Errorf("marks at or past the head must be dropped: %v", got)
	}
}

// PlanAuditPruneThrough bounds the prefix by id as well as by age, and a
// bound below the first id leaves nothing eligible.
func TestPlanAuditPruneThroughBoundsThePrefix(t *testing.T) {
	db := openFresh(t)
	for i := 0; i < 10; i++ {
		if err := db.AppendAuditEvent(&AuditEvent{EventType: "task.upsert"}); err != nil {
			t.Fatal(err)
		}
	}
	future := time.Now().Add(time.Hour)
	all, err := db.PlanAuditPrune(future)
	if err != nil || all.ThroughID != 10 || all.Count != 10 {
		t.Fatalf("unbounded plan = %+v, %v", all, err)
	}
	bounded, err := db.PlanAuditPruneThrough(future, 4)
	if err != nil || bounded.ThroughID != 4 || bounded.Count != 4 || bounded.Remaining != 6 {
		t.Fatalf("plan bounded at 4 = %+v, %v", bounded, err)
	}
	none, err := db.PlanAuditPruneThrough(future, 0)
	if err != nil || none.Count != 0 {
		t.Fatalf("plan bounded at 0 = %+v, %v; a sink that acknowledged nothing holds everything", none, err)
	}
}
