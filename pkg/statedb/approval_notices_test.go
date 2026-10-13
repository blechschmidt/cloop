package statedb

import (
	"errors"
	"testing"
	"time"
)

// TestApprovalNoticesAreRecordedOnce: a notice key records one row however
// many times it is offered, so a moment noticed by two passes — or two
// members — is sent once.
func TestApprovalNoticesAreRecordedOnce(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	first, err := db.InsertApprovalNotice("request.filed:req_1", "request.filed", `{"event":"request.filed"}`, at)
	if err != nil || !first {
		t.Fatalf("first insert = %v, %v; want recorded", first, err)
	}
	again, err := db.InsertApprovalNotice("request.filed:req_1", "request.filed", `{"other":true}`, at.Add(time.Minute))
	if err != nil || again {
		t.Fatalf("second insert = %v, %v; want ignored", again, err)
	}
	if _, err := db.InsertApprovalNotice("request.reminder:req_1", "request.reminder", `{}`, at); err != nil {
		t.Fatal(err)
	}
	got, err := db.ApprovalNoticesAfter(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Key != "request.filed:req_1" || got[0].Payload != `{"event":"request.filed"}` ||
		!got[0].CreatedAt.Equal(at) || got[1].ID <= got[0].ID {
		t.Fatalf("outbox = %+v", got)
	}
	if ok, _ := db.ApprovalNoticeRecorded("request.reminder:req_1"); !ok {
		t.Fatal("a recorded notice is reported absent")
	}
}

// TestApprovalNoticeIDsAreNeverReused: a pruned outbox keeps counting, so a
// cursor never finds a new notice under an id it has already passed.
func TestApprovalNoticeIDsAreNeverReused(t *testing.T) {
	db := openTestDB(t)
	old := time.Now().Add(-60 * 24 * time.Hour)
	for _, k := range []string{"a", "b", "c"} {
		if _, err := db.InsertApprovalNotice("request.filed:"+k, "request.filed", "{}", old); err != nil {
			t.Fatal(err)
		}
	}
	head, _ := db.MaxApprovalNoticeID()
	// What is still waiting keeps its row, however old: the row is what stops
	// the next leader announcing it again.
	waiting := map[string]bool{"request.filed:b": true}
	if n, err := db.PruneApprovalNotices(time.Now().Add(-30*24*time.Hour), head, waiting); err != nil || n != 2 {
		t.Fatalf("prune = %d, %v; want the two that no longer wait", n, err)
	}
	if ok, _ := db.ApprovalNoticeRecorded("request.filed:b"); !ok {
		t.Fatal("the prune removed the notice of something still waiting")
	}
	if n, err := db.PruneApprovalNotices(time.Now().Add(-30*24*time.Hour), head, nil); err != nil || n != 1 {
		t.Fatalf("prune once it no longer waits = %d, %v; want the last one", n, err)
	}
	if after, _ := db.MaxApprovalNoticeID(); after != head {
		t.Fatalf("the newest id after a prune is %d, want %d (the sequence, not the empty table)", after, head)
	}
	if _, err := db.InsertApprovalNotice("request.filed:d", "request.filed", "{}", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ApprovalNoticesAfter(head, 10)
	if len(got) != 1 || got[0].ID <= head {
		t.Fatalf("the notice after a prune got id %+v, at or below %d", got, head)
	}
	// A prune never removes what a cursor has not passed.
	if n, _ := db.PruneApprovalNotices(time.Now().Add(time.Hour), head, nil); n != 0 {
		t.Fatalf("pruned %d notice(s) above the floor", n)
	}
}

// TestApprovalNotifyCursorMovesOnlyFromWhereItWasRead: a leader that read a
// cursor at one position cannot move it once another has.
func TestApprovalNotifyCursorMovesOnlyFromWhereItWasRead(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	c, err := db.InitApprovalNotifyCursor("ops", 7, now)
	if err != nil || c.AckedID != 7 {
		t.Fatalf("init = %+v, %v", c, err)
	}
	if c, _ := db.InitApprovalNotifyCursor("ops", 0, now); c.AckedID != 7 {
		t.Fatalf("a second init reset the cursor to %d", c.AckedID)
	}
	next := now.Add(time.Minute)
	if err := db.NoteApprovalNotifyFailure("ops", 7, "503", next, now); err != nil {
		t.Fatal(err)
	}
	c, _, _ = db.ApprovalNotifyCursorFor("ops")
	if c.Failures != 1 || !c.NextAttemptAt.Equal(next) || c.LastError != "503" {
		t.Fatalf("after a failure = %+v", c)
	}
	if err := db.AdvanceApprovalNotifyCursor("ops", ApprovalNotifyAdvance{From: 7, To: 8, Delivered: true, At: now}); err != nil {
		t.Fatal(err)
	}
	c, _, _ = db.ApprovalNotifyCursorFor("ops")
	if c.AckedID != 8 || c.Delivered != 1 || c.Failures != 0 || !c.NextAttemptAt.IsZero() {
		t.Fatalf("after a delivery = %+v", c)
	}
	err = db.AdvanceApprovalNotifyCursor("ops", ApprovalNotifyAdvance{From: 7, To: 9, Dropped: true, Error: "x", At: now})
	if !errors.Is(err, ErrApprovalNotifyCursorMoved) {
		t.Fatalf("a stale advance = %v, want ErrApprovalNotifyCursorMoved", err)
	}
	if err := db.DeleteApprovalNotifyCursor("ops"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.ApprovalNotifyCursorFor("ops"); ok {
		t.Fatal("a deleted cursor is still there")
	}
}
