package statedb

import (
	"errors"
	"testing"
	"time"
)

// TestCISessionsMoveOnlyFromTheHolder covers the rows a CI relay session
// outlives its hub process with (Task 20390): the holder's writes name the
// holder they expect, two processes racing to restore one session cannot both
// win, a closed session can be neither taken over nor reopened, and an id is
// never recorded twice.
func TestCISessionsMoveOnlyFromTheHolder(t *testing.T) {
	db := openTestDB(t)
	issued := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	row := CISessionRow{
		SessionID: "ci_a", TokenSHA256: "ab12", RuleID: "rule_1", Holder: "hub_old", Instance: "8081",
		Provenance: `{"repository":"acme/tool"}`, Policy: `{"models":["claude-sonnet-*"]}`,
		IssuedAt: issued, ExpiresAt: issued.Add(time.Hour),
	}
	if err := db.InsertCISession(row); err != nil {
		t.Fatalf("InsertCISession: %v", err)
	}
	if err := db.InsertCISession(row); err == nil {
		t.Fatal("a second session under the same id was recorded")
	}
	got, err := db.GetCISession("ci_a")
	if err != nil {
		t.Fatalf("GetCISession: %v", err)
	}
	if got.TokenSHA256 != "ab12" || got.RuleID != "rule_1" || got.Holder != "hub_old" || got.Instance != "8081" ||
		got.Policy != row.Policy ||
		got.Provenance != row.Provenance || got.Counters != "{}" || !got.IssuedAt.Equal(issued) ||
		!got.ExpiresAt.Equal(row.ExpiresAt) || !got.Open() {
		t.Fatalf("round trip = %+v, want %+v", got, row)
	}
	if _, err := db.GetCISession("ci_none"); !errors.Is(err, ErrCISessionNotFound) {
		t.Fatalf("an unknown session = %v, want ErrCISessionNotFound", err)
	}

	used := issued.Add(5 * time.Minute)
	if ok, err := db.CheckpointCISession("ci_a", "hub_other", `{"requests":3}`, used); err != nil || ok {
		t.Fatalf("a non-holder's checkpoint = %v, %v; want refused", ok, err)
	}
	if ok, err := db.CheckpointCISession("ci_a", "hub_old", `{"requests":3}`, used); err != nil || !ok {
		t.Fatalf("the holder's checkpoint = %v, %v", ok, err)
	}

	// Two processes receive the job's next call; one restores the session.
	if ok, err := db.TakeCISession("ci_a", "hub_old", "hub_new", "8082"); err != nil || !ok {
		t.Fatalf("first takeover = %v, %v", ok, err)
	}
	if ok, err := db.TakeCISession("ci_a", "hub_old", "hub_late", "8083"); err != nil || ok {
		t.Fatalf("second takeover from the same holder = %v, %v; want refused", ok, err)
	}
	if ok, _ := db.CheckpointCISession("ci_a", "hub_old", `{}`, used); ok {
		t.Fatal("the previous holder checkpointed a session it lost")
	}
	if ok, _ := db.CloseCISession("ci_a", "hub_old", used, "lost", ""); ok {
		t.Fatal("the previous holder closed a session it lost")
	}
	narrowed := issued.Add(30 * time.Minute)
	if ok, err := db.NarrowCISession("ci_a", "hub_new", "8085", `{"models":["claude-haiku-*"]}`, narrowed); err != nil || !ok {
		t.Fatalf("the new holder's narrowing = %v, %v", ok, err)
	}
	got, _ = db.GetCISession("ci_a")
	if got.Holder != "hub_new" || got.Instance != "8085" || got.Counters != `{"requests":3}` || !got.LastUsedAt.Equal(used) ||
		got.Policy != `{"models":["claude-haiku-*"]}` || !got.ExpiresAt.Equal(narrowed) {
		t.Fatalf("after the takeover = %+v", got)
	}

	if ok, err := db.CloseCISession("ci_a", "hub_new", narrowed, "expired", `{"requests":4}`); err != nil || !ok {
		t.Fatalf("the holder's close = %v, %v", ok, err)
	}
	if ok, _ := db.TakeCISession("ci_a", "hub_new", "hub_after", "8084"); ok {
		t.Fatal("a closed session was taken over")
	}
	if ok, _ := db.CloseCISession("ci_a", "hub_new", narrowed, "again", ""); ok {
		t.Fatal("a closed session was closed twice")
	}
	got, _ = db.GetCISession("ci_a")
	if got.Open() || got.CloseReason != "expired" || got.Counters != `{"requests":4}` {
		t.Fatalf("closed = %+v", got)
	}

	if ok, _ := db.DeleteCISession("ci_a", "hub_other"); ok {
		t.Fatal("a process deleted a record another one holds")
	}
	if ok, err := db.DeleteCISession("ci_a", "hub_new"); err != nil || !ok {
		t.Fatalf("the holder's delete = %v, %v", ok, err)
	}
	if _, err := db.GetCISession("ci_a"); !errors.Is(err, ErrCISessionNotFound) {
		t.Fatalf("after the delete = %v", err)
	}
}

// TestCISessionsCloseByRuleWhoeverHoldsThem: an operator's change to a rule
// ends every open session it minted — the one a live process serves and the
// one no process serves right now — and leaves the other rules' sessions and
// the already closed ones alone.
func TestCISessionsCloseByRuleWhoeverHoldsThem(t *testing.T) {
	db := openTestDB(t)
	issued := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	for _, r := range []CISessionRow{
		{SessionID: "s1", TokenSHA256: "h1", RuleID: "r1", Holder: "hub_live"},
		{SessionID: "s2", TokenSHA256: "h2", RuleID: "r1", Holder: "hub_dead"},
		{SessionID: "s3", TokenSHA256: "h3", RuleID: "r2", Holder: "hub_live"},
		{SessionID: "s4", TokenSHA256: "h4", RuleID: "r1", Holder: "hub_live"},
	} {
		r.IssuedAt, r.ExpiresAt = issued, issued.Add(time.Hour)
		if err := db.InsertCISession(r); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := db.CloseCISession("s4", "hub_live", issued, "expired", ""); !ok {
		t.Fatal("close s4")
	}
	closed, err := db.CloseCISessionsForRule("r1", issued.Add(time.Minute), "rule deleted")
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 2 || closed[0].SessionID != "s1" || closed[1].SessionID != "s2" || !closed[0].Open() {
		t.Fatalf("closed for r1 = %+v, want s1 and s2 as they were", closed)
	}
	for id, want := range map[string]string{"s1": "rule deleted", "s2": "rule deleted", "s3": "", "s4": "expired"} {
		got, _ := db.GetCISession(id)
		if got.CloseReason != want {
			t.Errorf("%s close reason = %q, want %q", id, got.CloseReason, want)
		}
	}
	open, err := db.ListCISessions(CISessionFilter{OpenOnly: true})
	if err != nil || len(open) != 1 || open[0].SessionID != "s3" {
		t.Fatalf("open after the rule's close = %+v, %v", open, err)
	}
	if byRule, _ := db.ListCISessions(CISessionFilter{RuleID: "r1"}); len(byRule) != 3 {
		t.Fatalf("rule r1's records = %d, want 3", len(byRule))
	}
	if ids, err := db.OpenCISessionIDsHeldBy("hub_live"); err != nil || len(ids) != 1 || ids[0] != "s3" {
		t.Fatalf("open sessions hub_live holds = %v, %v; want s3 alone", ids, err)
	}
	if ids, err := db.OpenCISessionIDsHeldBy("hub_dead"); err != nil || len(ids) != 0 {
		t.Fatalf("open sessions hub_dead holds = %v, %v; want none", ids, err)
	}
}
