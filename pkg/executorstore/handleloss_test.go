package executorstore

// LossOfHandle: what the session store says about a workload the hub follows
// by executor and handle, against real SQLite (Task 20396).

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	db, err := statedb.Open(statedbtest.Path(t))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sched, err := NewScheduler(db)
	if err != nil {
		t.Fatal(err)
	}
	return sched
}

func openHandleSession(t *testing.T, s *Scheduler, id, exID, handle string, attempt int, from string) executor.Session {
	t.Helper()
	sess := executor.Session{
		ID: id, ExecutorID: exID, HandleID: handle, ProjectPath: "/srv/app",
		ClaimToken: "tok-" + id, Attempt: attempt, StartedAt: time.Now(),
		Spec: executor.Spec{WorkDir: "/srv/app", Argv: []string{"cloop", "run"}},
	}
	var err error
	if from == "" {
		err = s.OpenSession(sess)
	} else {
		err = s.OpenRequeuedSession(sess, from)
	}
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestLossOfHandleReadsTheClaim(t *testing.T) {
	s := newTestScheduler(t)

	if loss, err := s.LossOfHandle("edge-1", "h-unknown"); err != nil || loss.SessionID != "" || loss.Claimed() {
		t.Fatalf("an untracked workload = %+v, %v; want nothing known", loss, err)
	}

	running := openHandleSession(t, s, "s-run", "edge-1", "h-run", 1, "")
	if loss, err := s.LossOfHandle("edge-1", "h-run"); err != nil || loss.SessionID != running.ID || loss.Claimed() {
		t.Fatalf("a running session = %+v, %v; want it found and not claimed", loss, err)
	}

	// Claimed with nowhere to go: requeued, no successor.
	stranded := openHandleSession(t, s, "s-lost", "edge-1", "h-lost", 1, "")
	before := time.Now().Add(-time.Second)
	if _, exhausted, err := s.ClaimRequeue(stranded.ID, stranded.ClaimToken, 2, time.Now()); err != nil || exhausted {
		t.Fatalf("claim = %v, %v", exhausted, err)
	}
	loss, err := s.LossOfHandle("edge-1", "h-lost")
	if err != nil || !loss.Claimed() || loss.Replaced() || loss.Exhausted() || loss.ClaimedAt.Before(before) {
		t.Fatalf("a requeued session = %+v, %v; want claimed, not replaced, claimed just now", loss, err)
	}

	// A failover replaced it.
	openHandleSession(t, s, "s-next", "edge-2", "h-next", 2, stranded.ID)
	loss, err = s.LossOfHandle("edge-1", "h-lost")
	if err != nil || !loss.Replaced() || loss.Successor != "s-next" || loss.SuccessorExecutor != "edge-2" || loss.SuccessorHandle != "h-next" {
		t.Fatalf("a replaced session = %+v, %v; want its successor on edge-2", loss, err)
	}

	// Past the cap.
	last := openHandleSession(t, s, "s-last", "edge-3", "h-last", 3, "")
	if _, exhausted, err := s.ClaimRequeue(last.ID, last.ClaimToken, 2, time.Now()); err != nil || !exhausted {
		t.Fatalf("claim past the cap = %v, %v; want exhausted", exhausted, err)
	}
	if loss, err := s.LossOfHandle("edge-3", "h-last"); err != nil || !loss.Claimed() || !loss.Exhausted() || loss.Attempt != 3 {
		t.Fatalf("an exhausted session = %+v, %v; want claimed and exhausted at attempt 3", loss, err)
	}

	// A session that finished is not a loss.
	done := openHandleSession(t, s, "s-done", "edge-1", "h-done", 1, "")
	if err := s.CloseSession(done.ID, statedb.ExecutorSessionFinished, time.Now()); err != nil {
		t.Fatal(err)
	}
	if loss, err := s.LossOfHandle("edge-1", "h-done"); err != nil || loss.Claimed() {
		t.Fatalf("a finished session = %+v, %v; want not claimed", loss, err)
	}
}

// TestRestoreClaimedUndoesAClaimNothingReplaced: a claim the member holding
// the agent disproves is undone in the store — LossOfHandle no longer reads it
// as claimed — and on the record, as executor.failover_refuted naming what the
// claim had recorded. A claim a replacement followed stands, with no row
// (Task 20512).
func TestRestoreClaimedUndoesAClaimNothingReplaced(t *testing.T) {
	s := newTestScheduler(t).WithActor("ui")

	sess := openHandleSession(t, s, "s-live", "edge-1", "h-live", 1, "")
	claimedAt := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	if _, exhausted, err := s.ClaimRequeue(sess.ID, sess.ClaimToken, 2, claimedAt); err != nil || exhausted {
		t.Fatalf("claim = %v, %v", exhausted, err)
	}
	ok, err := s.RestoreClaimed(sess.ID, "edge-1", "the agent says it is running", time.Now())
	if err != nil || !ok {
		t.Fatalf("RestoreClaimed = %v, %v; want restored", ok, err)
	}
	loss, err := s.LossOfHandle("edge-1", "h-live")
	if err != nil || loss.Claimed() || loss.State != statedb.ExecutorSessionRunning {
		t.Fatalf("after the restore the workload reads %+v, %v; want running, not claimed", loss, err)
	}
	if running, err := s.RunningSessions("edge-1"); err != nil || len(running) != 1 || running[0].ID != sess.ID {
		t.Fatalf("running sessions on edge-1 = %+v, %v; want the restored one", running, err)
	}

	rows, _, err := s.db.ListAuditEvents(statedb.AuditFilter{EventType: "executor.failover_refuted"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("refutation rows = %d, %v; want one", len(rows), err)
	}
	row := rows[0]
	if row.Actor != "ui" || row.EntityType != "executor_session" || row.EntityID != sess.ID {
		t.Fatalf("refutation row = %+v, want actor ui on executor_session %s", row, sess.ID)
	}
	for _, want := range []string{`"claimed":"requeued"`, `"executor_id":"edge-1"`, `"handle_id":"h-live"`,
		`"reason":"the agent says it is running"`, `"claimed_at":"` + claimedAt.UTC().Format(time.RFC3339Nano) + `"`} {
		if !strings.Contains(row.Payload, want) {
			t.Errorf("refutation payload %s lacks %s", row.Payload, want)
		}
	}

	// A claim a failover followed with a replacement stands.
	stranded := openHandleSession(t, s, "s-lost", "edge-1", "h-lost", 1, "")
	if _, _, err := s.ClaimRequeue(stranded.ID, stranded.ClaimToken, 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	openHandleSession(t, s, "s-next", "edge-2", "h-next", 2, stranded.ID)
	if ok, err := s.RestoreClaimed(stranded.ID, "edge-1", "the agent says it is running", time.Now()); err != nil || ok {
		t.Fatalf("RestoreClaimed of a replaced session = %v, %v; want the claim to stand", ok, err)
	}
	if loss, _ := s.LossOfHandle("edge-1", "h-lost"); !loss.Replaced() {
		t.Fatalf("the replaced session reads %+v after a refused restore", loss)
	}
	if rows, _, _ := s.db.ListAuditEvents(statedb.AuditFilter{EventType: "executor.failover_refuted"}); len(rows) != 1 {
		t.Fatalf("a refused restore wrote a refutation row (%d rows)", len(rows))
	}
	if _, err := s.RestoreClaimed("s-ghost", "edge-1", "x", time.Now()); err == nil {
		t.Error("RestoreClaimed of an unknown session succeeded, want an error")
	}
}
