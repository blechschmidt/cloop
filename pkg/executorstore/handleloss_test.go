package executorstore

// LossOfHandle: what the session store says about a workload the hub follows
// by executor and handle, against real SQLite (Task 20396).

import (
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
