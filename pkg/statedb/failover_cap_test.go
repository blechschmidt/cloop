package statedb

// Tests for the storage half of the failover cap and the node-killer
// quarantine (Task 20391).

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func openCapSession(t *testing.T, db *DB, id string, attempt int, from string) {
	t.Helper()
	if err := db.OpenExecutorSession(ExecutorSessionRow{
		ID: id, ExecutorID: "edge-" + id, ClaimToken: "tok-" + id, Attempt: attempt,
		RequeuedFrom: from, ProjectPath: "/srv/app",
	}); err != nil {
		t.Fatalf("OpenExecutorSession(%s): %v", id, err)
	}
}

// TestClaimAppliesTheFailoverCap: the claim's one UPDATE decides requeued or
// exhausted from the stored attempt — at the cap a session may still be
// re-dispatched, one past it may not.
func TestClaimAppliesTheFailoverCap(t *testing.T) {
	cases := []struct {
		attempt, max int
		want         string
	}{
		{1, 2, ExecutorSessionRequeued},          // original dispatch, two re-dispatches left
		{2, 2, ExecutorSessionRequeued},          // one re-dispatch used, one left
		{3, 2, ExecutorSessionFailoverExhausted}, // two used: past the cap
		{9, 2, ExecutorSessionFailoverExhausted},
		{1, 0, ExecutorSessionFailoverExhausted},  // re-dispatch off
		{1, -5, ExecutorSessionFailoverExhausted}, // a bad cap is no re-dispatch, never no cap
		{11, 10, ExecutorSessionFailoverExhausted},
		{10, 10, ExecutorSessionRequeued},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("attempt%d_max%d", tc.attempt, tc.max), func(t *testing.T) {
			db := openTestDB(t)
			openCapSession(t, db, "s", tc.attempt, "")
			got, err := db.ClaimExecutorSessionRequeue("s", "tok-s", "tok-next", tc.max, time.Now())
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			if got.State != tc.want {
				t.Fatalf("state = %q, want %q", got.State, tc.want)
			}
			if got.ClaimToken != "tok-next" {
				t.Errorf("the claim did not rotate the token: %q", got.ClaimToken)
			}
			if got.Attempt != tc.attempt {
				t.Errorf("the claim changed the attempt to %d; it records the dispatch, not the next one", got.Attempt)
			}
			// Exhausted or not, the claim is spent: nobody can claim it again.
			if _, err := db.ClaimExecutorSessionRequeue("s", "tok-next", "tok-3", 99, time.Now()); !errors.Is(err, ErrExecutorSessionClaimLost) {
				t.Fatalf("second claim = %v, want ErrExecutorSessionClaimLost", err)
			}
		})
	}
}

// TestRacingClaimsAtTheCapAgree: eight claimants with different caps race for
// one session that sits exactly past the strictest of them. One wins, and the
// session's terminal state is the winner's decision — the record cannot say
// requeued for one claimant and exhausted for another.
func TestRacingClaimsAtTheCapAgree(t *testing.T) {
	db := openTestDB(t)
	openCapSession(t, db, "hot", 3, "")

	const n = 8
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		rows  = make([]ExecutorSessionRow, n)
		errs  = make([]error, n)
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Half the members run with the default cap, half with a raised
			// one — as two hub instances with different overlays would.
			max := 2
			if i%2 == 1 {
				max = 5
			}
			rows[i], errs[i] = db.ClaimExecutorSessionRequeue("hot", "tok-hot", fmt.Sprintf("tok-%d", i), max, time.Now())
		}(i)
	}
	close(start)
	wg.Wait()

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("claimants %d and %d both won", winner, i)
			}
			winner = i
		case !errors.Is(err, ErrExecutorSessionClaimLost):
			t.Fatalf("claimant %d: %v", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("nobody won the claim")
	}
	stored, err := db.GetExecutorSession("hot")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != rows[winner].State {
		t.Fatalf("stored state %q differs from the winner's decision %q", stored.State, rows[winner].State)
	}
	want := ExecutorSessionFailoverExhausted
	if winner%2 == 1 {
		want = ExecutorSessionRequeued
	}
	if stored.State != want {
		t.Fatalf("winner %d (cap %d) recorded %q, want %q", winner, map[bool]int{true: 5, false: 2}[winner%2 == 1], stored.State, want)
	}
}

// TestCloseLeavesAClaimedSessionAlone: the workload's watcher notices a lost
// node's end long after the claim, and its close must not turn
// failover_exhausted back into failed.
func TestCloseLeavesAClaimedSessionAlone(t *testing.T) {
	db := openTestDB(t)
	openCapSession(t, db, "x", 3, "")
	if _, err := db.ClaimExecutorSessionRequeue("x", "tok-x", "tok-y", 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.CloseExecutorSession("x", ExecutorSessionFailed, time.Now()); err != nil {
		t.Fatalf("closing an already-claimed session: %v, want a no-op", err)
	}
	got, _ := db.GetExecutorSession("x")
	if got.State != ExecutorSessionFailoverExhausted {
		t.Fatalf("state = %q after a late close, want %q kept", got.State, ExecutorSessionFailoverExhausted)
	}
	if err := db.CloseExecutorSession("ghost", ExecutorSessionFailed, time.Now()); !errors.Is(err, ErrExecutorSessionNotFound) {
		t.Fatalf("closing an unknown session = %v, want ErrExecutorSessionNotFound", err)
	}
}

// TestExecutorSessionChainWalksBackToTheOriginalDispatch: a failover names
// every node the run was lost on by walking requeued_from.
func TestExecutorSessionChainWalksBackToTheOriginalDispatch(t *testing.T) {
	db := openTestDB(t)
	openCapSession(t, db, "a", 1, "")
	openCapSession(t, db, "b", 2, "a")
	openCapSession(t, db, "c", 3, "b")

	chain, err := db.ExecutorSessionChain("c")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range chain {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "a,b,c" {
		t.Fatalf("chain = %v, want a,b,c oldest first", ids)
	}
	if next, ok, err := db.ExecutorSessionSuccessor("a"); err != nil || !ok || next != "b" {
		t.Fatalf("successor of a = %q, %v, %v; want b", next, ok, err)
	}
	if _, ok, err := db.ExecutorSessionSuccessor("c"); err != nil || ok {
		t.Fatalf("c has a successor (%v, %v); want none", ok, err)
	}
	if _, err := db.ExecutorSessionChain("ghost"); !errors.Is(err, ErrExecutorSessionNotFound) {
		t.Fatalf("chain of an unknown session = %v, want ErrExecutorSessionNotFound", err)
	}

	// A cycle written by hand ends the walk instead of the process.
	openCapSession(t, db, "p", 1, "q")
	openCapSession(t, db, "q", 2, "p")
	done := make(chan struct{})
	go func() {
		defer close(done)
		if chain, err := db.ExecutorSessionChain("q"); err != nil || len(chain) != 2 {
			t.Errorf("chain over a cycle = %d rows, %v; want the two sessions once each", len(chain), err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the chain walk did not terminate on a cycle")
	}
}

// TestRunningTasksAreRecordedOnlyWhileRunning: the record is a running
// session's, bounded and deduplicated, and a late write after a claim cannot
// rewrite what the failover read.
func TestRunningTasksAreRecordedOnlyWhileRunning(t *testing.T) {
	db := openTestDB(t)
	openCapSession(t, db, "r", 1, "")

	ok, err := db.SetExecutorSessionRunningTasks("r", []int{7, 7, -1, 0, 9})
	if err != nil || !ok {
		t.Fatalf("SetExecutorSessionRunningTasks = %v, %v", ok, err)
	}
	got, _ := db.GetExecutorSession("r")
	if fmt.Sprint(got.RunningTasks) != "[7 9]" {
		t.Fatalf("running tasks = %v, want [7 9]", got.RunningTasks)
	}

	many := make([]int, 500)
	for i := range many {
		many[i] = i + 1
	}
	if _, err := db.SetExecutorSessionRunningTasks("r", many); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetExecutorSession("r")
	if len(got.RunningTasks) != maxRunningTasks {
		t.Fatalf("a hostile run recorded %d tasks, want at most %d", len(got.RunningTasks), maxRunningTasks)
	}

	if _, err := db.ClaimExecutorSessionRequeue("r", "tok-r", "tok-r2", 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.SetExecutorSessionRunningTasks("r", []int{1}); err != nil || ok {
		t.Fatalf("a write after the claim = %v, %v; want no row written", ok, err)
	}
	got, _ = db.GetExecutorSession("r")
	if len(got.RunningTasks) != maxRunningTasks {
		t.Fatalf("the claimed session's record changed to %v", got.RunningTasks)
	}
}

// TestQuarantineSurvivesAStaleSave is the property the mark depends on: a run
// holding a copy of the plan from before the mark saves it, and the mark is
// still there; the explicit reset's clear is what removes it.
func TestQuarantineSurvivesAStaleSave(t *testing.T) {
	path := freshPath(t)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stale := &State{Goal: "g", PMMode: true, Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 7, Title: "the killer", Status: pm.TaskInProgress},
		{ID: 8, Title: "innocent", Status: pm.TaskPending},
	}}}
	if err := db.SaveState(stale); err != nil {
		t.Fatal(err)
	}

	t0 := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for i, ex := range []string{"sgx", "edge-2", "sgx"} {
		added, err := db.RecordTaskNodeLoss(7, pm.NodeLoss{
			ExecutorID: ex, SessionID: fmt.Sprintf("s%d", i), LostAt: t0.Add(time.Duration(i) * time.Minute), Attempt: i + 1,
		})
		if err != nil || !added {
			t.Fatalf("RecordTaskNodeLoss %d = %v, %v", i, added, err)
		}
	}
	// The same session twice is one loss.
	if added, err := db.RecordTaskNodeLoss(7, pm.NodeLoss{ExecutorID: "sgx", SessionID: "s0", LostAt: t0}); err != nil || added {
		t.Fatalf("re-recording a session's loss = %v, %v; want a no-op", added, err)
	}
	losses, err := db.TaskNodeLosses(7)
	if err != nil || len(losses) != 3 {
		t.Fatalf("losses = %v, %v; want 3", losses, err)
	}
	if got := pm.DistinctNodes(losses); fmt.Sprint(got) != "[sgx edge-2]" {
		t.Fatalf("distinct nodes = %v", got)
	}

	if err := db.PutTaskQuarantine(7, pm.TaskQuarantine{
		Kind: pm.QuarantineNodeKiller, Reason: "two nodes", Nodes: losses, MarkedAt: t0, MarkedBy: "failover",
	}); err != nil {
		t.Fatal(err)
	}
	task, err := db.LoadTask(7)
	if err != nil || task.Quarantine == nil || len(task.Quarantine.Nodes) != 3 || task.Quarantine.Reason != "two nodes" {
		t.Fatalf("LoadTask did not read the mark back: %+v, %v", task, err)
	}

	// The stale run saves its copy, which knows nothing of the mark.
	if err := db.SaveState(stale); err != nil {
		t.Fatal(err)
	}
	full, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if !full.Plan.TaskByID(7).Quarantined() {
		t.Fatal("a save from a copy loaded before the mark erased it")
	}
	if full.Plan.TaskByID(8).Quarantined() {
		t.Fatal("the mark spread to a task it does not belong to")
	}
	// Nor can a save from a copy that carries a mark write one.
	full.Plan.TaskByID(8).Quarantine = &pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller}
	if err := db.SaveState(full); err != nil {
		t.Fatal(err)
	}
	if q, _ := db.TaskQuarantine(8); q != nil {
		t.Fatal("SaveState wrote a quarantine; only the failover and the reset may")
	}

	peek, err := PeekTaskQuarantines(path)
	if err != nil || len(peek) != 1 || peek[0].TaskID != 7 || peek[0].Title != "the killer" {
		t.Fatalf("PeekTaskQuarantines = %+v, %v", peek, err)
	}

	cleared, err := db.ClearTaskQuarantine(7)
	if err != nil || !cleared {
		t.Fatalf("ClearTaskQuarantine = %v, %v", cleared, err)
	}
	if q, _ := db.TaskQuarantine(7); q != nil {
		t.Fatal("the mark survived its clear")
	}
	if losses, _ := db.TaskNodeLosses(7); len(losses) != 0 {
		t.Fatalf("the losses survived the reset: %v — the next lost node would quarantine the task again", losses)
	}
	if cleared, err := db.ClearTaskQuarantine(7); err != nil || cleared {
		t.Fatalf("clearing again = %v, %v; want a no-op", cleared, err)
	}
}

// TestADamagedQuarantineStillHolds: a mark whose nodes cannot be read is
// still a mark. Failing open here would release a suspected node killer
// because a column was corrupted.
func TestADamagedQuarantineStillHolds(t *testing.T) {
	db := openTestDB(t)
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 3, Title: "t", Status: pm.TaskFailed},
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutTaskQuarantine(3, pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`UPDATE task_quarantine SET nodes_json = '{not json' WHERE task_id = 3`); err != nil {
		t.Fatal(err)
	}
	task, err := db.LoadTask(3)
	if err != nil {
		t.Fatalf("a damaged mark failed the plan load: %v", err)
	}
	if !task.Quarantined() {
		t.Fatal("a damaged mark read as no mark")
	}
}

// TestFailoverCapMigrationIsAdditive: 0061 adds a column to a table no
// shipped build rewrites and two new tables, so a binary that predates it —
// this project's own long-lived run among them — keeps opening the database.
// A plan_tasks column here would have stopped that run.
func TestFailoverCapMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if !strings.Contains(m.Name, "failover_cap") {
			continue
		}
		if got := migrationVerdict(m); got != CompatAdditive {
			t.Fatalf("%s classifies %q, want %q", m.Name, got, CompatAdditive)
		}
		return
	}
	t.Fatal("no failover_cap migration is embedded")
}

// TestExecutorSessionForHandleFindsTheWorkloadsSession: the hub follows a run
// by its executor and handle, and learns from the session recorded for that
// pair whether a failover claim took it (Task 20396). The most recent session
// wins when a handle was recorded twice; another executor's handle of the
// same name is not it; an unknown or blank one is "none", not an error.
func TestExecutorSessionForHandleFindsTheWorkloadsSession(t *testing.T) {
	db := openTestDB(t)
	start := time.Now().Add(-time.Hour)
	for i, row := range []ExecutorSessionRow{
		{ID: "old", ExecutorID: "edge-1", HandleID: "h1", ClaimToken: "t-old", StartedAt: start},
		{ID: "new", ExecutorID: "edge-1", HandleID: "h1", ClaimToken: "t-new", StartedAt: start.Add(time.Minute)},
		{ID: "elsewhere", ExecutorID: "edge-2", HandleID: "h1", ClaimToken: "t-else", StartedAt: start.Add(2 * time.Minute)},
	} {
		if err := db.OpenExecutorSession(row); err != nil {
			t.Fatalf("OpenExecutorSession #%d: %v", i, err)
		}
	}
	got, ok, err := db.ExecutorSessionForHandle("edge-1", "h1")
	if err != nil || !ok || got.ID != "new" {
		t.Fatalf("ExecutorSessionForHandle(edge-1, h1) = %q, %v, %v; want the most recent session, new", got.ID, ok, err)
	}
	if _, err := db.ClaimExecutorSessionRequeue("new", "t-new", "t-next", 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := db.ExecutorSessionForHandle("edge-1", "h1"); got.State != ExecutorSessionRequeued {
		t.Fatalf("after the claim the handle's session is %q, want requeued", got.State)
	}
	for _, c := range [][2]string{{"edge-1", "h2"}, {"edge-3", "h1"}, {"", "h1"}, {"edge-1", ""}} {
		if got, ok, err := db.ExecutorSessionForHandle(c[0], c[1]); err != nil || ok {
			t.Errorf("ExecutorSessionForHandle(%q, %q) = %q, %v, %v; want none", c[0], c[1], got.ID, ok, err)
		}
	}
}
