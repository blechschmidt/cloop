package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// openTestDB is shared with kill_requests_test.go.

func TestExecutorHealthRoundTrip(t *testing.T) {
	db := openTestDB(t)

	seen := time.Now().Add(-30 * time.Second).Truncate(time.Millisecond)
	probe := time.Now().Truncate(time.Millisecond)
	changed := time.Now().Add(-5 * time.Minute).Truncate(time.Millisecond)
	row := ExecutorHealthRow{
		ExecutorID:          "edge-01",
		State:               "degraded",
		Reason:              "probe timeout after 3s",
		ConsecutiveFailures: 2,
		LastSeen:            seen,
		LastProbe:           probe,
		StateChangedAt:      changed,
	}
	if err := db.PutExecutorHealth(row); err != nil {
		t.Fatalf("PutExecutorHealth: %v", err)
	}

	got, err := db.GetExecutorHealth("edge-01")
	if err != nil {
		t.Fatalf("GetExecutorHealth: %v", err)
	}
	if got.State != "degraded" || got.Reason != "probe timeout after 3s" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.ConsecutiveFailures != 2 {
		t.Errorf("ConsecutiveFailures = %d, want 2", got.ConsecutiveFailures)
	}
	if !got.LastSeen.Equal(seen) || !got.LastProbe.Equal(probe) || !got.StateChangedAt.Equal(changed) {
		t.Errorf("timestamps did not survive: %+v", got)
	}

	// Upsert replaces in place: the prober computes the whole verdict, so a
	// second write must not leave the old failure count behind.
	row.State = "ready"
	row.Reason = ""
	row.ConsecutiveFailures = 0
	if err := db.PutExecutorHealth(row); err != nil {
		t.Fatalf("second PutExecutorHealth: %v", err)
	}
	got, err = db.GetExecutorHealth("edge-01")
	if err != nil {
		t.Fatalf("GetExecutorHealth after update: %v", err)
	}
	if got.State != "ready" || got.Reason != "" || got.ConsecutiveFailures != 0 {
		t.Errorf("update not applied wholesale: %+v", got)
	}
	if all, err := db.ListExecutorHealth(); err != nil || len(all) != 1 {
		t.Fatalf("ListExecutorHealth = (%d rows, %v), want (1, nil)", len(all), err)
	}
}

// TestExecutorHealthZeroTimesAndDefaults: an executor that has been registered
// but never probed must round-trip as zero times rather than year 1, and must
// not surface a blank state column.
func TestExecutorHealthZeroTimesAndDefaults(t *testing.T) {
	db := openTestDB(t)

	if err := db.PutExecutorHealth(ExecutorHealthRow{ExecutorID: "local"}); err != nil {
		t.Fatalf("PutExecutorHealth: %v", err)
	}
	got, err := db.GetExecutorHealth("local")
	if err != nil {
		t.Fatalf("GetExecutorHealth: %v", err)
	}
	if got.State != "ready" {
		t.Errorf("default State = %q, want ready", got.State)
	}
	if !got.LastSeen.IsZero() || !got.LastProbe.IsZero() || !got.StateChangedAt.IsZero() {
		t.Errorf("unset timestamps came back non-zero: %+v", got)
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0", got.ConsecutiveFailures)
	}

	// A previously-set timestamp must be clearable back to unset.
	if err := db.PutExecutorHealth(ExecutorHealthRow{ExecutorID: "local", LastSeen: time.Now()}); err != nil {
		t.Fatalf("PutExecutorHealth(with time): %v", err)
	}
	if err := db.PutExecutorHealth(ExecutorHealthRow{ExecutorID: "local"}); err != nil {
		t.Fatalf("PutExecutorHealth(clearing): %v", err)
	}
	got, _ = db.GetExecutorHealth("local")
	if !got.LastSeen.IsZero() {
		t.Errorf("LastSeen = %v, want zero after being cleared", got.LastSeen)
	}
}

// TestExecutorHealthIsIndependentOfEnrollment is the reason this is a separate
// table: localprocess and container executors are registered from config and
// never enroll, so health must be writable without an `executors` row. If it
// were not, exactly those executors could never be cordoned.
func TestExecutorHealthIsIndependentOfEnrollment(t *testing.T) {
	db := openTestDB(t)

	if err := db.PutExecutorHealth(ExecutorHealthRow{
		ExecutorID: "localprocess",
		State:      "cordoned",
		Reason:     "operator drain",
	}); err != nil {
		t.Fatalf("health for an unenrolled executor must be writable: %v", err)
	}
	if _, err := db.GetExecutor("localprocess"); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("precondition: executor should not be enrolled, got %v", err)
	}
	got, err := db.GetExecutorHealth("localprocess")
	if err != nil {
		t.Fatalf("GetExecutorHealth: %v", err)
	}
	if got.State != "cordoned" {
		t.Errorf("State = %q, want cordoned", got.State)
	}
}

func TestExecutorHealthMissingRowsAndDelete(t *testing.T) {
	db := openTestDB(t)

	// "Never probed" must be distinguishable from "probed and ready": a
	// caller that conflated them would treat an unobserved node as healthy.
	if _, err := db.GetExecutorHealth("ghost"); !errors.Is(err, ErrExecutorHealthNotFound) {
		t.Fatalf("GetExecutorHealth(unknown) = %v, want ErrExecutorHealthNotFound", err)
	}
	if err := db.PutExecutorHealth(ExecutorHealthRow{}); err == nil {
		t.Error("PutExecutorHealth with a blank executor id succeeded, want error")
	}
	// Deleting a row that was never written is a no-op, not an error.
	if err := db.DeleteExecutorHealth("ghost"); err != nil {
		t.Fatalf("DeleteExecutorHealth(missing) = %v, want nil", err)
	}

	for _, id := range []string{"c", "a", "b"} {
		if err := db.PutExecutorHealth(ExecutorHealthRow{ExecutorID: id}); err != nil {
			t.Fatalf("PutExecutorHealth(%s): %v", id, err)
		}
	}
	rows, err := db.ListExecutorHealth()
	if err != nil {
		t.Fatalf("ListExecutorHealth: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("ListExecutorHealth returned %d rows, want 3", len(rows))
	}
	for i, want := range []string{"a", "b", "c"} {
		if rows[i].ExecutorID != want {
			t.Errorf("row %d = %q, want %q (listing must be ordered by executor_id)", i, rows[i].ExecutorID, want)
		}
	}

	if err := db.DeleteExecutorHealth("b"); err != nil {
		t.Fatalf("DeleteExecutorHealth: %v", err)
	}
	if _, err := db.GetExecutorHealth("b"); !errors.Is(err, ErrExecutorHealthNotFound) {
		t.Fatalf("GetExecutorHealth after delete = %v, want ErrExecutorHealthNotFound", err)
	}
	if rows, err = db.ListExecutorHealth(); err != nil || len(rows) != 2 {
		t.Fatalf("ListExecutorHealth after delete = (%d rows, %v), want (2, nil)", len(rows), err)
	}
}

func TestExecutorSessionOpenGetListCount(t *testing.T) {
	db := openTestDB(t)

	started := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	row := ExecutorSessionRow{
		ID:           "sess-1",
		ExecutorID:   "edge-01",
		HandleID:     "handle-abc",
		ProjectPath:  "/srv/app",
		TaskID:       20162,
		ClaimToken:   "tok-1",
		Attempt:      2,
		StartedAt:    started,
		RequeuedFrom: "sess-0",
	}
	if err := db.OpenExecutorSession(row); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}

	got, err := db.GetExecutorSession("sess-1")
	if err != nil {
		t.Fatalf("GetExecutorSession: %v", err)
	}
	if got.ExecutorID != "edge-01" || got.HandleID != "handle-abc" || got.ProjectPath != "/srv/app" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.TaskID != 20162 || got.Attempt != 2 || got.RequeuedFrom != "sess-0" {
		t.Errorf("failover bookkeeping did not survive: %+v", got)
	}
	if got.State != ExecutorSessionRunning {
		t.Errorf("State = %q, want running by default", got.State)
	}
	if !got.StartedAt.Equal(started) {
		t.Errorf("StartedAt = %v, want %v", got.StartedAt, started)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should default to StartedAt, not stay zero")
	}
	if !got.EndedAt.IsZero() {
		t.Errorf("EndedAt = %v, want zero for a running session", got.EndedAt)
	}

	// A second executor's work, plus a finished session, so the filters have
	// something to exclude.
	if err := db.OpenExecutorSession(ExecutorSessionRow{
		ID: "sess-2", ExecutorID: "edge-02", ClaimToken: "tok-2",
		StartedAt: started.Add(time.Second),
	}); err != nil {
		t.Fatalf("OpenExecutorSession(sess-2): %v", err)
	}
	if err := db.OpenExecutorSession(ExecutorSessionRow{
		ID: "sess-3", ExecutorID: "edge-01", ClaimToken: "tok-3",
		State: ExecutorSessionFinished, StartedAt: started.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("OpenExecutorSession(sess-3): %v", err)
	}

	all, err := db.ListExecutorSessions("", false)
	if err != nil {
		t.Fatalf("ListExecutorSessions(all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListExecutorSessions(all) returned %d rows, want 3", len(all))
	}
	for i, want := range []string{"sess-1", "sess-2", "sess-3"} {
		if all[i].ID != want {
			t.Errorf("row %d = %q, want %q (ordering is started_at then id)", i, all[i].ID, want)
		}
	}

	perExecutor, err := db.ListExecutorSessions("edge-01", false)
	if err != nil {
		t.Fatalf("ListExecutorSessions(edge-01): %v", err)
	}
	if len(perExecutor) != 2 {
		t.Fatalf("ListExecutorSessions(edge-01) returned %d rows, want 2", len(perExecutor))
	}

	running, err := db.ListExecutorSessions("edge-01", true)
	if err != nil {
		t.Fatalf("ListExecutorSessions(edge-01, running): %v", err)
	}
	if len(running) != 1 || running[0].ID != "sess-1" {
		t.Fatalf("running sessions on edge-01 = %+v, want just sess-1", running)
	}

	if n, err := db.CountRunningExecutorSessions("edge-01"); err != nil || n != 1 {
		t.Fatalf("CountRunningExecutorSessions(edge-01) = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := db.CountRunningExecutorSessions(""); err != nil || n != 2 {
		t.Fatalf("CountRunningExecutorSessions(all) = (%d, %v), want (2, nil)", n, err)
	}
	if n, err := db.CountRunningExecutorSessions("edge-99"); err != nil || n != 0 {
		t.Fatalf("CountRunningExecutorSessions(unknown) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestExecutorSessionValidation(t *testing.T) {
	db := openTestDB(t)

	if err := db.OpenExecutorSession(ExecutorSessionRow{ExecutorID: "e", ClaimToken: "t"}); err == nil {
		t.Error("OpenExecutorSession with a blank id succeeded, want error")
	}
	// A blank claim token would make the requeue latch match any other
	// blank-token holder, so the row is refused rather than stored unclaimable.
	if err := db.OpenExecutorSession(ExecutorSessionRow{ID: "s", ExecutorID: "e"}); err == nil {
		t.Error("OpenExecutorSession with a blank claim token succeeded, want error")
	}
	if err := db.OpenExecutorSession(ExecutorSessionRow{ID: "s", ClaimToken: "t"}); err == nil {
		t.Error("OpenExecutorSession with a blank executor id succeeded, want error")
	}
	if _, err := db.GetExecutorSession("ghost"); !errors.Is(err, ErrExecutorSessionNotFound) {
		t.Fatalf("GetExecutorSession(unknown) = %v, want ErrExecutorSessionNotFound", err)
	}

	// Re-opening an existing session id must fail rather than overwrite: the
	// row carries a claim token a supervisor may already be holding.
	if err := db.OpenExecutorSession(ExecutorSessionRow{ID: "s1", ExecutorID: "e", ClaimToken: "tok"}); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}
	if err := db.OpenExecutorSession(ExecutorSessionRow{ID: "s1", ExecutorID: "e", ClaimToken: "other"}); err == nil {
		t.Error("re-opening an existing session id succeeded, want a uniqueness error")
	}
	got, err := db.GetExecutorSession("s1")
	if err != nil {
		t.Fatalf("GetExecutorSession: %v", err)
	}
	if got.ClaimToken != "tok" {
		t.Errorf("ClaimToken = %q, want the original tok — a duplicate open must not rotate it", got.ClaimToken)
	}
	if got.Attempt != 1 {
		t.Errorf("Attempt = %d, want 1 by default", got.Attempt)
	}
}

func TestCloseExecutorSession(t *testing.T) {
	db := openTestDB(t)
	if err := db.OpenExecutorSession(ExecutorSessionRow{
		ID: "sess-1", ExecutorID: "edge-01", ClaimToken: "tok-1",
	}); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}

	at := time.Now().Truncate(time.Millisecond)
	if err := db.CloseExecutorSession("sess-1", ExecutorSessionFinished, at); err != nil {
		t.Fatalf("CloseExecutorSession: %v", err)
	}
	got, err := db.GetExecutorSession("sess-1")
	if err != nil {
		t.Fatalf("GetExecutorSession: %v", err)
	}
	if got.State != ExecutorSessionFinished {
		t.Errorf("State = %q, want finished", got.State)
	}
	if !got.EndedAt.Equal(at) || !got.UpdatedAt.Equal(at) {
		t.Errorf("EndedAt/UpdatedAt = %v/%v, want %v", got.EndedAt, got.UpdatedAt, at)
	}
	if n, err := db.CountRunningExecutorSessions(""); err != nil || n != 0 {
		t.Fatalf("CountRunningExecutorSessions after close = (%d, %v), want (0, nil)", n, err)
	}

	// A closed session is no longer claimable for failover — the work already
	// ended, so requeueing it would be a duplicate execution.
	if _, err := db.ClaimExecutorSessionRequeue("sess-1", "tok-1", "tok-2", time.Now()); !errors.Is(err, ErrExecutorSessionClaimLost) {
		t.Fatalf("claim on a finished session = %v, want ErrExecutorSessionClaimLost", err)
	}

	// Defaults: blank state finishes, zero time stamps now.
	if err := db.OpenExecutorSession(ExecutorSessionRow{
		ID: "sess-2", ExecutorID: "edge-01", ClaimToken: "tok-2",
	}); err != nil {
		t.Fatalf("OpenExecutorSession(sess-2): %v", err)
	}
	if err := db.CloseExecutorSession("sess-2", "", time.Time{}); err != nil {
		t.Fatalf("CloseExecutorSession(defaults): %v", err)
	}
	got, _ = db.GetExecutorSession("sess-2")
	if got.State != ExecutorSessionFinished {
		t.Errorf("State = %q, want finished for a blank state", got.State)
	}
	if got.EndedAt.IsZero() {
		t.Error("a zero timestamp should default to now, not leave EndedAt unset")
	}

	// Closing a session the control plane never opened must surface, not be
	// silently dropped.
	if err := db.CloseExecutorSession("ghost", ExecutorSessionFailed, time.Now()); !errors.Is(err, ErrExecutorSessionNotFound) {
		t.Fatalf("CloseExecutorSession(unknown) = %v, want ErrExecutorSessionNotFound", err)
	}
}

func TestClaimExecutorSessionRequeue(t *testing.T) {
	db := openTestDB(t)
	if err := db.OpenExecutorSession(ExecutorSessionRow{
		ID: "sess-1", ExecutorID: "edge-01", ProjectPath: "/srv/app",
		TaskID: 42, ClaimToken: "tok-1", Attempt: 1,
	}); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}

	at := time.Now().Truncate(time.Millisecond)
	got, err := db.ClaimExecutorSessionRequeue("sess-1", "tok-1", "tok-2", at)
	if err != nil {
		t.Fatalf("ClaimExecutorSessionRequeue: %v", err)
	}
	if got.State != ExecutorSessionRequeued {
		t.Errorf("State = %q, want requeued", got.State)
	}
	if got.ClaimToken != "tok-2" {
		t.Errorf("ClaimToken = %q, want the rotated tok-2", got.ClaimToken)
	}
	if !got.EndedAt.Equal(at) || !got.UpdatedAt.Equal(at) {
		t.Errorf("EndedAt/UpdatedAt = %v/%v, want %v", got.EndedAt, got.UpdatedAt, at)
	}
	if got.TaskID != 42 || got.ProjectPath != "/srv/app" {
		t.Errorf("claim lost the work identity: %+v", got)
	}

	// The old token can never win again — this is what makes a winner's retry
	// safe instead of a second requeue.
	if _, err := db.ClaimExecutorSessionRequeue("sess-1", "tok-1", "tok-3", time.Now()); !errors.Is(err, ErrExecutorSessionClaimLost) {
		t.Fatalf("replay with the spent token = %v, want ErrExecutorSessionClaimLost", err)
	}
	// Even the new token loses, because the session is no longer running.
	if _, err := db.ClaimExecutorSessionRequeue("sess-1", "tok-2", "tok-3", time.Now()); !errors.Is(err, ErrExecutorSessionClaimLost) {
		t.Fatalf("claim on a requeued session = %v, want ErrExecutorSessionClaimLost", err)
	}

	// A genuinely unknown id is reported as not-found so an operator chasing a
	// stale session id is not told they lost a race that never existed.
	if _, err := db.ClaimExecutorSessionRequeue("ghost", "tok", "tok-new", time.Now()); !errors.Is(err, ErrExecutorSessionNotFound) {
		t.Fatalf("ClaimExecutorSessionRequeue(unknown) = %v, want ErrExecutorSessionNotFound", err)
	}
	if _, err := db.ClaimExecutorSessionRequeue("sess-1", "", "tok-3", time.Now()); err == nil {
		t.Error("claim with a blank current token succeeded, want error")
	}
	if _, err := db.ClaimExecutorSessionRequeue("sess-1", "tok-2", "  ", time.Now()); err == nil {
		t.Error("claim with a blank replacement token succeeded, want error")
	}
}

// TestClaimExecutorSessionRequeueIsExactlyOnce is the safety-critical test.
//
// Eight supervisors notice the same executor is dead and race to fail over the
// same session with the same claim token they each read. Exactly one may win;
// every other must be told it lost. Two winners would mean two AI agents
// editing the same repository at the same time, so "usually one" is not an
// acceptable outcome — the guarantee has to come from the conditional UPDATE,
// not from timing.
func TestClaimExecutorSessionRequeueIsExactlyOnce(t *testing.T) {
	db := openTestDB(t)
	if err := db.OpenExecutorSession(ExecutorSessionRow{
		ID: "sess-hot", ExecutorID: "edge-dead", ProjectPath: "/srv/app",
		TaskID: 7, ClaimToken: "tok-original",
	}); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}

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
			<-start // release all eight at once
			rows[i], errs[i] = db.ClaimExecutorSessionRequeue(
				"sess-hot", "tok-original", fmt.Sprintf("tok-supervisor-%d", i), time.Now())
		}(i)
	}
	close(start)
	wg.Wait()

	winners, lost := 0, 0
	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
			winner = i
		case errors.Is(err, ErrExecutorSessionClaimLost):
			lost++
		default:
			t.Errorf("goroutine %d got an unexpected error: %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d goroutines claimed the same session; exactly 1 may win", winners)
	}
	if lost != n-1 {
		t.Fatalf("%d losers reported ErrExecutorSessionClaimLost, want %d", lost, n-1)
	}

	// The winner's returned row must match what is durably stored, so a
	// supervisor can act on it without a re-read.
	stored, err := db.GetExecutorSession("sess-hot")
	if err != nil {
		t.Fatalf("GetExecutorSession: %v", err)
	}
	if stored.State != ExecutorSessionRequeued {
		t.Errorf("stored State = %q, want requeued", stored.State)
	}
	wantToken := fmt.Sprintf("tok-supervisor-%d", winner)
	if stored.ClaimToken != wantToken {
		t.Errorf("stored ClaimToken = %q, want %q (the winner's token)", stored.ClaimToken, wantToken)
	}
	if rows[winner].ClaimToken != stored.ClaimToken || rows[winner].State != stored.State {
		t.Errorf("winner's returned row %+v disagrees with storage %+v", rows[winner], stored)
	}
	for i, r := range rows {
		if i != winner && r.ID != "" {
			t.Errorf("loser %d received a populated row %+v; a lost claim must return nothing", i, r)
		}
	}
}

// TestExecutorSchedulingMigrationCreatesIndexes locks in the indexes failover
// scans and capacity checks depend on.
func TestExecutorSchedulingMigrationCreatesIndexes(t *testing.T) {
	db := openTestDB(t)
	want := []string{
		"idx_executor_health_state",
		"idx_executor_sessions_executor_state",
		"idx_executor_sessions_state",
	}
	for _, name := range want {
		db.mu.Lock()
		var got string
		err := db.conn.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&got)
		db.mu.Unlock()
		if errors.Is(err, sql.ErrNoRows) {
			t.Errorf("index %s was not created by migration 0013", name)
			continue
		}
		if err != nil {
			t.Fatalf("inspect sqlite_master for %s: %v", name, err)
		}
	}
}
