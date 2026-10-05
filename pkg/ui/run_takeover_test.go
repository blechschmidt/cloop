package ui

// A run adopted after the hub process that dispatched it stopped takes over
// what that process held for it (Task 20382): the run's secret lease — kept
// alive here, released here — and its executor session. tests/e2e
// (hubrestart_test.go) runs the whole restart with real processes; these pin
// the parts a few seconds of a real run cannot reach: the extension past the
// issued deadline, a lease that lapsed during the downtime, and the janitor
// sweeping a lease whose holder never came back.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// takeoverExecutor runs one workload until finish is called.
type takeoverExecutor struct {
	id   string
	mu   sync.Mutex
	st   executor.Status
	done chan struct{}
	once sync.Once
	// redactions are the values the hub asked to scrub, per handle.
	redactions map[string][]string
}

func (e *takeoverExecutor) AddHandleRedactions(handleID string, values ...string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.redactions == nil {
		e.redactions = map[string][]string{}
	}
	e.redactions[handleID] = append(e.redactions[handleID], values...)
	return true
}

func newTakeoverExecutor(id string) *takeoverExecutor {
	return &takeoverExecutor{id: id, st: executor.Status{State: executor.StateRunning}, done: make(chan struct{})}
}

func (e *takeoverExecutor) ID() string   { return e.id }
func (e *takeoverExecutor) Kind() string { return executor.KindRemoteAgent }
func (e *takeoverExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote}
}
func (e *takeoverExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, nil
}
func (e *takeoverExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *takeoverExecutor) HealthCheck(context.Context) error                     { return nil }
func (e *takeoverExecutor) Status(context.Context, string) (executor.Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st, nil
}

// Stream stays open until the workload finishes.
func (e *takeoverExecutor) Stream(ctx context.Context, _ string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	go func() {
		defer close(ch)
		select {
		case <-e.done:
		case <-ctx.Done():
		}
	}()
	return ch, nil
}

func (e *takeoverExecutor) finish() {
	e.mu.Lock()
	e.st = executor.Status{State: executor.StateExited}
	e.mu.Unlock()
	e.once.Do(func() { close(e.done) })
}

// takeoverHub is a control plane holding one env credential granted to the
// executor, with every broker the hub opens on a clock the test drives and
// recording its leases as held by whichever process the test is playing.
type takeoverHub struct {
	dir    string
	clock  *keepaliveClock
	holder string
}

func newTakeoverHub(t *testing.T, executorID string) *takeoverHub {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "run-takeover-unit-passphrase")
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "run takeover", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	h := &takeoverHub{dir: dir, clock: &keepaliveClock{now: time.Now().UTC()}, holder: "hub_dispatcher"}

	controlPlaneDirMu.Lock()
	prevDir := controlPlaneDirValue
	controlPlaneDirValue = dir
	controlPlaneDirMu.Unlock()
	prevOpts, prevHolder := testBrokerOptions, leaseHolderID
	testBrokerOptions = []secretbroker.Option{secretbroker.WithClock(h.clock.Now)}
	leaseHolderID = func() string { return h.holder }
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue = prevDir
		controlPlaneDirMu.Unlock()
		testBrokerOptions, leaseHolderID = prevOpts, prevHolder
	})

	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: "claude", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"CLAUDE_CODE_OAUTH_TOKEN":"takeover-credential-0123456789"}`), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: executorID},
		Constraints: secretbroker.Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}},
		TTL:         24 * time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return h
}

// dispatch issues a run's lease as the dispatching process does, bound to its
// workload, with the keepalive left to the test.
func (h *takeoverHub) dispatch(t *testing.T, ex executor.Executor, handleID string) *secretLease {
	t.Helper()
	sl := acquireSecretLease(h.dir, h.dir, ex, "run_takeover", nil)
	if sl == nil {
		t.Fatal("no lease was issued")
	}
	stopKeepaliveForTest(sl)
	sl.bindHandle(ex.ID(), handleID)
	t.Cleanup(func() { liveLeases.removeIf(sl) })
	return sl
}

func (h *takeoverHub) record(t *testing.T, leaseID string) (statedb.SecretLeaseRow, bool) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, err := db.GetSecretLease(leaseID)
	return row, err == nil
}

func (h *takeoverHub) audit(t *testing.T, action auditaction.Action, leaseID string) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []statedb.AuditEvent
	for _, r := range rows {
		if r.EntityID == leaseID || strings.Contains(r.Payload, leaseID) {
			out = append(out, r)
		}
	}
	return out
}

func registeredLease(id string) *secretLease {
	for _, sl := range liveLeases.snapshot() {
		if sl.lease != nil && sl.lease.ID == id {
			return sl
		}
	}
	return nil
}

// TestAdoptedRunTakesOverItsLease is the restart, in one process: the lease a
// stopped process issued is taken over by the one that adopted its run — the
// same lease, recorded as the new holder's — kept alive past its issued
// deadline from there, and released by it when the workload ends. The process
// that lost it, were it still running, would neither extend nor end it.
func TestAdoptedRunTakesOverItsLease(t *testing.T) {
	ex := newTakeoverExecutor("edge-takeover")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-1")
	leaseID := old.lease.ID
	issued := old.ExpiresAt()
	ids := liveLeases.forHandle(ex.ID(), "h-1")
	if len(ids) != 1 || ids[0] != leaseID {
		t.Fatalf("leases bound to the workload = %v, want [%s]", ids, leaseID)
	}
	if row, ok := h.record(t, leaseID); !ok || row.Holder != "hub_dispatcher" {
		t.Fatalf("the issued lease's record = %+v, %v", row, ok)
	}

	// The dispatching process stops; its registry goes with it.
	liveLeases.removeIf(old)
	h.clock.advance(2 * time.Minute)
	h.holder = "hub_adopter"
	s := &Server{WorkDir: h.dir}
	s.takeOverRunLeases(h.dir, ex, "h-1", ids)

	taken := registeredLease(leaseID)
	if taken == nil {
		t.Fatal("the adopting process does not hold the run's lease")
	}
	stopKeepaliveForTest(taken)
	if exID, handle := taken.boundHandle(); exID != ex.ID() || handle != "h-1" {
		t.Errorf("the taken-over lease is bound to %s/%s", exID, handle)
	}
	if row, _ := h.record(t, leaseID); row.Holder != "hub_adopter" {
		t.Fatalf("record holder after the takeover = %q", row.Holder)
	}
	if got := liveLeases.forHandle(ex.ID(), "h-1"); len(got) != 1 || got[0] != leaseID {
		t.Errorf("the adopted run's owner row would name leases %v", got)
	}
	// Its output is scrubbed of the credential the lease carries, as its
	// dispatcher's was.
	ex.mu.Lock()
	scrub := strings.Join(ex.redactions["h-1"], ",")
	ex.mu.Unlock()
	if !strings.Contains(scrub, "takeover-credential-0123456789") {
		t.Errorf("the adopted handle's output is not scrubbed of the leased credential: %q", scrub)
	}

	// Inside the keepalive's margin of the issued deadline: extended here,
	// record and all.
	h.clock.advance(9 * time.Minute)
	if !taken.keepAlive(context.Background(), h.clock.Now()) {
		t.Fatal("the adopting process's keepalive stopped on a healthy lease")
	}
	if !taken.ExpiresAt().After(issued) {
		t.Fatalf("the lease was not extended past its issued deadline %s: %s", issued, taken.ExpiresAt())
	}
	if row, _ := h.record(t, leaseID); !row.ExpiresAt.Equal(taken.ExpiresAt()) {
		t.Errorf("record deadline %s, lease deadline %s", row.ExpiresAt, taken.ExpiresAt())
	}

	// The process that lost it lets go instead of extending — without
	// dropping the lease this process holds under the same id.
	if old.keepAlive(context.Background(), h.clock.Now()) {
		t.Fatal("the previous holder's keepalive carried on")
	}
	if registeredLease(leaseID) != taken {
		t.Fatal("letting go of the previous holder's lease dropped the taken-over one")
	}
	old.Close()
	if row, ok := h.record(t, leaseID); !ok || row.Holder != "hub_adopter" {
		t.Fatalf("the previous holder's Close touched the record: %+v %v", row, ok)
	}
	if n := len(h.audit(t, auditaction.Action(secretbroker.ActionRelease), leaseID)); n != 0 {
		t.Fatalf("the previous holder released the lease (%d rows)", n)
	}

	// Past the issued deadline the janitor leaves it alone.
	if swept := s.sweepExpiredLeases(issued.Add(time.Minute)); len(swept) != 0 {
		t.Fatalf("the janitor swept the extended lease: %+v", swept)
	}

	// The workload ends: the adopter releases the lease.
	ex.finish()
	deadline := time.Now().Add(5 * time.Second)
	for registeredLease(leaseID) != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if registeredLease(leaseID) != nil {
		t.Fatal("the lease outlived its run")
	}
	if _, ok := h.record(t, leaseID); ok {
		t.Error("the lease's record outlived its run")
	}
	renews := h.audit(t, auditaction.Action(secretbroker.ActionRenew), leaseID)
	var tookOver bool
	for _, r := range renews {
		tookOver = tookOver || strings.Contains(r.Payload, "taken over")
	}
	if !tookOver {
		t.Errorf("no takeover row on the lease's trail: %+v", renews)
	}
	if n := len(h.audit(t, auditaction.Action(secretbroker.ActionRelease), leaseID)); n != 1 {
		t.Errorf("release rows = %d, want the adopter's one", n)
	}
}

// TestAdoptedRunWhoseLeaseLapsedIsScrubbed: the hub was down longer than the
// lease had left. Nothing may resurrect a lapsed lease, so the adopter does
// what the janitor would have done: takes it back from the device and ends
// it.
func TestAdoptedRunWhoseLeaseLapsedIsScrubbed(t *testing.T) {
	ex := newTakeoverExecutor("edge-lapsed")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-2")
	leaseID := old.lease.ID
	liveLeases.removeIf(old)

	var scrubbed []string
	prev := testRevokeLapsedLease
	testRevokeLapsedLease = func(id, reason string) { scrubbed = append(scrubbed, id+": "+reason) }
	t.Cleanup(func() { testRevokeLapsedLease = prev })

	h.clock.advance(secretbroker.DefaultMaxLeaseTTL + time.Minute)
	h.holder = "hub_adopter"
	(&Server{WorkDir: h.dir}).takeOverRunLeases(h.dir, ex, "h-2", []string{leaseID})

	if registeredLease(leaseID) != nil {
		t.Fatal("a lapsed lease was taken over")
	}
	if len(scrubbed) != 1 || !strings.HasPrefix(scrubbed[0], leaseID) || !strings.Contains(scrubbed[0], "lapsed") {
		t.Fatalf("scrubs = %v, want the lapsed lease taken back from the device", scrubbed)
	}
	if _, ok := h.record(t, leaseID); ok {
		t.Error("the lapsed lease's record was left behind")
	}
	if n := len(h.audit(t, auditaction.Action(secretbroker.ActionRelease), leaseID)); n != 1 {
		t.Errorf("release rows = %d, want one", n)
	}
}

// TestJanitorSweepsALeaseItsHolderLeftBehind: a run whose agent never came
// back is never adopted, so nobody takes its lease over. Once the lease lapses
// the leader's janitor sweeps it off the devices — the TTL binds across a
// restart as it does within one process — while a lease that has not lapsed,
// and one a live process still holds, are left alone.
func TestJanitorSweepsALeaseItsHolderLeftBehind(t *testing.T) {
	ex := newTakeoverExecutor("edge-orphan")
	h := newTakeoverHub(t, ex.ID())
	orphan := h.dispatch(t, ex, "h-3")
	liveLeases.removeIf(orphan)

	node, err := hubcluster.Join(fastClusterOptions(state.DBPath(h.dir), "http://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	node.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = node.Close()
	})
	waitCluster(t, "the member to lead", node.IsLeader)
	s := &Server{WorkDir: h.dir, Cluster: node}

	// This process's own lease, live in its registry.
	h.holder = node.ID()
	mine := h.dispatch(t, newTakeoverExecutor(ex.ID()), "h-4")

	if swept := s.sweepExpiredLeases(h.clock.Now()); len(swept) != 0 {
		t.Fatalf("the janitor swept leases that have not lapsed: %+v", swept)
	}
	at := h.clock.Now().Add(secretbroker.DefaultMaxLeaseTTL + time.Minute)
	h.clock.advance(secretbroker.DefaultMaxLeaseTTL + time.Minute)
	swept := s.sweepExpiredLeases(at)
	var orphaned, own bool
	for _, e := range swept {
		switch e.LeaseID {
		case orphan.lease.ID:
			orphaned = strings.Contains(e.Reason, "after the hub process holding it stopped")
		case mine.lease.ID:
			own = true
		}
	}
	if !orphaned {
		t.Fatalf("the janitor did not sweep the lease its stopped holder left: %+v", swept)
	}
	if !own {
		t.Errorf("the janitor did not sweep this process's own lapsed lease: %+v", swept)
	}
	if _, ok := h.record(t, orphan.lease.ID); ok {
		t.Error("the orphaned lease's record survived the sweep")
	}
	if n := len(h.audit(t, auditaction.Action(secretbroker.ActionRelease), orphan.lease.ID)); n != 1 {
		t.Errorf("release rows for the orphaned lease = %d, want one", n)
	}
	if n := len(h.audit(t, auditaction.Action(secretbroker.ActionLeaseRevokeSent), orphan.lease.ID)); n != 1 {
		t.Errorf("revoke_sent rows for the orphaned lease = %d, want one", n)
	}
}

// TestAdoptedRunsSessionIsWatchedToItsEnd: the session the dispatching process
// opened is closed by the one that adopted the run, with how the run ended —
// and a run that had already ended when it was adopted is closed at once.
func TestAdoptedRunsSessionIsWatchedToItsEnd(t *testing.T) {
	ex := newTakeoverExecutor("edge-session")
	h := newTakeoverHub(t, ex.ID())
	open := func(handleID string) string {
		t.Helper()
		sched, db, err := newScheduler(h.dir)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		id, _ := executorstore.NewSessionID()
		token, _ := executorstore.NewClaimToken()
		if err := sched.OpenSession(executor.Session{
			ID: id, ExecutorID: ex.ID(), HandleID: handleID, ProjectPath: h.dir,
			ClaimToken: token, Attempt: 1, StartedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	stateOf := func(id string) string {
		t.Helper()
		db, err := statedb.Open(state.DBPath(h.dir))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		sess, err := db.GetExecutorSession(id)
		if err != nil {
			t.Fatal(err)
		}
		return sess.State
	}

	live := open("h-live")
	watchAdoptedSessions(ex, "h-live")
	if got := stateOf(live); got != statedb.ExecutorSessionRunning {
		t.Fatalf("the adopted run's session = %s while it runs", got)
	}
	ex.finish()
	deadline := time.Now().Add(5 * time.Second)
	for stateOf(live) == statedb.ExecutorSessionRunning && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := stateOf(live); got != statedb.ExecutorSessionFinished {
		t.Errorf("the adopted run's session ended %s, want finished", got)
	}

	ended := open("h-ended")
	closeAdoptedSessions(ex, "h-ended", executor.Status{State: executor.StateExited, ExitCode: 3}, nil)
	if got := stateOf(ended); got != statedb.ExecutorSessionFailed {
		t.Errorf("a run that had exited 3 when adopted = %s, want failed", got)
	}
}
