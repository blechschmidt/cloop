package ui

// run_supervision_test.go covers Task 20419 in one process: a lease revocation
// that outlives the member holding the lease, a dispatch that cannot be
// recorded, a dead member's unrecorded dispatch reaped, and a member that
// heartbeats without answering having its run adopted. tests/cluster runs the
// revocation with real hub processes and a real container.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// revokeLease posts a lease revocation to s and decodes the answer.
func revokeLease(t *testing.T, s *Server, leaseID, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/leases/"+leaseID+"/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", leaseID)
	rec := httptest.NewRecorder()
	s.handleLeaseRevoke(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// recordedRevocations reads the revocations recorded for leaseID.
func recordedRevocations(t *testing.T, dir, leaseID string) []statedb.LeaseRevocationRow {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	revs, err := db.LeaseRevocations(leaseID)
	if err != nil {
		t.Fatal(err)
	}
	return revs
}

// TestARevocationOfADeadHoldersLeaseIsRecordedAndEnforcedOnAdoption is the
// incident responder's revoke that used to be silently undone (Task 20419):
// the member holding the lease is gone, so no live process holds it. The
// revoke answers 202, not 404, and is recorded; the stopped holder could not
// keep the lease alive after it; and the process that adopts the run takes the
// material back instead of taking the lease over — nothing of it is
// registered here, its record is retired, and the revocation is settled.
func TestARevocationOfADeadHoldersLeaseIsRecordedAndEnforcedOnAdoption(t *testing.T) {
	ex := newTakeoverExecutor("edge-revoked")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-1")
	leaseID := old.lease.ID
	// The dispatching member dies: nothing in a live process holds the lease.
	// The revocation is made through a surviving one.
	liveLeases.removeIf(old)
	h.holder = "hub_survivor"

	s := &Server{WorkDir: h.dir}
	code, body := revokeLease(t, s, leaseID, `{"reason":"token pasted into a public log"}`)
	if code != http.StatusAccepted {
		t.Fatalf("revoking a lease whose holder is gone = %d %v, want 202", code, body)
	}
	if body["state"] != string(executor.RevokeStatePending) || body["recorded"] != true {
		t.Fatalf("the answer = %v, want a recorded, pending revocation", body)
	}
	pending, _ := body["pending"].([]any)
	if len(pending) != 1 {
		t.Fatalf("pending holders = %v, want the stopped member's run", body["pending"])
	}
	if msg := pending[0].(map[string]any)["error"]; !strings.Contains(msg.(string), "takes effect when hub member hub_dispatcher's run is reached") {
		t.Errorf("the pending holder does not say when the revocation takes effect: %v", msg)
	}
	if note, _ := body["note"].(string); !strings.Contains(note, "Recorded; takes effect") {
		t.Errorf("note = %q", note)
	}
	revs := recordedRevocations(t, h.dir, leaseID)
	if len(revs) != 1 || revs[0].GrantID != "" || !revs[0].Pending() || revs[0].Holder != "hub_dispatcher" ||
		revs[0].Reason != "token pasted into a public log" {
		t.Fatalf("recorded revocations = %+v", revs)
	}

	// The stopped holder — had it only been unreachable — may not keep it
	// alive past the revocation.
	h.clock.advance(secretbroker.DefaultMaxLeaseTTL - 2*time.Minute)
	if old.keepAlive(context.Background(), h.clock.Now()) {
		t.Fatal("the holder's keepalive went on extending a revoked lease")
	}

	var enforced []string
	prev := testEnforceRevokedLease
	testEnforceRevokedLease = func(id, reason string, action executor.RevokeAction) {
		enforced = append(enforced, id+": "+reason)
	}
	t.Cleanup(func() { testEnforceRevokedLease = prev })

	h.holder = "hub_adopter"
	s.takeOverRunLeases(h.dir, ex, "h-1", []string{leaseID})
	if registeredLease(leaseID) != nil {
		t.Fatal("the adopting process took a revoked lease over")
	}
	if len(enforced) != 1 || !strings.HasPrefix(enforced[0], leaseID) ||
		!strings.Contains(enforced[0], "token pasted into a public log") {
		t.Fatalf("taken back on adoption: %v, want the revoked lease's material taken back", enforced)
	}
	if _, ok := h.record(t, leaseID); ok {
		t.Error("the revoked lease's record outlived the adoption")
	}
	if revs := recordedRevocations(t, h.dir, leaseID); len(revs) != 1 || revs[0].Pending() {
		t.Errorf("after the adoption enforced it, the revocation is %+v", revs)
	}
	var refused bool
	for _, row := range h.audit(t, auditaction.Action(secretbroker.ActionRenew), leaseID) {
		refused = refused || (strings.Contains(row.Payload, "revoked") && strings.Contains(row.Payload, "cannot be taken over"))
	}
	if !refused {
		t.Error("the trail has no refusal of the revoked lease's takeover")
	}
}

// TestARevocationTheHolderHearsIsSettled: the ordinary case keeps its answer —
// the lease is held here, the revocation takes it back, and the record says it
// was enforced.
func TestARevocationTheHolderHearsIsSettled(t *testing.T) {
	ex := newTakeoverExecutor("edge-held")
	h := newTakeoverHub(t, ex.ID())
	held := h.dispatch(t, ex, "h-2")
	s := &Server{WorkDir: h.dir}
	code, body := revokeLease(t, s, held.lease.ID, "")
	if code != http.StatusOK || body["wiped_locally"] != true || body["state"] != string(executor.RevokeStateRevoked) {
		t.Fatalf("revoking a lease held here = %d %v", code, body)
	}
	revs := recordedRevocations(t, h.dir, held.lease.ID)
	if len(revs) != 1 || revs[0].Pending() {
		t.Fatalf("the revocation the holder enforced is %+v, want settled", revs)
	}
	if code, _ := revokeLease(t, s, "lease_nobody_knows", ""); code != http.StatusNotFound {
		t.Errorf("revoking a lease nobody knows = %d, want 404", code)
	}
}

// supervisionRig is one control plane with a seed node bound to its project
// and an env credential granted to it.
type supervisionRig struct {
	dir  string
	node *seedNode
}

// revocableSeed is a seed node that can take a lease back, as every executor
// a leased run may be placed on must (executor.RequireRevocable).
type revocableSeed struct{ *seedNode }

func (r revocableSeed) SupportsRevocation() bool              { return true }
func (r revocableSeed) HoldsLease(string) bool                { return false }
func (r revocableSeed) Leases() []string                      { return nil }
func (r revocableSeed) Revocations() []executor.RevokeOutcome { return nil }
func (r revocableSeed) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	now := time.Now()
	return executor.RevokeOutcome{LeaseID: req.LeaseID, GrantID: req.GrantID, ExecutorID: r.id,
		State: executor.RevokeStateRevoked, SentAt: now, AckedAt: now, Ack: &executor.RevokeReport{LeaseID: req.LeaseID}}
}

func newSupervisionRig(t *testing.T) *supervisionRig {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "run-supervision-unit-passphrase")
	dir := setupProjectDir(t, "run supervision", nil)
	withControlPlaneDir(t, dir)
	node := newSeedNode(t, "supervised-"+strings.ReplaceAll(strings.TrimPrefix(dir, "/tmp/"), ".", "-"))
	if err := executor.DefaultRegistry.Register(revocableSeed{node}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(node.id) })
	if err := executor.Bind(dir, node.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: "npm", Kind: secretbroker.KindEnv, Payload: []byte(`{"NPM_TOKEN":"npm-supervision-0123456789"}`), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: node.id},
		Constraints: secretbroker.Constraints{EnvKeys: []string{"NPM_TOKEN"}}, TTL: time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return &supervisionRig{dir: dir, node: node}
}

// readOnlyRecords makes every write a dispatch records itself through fail
// as a read-only database fails it (PRAGMA query_only), until the test ends.
func readOnlyRecords(t *testing.T) {
	t.Helper()
	prev := testDispatchRecordHook
	testDispatchRecordHook = func(db *statedb.DB) {
		if err := db.SetQueryOnly(true); err != nil {
			t.Errorf("SetQueryOnly: %v", err)
		}
	}
	t.Cleanup(func() { testDispatchRecordHook = prev })
}

// heldLeasesFor reports the leases this process holds bound to handleID.
func heldLeasesFor(executorID, handleID string) []string {
	return liveLeases.forHandle(executorID, handleID)
}

// TestADispatchThatCannotBeRecordedIsRefused: a dispatch whose session record
// the control plane refuses (PRAGMA query_only) used to run untracked — never
// failed over, never adopted. It is refused now: the workload it started is
// stopped, the credential it was leased is released, and the run fails with
// the storage error.
func TestADispatchThatCannotBeRecordedIsRefused(t *testing.T) {
	r := newSupervisionRig(t)
	readOnlyRecords(t)

	ex, handle, err := startWorkloadAs(nil, nil, "", r.dir, []string{"cloop", "run"}, map[string]string{"handler": "run"})
	if err == nil {
		t.Fatalf("a dispatch whose session could not be recorded was started: %s on %v", handle.ID, ex)
	}
	if !errors.Is(err, errDispatchUnrecorded) || !strings.Contains(err.Error(), "readonly") {
		t.Fatalf("the refusal = %v, want errDispatchUnrecorded carrying the storage error", err)
	}
	r.node.mu.Lock()
	starts := r.node.starts
	var started *seedWorkload
	for _, w := range r.node.workloads {
		started = w
	}
	r.node.mu.Unlock()
	if starts != 1 || started == nil {
		t.Fatalf("the executor started %d workloads, want the one that was then stopped", starts)
	}
	if !started.ended || started.abandoned == "" || !strings.Contains(started.abandoned, "could not be recorded") {
		t.Fatalf("the workload was left running (ended %v, abandoned %q)", started.ended, started.abandoned)
	}
	if held := heldLeasesFor(r.node.id, started.handle); len(held) != 0 {
		t.Fatalf("the refused dispatch's lease is still held: %v", held)
	}

	// The handler's answer for it is a 503, not a 500.
	rec := httptest.NewRecorder()
	jsonWorkloadErr(rec, err)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("jsonWorkloadErr = %d, want 503", rec.Code)
	}
}

// TestADispatchWhoseIntentCannotBeRecordedNeverStarts: in a cluster the
// dispatch is on record before its workload exists, and one that cannot be is
// refused before anything is started.
func TestADispatchWhoseIntentCannotBeRecordedNeverStarts(t *testing.T) {
	r := newSupervisionRig(t)
	node, err := hubcluster.Join(fastClusterOptions(state.DBPath(r.dir), "http://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	node.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = node.Close()
	})
	prevCluster := processCluster.Load()
	processCluster.Store(node)
	t.Cleanup(func() { processCluster.Store(prevCluster) })
	readOnlyRecords(t)

	if _, _, err := startWorkloadAs(nil, nil, "", r.dir, []string{"cloop", "run"}, nil); !errors.Is(err, errDispatchUnrecorded) {
		t.Fatalf("startWorkloadAs = %v, want errDispatchUnrecorded", err)
	}
	r.node.mu.Lock()
	starts := r.node.starts
	r.node.mu.Unlock()
	if starts != 0 {
		t.Fatalf("the executor was asked to start %d workloads for a dispatch that was never recorded", starts)
	}
}

// TestADeadMembersUnrecordedDispatchIsReaped: a member that died between
// starting a workload and recording its run left a dispatching claim, which
// the leader used to clear — and the project could be started again beside a
// workload whose lease nobody kept or revoked. The leader now stops the
// workload, takes its credential back and retires the intent before it clears
// the claim.
func TestADeadMembersUnrecordedDispatchIsReaped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	r := newSupervisionRig(t)
	victim := newClusterMember(t, r.dir)
	survivor := newClusterMember(t, r.dir)
	waitCluster(t, "the members to see each other", func() bool {
		return victim.node.HasPeers() && survivor.node.HasPeers()
	})

	// The victim's dispatch, as far as it got: its claim marked with the run,
	// its intent naming the workload and the lease, the workload running.
	const runID = "run_reap_unit"
	handle, err := r.node.Start(context.Background(), executor.Spec{Labels: map[string]string{executor.LabelRunID: runID}})
	if err != nil {
		t.Fatal(err)
	}
	prevHolder := leaseHolderID
	leaseHolderID = func() string { return victim.node.ID() }
	lease := acquireSecretLease(r.dir, r.dir, r.node, runID, nil)
	leaseHolderID = prevHolder
	if lease == nil {
		t.Fatal("no lease was issued")
	}
	stopKeepaliveForTest(lease)
	liveLeases.removeIf(lease) // it lived in the victim's memory
	if _, ok, err := victim.node.Claim(ownerRun, r.dir, runOwnerMeta{
		Handler: "run", RunClaimMeta: hubcluster.RunClaimMeta{Dispatching: true, RunID: runID}, Executor: r.node.id,
	}); err != nil || !ok {
		t.Fatalf("the victim's claim: %v %v", ok, err)
	}
	db, err := statedb.Open(state.DBPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutDispatchIntent(statedb.DispatchIntentRow{
		RunID: runID, InstanceID: victim.node.ID(), ExecutorID: r.node.id, Driver: r.node.Kind(),
		ProjectPath: r.dir, HandleID: handle.ID, LeaseIDs: lease.LeaseIDs(), State: statedb.DispatchIntentStarted,
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// A dispatching claim whose dispatch reached its executor holds the
	// project while its member is freshly gone.
	if err := victim.node.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "the survivor to lead", survivor.node.IsLeader)
	if !survivor.srv.peerRunExecuting(r.dir) {
		t.Fatal("the project of a dispatch that reached its executor was released the moment its member died")
	}

	survivor.srv.adoptOrphanedRuns()

	w, ok := r.node.workload(handle.ID)
	if !ok || !w.ended || w.abandoned == "" {
		t.Fatalf("the unrecorded workload was left running (ended %v, abandoned %q)", w.ended, w.abandoned)
	}
	db, err = statedb.Open(state.DBPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.GetDispatchIntent(runID); !errors.Is(err, statedb.ErrDispatchIntentNotFound) {
		t.Errorf("the reaped dispatch's intent = %v, want retired", err)
	}
	if _, err := db.GetSecretLease(lease.LeaseIDs()[0]); err == nil {
		t.Error("the reaped workload's lease record was left for nobody to keep")
	}
	if _, _, found := survivor.srv.clusterRunOwner(r.dir); found {
		t.Error("the dispatching claim outlived the reap")
	}
}

// newProbingMember is newClusterMember with probing on, so a member that
// stops answering is judged unresponsive within a few hundred milliseconds.
func newProbingMember(t *testing.T, dir string) *clusterMember {
	t.Helper()
	var (
		mu      sync.RWMutex
		handler http.Handler = http.NotFoundHandler()
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		h := handler
		mu.RUnlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	opts := fastClusterOptions(state.DBPath(dir), ts.URL)
	opts.ProbeInterval = 40 * time.Millisecond
	opts.ProbeTimeout = 150 * time.Millisecond
	opts.UnresponsiveAfter = 400 * time.Millisecond
	node, err := hubcluster.Join(opts)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	srv := New(dir, 0, "")
	srv.Cluster = node
	srv.startClusterBus()
	ctx, cancel := context.WithCancel(context.Background())
	node.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = node.Close()
	})
	swap := func(h http.Handler) {
		mu.Lock()
		handler = h
		mu.Unlock()
	}
	swap(srv.Handler())
	return &clusterMember{srv: srv, node: node, ts: ts, swap: swap}
}

// TestAMemberThatStopsAnsweringHasItsRunAdopted: a member whose heartbeat
// goes on while its requests hang used to keep its runs for ever — adoption
// is for members that are gone. Judged unresponsive, it is treated as gone:
// its run is adopted while its heartbeat still says alive.
func TestAMemberThatStopsAnsweringHasItsRunAdopted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	r := newSupervisionRig(t)
	a := newProbingMember(t, r.dir)
	b := newProbingMember(t, r.dir)
	waitCluster(t, "the members to see each other", func() bool { return a.node.HasPeers() && b.node.HasPeers() })

	handle, err := r.node.Start(context.Background(), executor.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.node.finish(handle.ID, executor.StateExited, 0, "", nil) })
	stuck, healthy := a, b
	if _, ok, err := stuck.node.Claim(ownerRun, r.dir, runOwnerMeta{Executor: r.node.id, Handle: handle.ID, Handler: "run"}); err != nil || !ok {
		t.Fatalf("the stuck member's claim: %v %v", ok, err)
	}

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stuck.swap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))

	waitCluster(t, "the healthy member to judge the stuck one unresponsive", func() bool {
		return !healthy.node.Responsive(stuck.node.ID())
	})
	if !healthy.node.IsAlive(stuck.node.ID()) {
		t.Fatal("the stuck member stopped heartbeating; this test is about one that does not")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if o, _, found := healthy.srv.clusterRunOwner(r.dir); found && o.Self {
			return
		}
		healthy.srv.adoptOrphanedRuns()
		time.Sleep(50 * time.Millisecond)
	}
	o, _, found := healthy.srv.clusterRunOwner(r.dir)
	t.Fatalf("the run of a member that stopped answering was not adopted: owner %+v (found %v)", o, found)
}
