package ui

// Two hub processes serving one control plane, in one test process (Task
// 20354). Each member is a real Server with its own hubcluster.Node over the
// same state.db and its own HTTP listener, so what crosses between them —
// the bus, forwarded requests, ownership rows — crosses exactly as it would
// between two `cloop ui` processes. What these tests cannot reach is the
// process-wide plumbing two Servers in one binary share (the executor
// registry, the agent hub); tests/cluster runs real processes for that.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/state"
)

// clusterMember is one hub process of a test cluster.
type clusterMember struct {
	srv  *Server
	node *hubcluster.Node
	ts   *httptest.Server
	// swap replaces the handler the member's address serves, for a test that
	// has to see — or stand in front of — what its peers ask it.
	swap func(http.Handler)
}

func fastClusterOptions(dbPath, advertise string) hubcluster.Options {
	return hubcluster.Options{
		DBPath:         dbPath,
		AdvertiseURL:   advertise,
		Heartbeat:      40 * time.Millisecond,
		MemberTTL:      500 * time.Millisecond,
		BusPoll:        15 * time.Millisecond,
		BusFlush:       5 * time.Millisecond,
		Campaign:       30 * time.Millisecond,
		LeaderTTL:      600 * time.Millisecond,
		LeaderInterval: 60 * time.Millisecond,
	}
}

// newClusterMember starts one member serving the control plane at dir.
func newClusterMember(t *testing.T, dir string) *clusterMember {
	t.Helper()
	return newClusterMemberWithToken(t, dir, "")
}

// newClusterMemberWithToken is newClusterMember for a member given a static
// token, as `cloop ui --token` gives one.
func newClusterMemberWithToken(t *testing.T, dir, token string) *clusterMember {
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

	node, err := hubcluster.Join(fastClusterOptions(state.DBPath(dir), ts.URL))
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	srv := New(dir, 0, token)
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

// clusterPair starts two members over one project and waits until each sees
// the other.
func clusterPair(t *testing.T) (dir string, a, b *clusterMember) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	dir = setupProjectDir(t, "one control plane, two hubs", nil)
	a = newClusterMember(t, dir)
	b = newClusterMember(t, dir)
	waitCluster(t, "the members to see each other", func() bool {
		return a.node.HasPeers() && b.node.HasPeers()
	})
	return dir, a, b
}

// waitCluster polls cond until it holds or five seconds pass.
func waitCluster(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// nextMessage returns the next message of type typ a hub client receives.
func nextMessage(t *testing.T, hc *hubClient, typ string) wsMessage {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-hc.ch:
			if msg.Type == typ {
				return msg
			}
		case <-deadline:
			t.Fatalf("no %q message arrived", typ)
			return wsMessage{}
		}
	}
}

func TestClusterRelaysLiveOutputAndRunStateToOtherMembers(t *testing.T) {
	dir, a, b := clusterPair(t)
	watcher := subscribe(t, b.srv, dir, "viewer@example.com")

	a.srv.liveLogStartRun(dir)
	a.srv.publishRunState(dir, true)
	msg := nextMessage(t, watcher, "run_state")
	if !strings.Contains(string(msg.Data), `"running":true`) {
		t.Fatalf("run_state = %s, want running", msg.Data)
	}
	if !b.srv.liveLogRunningFor(dir) {
		t.Fatal("the member that did not start the run does not show it running")
	}
	if b.srv.liveLogLocalRunningFor(dir) {
		t.Fatal("a relayed run counts as this member's own; stale recovery would trust it")
	}

	a.srv.broadcastLog(dir, "line one\n")
	a.srv.broadcastLog(dir, "line two\n")
	var got strings.Builder
	waitCluster(t, "both lines to be relayed", func() bool {
		select {
		case m := <-watcher.ch:
			if m.Type == "step_output" {
				var p struct{ Chunk string }
				_ = json.Unmarshal(m.Data, &p)
				got.WriteString(p.Chunk)
			}
		default:
		}
		return strings.Contains(got.String(), "line two")
	})
	if !strings.Contains(got.String(), "line one\nline two\n") {
		t.Fatalf("relayed output = %q, want both lines in order", got.String())
	}
	// And it is in B's replay buffer, so a dashboard connecting to B mid-run
	// is shown the backlog.
	if replay := strings.Join(b.srv.liveLogReplay(dir), ""); !strings.Contains(replay, "line two") {
		t.Fatalf("B's replay buffer = %q, want the relayed output", replay)
	}

	a.srv.publishRunState(dir, false)
	msg = nextMessage(t, watcher, "run_state")
	if !strings.Contains(string(msg.Data), `"running":false`) {
		t.Fatalf("run_state = %s, want stopped", msg.Data)
	}
}

// TestClusterForgetsARunWhenItsMemberDies: a member that dies mid-run cannot
// say its run stopped; the others must not keep showing it as streaming.
func TestClusterForgetsARunWhenItsMemberDies(t *testing.T) {
	dir, a, b := clusterPair(t)
	a.srv.liveLogStartRun(dir)
	a.srv.publishRunState(dir, true)
	waitCluster(t, "B to relay the run", func() bool { return b.srv.liveLogRunningFor(dir) })

	if err := a.node.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "B to drop the relayed run", func() bool { return !b.srv.liveLogRunningFor(dir) })
}

func TestClusterMergesPresenceAcrossMembers(t *testing.T) {
	dir, a, b := clusterPair(t)
	onA := subscribe(t, a.srv, dir, "alice@example.com")
	onB := subscribe(t, b.srv, dir, "bob@example.com")
	a.srv.broadcastPresence(dir)
	b.srv.broadcastPresence(dir)

	for _, hc := range []*hubClient{onA, onB} {
		waitCluster(t, "a presence list naming both users", func() bool {
			for {
				select {
				case m := <-hc.ch:
					if m.Type == "presence" && strings.Contains(string(m.Data), "alice@example.com") &&
						strings.Contains(string(m.Data), "bob@example.com") {
						return true
					}
				default:
					return false
				}
			}
		})
	}
}

func TestClusterDeliversHubWideEventsToEveryMember(t *testing.T) {
	dir, a, b := clusterPair(t)
	watcher := subscribe(t, b.srv, dir, "admin@example.com")
	a.srv.broadcastExecutorUpdate("status:online", "edge-1")
	msg := nextMessage(t, watcher, "executor_update")
	if !strings.Contains(string(msg.Data), "edge-1") {
		t.Fatalf("executor_update = %s", msg.Data)
	}
	a.srv.broadcastSecretsUpdate("lease_revoked", "lease-1")
	nextMessage(t, watcher, "secrets_update")
	a.srv.broadcastAuditAppend("revoke")
	nextMessage(t, watcher, "audit_append")
}

// TestClusterFlagsConflictingEditsAcrossMembers: two people editing the same
// field of the same task through two members are told, as they would be
// through one.
func TestClusterFlagsConflictingEditsAcrossMembers(t *testing.T) {
	dir, a, b := clusterPair(t)
	if a.srv.checkAndRecordEdit(dir, "client-a", 7, []string{"title"}) {
		t.Fatal("the first edit was flagged")
	}
	waitCluster(t, "B to learn of A's edit", func() bool {
		b.srv.conflictMu.Lock()
		defer b.srv.conflictMu.Unlock()
		_, ok := b.srv.conflictTracker[dir]["7:title"]
		return ok
	})
	if !b.srv.checkAndRecordEdit(dir, "client-b", 7, []string{"title"}) {
		t.Fatal("an edit of the same field through another member within the window was not flagged")
	}
}

// TestClusterRunClaimIsExclusiveAndGuardsRecovery is the central safety
// property: a run another member streams is running, from every member's
// point of view — it cannot be started twice, and it is never "repaired".
func TestClusterRunClaimIsExclusiveAndGuardsRecovery(t *testing.T) {
	dir, a, b := clusterPair(t)
	if _, err := a.srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("A claimRun: %v", err)
	}
	if o, err := b.srv.claimRun(dir, "run"); err != errRunOwnedElsewhere || o.InstanceID != a.node.ID() {
		t.Fatalf("B claimRun = %v (owner %s), want errRunOwnedElsewhere naming A", err, o.InstanceID)
	}
	if !b.srv.projectExecuting(dir) {
		t.Fatal("B does not see A's run as executing")
	}

	// The persisted status says running, which is what stale-run recovery
	// repairs when nothing is behind it. On B nothing *local* is.
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Status = "running"
	if err := st.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	if b.srv.reconcileDeadRun(dir, runVerdict{}) {
		t.Fatal("B paused a project whose run A is streaming")
	}
	if st2, _ := state.Load(dir); st2.Status != "running" {
		t.Fatalf("status after B's recovery pass = %q, want running", st2.Status)
	}

	// Starting it on B is a 409, not a second harness.
	resp, err := http.Post(b.ts.URL+"/api/run", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/run on B while A runs = %d, want 409", resp.StatusCode)
	}

	a.srv.releaseRunClaim(dir)
	if b.srv.projectExecuting(dir) {
		t.Fatal("B still sees a run after A released it")
	}
	if !b.srv.reconcileDeadRun(dir, runVerdict{}) {
		t.Fatal("with the run gone, B did not clear the stale status")
	}
}

// TestClusterStopIsForwardedToTheRunsOwner: only the member streaming a run
// holds its handle, so Stop pressed on another member must reach it.
func TestClusterStopIsForwardedToTheRunsOwner(t *testing.T) {
	dir, a, b := clusterPair(t)
	if _, err := a.srv.claimRun(dir, "run"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(b.ts.URL+"/api/stop", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get(hubcluster.HeaderServedBy); got != a.node.ID() {
		t.Fatalf("Stop pressed on B was answered by %q, want the run's owner %q", got, a.node.ID())
	}
}

// TestClusterDeadOwnersRunHoldsItsProjectForTheGraceOnly: a run whose member
// died may be adopted by the member its agent reconnects to, so the project
// is left alone for a while — and then recovered, so a run nobody can reach
// does not wedge it.
func TestClusterDeadOwnersRunHoldsItsProjectForTheGraceOnly(t *testing.T) {
	dir, a, b := clusterPair(t)
	if _, err := a.srv.claimRun(dir, "run"); err != nil {
		t.Fatal(err)
	}
	// Record dispatch details, as a real run does: a claim still marked
	// "dispatching" belongs to a member that died before starting anything.
	if ok, err := a.node.UpdateMeta(ownerRun, dir, runOwnerMeta{Executor: "container", Handle: "h-1"}); err != nil || !ok {
		t.Fatalf("UpdateMeta = %v, %v", ok, err)
	}
	old := orphanRunGrace
	orphanRunGrace = 400 * time.Millisecond
	t.Cleanup(func() { orphanRunGrace = old })

	if err := a.node.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "B to judge A dead", func() bool { return !b.node.IsAlive(a.node.ID()) })
	if !b.srv.projectExecuting(dir) {
		t.Fatal("B treated the run of a member that just died as over")
	}
	waitCluster(t, "the grace to run out", func() bool { return !b.srv.projectExecuting(dir) })
}

func TestClusterRefusesForgedPeerClaims(t *testing.T) {
	_, _, b := clusterPair(t)
	req, _ := http.NewRequest(http.MethodGet, b.ts.URL+"/api/state", nil)
	req.Header.Set(hubcluster.HeaderPeer, "hub_forged")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged peer claim = %d, want 403", resp.StatusCode)
	}

	for _, path := range []string{clusterAPIAutoResume, clusterAPIRevokeLease, clusterAPIAgentOp, clusterAPIProxyGit + "/o/r/info/refs"} {
		resp, err := http.Post(b.ts.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("unsigned %s = %d, want 403", path, resp.StatusCode)
		}
	}
}

// TestClusterInternalCallsAreServed: a real peer call gets through.
func TestClusterInternalCallsAreServed(t *testing.T) {
	dir, a, b := clusterPair(t)
	bm, ok := a.node.Member(b.node.ID())
	if !ok {
		t.Fatal("A does not know B")
	}
	var out struct {
		OK      bool `json:"ok"`
		Started bool `json:"started"`
	}
	// Not paused, so nothing is started — but the call was authenticated,
	// routed and answered.
	if err := a.node.Call(context.Background(), bm, http.MethodPost, clusterAPIAutoResume,
		map[string]string{"project": dir}, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !out.OK || out.Started {
		t.Fatalf("reply = %+v", out)
	}
	// A directory that is not a registered project is refused: a member must
	// not be steerable into dispatching anywhere.
	err := a.node.Call(context.Background(), bm, http.MethodPost, clusterAPIAutoResume,
		map[string]string{"project": "/etc"}, nil)
	if err == nil {
		t.Fatal("auto-resume of an unregistered directory was accepted")
	}
}

// TestClusterQuotaCountersAreShared: a cap of one concurrent run is one across
// the cluster, not one per member.
func TestClusterQuotaCountersAreShared(t *testing.T) {
	_, a, b := clusterPair(t)
	resolver, err := quota.New(quota.Config{Defaults: quota.Limits{quota.ResConcurrentTasks: 1}})
	if err != nil {
		t.Fatal(err)
	}
	a.srv.SetQuotaPolicy(resolver)
	b.srv.SetQuotaPolicy(resolver)
	if !a.srv.quotas().Shared() || !b.srv.quotas().Shared() {
		t.Fatal("a cluster member's quota enforcer is not using the shared counters")
	}
	subj := quota.SubjectForIdentity("tenant@example.com")
	if _, err := a.srv.quotas().Admit(subj, quota.ResConcurrentTasks, 1); err != nil {
		t.Fatalf("first admission on A: %v", err)
	}
	if _, err := b.srv.quotas().Admit(subj, quota.ResConcurrentTasks, 1); err == nil {
		t.Fatal("B admitted a second concurrent run past a cap of one")
	}
	// Released on A, the slot is free on B.
	a.srv.quotas().Release(subj.Label(), quota.ResConcurrentTasks, 1)
	if _, err := b.srv.quotas().Admit(subj, quota.ResConcurrentTasks, 1); err != nil {
		t.Fatalf("admission on B after A released: %v", err)
	}
	// And B's view of usage, which the panel renders, is the shared one.
	if u := b.srv.quotas().Usage(subj.Label()); u[quota.ResConcurrentTasks] != 1 {
		t.Fatalf("B's usage = %v, want 1 concurrent task", u)
	}
}

// TestClusterRoutesAConversationToTheMemberHoldingIt: chat history and
// suggest jobs live in one member's memory.
func TestClusterRoutesAConversationToTheMemberHoldingIt(t *testing.T) {
	dir, a, b := clusterPair(t)
	if _, ok, err := a.node.Claim(ownerChat, dir, nil); err != nil || !ok {
		t.Fatalf("A claim chat: %v %v", ok, err)
	}
	a.srv.chatMu.Lock()
	a.srv.chatHistories[dir] = []ChatMessage{{Role: "user", Content: "hello from A"}}
	a.srv.chatMu.Unlock()

	resp, err := http.Get(b.ts.URL + "/api/chat/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get(hubcluster.HeaderServedBy); got != a.node.ID() {
		t.Fatalf("history on B was served by %q, want A", got)
	}
	var hist []ChatMessage
	if err := json.NewDecoder(resp.Body).Decode(&hist); err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Content != "hello from A" {
		t.Fatalf("history = %+v", hist)
	}
}

// TestClusterRoutesALoginCallbackToTheMemberThatBeganIt.
func TestClusterRoutesALoginCallbackToTheMemberThatBeganIt(t *testing.T) {
	_, a, b := clusterPair(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc?state="+a.node.ID()+".abc&code=x", nil)
	rec := httptest.NewRecorder()
	if !b.srv.routeOIDCCallback(rec, req) {
		t.Fatal("B served a callback for a login A began")
	}
	if got := rec.Header().Get(hubcluster.HeaderServedBy); got != a.node.ID() {
		t.Fatalf("callback answered by %q, want A", got)
	}
	// Its own logins, and unprefixed states from before clustering, are
	// served where they land.
	for _, state := range []string{b.node.ID() + ".abc", "plainstate"} {
		req := httptest.NewRequest(http.MethodGet, "/auth/oidc?state="+state+"&code=x", nil)
		if b.srv.routeOIDCCallback(httptest.NewRecorder(), req) {
			t.Fatalf("state %q was forwarded", state)
		}
	}
}

// TestClusterForwardedProjectIsResolvedByPath: the member answering a
// forwarded request acts on the project the forwarding member meant, not on
// whatever its own index happens to say.
func TestClusterForwardedProjectIsResolvedByPath(t *testing.T) {
	dir, _, b := clusterPair(t)
	req := httptest.NewRequest(http.MethodGet, "/api/state?project_idx=999", nil)
	req.Header.Set(headerPeerWorkdir, dir)
	req = req.WithContext(hubcluster.WithPeerCall(req.Context(), hubcluster.PeerCall{}))
	if got := b.srv.resolveWorkDir(req); got != dir {
		t.Fatalf("resolveWorkDir = %q, want the forwarded %q", got, dir)
	}
	// Not from a verified peer: the header means nothing.
	plain := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	plain.Header.Set(headerPeerWorkdir, "/somewhere/else")
	if got := b.srv.resolveWorkDir(plain); got == "/somewhere/else" {
		t.Fatal("a client-supplied project header was honoured")
	}
	// A path that is not one of this hub's projects is not honoured either.
	odd := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	odd.Header.Set(headerPeerWorkdir, "/etc")
	odd = odd.WithContext(hubcluster.WithPeerCall(odd.Context(), hubcluster.PeerCall{}))
	if got := b.srv.resolveWorkDir(odd); got == "/etc" {
		t.Fatal("a forwarded project that is not registered here was honoured")
	}
}

// TestClusterStatusEndpoint reports both members and the leader.
func TestClusterStatusEndpoint(t *testing.T) {
	_, a, b := clusterPair(t)
	waitCluster(t, "a leader", func() bool { return a.node.IsLeader() || b.node.IsLeader() })
	resp, err := http.Get(b.ts.URL + "/api/cluster")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st clusterStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.Clustered || st.Self != b.node.ID() || len(st.Members) != 2 || st.Leader == "" {
		t.Fatalf("status = %+v", st)
	}
}
