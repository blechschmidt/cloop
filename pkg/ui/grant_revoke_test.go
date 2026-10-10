package ui

// grant_revoke_test.go: revoking a grant takes its material back from the
// workloads holding it (Task 20403) — through the Secrets panel, the lease
// janitor, a CLI's announcement on the bus and another hub member — and a
// superseded grant leaves the run alone.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/drivertest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// revokeRecordingExec is a hub-local executor — a stand-in for the container
// and Kubernetes drivers — holding one lease, recording every revocation it
// is asked for.
type revokeRecordingExec struct {
	stubExec
	mu       sync.Mutex
	held     string
	requests []executor.RevokeRequest
}

func (e *revokeRecordingExec) SupportsRevocation() bool { return true }
func (e *revokeRecordingExec) HoldsLease(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.held != "" && e.held == id
}
func (e *revokeRecordingExec) Leases() []string { return nil }
func (e *revokeRecordingExec) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	e.mu.Lock()
	e.requests = append(e.requests, req)
	e.mu.Unlock()
	now := time.Now()
	return executor.RevokeOutcome{
		LeaseID: req.LeaseID, GrantID: req.GrantID, ExecutorID: e.id, Action: req.Effective(),
		State: executor.RevokeStateRevoked, SentAt: now, AckedAt: now,
		Ack: &executor.RevokeReport{LeaseID: req.LeaseID, GrantID: req.GrantID, Known: true, FilesRemoved: 1},
	}
}
func (e *revokeRecordingExec) Revocations() []executor.RevokeOutcome { return nil }

func (e *revokeRecordingExec) asked() []executor.RevokeRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]executor.RevokeRequest(nil), e.requests...)
}

// grantRevokeFixture is a control plane whose one executor holds a lease of
// two grants — a GitHub PAT delivered as files and an env secret — and the
// Server serving it.
type grantRevokeFixture struct {
	dir       string
	srv       *Server
	ex        *revokeRecordingExec
	sl        *secretLease
	broker    *secretbroker.Broker
	patGrant  secretbroker.Grant
	envGrant  secretbroker.Grant
	closeDB   func()
	execID    string
	pat, env  secretbroker.Secret
	project   string
	serverURL string
}

func newGrantRevokeFixture(t *testing.T, srv func(dir string) *Server) *grantRevokeFixture {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "grant-revoke-unit-passphrase")
	f := &grantRevokeFixture{execID: "grant-revoke-" + strings.ReplaceAll(t.Name(), "/", "-")}
	f.dir = setupProjectDir(t, "grant revocation", nil)
	f.project = f.dir

	broker, closeDB, err := openUIBroker(f.dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	f.broker, f.closeDB = broker, closeDB
	t.Cleanup(closeDB)
	ctx := context.Background()
	f.pat, err = broker.Mint(ctx, secretbroker.MintRequest{
		Name: "deploy-pat", Kind: secretbroker.KindGitHubPAT, Payload: []byte("ghp_grantrevoke0123456789abcdefghijklm"), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint PAT: %v", err)
	}
	f.env, err = broker.Mint(ctx, secretbroker.MintRequest{
		Name: "metrics", Kind: secretbroker.KindEnv, Payload: []byte(`{"METRICS_TOKEN":"metrics-canary-0123456789"}`), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint env: %v", err)
	}
	subject := secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: f.execID}
	f.patGrant, err = broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: f.pat.ID, Subject: subject, Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL: time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant PAT: %v", err)
	}
	f.envGrant, err = broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: f.env.ID, Subject: subject, Constraints: secretbroker.Constraints{EnvKeys: []string{"METRICS_TOKEN"}},
		TTL: time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant env: %v", err)
	}

	f.ex = &revokeRecordingExec{stubExec: stubExec{id: f.execID, caps: executor.Capabilities{
		SupportsSecretFiles: true, SecretFilesFromHostPath: false,
	}}}
	if err := executor.Register(f.ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(f.execID) })

	f.srv = srv(f.dir)
	f.sl = acquireSecretLease(f.dir, f.project, f.ex, "run_grant_revoke", nil)
	if f.sl == nil || f.sl.delivery == nil {
		t.Fatal("no delivered lease was issued")
	}
	stopKeepaliveForTest(f.sl)
	t.Cleanup(f.sl.Close)
	f.ex.mu.Lock()
	f.ex.held = f.sl.lease.ID
	f.ex.mu.Unlock()
	if got := f.sl.broker.HeldGrantIDs(f.sl.lease.ID); len(got) != 2 {
		t.Fatalf("the lease carries %v, want both grants", got)
	}
	return f
}

// deleteGrant revokes through the Secrets panel's route.
func (f *grantRevokeFixture) deleteGrant(t *testing.T, id string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/grants/"+id, nil)
	req.Host = "127.0.0.1" // a hub with no sign-in answers to loopback only
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/grants/%s = %d: %s", id, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// filesOf returns the names of the files the lease still holds for grantID.
func (f *grantRevokeFixture) filesOf(grantID string) []string {
	var out []string
	for _, sf := range f.sl.SecretFiles() {
		if sf.GrantID == grantID {
			out = append(out, sf.Name)
		}
	}
	return out
}

// TestRevokingAGrantReachesItsHoldersAndTheLeaseKeepsTheOthers is the panel's
// half (Task 20403): DELETE /api/grants/{id} takes the grant's material back
// from the hub's copy and every holder at once, reports what each did, and the
// lease goes on with the grant nobody revoked.
func TestRevokingAGrantReachesItsHoldersAndTheLeaseKeepsTheOthers(t *testing.T) {
	f := newGrantRevokeFixture(t, func(dir string) *Server { return New(dir, 0, "") })
	if len(f.filesOf(f.patGrant.ID)) == 0 {
		t.Fatal("precondition: the PAT grant delivered no files")
	}

	out := f.deleteGrant(t, f.patGrant.ID)
	if out["state"] != "revoked" {
		t.Fatalf("state = %v, want revoked (%v)", out["state"], out["note"])
	}
	leases, _ := out["leases"].([]any)
	if len(leases) != 1 {
		t.Fatalf("leases = %v, want the one lease carrying the grant", out["leases"])
	}
	first, _ := leases[0].(map[string]any)
	if first["lease_id"] != f.sl.lease.ID || first["grant_id"] != f.patGrant.ID || first["kept"] != true {
		t.Errorf("lease outcome = %v; want the lease, the revoked grant, and that the lease goes on", first)
	}
	if local, _ := out["local"].([]any); len(local) != 1 {
		t.Errorf("local holders = %v, want the executor's report", out["local"])
	}
	if note, _ := out["note"].(string); !strings.Contains(note, "taken back") {
		t.Errorf("note = %q; it must say the material was taken back", note)
	}

	asked := f.ex.asked()
	if len(asked) != 1 || asked[0].LeaseID != f.sl.lease.ID || asked[0].GrantID != f.patGrant.ID {
		t.Fatalf("the executor was asked %+v; want exactly the revoked grant of the lease", asked)
	}
	if !liveLeases.held(f.sl.lease.ID) {
		t.Fatal("the lease was ended although it carries a grant nobody revoked")
	}
	if got := f.sl.broker.HeldGrantIDs(f.sl.lease.ID); !slices.Equal(got, []string{f.envGrant.ID}) {
		t.Errorf("the lease carries %v, want only the env grant", got)
	}
	if files := f.filesOf(f.patGrant.ID); len(files) != 0 {
		t.Errorf("the hub still holds the revoked grant's files %v, ready to re-deliver", files)
	}
	if _, err := f.sl.broker.Extend(context.Background(), f.sl.lease.ID); err != nil {
		t.Errorf("the lease cannot be extended on the grant nobody revoked: %v", err)
	}

	// Revoke is idempotent: the second call takes nothing back again.
	again := f.deleteGrant(t, f.patGrant.ID)
	if again["already_revoked"] != true {
		t.Errorf("second revoke = %v, want already_revoked", again)
	}
	if n := len(f.ex.asked()); n != 1 {
		t.Errorf("a repeat revocation was cascaded again: %d requests", n)
	}
}

// TestTheJanitorTakesBackAGrantRevokedBehindTheHubsBack: a grant revoked by
// something that told no hub — a CLI against a hub reading no bus, an older
// binary sharing the control plane — is taken back at the janitor's next pass,
// not at the lease's deadline, and the lease keeps the other grant.
func TestTheJanitorTakesBackAGrantRevokedBehindTheHubsBack(t *testing.T) {
	f := newGrantRevokeFixture(t, func(dir string) *Server { return New(dir, 0, "") })
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeGrant(f.patGrant.ID, time.Now()); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if len(f.ex.asked()) != 0 {
		t.Fatal("a store write alone reached the executor; the test would prove nothing")
	}

	f.srv.sweepExpiredLeases(time.Now())

	asked := f.ex.asked()
	if len(asked) != 1 || asked[0].GrantID != f.patGrant.ID {
		t.Fatalf("one janitor pass asked %+v, want the revoked grant taken back", asked)
	}
	if !liveLeases.held(f.sl.lease.ID) {
		t.Fatal("the janitor ended the lease instead of taking back one grant")
	}
	// And a second pass does not ask again.
	f.srv.sweepExpiredLeases(time.Now())
	if n := len(f.ex.asked()); n != 1 {
		t.Errorf("a second janitor pass asked again: %d requests", n)
	}
}

// TestALapsedLeaseIsTakenBackFromTheHubLocalDrivers: a lease that lapsed is
// lapsed everywhere — a container's staged files and a Pod's lease Secret
// included, which the janitor used to leave until the workload exited.
func TestALapsedLeaseIsTakenBackFromTheHubLocalDrivers(t *testing.T) {
	f := newGrantRevokeFixture(t, func(dir string) *Server { return New(dir, 0, "") })
	now := f.sl.ExpiresAt().Add(time.Minute)

	swept := f.srv.sweepExpiredLeases(now)

	if len(swept) != 1 || swept[0].LeaseID != f.sl.lease.ID {
		t.Fatalf("swept %+v, want the lapsed lease for the agents", swept)
	}
	asked := f.ex.asked()
	if len(asked) != 1 || asked[0].LeaseID != f.sl.lease.ID || asked[0].GrantID != "" {
		t.Fatalf("the hub-local driver was asked %+v; want the whole lapsed lease", asked)
	}
	if liveLeases.held(f.sl.lease.ID) {
		t.Error("the lapsed lease is still registered")
	}
}

// TestASupersededGrantLeavesTheRunningWorkloadWorking is the trap: an edit
// revokes the old grant only after minting its successor, and cutting the run
// off would break work the successor still authorises. Nothing is taken back,
// and the lease stands on the successor past the old grant's revocation.
func TestASupersededGrantLeavesTheRunningWorkloadWorking(t *testing.T) {
	f := newGrantRevokeFixture(t, func(dir string) *Server { return New(dir, 0, "") })
	ctx := context.Background()
	successor, err := f.broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: f.pat.ID, Subject: f.patGrant.Subject, TTL: 2 * time.Hour, Actor: "test",
		Constraints: secretbroker.Constraints{Repos: []string{"acme/app"}},
	})
	if err != nil {
		t.Fatalf("Grant successor: %v", err)
	}
	bs, err := openBrokersAt(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.close()
	if err := f.srv.supersedeGrant(ctx, bs, f.patGrant.ID, successor.ID, "operator"); err != nil {
		t.Fatalf("supersedeGrant: %v", err)
	}

	if asked := f.ex.asked(); len(asked) != 0 {
		t.Fatalf("a supersession asked the executor to give back %+v", asked)
	}
	if !liveLeases.held(f.sl.lease.ID) || len(f.filesOf(f.patGrant.ID)) == 0 {
		t.Fatal("a supersession took the running lease's material away")
	}
	if got := f.sl.broker.WithdrawnGrants(f.sl.lease.ID); len(got) != 0 {
		t.Fatalf("the superseded grant is reported withdrawn: %+v", got)
	}
	if _, err := f.sl.broker.Extend(ctx, f.sl.lease.ID); err != nil {
		t.Fatalf("the lease cannot be extended on the successor: %v", err)
	}
	f.srv.sweepExpiredLeases(time.Now())
	if asked := f.ex.asked(); len(asked) != 0 {
		t.Fatalf("the janitor withdrew a superseded grant whose successor stands: %+v", asked)
	}
	if g, _ := f.broker.LookupGrant(f.patGrant.ID); g.RevokedCause != secretbroker.RevokedSuperseded || g.SupersededBy != successor.ID {
		t.Errorf("the grant records cause %q successor %q", g.RevokedCause, g.SupersededBy)
	}

	// The successor revoked in its turn: now the run loses the material.
	f.deleteGrant(t, successor.ID)
	asked := f.ex.asked()
	if len(asked) != 1 || asked[0].GrantID != f.patGrant.ID {
		t.Fatalf("revoking the successor asked %+v; want the superseded grant the lease held taken back", asked)
	}
}

// TestACLIRevocationReachesARunningHubThroughTheBus: `cloop secret revoke`
// revokes from a process that holds no lease, and announces it; the running
// member takes the grant back from what it holds and says so.
func TestACLIRevocationReachesARunningHubThroughTheBus(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	var member *clusterMember
	f := newGrantRevokeFixture(t, func(dir string) *Server {
		member = newClusterMember(t, dir)
		return member.srv
	})
	waitCluster(t, "the member to be alive", func() bool {
		db, err := statedb.Open(state.DBPath(f.dir))
		if err != nil {
			return false
		}
		defer db.Close()
		rows, _ := db.ListHubMembers()
		for _, r := range rows {
			if r.InstanceID == member.node.ID() && hubcluster.RowAlive(r, time.Now()) {
				return true
			}
		}
		return false
	})

	// The CLI: revoke in the store (no subscriber in its process), then
	// announce.
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeGrant(f.patGrant.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	rep, err := AnnounceGrantRevoked(db, "cli-test", GrantRevocationAnnouncement{
		GrantID: f.patGrant.ID, Actor: "operator",
	}, 10*time.Second)
	if err != nil {
		t.Fatalf("AnnounceGrantRevoked: %v", err)
	}
	if len(rep.Answered) != 1 || rep.Answered[0].Member != member.node.ID() || rep.Answered[0].Leases != 1 {
		t.Fatalf("report = %+v; want the member to answer for the one lease", rep)
	}
	if len(rep.Silent) != 0 || rep.NoHub {
		t.Errorf("report = %+v", rep)
	}
	asked := f.ex.asked()
	if len(asked) != 1 || asked[0].GrantID != f.patGrant.ID {
		t.Fatalf("the executor was asked %+v", asked)
	}

	// A forged announcement for a grant that is not revoked takes nothing.
	rep, err = AnnounceGrantRevoked(db, "cli-test", GrantRevocationAnnouncement{GrantID: f.envGrant.ID}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Answered) != 1 || rep.Answered[0].Leases != 0 {
		t.Errorf("a live grant's announcement was acted on: %+v", rep)
	}
	if n := len(f.ex.asked()); n != 1 {
		t.Errorf("a live grant was taken back on a bus event's word: %d requests", n)
	}
}

// TestAPeerHeldLeaseIsScrubbedThroughTheClusterFanOut: a lease lives in the
// memory of the member holding it, so a revocation made on another member
// reaches it through the cluster fan-out — and the peer's answer is part of
// what the revoking member reports.
//
// Two members in one test binary share the lease registry, so the lease is
// kept out of it until member B is asked: what B finds is then what only B
// would hold in a real deployment.
func TestAPeerHeldLeaseIsScrubbedThroughTheClusterFanOut(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	var a, b *clusterMember
	var hide sync.Once
	f := newGrantRevokeFixture(t, func(dir string) *Server {
		a = newClusterMember(t, dir)
		b = newClusterMember(t, dir)
		return a.srv
	})
	waitCluster(t, "the members to see each other", func() bool { return a.node.HasPeers() && b.node.HasPeers() })
	liveLeases.removeIf(f.sl)
	var askedB bool
	inner := b.srv.Handler()
	b.swap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == clusterAPIGrantRevoked {
			askedB = true
			hide.Do(func() { liveLeases.add(f.sl) })
		}
		inner.ServeHTTP(w, r)
	}))

	out := f.deleteGrant(t, f.patGrant.ID)
	if !askedB {
		t.Fatal("the revoking member did not ask its peer")
	}
	leases, _ := out["leases"].([]any)
	var fromB bool
	for _, l := range leases {
		m, _ := l.(map[string]any)
		if m["lease_id"] == f.sl.lease.ID && m["member"] == b.node.ID() {
			fromB = true
		}
	}
	if !fromB {
		t.Fatalf("leases = %v; want member %s's withdrawal of the lease", out["leases"], b.node.ID())
	}
	asked := f.ex.asked()
	if len(asked) != 1 || asked[0].GrantID != f.patGrant.ID {
		t.Fatalf("the holder was asked %+v", asked)
	}
}

// TestOneJanitorPassTakesALapsedLeaseFromContainersAndPods: a lease that lapsed
// is lapsed everywhere, and the hub-local drivers are among the holders — a
// container's staged lease files and a Pod's lease Secret used to keep an
// expired credential until the workload exited (Task 20403). Driven against
// the real container and Kubernetes drivers, through stand-ins for the runtime
// CLI and the API server.
func TestOneJanitorPassTakesALapsedLeaseFromContainersAndPods(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "janitor-drivers-unit-passphrase")
	dir := setupProjectDir(t, "lapsed lease", nil)
	const token = "ghp_janitorlapsed0123456789abcdefghijk"
	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{Name: "lapsing-pat",
		Kind: secretbroker.KindGitHubPAT, Payload: []byte(token), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: dir},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}}, TTL: time.Hour, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	closeDB()
	srv := New(dir, 0, "")
	ctx := context.Background()

	// A container.
	ctr, err := container.New(container.Options{ID: "janitor-ctr",
		Runtime: drivertest.ContainerRuntime(t, t.TempDir()), Image: drivertest.Image})
	if err != nil {
		t.Fatalf("container.New: %v", err)
	}
	if err := executor.Register(ctr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ctr.ID()) })
	ctrLease := acquireSecretLease(dir, dir, ctr, "run_janitor_ctr", nil)
	if ctrLease == nil || ctrLease.delivery == nil {
		t.Fatal("no lease was delivered to the container")
	}
	stopKeepaliveForTest(ctrLease)
	t.Cleanup(ctrLease.Close)
	workDir := t.TempDir()
	if os.Geteuid() == 0 {
		if err := os.Chown(workDir, 1000, 1000); err != nil {
			t.Skipf("cannot hand the work directory to an unprivileged uid: %v", err)
		}
	}
	before := stagedTokens(token)
	spec, err := applyLease(executor.Spec{WorkDir: workDir, Argv: []string{"sleep", "60"}}, ctr, ctrLease)
	if err != nil {
		t.Fatalf("applyLease: %v", err)
	}
	ctrHandle, err := ctr.Start(ctx, spec)
	if err != nil {
		t.Fatalf("container start: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Signal(context.Background(), ctrHandle.ID, executor.SignalKill) })
	var staged []string
	for _, p := range stagedTokens(token) {
		if !slices.Contains(before, p) {
			staged = append(staged, p)
		}
	}
	if len(staged) == 0 {
		t.Fatal("the container's token was not staged on this host")
	}

	// A Pod.
	api := drivertest.NewKubeAPI(t)
	pods, err := kubernetes.New(kubernetes.Options{ID: "janitor-k8s", Namespace: "cloop",
		Image: drivertest.Image, Credentials: drivertest.KubeSource{Rest: api.REST()}})
	if err != nil {
		t.Fatalf("kubernetes.New: %v", err)
	}
	t.Cleanup(pods.Close)
	if err := executor.Register(pods); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(pods.ID()) })
	podLease := acquireSecretLease(dir, dir, pods, "run_janitor_k8s", nil)
	if podLease == nil {
		t.Fatal("no lease was delivered to the Pod")
	}
	stopKeepaliveForTest(podLease)
	t.Cleanup(podLease.Close)
	pspec, err := applyLease(executor.Spec{WorkDir: t.TempDir(), Argv: []string{"sleep", "60"}}, pods, podLease)
	if err != nil {
		t.Fatalf("applyLease: %v", err)
	}
	if _, err := pods.Start(ctx, pspec); err != nil {
		t.Fatalf("kubernetes start: %v", err)
	}
	secretName := api.WaitSecret(t, "cloop-lease-")
	if api.KeyHolding(secretName, token+"\n") == "" && api.KeyHolding(secretName, token) == "" {
		t.Fatalf("the Pod's lease Secret %s does not hold the token", secretName)
	}

	// Both leases lapse; one janitor pass.
	now := ctrLease.ExpiresAt()
	if p := podLease.ExpiresAt(); p.After(now) {
		now = p
	}
	srv.sweepExpiredLeases(now.Add(time.Minute))

	for _, p := range staged {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("the lapsed lease's token is still staged for the container at %s", p)
		}
	}
	for k, v := range api.SecretData(secretName) {
		if strings.Contains(string(v), token) {
			t.Errorf("the lapsed lease's token is still in the Pod's lease Secret, under %s", k)
		}
	}
}

// stagedTokens returns the files in lease directories on this host holding
// token.
func stagedTokens(token string) []string {
	var out []string
	for _, root := range []string{"/dev/shm", os.TempDir()} {
		dirs, _ := os.ReadDir(root)
		for _, d := range dirs {
			if !d.IsDir() || !strings.HasPrefix(d.Name(), "cloop-lease-") {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(root, d.Name()))
			for _, f := range files {
				p := filepath.Join(root, d.Name(), f.Name())
				if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), token) {
					out = append(out, p)
				}
			}
		}
	}
	return out
}
