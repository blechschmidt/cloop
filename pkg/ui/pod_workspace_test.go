package ui

// A Kubernetes Pod's workspace session survives the hub process that minted it
// (Task 20455), in one process: the real Kubernetes driver, built through the
// reconcile options `cloop ui` builds it with, dispatches against a stand-in
// API server; the restart drops the dispatching process's registries as a
// dying one does and builds a second driver on the same handle store; the
// init container's fetch is played by real git against the rig's proxy,
// presenting what the driver put in the Pod's workspace Secret.
// tests/kube TestAPodsWorkspaceSurvivesItsHubBeingKilled runs it on a cluster,
// and tests/cluster TestAPodsWorkspaceSessionIsAdoptedByAnotherMember with a
// second member adopting.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/drivertest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/reconcile"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const podExecutorID = "k8s-pod"

// podRig is the restore rig with a Kubernetes executor: a stand-in API server,
// the cluster credential and the forge's App granted to the executor, and the
// handle store a restarted process rehydrates from.
type podRig struct {
	*restoreRig
	api   *drivertest.KubeAPI
	cfg   *config.Config
	store *executor.MemoryHandleStore
	grant secretbroker.Grant
}

func newPodRig(t *testing.T) *podRig {
	t.Helper()
	r := newWorkspaceRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	p := &podRig{restoreRig: r, api: drivertest.NewKubeAPI(t), store: executor.NewMemoryHandleStore()}

	broker, closeDB, err := openUIBroker(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	ctx := context.Background()
	rest := p.api.REST()
	kc, err := broker.Mint(ctx, secretbroker.MintRequest{Name: "pod-kubeconfig", Kind: secretbroker.KindKubeconfig,
		Payload: []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: c
clusters:
- name: c
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: c
  context:
    cluster: c
    user: u
    namespace: cloop
users:
- name: u
  user:
    token: %s
`, rest.Server, base64.StdEncoding.EncodeToString(rest.CAData), rest.BearerToken)), Actor: "test"})
	if err != nil {
		t.Fatalf("Mint kubeconfig: %v", err)
	}
	subject := secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: podExecutorID}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: kc.ID, Subject: subject,
		Constraints: secretbroker.Constraints{Namespaces: []string{"cloop"}}, TTL: 24 * time.Hour, Actor: "test"}); err != nil {
		t.Fatalf("Grant kubeconfig: %v", err)
	}
	p.grant, err = broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: r.appGrant.SecretID, Subject: subject,
		Constraints: secretbroker.Constraints{Repos: []string{restoreRepo}, Permissions: []string{"contents:write"}},
		TTL:         24 * time.Hour, Actor: "test"})
	if err != nil {
		t.Fatalf("Grant the App to the Kubernetes executor: %v", err)
	}

	p.cfg = &config.Config{}
	k := &p.cfg.Executors.Kubernetes
	k.Enabled, k.ID, k.Namespace, k.Image = true, podExecutorID, "cloop", drivertest.Image
	k.KubeconfigSecret = "pod-kubeconfig"
	return p
}

// driver builds the Kubernetes driver as `cloop ui` does, over the handle
// store: what a hub process starting up registers.
func (p *podRig) driver() *kubernetes.Executor {
	t := p.t
	reg := executor.NewRegistry()
	off := false
	report := reconcile.FromConfig(context.Background(), p.dir, p.cfg, withPodWorkspaceSource(reconcile.Options{
		Registry: reg, SkipPreflight: true, Publish: &off, HandleStore: p.store, QuietWhenHealthy: true,
		Logf: t.Logf,
	}))
	ex, err := reg.Get(podExecutorID)
	if err != nil {
		t.Fatalf("the Kubernetes executor was not registered: %v (%+v)", err, report.Diagnostics)
	}
	k := ex.(*kubernetes.Executor)
	t.Cleanup(k.Close)
	return k
}

// podDispatch is what the dispatching process started, and what the run's
// owner row names.
type podDispatch struct {
	handle   executor.Handle
	pod      string
	meta     *runWorkspaceMeta
	lease    *secretLease
	session  string
	user     string
	token    string
	repo     string
	tokenSum string
}

// dispatch starts a run whose workspace is the forge's repository on ex, and
// binds its workspace lease as the hub's dispatch path does.
func (p *podRig) dispatch(ex *kubernetes.Executor, wb executor.WriteBackMode) podDispatch {
	t := p.t
	spec := executor.Spec{
		WorkDir: p.dir,
		Argv:    []string{"cloop", "run"},
		Labels:  map[string]string{"project": p.dir, "task_id": "1", executor.LabelRunID: "run_pod_1"},
		Workspace: executor.Workspace{Kind: executor.WorkspaceGit, Repo: p.forgeRepoURL(), Ref: "main",
			CredentialGrant: p.grant.ID},
	}
	if wb == executor.WriteBackPush {
		spec.Workspace.Ref = strings.Repeat("c", 40)
		spec.WriteBack = executor.WriteBack{Mode: executor.WriteBackPush, Branch: "cloop/run-pod-1"}
	}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	bindWorkspaceLease(ex, h.ID)
	d := podDispatch{handle: h, pod: p.api.WaitWorkspacePod(t, true), meta: liveLeases.workspaceForHandle(ex.ID(), h.ID)}
	if d.meta == nil {
		t.Fatal("the run's owner row would name no workspace lease")
	}
	d.lease = registeredLease(d.meta.Lease)
	if d.lease == nil || !d.lease.isWorkspace() {
		t.Fatal("the Pod's workspace lease is not kept alive")
	}
	stopKeepaliveForTest(d.lease)
	secret := "cloop-ws-" + h.ID
	data := p.api.SecretData(secret)
	d.user, d.token = string(data[kubernetes.EnvWorkspaceUser]), string(data[kubernetes.EnvWorkspaceToken])
	d.repo = p.api.InitContainerArg(d.pod, "--repo")
	d.session = d.meta.Session
	if d.session == "" || d.user != d.session || d.token == "" {
		t.Fatalf("the workspace Secret holds user %q for session %q (token %d bytes)", d.user, d.session, len(d.token))
	}
	if !strings.HasPrefix(d.repo, p.gitSrv.URL+"/") {
		t.Fatalf("the init container fetches %q, not through the proxy", d.repo)
	}
	sum := sha256.Sum256([]byte(d.token))
	d.tokenSum = hex.EncodeToString(sum[:])
	return d
}

// restart drops the dispatching process — its driver walks away from the
// Pod, its git proxy suspends what is recorded and its registries go — and
// starts a new one as holder.
func (p *podRig) restart(ex *kubernetes.Executor, d podDispatch, holder string) {
	ex.Close()
	activeGitProxy().reg.Suspend(d.session, "the hub is shutting down")
	liveLeases.removeIf(d.lease)
	p.startProcess()
	p.holder.Store(holder)
}

// fetch plays the init container: git, presenting what the workspace Secret
// holds, against the URL the Pod was told to fetch.
func (p *podRig) fetch(d podDispatch) (string, error) {
	return p.git(dispatched{gitID: d.user, gitToken: d.token}, "", "clone", "-q", d.repo,
		filepath.Join(p.t.TempDir(), "tool"))
}

// TestAPodsWorkspaceSessionSurvivesARestart is the task: a Pod's workspace
// lease and its pinned session are recorded when the Kubernetes driver leases
// them, named for the run, taken over with the run by the process that adopts
// it — the session restored under the same id and token hash — and the init
// container's fetch, presenting the token the stopped process minted, is
// served. Once the fetch is confirmed the session is closed and the lease
// released, by the process holding them.
func TestAPodsWorkspaceSessionSurvivesARestart(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	p := newPodRig(t)
	ex1 := p.driver()
	d := p.dispatch(ex1, executor.WriteBackNone)

	rec, err := p.db.GetSecretLease(d.meta.Lease)
	if err != nil || rec.Holder != "hub_old" || rec.RunID != "run_pod_1" || rec.ExecutorID != podExecutorID {
		t.Fatalf("the Pod's workspace lease's record = %+v, %v; want held by hub_old for run_pod_1 on %s",
			rec, err, podExecutorID)
	}
	row, ok := p.session(statedb.ProxySessionGit, d.session)
	if !ok || row.LeaseID != d.meta.Lease || row.Holder != "hub_old" || row.TokenSHA256 != d.tokenSum ||
		row.RunID != "run_pod_1" || !strings.Contains(row.Scope, restoreRepo) || !row.Open() {
		t.Fatalf("the Pod's workspace session's record = %+v (found %v)", row, ok)
	}
	if strings.Contains(row.Scope, d.token) || strings.Contains(rec.Record, d.token) {
		t.Fatal("a record carries the session token")
	}
	if held, ok := ex1.HeldWorkspaceCredential(d.handle.ID); !ok || held.SessionID != d.session ||
		held.LeaseID != d.meta.Lease {
		t.Fatalf("the driver names %+v (%v)", held, ok)
	}

	p.restart(ex1, d, "hub_new")
	ex2 := p.driver()
	waitFor(t, 10*time.Second, "the restarted driver to adopt the Pod", func() bool {
		_, err := ex2.Status(context.Background(), d.handle.ID)
		return err == nil
	})
	(&Server{WorkDir: p.dir}).takeOverWorkspaceLease(p.dir, ex2, d.handle.ID, d.meta)
	taken := registeredLease(d.meta.Lease)
	if taken == nil || !taken.isWorkspace() {
		t.Fatal("the restarted process holds no workspace lease")
	}
	stopKeepaliveForTest(taken)
	if rec, _ := p.db.GetSecretLease(d.meta.Lease); rec.Holder != "hub_new" {
		t.Fatalf("the workspace lease is held by %q after the takeover", rec.Holder)
	}
	row, _ = p.session(statedb.ProxySessionGit, d.session)
	if row.Holder != "hub_new" || !row.Open() || row.TokenSHA256 != d.tokenSum {
		t.Fatalf("the session's record after the takeover = %+v, want held by hub_new under the same token hash", row)
	}
	if got := p.auditRows(auditaction.ActionGitProxySessionRestored, d.session); len(got) != 1 ||
		!strings.Contains(got[0].Payload, "hub_old") {
		t.Fatalf("restored rows = %v, want one naming hub_old", got)
	}
	if held, ok := ex2.HeldWorkspaceCredential(d.handle.ID); !ok || held.SessionID != d.session {
		t.Fatalf("the adopting driver names %+v (%v), want the restored session", held, ok)
	}

	// The init container's fetch, presenting the stopped process's token.
	if out, err := p.fetch(d); err != nil {
		t.Fatalf("the init container's fetch after the restart: %v\n%s", err, out)
	}
	if row, _ := p.session(statedb.ProxySessionGit, d.session); !row.Open() {
		t.Fatalf("the session was closed before the fetch was confirmed: %+v", row)
	}

	// The fetch is confirmed: the adopting process ends both.
	p.api.FinishInitContainer(d.pod, 0)
	waitFor(t, 10*time.Second, "the session to close once the fetch is confirmed", func() bool {
		row, _ := p.session(statedb.ProxySessionGit, d.session)
		return !row.Open()
	})
	waitFor(t, 10*time.Second, "the workspace lease's release", func() bool {
		_, err := p.db.GetSecretLease(d.meta.Lease)
		return err != nil
	})
	if !p.api.SecretDeleted("cloop-ws-" + d.handle.ID) {
		t.Error("the adopting driver left the workspace Secret after the fetch it served")
	}
	if out, err := p.fetch(d); err == nil {
		t.Fatalf("a fetch after the session was closed was served:\n%s", out)
	}
}

// TestAPodsWriteBackSessionLivesUntilTheRunEnds: under write_back: push the
// adopting process keeps the restored session past the fetch, for the
// harness's push, and ends it with the workload.
func TestAPodsWriteBackSessionLivesUntilTheRunEnds(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	p := newPodRig(t)
	ex1 := p.driver()
	d := p.dispatch(ex1, executor.WriteBackPush)
	p.restart(ex1, d, "hub_new")
	ex2 := p.driver()
	waitFor(t, 10*time.Second, "the restarted driver to adopt the Pod", func() bool {
		_, err := ex2.Status(context.Background(), d.handle.ID)
		return err == nil
	})
	(&Server{WorkDir: p.dir}).takeOverWorkspaceLease(p.dir, ex2, d.handle.ID, d.meta)
	if sl := registeredLease(d.meta.Lease); sl != nil {
		stopKeepaliveForTest(sl)
	}
	if out, err := p.fetch(d); err != nil {
		t.Fatalf("the init container's fetch after the restart: %v\n%s", err, out)
	}
	p.api.FinishInitContainer(d.pod, 0)
	waitFor(t, 10*time.Second, "the driver to see the fetch end", func() bool {
		st, err := ex2.Status(context.Background(), d.handle.ID)
		return err == nil && st.State != ""
	})
	time.Sleep(200 * time.Millisecond)
	if row, _ := p.session(statedb.ProxySessionGit, d.session); !row.Open() {
		t.Fatalf("the session a push write-back presents was closed when the fetch ended: %+v", row)
	}
	if held, ok := ex2.HeldWorkspaceCredential(d.handle.ID); !ok || held.SessionID != d.session {
		t.Fatalf("after the fetch the adopting driver names %+v (%v)", held, ok)
	}

	// The workload ends — its write-back pushed or abandoned — and the
	// adopting process ends the session and the lease with it.
	p.api.FinishPod(d.pod, 0)
	waitFor(t, 30*time.Second, "the session to close with the workload", func() bool {
		row, _ := p.session(statedb.ProxySessionGit, d.session)
		return !row.Open()
	})
	waitFor(t, 10*time.Second, "the workspace lease's release", func() bool {
		_, err := p.db.GetSecretLease(d.meta.Lease)
		return err != nil
	})
}

// TestARevokedPodWorkspaceLeaseIsNeverRestored: a workspace lease revoked while
// no hub process held it is not taken over (Task 20419): its session is not
// restored, the driver is handed nothing, and the init container's fetch is
// refused.
func TestARevokedPodWorkspaceLeaseIsNeverRestored(t *testing.T) {
	setSessionAdoptionWait(t, time.Second)
	p := newPodRig(t)
	ex1 := p.driver()
	d := p.dispatch(ex1, executor.WriteBackNone)
	p.restart(ex1, d, "hub_new")
	broker, closeDB, err := openUIBroker(p.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, recorded, err := broker.RecordLeaseRevocation(secretbroker.LeaseRevocation{LeaseID: d.meta.Lease,
		Action: "kill", Reason: "revoked while its hub was down", Actor: "test"}); err != nil || !recorded {
		t.Fatalf("record the revocation: %v, %v", recorded, err)
	}
	closeDB()
	ex2 := p.driver()
	waitFor(t, 10*time.Second, "the restarted driver to adopt the Pod", func() bool {
		_, err := ex2.Status(context.Background(), d.handle.ID)
		return err == nil
	})
	(&Server{WorkDir: p.dir}).takeOverWorkspaceLease(p.dir, ex2, d.handle.ID, d.meta)
	if registeredLease(d.meta.Lease) != nil {
		t.Fatal("a revoked workspace lease was taken over")
	}
	if got := p.auditRows(auditaction.ActionGitProxySessionRestored, d.session); len(got) != 0 {
		t.Fatalf("the revoked lease's session was restored: %v", got)
	}
	if held, ok := ex2.HeldWorkspaceCredential(d.handle.ID); ok {
		t.Fatalf("the driver was handed the revoked lease's credential: %+v", held)
	}
	if out, err := p.fetch(d); err == nil {
		t.Fatalf("the init container's fetch through the revoked lease's session was served:\n%s", out)
	}
}

// TestAnUndecidedPodWorkspaceTakeoverIsRetried: a takeover the store cannot
// decide is retried (Task 20451), and the retry that takes the lease over
// restores the session and hands the driver its release, as the first attempt
// would have.
func TestAnUndecidedPodWorkspaceTakeoverIsRetried(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	p := newPodRig(t)
	ex1 := p.driver()
	d := p.dispatch(ex1, executor.WriteBackNone)
	p.restart(ex1, d, "hub_new")
	ex2 := p.driver()
	waitFor(t, 10*time.Second, "the restarted driver to adopt the Pod", func() bool {
		_, err := ex2.Status(context.Background(), d.handle.ID)
		return err == nil
	})
	attempts, release := failLeaseTakeovers(t, d.meta.Lease)
	takeoverTest(t, 20*time.Millisecond)

	(&Server{WorkDir: p.dir}).takeOverWorkspaceLease(p.dir, ex2, d.handle.ID, d.meta)
	if registeredLease(d.meta.Lease) != nil || pendingTakeovers.get(takeoverWorkspace, d.meta.Lease) == nil {
		t.Fatal("the undecided workspace takeover was not kept")
	}
	if _, ok := ex2.HeldWorkspaceCredential(d.handle.ID); ok {
		t.Fatal("the driver was handed a credential whose takeover is undecided")
	}
	waitFor(t, 10*time.Second, "a retry", func() bool { return attempts.Load() >= 2 })
	release()
	waitFor(t, 10*time.Second, "the workspace lease to be taken over", func() bool {
		sl := registeredLease(d.meta.Lease)
		return sl != nil && sl.isWorkspace()
	})
	stopKeepaliveForTest(registeredLease(d.meta.Lease))
	// The lease is listed before its session is restored and the driver is
	// handed its release, which the retry does next.
	waitFor(t, 10*time.Second, "the driver to be handed the restored session", func() bool {
		held, ok := ex2.HeldWorkspaceCredential(d.handle.ID)
		return ok && held.SessionID == d.session
	})
	if out, err := p.fetch(d); err != nil {
		t.Fatalf("the init container's fetch after the retried takeover: %v\n%s", err, out)
	}
	p.api.FinishInitContainer(d.pod, 0)
	waitFor(t, 10*time.Second, "the session to close once the fetch is confirmed", func() bool {
		row, _ := p.session(statedb.ProxySessionGit, d.session)
		return !row.Open()
	})
}
