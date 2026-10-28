package reconcile

// A Kubernetes Pod's workspace session survives the hub process that minted it
// (Task 20455). Task 20451 pinned the opposite here — the driver's workspace
// source sat on a broker that kept no lease records, so nothing named the
// lease in secret_leases, the git proxy never recorded the session, and a hub
// process adopting the Pod had nothing to take over — and this test is what
// replaced that pin.
//
// A Pod's init container fetches its workspace after the dispatch returned,
// through a pinned git proxy session minted over the workspace credential
// source this package builds for the Kubernetes driver. Built with the options
// `cloop ui` passes (Options.WorkspaceBrokerOptions), that source's broker
// records its leases: the lease is in secret_leases with its holder and its
// run, the session in proxy_sessions with its token hash and scope, and
// another process can take the lease over and restore the session under the
// same id and token hash. pkg/ui TestAPodsWorkspaceSessionSurvivesARestart
// runs the hub's whole takeover against the real driver, and tests/kube and
// tests/cluster run it with real processes.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/executor/gitproxycreds"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const workspaceRecordsPAT = "ghp_reconcileWorkspaceRecords0123456789abcd"

// workspaceRecordsHub is one control plane holding a github_pat granted to a
// Kubernetes executor for acme/tool.
func workspaceRecordsHub(t *testing.T) (string, *config.Config, *statedb.DB) {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "reconcile-workspace-records-unit-passphrase")
	dir := statedbtest.Dir(t)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: "acme-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(workspaceRecordsPAT), Actor: "test"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "k8s-prod"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/tool"}},
		TTL:         time.Hour, Actor: "test"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	// The cluster credential the driver leases for itself.
	kc, err := broker.Mint(ctx, secretbroker.MintRequest{Name: "prod-kubeconfig", Kind: secretbroker.KindKubeconfig,
		Payload: []byte(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://k8s.example:6443
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
    namespace: work
users:
- name: prod
  user:
    token: reconcile-workspace-records-cluster-token
`), Actor: "test"})
	if err != nil {
		t.Fatalf("Mint kubeconfig: %v", err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: kc.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "k8s-prod"},
		Constraints: secretbroker.Constraints{Namespaces: []string{"work"}},
		TTL:         time.Hour, Actor: "test"}); err != nil {
		t.Fatalf("Grant kubeconfig: %v", err)
	}
	cfg := &config.Config{}
	cfg.Executors.Kubernetes.KubeconfigSecret = "prod-kubeconfig"
	return dir, cfg, db
}

// TestAPodsWorkspaceSourceRecordsItsLeaseAndSession: built as `cloop ui`
// builds it, the Kubernetes driver's workspace source records the lease a
// Pod's fetch stands on — holder, run, executor, project — and the pinned
// session the git proxy mints over it, by token hash and scope and never the
// token; another hub process takes the lease over and restores the session
// under the same id, and the token the Pod holds authenticates there. The
// kubeconfig the driver leases for itself stays unrecorded.
func TestAPodsWorkspaceSourceRecordsItsLeaseAndSession(t *testing.T) {
	dir, cfg, db := workspaceRecordsHub(t)
	id, cleanup, err := brokerCredentials(dir, cfg, "k8s-prod",
		[]secretbroker.Option{secretbroker.WithLeaseRecords("hub_a")})
	if err != nil {
		t.Fatalf("brokerCredentials: %v", err)
	}
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	src, ok := id.Workspace.(*gitcreds.BrokerSource)
	if !ok || src == nil {
		t.Fatalf("the Kubernetes driver's workspace source is %T, want the broker's", id.Workspace)
	}
	if !src.LeasesRecorded() {
		t.Fatal("the workspace source of a hub that names a lease holder records nothing")
	}

	// The git proxy in front of it, recording its sessions as hub_a's.
	reg, err := gitproxy.NewRegistry("https://proxy.hub.example")
	if err != nil {
		t.Fatal(err)
	}
	reg.Store = sessionrecord.NewGitStore(db, func() string { return "hub_a" }, nil)
	routed, err := gitproxycreds.New(src, reg, gitproxy.Policy{}, time.Hour, "k8s-prod", "reconcile")
	if err != nil {
		t.Fatal(err)
	}
	ctx := executor.WithDispatchRun(context.Background(), "run_pod_1")
	access, release, err := routed.ForWorkspace(ctx, "/srv/app", executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git", Ref: "main", CredentialGrant: "acme-pat",
	})
	if err != nil {
		t.Fatalf("ForWorkspace: %v", err)
	}
	cred := access.Credential
	if cred.SessionID == "" || cred.LeaseID == "" || cred.Password == workspaceRecordsPAT {
		t.Fatalf("the Pod would be handed %+v, want a proxy session", cred)
	}

	rec, err := db.GetSecretLease(cred.LeaseID)
	if err != nil {
		t.Fatalf("the Pod's workspace lease has no record: %v", err)
	}
	if rec.Holder != "hub_a" || rec.RunID != "run_pod_1" || rec.ExecutorID != "k8s-prod" || rec.ProjectID != "/srv/app" {
		t.Fatalf("the lease's record = %+v, want held by hub_a for run_pod_1 of /srv/app on k8s-prod", rec)
	}
	row, err := db.GetProxySession(statedb.ProxySessionGit, cred.SessionID)
	if err != nil {
		t.Fatalf("the Pod's workspace session has no record: %v", err)
	}
	sum := sha256.Sum256([]byte(cred.Password))
	if row.TokenSHA256 != hex.EncodeToString(sum[:]) || row.LeaseID != cred.LeaseID || row.Holder != "hub_a" ||
		row.RunID != "run_pod_1" || !strings.Contains(row.Scope, "acme/tool") || !row.Open() {
		t.Fatalf("the session's record = %+v", row)
	}
	for what, v := range map[string]string{"lease record": rec.Record, "session scope": row.Scope} {
		if strings.Contains(v, cred.Password) || strings.Contains(v, workspaceRecordsPAT) {
			t.Fatalf("the %s carries a credential", what)
		}
	}
	// The driver's own kubeconfig lease is no other process's to take over:
	// each leases its own, so it is not recorded.
	creds, err := id.Cluster.Acquire(context.Background(), "/srv/app")
	if err != nil || creds == nil || creds.LeaseID == "" {
		t.Fatalf("lease the cluster credential = %+v, %v", creds, err)
	}
	defer id.Cluster.Release(creds.LeaseID)
	all, err := db.ListSecretLeases()
	if err != nil || len(all) != 1 || all[0].LeaseID != cred.LeaseID {
		t.Fatalf("recorded leases = %+v (%v), want the workspace's alone", all, err)
	}

	// The process that minted them stops: its session is suspended, its
	// record kept. Another takes the lease over and restores the session.
	reg.Suspend(cred.SessionID, "the hub is shutting down")
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	adopter, err := secretbroker.New(store, secretbroker.WithLeaseRecords("hub_b"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adopter.Restore(context.Background(), cred.LeaseID); err != nil {
		t.Fatalf("the adopting process could not take the lease over: %v", err)
	}
	if rec, _ := db.GetSecretLease(cred.LeaseID); rec.Holder != "hub_b" {
		t.Fatalf("the lease is held by %q after the takeover", rec.Holder)
	}
	if ok, err := db.TakeProxySession(statedb.ProxySessionGit, cred.SessionID, "hub_a", "hub_b"); err != nil || !ok {
		t.Fatalf("take the session's record over = %v, %v", ok, err)
	}
	row, _ = db.GetProxySession(statedb.ProxySessionGit, cred.SessionID)
	record, err := sessionrecord.GitRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	reg2, err := gitproxy.NewRegistry("https://proxy.hub.example")
	if err != nil {
		t.Fatal(err)
	}
	reg2.Store = sessionrecord.NewGitStore(db, func() string { return "hub_b" }, nil)
	if _, err := reg2.Restore(gitproxy.RestoreRequest{Record: record, From: "hub_a",
		Credential: gitproxy.Credential{Username: secretbroker.GitHubUsername, Password: workspaceRecordsPAT}}); err != nil {
		t.Fatalf("restore the session: %v", err)
	}
	if _, err := reg2.Authenticate(cred.SessionID, cred.Password); err != nil {
		t.Fatalf("the token the Pod holds does not authenticate the restored session: %v", err)
	}
	if row, _ := db.GetProxySession(statedb.ProxySessionGit, cred.SessionID); row.Holder != "hub_b" || !row.Open() ||
		row.TokenSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("the restored session's record = %+v", row)
	}
	release()
}

// TestAWorkspaceSourceRecordsNothingWithoutAHolder: every entry point but
// `cloop ui` builds the source with BrokerCredentials, which names no holder
// — none runs the git proxy whose session there would be to restore — and
// keeps its leases in memory, as before.
func TestAWorkspaceSourceRecordsNothingWithoutAHolder(t *testing.T) {
	dir, cfg, db := workspaceRecordsHub(t)
	id, cleanup, err := BrokerCredentials(dir, cfg, "k8s-prod")
	if err != nil {
		t.Fatalf("BrokerCredentials: %v", err)
	}
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	src, ok := id.Workspace.(*gitcreds.BrokerSource)
	if !ok || src.LeasesRecorded() {
		t.Fatalf("BrokerCredentials' workspace source is %T and records leases: %v", id.Workspace, ok && src.LeasesRecorded())
	}
	access, release, err := src.ForWorkspace(context.Background(), "/srv/app", executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git", Ref: "main", CredentialGrant: "acme-pat",
	})
	if err != nil || access.Credential.Empty() {
		t.Fatalf("ForWorkspace = %+v, %v", access.Credential, err)
	}
	defer release()
	if all, err := db.ListSecretLeases(); err != nil || len(all) != 0 {
		t.Fatalf("recorded leases = %d (%v), want none", len(all), err)
	}
}
