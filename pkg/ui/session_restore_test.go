package ui

// What a restarted hub brings back of an adopted run's lease (Task 20383): the
// git proxy and Kubernetes monitor sessions its workload holds, under the same
// ids and tokens, with upstream credentials re-derived from the lease's
// grants, and the GitHub App token behind the git session kept alive past
// GitHub's hour. tests/e2e/hubrestart_test.go runs it with real processes;
// these run the restart in one process — the old registries dropped as a dying
// process drops them, new ones built as a restarted process builds them — so
// they can reach what a few seconds of a real run cannot: GitHub's hour, a
// grant revoked during the downtime, a session that lapsed, a lost race.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	restoreRepo         = "acme/tool"
	restoreClusterToken = "restore-cluster-token-0123456789"
)

// restoreRig is one control plane, a fake GitHub with a TLS forge, a fake
// Kubernetes API server, and the hub's git proxy and Kubernetes monitor as a
// process builds them — swappable, so a test can play the process that stops
// and the one that comes back.
type restoreRig struct {
	t      *testing.T
	dir    string
	db     *statedb.DB
	clock  *secretbrokertest.Clock
	gh     *secretbrokertest.GitHub
	forge  *secretbrokertest.Forge
	holder atomic.Value // string

	gitSrv   *httptest.Server
	gitH     atomic.Value // http.Handler
	kubeSrv  *httptest.Server
	kubeH    atomic.Value // http.Handler
	api      *httptest.Server
	apiCalls atomic.Int64

	appGrant, kubeGrant secretbroker.Grant
	ex                  *takeoverExecutor
	gitTTL              time.Duration
}

// heldSessionWaits counts the sessions requests are being held for.
func heldSessionWaits() int {
	sessionWaits.mu.Lock()
	defer sessionWaits.mu.Unlock()
	return len(sessionWaits.m)
}

// setSessionAdoptionWait shortens or lengthens the hold for one test. Call it
// before newRestoreRig: the proxies' goroutines read the wait, and only a
// write made before they start is ordered before their reads — a held request
// arriving through a git subprocess carries no happens-before edge the race
// detector can see.
func setSessionAdoptionWait(t *testing.T, d time.Duration) {
	t.Helper()
	prev := sessionAdoptionWait
	sessionAdoptionWait = d
	t.Cleanup(func() { sessionAdoptionWait = prev })
}

func newRestoreRig(t *testing.T) *restoreRig {
	t.Helper()
	secretbrokertest.GitTools(t)
	t.Setenv(secretbroker.EnvPassphraseKey, "session-restore-unit-passphrase")
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "session restore", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	r := &restoreRig{t: t, dir: dir, clock: secretbrokertest.NewClock(time.Now()), gitTTL: 4 * time.Hour}
	r.holder.Store("hub_old")
	r.gh = secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: restoreRepo})
	r.gh.Clock = r.clock.Now
	r.forge = secretbrokertest.NewForge(t, r.gh, restoreRepo)
	r.ex = newTakeoverExecutor("edge-restore")

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	r.db = db.AsControlPlane()
	t.Cleanup(func() { _ = r.db.Close() })

	controlPlaneDirMu.Lock()
	prevDir := controlPlaneDirValue
	controlPlaneDirValue = dir
	controlPlaneDirMu.Unlock()
	prevOpts, prevHolder, prevNow := testBrokerOptions, leaseHolderID, sessionNow
	prevGit, prevGitReq := gitProxySingleton.Load(), gitProxyRequired.Load()
	prevKube, prevKubeReq := kubeGuardSingleton.Load(), kubeGuardRequired.Load()
	testBrokerOptions = []secretbroker.Option{secretbroker.WithGitHubApp(r.gh), secretbroker.WithClock(r.clock.Now)}
	leaseHolderID = func() string { return r.holder.Load().(string) }
	sessionNow = r.clock.Now
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue = prevDir
		controlPlaneDirMu.Unlock()
		testBrokerOptions, leaseHolderID, sessionNow = prevOpts, prevHolder, prevNow
		gitProxySingleton.Store(prevGit)
		gitProxyRequired.Store(prevGitReq)
		kubeGuardSingleton.Store(prevKube)
		kubeGuardRequired.Store(prevKubeReq)
		for _, sl := range liveLeases.snapshot() {
			if sl.workDir == dir {
				stopKeepaliveForTest(sl)
				liveLeases.removeIf(sl)
			}
		}
	})

	// The proxies' listeners outlive any one process's registry: a restarted
	// hub binds the same addresses.
	r.gitSrv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if h, ok := r.gitH.Load().(http.Handler); ok {
			h.ServeHTTP(w, req)
			return
		}
		http.Error(w, "no git proxy", http.StatusServiceUnavailable)
	}))
	r.gitSrv.StartTLS()
	t.Cleanup(r.gitSrv.Close)
	r.kubeSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if h, ok := r.kubeH.Load().(http.Handler); ok {
			h.ServeHTTP(w, req)
			return
		}
		http.Error(w, "no monitor", http.StatusServiceUnavailable)
	}))
	t.Cleanup(r.kubeSrv.Close)
	r.api = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+restoreClusterToken {
			http.Error(w, "fake api server: bad credential", http.StatusUnauthorized)
			return
		}
		r.apiCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"kind":"PodList","items":[],"path":%q}`, req.URL.Path)
	}))
	t.Cleanup(r.api.Close)
	r.startProcess()

	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()
	ctx := context.Background()
	app, err := broker.Mint(ctx, secretbroker.MintRequest{
		Name: "restore-app", Kind: secretbroker.KindGitHubApp, Payload: secretbrokertest.AppPayload(301, 302), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint app: %v", err)
	}
	subject := secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: r.ex.ID()}
	r.appGrant, err = broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: app.ID, Subject: subject,
		Constraints: secretbroker.Constraints{Repos: []string{restoreRepo}, Permissions: []string{"contents:write"}},
		TTL:         24 * time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant app: %v", err)
	}
	kc, err := broker.Mint(ctx, secretbroker.MintRequest{
		Name: "restore-kube", Kind: secretbroker.KindKubeconfig, Payload: []byte(restoreKubeconfig(r.api.URL)), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint kubeconfig: %v", err)
	}
	r.kubeGrant, err = broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: kc.ID, Subject: subject,
		Constraints: secretbroker.Constraints{Namespaces: []string{"app"}},
		TTL:         24 * time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant kubeconfig: %v", err)
	}
	return r
}

func restoreKubeconfig(server string) string {
	return `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: ` + server + `
    insecure-skip-tls-verify: true
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
    namespace: app
users:
- name: prod-user
  user:
    token: ` + restoreClusterToken + `
`
}

// startProcess builds the git proxy and Kubernetes monitor as a hub process
// starting up does, with empty registries, and installs them.
func (r *restoreRig) startProcess() {
	t := r.t
	reg, err := gitproxy.NewRegistry(r.gitSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	reg.Now = r.clock.Now
	reg.OnEvent = withProxySessionOwnership(ownerGitProxy, gitProxySessionEvent, gitProxyAuditSink(r.db))
	reg.Store = newGitSessionStore(r.db)
	px, err := gitproxy.New(reg, gitproxy.Options{
		Transport: r.forge.Transport(),
		Fallback:  clusterProxyFallback(ownerGitProxy, clusterAPIProxyGit),
	})
	if err != nil {
		t.Fatal(err)
	}
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	gitSvc := &gitProxyService{reg: reg, proxy: px, baseURL: r.gitSrv.URL, policy: pol, ttl: r.gitTTL,
		githubUpstream: r.forge.URL, auditDB: r.db}
	gitProxySingleton.Store(gitSvc)
	gitProxyRequired.Store(true)
	r.gitH.Store(http.Handler(px))

	kreg, err := kubeguard.NewRegistry(r.kubeSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	kreg.Now = r.clock.Now
	kreg.OnEvent = withProxySessionOwnership(ownerKubeGuard, kubeGuardSessionEvent, kubeGuardAuditSink(r.db))
	kreg.Store = newKubeSessionStore(r.db)
	kpx, err := kubeguard.New(kreg, kubeguard.Options{Fallback: clusterProxyFallback(ownerKubeGuard, clusterAPIProxyKube)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = kpx.Close() })
	kubeGuardSingleton.Store(&kubeGuardService{reg: kreg, proxy: kpx, baseURL: r.kubeSrv.URL, ttl: time.Hour, auditDB: r.db})
	kubeGuardRequired.Store(true)
	r.kubeH.Store(http.Handler(kpx))
}

// dispatched is what the dispatching process handed the workload.
type dispatched struct {
	lease             *secretLease
	gitID, gitToken   string
	kubeID, kubeToken string
	firstAppToken     string
	firstMint         secretbroker.InstallationTokenRequest
}

// dispatch issues the run's lease, as the dispatching process does, bound to
// its workload, and reads back the session credentials the workload holds.
func (r *restoreRig) dispatch() dispatched {
	t := r.t
	sl := acquireSecretLease(r.dir, r.dir, r.ex, "run_restore", nil)
	if sl == nil {
		t.Fatal("no lease was issued")
	}
	stopKeepaliveForTest(sl)
	sl.bindHandle(r.ex.ID(), "h-1")
	d := dispatched{lease: sl}
	for _, f := range sl.SecretFiles() {
		switch f.Name {
		case "git-proxy-credential":
			sc := bufio.NewScanner(bytes.NewReader(f.Content))
			for sc.Scan() {
				if v, ok := strings.CutPrefix(sc.Text(), "username="); ok {
					d.gitID = v
				}
				if v, ok := strings.CutPrefix(sc.Text(), "password="); ok {
					d.gitToken = v
				}
			}
		case "kubeconfig":
			var doc struct {
				Users []struct {
					User struct {
						Token string `yaml:"token"`
					} `yaml:"user"`
				} `yaml:"users"`
			}
			if err := yaml.Unmarshal(f.Content, &doc); err != nil || len(doc.Users) != 1 {
				t.Fatalf("delivered kubeconfig: %v", err)
			}
			d.kubeToken = doc.Users[0].User.Token
			d.kubeID, _, _ = strings.Cut(d.kubeToken, ".")
		}
	}
	if d.gitID == "" || d.gitToken == "" || d.kubeToken == "" {
		t.Fatalf("the workload was not handed both sessions: %+v", d)
	}
	scoped := r.gh.Scoped()
	if len(scoped) != 1 {
		t.Fatalf("minted %d scoped tokens at dispatch, want 1", len(scoped))
	}
	d.firstAppToken = scoped[0].Token
	d.firstMint = r.gh.Creates()[len(r.gh.Creates())-1]
	return d
}

// restart drops the dispatching process — its lease registry entry and its
// proxies' sessions die with it — and starts a new one as holder.
func (r *restoreRig) restart(d dispatched, holder string) {
	liveLeases.removeIf(d.lease)
	r.startProcess()
	r.holder.Store(holder)
}

// takeOver adopts the run as the restarted process does.
func (r *restoreRig) takeOver(d dispatched) *secretLease {
	(&Server{WorkDir: r.dir}).takeOverRunLeases(r.dir, r.ex, "h-1", []string{d.lease.lease.ID})
	sl := registeredLease(d.lease.lease.ID)
	if sl != nil {
		stopKeepaliveForTest(sl)
	}
	return sl
}

func (r *restoreRig) session(kind, id string) (statedb.ProxySessionRow, bool) {
	row, err := r.db.GetProxySession(kind, id)
	return row, err == nil
}

func (r *restoreRig) auditRows(action auditaction.Action, id string) []statedb.AuditEvent {
	rows, _, err := r.db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 200})
	if err != nil {
		r.t.Fatal(err)
	}
	var out []statedb.AuditEvent
	for _, row := range rows {
		if row.EntityID == id || strings.Contains(row.Payload, id) {
			out = append(out, row)
		}
	}
	return out
}

// git runs git against the git proxy with the session credential the workload
// holds, as its lease's helper would present it.
func (r *restoreRig) git(d dispatched, dir string, args ...string) (string, error) {
	gitBin, _ := secretbrokertest.GitTools(r.t)
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(d.gitID+":"+d.gitToken))
	cmd := exec.Command(gitBin, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"HOME=" + r.t.TempDir(), "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_SSL_NO_VERIFY=true", "LC_ALL=C",
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http." + r.gitSrv.URL + "/.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: " + auth,
		"GIT_CONFIG_KEY_1=credential.helper", "GIT_CONFIG_VALUE_1=",
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// kube sends one request through the Kubernetes monitor with the workload's
// bearer token.
func (r *restoreRig) kube(d dispatched, path string) int {
	req, _ := http.NewRequest(http.MethodGet, r.kubeSrv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+d.kubeToken)
	resp, err := r.kubeSrv.Client().Do(req)
	if err != nil {
		r.t.Fatalf("GET %s: %v", path, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func restoreCount(kind, outcome string) float64 {
	return value((&Server{}).gatherMetrics(),
		series("cloop_proxy_session_restores_total", "kind", kind, "outcome", outcome))
}

// TestAdoptedRunsSessionsAreRestored is the task: after the restart the
// workload's git, holding the session token the stopped process minted,
// fetches and pushes through the new process's proxy; its kubectl, holding the
// monitor token, reads the cluster; and past GitHub's hour the git session is
// still served, because the App token behind it — minted afresh at the
// recorded scope — is refreshed from the request path.
func TestAdoptedRunsSessionsAreRestored(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := newRestoreRig(t)
	d := r.dispatch()
	leaseID := d.lease.lease.ID
	for _, kind := range []string{statedb.ProxySessionGit, statedb.ProxySessionKube} {
		id := d.gitID
		if kind == statedb.ProxySessionKube {
			id = d.kubeID
		}
		row, ok := r.session(kind, id)
		if !ok || row.Holder != "hub_old" || row.LeaseID != leaseID || row.RunID != "run_restore" || !row.Open() {
			t.Fatalf("%s session record = %+v, %v", kind, row, ok)
		}
	}
	work := filepath.Join(t.TempDir(), "work")
	if out, err := r.git(d, "", "clone", r.gitSrv.URL+"/"+restoreRepo, work); err != nil {
		t.Fatalf("clone before the restart: %v\n%s", err, out)
	}

	restoredBefore := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreRestored)
	r.clock.Advance(2 * time.Minute)
	r.restart(d, "hub_new")

	// The request the workload makes while no process serves its session waits
	// for the run to be adopted (session_hold.go) instead of failing.
	fetched := make(chan error, 1)
	go func() {
		out, err := r.git(d, work, "fetch", "origin")
		if err != nil {
			err = fmt.Errorf("%v: %s", err, out)
		}
		fetched <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for heldSessionWaits() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if heldSessionWaits() == 0 {
		t.Fatal("the workload's fetch was not held for the adoption")
	}

	taken := r.takeOver(d)
	if taken == nil {
		t.Fatal("the restarted process does not hold the run's lease")
	}
	if err := <-fetched; err != nil {
		t.Fatalf("the fetch held across the adoption failed: %v", err)
	}
	git, kube := activeGitProxy(), activeKubeGuard()
	if !git.reg.Known(d.gitID) || !kube.reg.Known(d.kubeID) {
		t.Fatalf("restored: git %v, kube %v", git.reg.Known(d.gitID), kube.reg.Known(d.kubeID))
	}
	for _, id := range []string{d.gitID, d.kubeID} {
		kind := statedb.ProxySessionGit
		if id == d.kubeID {
			kind = statedb.ProxySessionKube
		}
		if row, _ := r.session(kind, id); row.Holder != "hub_new" || !row.Open() {
			t.Fatalf("%s record after the restore = %+v", kind, row)
		}
	}
	if got := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreRestored); got != restoredBefore+1 {
		t.Errorf("git restores counted %v, want %v", got, restoredBefore+1)
	}
	rows := r.auditRows(auditaction.ActionGitProxySessionRestored, d.gitID)
	if len(rows) != 1 || !strings.Contains(rows[0].Payload, "hub_old") {
		t.Fatalf("restored rows = %+v", rows)
	}
	if len(r.auditRows(auditaction.ActionKubeGuardSessionRestored, d.kubeID)) != 1 {
		t.Fatal("no kubeguard.session_restored row")
	}

	// The upstream App token was minted again, at the recorded scope.
	scoped := r.gh.Scoped()
	if len(scoped) != 2 {
		t.Fatalf("scoped tokens = %d, want the dispatcher's and the restorer's", len(scoped))
	}
	last := r.gh.Creates()[len(r.gh.Creates())-1]
	if fmt.Sprint(last.RepositoryIDs, last.Permissions) != fmt.Sprint(d.firstMint.RepositoryIDs, d.firstMint.Permissions) {
		t.Fatalf("re-minted at %+v, first at %+v", last, d.firstMint)
	}

	// A push lands, and the policy came back with the session.
	if err := os.WriteFile(filepath.Join(work, "after.txt"), []byte("after the restart\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "after.txt"},
		{"-c", "user.email=a@b.invalid", "-c", "user.name=t", "commit", "-qm", "after the restart"},
		{"push", "origin", "HEAD:refs/heads/cloop/after-restart"},
	} {
		if out, err := r.git(d, work, args...); err != nil {
			t.Fatalf("git %s after the restore: %v\n%s", args[0], err, out)
		}
	}
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/after-restart") == "" {
		t.Fatal("the push after the restore did not reach the forge")
	}
	if out, err := r.git(d, work, "push", "origin", "HEAD:refs/heads/main"); err == nil {
		t.Fatalf("a push to main succeeded through the restored session:\n%s", out)
	}

	// The workload's kubectl reads the cluster through the restored session,
	// still confined to its namespace.
	if code := r.kube(d, "/api/v1/namespaces/app/pods"); code != http.StatusOK {
		t.Fatalf("kubectl after the restore = %d", code)
	}
	if code := r.kube(d, "/api/v1/namespaces/kube-system/secrets"); code != http.StatusForbidden {
		t.Fatalf("a namespace outside the grant = %d, want 403", code)
	}

	// Past the hour of every token minted so far, the session still works.
	r.clock.Advance(61 * time.Minute)
	for _, tok := range scoped {
		if r.gh.Valid(tok.Token) {
			t.Fatal("a token outlived its hour; the test would prove nothing")
		}
	}
	if out, err := r.git(d, work, "fetch", "origin"); err != nil {
		t.Fatalf("fetch past the hour after the restore: %v\n%s", err, out)
	}
	if n := len(r.gh.Scoped()); n != 3 {
		t.Fatalf("scoped tokens = %d, want a refresh after the hour", n)
	}

	// The run ends; the adopter releases the lease and with it the sessions.
	taken.Close()
	for _, c := range []struct{ kind, id string }{{statedb.ProxySessionGit, d.gitID}, {statedb.ProxySessionKube, d.kubeID}} {
		row, ok := r.session(c.kind, c.id)
		if !ok || row.Open() || row.CloseReason != "lease released" {
			t.Fatalf("%s record after the release = %+v, %v", c.kind, row, ok)
		}
	}
	if git.reg.Known(d.gitID) || len(r.gh.LiveTokens()) != 0 {
		t.Fatalf("the release left the session (%v) or live tokens (%v)", git.reg.Known(d.gitID), r.gh.LiveTokens())
	}
}

// TestSessionsOfARevokedGrantAreNotRestored: a grant revoked while no process
// held the lease refuses the lease, and its sessions are closed and scrubbed
// as the lease is — never served again.
func TestSessionsOfARevokedGrantAreNotRestored(t *testing.T) {
	r := newRestoreRig(t)
	d := r.dispatch()
	var scrubbed []string
	prev := testRevokeLapsedLease
	testRevokeLapsedLease = func(leaseID, reason string) { scrubbed = append(scrubbed, leaseID) }
	t.Cleanup(func() { testRevokeLapsedLease = prev })

	r.restart(d, "hub_new")
	broker, closeDB, err := openUIBroker(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Revoke(context.Background(), r.kubeGrant.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	closeDB()

	if taken := r.takeOver(d); taken != nil {
		t.Fatal("a lease carrying a revoked grant was taken over")
	}
	if len(scrubbed) != 1 || scrubbed[0] != d.lease.lease.ID {
		t.Fatalf("scrubbed = %v, want the lease", scrubbed)
	}
	if activeGitProxy().reg.Known(d.gitID) || activeKubeGuard().reg.Known(d.kubeID) {
		t.Fatal("a session of the refused lease was restored")
	}
	for _, c := range []struct {
		kind, id string
		action   auditaction.Action
	}{
		{statedb.ProxySessionGit, d.gitID, auditaction.ActionGitProxySessionClosed},
		{statedb.ProxySessionKube, d.kubeID, auditaction.ActionKubeGuardSessionClosed},
	} {
		if _, ok := r.session(c.kind, c.id); ok {
			t.Errorf("the %s record outlived its retired lease", c.kind)
		}
		rows := r.auditRows(c.action, c.id)
		if len(rows) != 1 || !strings.Contains(rows[0].Payload, "retired") {
			t.Errorf("%s close rows = %+v", c.kind, rows)
		}
	}
	if code := r.kube(d, "/api/v1/namespaces/app/pods"); code != http.StatusUnauthorized {
		t.Fatalf("the refused kube session answered %d", code)
	}
}

// TestLosingTheSessionRaceRestoresNothing: a session another process took over
// first is not restored here; the rest of the lease's sessions are.
func TestLosingTheSessionRaceRestoresNothing(t *testing.T) {
	r := newRestoreRig(t)
	d := r.dispatch()
	r.restart(d, "hub_new")
	// Both processes read the record while the stopped one holds it; the
	// other one's takeover lands between this one's read and its write.
	beforeSessionTake = func(row statedb.ProxySessionRow) {
		if row.Kind != statedb.ProxySessionGit {
			return
		}
		if ok, err := r.db.TakeProxySession(statedb.ProxySessionGit, d.gitID, "hub_old", "hub_other"); err != nil || !ok {
			t.Errorf("the other process's takeover = %v, %v", ok, err)
		}
	}
	t.Cleanup(func() { beforeSessionTake = nil })
	lostBefore := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreLost)
	if r.takeOver(d) == nil {
		t.Fatal("no lease taken over")
	}
	if activeGitProxy().reg.Known(d.gitID) {
		t.Fatal("the session another process took over was restored here too")
	}
	if !activeKubeGuard().reg.Known(d.kubeID) {
		t.Fatal("the lease's other session was not restored")
	}
	if row, _ := r.session(statedb.ProxySessionGit, d.gitID); row.Holder != "hub_other" || !row.Open() {
		t.Fatalf("the lost session's record = %+v", row)
	}
	if got := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreLost); got != lostBefore+1 {
		t.Errorf("lost restores counted %v, want %v", got, lostBefore+1)
	}
}

// TestARecordNamingAnotherUpstreamIsRefused: where a restored session presents
// its credential is this hub's configuration, never the record. A record edited
// to name another forge is refused before anything is minted for it, and
// closed with the reason; the lease's other session comes back all the same.
func TestARecordNamingAnotherUpstreamIsRefused(t *testing.T) {
	r := newRestoreRig(t)
	d := r.dispatch()
	r.restart(d, "hub_new")
	row, ok := r.session(statedb.ProxySessionGit, d.gitID)
	if !ok {
		t.Fatal("no record of the git session")
	}
	var scope map[string]any
	if err := json.Unmarshal([]byte(row.Scope), &scope); err != nil {
		t.Fatal(err)
	}
	scope["upstream"] = "https://collector.example"
	raw, _ := json.Marshal(scope)
	row.Scope = string(raw)
	if err := r.db.PutProxySession(row); err != nil {
		t.Fatal(err)
	}
	minted := len(r.gh.Scoped())
	refusedBefore := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreRefused)

	if r.takeOver(d) == nil {
		t.Fatal("no lease taken over")
	}
	if activeGitProxy().reg.Known(d.gitID) {
		t.Fatal("a session naming another upstream was restored")
	}
	if n := len(r.gh.Scoped()); n != minted {
		t.Fatalf("%d App token(s) minted for a session that was then refused", n-minted)
	}
	if row, _ := r.session(statedb.ProxySessionGit, d.gitID); row.Open() || !strings.Contains(row.CloseReason, "upstream") {
		t.Fatalf("the refused session's record = %+v", row)
	}
	if got := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreRefused); got != refusedBefore+1 {
		t.Errorf("refused restores counted %v, want %v", got, refusedBefore+1)
	}
	if !activeKubeGuard().reg.Known(d.kubeID) {
		t.Fatal("the lease's other session was not restored")
	}
}

// TestARetryLeavesWhatAnotherProcessTookOver: a session whose restore failed
// for a reason that may pass is retried — but not once another process has
// taken it over, and not at all once the lease itself has moved, when this
// process lets go of everything the lease fed.
func TestARetryLeavesWhatAnotherProcessTookOver(t *testing.T) {
	r := newRestoreRig(t)
	d := r.dispatch()
	r.restart(d, "hub_new")
	// GitHub unreachable: the App token behind the git session cannot be
	// minted, so that restore is left pending.
	r.gh.FailMints(true)
	sl := r.takeOver(d)
	if sl == nil {
		t.Fatal("no lease taken over")
	}
	if activeGitProxy().reg.Known(d.gitID) || !activeKubeGuard().reg.Known(d.kubeID) {
		t.Fatalf("restored: git %v (want pending), kube %v", activeGitProxy().reg.Known(d.gitID),
			activeKubeGuard().reg.Known(d.kubeID))
	}
	if row, _ := r.session(statedb.ProxySessionGit, d.gitID); row.Holder != "hub_new" || !row.Open() {
		t.Fatalf("the pending session's record = %+v", row)
	}
	r.gh.FailMints(false)

	// Another process takes the session over meanwhile.
	if ok, err := r.db.TakeProxySession(statedb.ProxySessionGit, d.gitID, "hub_new", "hub_third"); err != nil || !ok {
		t.Fatalf("the other process's takeover = %v, %v", ok, err)
	}
	lostBefore := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreLost)
	sl.retryPendingSessions()
	if activeGitProxy().reg.Known(d.gitID) {
		t.Fatal("a retry restored a session another process had taken over")
	}
	if got := restoreCount(hubmetrics.RestoreKindGit, hubmetrics.RestoreLost); got != lostBefore+1 {
		t.Errorf("lost restores counted %v, want %v", got, lostBefore+1)
	}

	// And when the lease itself moves, the next retry hands everything over.
	if ok, err := r.db.TakeProxySession(statedb.ProxySessionGit, d.gitID, "hub_third", "hub_new"); err != nil || !ok {
		t.Fatalf("give the session back = %v, %v", ok, err)
	}
	sl.addPending(statedb.ProxySessionRow{Kind: statedb.ProxySessionGit, SessionID: d.gitID}, "hub_old")
	if ok, err := r.db.TakeSecretLease(d.lease.lease.ID, "hub_new", "hub_third"); err != nil || !ok {
		t.Fatalf("move the lease = %v, %v", ok, err)
	}
	sl.retryPendingSessions()
	if !sl.isHandedOver() {
		t.Fatal("a retry under a lease another process took over did not hand it over")
	}
	if activeGitProxy().reg.Known(d.gitID) || activeKubeGuard().reg.Known(d.kubeID) {
		t.Fatal("this process still serves what the moved lease feeds")
	}
}

// TestALapsedSessionIsRetiredNotRestored: a session whose TTL ran out while no
// process held it stays ended, even though its lease is taken over.
func TestALapsedSessionIsRetiredNotRestored(t *testing.T) {
	r := newRestoreRig(t)
	r.gitTTL = 10 * time.Minute
	r.startProcess()
	d := r.dispatch()
	r.clock.Advance(11 * time.Minute)
	r.restart(d, "hub_new")
	if r.takeOver(d) == nil {
		t.Fatal("the lease, with time left, was not taken over")
	}
	if activeGitProxy().reg.Known(d.gitID) {
		t.Fatal("a lapsed session was restored")
	}
	if !activeKubeGuard().reg.Known(d.kubeID) {
		t.Fatal("the session with time left was not restored")
	}
	if _, ok := r.session(statedb.ProxySessionGit, d.gitID); ok {
		t.Fatal("the lapsed session's record was kept")
	}
	rows := r.auditRows(auditaction.ActionGitProxySessionClosed, d.gitID)
	if len(rows) != 1 || !strings.Contains(rows[0].Payload, "lapsed") {
		t.Fatalf("close rows = %+v", rows)
	}
}

// TestHeldRequestIsRefusedWithoutAdoption: a request presenting a recorded
// session waits for its run to be adopted and is refused once the wait is
// over; one presenting a wrong token is refused at once.
func TestHeldRequestIsRefusedWithoutAdoption(t *testing.T) {
	setSessionAdoptionWait(t, 1500*time.Millisecond)
	r := newRestoreRig(t)
	d := r.dispatch()
	r.restart(d, "hub_new")

	get := func(token string) (int, time.Duration) {
		req, _ := http.NewRequest(http.MethodGet, r.gitSrv.URL+"/"+restoreRepo+"/info/refs?service=git-upload-pack", nil)
		req.SetBasicAuth(d.gitID, token)
		start := time.Now()
		resp, err := r.gitSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, time.Since(start)
	}
	if code, took := get(d.gitToken + "x"); code != http.StatusUnauthorized || took > 300*time.Millisecond {
		t.Fatalf("a wrong token = %d after %s, want an immediate 401", code, took)
	}
	if code, took := get(d.gitToken); code != http.StatusUnauthorized || took < 1400*time.Millisecond {
		t.Fatalf("the right token with no adoption = %d after %s, want a 401 after the wait", code, took)
	}

	// A burst presenting the session — kubectl's discovery, parallel
	// fetches — shares one wait rather than taking one each.
	const burst = 5
	codes := make(chan int, burst)
	for range burst {
		go func() {
			req, _ := http.NewRequest(http.MethodGet, r.gitSrv.URL+"/"+restoreRepo+"/info/refs?service=git-upload-pack", nil)
			req.SetBasicAuth(d.gitID, d.gitToken)
			resp, err := r.gitSrv.Client().Do(req)
			if err != nil {
				codes <- 0
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	maxWaits, maxWaiters := 0, 0
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		sessionWaits.mu.Lock()
		maxWaits = max(maxWaits, len(sessionWaits.m))
		for _, w := range sessionWaits.m {
			maxWaiters = max(maxWaiters, w.waiters)
		}
		sessionWaits.mu.Unlock()
	}
	for range burst {
		if code := <-codes; code != http.StatusUnauthorized {
			t.Fatalf("a held request of the burst answered %d, want a 401 after the wait", code)
		}
	}
	if maxWaits != 1 || maxWaiters < 2 {
		t.Fatalf("a burst on one session held %d wait(s) with at most %d request(s) sharing one; want one shared wait",
			maxWaits, maxWaiters)
	}
}

// TestJanitorRetiresSessionRecords covers the leader's sweep: closed records
// go, open ones whose holder is gone go once they lapse or lose their lease,
// and a live holder's are left alone until they are well past their TTL.
func TestJanitorRetiresSessionRecords(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "session-janitor-unit-passphrase")
	db := statedbtest.Open(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	if err := db.PutSecretLease(statedb.SecretLeaseRow{LeaseID: "lease_live", Holder: "hub_alive",
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	put := func(id, holder, lease string, expires time.Time, updated time.Time, closed bool) {
		row := statedb.ProxySessionRow{Kind: statedb.ProxySessionGit, SessionID: id, Holder: holder, LeaseID: lease,
			IssuedAt: now.Add(-time.Hour), ExpiresAt: expires, UpdatedAt: updated, Scope: `{"upstream":"https://github.com"}`}
		if closed {
			row.ClosedAt, row.CloseReason = now.Add(-time.Minute), "lease released"
		}
		if err := db.PutProxySession(row); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-10 * time.Minute)
	put("closed", "hub_alive", "lease_live", now.Add(time.Hour), old, true)
	put("lapsed_dead", "hub_dead", "lease_live", now.Add(-time.Second), old, false)
	put("lapsed_alive", "hub_alive", "lease_live", now.Add(-time.Second), old, false)
	// A live holder's record well past its TTL: a close of its own that never
	// landed, and nothing serves it.
	put("stale_alive", "hub_alive", "lease_live", now.Add(-sessionRecordGrace-time.Minute), old, false)
	put("leaseless_dead", "hub_dead", "lease_gone", now.Add(time.Hour), old, false)
	put("leaseless_fresh", "hub_dead", "lease_gone", now.Add(time.Hour), now, false)
	put("live_dead_holder", "hub_dead", "lease_live", now.Add(time.Hour), old, false)
	if err := db.PutAppTokenSlot(statedb.AppTokenSlotRow{LeaseID: "lease_gone", GrantID: "g", Holder: "hub_dead"}); err != nil {
		t.Fatal(err)
	}

	alive := func(h string) bool { return h == "hub_alive" }
	if n := sweepSessionRecords(db, now, "hub_leader", alive); n != 4 {
		t.Fatalf("retired %d records, want closed, lapsed_dead, stale_alive and leaseless_dead", n)
	}
	rows, _ := db.ListProxySessions(statedb.ProxySessionFilter{})
	var left []string
	for _, row := range rows {
		left = append(left, row.SessionID)
	}
	if strings.Join(left, ",") != "lapsed_alive,leaseless_fresh,live_dead_holder" {
		t.Fatalf("records left = %v", left)
	}
	if slots, _ := db.ListAppTokenSlots(""); len(slots) != 0 {
		t.Fatalf("a slot outlived its lease: %+v", slots)
	}
	ev, _, _ := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionGitProxySessionClosed), Limit: 10})
	if len(ev) != 3 {
		t.Fatalf("close rows = %d, want one per open record retired (the closed one had its row)", len(ev))
	}
}

// TestGracefulStopSuspendsRecordedSessions: a hub stopping gracefully leaves a
// recorded session open for the process adopting its run, and closes one
// nothing could restore.
func TestGracefulStopSuspendsRecordedSessions(t *testing.T) {
	r := newRestoreRig(t)
	d := r.dispatch()
	svc := activeGitProxy()
	plain, err := svc.reg.Mint(gitproxy.MintRequest{Upstream: r.forge.URL + "/" + restoreRepo + ".git",
		Credential: gitproxy.Credential{Password: "p"}})
	if err != nil {
		t.Fatal(err)
	}
	// Close closes the service's database handle, which is the rig's: read on
	// through a new one.
	svc.Close()
	db, err := statedb.Open(state.DBPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	r.db = db
	if row, _ := r.session(statedb.ProxySessionGit, d.gitID); !row.Open() {
		t.Fatalf("a graceful stop closed a recorded session: %+v", row)
	}
	if len(r.auditRows(auditaction.ActionGitProxySessionClosed, d.gitID)) != 0 {
		t.Fatal("a suspended session got a close row")
	}
	if len(r.auditRows(auditaction.ActionGitProxySessionClosed, plain.Session.ID)) != 1 {
		t.Fatal("an unrecorded session was not closed with a row")
	}
}

// TestHandoverSuspendsWhatTheLeaseFed: a process whose lease another one took
// over stops serving the lease's sessions, leaves their records to the new
// holder, and destroys the App token its own session presented.
func TestHandoverSuspendsWhatTheLeaseFed(t *testing.T) {
	r := newRestoreRig(t)
	d := r.dispatch()
	if !r.gh.Valid(d.firstAppToken) {
		t.Fatal("the dispatch token is not live")
	}
	d.lease.handOver()
	if activeGitProxy().reg.Known(d.gitID) || activeKubeGuard().reg.Known(d.kubeID) {
		t.Fatal("the handed-over lease's sessions are still served here")
	}
	if row, _ := r.session(statedb.ProxySessionGit, d.gitID); !row.Open() {
		t.Fatal("handing over closed the session's record")
	}
	if r.gh.Valid(d.firstAppToken) {
		t.Fatal("the App token the suspended session presented is still live")
	}
}

var _ executor.Executor = (*takeoverExecutor)(nil)

// fileRefreshExec is a device holding a lease's files, whose agent can take a
// refreshed token file (protocol v17's secret_refresh): what the new holder's
// keepalive delivers to.
type fileRefreshExec struct {
	*takeoverExecutor
	leaseID   atomic.Value // string
	refreshes chan executor.SecretRefreshRequest
}

func (e *fileRefreshExec) SupportsRevocation() bool { return true }
func (e *fileRefreshExec) HoldsLease(id string) bool {
	held, _ := e.leaseID.Load().(string)
	return held != "" && held == id
}
func (e *fileRefreshExec) Leases() []string { return nil }
func (e *fileRefreshExec) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, State: executor.RevokeStateRevoked}
}
func (e *fileRefreshExec) Revocations() []executor.RevokeOutcome { return nil }
func (e *fileRefreshExec) RefreshSecretFiles(_ context.Context, req executor.SecretRefreshRequest) executor.SecretRefreshReport {
	cp := req
	cp.Files = nil
	for _, f := range req.Files {
		f.Content = append([]byte(nil), f.Content...)
		cp.Files = append(cp.Files, f)
	}
	e.refreshes <- cp
	return executor.SecretRefreshReport{LeaseID: req.LeaseID, Known: true, FilesRewritten: len(req.Files)}
}

// TestTakenOverLeaseRenewsItsAppTokenFile is the no-proxy half of item 4: a
// GitHub App token delivered into a device's files, minted by the process that
// stopped, is renewed past its hour by the keepalive of the process that took
// the lease over — minted at the recorded scope, sent over the same refresh the
// device would have got from the first.
func TestTakenOverLeaseRenewsItsAppTokenFile(t *testing.T) {
	const execID = "restore-file-device"
	rh := newRefreshHub(t, secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: execID})
	withControlPlaneDir(t, rh.dir)
	var holder atomic.Value
	holder.Store("hub_old")
	prevHolder := leaseHolderID
	leaseHolderID = func() string { return holder.Load().(string) }
	t.Cleanup(func() { leaseHolderID = prevHolder })

	ex := &fileRefreshExec{takeoverExecutor: newTakeoverExecutor(execID), refreshes: make(chan executor.SecretRefreshRequest, 4)}
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID); ex.finish() })
	project := t.TempDir()
	statedbtest.SeedDir(t, project)
	if _, err := state.Init(project, "file token project", 0); err != nil {
		t.Fatal(err)
	}
	sl := acquireSecretLease(rh.dir, project, ex, "run_file", nil)
	if sl == nil || sl.delivery == nil {
		t.Fatal("no delivered lease was issued")
	}
	stopKeepaliveForTest(sl)
	sl.bindHandle(execID, "h-f")
	ex.leaseID.Store(sl.lease.ID)
	first := scopedTokens(t, rh.gh)[0]
	firstMint := rh.gh.Creates()[len(rh.gh.Creates())-1]

	// The dispatching process stops; another takes the run over.
	liveLeases.removeIf(sl)
	holder.Store("hub_new")
	rh.clock.Advance(5 * time.Minute)
	(&Server{WorkDir: project}).takeOverRunLeases(project, ex, "h-f", []string{sl.lease.ID})
	taken := registeredLease(sl.lease.ID)
	if taken == nil {
		t.Fatal("the lease was not taken over")
	}
	stopKeepaliveForTest(taken)
	defer taken.Close()

	// Five minutes before the first token's hour: the new holder's keepalive
	// renews the device's file.
	rh.clock.Advance(50 * time.Minute)
	taken.refreshAppTokens(context.Background(), rh.clock.Now())
	var req executor.SecretRefreshRequest
	select {
	case req = <-ex.refreshes:
	default:
		t.Fatal("the new holder's keepalive sent the device no refreshed token file")
	}
	if len(req.Files) != 1 || req.Files[0].Name != "github-token" || req.LeaseID != sl.lease.ID {
		t.Fatalf("refresh = %+v", req)
	}
	second := strings.TrimSpace(string(req.Files[0].Content))
	if second == first || !rh.gh.Valid(second) {
		t.Fatal("the refreshed file does not carry a new live token")
	}
	last := rh.gh.Creates()[len(rh.gh.Creates())-1]
	if fmt.Sprint(last.RepositoryIDs, last.Permissions) != fmt.Sprint(firstMint.RepositoryIDs, firstMint.Permissions) {
		t.Fatalf("re-minted at %+v, first at %+v", last, firstMint)
	}
	// Past the first token's hour the device's new one still works.
	rh.clock.Advance(10 * time.Minute)
	if rh.gh.Valid(first) || !rh.gh.Valid(second) {
		t.Fatalf("first valid %v, second valid %v", rh.gh.Valid(first), rh.gh.Valid(second))
	}
}
