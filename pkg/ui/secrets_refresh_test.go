package ui

// Keeping a GitHub App token working past GitHub's hour (Task 20375), from the
// hub's side: the lease keepalive re-minting the token in a host workload's
// file while the workload's real git keeps fetching and pushing, a holder that
// cannot take the new file being journaled instead of handed a token it cannot
// use, and a guarded lease renewing through the real git proxy adapter.
//
// GitHub is secretbrokertest's fake, minting tokens that expire an hour after a
// clock the test drives; the forge honours only what that fake would honour
// now. Every broker the hub opens reaches both through testBrokerOptions.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const refreshTestRepo = "acme/tool"

// refreshHub is a control-plane directory holding one github_app grant, with
// every broker the hub opens minting through a fake GitHub on a driven clock.
type refreshHub struct {
	dir   string
	gh    *secretbrokertest.GitHub
	clock *secretbrokertest.Clock
	grant secretbroker.Grant
}

func newRefreshHub(t *testing.T, subject secretbroker.Subject, perms ...string) *refreshHub {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "token-refresh-unit-passphrase")
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "token refresh", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	rh := &refreshHub{dir: dir, clock: secretbrokertest.NewClock(time.Now())}
	rh.gh = secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: refreshTestRepo})
	rh.gh.Clock = rh.clock.Now
	prev := testBrokerOptions
	testBrokerOptions = []secretbroker.Option{
		secretbroker.WithGitHubApp(rh.gh), secretbroker.WithClock(rh.clock.Now),
	}
	t.Cleanup(func() { testBrokerOptions = prev })

	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: "refresh-app", Kind: secretbroker.KindGitHubApp,
		Payload: secretbrokertest.AppPayload(301, 302), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(perms) == 0 {
		perms = []string{"contents:write"}
	}
	rh.grant, err = broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: subject,
		Constraints: secretbroker.Constraints{Repos: []string{refreshTestRepo}, Permissions: perms},
		TTL:         24 * time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return rh
}

// auditRows returns the control plane's audit rows of one action.
func (rh *refreshHub) auditRows(t *testing.T, action auditaction.Action) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(state.DBPath(rh.dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 100})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	return rows
}

func credentialRefreshEvents(t *testing.T, dir string) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(dir, 0, 100)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var out []state.EventRow
	for _, r := range rows {
		if r.Type == state.EventCredentialRefresh {
			out = append(out, r)
		}
	}
	return out
}

// stopKeepaliveForTest ends the lease's keepalive goroutine, so the test drives
// every tick itself.
func stopKeepaliveForTest(sl *secretLease) {
	if sl.stopKeepalive != nil {
		sl.stopKeepalive()
		sl.stopKeepalive = nil
	}
}

// TestKeepaliveRefreshesAHostWorkloadsTokenFile is the no-proxy guarantee on a
// hub-local executor: the workload's own git, reading its lease's token file
// through the credential helper on every call, fetches and pushes after the
// first token's hour because the keepalive rewrote the file with a token the
// broker re-minted.
func TestKeepaliveRefreshesAHostWorkloadsTokenFile(t *testing.T) {
	gitBin, _ := secretbrokertest.GitTools(t)
	const execID = "refresh-host"
	rh := newRefreshHub(t, secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: execID})
	forge := secretbrokertest.NewForge(t, rh.gh, refreshTestRepo)
	proxy := secretbrokertest.NewConnectProxy(t, "127.0.0.1:0", forge.Addr)

	ex := localprocess.New(execID)
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })

	lease := acquireSecretLease(rh.dir, "/srv/refresh-proj", ex, "run_refresh_host")
	if lease == nil || lease.mount == nil {
		t.Fatal("no hub-materialised lease was issued for the host executor")
	}
	defer lease.Close()
	stopKeepaliveForTest(lease)

	work := t.TempDir()
	home := filepath.Join(work, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	script := `set -u
git clone -q https://github.com/acme/tool repo && echo CLONED
first=$(cat "$CLOOP_LEASE_DIR/github-token")
echo WAITING
i=0
while [ "$(cat "$CLOOP_LEASE_DIR/github-token")" = "$first" ]; do
  i=$((i+1)); [ "$i" -gt 600 ] && { echo NEVER_REFRESHED; exit 3; }
  sleep 0.1
done
echo REFRESHED
i=0
while [ ! -e "$GO_FILE" ]; do
  i=$((i+1)); [ "$i" -gt 600 ] && { echo NEVER_TOLD_TO_GO; exit 4; }
  sleep 0.1
done
cd repo
git fetch -q origin && echo FETCHED
echo late > late.txt && git add late.txt && git -c user.email=a@b.invalid -c user.name=t commit -qm late
git push -q origin HEAD:refs/heads/cloop/late && echo PUSHED
`
	spec := uiSpec(work, []string{"/bin/sh", "-c", script}, nil)
	spec.Env = []string{
		"HOME=" + home, "PATH=" + filepath.Dir(gitBin) + ":/usr/bin:/bin", "LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_SSL_NO_VERIFY=true",
		"HTTPS_PROXY=http://" + proxy.Addr, "NO_PROXY=", "GO_FILE=" + filepath.Join(work, "go"),
	}
	spec, err := applyLease(spec, ex, lease)
	if err != nil {
		t.Fatalf("applyLease: %v", err)
	}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(context.Background(), h.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var out strings.Builder
	waitLine := func(want string) {
		t.Helper()
		deadline := time.After(90 * time.Second)
		for !strings.Contains(out.String(), want) {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("the workload ended before %q:\n%s", want, out.String())
				}
				out.WriteString(l.Text)
			case <-deadline:
				t.Fatalf("timed out waiting for %q:\n%s", want, out.String())
			}
		}
	}
	waitLine("WAITING")
	first := scopedTokens(t, rh.gh)[0]

	// Inside the refresh window: the keepalive re-mints and rewrites the file.
	rh.clock.Advance(52 * time.Minute)
	if !lease.refreshAppTokens(context.Background(), rh.clock.Now()) {
		t.Fatal("the keepalive stopped watching a lease that holds an App token file")
	}
	waitLine("REFRESHED")

	// The superseded token goes once its grace has passed — destroyed at
	// GitHub, not left to run out its last minutes.
	rh.clock.Advance(3 * time.Minute)
	lease.refreshAppTokens(context.Background(), rh.clock.Now())
	if tok, _ := rh.gh.Token(first); !tok.Revoked {
		t.Error("the superseded token was not destroyed at GitHub after its grace")
	}

	// Past the first token's hour, the workload's git fetches and pushes.
	rh.clock.Advance(6 * time.Minute)
	if rh.gh.Valid(first) {
		t.Fatal("the first token is still valid after its hour; the test would prove nothing")
	}
	if err := os.WriteFile(filepath.Join(work, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitLine("PUSHED")
	if !strings.Contains(out.String(), "FETCHED") {
		t.Fatalf("the late fetch failed:\n%s", out.String())
	}
	if forge.Ref(t, refreshTestRepo, "refs/heads/cloop/late") == "" {
		t.Fatal("the push after the hour did not reach the forge")
	}
	if strings.Contains(out.String(), first) {
		t.Fatal("a token reached the workload's output")
	}

	allowed := 0
	for _, row := range rh.auditRows(t, auditaction.Action(secretbroker.ActionLeaseRefresh)) {
		if strings.Contains(row.Payload, `"decision":"allow"`) && strings.Contains(row.Payload, execID) {
			allowed++
		}
	}
	if allowed != 1 {
		t.Errorf("%d allowed lease.refresh rows name the executor, want one", allowed)
	}
	if rows := rh.auditRows(t, auditaction.ActionSecretRenew); len(rows) == 0 {
		t.Error("no secret.renew row records the re-mint")
	}
}

// scopedTokens returns the tokens the fake minted for leases, oldest first.
func scopedTokens(t *testing.T, gh *secretbrokertest.GitHub) []string {
	t.Helper()
	var out []string
	for _, m := range gh.Scoped() {
		out = append(out, m.Token)
	}
	if len(out) == 0 {
		t.Fatal("no token was minted for the lease")
	}
	return out
}

// refreshlessExec holds a lease (it is a Revoker that says so) and cannot
// rewrite its files: what a device whose agent predates v17 looks like to the
// keepalive.
type refreshlessExec struct {
	stubExec
	leaseID atomic.Value
}

func (e *refreshlessExec) SupportsRevocation() bool { return true }
func (e *refreshlessExec) HoldsLease(id string) bool {
	held, _ := e.leaseID.Load().(string)
	return held != "" && held == id
}
func (e *refreshlessExec) Leases() []string { return nil }
func (e *refreshlessExec) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, State: executor.RevokeStateRevoked}
}
func (e *refreshlessExec) Revocations() []executor.RevokeOutcome { return nil }

// TestKeepaliveJournalsAHolderThatCannotTakeARefresh: a holder that cannot
// receive a new token file is not handed one — nothing is minted for it — and
// the project's journal says once, with the reason, when the run's GitHub
// access will end.
func TestKeepaliveJournalsAHolderThatCannotTakeARefresh(t *testing.T) {
	const execID = "refresh-old-device"
	rh := newRefreshHub(t, secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: execID})
	ex := &refreshlessExec{stubExec: stubExec{id: execID, caps: executor.Capabilities{
		SupportsSecretFiles: true, SecretFilesFromHostPath: false,
	}}}
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })

	project := t.TempDir()
	statedbtest.SeedDir(t, project)
	if _, err := state.Init(project, "old device project", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	lease := acquireSecretLease(rh.dir, project, ex, "run_old_device")
	if lease == nil || lease.delivery == nil {
		t.Fatal("no delivered lease was issued")
	}
	defer lease.Close()
	stopKeepaliveForTest(lease)
	ex.leaseID.Store(lease.lease.ID)
	mints := len(rh.gh.Scoped())

	rh.clock.Advance(52 * time.Minute)
	lease.refreshAppTokens(context.Background(), rh.clock.Now())
	lease.refreshAppTokens(context.Background(), rh.clock.Now().Add(time.Minute))

	if n := len(rh.gh.Scoped()); n != mints {
		t.Errorf("%d token(s) minted for a holder that cannot receive one", n-mints)
	}
	rows := credentialRefreshEvents(t, project)
	if len(rows) != 1 {
		t.Fatalf("got %d credential_refresh journal rows, want one (not one per tick): %+v", len(rows), rows)
	}
	msg := rows[0].Message
	if !strings.Contains(msg, execID) || !strings.Contains(msg, "cannot replace a credential file") ||
		!strings.Contains(msg, "expires") {
		t.Errorf("journal row %q should name the executor, why, and that access ends at the token's expiry", msg)
	}
	denied := 0
	for _, row := range rh.auditRows(t, auditaction.Action(secretbroker.ActionLeaseRefresh)) {
		if strings.Contains(row.Payload, `"decision":"deny"`) {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("%d denied lease.refresh rows, want one", denied)
	}
}

// failingRefreshExec holds a lease and takes refreshes, but every delivery
// fails the same way, as on a host whose disk is full.
type failingRefreshExec struct {
	refreshlessExec
	calls atomic.Int32
}

func (e *failingRefreshExec) RefreshSecretFiles(_ context.Context, req executor.SecretRefreshRequest) executor.SecretRefreshReport {
	e.calls.Add(1)
	return executor.SecretRefreshReport{
		LeaseID: req.LeaseID, Known: true, Error: "write github-token: no space left on device",
	}
}

// TestKeepaliveGivesUpOnAHolderThatKeepsFailing: a delivery that fails the
// same way is audited once and retried with the token already minted — not a
// new one per tick — and after refreshGiveUpAfter ticks the holder is treated
// as unable to take a refresh: it is asked no more, and the journal says once
// when its access ends, by the token it still holds.
func TestKeepaliveGivesUpOnAHolderThatKeepsFailing(t *testing.T) {
	const execID = "refresh-full-disk"
	rh := newRefreshHub(t, secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: execID})
	ex := &failingRefreshExec{refreshlessExec: refreshlessExec{stubExec: stubExec{id: execID,
		caps: executor.Capabilities{SupportsSecretFiles: true, SecretFilesFromHostPath: false}}}}
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })

	project := t.TempDir()
	statedbtest.SeedDir(t, project)
	if _, err := state.Init(project, "full disk project", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	lease := acquireSecretLease(rh.dir, project, ex, "run_full_disk")
	if lease == nil || lease.delivery == nil {
		t.Fatal("no delivered lease was issued")
	}
	defer lease.Close()
	stopKeepaliveForTest(lease)
	ex.leaseID.Store(lease.lease.ID)
	first := scopedTokens(t, rh.gh)[0]
	firstExpiry := lease.appTokenDeadline()
	if firstExpiry.IsZero() {
		t.Fatal("the lease reports no App token deadline")
	}

	rh.clock.Advance(52 * time.Minute)
	for tick := 0; tick < refreshGiveUpAfter+2; tick++ {
		lease.refreshAppTokens(context.Background(), rh.clock.Now())
		rh.clock.Advance(time.Minute)
	}

	if n := int(ex.calls.Load()); n != refreshGiveUpAfter {
		t.Errorf("%d deliveries attempted, want %d: the keepalive should stop asking once it gave up",
			n, refreshGiveUpAfter)
	}
	if n := len(scopedTokens(t, rh.gh)); n != 2 {
		t.Errorf("%d tokens minted, want 2: a failed delivery is retried with the token already minted", n)
	}
	if !rh.gh.Valid(first) {
		t.Error("the token the workload still holds was destroyed although its replacement never reached it")
	}
	denied := 0
	for _, row := range rh.auditRows(t, auditaction.Action(secretbroker.ActionLeaseRefresh)) {
		if strings.Contains(row.Payload, `"decision":"deny"`) {
			denied++
		}
	}
	if denied != 2 {
		t.Errorf("%d denied lease.refresh rows, want 2: the first failure, and giving up", denied)
	}
	rows := credentialRefreshEvents(t, project)
	if len(rows) != 1 {
		t.Fatalf("got %d credential_refresh journal rows, want one: %+v", len(rows), rows)
	}
	msg := rows[0].Message
	if !strings.Contains(msg, execID) || !strings.Contains(msg, "no space left") ||
		!strings.Contains(msg, firstExpiry.UTC().Format(time.RFC3339)) {
		t.Errorf("journal row %q should name the executor, the failure, and the held token's expiry %s",
			msg, firstExpiry.UTC().Format(time.RFC3339))
	}
}

// TestAppTokenDeadlineFollowsADeliveredRefresh: once a refreshed token reached
// the workload, the hour it has left is the new token's, not the first's.
func TestAppTokenDeadlineFollowsADeliveredRefresh(t *testing.T) {
	const execID = "refresh-deadline"
	rh := newRefreshHub(t, secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: execID})
	ex := localprocess.New(execID)
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })

	lease := acquireSecretLease(rh.dir, t.TempDir(), ex, "run_deadline")
	if lease == nil {
		t.Fatal("no lease was issued")
	}
	defer lease.Close()
	stopKeepaliveForTest(lease)
	spec, err := applyLease(uiSpec(t.TempDir(), []string{"/bin/sh", "-c", "sleep 60"}, nil), ex, lease)
	if err != nil {
		t.Fatalf("applyLease: %v", err)
	}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), h.ID, executor.SignalKill) })

	before := lease.appTokenDeadline()
	rh.clock.Advance(52 * time.Minute)
	lease.refreshAppTokens(context.Background(), rh.clock.Now())
	if n := len(scopedTokens(t, rh.gh)); n != 2 {
		t.Fatalf("%d tokens minted, want the refresh's second", n)
	}
	after := lease.appTokenDeadline()
	if !after.After(before.Add(50 * time.Minute)) {
		t.Errorf("deadline after a delivered refresh = %s, want the new token's (about %s)",
			after.UTC().Format(time.RFC3339), before.Add(52*time.Minute).UTC().Format(time.RFC3339))
	}
}

// TestKeepaliveRefusedRefreshEndsAccessAndSaysWhy: a grant revoked since
// dispatch is not renewed; its token is destroyed and the journal says so.
func TestKeepaliveRefusedRefreshEndsAccessAndSaysWhy(t *testing.T) {
	const execID = "refresh-revoked"
	rh := newRefreshHub(t, secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: execID})
	ex := localprocess.New(execID)
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })

	project := t.TempDir()
	statedbtest.SeedDir(t, project)
	if _, err := state.Init(project, "revoked grant project", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	lease := acquireSecretLease(rh.dir, project, ex, "run_revoked")
	if lease == nil {
		t.Fatal("no lease was issued")
	}
	defer lease.Close()
	stopKeepaliveForTest(lease)
	first := scopedTokens(t, rh.gh)[0]
	// A workload holding the lease, as a run's would.
	spec, err := applyLease(uiSpec(t.TempDir(), []string{"/bin/sh", "-c", "sleep 60"}, nil), ex, lease)
	if err != nil {
		t.Fatalf("applyLease: %v", err)
	}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), h.ID, executor.SignalKill) })

	// Revoked from the Secrets panel's broker — another instance.
	broker, closeDB, err := openUIBroker(rh.dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	if err = broker.Revoke(context.Background(), rh.grant.ID, "admin"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	closeDB()

	rh.clock.Advance(52 * time.Minute)
	lease.refreshAppTokens(context.Background(), rh.clock.Now())
	if rh.gh.Valid(first) {
		t.Error("the revoked grant's token is still live at GitHub after its refresh was refused")
	}
	if n := len(rh.gh.Scoped()); n != 1 {
		t.Errorf("%d tokens minted; the revoked grant must not be renewed", n)
	}
	rows := credentialRefreshEvents(t, project)
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "ended") || !strings.Contains(rows[0].Message, "revoked") {
		t.Fatalf("journal = %+v; want one row saying the access ended because the grant was revoked", rows)
	}
	if lease.refreshAppTokens(context.Background(), rh.clock.Now()) {
		t.Error("the keepalive keeps watching a lease whose only App token was refused")
	}
}

// TestGuardedLeaseRenewsThroughTheRealProxyAdapter: the guarded delivery end to
// end — the hub's own gitGuard minting the session, the lease's own gitconfig
// and helper sending a real git to the proxy — with the session renewing the
// App token through the broker after the hour.
func TestGuardedLeaseRenewsThroughTheRealProxyAdapter(t *testing.T) {
	gitBin, _ := secretbrokertest.GitTools(t)
	rh := newRefreshHub(t, secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/guarded"})
	forge := secretbrokertest.NewForge(t, rh.gh, refreshTestRepo)

	// The hub's proxy service, built as startGitProxy builds it, with the
	// scoped sessions' forge pointed at the fake and the registry on the
	// fake clock.
	var handler atomic.Value
	proxySrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := handler.Load().(http.Handler); ok {
			h.ServeHTTP(w, r)
			return
		}
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)
	reg, err := gitproxy.NewRegistry(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	reg.Now = rh.clock.Now
	px, err := gitproxy.New(reg, gitproxy.Options{Transport: forge.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(http.Handler(px))
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	svc := &gitProxyService{reg: reg, proxy: px, baseURL: proxySrv.URL, policy: pol,
		ttl: 4 * time.Hour, githubUpstream: forge.URL}
	prevSvc, prevReq := gitProxySingleton.Load(), gitProxyRequired.Load()
	gitProxySingleton.Store(svc)
	gitProxyRequired.Store(true)
	t.Cleanup(func() {
		gitProxySingleton.Store(prevSvc)
		gitProxyRequired.Store(prevReq)
	})

	broker, closeDB, err := openUIBroker(rh.dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()
	lease, err := broker.LeaseFor(context.Background(),
		secretbroker.Requester{ExecutorID: "local", ProjectID: "/srv/guarded"}, "test")
	if err != nil || len(lease.Materials) != 1 {
		t.Fatalf("LeaseFor = %d materials, %v", len(lease.Materials), err)
	}
	defer broker.Release(lease.ID)
	defer closeGuardedSessions(lease)
	sandbox := t.TempDir()
	mount, err := lease.Materialize(sandbox)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer mount.Close()
	first := scopedTokens(t, rh.gh)[0]
	assertNoTokenUnder(t, sandbox, first)

	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append([]string{
		"HOME=" + home, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_SSL_NO_VERIFY=true", "LC_ALL=C",
	}, mount.Env()...)
	git := func(dir string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, gitBin, args...)
		cmd.Dir, cmd.Env = dir, env
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		err := cmd.Run()
		return buf.String(), err
	}
	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := git("", "clone", "https://github.com/acme/tool", repo); err != nil {
		t.Fatalf("clone through the guarded lease: %v\n%s", err, out)
	}

	rh.clock.Advance(61 * time.Minute)
	if rh.gh.Valid(first) {
		t.Fatal("the first token outlived its hour; the test would prove nothing")
	}
	if out, err := git(repo, "fetch", "origin"); err != nil {
		t.Fatalf("fetch an hour after dispatch: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(repo, "late.txt"), []byte("late\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "late.txt"},
		{"-c", "user.email=a@b.invalid", "-c", "user.name=t", "commit", "-qm", "late"},
		{"push", "origin", "HEAD:refs/heads/cloop/late"},
	} {
		if out, err := git(repo, args...); err != nil {
			t.Fatalf("git %s an hour after dispatch: %v\n%s", args[0], err, out)
		}
	}
	if forge.Ref(t, refreshTestRepo, "refs/heads/cloop/late") == "" {
		t.Fatal("the push did not reach the forge")
	}
	if len(scopedTokens(t, rh.gh)) != 2 {
		t.Errorf("minted %d tokens, want the first and one renewal", len(scopedTokens(t, rh.gh)))
	}
	assertNoTokenUnder(t, sandbox, scopedTokens(t, rh.gh)[1])
}

// TestSessionRefresherMapsAFinalRefusal: the adapter between the broker and the
// proxy must turn the broker's final refusal into the one the session closes
// on, and leave any other failure retryable.
func TestSessionRefresherMapsAFinalRefusal(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name  string
		err   error
		final bool
	}{
		{"revoked grant", secretbroker.ErrRefreshRefused, true},
		{"github unreachable", secretbroker.ErrGitHubAppMint, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refresh := sessionRefresher(secretbroker.GitGuardRequest{
				TokenExpiresAt: expires,
				Refresh: func(context.Context, string) (secretbroker.AppTokenRefresh, error) {
					return secretbroker.AppTokenRefresh{}, tc.err
				},
			})
			_, err := refresh(context.Background(), "held")
			if got := err != nil && isCredentialRefused(err); got != tc.final {
				t.Fatalf("final = %t for %v; want %t", got, err, tc.final)
			}
		})
	}
	if sessionRefresher(secretbroker.GitGuardRequest{}) != nil {
		t.Error("a PAT (no refresher) was given a session refresher")
	}
}

func isCredentialRefused(err error) bool {
	return strings.Contains(err.Error(), gitproxy.ErrCredentialRefused.Error())
}
