package e2e_test

// `cloop login` then `cloop remote init --run` end to end (Task 20417): the
// built ./cloop binary in a temporary checkout whose origin is on GitHub,
// signing in to a hub with single sign-on, and creating, binding and
// dispatching a project there without the dashboard.
//
// The hub runs in this test's process, as in devicelogin_test.go, for the
// same reason: the executor the project is bound to is a test executor
// registered in the hub's own process — one that isolates like a container,
// records what it is handed, and runs nothing — so the dispatch can be
// inspected. The hub's own work (`cloop init` for the new project) runs the
// built binary, exactly as a deployed hub runs itself.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// recordingExecutor isolates like a container and runs nothing: it records
// the spec each dispatch hands it, says one line, and ends the run cleanly.
type recordingExecutor struct {
	id string

	mu      sync.Mutex
	specs   []executor.Spec
	started chan struct{}
}

func (e *recordingExecutor) ID() string   { return e.id }
func (e *recordingExecutor) Kind() string { return "e2e-sandbox" }
func (e *recordingExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation: executor.IsolationContainer, SupportsStream: true, SupportsSignal: true,
		NetworkEgress: true, SupportsProjectSeed: true, SupportsWorkspaceProvisioning: true,
		SupportsSecretFiles: true,
	}
}

func (e *recordingExecutor) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	e.mu.Lock()
	e.specs = append(e.specs, spec)
	n := len(e.specs)
	e.mu.Unlock()
	if n == 1 {
		close(e.started)
	}
	return executor.Handle{ID: "rec-" + time.Now().Format("150405.000000"), ExecutorID: e.id, StartedAt: time.Now()}, nil
}

func (e *recordingExecutor) Signal(context.Context, string, executor.Signal) error { return nil }

func (e *recordingExecutor) Status(_ context.Context, id string) (executor.Status, error) {
	return executor.Status{HandleID: id, ExecutorID: e.id, State: executor.StateExited, FinishedAt: time.Now()}, nil
}

func (e *recordingExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine, 1)
	ch <- executor.LogLine{Time: time.Now(), Stream: executor.StreamStdout, Text: "hello from the e2e sandbox\n"}
	close(ch)
	return ch, nil
}

func (e *recordingExecutor) HealthCheck(context.Context) error { return nil }

// The hub hands a brokered credential only to an executor that can take it
// back from a running workload (executor.Revoker). This one holds nothing it
// would have to: it runs nothing.
func (e *recordingExecutor) SupportsRevocation() bool              { return true }
func (e *recordingExecutor) HoldsLease(string) bool                { return false }
func (e *recordingExecutor) Leases() []string                      { return nil }
func (e *recordingExecutor) Revocations() []executor.RevokeOutcome { return nil }
func (e *recordingExecutor) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, GrantID: req.GrantID, ExecutorID: e.id,
		State: executor.RevokeStateRevoked, Ack: &executor.RevokeReport{}}
}

// firstSpec is the first dispatch the executor received.
func (e *recordingExecutor) firstSpec(t *testing.T, within time.Duration) executor.Spec {
	t.Helper()
	select {
	case <-e.started:
	case <-time.After(within):
		t.Fatalf("nothing was dispatched to %s within %s", e.id, within)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.specs[0]
}

// startInitHub is a hub with single sign-on, a secret store, the recording
// executor, and the built binary as its own.
func startInitHub(t *testing.T, ex *recordingExecutor) *deviceHub {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv(secretbroker.EnvPassphraseKey, "e2e-remote-init-passphrase")

	idp := newDeviceIdP(t)
	dir := filepath.Join(t.TempDir(), "hub")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Init(dir, "The hub's own project", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	srv := ui.New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	srv.SelfExe = binaryPath(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	store, warn := srv.OpenSessionStore()
	if warn != nil {
		t.Fatalf("the session store is not durable: %v", warn)
	}
	cfg := oidcauth.Config{
		Enabled: true, Issuer: idp.server.URL, ClientID: "cloop-e2e", RedirectURL: ts.URL + "/auth/callback",
		AdminEmails: []string{deviceUser}, DeviceLogin: true, Store: store, Audit: srv.SessionAuditSink(),
	}
	srv.InstallOIDCHooks(&cfg)
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	roles, err := srv.OpenRoleStore()
	if err != nil {
		t.Fatalf("OpenRoleStore: %v", err)
	}
	resolver, err := authz.New(authz.Config{AdminEmails: []string{deviceUser}, Runtime: roles})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	if err := executor.Register(ex); err != nil {
		t.Fatalf("register %s: %v", ex.id, err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.id) })
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: ex.id, Name: "E2E sandbox", Kind: ex.Kind(),
		Status: statedb.ExecutorStatusOnline, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("record %s: %v", ex.id, err)
	}
	return &deviceHub{srv: srv, ts: ts, idp: idp, dir: dir, home: home}
}

// storeSecretAs stores a personal secret with the terminal's session, as
// the dashboard's Secrets panel would for the same person.
func storeSecretAs(t *testing.T, h *deviceHub, credential, name, kind, payload string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name, "kind": kind, "payload": payload, "personal": true})
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/secrets", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var raw bytes.Buffer
		_, _ = raw.ReadFrom(resp.Body)
		t.Fatalf("store %s = %d %s", name, resp.StatusCode, raw.String())
	}
}

func TestE2ERemoteInitCreatesBindsAndDispatches(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ex := &recordingExecutor{id: "e2e-sandbox-" + strings.ReplaceAll(t.Name(), "/", "-"), started: make(chan struct{})}
	h := startInitHub(t, ex)
	credPath := filepath.Join(h.home, ".config", "cloop", "hubs.json")

	// ── sign in ──
	login := h.start(t, "login", h.ts.URL, "--no-browser", "--hostname", "e2e-laptop")
	link := login.await(t, reApprovalLink, 30*time.Second)[1]
	if res := h.decide(t, link, "approve"); !res.RequestShown || !res.Finished {
		t.Fatalf("the approval did not complete: %+v", res)
	}
	login.wait(t, 90*time.Second)
	if login.err != nil {
		t.Fatalf("cloop login: %v\n%s%s", login.err, login.stdout, login.stderr)
	}
	raw, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatal(err)
	}
	credential := credentialIn(raw)

	// The developer's own credentials, already on the hub: a GitHub token
	// for the repository, and the Claude credential a sandbox signs in with.
	storeSecretAs(t, h, credential, "alice-pat", "github_pat", "ghp_e2eRemoteInit0123456789abcdefghijk")
	storeSecretAs(t, h, credential, "alice-claude", "env", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-ant-oat01-e2e-remote-init"}`)

	// ── a checkout of acme/widgets ──
	checkout := filepath.Join(t.TempDir(), "widgets-checkout")
	if err := os.MkdirAll(checkout, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "git@github.com:acme/widgets.git"}} {
		if out, err := exec.Command("git", append([]string{"-C", checkout}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// ── init --run ──
	p := h.startIn(t, checkout, "remote", "init", "--goal", "Ship the widgets API", "--executor", ex.id,
		"--repo-secret", "alice-pat", "--access", "write", "--run")
	p.wait(t, 120*time.Second)
	out := p.stdout.String() + p.stderr.String()
	if p.err != nil {
		t.Fatalf("cloop remote init --run: %v\n%s", p.err, out)
	}
	projectPath := filepath.Join(h.home, "projects", "widgets")
	for _, want := range []string{
		"Created widgets on " + h.ts.URL + " at " + projectPath + ", bound to executor " + ex.id,
		"Granted acme/widgets (write) through alice-pat",
		"Granted your Claude credential alice-claude to its sandbox",
		"Dashboard: " + h.ts.URL + "/?project=",
		"Started widgets. Follow it with: cloop remote logs widgets --follow",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cloop remote init printed no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, credential) || strings.Contains(out, "ghp_e2eRemoteInit") || strings.Contains(out, "sk-ant-oat01") {
		t.Fatalf("cloop remote init printed a credential:\n%s", out)
	}

	// ── created: initialised on the hub, owned by who created it ──
	st, err := state.LoadLite(projectPath)
	if err != nil || st.Goal != "Ship the widgets API" {
		t.Fatalf("the project on the hub: goal %q, %v", st.Goal, err)
	}
	entries, err := multiui.Load()
	if err != nil {
		t.Fatal(err)
	}
	owned := false
	for _, e := range entries {
		owned = owned || (e.Path == projectPath && strings.EqualFold(e.Owner, deviceUser))
	}
	if !owned {
		t.Fatalf("%s is not registered as %s's: %+v", projectPath, deviceUser, entries)
	}

	// ── bound ──
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if id, ok, err := db.ProjectExecutor(projectPath); err != nil || !ok || id != ex.id {
		t.Fatalf("the project is bound to %q (%v, %v), want %s", id, ok, err, ex.id)
	}

	// ── dispatched, with its project and its credentials ──
	spec := ex.firstSpec(t, 30*time.Second)
	if spec.Labels["project"] != projectPath {
		t.Errorf("the dispatch is for project %q, want %s", spec.Labels["project"], projectPath)
	}
	if len(spec.Argv) < 2 || spec.Argv[1] != "run" {
		t.Errorf("the dispatch runs %v, want the hub's binary with run", spec.Argv)
	}
	if len(spec.ProjectSeed) == 0 {
		t.Error("the dispatch carries no project state for the sandbox to run")
	}
	env := strings.Join(spec.Env, "\n")
	if !strings.Contains(env, "CLAUDE_CODE_OAUTH_TOKEN=") {
		t.Error("the Claude credential granted by init did not reach the dispatch")
	}
	if !strings.Contains(env, "CLOOP_GITHUB_REPO_ALLOWLIST=acme/widgets") {
		t.Errorf("the repository grant did not reach the dispatch:\n%s", redactEnv(spec.Env))
	}

	// ── and the terminal sees it ──
	listed, err := h.run(t, "remote", "repos", "list", "widgets")
	if err != nil || !strings.Contains(listed, "acme/widgets") || !strings.Contains(listed, "alice-pat") {
		t.Fatalf("cloop remote repos list: %v\n%s", err, listed)
	}
	listed, err = h.run(t, "remote", "projects")
	if err != nil || !strings.Contains(listed, "widgets") {
		t.Fatalf("cloop remote projects: %v\n%s", err, listed)
	}
}

// redactEnv lists an environment's keys, for a failure message that must not
// print the values.
func redactEnv(env []string) string {
	keys := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		keys = append(keys, k)
	}
	return strings.Join(keys, " ")
}
