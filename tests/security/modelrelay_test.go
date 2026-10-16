package security

// Guarantee: with the hub's model relay on, a sandboxed run never holds its
// Claude credential, and what the hub charges for it is what the API counted
// (Task 20435).
//
// Without the relay a run on an executor that isolates from the hub is handed
// its CLAUDE_CODE_OAUTH_TOKEN as a leased environment variable: the workload
// holds the plaintext for the whole run, a revocation cannot take it out of a
// running device task, and the spend the hub charges is whatever the run
// reports. This scenario drives the real hub — its configuration, its run
// route, its grant revocation route, its relay route — with a stand-in for the
// Anthropic API and an isolating executor that records what it is handed:
//
//   - the dispatched spec, as the executor receives it and as it would be
//     stored, holds no byte of the credential, and points the harness at the
//     relay with a session token instead;
//   - a call through the relay reaches the API with the grant's credential,
//     and the identity that started the run is charged what the API counted;
//   - revoking the grant through the hub's route refuses the run's very next
//     call with a 403 naming why, without reaching the API;
//   - at the run's end its project ledger carries the relay's count, and the
//     difference from what the run reported is on the audit trail.
//
// The body runs in a child process: the relay, like the git proxy, is started
// once per process by the first hub built in it, and a fresh process is the
// only way to make that this test's.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// modelRelayChild marks the child process that runs the scenario.
const modelRelayChild = "CLOOP_SECURITY_MODEL_RELAY_CHILD"

func TestARelayedRunNeverHoldsItsClaudeCredential(t *testing.T) {
	if os.Getenv(modelRelayChild) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestARelayedRunNeverHoldsItsClaudeCredential$", "-test.v",
			"-test.timeout", "3m")
		cmd.Env = append(os.Environ(), modelRelayChild+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestARelayedRunNeverHoldsItsClaudeCredential") {
			t.Fatalf("the model relay scenario failed in its own process (%v):\n%s", err, out)
		}
		return
	}
	relayedRunNeverHoldsItsCredential(t)
}

// relaySandbox is an isolating executor that records what it is handed and
// runs until released.
type relaySandbox struct {
	id   string
	done chan struct{}

	mu    sync.Mutex
	specs []executor.Spec
}

func (e *relaySandbox) ID() string   { return e.id }
func (e *relaySandbox) Kind() string { return executor.KindContainer }
func (e *relaySandbox) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer, SharesHostFilesystem: true}
}
func (e *relaySandbox) HealthCheck(context.Context) error { return nil }
func (e *relaySandbox) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.specs = append(e.specs, spec)
	return executor.Handle{ID: fmt.Sprintf("%s-%d", e.id, len(e.specs)), ExecutorID: e.id, StartedAt: time.Now()}, nil
}
func (e *relaySandbox) Status(_ context.Context, id string) (executor.Status, error) {
	select {
	case <-e.done:
		return executor.Status{HandleID: id, ExecutorID: e.id, State: executor.StateExited}, nil
	default:
		return executor.Status{HandleID: id, ExecutorID: e.id, State: executor.StateRunning}, nil
	}
}
func (e *relaySandbox) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	go func() {
		<-e.done
		close(ch)
	}()
	return ch, nil
}
func (e *relaySandbox) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *relaySandbox) SupportsRevocation() bool                              { return true }
func (e *relaySandbox) HoldsLease(string) bool                                { return false }
func (e *relaySandbox) Leases() []string                                      { return nil }
func (e *relaySandbox) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, State: executor.RevokeStateRevoked}
}
func (e *relaySandbox) Revocations() []executor.RevokeOutcome { return nil }

func (e *relaySandbox) started() []executor.Spec {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]executor.Spec(nil), e.specs...)
}

func relayedRunNeverHoldsItsCredential(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv(secretbroker.EnvPassphraseKey, "model-relay-security-passphrase")
	credential := "sk-" + "ant-oat01-" + "security-canary-relay-credential-7f31c9a2"

	// ── the Anthropic API ──
	var (
		apiMu    sync.Mutex
		apiCalls []string
	)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		apiMu.Lock()
		apiCalls = append(apiCalls, r.Header.Get("Authorization"))
		apiMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"claude-sonnet-5-20260901","usage":{"input_tokens":400,"output_tokens":50,` +
			`"cache_read_input_tokens":3000,"cache_creation_input_tokens":0}}`))
	}))
	defer api.Close()

	// ── the hub, with the relay on ──
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "model relay", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	cfg := "ui:\n  external_url: https://hub.example.com\nexecutors:\n  model_relay:\n    enabled: true\n" +
		"    listener: dashboard\n    upstream_base_url: " + api.URL + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var (
		mu      sync.RWMutex
		handler http.Handler = http.NotFoundHandler()
	)
	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		h := handler
		mu.RUnlock()
		h.ServeHTTP(w, r)
	}))
	defer hubSrv.Close()
	node, err := hubcluster.Join(hubcluster.Options{
		DBPath: state.DBPath(dir), AdvertiseURL: hubSrv.URL,
		Heartbeat: 40 * time.Millisecond, MemberTTL: 500 * time.Millisecond,
		BusPoll: 15 * time.Millisecond, BusFlush: 5 * time.Millisecond,
		Campaign: 30 * time.Millisecond, LeaderTTL: 600 * time.Millisecond, LeaderInterval: 60 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	node.Start(ctx)
	defer node.Close()
	sandbox := &relaySandbox{id: "relay-sandbox", done: make(chan struct{})}
	register(t, sandbox)
	srv := ui.NewInCluster(dir, 0, "", node)
	mu.Lock()
	handler = srv.Handler()
	mu.Unlock()
	if err := executor.Bind(dir, sandbox.ID()); err != nil {
		t.Fatal(err)
	}

	// ── the project's Claude credential, granted as the dashboard would ──
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: "claude-harness", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"CLAUDE_CODE_OAUTH_TOKEN":"` + credential + `"}`), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: dir}, TTL: time.Hour, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}

	call := func(method, path, auth, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, hubSrv.URL+path, rdr)
		req.Host = "127.0.0.1"
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := hubSrv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// ── the run ──
	if code, body := call(http.MethodPost, "/api/run", "", `{}`); code != http.StatusOK {
		t.Fatalf("POST /api/run = %d %s", code, body)
	}
	var spec executor.Spec
	deadline := time.Now().Add(20 * time.Second)
	for {
		if s := sandbox.started(); len(s) == 1 {
			spec = s[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run was never handed to the sandbox")
		}
		time.Sleep(20 * time.Millisecond)
	}
	stored, _ := json.Marshal(spec)
	handed := strings.Join(spec.Env, "\n") + string(stored)
	for _, f := range spec.SecretFiles {
		handed += string(f.Content)
	}
	if strings.Contains(handed, credential) {
		t.Fatal("the run's Claude credential is in what the sandbox was handed")
	}
	env := map[string]string{}
	for _, kv := range spec.Env {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	if env["ANTHROPIC_BASE_URL"] != "https://hub.example.com/_anthropic" ||
		!strings.HasPrefix(env["ANTHROPIC_AUTH_TOKEN"], "cloop_relay_") || env["CLAUDE_CODE_OAUTH_TOKEN"] != "" {
		t.Fatalf("the sandbox was not pointed at the relay: base %q token set %v",
			env["ANTHROPIC_BASE_URL"], env["ANTHROPIC_AUTH_TOKEN"] != "")
	}
	token := env["ANTHROPIC_AUTH_TOKEN"]

	// ── a call through the relay spends the credential upstream ──
	msg := `{"model":"claude-sonnet-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`
	if code, body := call(http.MethodPost, "/_anthropic/v1/messages", token, msg); code != http.StatusOK {
		t.Fatalf("relayed call = %d %s", code, body)
	}
	apiMu.Lock()
	seen := append([]string(nil), apiCalls...)
	apiMu.Unlock()
	if len(seen) != 1 || seen[0] != "Bearer "+credential {
		t.Fatalf("the API saw %d calls; the first presented the run's credential: %v", len(seen),
			len(seen) == 1 && seen[0] == "Bearer "+credential)
	}

	// ── revoking the grant refuses the next call ──
	if code, body := call(http.MethodDelete, "/api/grants/"+grant.ID, "", ""); code != http.StatusOK {
		t.Fatalf("DELETE /api/grants = %d %s", code, body)
	}
	// Refused with the revocation's own reason, not only that the lease went.
	code, body := call(http.MethodPost, "/_anthropic/v1/messages", token, msg)
	if code != http.StatusForbidden || !strings.Contains(body, "grant "+grant.ID+" revoked by") {
		t.Fatalf("the call after the revocation = %d %s", code, body)
	}
	apiMu.Lock()
	n := len(apiCalls)
	apiMu.Unlock()
	if n != 1 {
		t.Fatalf("the API was reached %d times; a revoked session reached it", n)
	}

	// ── the run's end: its ledger carries the relay's count ──
	close(sandbox.done)
	var gap []statedb.AuditEvent
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "model_relay.usage_gap", Limit: 10})
		if err == nil && len(rows) > 0 {
			gap = rows
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(gap) != 1 || !strings.Contains(gap[0].Payload, `"relay_tokens":3450`) || strings.Contains(gap[0].Payload, credential) {
		t.Fatalf("usage_gap rows after the run ended: %+v", gap)
	}
	costs, err := db.ReadCosts()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, c := range costs {
		total += c.InputTokens + c.OutputTokens
	}
	if total != 3450 {
		t.Fatalf("the project's ledger carries %d tokens for the run, want the relay's 3450", total)
	}
	raw, _ := os.ReadFile(state.DBPath(dir))
	if strings.Contains(string(raw), credential) {
		t.Fatal("the credential is in the hub's database in the clear")
	}
}
