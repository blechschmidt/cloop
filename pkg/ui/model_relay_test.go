package ui

// Tests for the model relay for sandboxed runs (Task 20435): a run's Claude
// credential stays on the hub, its sandbox gets a session that spends it, and
// the hub charges and caps what the API reports — through the lifecycle of the
// lease the session stands on, across a restart, and at the run's end.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// relayAPI stands in for api.anthropic.com: it records what reached it and
// answers every Messages call with the same usage.
type relayAPI struct {
	srv   *httptest.Server
	mu    sync.Mutex
	heads []http.Header
}

func newRelayAPI(t *testing.T) *relayAPI {
	a := &relayAPI{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		a.mu.Lock()
		a.heads = append(a.heads, r.Header.Clone())
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5-20260901",` +
			`"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1000,"output_tokens":200,` +
			`"cache_read_input_tokens":5000,"cache_creation_input_tokens":100}}`))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *relayAPI) calls() []http.Header {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]http.Header(nil), a.heads...)
}

// relayTokensPerCall is what one relayAPI answer reports spending.
const relayTokensPerCall = 1000 + 200 + 5000 + 100

// relayRig is a control plane running the model relay as a hub process does,
// with a front door that serves whichever relay the current process runs.
type relayRig struct {
	t       *testing.T
	dir     string
	db      *statedb.DB
	api     *relayAPI
	front   *httptest.Server
	srv     *Server
	quotas  *quota.Enforcer
	cfg     config.ModelRelayConfig
	holder  atomic.Value // string
	token   string       // the OAuth token granted
	secrets int          // how many secrets grant minted, for their names
	// servedCh receives once the relay has returned from a call.
	servedCh chan struct{}
}

func newRelayRig(t *testing.T, limits quota.Limits) *relayRig {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "model-relay-unit-passphrase")
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "model relay", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"),
		[]byte("ui:\n  external_url: https://hub.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	r := &relayRig{t: t, dir: dir, db: db.AsControlPlane(), api: newRelayAPI(t),
		token: fakeAnthropicToken("oat01", "relaytok")}
	t.Cleanup(func() { _ = r.db.Close() })
	r.holder.Store("hub_old")
	r.cfg = config.ModelRelayConfig{Enabled: true, Listener: config.ModelRelayListenerDashboard,
		UpstreamBaseURL: r.api.srv.URL}

	useControlPlaneDir(t, dir)
	prevHolder := leaseHolderID
	leaseHolderID = func() string { return r.holder.Load().(string) }
	prevWanted, prevSvc, prevHub := modelRelayWanted.Load(), modelRelayCurrent.Load(), modelRelayHub.Load()
	r.srv = &Server{WorkDir: dir}
	r.quotas = installQuotas(t, r.srv, quota.Config{Defaults: limits})
	modelRelayHub.Store(r.srv)
	t.Cleanup(func() {
		if svc := modelRelayCurrent.Load(); svc != nil && svc != prevSvc {
			svc.close("test over")
		}
		modelRelayCurrent.Store(prevSvc)
		modelRelayWanted.Store(prevWanted)
		modelRelayHub.Store(prevHub)
		leaseHolderID = prevHolder
		for _, sl := range liveLeases.snapshot() {
			if sl.workDir == dir {
				stopKeepaliveForTest(sl)
				liveLeases.removeIf(sl)
			}
		}
	})
	r.startProcess()
	r.servedCh = make(chan struct{}, 64)
	r.front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The relay books a response's spend after the last byte is written,
		// which the client may already hold: a call is over when this returns.
		defer func() { r.servedCh <- struct{}{} }()
		if svc := activeModelRelay(); svc != nil {
			svc.ServeHTTP(w, req)
			return
		}
		writeRelayNotHere(w)
	}))
	t.Cleanup(r.front.Close)
	return r
}

// startProcess starts the relay as a hub process starting up does.
func (r *relayRig) startProcess() *modelRelayService {
	r.t.Helper()
	svc, err := startModelRelay(r.cfg, r.dir)
	if err != nil {
		r.t.Fatalf("startModelRelay: %v", err)
	}
	modelRelayWanted.Store(true)
	modelRelayCurrent.Store(svc)
	return svc
}

// crash drops the current process's relay as a killed process does — no
// suspension, its sessions simply gone — and starts another as holder.
func (r *relayRig) crash(holder string) *modelRelayService {
	if old := modelRelayCurrent.Load(); old != nil {
		old.stop()
		<-old.done
		_ = old.auditDB.Close()
	}
	r.holder.Store(holder)
	return r.startProcess()
}

// grant grants the rig's OAuth token, or another env payload, to subject.
func (r *relayRig) grant(subject string, payload map[string]string) secretbroker.Grant {
	r.t.Helper()
	broker, closeDB, err := openUIBroker(r.dir)
	if err != nil {
		r.t.Fatal(err)
	}
	defer closeDB()
	raw, _ := json.Marshal(payload)
	r.secrets++
	sec, err := broker.Mint(r.t.Context(), secretbroker.MintRequest{
		Name: fmt.Sprintf("relay-claude-%d", r.secrets), Kind: secretbroker.KindEnv, Payload: raw, Actor: "test",
	})
	if err != nil {
		r.t.Fatalf("mint: %v", err)
	}
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		r.t.Fatal(err)
	}
	g, err := broker.Grant(r.t.Context(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: sub, TTL: 24 * time.Hour, Actor: "test",
	})
	if err != nil {
		r.t.Fatalf("grant: %v", err)
	}
	return g
}

// leaseFor acquires a run's lease for ex and relays it, as a dispatch does,
// and returns the lease and the spec the workload would be handed.
func (r *relayRig) leaseFor(ex executor.Executor, runID string) (*secretLease, executor.Spec, string) {
	r.t.Helper()
	sl := acquireSecretLease(r.dir, r.dir, ex, runID, nil)
	if sl == nil {
		r.t.Fatal("no lease was issued")
	}
	stopKeepaliveForTest(sl)
	spec, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, ex, sl)
	if err != nil {
		r.t.Fatal(err)
	}
	spec, id, err := applyModelRelay(spec, ex, r.dir, sl, relayDispatch{runID: runID,
		payer: "alice@corp.example", provider: "claudecode", run: true})
	if err != nil {
		r.t.Fatalf("applyModelRelay: %v", err)
	}
	if id == "" {
		r.t.Fatal("the run was not relayed")
	}
	sl.bindHandle(ex.ID(), "h-"+runID)
	return sl, spec, id
}

// call makes one Messages call the way the sandbox's harness would, with
// whatever token its environment holds.
func (r *relayRig) call(spec executor.Spec) (int, string) {
	r.t.Helper()
	tok, _ := envValue(spec.Env, envAnthropicAuth)
	req, _ := http.NewRequest(http.MethodPost, r.front.URL+modelRelayMount+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-5","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.front.Client().Do(req)
	if err != nil {
		r.t.Fatalf("relay call: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	<-r.servedCh
	return resp.StatusCode, string(b)
}

func (r *relayRig) auditRows(action auditaction.Action) []statedb.AuditEvent {
	rows, _, err := r.db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 200})
	if err != nil {
		r.t.Fatal(err)
	}
	return rows
}

func (r *relayRig) spentToday(identity string) (tokens, usd float64) {
	u := r.quotas.Usage(identity)
	return u[quota.ResDailyTokens], u[quota.ResDailyCostUSD]
}

// relayJournal is the project's model relay rows, newest first.
func relayJournal(t *testing.T, dir string) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(dir, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []state.EventRow
	for _, row := range rows {
		if row.Type == state.EventModelRelay {
			out = append(out, row)
		}
	}
	return out
}

// liveExec is an isolating executor whose workload runs until released.
type liveExec struct {
	*harnessExec
	done chan struct{}
}

func newLiveExec(id string) *liveExec {
	return &liveExec{harnessExec: newHarnessExec(id, executor.KindContainer, executor.IsolationContainer),
		done: make(chan struct{})}
}

// Stream stays open until the workload is released, as a live workload's
// output does.
func (e *liveExec) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	go func() {
		<-e.done
		close(ch)
	}()
	return ch, nil
}

func (e *liveExec) Status(_ context.Context, id string) (executor.Status, error) {
	select {
	case <-e.done:
		return executor.Status{HandleID: id, ExecutorID: e.id, State: executor.StateExited}, nil
	default:
		return executor.Status{HandleID: id, ExecutorID: e.id, State: executor.StateRunning}, nil
	}
}

// TestModelRelayKeepsTheRunsCredentialOnTheHub is the task's core: a run on an
// isolating executor is dispatched with no Claude credential anywhere in what
// its executor is handed — environment, bindings, files, the stored spec — and
// with the relay's URL and a session token instead; its call reaches the API
// with the credential the run's grant holds, and what the API reports is
// charged to the identity that started the run.
func TestModelRelayKeepsTheRunsCredentialOnTheHub(t *testing.T) {
	r := newRelayRig(t, nil)
	project := statedbtest.Dir(t)
	ex := newLiveExec("relay-box")
	t.Cleanup(func() { close(ex.done) })
	registerStub(t, ex)
	if err := executor.Bind(project, ex.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(project) })
	g := r.grant("project:"+project, map[string]string{envClaudeOAuthToken: r.token})

	alice := newHarnessClearance(project, harnessWho{identity: "alice@corp.example"}, "")
	if _, _, err := startWorkloadAs(nil, alice, "alice@corp.example", project, []string{"cloop", "run"}, nil); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	specs := ex.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads", len(specs))
	}
	spec := specs[0]
	whole, _ := json.Marshal(spec)
	all := strings.Join(spec.Env, "\n") + string(whole)
	for _, f := range spec.SecretFiles {
		all += string(f.Content)
	}
	if strings.Contains(all, r.token) {
		t.Fatal("the run's Claude credential reached what its executor was handed")
	}
	for _, b := range spec.Secrets {
		for _, k := range b.EnvKeys {
			if k == envClaudeOAuthToken {
				t.Errorf("binding %s still names %s", b.GrantID, k)
			}
		}
	}
	base, _ := envValue(spec.Env, envAnthropicBaseURL)
	tok, _ := envValue(spec.Env, envAnthropicAuth)
	id, _ := envValue(spec.Env, modelRelayEnvKey)
	red, _ := envValue(spec.Env, redact.EnvKey)
	if base != "https://hub.example.com/_anthropic" || !strings.HasPrefix(tok, modelRelayTokenPrefix) || id == "" {
		t.Fatalf("relay env: base %q token %q session %q", base, tok, id)
	}
	if !strings.Contains(","+red+",", ","+envAnthropicAuth+",") {
		t.Errorf("CLOOP_REDACT_ENV %q does not declare the session token sensitive", red)
	}

	code, body := r.call(spec)
	if code != http.StatusOK {
		t.Fatalf("relayed call: %d %s", code, body)
	}
	calls := r.api.calls()
	if len(calls) != 1 || calls[0].Get("Authorization") != "Bearer "+r.token ||
		!strings.Contains(calls[0].Get("Anthropic-Beta"), claudeproxy.OAuthBeta) {
		t.Fatalf("the API saw %+v", calls)
	}
	tokens, usd := r.spentToday("alice@corp.example")
	if tokens != relayTokensPerCall || usd <= 0 {
		t.Fatalf("alice was charged %v tokens, $%v; want the API's %d", tokens, usd, relayTokensPerCall)
	}
	minted := r.auditRows(auditaction.ActionModelRelaySessionMinted)
	if len(minted) != 1 || !strings.Contains(minted[0].Payload, g.ID) ||
		!strings.Contains(minted[0].Payload, `"upstream_kind":"oauth_token"`) ||
		!strings.Contains(minted[0].Payload, `"payer":"alice@corp.example"`) || strings.Contains(minted[0].Payload, r.token) {
		t.Fatalf("minted rows %+v", minted)
	}
	if got := relayedRunSession(r.db, project); got != id {
		t.Fatalf("the run is marked relayed by %q, want %q", got, id)
	}
}

// TestModelRelayRefusesPastThePayersBudget: the call after the payer's daily
// token budget is spent is refused with a 403 — which Claude Code ends a task
// on at once — naming the cap, and never reaches the API.
func TestModelRelayRefusesPastThePayersBudget(t *testing.T) {
	r := newRelayRig(t, quota.Limits{quota.ResDailyTokens: 1000})
	ex := newTakeoverExecutor("edge-budget")
	r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	_, spec, _ := r.leaseFor(ex, "run_budget")
	refusedBefore := value((&Server{}).gatherMetrics(),
		series("cloop_model_relay_refusals_total", "reason", string(claudeproxy.DenyBudget)))

	if code, body := r.call(spec); code != http.StatusOK {
		t.Fatalf("the first call, with budget left: %d %s", code, body)
	}
	code, body := r.call(spec)
	if code != http.StatusForbidden || !strings.Contains(body, "daily token budget (daily_token_budget) of 1000 tokens") ||
		!strings.Contains(body, "alice@corp.example") {
		t.Fatalf("the call past the budget: %d %s", code, body)
	}
	if n := len(r.api.calls()); n != 1 {
		t.Fatalf("the API was reached %d times, want once", n)
	}
	denied := r.auditRows(auditaction.ActionModelRelayDenied)
	if len(denied) != 1 || !strings.Contains(denied[0].Payload, `"reason":"budget_exhausted"`) {
		t.Fatalf("denied rows %+v", denied)
	}
	if got := value((&Server{}).gatherMetrics(), series("cloop_model_relay_refusals_total", "reason",
		string(claudeproxy.DenyBudget))); got != refusedBefore+1 {
		t.Errorf("budget refusals counted %v, want %v", got, refusedBefore+1)
	}
}

// TestModelRelaySessionEndsWithItsGrantAndItsLease: revoking the grant behind
// a session refuses the very next call, with the reason; releasing the lease a
// session stands on does the same; and each end is audited.
func TestModelRelaySessionEndsWithItsGrantAndItsLease(t *testing.T) {
	r := newRelayRig(t, nil)
	ex := newTakeoverExecutor("edge-revoke")
	g := r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	sl, spec, id := r.leaseFor(ex, "run_revoke")
	if code, _ := r.call(spec); code != http.StatusOK {
		t.Fatalf("before the revocation: %d", code)
	}
	if err := sl.withdrawGrant(r.t.Context(), g.ID, "grant "+g.ID+" revoked by test"); err != nil {
		t.Fatalf("withdrawGrant: %v", err)
	}
	code, body := r.call(spec)
	if code != http.StatusForbidden || !strings.Contains(body, "revoked by test") {
		t.Fatalf("the call after the revocation: %d %s", code, body)
	}
	if n := len(r.api.calls()); n != 1 {
		t.Fatalf("the API was reached %d times after the revocation", n)
	}
	if rows := r.auditRows(auditaction.ActionModelRelayRejected); len(rows) != 1 || rows[0].EntityID != id {
		t.Fatalf("rejected rows %+v", rows)
	}

	// A second run's session ends with its lease.
	r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	sl2, spec2, id2 := r.leaseFor(ex, "run_release")
	sl2.Close()
	code, body = r.call(spec2)
	if code != http.StatusForbidden || !strings.Contains(body, "the lease it stands on was released") {
		t.Fatalf("the call after the lease was released: %d %s", code, body)
	}
	closed := r.auditRows(auditaction.ActionModelRelaySessionClosed)
	ended := map[string]bool{}
	for _, row := range closed {
		ended[row.EntityID] = true
	}
	if !ended[id] || !ended[id2] {
		t.Fatalf("closed rows name %v, want %s and %s", ended, id, id2)
	}
	if row, err := r.db.GetProxySession(statedb.ProxySessionModel, id2); err != nil || row.Open() {
		t.Fatalf("the session's record after its lease was released: %+v, %v", row, err)
	}

	// A session whose lease this process does not hold — one it restored
	// with a run it is adopting, say — ends with its grant all the same, told
	// why: the revocation reaches the lease through its record in the store.
	ex3 := newTakeoverExecutor("edge-revoke-untracked")
	g3 := r.grant("executor:"+ex3.ID(), map[string]string{envClaudeOAuthToken: r.token})
	sl3, spec3, _ := r.leaseFor(ex3, "run_untracked")
	liveLeases.removeIf(sl3)
	t.Cleanup(sl3.Close)
	broker, closeDB, err := openUIBroker(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = broker.RevokeGrant(t.Context(), secretbroker.RevokeGrantRequest{GrantID: g3.ID, Actor: "test"})
	closeDB()
	if err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	r.srv.grantRevokedHere(t.Context(), clusterGrantRequest{GrantID: g3.ID, Actor: "test"})
	code, body = r.call(spec3)
	if code != http.StatusForbidden || !strings.Contains(body, "grant "+g3.ID+" revoked by test") {
		t.Fatalf("the call after its grant was revoked: %d %s", code, body)
	}
}

// TestModelRelayFollowsItsLeaseKeepalive: a session lasts exactly as long as
// the lease it stands on — the keepalive's extension moves it, in memory and
// in its record.
func TestModelRelayFollowsItsLeaseKeepalive(t *testing.T) {
	r := newRelayRig(t, nil)
	ex := newTakeoverExecutor("edge-keepalive")
	r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	sl, _, id := r.leaseFor(ex, "run_keepalive")
	s, ok := activeModelRelay().reg.Session(id)
	if !ok {
		t.Fatal("no session")
	}
	if d := s.Deadline().Sub(sl.ExpiresAt()); d > time.Second || d < -time.Second {
		t.Fatalf("session deadline %v, lease %v", s.Deadline(), sl.ExpiresAt())
	}
	later := sl.ExpiresAt().Add(10 * time.Minute)
	sl.mu.Lock()
	sl.expiry = later
	sl.mu.Unlock()
	sl.extendModelRelaySessions()
	if !s.Deadline().Equal(later) {
		t.Fatalf("after the keepalive the session runs until %v, want %v", s.Deadline(), later)
	}
	row, err := r.db.GetProxySession(statedb.ProxySessionModel, id)
	if err != nil || !row.ExpiresAt.Equal(later.UTC().Truncate(time.Second)) && !row.ExpiresAt.Equal(later) {
		t.Fatalf("the record after the extension: %+v (%v), want until %v", row.ExpiresAt, err, later)
	}
}

// TestModelRelayLeavesAnUnprovenCredentialAsBefore: a credential kind nobody
// has proven through the relay against the real API reaches the sandbox as it
// did before the relay existed, and the run's journal and the trail say why.
func TestModelRelayLeavesAnUnprovenCredentialAsBefore(t *testing.T) {
	if relayProven(relayKindAPIKey) {
		t.Skip("API keys are proven through the relay; nothing is left unrelayed")
	}
	r := newRelayRig(t, nil)
	ex := newTakeoverExecutor("edge-apikey")
	key := fakeAnthropicToken("api03", "relaykey")
	r.grant("executor:"+ex.ID(), map[string]string{envAnthropicAPIKey: key})
	sl := acquireSecretLease(r.dir, r.dir, ex, "run_apikey", nil)
	stopKeepaliveForTest(sl)
	t.Cleanup(sl.Close)
	spec, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, ex, sl)
	if err != nil {
		t.Fatal(err)
	}
	out, id, err := applyModelRelay(spec, ex, r.dir, sl, relayDispatch{runID: "run_apikey", provider: "claudecode", run: true})
	if err != nil || id != "" {
		t.Fatalf("applyModelRelay = %q, %v; want the run left alone", id, err)
	}
	if v, _ := envValue(out.Env, envAnthropicAPIKey); v != key {
		t.Fatal("the API key no longer reaches the sandbox as before")
	}
	if _, ok := envValue(out.Env, envAnthropicBaseURL); ok {
		t.Fatal("an unrelayed run was pointed at the relay")
	}
	rows := r.auditRows(auditaction.ActionModelRelayNotRelayed)
	if len(rows) != 1 || !strings.Contains(rows[0].Payload, `"credential_kind":"api_key"`) {
		t.Fatalf("not_relayed rows %+v", rows)
	}
	if evs := relayJournal(t, r.dir); len(evs) == 0 || !strings.Contains(evs[0].Message, "Not relayed") {
		t.Fatalf("journal %+v", evs)
	}
}

// TestModelRelayRefusesWhenItCannotServe: a hub that turned the relay on
// never falls back to handing the sandbox the credential — a relay that is
// not running, or a listener that is not there, refuses the dispatch.
func TestModelRelayRefusesWhenItCannotServe(t *testing.T) {
	r := newRelayRig(t, nil)
	ex := newTakeoverExecutor("edge-down")
	r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	sl := acquireSecretLease(r.dir, r.dir, ex, "run_down", nil)
	stopKeepaliveForTest(sl)
	t.Cleanup(sl.Close)
	spec, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, ex, sl)
	if err != nil {
		t.Fatal(err)
	}

	svc := modelRelayCurrent.Swap(nil)
	_, _, err = applyModelRelay(spec, ex, r.dir, sl, relayDispatch{runID: "run_down", provider: "claudecode"})
	modelRelayCurrent.Store(svc)
	if _, ok := err.(*modelRelayUnavailableError); !ok {
		t.Fatalf("relay not running: err = %v", err)
	}

	r.cfg.Listener = config.ModelRelayListenerGitProxy
	prevGit := gitProxySingleton.Swap(nil)
	t.Cleanup(func() { gitProxySingleton.Store(prevGit) })
	svc.cfg.Listener = config.ModelRelayListenerGitProxy
	_, _, err = applyModelRelay(spec, ex, r.dir, sl, relayDispatch{runID: "run_down", provider: "claudecode"})
	svc.cfg.Listener = config.ModelRelayListenerDashboard
	if _, ok := err.(*modelRelayUnavailableError); !ok || !strings.Contains(err.Error(), "git proxy") {
		t.Fatalf("listener git_proxy with no git proxy: err = %v", err)
	}
}

// TestModelRelaySessionSurvivesAHubRestart: the process serving a run's
// session dies; a call the sandbox makes meanwhile is held, and served once the
// process that adopts the run has taken the lease over and restored the
// session with it — its credential re-derived from the grant, never read from
// a record — under the same token, with the spend it had reached.
func TestModelRelaySessionSurvivesAHubRestart(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := newRelayRig(t, nil)
	ex := newTakeoverExecutor("edge-restart")
	r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	sl, spec, id := r.leaseFor(ex, "run_restart")
	if code, _ := r.call(spec); code != http.StatusOK {
		t.Fatalf("before the restart: %d", code)
	}
	activeModelRelay().reg.Checkpoint()
	row, err := r.db.GetProxySession(statedb.ProxySessionModel, id)
	if err != nil || row.Holder != "hub_old" || row.LeaseID != sl.lease.ID || !row.Open() {
		t.Fatalf("the session's record: %+v, %v", row, err)
	}
	if strings.Contains(row.Scope+row.Counters, r.token) {
		t.Fatal("the record holds the credential")
	}
	restoredBefore := restoreCount(hubmetrics.RestoreKindModel, hubmetrics.RestoreRestored)

	liveLeases.removeIf(sl)
	r.crash("hub_new")
	held := make(chan int, 1)
	go func() {
		code, _ := r.call(spec)
		held <- code
	}()
	deadline := time.Now().Add(10 * time.Second)
	for heldSessionWaits() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if heldSessionWaits() == 0 {
		t.Fatal("the call made during the restart was not held for the adoption")
	}
	(&Server{WorkDir: r.dir}).takeOverRunLeases(r.dir, ex, "h-run_restart", []string{sl.lease.ID})
	if taken := registeredLease(sl.lease.ID); taken != nil {
		stopKeepaliveForTest(taken)
	}
	if code := <-held; code != http.StatusOK {
		t.Fatalf("the call held across the adoption: %d", code)
	}
	if !activeModelRelay().reg.Known(id) {
		t.Fatal("the new process does not serve the session")
	}
	if row, _ := r.db.GetProxySession(statedb.ProxySessionModel, id); row.Holder != "hub_new" || !row.Open() {
		t.Fatalf("the record after the restore: %+v", row)
	}
	calls := r.api.calls()
	if len(calls) != 2 || calls[1].Get("Authorization") != "Bearer "+r.token {
		t.Fatalf("after the restore the API saw %d calls, the last with %q", len(calls),
			calls[len(calls)-1].Get("Authorization"))
	}
	if got := restoreCount(hubmetrics.RestoreKindModel, hubmetrics.RestoreRestored); got != restoredBefore+1 {
		t.Errorf("model restores counted %v, want %v", got, restoredBefore+1)
	}
	if rows := r.auditRows(auditaction.ActionModelRelaySessionRestored); len(rows) != 1 || rows[0].EntityID != id {
		t.Fatalf("restored rows %+v", rows)
	}
	spend := activeModelRelay().spendOf(id)
	if spend.USD <= 0 || spend.Models["claude-sonnet-5-20260901"].Input != 2000 {
		t.Fatalf("the restored session's account %+v, want both calls", spend)
	}
}

// TestModelRelaySettlesTheRunsLedger: at a relayed run's end its project
// ledger is brought to the relay's count — the run's own rows are not charged
// a second time — and the difference is a journal row, an audit row and a
// metric.
func TestModelRelaySettlesTheRunsLedger(t *testing.T) {
	r := newRelayRig(t, nil)
	ex := newTakeoverExecutor("edge-settle")
	r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	r.srv.openSpendCursor(r.dir, "alice@corp.example")
	_, spec, id := r.leaseFor(ex, "run_settle")
	setRelayedRun(r.dir, id)
	for i := 0; i < 2; i++ {
		if code, _ := r.call(spec); code != http.StatusOK {
			t.Fatalf("call %d: %d", i, code)
		}
	}
	// What a claudecode run writes for its task: nothing it can count.
	pdb, err := statedb.Open(state.DBPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := pdb.AppendCost(statedb.CostEntry{Timestamp: time.Now().UTC(), TaskID: 1, TaskTitle: "work",
		Provider: "claudecode", Model: "claude-sonnet-5", Identity: "mallory@corp.example"}); err != nil {
		t.Fatal(err)
	}
	_ = pdb.Close()
	if _, err := r.srv.drainSpend(r.dir); err != nil {
		t.Fatal(err)
	}
	gapBefore := value((&Server{}).gatherMetrics(), series("cloop_model_relay_usage_gap_tokens_total",
		"direction", hubmetrics.ModelRelayUnreported))

	r.srv.settleModelRelayRun(r.dir)

	tokens, _ := r.spentToday("alice@corp.example")
	if tokens != 2*relayTokensPerCall {
		t.Fatalf("alice was charged %v tokens, want the relay's %d and nothing more", tokens, 2*relayTokensPerCall)
	}
	pdb, err = statedb.Open(state.DBPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pdb.Close() }()
	rows, err := pdb.ReadCosts()
	if err != nil {
		t.Fatal(err)
	}
	var total int
	var correction *statedb.CostEntry
	for i := range rows {
		total += rows[i].InputTokens + rows[i].OutputTokens
		if strings.HasPrefix(rows[i].TaskTitle, "Model relay:") {
			correction = &rows[i]
		}
	}
	if correction == nil || total != 2*relayTokensPerCall || correction.Identity != "alice@corp.example" ||
		correction.EstimatedUSD <= 0 {
		t.Fatalf("ledger total %d, correction %+v; want the relay's %d charged to alice", total, correction, 2*relayTokensPerCall)
	}
	if rows := r.auditRows(auditaction.ActionModelRelayUsageGap); len(rows) != 1 ||
		!strings.Contains(rows[0].Payload, `"relay_tokens":12600`) || !strings.Contains(rows[0].Payload, `"reported_tokens":0`) {
		t.Fatalf("usage_gap rows %+v", rows)
	}
	if got := value((&Server{}).gatherMetrics(), series("cloop_model_relay_usage_gap_tokens_total",
		"direction", hubmetrics.ModelRelayUnreported)); got != gapBefore+2*relayTokensPerCall {
		t.Errorf("unreported tokens counted %v, want %v", got, gapBefore+2*relayTokensPerCall)
	}
	if relayedRunSession(r.db, r.dir) != "" {
		t.Error("the run is still marked relayed after its settlement")
	}
	if activeModelRelay().reg.Known(id) {
		t.Error("the run's session outlived its settlement")
	}
	if evs := relayJournal(t, r.dir); len(evs) == 0 || !strings.Contains(evs[0].Message, "12,600 tokens") {
		t.Fatalf("journal %+v", evs)
	}
	// Settled once: a second end of the same run changes nothing.
	r.srv.settleModelRelayRun(r.dir)
	if rows := r.auditRows(auditaction.ActionModelRelayUsageGap); len(rows) != 1 {
		t.Fatalf("a second settlement wrote %d usage_gap rows", len(rows))
	}
}

// TestModelRelayEnvForTheAnthropicProvider: cloop's own Anthropic provider
// appends /messages to its base URL, so a relayed run of it is pointed at the
// relay's /v1, with the token where that provider reads its key.
func TestModelRelayEnvForTheAnthropicProvider(t *testing.T) {
	spec := withRelayEnv(executor.Spec{Env: []string{envAnthropicAPIKey + "=sk-held", "KEEP=1",
		redact.EnvKey + "=" + envAnthropicAPIKey}}, "anthropic", "https://hub.example.com/_anthropic", "cloop_relay_x.y", "abc")
	if v, _ := envValue(spec.Env, envAnthropicBaseURL); v != "https://hub.example.com/_anthropic/v1" {
		t.Errorf("base %q", v)
	}
	if v, _ := envValue(spec.Env, envAnthropicAPIKey); v != "cloop_relay_x.y" {
		t.Errorf("key %q", v)
	}
	if _, ok := envValue(spec.Env, envAnthropicAuth); ok {
		t.Error("the anthropic provider was handed a bearer it does not read")
	}
	if v, _ := envValue(spec.Env, "KEEP"); v != "1" {
		t.Error("an unrelated variable was dropped")
	}
	if strings.Contains(strings.Join(spec.Env, "\n"), "sk-held") {
		t.Error("the held credential survived")
	}
}

// TestModelRelayProjectModelsNarrowTheHubs: a project's own allowlist narrows
// the hub's and cannot widen it, and the API refuses a list that permits
// nothing the hub's does.
func TestModelRelayProjectModelsNarrowTheHubs(t *testing.T) {
	r := newRelayRig(t, nil)
	if err := setProjectRelayModels(r.dir, []string{"claude-haiku-*"}); err != nil {
		t.Fatal(err)
	}
	pol, err := activeModelRelay().policyFor(r.dir)
	if err != nil || len(pol.Models) != 1 || pol.Models[0] != "claude-haiku-*" {
		t.Fatalf("policy %+v, %v", pol, err)
	}
	writeHub := func(relay string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(r.dir, ".cloop", "config.yaml"), []byte("ui:\n  external_url: "+
			"https://hub.example.com\nexecutors:\n  model_relay:\n"+relay), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeHub("    enabled: true\n    models: [\"claude-sonnet-*\"]\n")
	if _, err := activeModelRelay().policyFor(r.dir); err == nil {
		t.Fatal("a project list sharing nothing with the hub's was honoured")
	}
	if err := setProjectRelayModels(r.dir, nil); err != nil {
		t.Fatal(err)
	}
	pol, err = activeModelRelay().policyFor(r.dir)
	if err != nil || len(pol.Models) != 1 || pol.Models[0] != "claude-sonnet-*" {
		t.Fatalf("with the project's list cleared: %+v, %v", pol, err)
	}

	// Edited into a section that does not load, the hub's list refuses the
	// run; it is never read as the every-model default Load could reset it to.
	writeHub("    enabled: true\n    models: [\"claude-[\"]\n")
	if pol, err := activeModelRelay().policyFor(r.dir); err == nil || !strings.Contains(err.Error(), "does not load as written") {
		t.Fatalf("a broken section was read: %+v, %v", pol, err)
	}
	// Switched off in the file, the running relay keeps the section it
	// started with until the restart that stops it — not the defaults the
	// file now leaves.
	activeModelRelay().cfg.Models = []string{"claude-opus-*"}
	writeHub("    enabled: false\n")
	pol, err = activeModelRelay().policyFor(r.dir)
	if err != nil || len(pol.Models) != 1 || pol.Models[0] != "claude-opus-*" {
		t.Fatalf("with the relay switched off in the file: %+v, %v", pol, err)
	}
}

// TestModelRelayBrokenSectionRefusesRatherThanDelivers: an enabled section
// Load could not take as written starts no relay, and a run it would relay is
// refused — not dispatched with its Claude credential as if the relay were off.
func TestModelRelayBrokenSectionRefusesRatherThanDelivers(t *testing.T) {
	r := newRelayRig(t, nil)
	ex := newTakeoverExecutor("edge-broken")
	r.grant("executor:"+ex.ID(), map[string]string{envClaudeOAuthToken: r.token})
	sl := acquireSecretLease(r.dir, r.dir, ex, "run_broken", nil)
	stopKeepaliveForTest(sl)
	t.Cleanup(sl.Close)
	spec, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, ex, sl)
	if err != nil {
		t.Fatal(err)
	}

	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, ".cloop", "config.yaml"),
		[]byte("executors:\n  model_relay:\n    enabled: true\n    listener: dashbord\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(other)
	if err != nil {
		t.Fatal(err)
	}
	running, failure := modelRelayCurrent.Swap(nil), modelRelayFailure.Load()
	t.Cleanup(func() {
		modelRelayCurrent.Store(running)
		modelRelayFailure.Store(failure)
	})
	bringUpModelRelay(cfg, other)
	if activeModelRelay() != nil {
		t.Fatal("a section that does not load started a relay")
	}
	_, _, err = applyModelRelay(spec, ex, r.dir, sl, relayDispatch{runID: "run_broken", provider: "claudecode"})
	var unavailable *modelRelayUnavailableError
	if !errors.As(err, &unavailable) || !strings.Contains(err.Error(), "does not load as written") ||
		!strings.Contains(err.Error(), "dashbord") {
		t.Fatalf("a run under a broken relay section: err = %v", err)
	}
}
