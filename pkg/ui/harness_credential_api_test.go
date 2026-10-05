package ui

// The Claude credential panel's API over HTTP (Task 20379): who may grant
// what, that every grant is audited, that a refused run starts nothing and a
// granted one starts with the token — and that a pasted token appears in no
// response, no log line, no audit row and nowhere in the database but the
// sealed secret.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// lockedBuffer is a bytes.Buffer the hub's logger and a test may share.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// harnessHub is an OIDC hub whose own project runs on an enrolled device, with
// five people at the four roles and a viewer.
type harnessHub struct {
	srv     *Server
	base    string
	clients map[string]*http.Client
	ex      *harnessExec
	logs    *lockedBuffer
	// bodies collects every response body, for the non-disclosure sweep.
	mu     sync.Mutex
	bodies []string
}

func newHarnessHub(t *testing.T) *harnessHub {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "harness-credential-api-passphrase")
	// A registry of the test's own, so the hub lists exactly its project.
	t.Setenv("HOME", t.TempDir())

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "watchers", Role: authz.RoleViewer},
		{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
		{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
		{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	srv.RPS, srv.Burst = 1000, 1000
	logs := &lockedBuffer{}
	srv.Log = logger.NewWithWriter(logs, true)
	statedbtest.SeedDir(t, srv.WorkDir)
	if _, err := state.Init(srv.WorkDir, "harness credential", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	ex := newHarnessExec("harness-api-device", executor.KindRemoteAgent, executor.IsolationRemote)
	registerStub(t, ex)
	if err := executor.Bind(srv.WorkDir, ex.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(srv.WorkDir) })

	loginAs := func(sub, email string, groups []string) *http.Client {
		idp.sub, idp.email, idp.groups = sub, email, groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	return &harnessHub{
		srv: srv, base: ts.URL, ex: ex, logs: logs,
		clients: map[string]*http.Client{
			"wanda": loginAs("sub-wanda", "wanda@corp.example", []string{"watchers"}),
			"alice": loginAs("sub-alice", "alice@corp.example", []string{"engineers"}),
			"bob":   loginAs("sub-bob", "bob@corp.example", []string{"engineers"}),
			"lead":  loginAs("sub-lead", "lead@corp.example", []string{"leads"}),
			"root":  loginAs("sub-root", "root@corp.example", []string{"owners"}),
		},
	}
}

func (h *harnessHub) do(t *testing.T, who, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(blob)
	}
	req, err := http.NewRequest(method, h.base+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.clients[who].Do(req)
	if err != nil {
		t.Fatalf("%s %s %s: %v", who, method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	h.mu.Lock()
	h.bodies = append(h.bodies, string(raw))
	h.mu.Unlock()
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

const harnessPath = "/api/projects/0/harness-credential"

// seedSharedEnv mints an organisation-owned env secret through the broker.
func (h *harnessHub) seedSharedEnv(t *testing.T, name, key, value string) secretbroker.Secret {
	t.Helper()
	db, err := statedb.Open(state.DBPath(h.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.AsControlPlane()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{key: value})
	sec, err := b.Mint(t.Context(), secretbroker.MintRequest{Name: name, Kind: secretbroker.KindEnv, Payload: payload, Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

// captureStderr runs fn with os.Stderr redirected and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() {
		os.Stderr = prev
	}()
	fn()
	os.Stderr = prev
	_ = w.Close()
	return <-done
}

func TestHarnessCredentialAPIGrantsAPastedTokenAndNeverRepeatsIt(t *testing.T) {
	h := newHarnessHub(t)
	token := fakeAnthropicToken("oat01", "pastedtoken")

	code, view := h.do(t, "alice", "GET", harnessPath, nil)
	if code != http.StatusOK || view["applies"] != true || view["state"] != "missing" || view["can_paste"] != true || view["personal"] != true {
		t.Fatalf("alice's first look = %d %v", code, view)
	}
	if ex, _ := view["executor"].(map[string]any); ex["id"] != h.ex.ID() || ex["isolates"] != true {
		t.Errorf("view names executor %v, want %s isolating", ex, h.ex.ID())
	}

	var granted map[string]any
	stderr := captureStderr(t, func() {
		var c int
		c, granted = h.do(t, "alice", "POST", harnessPath, map[string]any{"token": "  " + token + "\n"})
		if c != http.StatusOK {
			t.Fatalf("paste = %d %v", c, granted)
		}
		// Every other reader of the panel, while the stderr capture runs.
		h.do(t, "alice", "GET", harnessPath, nil)
		h.do(t, "bob", "GET", harnessPath, nil)
		h.do(t, "root", "GET", harnessPath, nil)
		h.do(t, "alice", "GET", "/api/secrets", nil)
		h.do(t, "root", "GET", "/api/grants", nil)
	})
	g, _ := granted["granted"].(map[string]any)
	if g["minted"] != true || g["personal"] != true || !strings.HasPrefix(g["secret_name"].(string), "claude-oauth-") {
		t.Fatalf("granted = %v", g)
	}
	if keys, _ := g["env_keys"].([]any); len(keys) != 1 || keys[0] != envClaudeOAuthToken {
		t.Errorf("env_keys = %v, want only %s", g["env_keys"], envClaudeOAuthToken)
	}
	exp, err := time.Parse(time.RFC3339, g["expires_at"].(string))
	if err != nil || exp.Before(time.Now().Add(29*24*time.Hour)) || exp.After(time.Now().Add(31*24*time.Hour)) {
		t.Errorf("expires_at = %v, want about 30 days out", g["expires_at"])
	}
	if granted["state"] != "ok" {
		t.Errorf("the response's own view still says %v", granted["state"])
	}
	name := g["secret_name"].(string)

	// Alice's sandbox now signs in with it; bob's would not, and bob is not
	// even told what alice keeps.
	_, mine := h.do(t, "alice", "GET", harnessPath, nil)
	if sb, _ := mine["satisfied_by"].(map[string]any); mine["state"] != "ok" || sb["secret_name"] != name || sb["owner"] != "alice@corp.example" {
		t.Errorf("alice after granting = %v", mine)
	}
	code, bobs := h.do(t, "bob", "GET", harnessPath, nil)
	if code != http.StatusOK || bobs["state"] != "missing" || bobs["satisfied_by"] != nil {
		t.Errorf("bob after alice granted her own token = %d %v", code, bobs)
	}
	if blob, _ := json.Marshal(bobs); strings.Contains(string(blob), name) {
		t.Errorf("bob's view names alice's secret: %s", blob)
	}

	// Audited, on the control plane's chain, naming who did it.
	db, err := statedb.Open(state.DBPath(h.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	all, _, err := db.ListAuditEvents(statedb.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var mintRow, grantRow bool
	for _, row := range all {
		switch row.EventType {
		// The payload's secret_name is scrubbed by the audit store's key-based
		// redaction (statedb/audit_redact.go), so the rows are identified by
		// actor, kind and subject.
		case string(secretbroker.ActionMint):
			mintRow = mintRow || (strings.Contains(row.Actor, "alice") && strings.Contains(row.Payload, `"kind":"env"`))
		case string(secretbroker.ActionGrant):
			grantRow = grantRow || (strings.Contains(row.Actor, "alice") && strings.Contains(row.Payload, "project:"+h.srv.WorkDir))
		}
	}
	if !mintRow || !grantRow {
		t.Errorf("audit rows: mint %v grant %v — every grant must be audited with its actor and subject", mintRow, grantRow)
	}

	// The token itself: in no response, no log line, no audit row, and
	// nowhere in the database files but sealed.
	h.mu.Lock()
	bodies := strings.Join(h.bodies, "\n")
	h.mu.Unlock()
	for where, text := range map[string]string{
		"a response": bodies, "the hub's log": h.logs.String(), "stderr": stderr,
	} {
		if strings.Contains(text, token) {
			t.Errorf("the pasted token appears in %s", where)
		}
	}
	for _, row := range all {
		if strings.Contains(row.Payload, token) || strings.Contains(row.Actor, token) {
			t.Errorf("the pasted token appears in audit row %s", row.EventType)
		}
	}
	matches, _ := filepath.Glob(state.DBPath(h.srv.WorkDir) + "*")
	for _, p := range matches {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(token)) {
			t.Errorf("the pasted token is stored in plaintext in %s", filepath.Base(p))
		}
	}
}

func TestHarnessCredentialAPIGrantsOnlyWithAuthority(t *testing.T) {
	h := newHarnessHub(t)
	shared := h.seedSharedEnv(t, "team-claude", envClaudeOAuthToken, fakeAnthropicToken("oat01", "teamshared"))
	code, mine := h.do(t, "alice", "POST", harnessPath, map[string]any{"token": fakeAnthropicToken("oat01", "aliceowns")})
	if code != http.StatusOK {
		t.Fatalf("alice's paste = %d %v", code, mine)
	}
	aliceSecret := mine["granted"].(map[string]any)["secret_name"].(string)

	// A viewer reads the card, and may grant nothing.
	if code, _ := h.do(t, "wanda", "GET", harnessPath, nil); code != http.StatusOK {
		t.Errorf("viewer GET = %d, want 200", code)
	}
	if code, body := h.do(t, "wanda", "POST", harnessPath, map[string]any{"token": fakeAnthropicToken("oat01", "wandatry")}); code != http.StatusForbidden {
		t.Errorf("viewer paste = %d %v, want 403", code, body)
	}
	// An operator may not hand out the organisation's credential…
	if code, body := h.do(t, "bob", "POST", harnessPath, map[string]any{"secret": shared.Name}); code != http.StatusForbidden {
		t.Errorf("operator granting a shared secret = %d %v, want 403", code, body)
	}
	// …nor somebody else's, which they are told does not exist…
	if code, body := h.do(t, "bob", "POST", harnessPath, map[string]any{"secret": aliceSecret}); code != http.StatusNotFound {
		t.Errorf("operator granting alice's secret = %d %v, want 404", code, body)
	}
	// …and an admin, who may see alice's secret, still may not spend it.
	if code, body := h.do(t, "root", "POST", harnessPath, map[string]any{"secret": aliceSecret}); code != http.StatusForbidden {
		t.Errorf("admin granting alice's secret = %d %v, want 403", code, body)
	}
	// Bob's candidates are his own; a maintainer's include the shared one.
	_, bobs := h.do(t, "bob", "GET", harnessPath, nil)
	if c, _ := bobs["candidates"].([]any); len(c) != 0 {
		t.Errorf("bob is offered %v", c)
	}
	_, leads := h.do(t, "lead", "GET", harnessPath, nil)
	if c, _ := leads["candidates"].([]any); len(c) != 1 || c[0].(map[string]any)["name"] != "team-claude" {
		t.Errorf("the maintainer is offered %v, want the shared secret alone", leads["candidates"])
	}
	if code, body := h.do(t, "lead", "POST", harnessPath, map[string]any{"secret": "team-claude", "ttl_minutes": 60}); code != http.StatusOK {
		t.Fatalf("maintainer granting the shared secret = %d %v", code, body)
	}
	_, bobs = h.do(t, "bob", "GET", harnessPath, nil)
	if sb, _ := bobs["satisfied_by"].(map[string]any); bobs["state"] != "ok" || sb["secret_name"] != "team-claude" {
		t.Errorf("bob once the shared credential is granted = %v", bobs)
	}

	// Malformed requests, all refused before anything is stored.
	for _, body := range []map[string]any{
		{},
		{"secret": "team-claude", "token": fakeAnthropicToken("oat01", "both")},
		{"secret": "team-claude", "ttl_minutes": 999999999},
		{"secret": "team-claude", "env_keys": []string{"GITHUB_TOKEN"}},
	} {
		if code, out := h.do(t, "lead", "POST", harnessPath, body); code != http.StatusBadRequest {
			t.Errorf("POST %v = %d %v, want 400", body, code, out)
		}
	}
}

func TestHarnessCredentialAPIRefusesBadPastesWithoutRepeatingThem(t *testing.T) {
	h := newHarnessHub(t)
	refresh := fakeAnthropicToken("ort01", "refreshtoken")
	for name, paste := range map[string]string{
		"prose":          "my token is " + fakeAnthropicToken("oat01", "inprose"),
		"refresh token":  refresh,
		"two lines":      fakeAnthropicToken("oat01", "lineone") + "\n" + fakeAnthropicToken("oat01", "linetwo"),
		"github token":   "ghp_" + strings.Repeat("A1b2", 9),
		"far too long":   fakeAnthropicToken("oat01", "long") + strings.Repeat("x", 2000),
		"almost a token": "sk-" + "ant-oat01-short",
	} {
		code, out := h.do(t, "alice", "POST", harnessPath, map[string]any{"token": paste})
		if code != http.StatusBadRequest {
			t.Errorf("%s: %d %v, want 400", name, code, out)
			continue
		}
		msg, _ := out["error"].(map[string]any)
		text, _ := msg["message"].(string)
		if text == "" || strings.Contains(text, paste) || (len(paste) > 20 && strings.Contains(text, paste[13:])) {
			t.Errorf("%s: the refusal repeats the paste or says nothing: %q", name, text)
		}
		if name == "refresh token" && !strings.Contains(text, "setup-token") {
			t.Errorf("a refresh token's refusal does not say how to get the right one: %q", text)
		}
	}
	// An anthropic-provider project needs an API key, and says so.
	setProvider(t, h.srv.WorkDir, "anthropic")
	code, out := h.do(t, "alice", "POST", harnessPath, map[string]any{"token": fakeAnthropicToken("oat01", "wrongkind")})
	if msg, _ := out["error"].(map[string]any); code != http.StatusBadRequest || !strings.Contains(msg["message"].(string), envAnthropicAPIKey) {
		t.Errorf("an OAuth token for an anthropic project = %d %v", code, out)
	}
	if code, out := h.do(t, "alice", "POST", harnessPath, map[string]any{"token": fakeAnthropicToken("api03", "rightkind")}); code != http.StatusOK {
		t.Errorf("an API key for an anthropic project = %d %v", code, out)
	}
	if rows := h.logs.String(); strings.Contains(rows, refresh) {
		t.Error("a refused paste reached the log")
	}
}

// The Run button end to end: refused with the code the dialog opens on and no
// workload started, then — once the credential is granted from the panel —
// started with the token in the sandbox's environment.
func TestHarnessCredentialRunRefusedThenStartedOnceGranted(t *testing.T) {
	h := newHarnessHub(t)

	code, body := h.do(t, "alice", "POST", "/api/projects/0/run", map[string]any{})
	if code != http.StatusConflict || body["code"] != codeHarnessCredentialMissing || body["executor_id"] != h.ex.ID() {
		t.Fatalf("run without a credential = %d %v", code, body)
	}
	if body["remediation"] == "" || body["needed"] == nil {
		t.Errorf("the refusal carries no remedy or need: %v", body)
	}
	if n := len(h.ex.started()); n != 0 {
		t.Fatalf("a refused run started %d workload(s)", n)
	}
	// The run bar's own route, the same answer.
	if code, body := h.do(t, "alice", "POST", "/api/run?project_idx=0", map[string]any{}); code != http.StatusConflict || body["code"] != codeHarnessCredentialMissing {
		t.Fatalf("/api/run without a credential = %d %v", code, body)
	}

	token := fakeAnthropicToken("oat01", "runtoken")
	if code, out := h.do(t, "alice", "POST", harnessPath, map[string]any{"token": token}); code != http.StatusOK {
		t.Fatalf("paste = %d %v", code, out)
	}
	// Bob is still refused: alice's token is hers.
	if code, body := h.do(t, "bob", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusConflict {
		t.Fatalf("bob's run on alice's personal grant = %d %v", code, body)
	}
	if code, body := h.do(t, "alice", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
		t.Fatalf("alice's run once granted = %d %v", code, body)
	}
	specs := h.ex.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads, want 1", len(specs))
	}
	if !strings.Contains(strings.Join(specs[0].Env, "\n"), envClaudeOAuthToken+"="+token) {
		t.Error("the started run's environment lacks the granted token")
	}
	// Its automatic resume would act for alice, who started it — not for the
	// project's owner, and not for nobody — so it resumes on her credential.
	if who := h.srv.harnessWhoForResume(h.srv.WorkDir); !who.personal || who.identity != "alice@corp.example" {
		t.Errorf("a resume of alice's run acts for %+v", who)
	}
	// Let the run settle before the project directory is removed.
	deadline := time.Now().Add(10 * time.Second)
	for h.srv.projectExecuting(h.srv.WorkDir) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
}
