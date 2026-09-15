package ui

// Integration tests for CI/CD pipeline federation (Task 20278).
//
// These drive the whole circuit through the hub's real HTTP stack: a fake
// forge signs an OIDC token, a pipeline exchanges it at /api/ci/token, and the
// session that comes back relays a Messages API call through
// /api/ci/anthropic to a fake Anthropic. Nothing is stubbed between those
// points — the verifier fetches the fake forge's key set over HTTP, the relay
// dials the fake upstream, and both run under the same middleware chain a real
// request does.
//
// Loopback is what makes that possible without a certificate: pkg/ciauth
// accepts a plaintext issuer only for a loopback host, and pkg/claudeproxy the
// same for its upstream, so httptest servers work end to end.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// ciForge is a stand-in for token.actions.githubusercontent.com.
type ciForge struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newCIForge(t *testing.T) *ciForge {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &ciForge{t: t, key: k}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": ciB64(f.key.N.Bytes()),
			"e": ciB64(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func ciB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// token mints a signed assertion. Overrides win over the defaults; a nil value
// deletes the claim.
func (f *ciForge) token(overrides map[string]any) string {
	f.t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":              f.srv.URL,
		"aud":              "cloop",
		"sub":              "repo:acme/tool:ref:refs/heads/main",
		"jti":              fmt.Sprintf("jti-%d", time.Now().UnixNano()),
		"iat":              now.Unix(),
		"exp":              now.Add(10 * time.Minute).Unix(),
		"repository":       "acme/tool",
		"repository_owner": "acme",
		"ref":              "refs/heads/main",
		"workflow":         "release",
		"workflow_ref":     "acme/tool/.github/workflows/release.yml@refs/heads/main",
		"actor":            "dana",
		"event_name":       "push",
		"run_id":           "42",
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	cb, _ := json.Marshal(claims)
	signing := ciB64(hb) + "." + ciB64(cb)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	return signing + "." + ciB64(sig)
}

// ciUpstream is a stand-in for api.anthropic.com.
type ciUpstream struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	handler  http.HandlerFunc
}

func newCIUpstream(t *testing.T) *ciUpstream {
	t.Helper()
	u := &ciUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.requests = append(u.requests, r.Clone(r.Context()))
		u.bodies = append(u.bodies, body)
		h := u.handler
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","content":[{"type":"text","text":"ok"}],` +
			`"usage":{"input_tokens":5,"output_tokens":9}}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *ciUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}

func (u *ciUpstream) last() (*http.Request, []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.requests) == 0 {
		return nil, nil
	}
	return u.requests[len(u.requests)-1], u.bodies[len(u.bodies)-1]
}

// ciHarness is a hub with CI federation configured, plus the fake forge and
// upstream it talks to.
type ciHarness struct {
	t      *testing.T
	dir    string
	srv    *Server
	http   *httptest.Server
	forge  *ciForge
	up     *ciUpstream
	client *http.Client
}

const ciHubKey = "sk-ant-hub-key-never-leaves-the-hub"

func newCIHarness(t *testing.T, mutate ...func(*config.Config)) *ciHarness {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	h := &ciHarness{t: t, dir: dir, forge: newCIForge(t), up: newCIUpstream(t)}

	cfg := config.Default()
	cfg.Anthropic.APIKey = ciHubKey
	cfg.UI.CI = config.CIConfig{
		Enabled:         true,
		Issuer:          h.forge.srv.URL,
		Audience:        "cloop",
		UpstreamBaseURL: h.up.srv.URL,
		DefaultModels:   []string{"claude-sonnet-*"},
	}
	for _, m := range mutate {
		m(cfg)
	}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	h.srv = New(dir, 0, "")
	h.http = httptest.NewServer(h.srv.Handler())
	t.Cleanup(func() {
		h.http.Close()
		h.srv.closeCI()
	})
	h.client = h.http.Client()
	return h
}

// addRule stores an allowlist entry the way the API would.
func (h *ciHarness) addRule(t *testing.T, body map[string]any) string {
	t.Helper()
	resp := h.post(t, "/api/ci/rules", body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("add rule: %d %s", resp.StatusCode, b)
	}
	var out struct {
		ID string `json:"id"`
	}
	h.decode(t, resp, &out)
	return out.ID
}

func (h *ciHarness) do(t *testing.T, method, path string, body any,
	mutate ...func(*http.Request)) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, h.http.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, m := range mutate {
		m(req)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *ciHarness) post(t *testing.T, path string, body any) *http.Response {
	return h.do(t, http.MethodPost, path, body)
}

func (h *ciHarness) decode(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

// exchange federates a token and returns the decoded response.
func (h *ciHarness) exchange(t *testing.T, token string) (*http.Response, ciExchangeResponse) {
	t.Helper()
	resp := h.post(t, "/api/ci/token", map[string]string{"token": token})
	var out ciExchangeResponse
	if resp.StatusCode == http.StatusOK {
		h.decode(t, resp, &out)
	}
	return resp, out
}

// relay makes a Messages API call the way an SDK inside a runner would, and
// drains the response before returning.
//
// The drain is load-bearing, not tidiness. An HTTP client returns as soon as
// the response *headers* arrive, while the hub is still streaming the body —
// and the relay's token counters are only added once that stream completes. A
// test that read Usage() off the returned response would see the request
// counted and the tokens not, intermittently, for a reason that has nothing to
// do with the code under test.
func (h *ciHarness) relay(t *testing.T, sessionToken, body string) *http.Response {
	t.Helper()
	resp := h.do(t, http.MethodPost, "/api/ci/anthropic/v1/messages", nil, func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sessionToken)
	})
	drained, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read relay body: %v", err)
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(drained)))
	return resp
}

const ciRelayBody = `{"model":"claude-sonnet-4-6","max_tokens":64,` +
	`"messages":[{"role":"user","content":"hi"}]}`

var ciBasicRule = map[string]any{
	"name": "acme tool", "repository": "acme/tool", "enabled": true,
}

// ---------------------------------------------------------------------------
// the circuit
// ---------------------------------------------------------------------------

// TestCI_FullCircuit is the end-to-end proof: a forge-signed token becomes a
// session, and that session relays a real HTTP call to the upstream carrying
// the hub's credential and not the pipeline's.
func TestCI_FullCircuit(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)

	resp, got := h.exchange(t, h.forge.token(nil))
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("exchange: %d %s", resp.StatusCode, b)
	}
	if !strings.HasPrefix(got.Token, "cloop_ci_") {
		t.Errorf("session token %q does not carry the scanner-visible prefix", got.Token)
	}
	if !strings.HasSuffix(got.BaseURL, ciMountPath) {
		t.Errorf("base_url = %q, want it to end in %q", got.BaseURL, ciMountPath)
	}
	if got.Env["ANTHROPIC_BASE_URL"] != got.BaseURL || got.Env["ANTHROPIC_AUTH_TOKEN"] != got.Token {
		t.Errorf("env block disagrees with the response: %+v", got.Env)
	}
	if got.Rule != "acme tool" || got.Pipeline == "" {
		t.Errorf("provenance missing: rule=%q pipeline=%q", got.Rule, got.Pipeline)
	}
	if len(got.Models) == 0 {
		t.Error("no model allowlist was reported")
	}

	relay := h.relay(t, got.Token, ciRelayBody)
	if relay.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(relay.Body)
		t.Fatalf("relay: %d %s", relay.StatusCode, b)
	}
	body, _ := io.ReadAll(relay.Body)
	if !strings.Contains(string(body), `"msg_1"`) {
		t.Errorf("upstream response did not reach the pipeline: %s", body)
	}

	req, upBody := h.up.last()
	if req == nil {
		t.Fatal("the upstream saw no request")
	}
	if req.URL.Path != "/v1/messages" {
		t.Errorf("upstream path = %q", req.URL.Path)
	}
	// The property the whole feature exists for.
	if key := req.Header.Get("X-Api-Key"); key != ciHubKey {
		t.Errorf("upstream X-Api-Key = %q, want the hub's credential", key)
	}
	blob := fmt.Sprintf("%v %s", req.Header, upBody)
	if strings.Contains(blob, got.Token) {
		t.Fatal("the pipeline's session token was forwarded to the upstream")
	}
}

// TestCI_TokenIsSingleUse pins the replay refusal at the hub boundary.
func TestCI_TokenIsSingleUse(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)
	tok := h.forge.token(nil)

	if resp, _ := h.exchange(t, tok); resp.StatusCode != http.StatusOK {
		t.Fatalf("first exchange: %d", resp.StatusCode)
	}
	resp, _ := h.exchange(t, tok)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("replayed token got %d, want 401", resp.StatusCode)
	}
}

func TestCI_RefusesPipelinesNoRuleAdmits(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)

	// A genuine, correctly signed token — from a repository nobody listed.
	// This is the case that makes verification alone insufficient: anyone can
	// obtain a valid token naming their own repository.
	resp, _ := h.exchange(t, h.forge.token(map[string]any{
		"repository": "evil/tool",
		"sub":        "repo:evil/tool:ref:refs/heads/main",
	}))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	// The refusal must not name the allowlist: the caller is unauthenticated.
	if strings.Contains(string(b), "acme") {
		t.Errorf("the refusal disclosed allowlist contents: %s", b)
	}
}

func TestCI_RefusesTokensItCannotVerify(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)

	cases := map[string]string{
		"garbage":        "not-a-token",
		"empty":          "",
		"wrong audience": h.forge.token(map[string]any{"aud": "someone-else"}),
		"expired":        h.forge.token(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
		"no expiry":      h.forge.token(map[string]any{"exp": nil}),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			resp, _ := h.exchange(t, tok)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("the hub accepted a token it must refuse")
			}
		})
	}
}

func TestCI_DisabledHubRefusesBothEndpoints(t *testing.T) {
	h := newCIHarness(t, func(c *config.Config) { c.UI.CI.Enabled = false })

	resp, _ := h.exchange(t, h.forge.token(nil))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("exchange on a disabled hub = %d, want 503", resp.StatusCode)
	}
	relay := h.relay(t, "cloop_ci_aaaa.bbbb", ciRelayBody)
	if relay.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("relay on a disabled hub = %d, want 503", relay.StatusCode)
	}
	if h.up.count() != 0 {
		t.Error("a disabled hub reached the upstream")
	}
}

// TestCI_MisconfiguredHubRefusesWithoutLeakingWhy covers the case an operator
// will actually hit: federation on, no Anthropic credential to relay with.
func TestCI_MisconfiguredHubRefusesWithoutLeakingWhy(t *testing.T) {
	h := newCIHarness(t, func(c *config.Config) {
		c.Anthropic.APIKey = ""
		c.UI.CI.UpstreamAuthToken = ""
	})
	h.addRuleDirect(t)

	resp, _ := h.exchange(t, h.forge.token(nil))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(strings.ToLower(string(b)), "anthropic") {
		t.Errorf("the refusal told an unauthenticated caller about the hub's configuration: %s", b)
	}
	// The operator, however, is told exactly what is wrong.
	view := h.srv.ciSettings(httptest.NewRequest("GET", "/api/ci/config", nil))
	if !strings.Contains(view.Error, "Anthropic credential") {
		t.Errorf("the settings view does not name the problem: %q", view.Error)
	}
	if view.UpstreamReady {
		t.Error("UpstreamReady is true with no credential configured")
	}
}

// addRuleDirect writes a rule through statedb, for harnesses whose HTTP rule
// API is not the thing under test.
func (h *ciHarness) addRuleDirect(t *testing.T) string {
	t.Helper()
	return h.addRule(t, ciBasicRule)
}

// ---------------------------------------------------------------------------
// policy enforcement on the relay
// ---------------------------------------------------------------------------

func TestCI_RelayEnforcesTheRulesPolicy(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, map[string]any{
		"name": "narrow", "repository": "acme/tool", "enabled": true,
		"models": []string{"claude-haiku-4-5"}, "max_requests": 2,
	})
	_, sess := h.exchange(t, h.forge.token(nil))
	if sess.Token == "" {
		t.Fatal("no session was minted")
	}

	t.Run("a model outside the rule is refused", func(t *testing.T) {
		resp := h.relay(t, sess.Token, ciRelayBody) // claude-sonnet-4-6
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		if h.up.count() != 0 {
			t.Error("a refused model reached the upstream")
		}
	})

	t.Run("the permitted model is relayed and budgeted", func(t *testing.T) {
		ok := `{"model":"claude-haiku-4-5","max_tokens":16,"messages":[]}`
		for i := 0; i < 2; i++ {
			if resp := h.relay(t, sess.Token, ok); resp.StatusCode != http.StatusOK {
				t.Fatalf("request %d: %d", i, resp.StatusCode)
			}
		}
		if resp := h.relay(t, sess.Token, ok); resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 once the budget is spent", resp.StatusCode)
		}
		if h.up.count() != 2 {
			t.Errorf("the upstream saw %d requests, want the budgeted 2", h.up.count())
		}
	})
}

func TestCI_RelayRefusesTheRestOfTheAPI(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)
	_, sess := h.exchange(t, h.forge.token(nil))

	for _, path := range []string{"/v1/files", "/v1/organizations/users", "/v1/messages/batches"} {
		resp := h.do(t, http.MethodPost, ciMountPath+path, nil, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+sess.Token)
		})
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s was relayed", path)
		}
	}
	if h.up.count() != 0 {
		t.Errorf("the upstream saw %d requests for endpoints outside the surface", h.up.count())
	}
}

// ---------------------------------------------------------------------------
// the auth carve-out
// ---------------------------------------------------------------------------

// TestCI_EndpointsBypassHubAuthButNothingElseDoes is the security property the
// carve-out has to hold: with a static token configured, a pipeline reaches
// the two CI endpoints without it, and reaches nothing else.
func TestCI_EndpointsBypassHubAuthButNothingElseDoes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	forge := newCIForge(t)
	up := newCIUpstream(t)
	cfg := config.Default()
	cfg.Anthropic.APIKey = ciHubKey
	cfg.UI.CI = config.CIConfig{Enabled: true, Issuer: forge.srv.URL, Audience: "cloop",
		UpstreamBaseURL: up.srv.URL, DefaultModels: []string{"claude-sonnet-*"}}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	srv := New(dir, 0, "the-hub-static-token")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	defer srv.closeCI()

	h := &ciHarness{t: t, dir: dir, srv: srv, http: ts, forge: forge, up: up, client: ts.Client()}

	// A rule has to exist, and writing one requires the static token — which
	// is the point: configuring the allowlist is privileged, using it is not.
	resp := h.do(t, http.MethodPost, "/api/ci/rules", ciBasicRule)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rule write without the static token = %d, want 401", resp.StatusCode)
	}
	resp = h.do(t, http.MethodPost, "/api/ci/rules", ciBasicRule, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer the-hub-static-token")
	})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("rule write with the static token = %d %s", resp.StatusCode, b)
	}

	// The exchange, with no hub credential at all.
	exResp, sess := h.exchange(t, forge.token(nil))
	if exResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(exResp.Body)
		t.Fatalf("exchange without the static token = %d %s", exResp.StatusCode, b)
	}
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusOK {
		t.Fatalf("relay without the static token = %d", relay.StatusCode)
	}

	// And nothing else is reachable. /api/ci/config sits next to the two
	// public routes and shares their prefix, so it is the one most likely to
	// be swept into the carve-out by a sloppy prefix match.
	for _, path := range []string{"/api/ci/config", "/api/ci/rules", "/api/ci/sessions",
		"/api/ci/exchanges", "/api/state", "/api/projects"} {
		resp := h.do(t, http.MethodGet, path, nil)
		// 401 is the answer; 429 is also acceptable and is the hub working as
		// designed — repeated credential-less requests from one IP trip the
		// auth lockout, and by the tail of this loop they have. What must
		// never appear is a 2xx.
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("GET %s without a credential = %d, want 401 (or 429 once locked out)",
				path, resp.StatusCode)
		}
	}
	// A GET on the exchange path is not the exchange and must stay gated.
	if resp := h.do(t, http.MethodGet, "/api/ci/token", nil); resp.StatusCode == http.StatusOK {
		t.Error("GET /api/ci/token was served without a credential")
	}
}

// ---------------------------------------------------------------------------
// rule administration
// ---------------------------------------------------------------------------

func TestCI_RuleValidationIsEnforcedAtTheAPI(t *testing.T) {
	h := newCIHarness(t)
	cases := map[string]map[string]any{
		"no name":         {"repository": "acme/tool"},
		"no repository":   {"name": "n", "ref": "refs/heads/main"},
		"wildcard owner":  {"name": "n", "repository": "*/tool"},
		"bad condition":   {"name": "n", "condition": "assertion.repository =="},
		"macro condition": {"name": "n", "condition": `assertion.x.all(i, i == 1)`},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp := h.post(t, "/api/ci/rules", body)
			if resp.StatusCode != http.StatusBadRequest {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want 400 (%s)", resp.StatusCode, b)
			}
		})
	}
}

func TestCI_ConditionRulesWork(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, map[string]any{
		"name": "release branches only", "enabled": true,
		"condition": `assertion.repository == "acme/tool" && assertion.ref.startsWith("refs/heads/release/")`,
	})

	if resp, _ := h.exchange(t, h.forge.token(nil)); resp.StatusCode != http.StatusForbidden {
		t.Errorf("main branch = %d, want 403", resp.StatusCode)
	}
	resp, _ := h.exchange(t, h.forge.token(map[string]any{"ref": "refs/heads/release/1.2"}))
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("release branch = %d %s, want 200", resp.StatusCode, b)
	}
}

func TestCI_EditingARuleRevokesItsLiveSessions(t *testing.T) {
	h := newCIHarness(t)
	id := h.addRule(t, ciBasicRule)
	_, sess := h.exchange(t, h.forge.token(nil))
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusOK {
		t.Fatalf("relay before the edit = %d", relay.StatusCode)
	}

	resp := h.do(t, http.MethodPut, "/api/ci/rules/"+id, map[string]any{
		"name": "acme tool", "repository": "acme/tool", "enabled": true,
		"models": []string{"claude-haiku-*"},
	})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("edit = %d %s", resp.StatusCode, b)
	}
	var out struct {
		Revoked int `json:"revoked_sessions"`
	}
	h.decode(t, resp, &out)
	if out.Revoked != 1 {
		t.Errorf("revoked_sessions = %d, want 1", out.Revoked)
	}
	// A session minted under the old text must not keep spending under a
	// policy that no longer exists.
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusUnauthorized {
		t.Errorf("relay after the edit = %d, want 401", relay.StatusCode)
	}
}

func TestCI_DeletingARuleRevokesItsLiveSessions(t *testing.T) {
	h := newCIHarness(t)
	id := h.addRule(t, ciBasicRule)
	_, sess := h.exchange(t, h.forge.token(nil))

	resp := h.do(t, http.MethodDelete, "/api/ci/rules/"+id, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusUnauthorized {
		t.Errorf("relay after the delete = %d, want 401", relay.StatusCode)
	}
	if resp := h.do(t, http.MethodDelete, "/api/ci/rules/"+id, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", resp.StatusCode)
	}
}

func TestCI_TurningFederationOffStopsLiveSessions(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)
	_, sess := h.exchange(t, h.forge.token(nil))
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusOK {
		t.Fatalf("relay while enabled = %d", relay.StatusCode)
	}

	resp := h.do(t, http.MethodPut, "/api/ci/config", map[string]any{"enabled": false})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("disable = %d %s", resp.StatusCode, b)
	}
	// The switch an operator reaches for when a pipeline is misbehaving has to
	// stop the ones already federated, not just the next one to ask.
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("relay after disabling = %d, want 503", relay.StatusCode)
	}
}

func TestCI_RuleTester(t *testing.T) {
	h := newCIHarness(t)

	t.Run("reports an unparseable condition before it is saved", func(t *testing.T) {
		resp := h.post(t, "/api/ci/rules/test", map[string]any{
			"name": "n", "condition": "assertion.x.all(i, i == 1)",
		})
		var out ciRuleTestResponse
		h.decode(t, resp, &out)
		if out.Valid {
			t.Fatalf("a macro condition was reported valid: %+v", out)
		}
		if !strings.Contains(out.Error, "unsupported method") {
			t.Errorf("error = %q", out.Error)
		}
	})

	t.Run("reports a match against the sample pipeline", func(t *testing.T) {
		resp := h.post(t, "/api/ci/rules/test", map[string]any{
			"name": "n", "repository": "acme/tool", "ref": "refs/heads/main",
		})
		var out ciRuleTestResponse
		h.decode(t, resp, &out)
		if !out.Valid || !out.Matched {
			t.Errorf("out = %+v, want valid and matched", out)
		}
	})

	t.Run("names an undecidable condition rather than calling it a mismatch", func(t *testing.T) {
		// The failure mode this exists to surface: a rule reading a claim the
		// token does not carry refuses every real pipeline, and looks
		// identical to "no rule matched" from the outside.
		resp := h.post(t, "/api/ci/rules/test", map[string]any{
			"name": "n", "repository": "acme/tool",
			"condition": `assertion.environment == "production"`,
		})
		var out ciRuleTestResponse
		h.decode(t, resp, &out)
		if !out.Valid {
			t.Fatalf("the condition should compile: %+v", out)
		}
		if out.Matched {
			t.Error("matched despite reading an absent claim")
		}
		if !strings.Contains(out.Reason, "environment") {
			t.Errorf("reason = %q, want it to name the missing claim", out.Reason)
		}
	})
}

// ---------------------------------------------------------------------------
// operator visibility
// ---------------------------------------------------------------------------

func TestCI_ExchangesAreRecordedForBothOutcomes(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)

	if resp, _ := h.exchange(t, h.forge.token(nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("accepted exchange: %d", resp.StatusCode)
	}
	if resp, _ := h.exchange(t, h.forge.token(map[string]any{
		"repository": "evil/tool", "sub": "repo:evil/tool"})); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("refused exchange: %d", resp.StatusCode)
	}

	resp := h.do(t, http.MethodGet, "/api/ci/exchanges", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list exchanges: %d", resp.StatusCode)
	}
	var out struct {
		Exchanges []struct {
			Accepted   bool           `json:"accepted"`
			Repository string         `json:"repository"`
			Reason     string         `json:"reason"`
			Detail     string         `json:"detail"`
			Claims     map[string]any `json:"claims"`
		} `json:"exchanges"`
	}
	h.decode(t, resp, &out)
	if len(out.Exchanges) < 2 {
		t.Fatalf("got %d exchanges, want both outcomes recorded", len(out.Exchanges))
	}
	var sawAccepted, sawRefused bool
	for _, e := range out.Exchanges {
		if e.Accepted && e.Repository == "acme/tool" {
			sawAccepted = true
		}
		if !e.Accepted && e.Repository == "evil/tool" && e.Reason == "no_rule" {
			sawRefused = true
			// The claims are what make a refusal debuggable: the operator
			// cannot decode the token and has nowhere else to look.
			if e.Claims["repository"] != "evil/tool" {
				t.Errorf("the refusal recorded no claims: %+v", e.Claims)
			}
		}
	}
	if !sawAccepted || !sawRefused {
		t.Errorf("accepted=%v refused=%v, want both", sawAccepted, sawRefused)
	}
}

func TestCI_SessionsAreListedWithTheirSpend(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)
	_, sess := h.exchange(t, h.forge.token(nil))
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusOK {
		t.Fatalf("relay: %d", relay.StatusCode)
	}

	resp := h.do(t, http.MethodGet, "/api/ci/sessions", nil)
	var out struct {
		Sessions []ciSessionView `json:"sessions"`
	}
	h.decode(t, resp, &out)
	if len(out.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(out.Sessions))
	}
	s := out.Sessions[0]
	if s.Repository != "acme/tool" || s.RuleName != "acme tool" {
		t.Errorf("provenance missing: %+v", s)
	}
	if s.Usage.Requests != 1 {
		t.Errorf("Usage.Requests = %d, want 1", s.Usage.Requests)
	}
	if s.Usage.InputTokens != 5 || s.Usage.OutputTokens != 9 {
		t.Errorf("token counts = %d/%d, want 5/9 from the upstream's usage block",
			s.Usage.InputTokens, s.Usage.OutputTokens)
	}
	// The listing must never carry anything that could be replayed.
	blob := fmt.Sprintf("%+v", s)
	if strings.Contains(blob, sess.Token) || strings.Contains(blob, ciHubKey) {
		t.Fatal("the session listing leaked a credential")
	}
}

func TestCI_SessionCanBeRevokedByAnOperator(t *testing.T) {
	h := newCIHarness(t)
	h.addRule(t, ciBasicRule)
	_, sess := h.exchange(t, h.forge.token(nil))

	resp := h.do(t, http.MethodDelete, "/api/ci/sessions/"+sess.SessionID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}
	if relay := h.relay(t, sess.Token, ciRelayBody); relay.StatusCode != http.StatusUnauthorized {
		t.Errorf("relay after revocation = %d, want 401", relay.StatusCode)
	}
	if resp := h.do(t, http.MethodDelete, "/api/ci/sessions/nope", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoking an unknown session = %d, want 404", resp.StatusCode)
	}
}

func TestCI_SettingsExposeAPastableSnippetAndNoCredential(t *testing.T) {
	h := newCIHarness(t)
	resp := h.do(t, http.MethodGet, "/api/ci/config", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var view ciSettingsView
	h.decode(t, resp, &view)
	if !view.Enabled || !view.UpstreamReady {
		t.Errorf("view = %+v, want enabled and ready", view)
	}
	for _, want := range []string{"id-token: write", "ACTIONS_ID_TOKEN_REQUEST_URL",
		"/api/ci/token", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "add-mask"} {
		if !strings.Contains(view.Snippet, want) {
			t.Errorf("the workflow snippet omits %q:\n%s", want, view.Snippet)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", view), ciHubKey) {
		t.Fatal("the settings view leaked the hub's Anthropic credential")
	}
}

func TestCI_SettingsRefuseAConfigurationThatCouldNotWork(t *testing.T) {
	h := newCIHarness(t)
	resp := h.do(t, http.MethodPut, "/api/ci/config", map[string]any{
		"enabled": true, "issuer": "http://token.actions.githubusercontent.com",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a plaintext non-loopback issuer", resp.StatusCode)
	}
	// And the bad value was not saved.
	cfg, err := config.Load(h.dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if strings.HasPrefix(cfg.UI.CI.Issuer, "http://token.actions") {
		t.Error("the refused issuer was written to config.yaml anyway")
	}
}

func TestCI_IsCIFederationEndpointIsNarrow(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"POST /api/ci/token":                 true,
		"GET /api/ci/token":                  false,
		"DELETE /api/ci/token":               false,
		"POST /api/ci/anthropic":             true,
		"POST /api/ci/anthropic/v1/messages": true,
		"GET /api/ci/anthropic/v1/models":    true,
		"GET /api/ci/config":                 false,
		"PUT /api/ci/config":                 false,
		"GET /api/ci/rules":                  false,
		"POST /api/ci/rules":                 false,
		"GET /api/ci/sessions":               false,
		"GET /api/ci/exchanges":              false,
		"POST /api/ci/tokenizer":             false,
		"POST /api/ci/anthropicx":            false,
		"GET /api/state":                     false,
		"POST /api/ci/token/../config":       false,
	}
	for spec, want := range cases {
		method, path, _ := strings.Cut(spec, " ")
		got := isCIFederationEndpoint(httptest.NewRequest(method, path, nil))
		if got != want {
			t.Errorf("isCIFederationEndpoint(%s) = %v, want %v", spec, got, want)
		}
	}
}
