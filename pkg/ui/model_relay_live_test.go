package ui

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// TestLiveModelRelay relays real calls to api.anthropic.com with a real
// credential. It is how a credential kind is proven before relayProvenKinds
// names it (Task 20435): run it with a credential of that kind and record what
// it showed there.
//
// Opt-in. CLOOP_LIVE_MODEL_RELAY_CREDENTIAL names a file holding the
// credential — never the value itself, so it stays out of the process table
// and the shell's history — and CLOOP_LIVE_MODEL_RELAY_KIND says what it is:
// oauth_token (from `claude setup-token`, the default) or api_key. Each run
// spends two calls of a few tokens on claude-haiku-4-5.
//
// What it shows: the sandbox's spec holds a session token and not the
// credential; a plain and a streamed call through the relay are answered by
// the API; what the payer was charged for the plain one is what the API
// reported; and a model outside the project's allowlist is refused before it
// reaches the API.
func TestLiveModelRelay(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("CLOOP_LIVE_MODEL_RELAY_CREDENTIAL"))
	if path == "" {
		t.Skip("set CLOOP_LIVE_MODEL_RELAY_CREDENTIAL to a file holding a Claude credential " +
			"(and CLOOP_LIVE_MODEL_RELAY_KIND=api_key for an API key) to relay real calls")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the credential: %v", err)
	}
	credential := strings.TrimSpace(string(raw))
	kind := strings.TrimSpace(os.Getenv("CLOOP_LIVE_MODEL_RELAY_KIND"))
	if kind == "" {
		kind = relayKindOAuth
	}
	key := envClaudeOAuthToken
	switch kind {
	case relayKindOAuth:
	case relayKindAPIKey:
		key = envAnthropicAPIKey
	default:
		t.Fatalf("CLOOP_LIVE_MODEL_RELAY_KIND=%q: use %s or %s", kind, relayKindOAuth, relayKindAPIKey)
	}
	// A kind being proven is relayed for this test alone.
	if !relayProven(kind) {
		relayProvenKinds[kind] = "under test"
		t.Cleanup(func() { delete(relayProvenKinds, kind) })
	}

	r := newRelayRig(t, nil)
	r.cfg.UpstreamBaseURL = "" // the real API
	r.crash("hub_live")
	if err := setProjectRelayModels(r.dir, []string{"claude-haiku-*"}); err != nil {
		t.Fatal(err)
	}
	ex := newTakeoverExecutor("edge-live")
	r.grant("executor:"+ex.ID(), map[string]string{key: credential})
	sl, spec, id := r.leaseFor(ex, "run_live")
	t.Cleanup(sl.Close)
	for _, kv := range spec.Env {
		if strings.Contains(kv, credential) {
			t.Fatalf("the sandbox's spec holds the credential in %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	token, _ := envValue(spec.Env, envAnthropicAuth)
	if !strings.HasPrefix(token, modelRelayTokenPrefix) {
		t.Fatalf("the sandbox was not handed a relay session token (session %s)", id)
	}

	post := func(body string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, r.front.URL+modelRelayMount+"/v1/messages", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		resp, err := r.front.Client().Do(req)
		if err != nil {
			t.Fatalf("relay call: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		<-r.servedCh
		return resp.StatusCode, b
	}
	const ask = `"max_tokens":16,"messages":[{"role":"user","content":"Reply with the single word ok."}]`

	beforeTokens, _ := r.spentToday("alice@corp.example")
	code, body := post(`{"model":"claude-haiku-4-5",` + ask + `}`)
	if code != http.StatusOK {
		t.Fatalf("the plain call = %d %s", code, body)
	}
	var plain struct {
		Usage struct {
			Input       int64 `json:"input_tokens"`
			Output      int64 `json:"output_tokens"`
			CacheRead   int64 `json:"cache_read_input_tokens"`
			CacheCreate int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &plain); err != nil {
		t.Fatalf("the plain call's answer: %v", err)
	}
	reported := plain.Usage.Input + plain.Usage.Output + plain.Usage.CacheRead + plain.Usage.CacheCreate
	afterPlain, usd := r.spentToday("alice@corp.example")
	if reported <= 0 || int64(afterPlain-beforeTokens) != reported || usd <= 0 {
		t.Fatalf("charged %v tokens ($%v) for a call the API reported as %d", afterPlain-beforeTokens, usd, reported)
	}

	code, body = post(`{"model":"claude-haiku-4-5","stream":true,` + ask + `}`)
	if code != http.StatusOK || !strings.Contains(string(body), "message_stop") {
		t.Fatalf("the streamed call = %d %s", code, body)
	}
	if afterStream, _ := r.spentToday("alice@corp.example"); afterStream <= afterPlain {
		t.Fatalf("the streamed call charged nothing: %v then %v", afterPlain, afterStream)
	}

	code, body = post(`{"model":"claude-sonnet-4-5",` + ask + `}`)
	if code != http.StatusForbidden || !strings.Contains(string(body), "claude-sonnet-4-5") {
		t.Fatalf("a model outside the project's allowlist = %d %s", code, body)
	}
	denied := false
	for _, row := range r.auditRows(auditaction.ActionModelRelayDenied) {
		denied = denied || (row.EntityID == id && strings.Contains(row.Payload, "model_not_allowed"))
	}
	if !denied {
		t.Fatal("the refused model was not audited as model_not_allowed")
	}
	t.Logf("relayed a %s to the real API: plain call charged %d tokens as the API reported, streamed call "+
		"answered, claude-sonnet-4-5 refused before the API", relayKindLabel(kind), reported)
}
