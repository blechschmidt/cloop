package claudeproxy

// runrelay_test.go: what a run relay (Task 20435) adds to the engine — a
// session that carries its own upstream credential, bound to a lease and a
// grant, extended with its lease, closed with it, admitted against its payer's
// budget, and explaining its end to the holder of its token.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	runPrefix     = "cloop_relay_"
	runOAuthToken = "sk-ant-oat01-run-credential-stays-on-the-hub"
	runAPIKey     = "sk-ant-api03-run-key-stays-on-the-hub"
)

// runHarness is a run relay: a proxy holding no credential of its own in
// front of a fake upstream, and sessions that each carry one.
type runHarness struct {
	t     *testing.T
	up    *fakeAnthropic
	reg   *Registry
	proxy *Proxy
	front *httptest.Server
	now   time.Time
	clock sync.Mutex

	mu     sync.Mutex
	events []Event
	spends []Spend

	// admit, when set, is consulted for every Messages request.
	admit func(*Session, string) *Denial
}

func newRunHarness(t *testing.T) *runHarness {
	t.Helper()
	h := &runHarness{t: t, up: newFakeAnthropic(t), now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	h.reg = NewRegistryWithPrefix("https://relay.example.com/_anthropic", runPrefix)
	h.reg.SetClock(h.clockNow)
	h.reg.OnEvent = func(e Event) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.events = append(h.events, e)
	}
	px, err := New(h.reg, Options{
		PathPrefix:       "/_anthropic",
		Transport:        h.up.srv.Client().Transport,
		Now:              h.clockNow,
		SessionUpstreams: true,
		ExplainClosed:    true,
		UserAgent:        "cloop-model-relay/1",
		Unauthenticated:  "the model relay session token was not accepted",
		Admit: func(s *Session, model string) *Denial {
			if h.admit != nil {
				return h.admit(s, model)
			}
			return nil
		},
		OnSpend: func(s *Session, sp Spend) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.spends = append(h.spends, sp)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.proxy = px
	h.front = httptest.NewServer(px)
	t.Cleanup(h.front.Close)
	return h
}

func (h *runHarness) clockNow() time.Time {
	h.clock.Lock()
	defer h.clock.Unlock()
	return h.now
}

func (h *runHarness) advance(d time.Duration) {
	h.clock.Lock()
	defer h.clock.Unlock()
	h.now = h.now.Add(d)
}

func (h *runHarness) mint(up *Upstream, mutate ...func(*MintRequest)) *Minted {
	h.t.Helper()
	req := MintRequest{
		Policy:  Policy{Models: []string{"claude-*"}},
		Project: "/srv/app", RunID: "run-1", LeaseID: "lease-1", GrantID: "grant-1",
		ExecutorID: "exec-1", Payer: "alice@example.com", TTL: 15 * time.Minute,
		Upstream: up,
	}
	for _, m := range mutate {
		m(&req)
	}
	m, err := h.reg.Mint(req)
	if err != nil {
		h.t.Fatalf("Mint: %v", err)
	}
	return m
}

func (h *runHarness) post(token, body string) (*http.Response, string) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.front.URL+"/_anthropic/v1/messages", strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Anthropic-Beta", "interleaved-thinking-2025-05-14")
	resp, err := h.front.Client().Do(req)
	if err != nil {
		h.t.Fatalf("POST: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

func (h *runHarness) eventsOf(k EventKind) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Event
	for _, e := range h.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

const runBody = `{"model":"claude-sonnet-5","max_tokens":1000,"messages":[{"role":"user","content":"hi"}]}`

func TestRunRelay_EachSessionSpendsItsOwnCredential(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	h.up.srv.URL = strings.TrimSuffix(h.up.srv.URL, "/")
	oauth := h.mint(&Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true})
	key := h.mint(&Upstream{BaseURL: h.up.srv.URL, APIKey: runAPIKey}, func(m *MintRequest) {
		m.LeaseID, m.GrantID = "lease-2", "grant-2"
	})

	if resp, body := h.post(oauth.Token, runBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("oauth session: %d %s", resp.StatusCode, body)
	}
	if resp, body := h.post(key.Token, runBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("api key session: %d %s", resp.StatusCode, body)
	}
	seen := h.up.seen()
	if len(seen) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(seen))
	}
	first, second := seen[0].Header, seen[1].Header
	if got := first.Get("Authorization"); got != "Bearer "+runOAuthToken {
		t.Errorf("the oauth session was relayed with Authorization %q", got)
	}
	if first.Get("X-Api-Key") != "" {
		t.Error("the oauth session's request also carried an x-api-key")
	}
	if got := first.Get("Anthropic-Beta"); got != "interleaved-thinking-2025-05-14,"+OAuthBeta {
		t.Errorf("anthropic-beta = %q, want the client's betas and the OAuth beta", got)
	}
	if got := second.Get("X-Api-Key"); got != runAPIKey {
		t.Errorf("the api-key session was relayed with x-api-key %q", got)
	}
	if second.Get("Authorization") != "" {
		t.Error("the api-key session's request also carried an Authorization header")
	}
	if strings.Contains(second.Get("Anthropic-Beta"), OAuthBeta) {
		t.Error("an api-key session named the OAuth beta")
	}
	for i, r := range seen {
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "cloop-model-relay/1 (session ") {
			t.Errorf("request %d user agent %q", i, got)
		}
		for _, tok := range []string{oauth.Token, key.Token} {
			for name, vv := range r.Header {
				for _, v := range vv {
					if strings.Contains(v, tok) {
						t.Errorf("request %d carried a session token upstream in %s", i, name)
					}
				}
			}
		}
	}
}

func TestRunRelay_ASessionWithoutACredentialIsNeverRelayedWithAnother(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	bare := h.mint(nil)
	resp, body := h.post(bare.Token, runBody)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d (%s), want 502", resp.StatusCode, body)
	}
	if n := h.up.count(); n != 0 {
		t.Fatalf("the upstream was reached %d times", n)
	}
	if _, err := New(NewRegistry("https://x"), Options{SessionUpstreams: true,
		Upstream: Upstream{APIKey: "k"}}); err == nil {
		t.Fatal("a proxy whose sessions carry their credentials was given one of its own")
	}
	if _, err := New(NewRegistry("https://x"), Options{SessionUpstreams: true}); err != nil {
		t.Fatalf("a credential-less session proxy was refused: %v", err)
	}
}

func TestRunRelay_PrefixesKeepRelaysApart(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	m := h.mint(&Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true})
	if !strings.HasPrefix(m.Token, runPrefix) {
		t.Fatalf("token %q does not carry the registry's prefix", m.Token[:16])
	}
	if id, ok := h.reg.SessionIDOf(m.Token); !ok || id != m.Session.ID {
		t.Fatalf("SessionIDOf = %q, %v", id, ok)
	}
	if _, ok := SessionIDOf(m.Token); ok {
		t.Error("the CI parser accepted a run relay token")
	}
	ci := NewRegistry("https://hub/api/ci/anthropic")
	if _, err := ci.Authenticate(m.Token); err == nil {
		t.Error("a CI registry authenticated a run relay token")
	}
	// The same id and secret under the CI prefix is not this registry's.
	forged := TokenPrefix + strings.TrimPrefix(m.Token, runPrefix)
	if _, err := h.reg.Authenticate(forged); err == nil {
		t.Error("a run relay registry accepted a CI-prefixed token")
	}
	for _, bad := range []string{"", "nope", "a.b", "relay_"} {
		func() {
			defer func() { _ = recover() }()
			NewRegistryWithPrefix("https://x", bad)
			t.Errorf("prefix %q was accepted", bad)
		}()
	}
}

// renewStore is a memStore that keeps renewals.
type renewStore struct {
	*memStore
	mu      sync.Mutex
	renewed map[string]time.Time
	gone    bool
}

func (s *renewStore) RenewSession(id string, expiresAt, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gone {
		return ErrRecordGone
	}
	if s.renewed == nil {
		s.renewed = map[string]time.Time{}
	}
	s.renewed[id] = expiresAt
	return nil
}

func TestRunRelay_ExtendMovesTheDeadlineWithTheLease(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	store := &renewStore{memStore: newMemStore()}
	h.reg.Store = store
	m := h.mint(&Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true})
	issued := m.Session.Deadline()

	h.advance(10 * time.Minute)
	until := h.clockNow().Add(15 * time.Minute)
	got, err := h.reg.Extend(m.Session.ID, until)
	if err != nil || !got.Equal(until) {
		t.Fatalf("Extend = %v, %v; want %v", got, err, until)
	}
	if !m.Session.Deadline().Equal(until) || !m.Session.ExpiresAt.Equal(issued) {
		t.Fatalf("deadline %v (issued %v)", m.Session.Deadline(), m.Session.ExpiresAt)
	}
	if !store.renewed[m.Session.ID].Equal(until) {
		t.Fatalf("the store recorded %v", store.renewed[m.Session.ID])
	}
	// Past the issued deadline, the session still authenticates.
	h.advance(10 * time.Minute)
	if resp, body := h.post(m.Token, runBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("an extended session past its issued deadline: %d %s", resp.StatusCode, body)
	}
	// Never past MaxTTL from now, and never backwards.
	far := h.clockNow().Add(48 * time.Hour)
	got, _ = h.reg.Extend(m.Session.ID, far)
	if want := h.clockNow().Add(MaxTTL); !got.Equal(want) {
		t.Errorf("an extension to %v landed at %v, want %v", far, got, want)
	}
	if back, _ := h.reg.Extend(m.Session.ID, h.clockNow()); !back.Equal(got) {
		t.Errorf("an extension backwards moved the deadline to %v", back)
	}
	// A lapsed session is not revived.
	h.advance(MaxTTL + time.Minute)
	if _, err := h.reg.Extend(m.Session.ID, h.clockNow().Add(time.Hour)); !errors.Is(err, ErrNotExtendable) {
		t.Errorf("a lapsed session was extended: %v", err)
	}
}

func TestRunRelay_ARenewalWhoseRecordWentElsewhereEndsTheSession(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	store := &renewStore{memStore: newMemStore()}
	h.reg.Store = store
	m := h.mint(&Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true})
	store.gone = true
	if _, err := h.reg.Extend(m.Session.ID, h.clockNow().Add(time.Hour)); !errors.Is(err, ErrNotExtendable) {
		t.Fatalf("Extend = %v, want ErrNotExtendable", err)
	}
	if h.reg.Known(m.Session.ID) {
		t.Fatal("a session whose record another process holds is still served here")
	}
}

func TestRunRelay_ClosedSessionsExplainThemselvesToTheirTokenOnly(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	up := &Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true}
	a := h.mint(up)
	b := h.mint(up, func(m *MintRequest) { m.LeaseID, m.GrantID = "lease-2", "grant-2" })
	c := h.mint(up, func(m *MintRequest) { m.LeaseID, m.GrantID = "lease-3", "grant-3" })

	if n := h.reg.CloseForGrant("lease-1", "grant-1", "the grant behind it was revoked"); n != 1 {
		t.Fatalf("CloseForGrant closed %d", n)
	}
	if n := h.reg.CloseForLease("lease-2", "the run ended"); n != 1 {
		t.Fatalf("CloseForLease closed %d", n)
	}
	if got := h.reg.LeaseSessions("lease-3"); len(got) != 1 || got[0].ID != c.Session.ID {
		t.Fatalf("LeaseSessions(lease-3) = %v", got)
	}

	resp, body := h.post(a.Token, runBody)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "the grant behind it was revoked") {
		t.Fatalf("revoked session: %d %s", resp.StatusCode, body)
	}
	resp, body = h.post(b.Token, runBody)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "the run ended") {
		t.Fatalf("ended session: %d %s", resp.StatusCode, body)
	}
	// The id with the wrong secret learns nothing.
	wrong := a.Token[:strings.LastIndexByte(a.Token, '.')+1] + strings.Repeat("0", 64)
	resp, body = h.post(wrong, runBody)
	if resp.StatusCode != http.StatusUnauthorized || strings.Contains(body, "revoked") {
		t.Fatalf("a wrong token for a closed session: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "the model relay session token was not accepted") {
		t.Errorf("401 body %q does not carry the relay's message", body)
	}
	if resp, _ := h.post(c.Token, runBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("the untouched session: %d", resp.StatusCode)
	}
	if n := h.up.count(); n != 1 {
		t.Fatalf("the upstream saw %d requests, want only the live session's", n)
	}
	// The explanation outlives a short deadline.
	h.advance(45 * time.Minute)
	if resp, body := h.post(a.Token, runBody); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("45 minutes after its revocation, past its deadline: %d %s", resp.StatusCode, body)
	}
	h.advance(30 * time.Minute)
	h.reg.ReapExpired()
	if resp, _ := h.post(a.Token, runBody); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("over an hour later the tombstone should be gone: %d", resp.StatusCode)
	}
	rejected := h.eventsOf(EventRejected)
	if len(rejected) == 0 || rejected[0].SessionID != a.Session.ID || rejected[0].Status != http.StatusForbidden {
		t.Fatalf("the explained refusal was not recorded against the session: %+v", rejected)
	}
}

func TestRunRelay_AdmitRefusesBeforeTheUpstreamAndCountsNothing(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	var asked []string
	var mu sync.Mutex
	h.admit = func(s *Session, model string) *Denial {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, s.Payer+"/"+model)
		return &Denial{Reason: DenyBudget, Status: http.StatusForbidden,
			Message: "the daily token budget of alice@example.com is spent"}
	}
	m := h.mint(&Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true})
	resp, body := h.post(m.Token, runBody)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "daily token budget") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if n := h.up.count(); n != 0 {
		t.Fatalf("a refused request reached the upstream %d times", n)
	}
	if u := m.Session.Usage(); u.Requests != 0 || u.Denied != 1 {
		t.Fatalf("usage after a refusal: %+v", u)
	}
	if len(asked) != 1 || asked[0] != "alice@example.com/claude-sonnet-5" {
		t.Fatalf("Admit was asked %v", asked)
	}
	// Counting tokens spends nothing and is not held to the budget.
	req, _ := http.NewRequest(http.MethodPost, h.front.URL+"/_anthropic/v1/messages/count_tokens",
		strings.NewReader(`{"model":"claude-sonnet-5","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+m.Token)
	r2, err := h.front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusOK || len(asked) != 1 {
		t.Fatalf("count_tokens: %d, admit asked %d times", r2.StatusCode, len(asked))
	}
	denied := h.eventsOf(EventRelayDenied)
	if len(denied) != 1 || denied[0].Reason != DenyBudget || denied[0].Payer != "alice@example.com" ||
		denied[0].LeaseID != "lease-1" || denied[0].UpstreamKind != "oauth_token" {
		t.Fatalf("the refusal's event: %+v", denied)
	}
}

func TestRunRelay_OnSpendReportsWhatTheUpstreamCounted(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	h.up.handler = func(w http.ResponseWriter, r *http.Request) {
		// The fake has read and recorded the body already.
		seen := h.up.seen()
		if strings.Contains(string(seen[len(seen)-1].Body), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: message_start\n")
			fmt.Fprint(w, `data: {"type":"message_start","message":{"model":"claude-haiku-4-5-20251001",`+
				`"usage":{"input_tokens":16,"cache_creation_input_tokens":40,"cache_read_input_tokens":500,`+
				`"cache_creation":{"ephemeral_5m_input_tokens":10,"ephemeral_1h_input_tokens":30},"output_tokens":1}}}`+"\n\n")
			fmt.Fprint(w, `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"1 2 3"}}`+"\n\n")
			fmt.Fprint(w, `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":13}}`+"\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"claude-sonnet-5-20260901","usage":{"input_tokens":11,"output_tokens":7,` +
			`"cache_read_input_tokens":3,"cache_creation_input_tokens":2,` +
			`"cache_creation":{"ephemeral_5m_input_tokens":2,"ephemeral_1h_input_tokens":0}}}`))
	}
	m := h.mint(&Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true})
	if resp, _ := h.post(m.Token, runBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("buffered: %d", resp.StatusCode)
	}
	if resp, _ := h.post(m.Token, `{"model":"claude-haiku-4-5","max_tokens":40,"stream":true,"messages":[]}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("streamed: %d", resp.StatusCode)
	}
	// OnSpend runs after the body is relayed, on the request's goroutine;
	// the server's handler has returned by the time Close does.
	h.front.Close()
	h.mu.Lock()
	spends := append([]Spend(nil), h.spends...)
	h.mu.Unlock()
	want := []Spend{
		{Model: "claude-sonnet-5-20260901", Status: 200, Input: 11, Output: 7, CacheRead: 3, CacheWrite: 2},
		{Model: "claude-haiku-4-5-20251001", Status: 200, Input: 16, Output: 13, CacheRead: 500, CacheWrite: 40, CacheWrite1h: 30},
	}
	if len(spends) != len(want) {
		t.Fatalf("spends %+v", spends)
	}
	for i := range want {
		if spends[i] != want[i] {
			t.Errorf("spend %d = %+v, want %+v", i, spends[i], want[i])
		}
	}
	if got := spends[1].Tokens(); got != 16+13+500+40 {
		t.Errorf("Tokens() = %d", got)
	}
	if u := m.Session.Usage(); u.InputTokens != 27 || u.OutputTokens != 20 || u.CacheRead != 503 || u.CacheWrite != 42 {
		t.Errorf("session usage %+v", u)
	}
}

func TestRunRelay_ThinkingBudgetFollowsAClampedMaxTokens(t *testing.T) {
	t.Parallel()
	pol := Policy{Models: []string{"claude-*"}, MaxOutputTokens: 2048}
	cases := []struct {
		name, body string
		want       map[string]any // thinking after the decision; nil = absent
	}{
		{"budget at the request's max", `{"model":"claude-x","max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":4095}}`,
			map[string]any{"type": "enabled", "budget_tokens": float64(2047)}},
		{"budget under the cap", `{"model":"claude-x","max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":1500}}`,
			map[string]any{"type": "enabled", "budget_tokens": float64(1500)}},
		{"adaptive", `{"model":"claude-x","max_tokens":4096,"thinking":{"type":"adaptive"}}`,
			map[string]any{"type": "adaptive"}},
	}
	for _, tc := range cases {
		out, _, d := pol.DecideMessages([]byte(tc.body))
		if d != nil {
			t.Fatalf("%s: %v", tc.name, d)
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["max_tokens"] != float64(2048) {
			t.Errorf("%s: max_tokens %v", tc.name, doc["max_tokens"])
		}
		if fmt.Sprint(doc["thinking"]) != fmt.Sprint(tc.want) {
			t.Errorf("%s: thinking %v, want %v", tc.name, doc["thinking"], tc.want)
		}
	}
	// A cap too small for any budget the API takes drops thinking rather
	// than sending a request the API refuses.
	tiny := Policy{Models: []string{"claude-*"}, MaxOutputTokens: 1000}
	out, _, d := tiny.DecideMessages([]byte(`{"model":"claude-x","max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":3000}}`))
	if d != nil {
		t.Fatal(d)
	}
	if strings.Contains(string(out), "thinking") {
		t.Errorf("thinking survived a cap below the smallest budget: %s", out)
	}
}

func TestRunRelay_RestoreTakesTheCredentialFromTheCallerNeverTheRecord(t *testing.T) {
	t.Parallel()
	h := newRunHarness(t)
	store := &renewStore{memStore: newMemStore()}
	h.reg.Store = store
	m := h.mint(&Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true})
	h.advance(5 * time.Minute)
	if _, err := h.reg.Extend(m.Session.ID, h.clockNow().Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	h.reg.Checkpoint()
	if !h.reg.Suspend(m.Session.ID, "the hub is shutting down") {
		t.Fatal("Suspend")
	}
	rec := store.record(m.Session.ID)
	rec.ExpiresAt = store.renewed[m.Session.ID]
	rec.RenewedAt = h.clockNow()
	raw, _ := json.Marshal(rec)
	for _, secret := range []string{runOAuthToken, m.Token} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("the record holds a credential")
		}
	}
	if rec.UpstreamKind != "oauth_token" || rec.LeaseID != "lease-1" || rec.Payer != "alice@example.com" {
		t.Fatalf("record binding %+v", rec)
	}

	other := NewRegistryWithPrefix("https://relay.example.com/_anthropic", runPrefix)
	other.SetClock(h.clockNow)
	if _, err := other.Restore(RestoreRequest{Record: rec}); err == nil {
		t.Error("a session that relays with a credential was restored without one")
	}
	if _, err := other.Restore(RestoreRequest{Record: rec, Upstream: &Upstream{BaseURL: h.up.srv.URL, APIKey: runAPIKey}}); err == nil {
		t.Error("an oauth session was restored with an api key")
	}
	s, err := other.Restore(RestoreRequest{Record: rec, From: "member-a",
		Upstream: &Upstream{BaseURL: h.up.srv.URL, AuthToken: runOAuthToken, OAuth: true}})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if s.UpstreamKind() != "oauth_token" || s.LeaseID != "lease-1" || s.RenewedAt().IsZero() {
		t.Fatalf("restored %+v", s)
	}
	if _, err := other.Authenticate(m.Token); err != nil {
		t.Fatalf("the restored session does not take its token: %v", err)
	}
	// A renewed record is bounded from its renewal, not its issue.
	h.advance(MaxTTL)
	stale := rec
	stale.ID = "0123456789abcdef01234567"
	stale.RenewedAt = h.clockNow().Add(-time.Minute)
	stale.ExpiresAt = h.clockNow().Add(MaxTTL - 2*time.Minute)
	if err := other.CheckRestore(stale); err != nil {
		t.Errorf("a record renewed a minute ago was refused: %v", err)
	}
	stale.RenewedAt = time.Time{}
	if err := other.CheckRestore(stale); err == nil {
		t.Error("a deadline MaxTTL past a long-ago issue, with no renewal, was accepted")
	}
}
