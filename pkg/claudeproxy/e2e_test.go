package claudeproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAnthropic stands in for api.anthropic.com. It records every request it
// receives, which is how the tests assert the two properties that matter most:
// that a refused request never reaches it at all, and that an allowed one
// arrives carrying the hub's credential and not the pipeline's.
type fakeAnthropic struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []recordedRequest

	// handler, when set, replaces the default Messages API response.
	handler http.HandlerFunc
}

type recordedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

func newFakeAnthropic(t *testing.T) *fakeAnthropic {
	t.Helper()
	f := &fakeAnthropic{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, recordedRequest{
			Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body,
		})
		f.mu.Unlock()

		if f.handler != nil {
			f.handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Request-Id", "req_upstream_1")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant",` +
			`"content":[{"type":"text","text":"hello"}],` +
			`"usage":{"input_tokens":11,"output_tokens":7,` +
			`"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAnthropic) seen() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedRequest, len(f.requests))
	copy(out, f.requests)
	return out
}

func (f *fakeAnthropic) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// harness is a proxy in front of a fake upstream, plus a session to use it.
type harness struct {
	t     *testing.T
	up    *fakeAnthropic
	reg   *Registry
	proxy *Proxy
	front *httptest.Server
	token string
	sess  *Session

	mu     sync.Mutex
	events []Event
}

const hubUpstreamKey = "sk-ant-hub-credential-never-leaves"

func newHarness(t *testing.T, mutate ...func(*MintRequest)) *harness {
	t.Helper()
	up := newFakeAnthropic(t)
	h := &harness{t: t, up: up}

	h.reg = NewRegistry("https://hub.example.com/api/ci/anthropic")
	h.reg.OnEvent = func(e Event) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.events = append(h.events, e)
	}
	px, err := New(h.reg, Options{
		Upstream:   Upstream{BaseURL: up.srv.URL, APIKey: hubUpstreamKey},
		PathPrefix: "/api/ci/anthropic",
		Transport:  up.srv.Client().Transport,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.proxy = px
	h.front = httptest.NewServer(px)
	t.Cleanup(h.front.Close)

	m := testMint(t, h.reg, mutate...)
	h.token, h.sess = m.Token, m.Session
	return h
}

// do sends a request through the proxy exactly as a pipeline would, with
// ANTHROPIC_BASE_URL pointed at the mount point.
func (h *harness) do(method, apiPath, body string, mutate ...func(*http.Request)) *http.Response {
	h.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.front.URL+"/api/ci/anthropic"+apiPath, rdr)
	if err != nil {
		h.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	for _, m := range mutate {
		m(req)
	}
	resp, err := h.front.Client().Do(req)
	if err != nil {
		h.t.Fatalf("request: %v", err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *harness) eventsOfKind(k EventKind) []Event {
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

const validBody = `{"model":"claude-sonnet-4-6","max_tokens":100,` +
	`"messages":[{"role":"user","content":"hi"}]}`

func TestE2E_RelaysAndSwapsTheCredential(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	resp := h.do("POST", "/v1/messages", validBody)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"msg_1"`) {
		t.Errorf("the upstream response did not reach the client: %s", body)
	}
	// Upstream headers the client legitimately wants are passed through.
	if got := resp.Header.Get("Request-Id"); got != "req_upstream_1" {
		t.Errorf("Request-Id = %q, want the upstream's", got)
	}

	seen := h.up.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(seen))
	}
	got := seen[0]
	if got.Path != "/v1/messages" {
		t.Errorf("upstream path = %q", got.Path)
	}
	// The whole point: the hub's credential goes up, the session token does
	// not, and the session token appears nowhere in the forwarded request.
	if key := got.Header.Get("X-Api-Key"); key != hubUpstreamKey {
		t.Errorf("X-Api-Key = %q, want the hub credential", key)
	}
	if auth := got.Header.Get("Authorization"); auth != "" {
		t.Errorf("Authorization was forwarded upstream: %q", auth)
	}
	blob := fmt.Sprintf("%v %s", got.Header, got.Body)
	if strings.Contains(blob, h.token) {
		t.Fatalf("the session token was forwarded to the upstream")
	}
}

func TestE2E_AcceptsBothCredentialForms(t *testing.T) {
	t.Parallel()
	// Claude Code sends ANTHROPIC_AUTH_TOKEN as a bearer; the SDKs send
	// ANTHROPIC_API_KEY in x-api-key. A pipeline should not have to know
	// which one the harness it runs happens to use.
	for _, tc := range []struct {
		name  string
		apply func(*http.Request, string)
	}{
		{"bearer", func(r *http.Request, tok string) {
			r.Header.Set("Authorization", "Bearer "+tok)
			r.Header.Del("X-Api-Key")
		}},
		{"x-api-key", func(r *http.Request, tok string) {
			r.Header.Del("Authorization")
			r.Header.Set("X-Api-Key", tok)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			resp := h.do("POST", "/v1/messages", validBody, func(r *http.Request) {
				tc.apply(r, h.token)
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
		})
	}
}

func TestE2E_RefusedRequestsNeverReachTheUpstream(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantReason DenyReason
	}{
		{"model outside the allowlist", "POST", "/v1/messages",
			`{"model":"claude-opus-4-8","max_tokens":10,"messages":[]}`,
			http.StatusForbidden, DenyModelNotAllowed},
		{"batches endpoint", "POST", "/v1/messages/batches", `{}`,
			http.StatusNotFound, DenyPathNotAllowed},
		{"files endpoint", "POST", "/v1/files", `{}`,
			http.StatusNotFound, DenyPathNotAllowed},
		{"organization admin", "GET", "/v1/organizations/users", "",
			http.StatusNotFound, DenyPathNotAllowed},
		{"wrong method", "GET", "/v1/messages", "",
			http.StatusMethodNotAllowed, DenyMethodNotAllowd},
		{"malformed body", "POST", "/v1/messages", `{`,
			http.StatusBadRequest, DenyBodyMalformed},
		{"traversal to a forbidden endpoint", "POST", "/v1/messages/../files", `{}`,
			http.StatusNotFound, DenyPathNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			resp := h.do(tc.method, tc.path, tc.body)
			if resp.StatusCode != tc.wantStatus {
				b, _ := io.ReadAll(resp.Body)
				t.Errorf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, b)
			}
			if n := h.up.count(); n != 0 {
				t.Fatalf("the upstream saw %d requests for a refusal — the hub's "+
					"credential was spent on a request the policy denied", n)
			}
			denials := h.eventsOfKind(EventRelayDenied)
			if len(denials) != 1 {
				t.Fatalf("got %d denial events, want 1", len(denials))
			}
			if denials[0].Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", denials[0].Reason, tc.wantReason)
			}
			// A refusal must not consume budget.
			if got := h.sess.Usage().Requests; got != 0 {
				t.Errorf("a refused request consumed %d units of budget", got)
			}
			// The body must be shaped like an Anthropic error so an SDK
			// surfaces the message rather than "unexpected response".
			var parsed struct {
				Type  string `json:"type"`
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			b, _ := io.ReadAll(resp.Body)
			if err := json.Unmarshal(b, &parsed); err != nil || parsed.Type != "error" {
				t.Errorf("refusal body is not an API error: %s", b)
			}
			if parsed.Error.Message == "" {
				t.Errorf("refusal carried no message: %s", b)
			}
		})
	}
}

// TestE2E_TheUpstreamSeesTheSamePathThatWasChecked is the normalise-once
// guarantee. A path that satisfies the allowlist after cleaning but is
// forwarded before it is the classic proxy bypass: the check is about one
// endpoint and the request asks for another.
func TestE2E_TheUpstreamSeesTheSamePathThatWasChecked(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do("POST", "/v1/messages/../messages", validBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the request to be permitted", resp.StatusCode)
	}
	seen := h.up.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests", len(seen))
	}
	if seen[0].Path != "/v1/messages" {
		t.Errorf("the upstream was asked for %q, but the allowlist was consulted about "+
			"%q — the check and the request must be the same path",
			seen[0].Path, "/v1/messages")
	}
}

func TestE2E_MaxTokensIsClampedAtTheUpstream(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(m *MintRequest) { m.Policy.MaxOutputTokens = 256 })
	resp := h.do("POST", "/v1/messages",
		`{"model":"claude-sonnet-4-6","max_tokens":1000000,"messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	seen := h.up.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests", len(seen))
	}
	var got map[string]any
	if err := json.Unmarshal(seen[0].Body, &got); err != nil {
		t.Fatalf("upstream body: %v", err)
	}
	if got["max_tokens"] != float64(256) {
		t.Errorf("upstream received max_tokens = %v, want the clamped 256", got["max_tokens"])
	}
}

func TestE2E_BudgetIsEnforced(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(m *MintRequest) { m.Policy.MaxRequests = 2 })
	for i := 0; i < 2; i++ {
		if resp := h.do("POST", "/v1/messages", validBody); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
	}
	resp := h.do("POST", "/v1/messages", validBody)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if n := h.up.count(); n != 2 {
		t.Errorf("upstream saw %d requests, want the budgeted 2", n)
	}
	if got := h.sess.RemainingRequests(); got != 0 {
		t.Errorf("RemainingRequests() = %d, want 0", got)
	}
}

func TestE2E_MetersUsageFromABufferedResponse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if resp := h.do("POST", "/v1/messages", validBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// Drain so the relay completes before the counters are read.
	u := h.sess.Usage()
	if u.InputTokens != 11 || u.OutputTokens != 7 || u.CacheRead != 3 || u.CacheWrite != 2 {
		t.Errorf("usage = %+v, want input 11 / output 7 / cacheRead 3 / cacheWrite 2", u)
	}
	if u.BytesUp == 0 || u.BytesDown == 0 {
		t.Errorf("byte counters were not moved: %+v", u)
	}
	allowed := h.eventsOfKind(EventRelayAllowed)
	if len(allowed) != 1 {
		t.Fatalf("got %d allow events, want 1", len(allowed))
	}
	if allowed[0].Model != "claude-sonnet-4-6" || allowed[0].Status != 200 {
		t.Errorf("event = %+v", allowed[0])
	}
	if allowed[0].OutputTokens != 7 {
		t.Errorf("event OutputTokens = %d, want 7", allowed[0].OutputTokens)
	}
}

func TestE2E_StreamsAndMetersServerSentEvents(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// A realistic stream: message_start carries the input count, each
	// message_delta carries a *cumulative* output count. Summing them would
	// triple-count, so the final value is the answer.
	h.up.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flush, _ := w.(http.Flusher)
		lines := []string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"id":"msg_2","usage":{"input_tokens":40,"cache_read_input_tokens":5,"cache_creation_input_tokens":1,"output_tokens":1}}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"partial"}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":23}}`,
			``,
		}
		for _, l := range lines {
			_, _ = fmt.Fprintf(w, "%s\n", l)
			if flush != nil {
				flush.Flush()
			}
		}
	}

	resp := h.do("POST", "/v1/messages",
		`{"model":"claude-sonnet-4-6","max_tokens":100,"stream":true,"messages":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q, want the stream to be relayed as one", ct)
	}
	var got []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		got = append(got, sc.Text())
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, `"text":"partial"`) {
		t.Errorf("stream content did not reach the client:\n%s", joined)
	}
	if !strings.Contains(joined, `"output_tokens":23`) {
		t.Errorf("the final delta did not reach the client:\n%s", joined)
	}

	u := h.sess.Usage()
	if u.InputTokens != 40 {
		t.Errorf("InputTokens = %d, want 40", u.InputTokens)
	}
	if u.OutputTokens != 23 {
		t.Errorf("OutputTokens = %d, want the cumulative final value 23 (summing the "+
			"deltas would give 36)", u.OutputTokens)
	}
	if u.CacheRead != 5 || u.CacheWrite != 1 {
		t.Errorf("cache counters = %d/%d, want 5/1", u.CacheRead, u.CacheWrite)
	}
}

func TestE2E_StreamIsFlushedIncrementally(t *testing.T) {
	t.Parallel()
	// A proxy that buffers the whole stream turns a live agent transcript
	// into a long pause followed by everything at once. Assert the first
	// chunk arrives before the upstream has finished.
	h := newHarness(t)
	release := make(chan struct{})
	h.up.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flush, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: ping\ndata: {\"type\":\"ping\"}\n\n")
		if flush != nil {
			flush.Flush()
		}
		<-release
		_, _ = io.WriteString(w, "event: done\ndata: {\"type\":\"done\"}\n\n")
	}
	defer close(release)

	resp := h.do("POST", "/v1/messages",
		`{"model":"claude-sonnet-4-6","max_tokens":10,"stream":true,"messages":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	first := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		first <- string(buf[:n])
	}()
	select {
	case got := <-first:
		if !strings.Contains(got, "ping") {
			t.Errorf("first chunk = %q, want the flushed ping", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no bytes arrived before the upstream finished: the stream is being buffered")
	}
}

func TestE2E_UpstreamErrorsAreRelayedVerbatim(t *testing.T) {
	t.Parallel()
	// An overloaded_error from Anthropic must reach the SDK as itself, so a
	// pipeline's retry logic works. Rewriting it into a proxy error would
	// make every upstream hiccup look like a cloop bug.
	h := newHarness(t)
	h.up.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`)
	}
	resp := h.do("POST", "/v1/messages", validBody)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "overloaded_error") {
		t.Errorf("body = %s, want the upstream error verbatim", body)
	}
	// It still counted against the budget: the upstream was reached.
	if got := h.sess.Usage().Requests; got != 1 {
		t.Errorf("Requests = %d, want 1", got)
	}
}

func TestE2E_UpstreamWWWAuthenticateIsNotRelayed(t *testing.T) {
	t.Parallel()
	// A 401 from Anthropic carries a challenge describing how to
	// authenticate to Anthropic. Passing it on would invite a pipeline to
	// act on a challenge that is not addressed to it.
	h := newHarness(t)
	h.up.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="anthropic"`)
		w.WriteHeader(http.StatusUnauthorized)
	}
	resp := h.do("POST", "/v1/messages", validBody)
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want it dropped", got)
	}
}

func TestE2E_RejectsUnusableSessionTokens(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cases := map[string]func(*http.Request){
		"no credential":  func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong secret":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+TokenPrefix+h.sess.ID+".00") },
		"unknown token":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+TokenPrefix+"aaaa.bbbb") },
		"an api key":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer sk-ant-api03-nope") },
		"basic auth":     func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") },
		"empty x-apikey": func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("X-Api-Key", "") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			resp := h.do("POST", "/v1/messages", validBody, mutate)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
			if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
				t.Errorf("WWW-Authenticate = %q, want a bearer challenge", got)
			}
		})
	}
	if n := h.up.count(); n != 0 {
		t.Errorf("the upstream saw %d unauthenticated requests", n)
	}
}

func TestE2E_RevokedSessionStopsRelayingImmediately(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if resp := h.do("POST", "/v1/messages", validBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if err := h.reg.Close(h.sess.ID, "operator revoked"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	resp := h.do("POST", "/v1/messages", validBody)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 after revocation", resp.StatusCode)
	}
	if n := h.up.count(); n != 1 {
		t.Errorf("upstream saw %d requests, want only the one before revocation", n)
	}
}

func TestE2E_OversizeBodyIsRefusedWithoutReachingTheUpstream(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(m *MintRequest) { m.Policy.MaxBodyBytes = 512 })
	big := `{"model":"claude-sonnet-4-6","max_tokens":10,"messages":[{"role":"user","content":"` +
		strings.Repeat("x", 4096) + `"}]}`
	resp := h.do("POST", "/v1/messages", big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if n := h.up.count(); n != 0 {
		t.Errorf("an oversize body reached the upstream")
	}
}

func TestE2E_RequestHeadersAreAllowlisted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.do("POST", "/v1/messages", validBody, func(r *http.Request) {
		r.Header.Set("Anthropic-Beta", "some-beta-feature")
		r.Header.Set("X-Forwarded-For", "10.0.0.1")
		r.Header.Set("Cookie", "session=leak-me")
		r.Header.Set("X-Custom-Injected", "nope")
	})
	seen := h.up.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests", len(seen))
	}
	hdr := seen[0].Header
	if got := hdr.Get("Anthropic-Beta"); got != "some-beta-feature" {
		t.Errorf("Anthropic-Beta = %q, want it forwarded", got)
	}
	for _, h := range []string{"X-Forwarded-For", "Cookie", "X-Custom-Injected"} {
		if got := hdr.Get(h); got != "" {
			t.Errorf("%s = %q, want it dropped by the allowlist", h, got)
		}
	}
	if ua := hdr.Get("User-Agent"); !strings.Contains(ua, "cloop-ci-proxy") {
		t.Errorf("User-Agent = %q, want the hub to identify itself", ua)
	}
}

func TestE2E_UpstreamUnreachableRefundsTheBudget(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(m *MintRequest) { m.Policy.MaxRequests = 3 })
	h.up.srv.Close() // the upstream is gone

	resp := h.do("POST", "/v1/messages", validBody)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	// A request that never reached the upstream must not have been charged:
	// otherwise a network blip eats a pipeline's whole allowance.
	if got := h.sess.Usage().Requests; got != 0 {
		t.Errorf("Requests = %d, want 0 after an unreachable upstream", got)
	}
}

func TestNew_RefusesWithoutAnUpstreamCredential(t *testing.T) {
	t.Parallel()
	if _, err := New(NewRegistry("https://hub.example.com"), Options{}); err == nil {
		t.Fatal("New accepted a proxy with nothing to relay to")
	}
	if _, err := New(nil, Options{Upstream: Upstream{APIKey: "k"}}); err == nil {
		t.Fatal("New accepted a nil registry")
	}
}
