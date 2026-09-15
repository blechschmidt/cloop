package kubeguard

// e2e_test.go drives the monitor the way a sandbox would: a real HTTP client,
// a real proxy, and a stand-in API server that records what actually reached
// it.
//
// The upstream recorder is what makes these tests worth more than the policy
// unit tests. A refusal that returns 403 while still forwarding the request
// would pass a test that only reads the response; here, every denial test also
// asserts the API server was never called at all.

import (
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

// fakeAPIServer stands in for a cluster. It records every request it receives
// and answers 200 with a small JSON body.
type fakeAPIServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
}

func newFakeAPIServer(t *testing.T) *fakeAPIServer {
	t.Helper()
	f := &fakeAPIServer{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, r.Clone(r.Context()))
		f.bodies = append(f.bodies, string(body))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"kind":"PodList","items":[],"path":%q}`, r.URL.Path)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPIServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeAPIServer) last() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return nil
	}
	return f.requests[len(f.requests)-1]
}

// harness is one monitor in front of one fake cluster, plus a client holding
// the session token the sandbox would hold.
type harness struct {
	api    *fakeAPIServer
	reg    *Registry
	proxy  *Proxy
	server *httptest.Server
	token  string
	sess   *Session

	mu     sync.Mutex
	events []Event
}

func newHarness(t *testing.T, policy Policy) *harness {
	t.Helper()
	h := &harness{api: newFakeAPIServer(t)}

	reg, err := NewRegistry("https://monitor.example:8444")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	reg.OnEvent = func(e Event) {
		h.mu.Lock()
		h.events = append(h.events, e)
		h.mu.Unlock()
	}
	h.reg = reg

	px, err := New(reg, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.proxy = px
	h.server = httptest.NewServer(px)
	t.Cleanup(func() {
		h.server.Close()
		_ = px.Close()
	})

	m, err := reg.Mint(MintRequest{
		Kubeconfig: testInsecureKubeconfig(h.api.srv.URL),
		Policy:     policy,
		ProjectID:  "/srv/app",
		ExecutorID: "exec-1",
		Actor:      "dev@example.com",
		GrantID:    "grant-1",
		LeaseID:    "lease-1",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.token, h.sess = m.Token, m.Session
	return h
}

// do issues a request as the sandbox would: at the monitor, with the session
// token.
func (h *harness) do(t *testing.T, method, path string, body io.Reader, headers ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, h.server.URL+path, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *harness) eventKinds() []EventKind {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]EventKind, 0, len(h.events))
	for _, e := range h.events {
		out = append(out, e.Kind)
	}
	return out
}

func (h *harness) lastDenial(t *testing.T) Event {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.events) - 1; i >= 0; i-- {
		if h.events[i].Kind == EventRequestDenied {
			return h.events[i]
		}
	}
	t.Fatalf("no request_denied event; got %v", h.eventKinds())
	return Event{}
}

// decodeStatus reads the metav1.Status body a refusal returns.
func decodeStatus(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var out map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("refusal body is not JSON (%v): %s", err, body)
	}
	return out
}

// TestReadIsForwardedWithTheRealCredential is the happy path, and it checks
// the substitution in both directions: the sandbox never sent the cluster
// token, and the cluster nevertheless received it.
func TestReadIsForwardedWithTheRealCredential(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())

	resp := h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if h.api.count() != 1 {
		t.Fatalf("the cluster saw %d requests, want 1", h.api.count())
	}

	up := h.api.last()
	if got := up.Header.Get("Authorization"); got != "Bearer "+testClusterToken {
		t.Errorf("upstream Authorization = %q, want the cluster token", got)
	}
	if up.URL.Path != "/api/v1/namespaces/app/pods" {
		t.Errorf("upstream path = %q", up.URL.Path)
	}
	// The sandbox's own token must not travel onward.
	if strings.Contains(up.Header.Get("Authorization"), h.token) {
		t.Error("the session token was forwarded to the cluster")
	}
}

func TestQueryStringIsPreserved(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods?labelSelector=app%3Dweb&limit=5", nil)
	up := h.api.last()
	if up == nil {
		t.Fatal("the cluster saw no request")
	}
	if got := up.URL.Query().Get("labelSelector"); got != "app=web" {
		t.Errorf("labelSelector = %q, want app=web", got)
	}
	if got := up.URL.Query().Get("limit"); got != "5" {
		t.Errorf("limit = %q, want 5", got)
	}
}

// TestWriteIsRefusedAndNeverReachesTheCluster is the headline behaviour.
func TestWriteIsRefusedAndNeverReachesTheCluster(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())

	resp := h.do(t, http.MethodPost, "/api/v1/namespaces/app/pods",
		strings.NewReader(`{"kind":"Pod"}`), "Content-Type", "application/json")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if h.api.count() != 0 {
		t.Fatalf("the cluster saw %d requests; a refused write must not be forwarded", h.api.count())
	}

	// The refusal is a Status object, so kubectl prints the message.
	st := decodeStatus(t, resp)
	if st["kind"] != "Status" || st["status"] != "Failure" {
		t.Errorf("refusal is not a metav1.Status: %v", st)
	}
	msg, _ := st["message"].(string)
	if !strings.Contains(msg, "read-only") {
		t.Errorf("message does not explain the refusal: %q", msg)
	}

	ev := h.lastDenial(t)
	if ev.Reason != DenyVerbNotAllowed {
		t.Errorf("audit reason = %q, want %q", ev.Reason, DenyVerbNotAllowed)
	}
	if ev.Verb != VerbCreate || ev.Namespace != "app" || ev.Resource != "pods" {
		t.Errorf("audit row does not describe the request: %+v", ev)
	}
	if ev.ProjectID != "/srv/app" || ev.Actor != "dev@example.com" || ev.GrantID != "grant-1" {
		t.Errorf("audit row lost its attribution: %+v", ev)
	}
}

// TestExecIsRefusedForEveryMethod is the bypass that makes a verb-only
// allowlist unsafe: the API server serves exec over GET as well as POST.
func TestExecIsRefusedForEveryMethod(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, sub := range []string{"exec", "attach", "portforward"} {
			t.Run(method+"/"+sub, func(t *testing.T) {
				before := h.api.count()
				resp := h.do(t, method,
					"/api/v1/namespaces/app/pods/web-0/"+sub+"?command=sh", nil)
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("status = %d, want 403", resp.StatusCode)
				}
				if h.api.count() != before {
					t.Error("the request reached the cluster")
				}
			})
		}
	}
	if ev := h.lastDenial(t); ev.Reason != DenyDangerousSubresource {
		t.Errorf("audit reason = %q, want %q", ev.Reason, DenyDangerousSubresource)
	}
}

func TestNamespaceConfinementIsEnforcedOnTheRequest(t *testing.T) {
	policy := Policy{Namespaces: []string{"app"}}
	h := newHarness(t, policy)

	t.Run("granted namespace", func(t *testing.T) {
		if resp := h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil); resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})
	// This is the request a kubeconfig's default namespace cannot stop.
	t.Run("kubectl -n kube-system", func(t *testing.T) {
		before := h.api.count()
		resp := h.do(t, http.MethodGet, "/api/v1/namespaces/kube-system/secrets", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
		if h.api.count() != before {
			t.Error("a cross-namespace read reached the cluster")
		}
		if ev := h.lastDenial(t); ev.Reason != DenyNamespaceNotAllowed {
			t.Errorf("reason = %q, want %q", ev.Reason, DenyNamespaceNotAllowed)
		}
	})
	t.Run("all namespaces", func(t *testing.T) {
		before := h.api.count()
		resp := h.do(t, http.MethodGet, "/api/v1/pods", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
		if h.api.count() != before {
			t.Error("a cluster-wide read reached the cluster")
		}
	})
	// And the traversal spelling of the same request.
	t.Run("path traversal", func(t *testing.T) {
		before := h.api.count()
		resp := h.do(t, http.MethodGet, "/api/v1/namespaces/app/../kube-system/secrets", nil)
		if resp.StatusCode == http.StatusOK {
			t.Error("a traversal path was allowed")
		}
		if h.api.count() != before {
			t.Error("a traversal path reached the cluster")
		}
	})
}

// TestImpersonationHeadersAreStripped: a kubeconfig a developer uploads is
// frequently a privileged one, and forwarding Impersonate-User would hand the
// sandbox every identity in the cluster through a header.
func TestImpersonationHeadersAreStripped(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil,
		"Impersonate-User", "system:admin",
		"Impersonate-Group", "system:masters",
		"Impersonate-Uid", "0",
		"Impersonate-Extra-Scopes", "everything",
	)
	up := h.api.last()
	if up == nil {
		t.Fatal("the cluster saw no request")
	}
	for k := range up.Header {
		if isImpersonation(k) {
			t.Errorf("impersonation header %q reached the cluster with value %q", k, up.Header.Get(k))
		}
	}
}

func TestHopByHopHeadersAreStripped(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil,
		"Proxy-Authorization", "Basic c21circles",
		"Te", "trailers",
	)
	up := h.api.last()
	if up == nil {
		t.Fatal("the cluster saw no request")
	}
	if got := up.Header.Get("Proxy-Authorization"); got != "" {
		t.Errorf("Proxy-Authorization reached the cluster: %q", got)
	}
}

func TestUpgradeRequestsAreRefused(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	resp := h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods?watch=true", nil,
		"Connection", "Upgrade", "Upgrade", "websocket")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if h.api.count() != 0 {
		t.Error("an upgrade request reached the cluster")
	}
	if ev := h.lastDenial(t); ev.Reason != DenyProtocolUpgrade {
		t.Errorf("reason = %q, want %q", ev.Reason, DenyProtocolUpgrade)
	}
}

func TestOversizedBodyIsRefusedRatherThanTruncated(t *testing.T) {
	// A harness each. An aborted chunked upload is the one case where the
	// upstream may or may not have seen a partial request by the time the
	// client's Do returns, so sharing a request counter across these subtests
	// makes them order-dependent for a reason that has nothing to do with
	// what they assert.
	policy := Policy{Verbs: []string{"create"}, MaxBodyBytes: 64}

	// Declared length over the cap: refused before a byte is read.
	t.Run("declared", func(t *testing.T) {
		h := newHarness(t, policy)
		resp := h.do(t, http.MethodPost, "/api/v1/namespaces/app/pods",
			strings.NewReader(strings.Repeat("x", 512)))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		if h.api.count() != 0 {
			t.Error("an oversized body reached the cluster")
		}
		if ev := h.lastDenial(t); ev.Reason != DenyBodyTooLarge {
			t.Errorf("reason = %q, want %q", ev.Reason, DenyBodyTooLarge)
		}
	})

	// An undeclared (chunked) body has to be caught while streaming. The
	// earlier implementation truncated here, which made the API server answer
	// with a parse error and blamed the sandbox's JSON for the hub's limit.
	t.Run("chunked", func(t *testing.T) {
		h := newHarness(t, policy)
		req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/namespaces/app/pods",
			io.NopCloser(strings.NewReader(strings.Repeat("y", 4096))))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+h.token)
		req.ContentLength = -1 // force chunked
		resp, err := h.server.Client().Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("an oversized chunked body was accepted")
		}
		// Whatever the upstream did or did not see, it must not have seen the
		// whole body: that is what "refused rather than truncated" means from
		// the cluster's side.
		h.api.mu.Lock()
		defer h.api.mu.Unlock()
		for _, b := range h.api.bodies {
			if len(b) > int(policy.MaxBodyBytes) {
				t.Errorf("the cluster received %d body bytes, over the %d cap",
					len(b), policy.MaxBodyBytes)
			}
		}
	})

	// A body within the cap still arrives whole.
	t.Run("within the cap", func(t *testing.T) {
		h := newHarness(t, policy)
		resp := h.do(t, http.MethodPost, "/api/v1/namespaces/app/pods",
			strings.NewReader(`{"kind":"Pod"}`))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if h.api.count() != 1 {
			t.Fatalf("the cluster saw %d requests, want 1", h.api.count())
		}
		h.api.mu.Lock()
		body := h.api.bodies[0]
		h.api.mu.Unlock()
		if body != `{"kind":"Pod"}` {
			t.Errorf("the cluster received %q, want the whole body", body)
		}
	})
}

// --- authentication -------------------------------------------------------

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())

	cases := []struct{ name, header string }{
		{"no credential", ""},
		{"wrong token", "Bearer " + h.sess.ID + ".not-the-secret"},
		{"unknown session", "Bearer nosuchsession.secret"},
		{"not a bearer", "Basic dXNlcjpwYXNz"},
		{"malformed", "Bearer "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet,
				h.server.URL+"/api/v1/namespaces/app/pods", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, err := h.server.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
	if h.api.count() != 0 {
		t.Errorf("the cluster saw %d unauthenticated requests", h.api.count())
	}
}

// TestBearerSchemeIsMatchedCaseInsensitively: RFC 7235 says the scheme is
// case-insensitive, and a client that sends "bearer" is not an attacker.
func TestBearerSchemeIsMatchedCaseInsensitively(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/namespaces/app/pods", nil)
		req.Header.Set("Authorization", scheme+" "+h.token)
		resp, err := h.server.Client().Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("scheme %q: status = %d, want 200", scheme, resp.StatusCode)
		}
	}
}

func TestRevokedSessionStopsWorkingImmediately(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	if resp := h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil); resp.StatusCode != 200 {
		t.Fatalf("status = %d before revocation, want 200", resp.StatusCode)
	}

	h.reg.Close(h.sess.ID, "operator revoked")

	before := h.api.count()
	resp := h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d after revocation, want 401", resp.StatusCode)
	}
	if h.api.count() != before {
		t.Error("a revoked session still reached the cluster")
	}
	msg, _ := decodeStatus(t, resp)["message"].(string)
	if !strings.Contains(msg, "revoked") {
		t.Errorf("message does not say the session was revoked: %q", msg)
	}
}

func TestExpiredSessionStopsWorking(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())

	// Move the registry's clock past the session's expiry.
	h.reg.Now = func() time.Time { return h.sess.ExpiresAt.Add(time.Second) }

	before := h.api.count()
	resp := h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if h.api.count() != before {
		t.Error("an expired session still reached the cluster")
	}
	msg, _ := decodeStatus(t, resp)["message"].(string)
	if !strings.Contains(msg, "expired") {
		t.Errorf("message does not say the session expired: %q", msg)
	}
}

func TestSessionCountersAndClosingRow(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil)
	h.do(t, http.MethodPost, "/api/v1/namespaces/app/pods", strings.NewReader(`{}`))

	if st := h.sess.Stats(); st.Allowed != 1 || st.Denied != 1 {
		t.Errorf("stats = %+v, want 1 allowed and 1 denied", st)
	}

	h.reg.Close(h.sess.ID, "lease released")
	h.mu.Lock()
	defer h.mu.Unlock()
	last := h.events[len(h.events)-1]
	if last.Kind != EventSessionClosed {
		t.Fatalf("last event = %q, want %q", last.Kind, EventSessionClosed)
	}
	if !strings.Contains(last.Detail, "allowed=1") || !strings.Contains(last.Detail, "denied=1") {
		t.Errorf("closing row lost the counters: %q", last.Detail)
	}
}

// TestTransportsAreNotLeakedAcrossSessions: each session gets its own
// connection pool, because the TLS material is per cluster — and nothing told
// the proxy when the registry reaped a session, so before pruning existed the
// map grew for the life of the process, one idle pool per session ever minted.
func TestTransportsAreNotLeakedAcrossSessions(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	// Options.Transport is set to nil here so the real per-session path runs;
	// newHarness leaves it nil already.
	for i := 0; i < transportPruneThreshold+8; i++ {
		m, err := h.reg.Mint(MintRequest{Kubeconfig: testInsecureKubeconfig(h.api.srv.URL)})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if _, err := h.proxy.transportFor(m.Session); err != nil {
			t.Fatalf("transportFor: %v", err)
		}
		// Retire it the way the TTL would.
		h.reg.Close(m.Session.ID, "test")
		h.reg.ReapExpired()
	}

	h.proxy.mu.Lock()
	n := len(h.proxy.transport)
	h.proxy.mu.Unlock()
	if n > transportPruneThreshold {
		t.Errorf("proxy holds %d transports after %d retired sessions; the sweep did not run",
			n, transportPruneThreshold+8)
	}
}
