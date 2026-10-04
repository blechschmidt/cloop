package kubeguard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// answerAnyway is an upstream transport that reads the request body until it
// fails and then answers 200 regardless: deterministically, what the race
// between streaming a capped body and the upstream's answer delivered in CI,
// where an upstream answering once the stream broke off won, and RoundTrip
// returned its answer with the cap's error swallowed (Task 20371).
type answerAnyway struct{ read int }

func (a *answerAnyway) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		n, _ := io.Copy(io.Discard, r.Body)
		a.read = int(n)
		_ = r.Body.Close()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"kind":"Pod"}`)),
		Request:    r,
	}, nil
}

func newTransportHarness(t *testing.T, policy Policy, tr http.RoundTripper) (*harness, *httptest.Server) {
	t.Helper()
	h := &harness{}
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
	px, err := New(reg, Options{Transport: tr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.proxy = px
	srv := httptest.NewServer(px)
	h.server = srv
	t.Cleanup(func() { srv.Close(); _ = px.Close() })
	m, err := reg.Mint(MintRequest{
		Kubeconfig: testInsecureKubeconfig("https://cluster.invalid:6443"),
		Policy:     policy, ProjectID: "/srv/app", ExecutorID: "exec-1",
		Actor: "dev@example.com", GrantID: "grant-1", LeaseID: "lease-1",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.token, h.sess = m.Token, m.Session
	return h, srv
}

func chunkedPost(t *testing.T, h *harness, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/namespaces/app/pods",
		io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.ContentLength = -1 // force chunked
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestAnswerToAnOversizedBodyIsNotRelayed: whatever the upstream answers once
// the cap has tripped, the sandbox is told its body was too large.
func TestAnswerToAnOversizedBodyIsNotRelayed(t *testing.T) {
	policy := Policy{Verbs: []string{"create"}, MaxBodyBytes: 64}
	up := &answerAnyway{}
	h, _ := newTransportHarness(t, policy, up)

	resp := chunkedPost(t, h, strings.Repeat("y", 4096))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the upstream's answer to a refused body was relayed", resp.StatusCode)
	}
	if up.read > int(policy.MaxBodyBytes) {
		t.Errorf("the upstream read %d body bytes, over the %d cap", up.read, policy.MaxBodyBytes)
	}
	if ev := h.lastDenial(t); ev.Reason != DenyBodyTooLarge {
		t.Errorf("reason = %q, want %q", ev.Reason, DenyBodyTooLarge)
	}
}

// TestChunkedBodyExactlyAtTheCapPasses: a body of exactly MaxBodyBytes is
// within the cap whether its length was declared or not.
func TestChunkedBodyExactlyAtTheCapPasses(t *testing.T) {
	policy := Policy{Verbs: []string{"create"}, MaxBodyBytes: 64}
	h := newHarness(t, policy)
	body := strings.Repeat("z", int(policy.MaxBodyBytes))

	resp := chunkedPost(t, h, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a chunked body of exactly the cap", resp.StatusCode)
	}
	h.api.mu.Lock()
	defer h.api.mu.Unlock()
	if len(h.api.bodies) != 1 || h.api.bodies[0] != body {
		t.Fatalf("the cluster did not receive the whole %d-byte body: %d request(s)", len(body), len(h.api.bodies))
	}
}
