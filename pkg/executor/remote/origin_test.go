package remote

// origin_test.go covers the hub's WebSocket Origin policy.
//
// The two failure directions have very different costs, so both are pinned
// here. Too strict and every legitimate agent is refused — the feature is
// simply broken. Too lax and a page on an attacker's site can drive the agent
// endpoint from an operator's browser. The tests below therefore assert the
// allow list is exactly as wide as it needs to be and no wider, including the
// near-miss hostnames a substring match would wrongly accept.

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// originStore is a minimal in-memory Store. The package already has one in
// memstore_test.go, but that file is in the external test package (so the e2e
// test can share it with pkg/executor/agent) and these tests are internal:
// checkOrigin and originHostOf are unexported, and testing an origin policy
// through the exported surface only would mean testing it through a WebSocket
// handshake, which is a lot of machinery between the assertion and the rule.
type originStore struct {
	mu          sync.Mutex
	enrollments map[string]EnrollmentRecord
	agents      map[string]AgentRecord
}

func newOriginStore() *originStore {
	return &originStore{
		enrollments: make(map[string]EnrollmentRecord),
		agents:      make(map[string]AgentRecord),
	}
}

func (s *originStore) PutEnrollment(rec EnrollmentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollments[rec.ID] = rec
	return nil
}

func (s *originStore) GetEnrollment(id string) (EnrollmentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.enrollments[id]
	if !ok {
		return EnrollmentRecord{}, fmt.Errorf("%w: %s", ErrTokenInvalid, id)
	}
	return rec, nil
}

// RedeemEnrollment claims atomically under the lock, matching what the SQLite
// implementation gets from a conditional UPDATE. A check-then-write fake would
// let a replay bug pass.
func (s *originStore) RedeemEnrollment(id, agentID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.enrollments[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrTokenInvalid, id)
	}
	if !rec.RedeemedAt.IsZero() {
		return fmt.Errorf("%w: %s", ErrTokenAlreadyUsed, id)
	}
	rec.RedeemedAt, rec.RedeemedAgentID = at, agentID
	s.enrollments[id] = rec
	return nil
}

func (s *originStore) RevokeEnrollment(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.enrollments[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrTokenInvalid, id)
	}
	rec.RevokedAt = at
	s.enrollments[id] = rec
	return nil
}

func (s *originStore) ListEnrollments() ([]EnrollmentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]EnrollmentRecord, 0, len(s.enrollments))
	for _, r := range s.enrollments {
		out = append(out, r)
	}
	return out, nil
}

func (s *originStore) PutAgent(rec AgentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[rec.AgentID] = rec
	return nil
}

func (s *originStore) GetAgent(agentID string) (AgentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.agents[agentID]
	if !ok {
		return AgentRecord{}, fmt.Errorf("%w: %s", ErrAgentNotFound, agentID)
	}
	return rec, nil
}

func (s *originStore) RevokeAgent(agentID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.agents[agentID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrAgentNotFound, agentID)
	}
	rec.RevokedAt = at
	s.agents[agentID] = rec
	return nil
}

func (s *originStore) TouchAgent(agentID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.agents[agentID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrAgentNotFound, agentID)
	}
	rec.LastSeen = at
	s.agents[agentID] = rec
	return nil
}

func (s *originStore) ListAgents() ([]AgentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AgentRecord, 0, len(s.agents))
	for _, r := range s.agents {
		out = append(out, r)
	}
	return out, nil
}

// newOriginHub builds a hub with an origin policy and nothing else. Its store
// is empty, so any request that gets past the origin check fails
// authentication — which is exactly the signal we want: 403 means the origin
// was refused, 401 means it was accepted and the request moved on.
func newOriginHub(t *testing.T, externalURL string, allowed []string) *Hub {
	t.Helper()
	h, err := NewHub(HubOptions{
		Store:          newOriginStore(),
		Registry:       executor.NewRegistry(),
		ExternalURL:    externalURL,
		AllowedOrigins: allowed,
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	return h
}

func TestHubCheckOrigin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		externalURL string
		allowed     []string
		host        string
		tls         bool              // the connection itself is TLS
		remote      string            // RemoteAddr; "" keeps httptest's 192.0.2.1
		forwarded   map[string]string // X-Forwarded-* headers
		origin      string
		want        bool
	}{
		// A real agent — Go, Python, curl — sends no Origin at all. Refusing
		// these would refuse the entire feature.
		{name: "no origin is the agent case", host: "hub.example.com", want: true},

		// Exact: scheme, host and port (Task 20394).
		{name: "same origin, plaintext", host: "hub.example.com", origin: "http://hub.example.com", want: true},
		{name: "same origin, TLS", host: "hub.example.com", tls: true, origin: "https://hub.example.com", want: true},
		{name: "same origin with port", host: "hub.example.com:8443", tls: true, origin: "https://hub.example.com:8443", want: true},
		{name: "loopback, same origin", host: "127.0.0.1:8080", origin: "http://127.0.0.1:8080", want: true},
		{name: "same host, different port", host: "hub.example.com:8443", tls: true, origin: "https://hub.example.com", want: false},
		{name: "same host, other scheme", host: "hub.example.com", origin: "https://hub.example.com", want: false},
		// Loopback is not a credential: another port of localhost is another
		// origin, and so is another loopback name for the same port.
		{name: "loopback, other port", host: "127.0.0.1:8080", origin: "http://127.0.0.1:3000", want: false},
		{name: "loopback name for a loopback address", host: "127.0.0.1:8080", origin: "http://localhost:8080", want: false},
		{name: "loopback page, remote hub", host: "hub.example.com", origin: "http://localhost:8080", want: false},
		{name: "loopback v6 page", host: "hub.example.com", origin: "http://[::1]:8080", want: false},

		// Behind a proxy that rewrites Host, the request's own origin cannot
		// be seen, so the deployment's own name has to be configured.
		{name: "external url", externalURL: "https://hub.example.com", host: "10.0.0.5:8080", origin: "https://hub.example.com", want: true},
		{name: "external url with port", externalURL: "https://hub.example.com:8443", host: "internal:8080", origin: "https://hub.example.com:8443", want: true},
		{name: "external url, other scheme", externalURL: "https://hub.example.com", host: "internal", origin: "http://hub.example.com", want: false},
		{name: "external url, other port", externalURL: "https://hub.example.com", host: "internal", origin: "https://hub.example.com:8443", want: false},

		// Or the proxy says so — and is believed only from loopback.
		{name: "loopback proxy reports the origin", host: "127.0.0.1:8081", remote: "127.0.0.1:40000",
			forwarded: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "hub.example.com:8888"},
			origin:    "https://hub.example.com:8888", want: true},
		{name: "a proxy elsewhere is not believed", host: "127.0.0.1:8081", remote: "203.0.113.9:40000",
			forwarded: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "hub.example.com:8888"},
			origin:    "https://hub.example.com:8888", want: false},
		{name: "a client cannot choose the scheme it is judged by", host: "hub.example.com", remote: "203.0.113.9:40000",
			forwarded: map[string]string{"X-Forwarded-Proto": "https"}, origin: "https://hub.example.com", want: false},

		{name: "allowlist bare host means https", allowed: []string{"ops.example.com"}, host: "hub.example.com", origin: "https://ops.example.com", want: true},
		{name: "allowlist bare host is not http", allowed: []string{"ops.example.com"}, host: "hub.example.com", origin: "http://ops.example.com", want: false},
		{name: "allowlist host:port", allowed: []string{"ops.example.com:8443"}, host: "hub.example.com", origin: "https://ops.example.com:8443", want: true},
		{name: "allowlist full origin", allowed: []string{"https://ops.example.com"}, host: "hub.example.com", origin: "https://ops.example.com", want: true},
		{name: "allowlist plaintext origin", allowed: []string{"http://ops.lan:8081"}, host: "hub.example.com", origin: "http://ops.lan:8081", want: true},

		// The refusals.
		{name: "cross origin", host: "hub.example.com", origin: "https://evil.example", want: false},
		{name: "external url set, stranger refused", externalURL: "https://hub.example.com", host: "hub.example.com", origin: "https://evil.example", want: false},
		// Suffix confusion: the classic bypass. "hub.example.com.evil.test"
		// is a hostname the attacker fully controls.
		{name: "suffix confusion", externalURL: "https://hub.example.com", host: "hub.example.com", origin: "https://hub.example.com.evil.test", want: false},
		{name: "prefix confusion", externalURL: "https://hub.example.com", host: "hub.example.com", origin: "https://evilhub.example.com", want: false},
		{name: "loopback lookalike", host: "hub.example.com", origin: "http://localhost.evil.test", want: false},
		{name: "allowlist near miss", allowed: []string{"ops.example.com"}, host: "hub.example.com", origin: "https://ops.example.com.evil.test", want: false},
		{name: "malformed origin", host: "hub.example.com", origin: "://not a url", want: false},
		{name: "null origin (sandboxed iframe)", host: "hub.example.com", origin: "null", want: false},
		{name: "empty allowlist entries are ignored", allowed: []string{"", "  "}, host: "hub.example.com", origin: "https://evil.example", want: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newOriginHub(t, c.externalURL, c.allowed)
			r := httptest.NewRequest(http.MethodGet, "/api/executors/connect", nil)
			r.Host = c.host
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if c.remote != "" {
				r.RemoteAddr = c.remote
			}
			for k, v := range c.forwarded {
				r.Header.Set(k, v)
			}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			d := h.checkOrigin(r)
			if d.allowed != c.want {
				t.Fatalf("checkOrigin(host=%q, origin=%q) = %v (%s), want %v",
					c.host, c.origin, d.allowed, d.reason, c.want)
			}
			if !d.allowed && strings.TrimSpace(d.reason) == "" {
				t.Error("a refusal must carry a reason the operator can act on")
			}
		})
	}
}

// TestHubUsesTheDashboardsForwardingRule: the hub is handed the dashboard's
// rule for whose X-Forwarded-* to believe, and tells it of every refusal, so
// one request is judged and recorded alike at both endpoints.
func TestHubUsesTheDashboardsForwardingRule(t *testing.T) {
	t.Parallel()
	var refused []string
	h, err := NewHub(HubOptions{
		Store:            newOriginStore(),
		Registry:         executor.NewRegistry(),
		ForwardedTrusted: func(r *http.Request) bool { return strings.HasPrefix(r.RemoteAddr, "10.") },
		OnOriginRefused:  func(r *http.Request) { refused = append(refused, r.Header.Get("Origin")) },
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/executors/connect", nil)
	r.Host = "cloop-hub:8080"
	r.RemoteAddr = "10.4.0.9:5000"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "hub.example.com")
	r.Header.Set("Origin", "https://hub.example.com")
	if d := h.checkOrigin(r); !d.allowed {
		t.Fatalf("an ingress the rule trusts was not believed: %s", d.reason)
	}
	r.Header.Set("Origin", "https://evil.example")
	if d := h.checkOrigin(r); d.allowed {
		t.Fatal("a foreign origin was admitted")
	}
	if len(refused) != 1 || refused[0] != "https://evil.example" {
		t.Errorf("OnOriginRefused saw %v", refused)
	}
}

// TestHubServeHTTPRejectsCrossOrigin checks the wire behaviour, not just the
// predicate: an unrecognised Origin gets 403 with a usable message, and never
// reaches the upgrade.
func TestHubServeHTTPRejectsCrossOrigin(t *testing.T) {
	t.Parallel()
	h := newOriginHub(t, "https://hub.example.com", nil)

	r := httptest.NewRequest(http.MethodGet, "/api/executors/connect", nil)
	r.Host = "hub.example.com"
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Authorization", "Bearer clet1.aaaa.bbbb.cccc")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %q", w.Body.String())
	}
	if !strings.Contains(body["error"], "evil.example") {
		t.Errorf("error %q does not name the rejected origin", body["error"])
	}
	// The remedy has to be in the message. "forbidden" sends an operator to
	// the source; naming the config keys sends them to the fix.
	if !strings.Contains(body["error"], "allowed_origins") && !strings.Contains(body["error"], "external_url") {
		t.Errorf("error %q does not say how to allow the origin", body["error"])
	}
	if w.Header().Get("Upgrade") != "" {
		t.Error("a refused request must not be upgraded")
	}
}

// TestHubOriginCheckPrecedesTokenRedemption is the reason checkOrigin runs
// first in ServeHTTP.
//
// Redemption is single-use and destructive. If a cross-origin request reached
// Redeem, script on an attacker's page — or merely a link the operator clicked
// with ?token= in it — would spend an enrollment token the operator then has
// to re-mint, and the device that token was meant for would fail to enroll
// with "already redeemed". Refusing before any state changes makes a rejected
// request cost nothing.
func TestHubOriginCheckPrecedesTokenRedemption(t *testing.T) {
	t.Parallel()
	store := newOriginStore()
	h, err := NewHub(HubOptions{
		Store:       store,
		Registry:    executor.NewRegistry(),
		ExternalURL: "https://hub.example.com",
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}

	token, rec, err := Mint(store, MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/executors/connect?token="+token, nil)
	r.Host = "hub.example.com"
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	after, err := store.GetEnrollment(rec.ID)
	if err != nil {
		t.Fatalf("GetEnrollment: %v", err)
	}
	if after.Redeemed() {
		t.Fatal("a cross-origin request consumed the enrollment token; " +
			"the origin check must run before Redeem")
	}
}

// TestHubAllowsAgentWithoutOrigin confirms the normal path is untouched: a
// headless agent still reaches authentication, and fails there (401) rather
// than at the origin check (403).
func TestHubAllowsAgentWithoutOrigin(t *testing.T) {
	t.Parallel()
	h := newOriginHub(t, "https://hub.example.com", nil)

	r := httptest.NewRequest(http.MethodGet, "/api/executors/connect", nil)
	r.Host = "hub.example.com"
	r.Header.Set("Authorization", "Bearer clac1.unknown.unknown.unknown")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code == http.StatusForbidden {
		t.Fatal("an agent sending no Origin was refused by the origin check")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (bad credential, origin accepted)", w.Code)
	}
}
