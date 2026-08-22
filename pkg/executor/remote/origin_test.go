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
		origin      string
		want        bool
	}{
		// A real agent — Go, Python, curl — sends no Origin at all. Refusing
		// these would refuse the entire feature.
		{"no origin is the agent case", "", nil, "hub.example.com", "", true},

		{"same origin", "", nil, "hub.example.com", "https://hub.example.com", true},
		{"same origin with port", "", nil, "hub.example.com:8443", "https://hub.example.com:8443", true},
		{"same host, different port", "", nil, "hub.example.com:8443", "https://hub.example.com", true},

		{"loopback name", "", nil, "hub.example.com", "http://localhost:8080", true},
		{"loopback v4", "", nil, "hub.example.com", "http://127.0.0.1:8080", true},
		{"loopback v6", "", nil, "hub.example.com", "http://[::1]:8080", true},

		// Behind a proxy that rewrites Host, same-origin cannot fire, so the
		// deployment's own name has to be configured.
		{"external url host", "https://hub.example.com", nil, "10.0.0.5:8080", "https://hub.example.com", true},
		{"external url with port", "https://hub.example.com:8443", nil, "internal:8080", "https://hub.example.com:8443", true},
		{"external url scheme mismatch still matches host", "https://hub.example.com", nil, "internal", "http://hub.example.com", true},

		{"allowlist bare host", "", []string{"ops.example.com"}, "hub.example.com", "https://ops.example.com", true},
		{"allowlist host:port", "", []string{"ops.example.com:8443"}, "hub.example.com", "https://ops.example.com:8443", true},
		{"allowlist full origin", "", []string{"https://ops.example.com"}, "hub.example.com", "https://ops.example.com", true},

		// The refusals.
		{"cross origin", "", nil, "hub.example.com", "https://evil.example", false},
		{"external url set, stranger refused", "https://hub.example.com", nil, "hub.example.com", "https://evil.example", false},
		// Suffix confusion: the classic bypass. "hub.example.com.evil.test"
		// is a hostname the attacker fully controls.
		{"suffix confusion", "https://hub.example.com", nil, "hub.example.com", "https://hub.example.com.evil.test", false},
		{"prefix confusion", "https://hub.example.com", nil, "hub.example.com", "https://evilhub.example.com", false},
		{"loopback lookalike", "", nil, "hub.example.com", "http://localhost.evil.test", false},
		{"allowlist near miss", "", []string{"ops.example.com"}, "hub.example.com", "https://ops.example.com.evil.test", false},
		{"malformed origin", "", nil, "hub.example.com", "://not a url", false},
		{"null origin (sandboxed iframe)", "", nil, "hub.example.com", "null", false},
		{"empty allowlist entries are ignored", "", []string{"", "  "}, "hub.example.com", "https://evil.example", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newOriginHub(t, c.externalURL, c.allowed)
			r := httptest.NewRequest(http.MethodGet, "/api/executors/connect", nil)
			r.Host = c.host
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

func TestOriginHostOf(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://hub.example.com":      "hub.example.com",
		"https://hub.example.com:8443": "hub.example.com:8443",
		"https://hub.example.com/":     "hub.example.com",
		"hub.example.com":              "hub.example.com",
		"hub.example.com:8443":         "hub.example.com:8443",
		"hub.example.com/":             "hub.example.com",
		"":                             "",
		"   ":                          "",
		"://broken":                    "",
	}
	for in, want := range cases {
		if got := originHostOf(in); got != want {
			t.Errorf("originHostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
