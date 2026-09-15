package claudeproxy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func testMint(t *testing.T, r *Registry, mutate ...func(*MintRequest)) *Minted {
	t.Helper()
	req := MintRequest{
		Policy:     Policy{Models: []string{"claude-sonnet-4-6"}, MaxRequests: 10},
		RuleID:     "rule-1",
		RuleName:   "acme tool",
		Repository: "acme/tool",
		Ref:        "refs/heads/main",
		Workflow:   "release",
		Actor:      "dana",
		TTL:        30 * time.Minute,
	}
	for _, m := range mutate {
		m(&req)
	}
	got, err := r.Mint(req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return got
}

func TestMint_TokenShapeAndAuthentication(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com/api/ci/anthropic")
	m := testMint(t, r)

	if !strings.HasPrefix(m.Token, TokenPrefix) {
		t.Errorf("token %q does not carry the scanner-visible prefix %q", m.Token, TokenPrefix)
	}
	if !strings.Contains(m.Token, m.Session.ID+".") {
		t.Errorf("token does not carry its session id")
	}
	if m.BaseURL != "https://hub.example.com/api/ci/anthropic" {
		t.Errorf("BaseURL = %q", m.BaseURL)
	}

	got, err := r.Authenticate(m.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != m.Session.ID {
		t.Errorf("authenticated a different session")
	}
	if got.LastUsed().IsZero() {
		t.Error("LastUsed was not stamped")
	}
}

func TestMint_RefusesAPolicyWithNoModels(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com")
	// A session that can authenticate and use no model reads as a broken
	// proxy rather than as a policy decision.
	if _, err := r.Mint(MintRequest{Policy: Policy{}, TTL: time.Minute}); err == nil {
		t.Fatal("Mint accepted a policy with an empty model allowlist")
	}
}

func TestAuthenticate_RefusalsAreIndistinguishable(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com")
	m := testMint(t, r)
	id := m.Session.ID

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no prefix", "abc.def"},
		{"prefix only", TokenPrefix},
		{"no separator", TokenPrefix + "abcdef"},
		{"empty secret", TokenPrefix + id + "."},
		{"unknown id", TokenPrefix + "deadbeefdeadbeefdeadbeef.aaaa"},
		{"right id, wrong secret", TokenPrefix + id + ".0000000000000000000000000000000000000000000000000000000000000000"},
		{"an Anthropic key by mistake", "sk-ant-api03-not-a-session-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Authenticate(tc.token)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate(%q) = %v, want ErrUnauthenticated", tc.name, err)
			}
			// The message must not distinguish the cases: a caller probing
			// for a live session should not learn which half was wrong.
			if err.Error() != ErrUnauthenticated.Error() {
				t.Errorf("error = %q, want the undifferentiated %q", err, ErrUnauthenticated)
			}
		})
	}
}

func TestAuthenticate_RefusesExpiredAndClosedSessions(t *testing.T) {
	t.Parallel()
	now := time.Now()
	r := NewRegistry("https://hub.example.com")
	r.SetClock(func() time.Time { return now })

	expiring := testMint(t, r, func(m *MintRequest) { m.TTL = 5 * time.Minute })
	revoked := testMint(t, r)

	if _, err := r.Authenticate(expiring.Token); err != nil {
		t.Fatalf("Authenticate before expiry: %v", err)
	}
	now = now.Add(6 * time.Minute)
	if _, err := r.Authenticate(expiring.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("an expired session still authenticated: %v", err)
	}

	if err := r.Close(revoked.Session.ID, "operator revoked"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := r.Authenticate(revoked.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a revoked session still authenticated: %v", err)
	}
	if !revoked.Session.Closed() || revoked.Session.CloseReason() != "operator revoked" {
		t.Errorf("close reason = %q", revoked.Session.CloseReason())
	}
	// Close is idempotent.
	if err := r.Close(revoked.Session.ID, "again"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("second Close = %v, want ErrSessionNotFound", err)
	}
}

func TestClaimRequest_IsExactUnderConcurrency(t *testing.T) {
	t.Parallel()
	// The budget is the only thing standing between a runaway agent loop and
	// an unbounded bill, so two goroutines racing for the last unit must not
	// both win.
	r := NewRegistry("https://hub.example.com")
	m := testMint(t, r, func(mr *MintRequest) { mr.Policy.MaxRequests = 50 })

	const workers = 32
	var wg sync.WaitGroup
	granted := make([]int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if m.Session.claimRequest() {
					granted[i]++
				}
			}
		}(i)
	}
	wg.Wait()
	total := 0
	for _, g := range granted {
		total += g
	}
	if total != 50 {
		t.Errorf("granted %d requests against a budget of 50", total)
	}
	if got := m.Session.Usage().Requests; got != 50 {
		t.Errorf("Usage().Requests = %d, want 50", got)
	}
	if got := m.Session.RemainingRequests(); got != 0 {
		t.Errorf("RemainingRequests() = %d, want 0", got)
	}
}

func TestRemainingRequests_UnlimitedIsReportedAsSuch(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com")
	m := testMint(t, r, func(mr *MintRequest) { mr.Policy.MaxRequests = 0 })
	if got := m.Session.RemainingRequests(); got != -1 {
		t.Errorf("RemainingRequests() = %d, want -1", got)
	}
	if !m.Session.claimRequest() {
		t.Error("an uncapped session refused a request")
	}
}

func TestTTL_IsClamped(t *testing.T) {
	t.Parallel()
	now := time.Now()
	r := NewRegistry("https://hub.example.com")
	r.SetClock(func() time.Time { return now })

	long := testMint(t, r, func(m *MintRequest) { m.TTL = 30 * 24 * time.Hour })
	if got := long.Session.ExpiresAt.Sub(now); got != MaxTTL {
		t.Errorf("TTL = %v, want it clamped to %v", got, MaxTTL)
	}
	short := testMint(t, r, func(m *MintRequest) { m.TTL = time.Second })
	if got := short.Session.ExpiresAt.Sub(now); got != MinTTL {
		t.Errorf("TTL = %v, want it raised to %v", got, MinTTL)
	}
}

func TestReapExpired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	r := NewRegistry("https://hub.example.com")
	r.SetClock(func() time.Time { return now })

	testMint(t, r, func(m *MintRequest) { m.TTL = 5 * time.Minute })
	live := testMint(t, r, func(m *MintRequest) { m.TTL = time.Hour })

	now = now.Add(10 * time.Minute)
	if got := r.ReapExpired(); got != 1 {
		t.Errorf("ReapExpired() = %d, want 1", got)
	}
	if len(r.Sessions()) != 1 || r.Sessions()[0].ID != live.Session.ID {
		t.Errorf("the wrong session survived the sweep")
	}
}

func TestCloseAll_And_CloseByRule(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com")
	a := testMint(t, r, func(m *MintRequest) { m.RuleID = "rule-a" })
	b := testMint(t, r, func(m *MintRequest) { m.RuleID = "rule-b" })

	// Disabling a rule must take its already-minted sessions with it: a
	// policy change that leaves live sessions relaying did not happen.
	if got := r.CloseByRule("rule-a", "rule disabled"); got != 1 {
		t.Fatalf("CloseByRule = %d, want 1", got)
	}
	if _, err := r.Authenticate(a.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Error("a session whose rule was disabled still authenticates")
	}
	if _, err := r.Authenticate(b.Token); err != nil {
		t.Errorf("an unrelated rule's session was closed too: %v", err)
	}
	if got := r.CloseByRule("", "noop"); got != 0 {
		t.Errorf("CloseByRule(\"\") closed %d sessions", got)
	}
	if got := r.CloseAll("shutting down"); got != 1 {
		t.Errorf("CloseAll = %d, want 1", got)
	}
	if len(r.Sessions()) != 0 {
		t.Error("sessions survived CloseAll")
	}
}

func TestRegistry_BoundsLiveSessions(t *testing.T) {
	t.Parallel()
	now := time.Now()
	r := NewRegistry("https://hub.example.com")
	r.SetClock(func() time.Time { return now })
	for i := 0; i < MaxSessions; i++ {
		if _, err := r.Mint(MintRequest{
			Policy: Policy{Models: []string{"m"}}, TTL: time.Hour,
		}); err != nil {
			t.Fatalf("Mint %d: %v", i, err)
		}
	}
	if _, err := r.Mint(MintRequest{Policy: Policy{Models: []string{"m"}}, TTL: time.Hour}); err == nil {
		t.Fatal("Mint exceeded MaxSessions")
	}
	// Once the live set lapses, minting works again without operator action.
	now = now.Add(2 * time.Hour)
	if _, err := r.Mint(MintRequest{Policy: Policy{Models: []string{"m"}}, TTL: time.Hour}); err != nil {
		t.Fatalf("Mint after the live set expired: %v", err)
	}
}

func TestEvents_CoverTheSessionLifetimeWithoutLeakingTheToken(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com")
	var mu sync.Mutex
	var events []Event
	r.OnEvent = func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	m := testMint(t, r)
	if err := r.Close(m.Session.ID, "done"); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("got %d events, want minted + closed: %+v", len(events), events)
	}
	if events[0].Kind != EventSessionMinted || events[1].Kind != EventSessionClosed {
		t.Errorf("kinds = %q, %q", events[0].Kind, events[1].Kind)
	}
	for _, e := range events {
		if e.Repository != "acme/tool" {
			t.Errorf("event does not name the pipeline: %+v", e)
		}
		blob := fmt.Sprintf("%+v", e)
		if strings.Contains(blob, m.Token) {
			t.Fatalf("an audit event carried the session token: %s", blob)
		}
	}
}

func TestSessionLabel(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com")
	m := testMint(t, r)
	if want := "acme/tool refs/heads/main release"; m.Session.Label() != want {
		t.Errorf("Label() = %q, want %q", m.Session.Label(), want)
	}
	bare := &Session{ID: "abc"}
	if bare.Label() != "abc" {
		t.Errorf("Label() = %q, want the id when nothing else is known", bare.Label())
	}
}
