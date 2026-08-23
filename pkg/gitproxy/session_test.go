package gitproxy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const testBase = "https://hub.internal:8443"

// newTestRegistry returns a registry with a frozen clock, so an expiry test can
// move time instead of waiting for it.
func newTestRegistry(t *testing.T, now time.Time) *Registry {
	t.Helper()
	reg, err := NewRegistry(testBase)
	if err != nil {
		t.Fatalf("NewRegistry(%q) = %v", testBase, err)
	}
	reg.Now = func() time.Time { return now }
	return reg
}

// setClock replaces a registry's clock wholesale. Tests that need to move time
// keep their own variable; this helper exists so the assignment is race-free
// under -race when only one goroutine is running.
func setClock(reg *Registry, at *time.Time, mu *sync.Mutex) {
	reg.Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return *at
	}
}

// mintOne mints a session against a well-formed upstream and fails the test if
// it cannot.
func mintOne(t *testing.T, reg *Registry, req MintRequest) *Minted {
	t.Helper()
	if req.Upstream == "" {
		req.Upstream = "https://github.com/acme/tool.git"
	}
	m, err := reg.Mint(req)
	if err != nil {
		t.Fatalf("Mint(%+v) = %v", req, err)
	}
	return m
}

// --- UpstreamRepoPath --------------------------------------------------------

func TestUpstreamRepoPathAcceptsAForgeCloneURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "https://github.com/acme/tool", "acme/tool"},
		{"dot-git suffix", "https://github.com/acme/tool.git", "acme/tool"},
		{"trailing slash", "https://github.com/acme/tool/", "acme/tool"},
		{"leading and trailing whitespace", "  https://github.com/acme/tool.git  ", "acme/tool"},
		{"port", "https://forge.internal:8443/acme/tool", "acme/tool"},
		{"dots in the name", "https://github.com/acme/tool.io", "acme/tool.io"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UpstreamRepoPath(tc.in)
			if err != nil {
				t.Fatalf("UpstreamRepoPath(%q) = %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("UpstreamRepoPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestUpstreamRepoPathRejectsAnythingElse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantMsg string
	}{
		{"empty", "", "is empty"},
		{"whitespace only", "   ", "is empty"},
		{"http", "http://github.com/acme/tool", "must be an https:// URL"},
		{"ssh", "ssh://git@github.com/acme/tool", "must be an https:// URL"},
		// The scp-style remote does not survive url.Parse at all, so it is
		// refused a step earlier than the scheme check.
		{"scp shorthand", "git@github.com:acme/tool.git", "is not a URL"},
		{"no host", "https:///acme/tool", "has no host"},
		{"embedded userinfo", "https://u:p@github.com/acme/tool", "must not embed credentials"},
		{"embedded username only", "https://u@github.com/acme/tool", "must not embed credentials"},
		{"one path segment", "https://github.com/acme", "is not owner/name"},
		{"no path", "https://github.com", "is not owner/name"},
		{"three path segments", "https://github.com/acme/group/tool", "is not owner/name"},
		{"dot component", "https://github.com/./tool", "unusable component"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UpstreamRepoPath(tc.in)
			if err == nil {
				t.Fatalf("UpstreamRepoPath(%q) = %q, want a refusal", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("UpstreamRepoPath(%q) = %q, want it to mention %q", tc.in, err, tc.wantMsg)
			}
			if got != "" {
				t.Fatalf("UpstreamRepoPath(%q) returned %q alongside an error", tc.in, got)
			}
		})
	}
}

func TestUpstreamRepoPathMatchesExecutorRepoPath(t *testing.T) {
	// pkg/executor's Workspace.RepoPath parses the same shape to match a
	// GitHub grant's repository allowlist. If the two ever disagreed, routing a
	// workspace through the proxy would change which grants authorise it.
	for _, raw := range []string{
		"https://github.com/acme/tool",
		"https://github.com/acme/tool.git",
		"https://github.com/acme/tool/",
	} {
		got, err := UpstreamRepoPath(raw)
		if err != nil {
			t.Fatalf("UpstreamRepoPath(%q) = %v", raw, err)
		}
		if got != "acme/tool" {
			t.Fatalf("UpstreamRepoPath(%q) = %q, want acme/tool", raw, got)
		}
	}
}

// --- NewRegistry -------------------------------------------------------------

func TestNewRegistryAcceptsACleanHTTPSBase(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://hub.internal:8443", "https://hub.internal:8443"},
		{"https://hub.internal", "https://hub.internal"},
		{"https://hub.internal/", "https://hub.internal"},
		{"  https://hub.internal:8443/  ", "https://hub.internal:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			reg, err := NewRegistry(tc.in)
			if err != nil {
				t.Fatalf("NewRegistry(%q) = %v", tc.in, err)
			}
			if reg.BaseURL != tc.want {
				t.Fatalf("BaseURL = %q, want %q", reg.BaseURL, tc.want)
			}
			if len(reg.Sessions()) != 0 {
				t.Fatalf("a fresh registry holds %d sessions", len(reg.Sessions()))
			}
		})
	}
}

func TestNewRegistryRejectsAnUnusableBase(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantMsg string
	}{
		{"empty", "", "is empty"},
		{"http", "http://hub.internal:8443", "must be https"},
		{"no scheme", "hub.internal:8443", "must be https"},
		{"no host", "https://", "no host"},
		{"path", "https://hub.internal/git", "must have no path"},
		{"query", "https://hub.internal?a=b", "query or fragment"},
		{"fragment", "https://hub.internal#frag", "query or fragment"},
		{"embedded credentials", "https://user:pass@hub.internal", "must not embed credentials"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg, err := NewRegistry(tc.in)
			if err == nil {
				t.Fatalf("NewRegistry(%q) = %+v, want a refusal", tc.in, reg)
			}
			if reg != nil {
				t.Fatalf("NewRegistry(%q) returned a registry alongside an error", tc.in)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("NewRegistry(%q) = %q, want it to mention %q", tc.in, err, tc.wantMsg)
			}
		})
	}
}

// --- Mint --------------------------------------------------------------------

func TestMintDefaultsAZeroPolicyToWriteBack(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	m := mintOne(t, reg, MintRequest{})

	got := m.Session.Policy
	want := WriteBackPolicy()
	want.Normalize()

	if !equalStrings(got.AllowedRefs, want.AllowedRefs) {
		t.Fatalf("AllowedRefs = %q, want %q", got.AllowedRefs, want.AllowedRefs)
	}
	if !got.AllowCreate || !got.AllowUpdate {
		t.Fatalf("default policy must permit create and update, got %+v", got)
	}
	if got.AllowDelete || got.AllowFetch {
		t.Fatalf("default policy must not permit delete or fetch, got %+v", got)
	}
	if got.MaxCommands != DefaultMaxCommands || got.MaxPackBytes != DefaultMaxPackBytes {
		t.Fatalf("default policy bounds = (%d,%d), want (%d,%d)",
			got.MaxCommands, got.MaxPackBytes, DefaultMaxCommands, DefaultMaxPackBytes)
	}
}

func TestMintNormalizesAndValidatesAnExplicitPolicy(t *testing.T) {
	reg := newTestRegistry(t, time.Now())

	t.Run("a bare branch name is canonicalised", func(t *testing.T) {
		m := mintOne(t, reg, MintRequest{
			Policy: Policy{AllowedRefs: []string{"cloop/*"}, AllowCreate: true},
		})
		if want := []string{"refs/heads/cloop/*"}; !equalStrings(m.Session.Policy.AllowedRefs, want) {
			t.Fatalf("AllowedRefs = %q, want %q", m.Session.Policy.AllowedRefs, want)
		}
		// A non-zero policy is honoured, not replaced by the default.
		if m.Session.Policy.AllowUpdate {
			t.Fatal("Mint widened an explicit create-only policy to permit updates")
		}
	})

	t.Run("a policy that permits nothing is refused", func(t *testing.T) {
		// Non-zero (it names a ref) so Mint does not substitute the default,
		// and unusable (no authority) so Validate must refuse it.
		_, err := reg.Mint(MintRequest{
			Upstream: "https://github.com/acme/tool",
			Policy:   Policy{AllowedRefs: []string{"refs/heads/cloop/**"}},
		})
		if err == nil {
			t.Fatal("Mint accepted a policy that permits nothing")
		}
		if !strings.Contains(err.Error(), "permits nothing") {
			t.Fatalf("Mint error = %q, want it to name the unusable policy", err)
		}
	})

	t.Run("a malformed pattern is refused", func(t *testing.T) {
		_, err := reg.Mint(MintRequest{
			Upstream: "https://github.com/acme/tool",
			Policy:   Policy{AllowedRefs: []string{"refs/heads/../../x"}, AllowCreate: true},
		})
		if err == nil {
			t.Fatal("Mint accepted a traversal pattern")
		}
	})
}

func TestMintRefusesAnUnusableUpstream(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	m, err := reg.Mint(MintRequest{Upstream: "https://github.com/acme"})
	if err == nil {
		t.Fatalf("Mint accepted a non owner/name upstream: %+v", m)
	}
	if len(reg.Sessions()) != 0 {
		t.Fatalf("a failed Mint left %d sessions behind", len(reg.Sessions()))
	}
}

func TestMintTTL(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	t.Run("zero gets the default", func(t *testing.T) {
		reg := newTestRegistry(t, now)
		m := mintOne(t, reg, MintRequest{})
		if want := now.Add(DefaultSessionTTL); !m.Session.ExpiresAt.Equal(want) {
			t.Fatalf("ExpiresAt = %s, want %s", m.Session.ExpiresAt, want)
		}
		if !m.Session.IssuedAt.Equal(now) {
			t.Fatalf("IssuedAt = %s, want the registry clock %s", m.Session.IssuedAt, now)
		}
	})

	t.Run("an explicit TTL is honoured", func(t *testing.T) {
		reg := newTestRegistry(t, now)
		m := mintOne(t, reg, MintRequest{TTL: 90 * time.Minute})
		if want := now.Add(90 * time.Minute); !m.Session.ExpiresAt.Equal(want) {
			t.Fatalf("ExpiresAt = %s, want %s", m.Session.ExpiresAt, want)
		}
	})

	t.Run("exactly the maximum is allowed", func(t *testing.T) {
		reg := newTestRegistry(t, now)
		m := mintOne(t, reg, MintRequest{TTL: MaxSessionTTL})
		if want := now.Add(MaxSessionTTL); !m.Session.ExpiresAt.Equal(want) {
			t.Fatalf("ExpiresAt = %s, want %s", m.Session.ExpiresAt, want)
		}
	})

	t.Run("above the maximum is an error, not a clamp", func(t *testing.T) {
		// A caller who asked for a day and silently got twelve hours would
		// discover it as a push that failed halfway through a long run.
		reg := newTestRegistry(t, now)
		m, err := reg.Mint(MintRequest{Upstream: "https://github.com/acme/tool", TTL: MaxSessionTTL + time.Second})
		if err == nil {
			t.Fatalf("Mint clamped an over-long TTL to %s instead of refusing it",
				m.Session.ExpiresAt.Sub(m.Session.IssuedAt))
		}
		if !strings.Contains(err.Error(), "maximum") {
			t.Fatalf("Mint error = %q, want it to name the maximum", err)
		}
		if len(reg.Sessions()) != 0 {
			t.Fatalf("a refused Mint left %d sessions behind", len(reg.Sessions()))
		}
	})

	t.Run("negative is an error", func(t *testing.T) {
		reg := newTestRegistry(t, now)
		if _, err := reg.Mint(MintRequest{Upstream: "https://github.com/acme/tool", TTL: -time.Second}); err == nil {
			t.Fatal("Mint accepted a negative TTL")
		}
	})
}

func TestMintReturnsFreshIdentifiersAndTokens(t *testing.T) {
	reg := newTestRegistry(t, time.Now())

	const n = 32
	ids := make(map[string]bool, n)
	tokens := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		m := mintOne(t, reg, MintRequest{})
		switch {
		case m.Session.ID == "":
			t.Fatal("Mint returned an empty session ID")
		case m.Token == "":
			t.Fatal("Mint returned an empty token")
		case m.Session.ID == m.Token:
			t.Fatal("the session ID and its token are the same string; the public half is the secret half")
		case ids[m.Session.ID]:
			t.Fatalf("Mint reused session ID %q", m.Session.ID)
		case tokens[m.Token]:
			t.Fatalf("Mint reused token %q", m.Token)
		}
		ids[m.Session.ID] = true
		tokens[m.Token] = true
	}
	if len(reg.Sessions()) != n {
		t.Fatalf("registry holds %d sessions after %d mints", len(reg.Sessions()), n)
	}
}

func TestMintRepoURLIsThePublicBasePlusOwnerName(t *testing.T) {
	reg := newTestRegistry(t, time.Now())

	for _, upstream := range []string{
		"https://github.com/acme/tool",
		"https://github.com/acme/tool.git",
		"https://github.com/acme/tool/",
	} {
		m := mintOne(t, reg, MintRequest{Upstream: upstream})
		if want := testBase + "/acme/tool"; m.RepoURL != want {
			t.Fatalf("RepoURL for %q = %q, want %q", upstream, m.RepoURL, want)
		}
		if m.Session.RepoPath != "acme/tool" {
			t.Fatalf("RepoPath = %q, want acme/tool", m.Session.RepoPath)
		}
		// The URL the sandbox clones from carries no credential.
		if strings.Contains(m.RepoURL, "@") || strings.Contains(m.RepoURL, m.Token) {
			t.Fatalf("RepoURL %q carries a credential", m.RepoURL)
		}
	}
}

func TestMintUpstreamAndCredentialStayOnTheHub(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	const pat = "ghp_forge_pat_value_that_must_not_leak"

	m := mintOne(t, reg, MintRequest{
		Upstream:   "https://github.com/acme/tool.git",
		Credential: Credential{Username: "x-access-token", Password: pat, GrantID: "g1", LeaseID: "l1"},
	})

	// The forge credential is reachable only through the unexported field the
	// proxy reads when it forwards; nothing the sandbox is handed carries it.
	if m.Session.credential.Password != pat {
		t.Fatalf("session upstream credential = %q, want the PAT", m.Session.credential.Password)
	}
	if m.Token == pat {
		t.Fatal("the session token is the PAT")
	}
	if cred := m.Credential(); cred.Password == pat {
		t.Fatal("Minted.Credential() hands the sandbox the PAT")
	}
	if want := "https://github.com/acme/tool.git"; m.Session.Upstream != want {
		t.Fatalf("Session.Upstream = %q, want %q", m.Session.Upstream, want)
	}
}

func TestMintedCredentialIsTheSessionIDAndToken(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	m := mintOne(t, reg, MintRequest{})

	cred := m.Credential()
	if cred.Username != m.Session.ID {
		t.Fatalf("Credential().Username = %q, want the session ID %q", cred.Username, m.Session.ID)
	}
	if cred.Password != m.Token {
		t.Fatalf("Credential().Password = %q, want the token %q", cred.Password, m.Token)
	}
	if cred.Empty() {
		t.Fatal("Credential() reports Empty")
	}
	// The pair round-trips through Authenticate, which is the only thing the
	// sandbox will ever do with it.
	if _, err := reg.Authenticate(cred.Username, cred.Password); err != nil {
		t.Fatalf("Authenticate with the minted credential = %v", err)
	}
}

func TestMintCarriesTheAuditLabels(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	var events []Event
	reg.OnEvent = func(e Event) { events = append(events, e) }

	m := mintOne(t, reg, MintRequest{
		ProjectID: "proj-1", TaskID: "task-2", ExecutorID: "exec-3", Actor: "alice",
	})

	s := m.Session
	if s.ProjectID != "proj-1" || s.TaskID != "task-2" || s.ExecutorID != "exec-3" || s.Actor != "alice" {
		t.Fatalf("audit labels lost: %+v", s)
	}
	if len(events) != 1 || events[0].Kind != EventSessionMinted {
		t.Fatalf("events = %+v, want one session_minted", events)
	}
	e := events[0]
	if e.SessionID != s.ID || e.RepoPath != "acme/tool" || e.ProjectID != "proj-1" ||
		e.TaskID != "task-2" || e.Actor != "alice" {
		t.Fatalf("mint event = %+v, want it to carry the session's labels", e)
	}
	if strings.Contains(e.String(), m.Token) {
		t.Fatal("the mint event log line carries the session token")
	}
}

// --- Authenticate ------------------------------------------------------------

func TestAuthenticateAcceptsTheMintedPair(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	m := mintOne(t, reg, MintRequest{})

	got, err := reg.Authenticate(m.Session.ID, m.Token)
	if err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if got != m.Session {
		t.Fatalf("Authenticate returned session %q, want %q", got.ID, m.Session.ID)
	}
}

func TestAuthenticateFailuresAreOneError(t *testing.T) {
	// A caller that could tell "no such session" from "wrong token" would be an
	// oracle for enumerating session IDs.
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := now
	var mu sync.Mutex
	reg, err := NewRegistry(testBase)
	if err != nil {
		t.Fatalf("NewRegistry = %v", err)
	}
	setClock(reg, &clock, &mu)

	live := mintOne(t, reg, MintRequest{TTL: time.Hour})
	closed := mintOne(t, reg, MintRequest{TTL: time.Hour})
	expired := mintOne(t, reg, MintRequest{TTL: time.Minute})
	reg.Close(closed.Session.ID, "run finished")

	mu.Lock()
	clock = now.Add(2 * time.Minute) // past the expired session, not the others
	mu.Unlock()

	cases := []struct {
		name  string
		id    string
		token string
	}{
		{"unknown session", "no-such-session", live.Token},
		{"wrong token", live.Session.ID, "not-the-token"},
		{"closed session", closed.Session.ID, closed.Token},
		{"expired session", expired.Session.ID, expired.Token},
		{"empty id and token", "", ""},
		{"right token, wrong session", closed.Session.ID, live.Token},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := reg.Authenticate(tc.id, tc.token)
			if err == nil {
				t.Fatalf("Authenticate(%q, ...) succeeded, returning %q", tc.id, s.ID)
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate(%q, ...) = %v, want ErrUnauthenticated", tc.id, err)
			}
			if s != nil {
				t.Fatalf("Authenticate(%q, ...) returned a session alongside an error", tc.id)
			}
		})
	}

	// The three failures reachable without holding a valid token must be
	// byte-identical, or the difference itself is the oracle. (The expired case
	// carries a detail, but reaching it requires already presenting the correct
	// token for that session, so it tells an attacker nothing they did not have.)
	var texts []string
	for _, tc := range cases[:2] {
		_, err := reg.Authenticate(tc.id, tc.token)
		texts = append(texts, err.Error())
	}
	if _, err := reg.Authenticate(closed.Session.ID, closed.Token); err != nil {
		texts = append(texts, err.Error())
	}
	for i := 1; i < len(texts); i++ {
		if texts[i] != texts[0] {
			t.Fatalf("authentication failures are distinguishable: %q vs %q", texts[0], texts[i])
		}
	}
	if texts[0] != ErrUnauthenticated.Error() {
		t.Fatalf("failure text = %q, want the bare sentinel %q", texts[0], ErrUnauthenticated.Error())
	}
}

func TestAuthenticateExpiryBoundary(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := now
	var mu sync.Mutex
	reg, err := NewRegistry(testBase)
	if err != nil {
		t.Fatalf("NewRegistry = %v", err)
	}
	setClock(reg, &clock, &mu)

	m := mintOne(t, reg, MintRequest{TTL: time.Hour})

	move := func(d time.Duration) {
		mu.Lock()
		clock = now.Add(d)
		mu.Unlock()
	}

	move(time.Hour - time.Nanosecond)
	if _, err := reg.Authenticate(m.Session.ID, m.Token); err != nil {
		t.Fatalf("Authenticate one nanosecond before expiry = %v", err)
	}
	if m.Session.Expired(now.Add(time.Hour - time.Nanosecond)) {
		t.Fatal("Expired reported true before ExpiresAt")
	}

	move(time.Hour) // exactly at ExpiresAt
	if !m.Session.Expired(now.Add(time.Hour)) {
		t.Fatal("Expired reported false exactly at ExpiresAt")
	}
	if _, err := reg.Authenticate(m.Session.ID, m.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate at expiry = %v, want ErrUnauthenticated", err)
	}
}

// --- Close -------------------------------------------------------------------

func TestCloseIsIdempotentAndRevokes(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	var events []Event
	reg.OnEvent = func(e Event) { events = append(events, e) }

	m := mintOne(t, reg, MintRequest{ProjectID: "proj-1"})
	id := m.Session.ID

	reg.Close(id, "run finished")
	if !m.Session.Closed() {
		t.Fatal("Close did not mark the session closed")
	}
	if got := m.Session.CloseReason(); got != "run finished" {
		t.Fatalf("CloseReason = %q, want %q", got, "run finished")
	}
	if _, err := reg.Authenticate(id, m.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a closed session still authenticates: %v", err)
	}
	if _, err := reg.Session(id); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Session(%q) after Close = %v, want ErrSessionNotFound", id, err)
	}

	// A driver calls Close from a defer without checking whether the run
	// already ended, so a second call must be a no-op — including on the event
	// stream, where a duplicate close row would misreport the trail.
	closes := countKind(events, EventSessionClosed)
	reg.Close(id, "again")
	reg.Close("never-existed", "and again")
	if got := countKind(events, EventSessionClosed); got != closes {
		t.Fatalf("repeated Close emitted %d close events, want %d", got, closes)
	}
	if got := m.Session.CloseReason(); got != "run finished" {
		t.Fatalf("a second Close overwrote the reason with %q", got)
	}
	if closes != 1 {
		t.Fatalf("Close emitted %d close events, want 1", closes)
	}
}

func TestCloseDefaultsTheReason(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	m := mintOne(t, reg, MintRequest{})
	reg.Close(m.Session.ID, "")
	if got := m.Session.CloseReason(); got != "closed" {
		t.Fatalf("CloseReason = %q, want %q", got, "closed")
	}
}

// --- ReapExpired -------------------------------------------------------------

func TestReapExpiredDropsOnlyTheDead(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := now
	var mu sync.Mutex
	reg, err := NewRegistry(testBase)
	if err != nil {
		t.Fatalf("NewRegistry = %v", err)
	}
	setClock(reg, &clock, &mu)
	var events []Event
	reg.OnEvent = func(e Event) { events = append(events, e) }

	short1 := mintOne(t, reg, MintRequest{TTL: time.Minute})
	short2 := mintOne(t, reg, MintRequest{TTL: time.Minute})
	long := mintOne(t, reg, MintRequest{TTL: 6 * time.Hour})

	if n := reg.ReapExpired(); n != 0 {
		t.Fatalf("ReapExpired dropped %d live sessions", n)
	}
	if len(reg.Sessions()) != 3 {
		t.Fatalf("registry holds %d sessions, want 3", len(reg.Sessions()))
	}

	mu.Lock()
	clock = now.Add(2 * time.Minute)
	mu.Unlock()

	if n := reg.ReapExpired(); n != 2 {
		t.Fatalf("ReapExpired = %d, want 2", n)
	}
	if n := reg.ReapExpired(); n != 0 {
		t.Fatalf("a second ReapExpired = %d, want 0", n)
	}

	live := reg.Sessions()
	if len(live) != 1 || live[0].ID != long.Session.ID {
		t.Fatalf("ReapExpired dropped the live session; %d left", len(live))
	}
	for _, m := range []*Minted{short1, short2} {
		if !m.Session.Closed() {
			t.Fatalf("reaped session %q is not marked closed", m.Session.ID)
		}
		if got := m.Session.CloseReason(); got != "expired" {
			t.Fatalf("reaped session close reason = %q, want %q", got, "expired")
		}
		if _, err := reg.Authenticate(m.Session.ID, m.Token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("a reaped session still authenticates: %v", err)
		}
	}
	if got := countKind(events, EventSessionClosed); got != 2 {
		t.Fatalf("ReapExpired emitted %d close events, want 2", got)
	}
	if _, err := reg.Authenticate(long.Session.ID, long.Token); err != nil {
		t.Fatalf("the surviving session no longer authenticates: %v", err)
	}
}

func TestReapExpiredDoesNotResurrectAClosedSession(t *testing.T) {
	// Close already removed it from the map, so the reaper must not emit a
	// second close row for the same session when its TTL later elapses.
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := now
	var mu sync.Mutex
	reg, err := NewRegistry(testBase)
	if err != nil {
		t.Fatalf("NewRegistry = %v", err)
	}
	setClock(reg, &clock, &mu)
	var events []Event
	reg.OnEvent = func(e Event) { events = append(events, e) }

	m := mintOne(t, reg, MintRequest{TTL: time.Minute})
	reg.Close(m.Session.ID, "run finished")

	mu.Lock()
	clock = now.Add(time.Hour)
	mu.Unlock()

	if n := reg.ReapExpired(); n != 0 {
		t.Fatalf("ReapExpired = %d, want 0 for an already-closed session", n)
	}
	if got := countKind(events, EventSessionClosed); got != 1 {
		t.Fatalf("close events = %d, want 1", got)
	}
}

// --- Session lookup ----------------------------------------------------------

func TestSessionLookup(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	m := mintOne(t, reg, MintRequest{})

	got, err := reg.Session(m.Session.ID)
	if err != nil {
		t.Fatalf("Session(%q) = %v", m.Session.ID, err)
	}
	if got != m.Session {
		t.Fatalf("Session returned %q, want %q", got.ID, m.Session.ID)
	}

	if _, err := reg.Session("nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Session(nope) = %v, want ErrSessionNotFound", err)
	}
}

func TestSessionStatsStartAtZero(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	m := mintOne(t, reg, MintRequest{})
	if got := m.Session.Stats(); got != (Stats{}) {
		t.Fatalf("a fresh session reports %+v, want zero counters", got)
	}
}

// --- concurrency -------------------------------------------------------------

func TestRegistryIsRaceFreeUnderConcurrentUse(t *testing.T) {
	// The registry is shared by every request goroutine the proxy serves, so
	// mint, authenticate, close, reap and list all run at once here. The
	// assertions are deliberately weak: the point is what -race observes.
	reg, err := NewRegistry(testBase)
	if err != nil {
		t.Fatalf("NewRegistry = %v", err)
	}
	var eventMu sync.Mutex
	var events int
	reg.OnEvent = func(Event) {
		eventMu.Lock()
		events++
		eventMu.Unlock()
	}

	const workers = 8
	const rounds = 40

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				m, err := reg.Mint(MintRequest{
					Upstream:  fmt.Sprintf("https://github.com/acme/tool-%d", w),
					ProjectID: fmt.Sprintf("proj-%d", w),
					TTL:       time.Minute,
				})
				if err != nil {
					t.Errorf("Mint = %v", err)
					return
				}
				if _, err := reg.Authenticate(m.Session.ID, m.Token); err != nil {
					t.Errorf("Authenticate = %v", err)
					return
				}
				if _, err := reg.Authenticate(m.Session.ID, "wrong"); !errors.Is(err, ErrUnauthenticated) {
					t.Errorf("Authenticate with a wrong token = %v", err)
					return
				}
				_, _ = reg.Session(m.Session.ID)
				_ = m.Session.Stats()
				reg.Close(m.Session.ID, "done")
				reg.Close(m.Session.ID, "done twice")
			}
		}(w)
	}

	// Readers and the reaper run alongside the writers.
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds*workers; i++ {
				for _, s := range reg.Sessions() {
					_ = s.Stats()
					_ = s.Closed()
					_ = s.CloseReason()
					_ = s.Expired(time.Now())
				}
				reg.ReapExpired()
			}
		}()
	}

	wg.Wait()

	if len(reg.Sessions()) != 0 {
		t.Fatalf("%d sessions survived a run that closed every one it minted", len(reg.Sessions()))
	}
	eventMu.Lock()
	defer eventMu.Unlock()
	if want := workers * rounds * 2; events != want {
		t.Fatalf("emitted %d events, want %d (one mint and one close per session)", events, want)
	}
}

// --- helpers -----------------------------------------------------------------

func countKind(events []Event, kind EventKind) int {
	n := 0
	for _, e := range events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}
