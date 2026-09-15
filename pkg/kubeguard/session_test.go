package kubeguard

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMintAppliesTheDefaultTTL(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	reg.Now = func() time.Time { return now }

	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if got := m.Session.ExpiresAt.Sub(now); got != DefaultSessionTTL {
		t.Errorf("ttl = %s, want %s", got, DefaultSessionTTL)
	}
}

// TestMintRefusesAnOverlongTTL: clamping would be discovered as a kubectl
// call that stopped working halfway through a long run.
func TestMintRefusesAnOverlongTTL(t *testing.T) {
	reg := newTestRegistry(t)
	_, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), TTL: MaxSessionTTL + time.Minute})
	if err == nil {
		t.Fatal("a TTL above the maximum was accepted")
	}
	if !strings.Contains(err.Error(), "maximum") {
		t.Errorf("error does not name the ceiling: %v", err)
	}
	if _, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), TTL: -time.Second}); err == nil {
		t.Error("a negative TTL was accepted")
	}
}

func TestMintDefaultsToReadOnly(t *testing.T) {
	reg := newTestRegistry(t)
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !m.Session.Policy.ReadOnly() {
		t.Errorf("a session minted with no policy is not read-only: %s", m.Session.Policy.Summary())
	}
}

func TestMintRefusesAPolicyThatPermitsNothing(t *testing.T) {
	reg := newTestRegistry(t)
	// Not IsZero (MaxBodyBytes is set), so Normalize will not substitute the
	// default — and an empty verb list genuinely means nothing.
	_, err := reg.Mint(MintRequest{
		Kubeconfig: testKubeconfig(""),
		Policy:     Policy{Verbs: []string{"frobnicate"}, MaxBodyBytes: 1024},
	})
	if err == nil {
		t.Fatal("a policy with an unknown verb was accepted")
	}
}

func TestAuthenticateRejectsEveryWrongCredentialTheSameWay(t *testing.T) {
	reg := newTestRegistry(t)
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if _, err := reg.Authenticate(m.Token); err != nil {
		t.Fatalf("the minted token does not authenticate: %v", err)
	}

	// "No such session" and "wrong token" are the same error, because
	// distinguishing them is an oracle for enumerating live sessions.
	for _, tc := range []struct{ name, token string }{
		{"wrong secret", m.Session.ID + ".wrong"},
		{"unknown session", "nosuchsession.secret"},
		{"no separator", "justastring"},
		{"empty", ""},
		{"empty id", ".secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := reg.Authenticate(tc.token); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("err = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestAuthenticateReportsExpiryAndRevocationDistinctly(t *testing.T) {
	// Both are only ever returned to a caller that already proved it held the
	// token, so naming the cause costs nothing and saves an operator an hour.
	reg := newTestRegistry(t)
	now := time.Now()
	reg.Now = func() time.Time { return now }

	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	reg.Now = func() time.Time { return m.Session.ExpiresAt.Add(time.Second) }
	if _, err := reg.Authenticate(m.Token); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("err = %v, want ErrSessionExpired", err)
	}

	reg2 := newTestRegistry(t)
	m2, err := reg2.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	reg2.Close(m2.Session.ID, "revoked")
	if _, err := reg2.Authenticate(m2.Token); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("err = %v, want ErrSessionClosed", err)
	}
}

// TestCloseForLeaseRevokesEverySessionTheLeaseMinted is the gap Task 20178
// closed for the other secret kinds: without it, releasing a lease wipes the
// kubeconfig file in the sandbox while the session it already authenticated
// with keeps working until the TTL.
func TestCloseForLeaseRevokesEverySessionTheLeaseMinted(t *testing.T) {
	reg := newTestRegistry(t)
	var mine []*Minted
	for i := 0; i < 3; i++ {
		m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), LeaseID: "lease-1"})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		mine = append(mine, m)
	}
	other, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), LeaseID: "lease-2"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if n := reg.CloseForLease("lease-1", "lease released"); n != 3 {
		t.Errorf("CloseForLease closed %d sessions, want 3", n)
	}
	for i, m := range mine {
		if _, err := reg.Authenticate(m.Token); !errors.Is(err, ErrSessionClosed) {
			t.Errorf("session %d still authenticates: %v", i, err)
		}
	}
	if _, err := reg.Authenticate(other.Token); err != nil {
		t.Errorf("another lease's session was closed too: %v", err)
	}

	// Idempotent, and a no-op for an unknown lease.
	if n := reg.CloseForLease("lease-1", "again"); n != 0 {
		t.Errorf("a second CloseForLease closed %d sessions, want 0", n)
	}
	if n := reg.CloseForLease("", "empty"); n != 0 {
		t.Errorf("CloseForLease(\"\") closed %d sessions, want 0", n)
	}
}

func TestReapExpiredRemovesLapsedSessions(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Now()
	reg.Now = func() time.Time { return now }

	var closed []Event
	reg.OnEvent = func(e Event) {
		if e.Kind == EventSessionClosed {
			closed = append(closed, e)
		}
	}

	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), TTL: time.Minute})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if n := reg.ReapExpired(); n != 0 {
		t.Errorf("reaped %d live sessions", n)
	}

	reg.Now = func() time.Time { return m.Session.ExpiresAt.Add(time.Second) }
	if n := reg.ReapExpired(); n != 1 {
		t.Errorf("reaped %d sessions, want 1", n)
	}
	if len(closed) != 1 || !strings.Contains(closed[0].Detail, "expired") {
		t.Errorf("expiry was not recorded: %+v", closed)
	}
	if _, ok := reg.Session(m.Session.ID); ok {
		t.Error("the lapsed session is still in the registry")
	}
}

func TestNewRegistryRefusesAnUnusableBaseURL(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		// http would publish the session token rather than deliver it, and a
		// loopback listener is no exception: a sandbox may share a host with
		// whatever else is listening there.
		{"http", "http://hub.example:8444"},
		{"no scheme", "hub.example:8444"},
		{"no host", "https://"},
		{"embedded credentials", "https://user:pass@hub.example:8444"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRegistry(tc.url); err == nil {
				t.Errorf("NewRegistry(%q) succeeded", tc.url)
			}
		})
	}
}

func TestSessionDescribeCarriesNoCredential(t *testing.T) {
	reg := newTestRegistry(t)
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	d := m.Session.Describe()
	if strings.Contains(d, testClusterToken) || strings.Contains(d, m.Token) {
		t.Errorf("Describe() leaks a credential: %q", d)
	}
	if !strings.Contains(d, m.Session.ID) {
		t.Errorf("Describe() does not name the session: %q", d)
	}
}

func TestMintedSessionsAreDistinct(t *testing.T) {
	reg := newTestRegistry(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if seen[m.Session.ID] {
			t.Fatalf("duplicate session id %q", m.Session.ID)
		}
		if seen[m.Token] {
			t.Fatalf("duplicate token")
		}
		seen[m.Session.ID], seen[m.Token] = true, true
		// The split must be unambiguous: base64url never emits a ".".
		if strings.Count(m.Token, ".") != 1 {
			t.Fatalf("token %q does not split cleanly", m.Token)
		}
	}
}
