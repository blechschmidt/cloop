package gitproxy

// Unit tests for renewing a session's upstream credential (Task 20375). The
// end-to-end proof — a real git, a real broker, a forge refusing the expired
// token — is refresh_e2e_test.go.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// refreshRig is a registry on a driven clock and a refresher whose answers a
// test scripts.
type refreshRig struct {
	reg   *Registry
	now   atomic.Int64
	calls atomic.Int32

	mu      sync.Mutex
	next    int
	fail    error
	block   chan struct{}
	retired []string
	events  []Event
}

func newRefreshRig(t *testing.T) *refreshRig {
	t.Helper()
	rig := &refreshRig{}
	rig.now.Store(time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC).UnixNano())
	reg, err := NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	reg.Now = rig.clock
	reg.OnEvent = func(e Event) {
		rig.mu.Lock()
		rig.events = append(rig.events, e)
		rig.mu.Unlock()
	}
	rig.reg = reg
	return rig
}

func (r *refreshRig) clock() time.Time        { return time.Unix(0, r.now.Load()).UTC() }
func (r *refreshRig) advance(d time.Duration) { r.now.Add(int64(d)) }

// refresh is the scripted RefreshFunc: it mints tok-N, expiring an hour after
// the rig's clock, and records retirements.
func (r *refreshRig) refresh(_ context.Context, held string) (Refreshed, error) {
	r.calls.Add(1)
	r.mu.Lock()
	block, fail := r.block, r.fail
	r.mu.Unlock()
	if block != nil {
		<-block
	}
	if fail != nil {
		return Refreshed{}, fail
	}
	r.mu.Lock()
	r.next++
	tok := fmt.Sprintf("upstream-token-%d", r.next)
	r.mu.Unlock()
	return Refreshed{
		Credential: Credential{Username: "x-access-token", Password: tok},
		ExpiresAt:  r.clock().Add(time.Hour),
		Retire: func() {
			r.mu.Lock()
			r.retired = append(r.retired, held)
			r.mu.Unlock()
		},
	}, nil
}

func (r *refreshRig) retiredTokens() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.retired...)
}

func (r *refreshRig) mint(t *testing.T, onEnd func()) *Minted {
	t.Helper()
	m, err := r.reg.Mint(MintRequest{
		Upstream:            "https://github.com",
		RepoPatterns:        []string{"acme/*"},
		Credential:          Credential{Username: "x-access-token", Password: "upstream-token-0"},
		CredentialExpiresAt: r.clock().Add(time.Hour),
		Refresh:             r.refresh,
		TTL:                 4 * time.Hour,
		OnEnd:               onEnd,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return m
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestSessionRenewsInsideTheWindow: outside the window the credential is
// presented as it is; inside it, renewed once, presented from then on, and the
// superseded one retired only after the last request presenting it finishes.
func TestSessionRenewsInsideTheWindow(t *testing.T) {
	rig := newRefreshRig(t)
	m := rig.mint(t, nil)
	ctx := context.Background()

	rig.advance(40 * time.Minute)
	cred, doneOld, err := rig.reg.credentialFor(ctx, m.Session)
	if err != nil || cred.Password != "upstream-token-0" {
		t.Fatalf("credential at 40m = %q, %v; want the original, unrenewed", cred.Password, err)
	}
	if n := rig.calls.Load(); n != 0 {
		t.Fatalf("refreshed %d time(s) twenty minutes before the window", n)
	}

	// A request still holding the original when the window opens.
	rig.advance(11 * time.Minute)
	cred, done, err := rig.reg.credentialFor(ctx, m.Session)
	if err != nil || cred.Password != "upstream-token-1" {
		t.Fatalf("credential at 51m = %q, %v; want the renewed one", cred.Password, err)
	}
	done()
	if got := m.Session.CredentialExpiresAt(); !got.Equal(rig.clock().Add(time.Hour)) {
		t.Errorf("session's credential expiry = %s; want the renewed token's", got)
	}
	time.Sleep(20 * time.Millisecond)
	if r := rig.retiredTokens(); len(r) != 0 {
		t.Fatalf("retired %v while a request was still presenting it", r)
	}
	doneOld()
	waitFor(t, "the superseded credential to be retired", func() bool {
		r := rig.retiredTokens()
		return len(r) == 1 && r[0] == "upstream-token-0"
	})

	// From now on the renewed credential, without asking again.
	cred, done, _ = rig.reg.credentialFor(ctx, m.Session)
	done()
	if cred.Password != "upstream-token-1" || rig.calls.Load() != 1 {
		t.Errorf("after the renewal: credential %q, %d refreshes; want token 1, one refresh", cred.Password, rig.calls.Load())
	}
}

// TestSessionRenewalIsSingleFlight: every request that finds the credential due
// waits for one renewal and presents its result.
func TestSessionRenewalIsSingleFlight(t *testing.T) {
	rig := newRefreshRig(t)
	m := rig.mint(t, nil)
	rig.advance(55 * time.Minute)
	release := make(chan struct{})
	rig.mu.Lock()
	rig.block = release
	rig.mu.Unlock()

	const n = 8
	got := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cred, done, err := rig.reg.credentialFor(context.Background(), m.Session)
			if err != nil {
				t.Errorf("request %d: %v", i, err)
				return
			}
			got[i] = cred.Password
			done()
		}(i)
	}
	waitFor(t, "the first refresh to start", func() bool { return rig.calls.Load() >= 1 })
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if c := rig.calls.Load(); c != 1 {
		t.Fatalf("%d concurrent requests ran %d refreshes, want one", n, c)
	}
	for i, p := range got {
		if p != "upstream-token-1" {
			t.Errorf("request %d presented %q, want the one renewal's token", i, p)
		}
	}
}

// TestRefusedRenewalClosesTheSession: the issuer saying no for good ends the
// session exactly as revocation does — closed, audited, its OnEnd run — and
// the request is answered as unauthenticated.
func TestRefusedRenewalClosesTheSession(t *testing.T) {
	rig := newRefreshRig(t)
	var ended atomic.Bool
	m := rig.mint(t, func() { ended.Store(true) })
	rig.mu.Lock()
	rig.fail = fmt.Errorf("%w: grant g-1 was revoked", ErrCredentialRefused)
	rig.mu.Unlock()
	rig.advance(61 * time.Minute)

	_, _, err := rig.reg.credentialFor(context.Background(), m.Session)
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("credentialFor = %v; want ErrCredentialRefused", err)
	}
	if !m.Session.Closed() || !ended.Load() {
		t.Fatalf("closed=%t ended=%t; a refused renewal must close the session and release what it stands on",
			m.Session.Closed(), ended.Load())
	}
	if _, err := rig.reg.Authenticate(m.Session.ID, m.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate after the refusal = %v; want ErrUnauthenticated", err)
	}
	rig.mu.Lock()
	defer rig.mu.Unlock()
	var closed []Event
	for _, e := range rig.events {
		if e.Kind == EventSessionClosed {
			closed = append(closed, e)
		}
	}
	if len(closed) != 1 || !strings.Contains(closed[0].Detail, "will not be renewed") ||
		!strings.Contains(closed[0].Detail, "revoked") {
		t.Fatalf("session_closed rows = %+v; want one naming the refusal", closed)
	}
}

// TestFailedRenewalKeepsTheHeldCredential: a failure that may pass leaves the
// working credential in use, backs off, and only refuses once the credential
// has actually lapsed.
func TestFailedRenewalKeepsTheHeldCredential(t *testing.T) {
	rig := newRefreshRig(t)
	m := rig.mint(t, nil)
	rig.mu.Lock()
	rig.fail = errors.New("github unreachable: i/o timeout")
	rig.mu.Unlock()
	ctx := context.Background()

	rig.advance(52 * time.Minute)
	cred, done, err := rig.reg.credentialFor(ctx, m.Session)
	if err != nil || cred.Password != "upstream-token-0" {
		t.Fatalf("after a failed renewal = %q, %v; want the held, still-valid credential", cred.Password, err)
	}
	done()
	// Within the backoff: no second attempt.
	rig.advance(30 * time.Second)
	_, done, _ = rig.reg.credentialFor(ctx, m.Session)
	done()
	if c := rig.calls.Load(); c != 1 {
		t.Fatalf("%d attempts inside the backoff, want one", c)
	}
	// Past it: tried again.
	rig.advance(credentialRefreshBackoff)
	_, done, _ = rig.reg.credentialFor(ctx, m.Session)
	done()
	if c := rig.calls.Load(); c != 2 {
		t.Fatalf("%d attempts after the backoff, want two", c)
	}
	if m.Session.Closed() {
		t.Fatal("a renewal that may yet succeed closed the session")
	}

	// Lapsed, still failing: refused promptly, with the reason.
	rig.advance(10 * time.Minute)
	_, _, err = rig.reg.credentialFor(ctx, m.Session)
	if err == nil || !errors.Is(err, errCredentialExpired) || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("a lapsed credential that cannot be renewed = %v; want an expiry error naming why", err)
	}

	// And recovers once the issuer does.
	rig.mu.Lock()
	rig.fail = nil
	rig.mu.Unlock()
	rig.advance(credentialRefreshBackoff)
	cred, done, err = rig.reg.credentialFor(ctx, m.Session)
	if err != nil || cred.Password != "upstream-token-1" {
		t.Fatalf("after the issuer recovered = %q, %v; want a renewed credential", cred.Password, err)
	}
	done()
}

// TestCredentialWithoutRefreshIsPresentedAsIs: a PAT has no expiry the hub
// knows and no refresher, and nothing about it changes.
func TestCredentialWithoutRefreshIsPresentedAsIs(t *testing.T) {
	rig := newRefreshRig(t)
	m, err := rig.reg.Mint(MintRequest{
		Upstream: "https://github.com", RepoPatterns: []string{"acme/*"},
		Credential: Credential{Password: "ghp_personal"}, TTL: 4 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	rig.advance(3 * time.Hour)
	cred, done, err := rig.reg.credentialFor(context.Background(), m.Session)
	done()
	if err != nil || cred.Password != "ghp_personal" || m.Session.Refreshable() {
		t.Fatalf("PAT session after 3h = %q, %v, refreshable=%t", cred.Password, err, m.Session.Refreshable())
	}
}

// TestMintRefusesARefresherWithoutAnExpiry: a refresher with nothing to
// measure the credential against would never run.
func TestMintRefusesARefresherWithoutAnExpiry(t *testing.T) {
	rig := newRefreshRig(t)
	_, err := rig.reg.Mint(MintRequest{
		Upstream: "https://github.com", RepoPatterns: []string{"acme/*"},
		Credential: Credential{Password: "tok"}, Refresh: rig.refresh,
	})
	if err == nil {
		t.Fatal("a refreshable credential with no expiry was accepted")
	}
}

// TestRefresherPanicFailsTheRequestNotTheProxy.
func TestRefresherPanicFailsTheRequestNotTheProxy(t *testing.T) {
	rig := newRefreshRig(t)
	m, err := rig.reg.Mint(MintRequest{
		Upstream: "https://github.com", RepoPatterns: []string{"acme/*"},
		Credential: Credential{Password: "tok"}, CredentialExpiresAt: rig.clock().Add(time.Hour),
		Refresh: func(context.Context, string) (Refreshed, error) { panic("broken issuer") },
		TTL:     4 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	rig.advance(61 * time.Minute)
	if _, _, err := rig.reg.credentialFor(context.Background(), m.Session); err == nil {
		t.Fatal("a panicking refresher yielded a credential")
	}
}
