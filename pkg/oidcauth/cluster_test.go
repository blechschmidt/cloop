package oidcauth

// Hooks for several hub processes sharing one session store (Task 20354).
// Each Authenticator below plays one process; they share a store the way two
// `cloop ui` processes share state.db, and nothing else.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRefreshLockSerialisesRedemptionsAcrossProcesses: two processes asked
// for fresh claims on one session at the same moment redeem its refresh token
// once. Without the lock each would redeem it, and a provider that rotates
// refresh tokens answers the second with invalid_grant — a sign-out caused by
// nothing but a dashboard's page load landing on two processes.
func TestRefreshLockSerialisesRedemptionsAcrossProcesses(t *testing.T) {
	idp := newFakeIdP(t)
	idp.refreshIDToken = adminThenDemoted(idp)
	clk := newClock()
	store := NewMemorySessionStore(0)

	var lockMu sync.Mutex
	var acquired int
	lock := func(ctx context.Context, id string) (func(), error) {
		lockMu.Lock()
		acquired++
		return lockMu.Unlock, nil
	}
	mk := func() *Authenticator {
		return newLifecycleAuth(t, idp, store, clk, func(c *Config) {
			c.RefreshInterval = -1
			c.MaxClaimAge = 5 * time.Minute
			c.EffectiveRole = stubRoleLadder
			c.RefreshLock = lock
		})
	}
	a, b := mk(), mk()
	sid := signedInAdmin(t, a, "rt-1")
	id := sessionIDFor(sid)
	clk.advance(6 * time.Minute)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, auth := range []*Authenticator{a, b} {
		wg.Add(1)
		go func(auth *Authenticator) {
			defer wg.Done()
			_, err := auth.EnsureFreshClaims(context.Background(), id)
			errs <- err
		}(auth)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("EnsureFreshClaims: %v", err)
		}
	}
	if idp.refreshRequests != 1 {
		t.Fatalf("the refresh token was redeemed %d times across two processes, want 1", idp.refreshRequests)
	}
	if acquired != 2 {
		t.Fatalf("lock taken %d times, want once per process", acquired)
	}
}

// TestStatePrefixNamesTheProcessThatBeganTheLogin: the one value the IdP hands
// back unchanged has to say which process holds the login's verifier.
func TestStatePrefixNamesTheProcessThatBeganTheLogin(t *testing.T) {
	idp := newFakeIdP(t)
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, func(c *Config) {
		c.StatePrefix = "hub_member1"
	})
	rec := httptest.NewRecorder()
	a.BeginLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	state := loc.Query().Get("state")
	if !strings.HasPrefix(state, "hub_member1.") || len(state) <= len("hub_member1.")+8 {
		t.Fatalf("state = %q, want the prefix and a random part", state)
	}
	if got := StateOwner(state); got != "hub_member1" {
		t.Fatalf("StateOwner(%q) = %q", state, got)
	}
	if got := StateOwner("nodotinthisstate"); got != "" {
		t.Fatalf("an unprefixed state was attributed to %q", got)
	}
}

// TestSessionChangesAreAnnounced: a process revoking a session tells the
// others, which drop their cached copies.
func TestSessionChangesAreAnnounced(t *testing.T) {
	idp := newFakeIdP(t)
	store := NewMemorySessionStore(0)
	var mu sync.Mutex
	var announced []string
	a := newLifecycleAuth(t, idp, store, nil, func(c *Config) {
		c.OnCacheInvalidate = func(id string) {
			mu.Lock()
			announced = append(announced, id)
			mu.Unlock()
		}
	})
	b := newLifecycleAuth(t, idp, store, nil, nil)

	sid := signedInAdmin(t, a, "")
	id := sessionIDFor(sid)
	// B serves the session and caches it.
	if b.IdentityFromRequest(reqWithCookie(sid)) == nil {
		t.Fatal("B could not authenticate a session in the shared store")
	}
	if ok, err := a.RevokeSession(id, "admin", "incident"); err != nil || !ok {
		t.Fatalf("RevokeSession = %v, %v", ok, err)
	}
	mu.Lock()
	got := append([]string(nil), announced...)
	mu.Unlock()
	if len(got) == 0 || got[0] != id {
		t.Fatalf("announced %v, want the revoked session", got)
	}
	// What a peer does with the announcement.
	b.EvictCachedSession(id)
	if b.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("B still honours a session A revoked, after being told")
	}
}
