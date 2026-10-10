package oidcauth

// CheckSession and the order of invalidation notices (Task 20398).
//
// A stream outlives the request that opened it, so it has to ask on a timer
// whether its session still stands. Two properties make that question safe to
// ask: asking it must not count as the user being active, and a notice that a
// session changed must arrive only once the change can be read back.

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestCheckSessionLeavesTheIdleClockAlone: a stream re-checking its session
// every thirty seconds must not keep an unattended tab signed in. The same
// cadence through SessionFromRequest does exactly that, which is why streams
// may not use it.
func TestCheckSessionLeavesTheIdleClockAlone(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.SessionTTL = 24 * time.Hour
		c.IdleTimeout = time.Hour
		c.Audit = rec.sink
	})
	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	id := HashSessionID(sid)

	for elapsed := time.Duration(0); elapsed < 59*time.Minute; elapsed += 30 * time.Second {
		clk.advance(30 * time.Second)
		if _, st := a.CheckSession(id); st != SessionLive {
			t.Fatalf("after %s of re-checks the session reads %q, want live", elapsed, st)
		}
	}
	clk.advance(2 * time.Minute)
	if _, st := a.CheckSession(id); st != SessionIdle {
		t.Fatalf("an hour of nothing but re-checks left the session %q, want idle: a re-check "+
			"that counts as use keeps an unattended tab signed in for ever", st)
	}
	if a.SessionCount() != 0 {
		t.Error("an idle session found by a re-check must be ended, as the request path ends it")
	}
	if ev, ok := rec.last(AuditSessionExpired); !ok || ev.Reason != ReasonIdleTimeout {
		t.Errorf("want session.expired/%s, got %+v (found=%v)", ReasonIdleTimeout, ev, ok)
	}

	// The contrast, which is the reason CheckSession exists.
	b := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.SessionTTL = 24 * time.Hour
		c.IdleTimeout = time.Hour
	})
	sid2, err := b.createSession(Identity{Sub: "u2"}, reqWithCookie("x"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2*61; i++ {
		clk.advance(30 * time.Second)
		if _, ok := b.SessionFromRequest(reqWithCookie(sid2)); !ok {
			t.Fatalf("SessionFromRequest every 30s ended the session after %d checks", i+1)
		}
	}
}

// TestCheckSessionNamesEachEnding: every way a session stops authenticating
// reads as not live, and the three a stream reports differently are told apart.
func TestCheckSessionNamesEachEnding(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	a := newLifecycleAuth(t, idp, store, clk, func(c *Config) {
		c.SessionTTL = 3 * time.Hour
		c.IdleTimeout = time.Hour
	})
	mint := func(sub string) (cookie, id string) {
		t.Helper()
		sid, err := a.createSession(Identity{Sub: sub}, reqWithCookie("x"), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		return sid, HashSessionID(sid)
	}

	_, revoked := mint("revoked")
	if ok, err := a.RevokeSession(revoked, "admin", ""); err != nil || !ok {
		t.Fatalf("RevokeSession = %v, %v", ok, err)
	}
	signedOut, signedOutID := mint("signed-out")
	a.Logout(httptest.NewRecorder(), reqWithCookie(signedOut))
	_, others := mint("everywhere")
	if _, err := a.LogoutAll("everywhere", "", "everywhere"); err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{
		"revoked": revoked, "signed out": signedOutID, "logged out everywhere": others,
		"never issued": HashSessionID("no-such-cookie"), "empty": "",
	} {
		if _, st := a.CheckSession(id); st != SessionGone {
			t.Errorf("%s: %q, want gone", name, st)
		}
	}

	// The two clocks, each found by CheckSession itself rather than by a
	// request that got there first.
	_, fresh := mint("fresh")
	if rec, st := a.CheckSession(fresh); st != SessionLive || rec.Identity.Sub != "fresh" {
		t.Fatalf("a live session reads %q (%+v)", st, rec.Identity)
	}
	clk.advance(61 * time.Minute)
	if _, st := a.CheckSession(fresh); st != SessionIdle {
		t.Errorf("idle: %q, want idle", st)
	}
	ceiling, ceilingID := mint("ceiling")
	for i := 0; i < 5; i++ {
		clk.advance(30 * time.Minute)
		if _, ok := a.SessionFromRequest(reqWithCookie(ceiling)); !ok {
			t.Fatalf("a session in use ended after %d half-hours", i+1)
		}
	}
	// 3h01m since sign-in, 31 minutes since last used: never idle, past its 3h.
	clk.advance(31 * time.Minute)
	if _, st := a.CheckSession(ceilingID); st != SessionExpired {
		t.Errorf("past its ceiling: %q, want expired", st)
	}

	var off *Authenticator
	if _, st := off.CheckSession(fresh); st != SessionGone {
		t.Errorf("a nil authenticator reads %q, want gone", st)
	}
}

// TestSessionChangeIsAnnouncedAfterTheRowIsGone: whoever hears that a session
// changed re-reads it. Announced before the delete, the re-read found the row
// still there — another hub process cached it for thirty more seconds, and a
// stream asking whether it may stay open was told yes.
func TestSessionChangeIsAnnouncedAfterTheRowIsGone(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)

	var mu sync.Mutex
	stillThere := map[string]bool{}
	announced := map[string]bool{}
	a := newLifecycleAuth(t, idp, store, clk, func(c *Config) {
		c.SessionTTL = 3 * time.Hour
		c.IdleTimeout = time.Hour
		c.OnCacheInvalidate = func(id string) {
			_, err := store.Get(id)
			mu.Lock()
			announced[id] = true
			if err == nil {
				stillThere[id] = true
			}
			mu.Unlock()
		}
	})
	mint := func(sub string) (string, string) {
		t.Helper()
		sid, err := a.createSession(Identity{Sub: sub}, reqWithCookie("x"), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		return sid, HashSessionID(sid)
	}

	_, revoked := mint("revoked")
	if ok, err := a.RevokeSession(revoked, "admin", ""); err != nil || !ok {
		t.Fatalf("RevokeSession = %v, %v", ok, err)
	}
	signedOut, signedOutID := mint("signed-out")
	a.Logout(httptest.NewRecorder(), reqWithCookie(signedOut))
	_, everywhere := mint("everywhere")
	if _, err := a.LogoutAll("everywhere", "", "everywhere"); err != nil {
		t.Fatal(err)
	}
	idle, idleID := mint("idle")
	clk.advance(61 * time.Minute)
	if _, ok := a.SessionFromRequest(reqWithCookie(idle)); ok {
		t.Fatal("an idle session authenticated")
	}
	_, swept := mint("swept")
	clk.advance(61 * time.Minute)
	if n := a.SweepExpired(); n != 1 {
		t.Fatalf("SweepExpired ended %d sessions, want 1", n)
	}

	mu.Lock()
	defer mu.Unlock()
	for name, id := range map[string]string{
		"RevokeSession": revoked, "Logout": signedOutID, "LogoutAll": everywhere,
		"idle on the read path": idleID, "SweepExpired": swept,
	} {
		if !announced[id] {
			t.Errorf("%s: the change was never announced", name)
			continue
		}
		if stillThere[id] {
			t.Errorf("%s: announced while the row was still in the store — a listener "+
				"re-reading on the notice finds the session alive", name)
		}
	}
}
