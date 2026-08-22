package oidcauth

// Session lifecycle tests (Task 20176).
//
// The five things that must hold for a hosted deployment, plus the race that
// makes the idle clock trustworthy under concurrency:
//
//	restart survival    a session outlives the process that created it
//	idle expiry         an unused session ends before its ceiling
//	absolute expiry     an active session still ends at its ceiling
//	revocation          a terminated session is refused on the next request
//	IdP revocation      a refused refresh ends the session; an outage does not
//	last_seen race      concurrent requests on one session stay coherent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source so the two expiry clocks can be driven
// without sleeping through hours.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newLifecycleAuth builds an authenticator over the supplied store and clock.
func newLifecycleAuth(t *testing.T, idp *fakeIdP, store SessionStore, clk *clock, mutate func(*Config)) *Authenticator {
	t.Helper()
	cfg := Config{
		Enabled:      true,
		Issuer:       idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "s3cret",
		RedirectURL:  "https://cloop.example.com/auth/callback",
		SessionTTL:   24 * time.Hour,
		IdleTimeout:  8 * time.Hour,
		Store:        store,
	}
	if clk != nil {
		cfg.Clock = clk.now
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// reqWithCookie builds a request carrying a session cookie.
func reqWithCookie(sid string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sid})
	r.RemoteAddr = "203.0.113.9:51234"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/128")
	return r
}

// auditRecorder collects lifecycle events for assertion.
type auditRecorder struct {
	mu     sync.Mutex
	events []SessionAudit
}

func (a *auditRecorder) sink(ev SessionAudit) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *auditRecorder) countOf(event string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e.Event == event {
			n++
		}
	}
	return n
}

func (a *auditRecorder) last(event string) (SessionAudit, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.events) - 1; i >= 0; i-- {
		if a.events[i].Event == event {
			return a.events[i], true
		}
	}
	return SessionAudit{}, false
}

// ── restart survival ────────────────────────────────────────────────────────

// TestSessionSurvivesRestart is the reason this feature exists: a session
// created by one process must still authenticate after that process is gone,
// so a rolling upgrade does not sign the whole fleet out.
//
// The store is the only thing shared between the two authenticators — the
// second has an empty cache and has never seen the cookie.
func TestSessionSurvivesRestart(t *testing.T) {
	idp := newFakeIdP(t)
	store := NewMemorySessionStore(0)
	rec := &auditRecorder{}

	before := newLifecycleAuth(t, idp, store, nil, func(c *Config) { c.Audit = rec.sink })
	sid, err := before.createSession(Identity{Sub: "u1", Email: "alice@example.com"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if rec.countOf(AuditSessionCreated) != 1 {
		t.Fatalf("session.created audited %d times, want 1", rec.countOf(AuditSessionCreated))
	}

	// "Restart": a brand new authenticator over the same store.
	after := newLifecycleAuth(t, idp, store, nil, nil)
	id := after.IdentityFromRequest(reqWithCookie(sid))
	if id == nil {
		t.Fatal("session must survive a restart — this is the whole point of persisting it")
	}
	if id.Sub != "u1" || id.Email != "alice@example.com" {
		t.Fatalf("reloaded identity = %+v, want sub u1 / alice@example.com", id)
	}
}

// TestOnlyTheHashIsStored pins that the store never holds a value a thief
// could present as a cookie.
func TestOnlyTheHashIsStored(t *testing.T) {
	idp := newFakeIdP(t)
	store := NewMemorySessionStore(0)
	a := newLifecycleAuth(t, idp, store, nil, nil)

	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.List()
	if err != nil || len(rows) != 1 {
		t.Fatalf("List: %v, %d rows", err, len(rows))
	}
	if rows[0].ID == sid {
		t.Fatal("the raw session id was stored — a stolen store would yield usable cookies")
	}
	if rows[0].ID != HashSessionID(sid) {
		t.Fatalf("stored id %q is not the digest of the cookie", rows[0].ID)
	}
	// And the digest is not a usable credential.
	if a.IdentityFromRequest(reqWithCookie(rows[0].ID)) != nil {
		t.Fatal("presenting the stored id as a cookie authenticated — the id must not be the secret")
	}
}

// ── the two clocks ──────────────────────────────────────────────────────────

// TestIdleTimeoutEndsSession checks that a session left unused past the idle
// window is refused, even though its absolute ceiling is hours away.
func TestIdleTimeoutEndsSession(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.SessionTTL = 24 * time.Hour
		c.IdleTimeout = time.Hour
		c.Audit = rec.sink
	})

	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}

	// Active use keeps it alive well past the idle window in aggregate.
	for i := 0; i < 4; i++ {
		clk.advance(50 * time.Minute)
		if a.IdentityFromRequest(reqWithCookie(sid)) == nil {
			t.Fatalf("session ended after %d periods of activity — use must refresh the idle clock", i+1)
		}
	}

	// Now leave it alone for longer than the window.
	clk.advance(61 * time.Minute)
	if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("idle session must be refused")
	}
	if a.SessionCount() != 0 {
		t.Fatal("idle session must be removed, not merely refused")
	}
	ev, ok := rec.last(AuditSessionExpired)
	if !ok || ev.Reason != "idle_timeout" {
		t.Fatalf("want a session.expired/idle_timeout audit event, got %+v (found=%v)", ev, ok)
	}
}

// TestAbsoluteExpiryEndsSession checks the ceiling cannot be extended by
// activity — the property that makes it a ceiling rather than a second idle
// timer.
func TestAbsoluteExpiryEndsSession(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.SessionTTL = 3 * time.Hour
		c.IdleTimeout = time.Hour
		c.Audit = rec.sink
	})

	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	// Continuous use: never idle, but the ceiling still arrives.
	for i := 0; i < 6; i++ {
		clk.advance(30 * time.Minute)
		a.IdentityFromRequest(reqWithCookie(sid))
	}
	clk.advance(time.Minute)
	if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("absolute TTL must end the session regardless of activity")
	}
	ev, ok := rec.last(AuditSessionExpired)
	if !ok || ev.Reason != "absolute_ttl" {
		t.Fatalf("want a session.expired/absolute_ttl audit event, got %+v (found=%v)", ev, ok)
	}
}

// TestIdleTimeoutClampedToTTL guards the config combination that would
// silently disable the idle clock: an idle window longer than the ceiling can
// never fire, so New holds it down instead of accepting it.
func TestIdleTimeoutClampedToTTL(t *testing.T) {
	idp := newFakeIdP(t)
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, func(c *Config) {
		c.SessionTTL = 2 * time.Hour
		c.IdleTimeout = 30 * time.Hour
	})
	if got := a.IdleTimeout(); got != 2*time.Hour {
		t.Fatalf("IdleTimeout = %s, want it clamped to the 2h ceiling", got)
	}
}

// TestSweepExpiredAuditsOnce checks the janitor's sweep removes sessions past
// either clock and audits each exactly once.
func TestSweepExpiredAuditsOnce(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.SessionTTL = time.Hour
		c.IdleTimeout = 30 * time.Minute
		c.Audit = rec.sink
	})
	for i := 0; i < 3; i++ {
		if _, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), ""); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(31 * time.Minute)
	if n := a.SweepExpired(); n != 3 {
		t.Fatalf("SweepExpired removed %d, want 3", n)
	}
	if n := a.SweepExpired(); n != 0 {
		t.Fatalf("second sweep removed %d, want 0 — rows must not be re-audited", n)
	}
	if got := rec.countOf(AuditSessionExpired); got != 3 {
		t.Fatalf("session.expired audited %d times, want exactly 3", got)
	}
}

// ── revocation ──────────────────────────────────────────────────────────────

// TestRevokeThenRequestIsRefused is the operator kill switch: after
// RevokeSession the very next request must not authenticate.
//
// It deliberately warms the cache first, since a revocation that only works on
// a cold cache is not a revocation.
func TestRevokeThenRequestIsRefused(t *testing.T) {
	idp := newFakeIdP(t)
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, func(c *Config) { c.Audit = rec.sink })

	sid, err := a.createSession(Identity{Sub: "u1", Email: "alice@example.com"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) == nil {
		t.Fatal("session must authenticate before revocation")
	}

	ok, err := a.RevokeSession(HashSessionID(sid), "ops@example.com", "")
	if err != nil || !ok {
		t.Fatalf("RevokeSession = %v, %v; want true, nil", ok, err)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("a revoked session authenticated — the cache must be evicted on revoke")
	}
	ev, ok := rec.last(AuditSessionRevoked)
	if !ok {
		t.Fatal("revocation must be audited")
	}
	if ev.Actor != "ops@example.com" || ev.Reason != "admin_revoked" {
		t.Fatalf("audit event = %+v, want actor ops@example.com / reason admin_revoked", ev)
	}

	// Revoking again is not an error, and must not write a second event.
	if ok, err := a.RevokeSession(HashSessionID(sid), "ops@example.com", ""); err != nil || ok {
		t.Fatalf("second RevokeSession = %v, %v; want false, nil", ok, err)
	}
	if got := rec.countOf(AuditSessionRevoked); got != 1 {
		t.Fatalf("session.revoked audited %d times, want 1", got)
	}
}

// TestLogoutAllEndsOtherSessionsOnly checks the self-service path ends every
// other session for the subject, spares the caller's, and does not touch
// anybody else's.
func TestLogoutAllEndsOtherSessionsOnly(t *testing.T) {
	idp := newFakeIdP(t)
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, func(c *Config) { c.Audit = rec.sink })

	mine, err := a.createSession(Identity{Sub: "u1", Email: "alice@example.com"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	var others []string
	for i := 0; i < 2; i++ {
		sid, err := a.createSession(Identity{Sub: "u1", Email: "alice@example.com"}, reqWithCookie("x"), "")
		if err != nil {
			t.Fatal(err)
		}
		others = append(others, sid)
	}
	bob, err := a.createSession(Identity{Sub: "u2", Email: "bob@example.com"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}

	n, err := a.LogoutAll("u1", HashSessionID(mine), "alice@example.com")
	if err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	if n != 2 {
		t.Fatalf("LogoutAll ended %d sessions, want 2", n)
	}
	if a.IdentityFromRequest(reqWithCookie(mine)) == nil {
		t.Fatal("logout-all must spare the calling session")
	}
	for _, sid := range others {
		if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
			t.Fatal("logout-all must end the subject's other sessions")
		}
	}
	if a.IdentityFromRequest(reqWithCookie(bob)) == nil {
		t.Fatal("logout-all must not touch another subject's session")
	}
	if got := rec.countOf(AuditSessionRevoked); got != 2 {
		t.Fatalf("session.revoked audited %d times, want 2", got)
	}
}

// TestLogoutClearsCookieAndSession checks the ordinary sign-out path.
func TestLogoutClearsCookieAndSession(t *testing.T) {
	idp := newFakeIdP(t)
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, func(c *Config) { c.Audit = rec.sink })

	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if id := a.Logout(w, reqWithCookie(sid)); id == nil || id.Sub != "u1" {
		t.Fatalf("Logout returned %+v, want the signed-out identity", id)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("session must be gone after logout")
	}
	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout must clear the session cookie")
	}
	if ev, ok := rec.last(AuditSessionRevoked); !ok || ev.Reason != "user_logout" {
		t.Fatalf("want session.revoked/user_logout, got %+v (found=%v)", ev, ok)
	}
}

// ── IdP revalidation ────────────────────────────────────────────────────────

// TestRefreshRejectionTerminatesSession is the mechanism that makes IdP-side
// revocation real: the provider answering invalid_grant — what a disabled user
// looks like on the wire — must end the session without waiting for a timeout.
func TestRefreshRejectionTerminatesSession(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.RefreshInterval = 15 * time.Minute
		c.Audit = rec.sink
	})

	sid, err := a.createSession(Identity{Sub: "u1", Email: "alice@example.com"}, reqWithCookie("x"), "rt-1")
	if err != nil {
		t.Fatal(err)
	}
	// The user is disabled at the provider.
	idp.refreshStatus = http.StatusBadRequest
	idp.refreshBody = `{"error":"invalid_grant","error_description":"Session not active"}`

	clk.advance(16 * time.Minute)
	checked, terminated := a.RevalidateDue(context.Background())
	if checked != 1 || terminated != 1 {
		t.Fatalf("RevalidateDue = (%d checked, %d terminated), want (1, 1)", checked, terminated)
	}
	if idp.lastRefreshToken != "rt-1" {
		t.Fatalf("IdP saw refresh_token %q, want rt-1", idp.lastRefreshToken)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("a session the IdP refused to renew must stop authenticating")
	}
	ev, ok := rec.last(AuditSessionIdPRevoked)
	if !ok {
		t.Fatal("an IdP-driven termination must be audited as session.idp_revoked")
	}
	if ev.Reason != "idp_invalid_grant" {
		t.Fatalf("audit reason = %q, want idp_invalid_grant so an operator can see why", ev.Reason)
	}
}

// TestRefreshOutageKeepsSession is the other half of the taxonomy: an
// unreachable or erroring IdP must not sign the fleet out. Failing closed here
// would turn a dependency outage into an availability incident.
func TestRefreshOutageKeepsSession(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.RefreshInterval = 15 * time.Minute
		c.Audit = rec.sink
	})

	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "rt-1")
	if err != nil {
		t.Fatal(err)
	}
	idp.refreshStatus = http.StatusServiceUnavailable
	idp.refreshBody = `{"error":"temporarily_unavailable"}`

	clk.advance(16 * time.Minute)
	if _, terminated := a.RevalidateDue(context.Background()); terminated != 0 {
		t.Fatalf("an IdP outage terminated %d sessions, want 0", terminated)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) == nil {
		t.Fatal("an IdP outage must not sign users out")
	}
	if got := rec.countOf(AuditSessionIdPRevoked); got != 0 {
		t.Fatalf("an outage produced %d idp_revoked events, want 0", got)
	}

	// The attempt is stamped, so the next tick backs off rather than
	// hammering a provider that is already struggling.
	before := idp.refreshRequests
	if _, _ = a.RevalidateDue(context.Background()); idp.refreshRequests != before {
		t.Fatalf("a second immediate pass retried (%d → %d requests); a failed check must back off",
			before, idp.refreshRequests)
	}
}

// TestRefreshRotationStoresNewToken guards the failure mode where a rotating
// IdP would sign everyone out on the *second* check: if the replacement token
// is not stored, the next redemption presents an already-consumed one and the
// provider answers invalid_grant.
func TestRefreshRotationStoresNewToken(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	a := newLifecycleAuth(t, idp, store, clk, func(c *Config) { c.RefreshInterval = 15 * time.Minute })

	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "rt-1")
	if err != nil {
		t.Fatal(err)
	}
	idp.nextRefreshToken = "rt-2"

	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())

	rec, err := store.Get(HashSessionID(sid))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.RefreshToken != "rt-2" {
		t.Fatalf("stored refresh token = %q, want the rotated rt-2", rec.RefreshToken)
	}
	if rec.RefreshCheckedAt.IsZero() {
		t.Fatal("a successful check must stamp refresh_checked_at or it re-runs every tick")
	}

	// Second pass presents the rotated token, not the consumed one.
	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())
	if idp.lastRefreshToken != "rt-2" {
		t.Fatalf("second check presented %q, want rt-2", idp.lastRefreshToken)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) == nil {
		t.Fatal("rotation must not sign the user out")
	}
}

// TestNoRefreshTokenSkipsRevalidation checks the degraded mode (no encryption
// key, so nothing retained) does not produce spurious IdP traffic.
func TestNoRefreshTokenSkipsRevalidation(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.RefreshInterval = 15 * time.Minute
	})
	if _, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), ""); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Hour)
	if checked, _ := a.RevalidateDue(context.Background()); checked != 0 {
		t.Fatalf("checked %d sessions with no refresh token, want 0", checked)
	}
	if idp.refreshRequests != 0 {
		t.Fatalf("made %d refresh requests with nothing to redeem", idp.refreshRequests)
	}
}

// TestRevalidationDisabled checks refresh_interval_minutes: -1 turns the whole
// mechanism off rather than merely making it slow.
func TestRevalidationDisabled(t *testing.T) {
	idp := newFakeIdP(t)
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, func(c *Config) {
		c.RefreshInterval = -1
	})
	if _, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "rt-1"); err != nil {
		t.Fatal(err)
	}
	if checked, _ := a.RevalidateDue(context.Background()); checked != 0 {
		t.Fatalf("checked %d sessions with revalidation disabled, want 0", checked)
	}
}

// ── concurrency ─────────────────────────────────────────────────────────────

// TestConcurrentRequestsDoNotCorruptLastSeen is the race test.
//
// Many goroutines authenticate with one cookie while the clock advances under
// them. Three things must hold: no data race (go test -race), the *shared*
// idle clock only ever moves forward, and the throttle actually throttles —
// N concurrent requests must not become N writes to the store.
//
// The monotonicity assertion samples the cache and the store, not the values
// returned to individual requests. Two concurrent requests read the clock at
// different instants and may finish in either order, so "the value handed to
// request N+1 is never earlier than the one handed to request N" is not a
// property any system has. What must hold is that neither request can move the
// shared timestamp backwards — because that, and only that, is what would
// shorten the idle window and expire a session early.
func TestConcurrentRequestsDoNotCorruptLastSeen(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	counting := &countingStore{SessionStore: store}
	a := newLifecycleAuth(t, idp, counting, clk, func(c *Config) {
		c.SessionTTL = 24 * time.Hour
		c.IdleTimeout = time.Hour
	})

	sid, err := a.createSession(Identity{Sub: "u1"}, reqWithCookie("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	hash := HashSessionID(sid)

	const workers, iterations = 16, 40
	var wg, sampler sync.WaitGroup
	done := make(chan struct{})
	var sampleMu sync.Mutex
	regressed := false

	// Sampler: watches the shared timestamps for a backwards step. It runs on
	// its own WaitGroup so it can be stopped *after* the workers finish.
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		var prevCache, prevStore time.Time
		for {
			select {
			case <-done:
				return
			default:
			}
			a.mu.Lock()
			cached := time.Time{}
			if ent, ok := a.cache[hash]; ok {
				cached = ent.rec.LastSeen
			}
			a.mu.Unlock()
			stored := time.Time{}
			if rec, err := store.Get(hash); err == nil {
				stored = rec.LastSeen
			}

			sampleMu.Lock()
			if cached.Before(prevCache) || stored.Before(prevStore) {
				regressed = true
			}
			if cached.After(prevCache) {
				prevCache = cached
			}
			if stored.After(prevStore) {
				prevStore = stored
			}
			sampleMu.Unlock()
		}
	}()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, ok := a.SessionFromRequest(reqWithCookie(sid)); !ok {
					t.Errorf("session must stay valid throughout the race")
					return
				}
			}
		}()
	}
	// Advance the clock concurrently so the throttle boundary is crossed
	// while requests are in flight — the interleaving that would corrupt a
	// naively-updated timestamp.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			clk.advance(10 * time.Second)
		}
	}()
	wg.Wait()
	close(done)
	sampler.Wait()

	sampleMu.Lock()
	bad := regressed
	sampleMu.Unlock()
	if bad {
		t.Fatal("last_seen went backwards under concurrency — the idle clock would expire early")
	}

	final, err := store.Get(hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.LastSeen.Before(final.IssuedAt) {
		t.Fatalf("persisted last_seen %s precedes issued_at %s", final.LastSeen, final.IssuedAt)
	}
	if final.LastSeen.After(clk.now()) {
		t.Fatalf("persisted last_seen %s is in the future (now %s)", final.LastSeen, clk.now())
	}

	// The clock advanced 200s across ~640 authenticated requests. With a
	// one-minute throttle that is a handful of writes, not hundreds.
	writes := counting.touches()
	if writes > 10 {
		t.Fatalf("%d last_seen writes for %d requests — the throttle is not throttling",
			writes, workers*iterations)
	}
	if a.SessionCount() != 1 {
		t.Fatalf("SessionCount = %d, want 1 — the race must not duplicate or drop the session",
			a.SessionCount())
	}
}

// countingStore counts Touch calls so the write-amplification guard above can
// assert on them.
type countingStore struct {
	SessionStore
	mu sync.Mutex
	n  int
}

func (c *countingStore) Touch(id string, t time.Time) error {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.SessionStore.Touch(id, t)
}

func (c *countingStore) touches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// ── IdP-side logout ─────────────────────────────────────────────────────────

// TestEndSessionURL checks the RP-initiated logout URL is built from discovery
// and carries what a provider needs to honour it.
func TestEndSessionURL(t *testing.T) {
	idp := newFakeIdP(t)
	idp.endSession = idp.server.URL + "/logout"
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, nil)

	// Nothing is known before discovery runs.
	if got := a.EndSessionURL(); got != "" {
		t.Fatalf("EndSessionURL before discovery = %q, want empty", got)
	}
	if _, err := a.discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}

	got := a.EndSessionURL()
	if got == "" {
		t.Fatal("EndSessionURL must be built once the provider advertises one")
	}
	for _, want := range []string{
		idp.server.URL + "/logout?",
		"client_id=cloop-dashboard",
		"post_logout_redirect_uri=https%3A%2F%2Fcloop.example.com%2F",
	} {
		if !contains(got, want) {
			t.Errorf("EndSessionURL = %q, missing %q", got, want)
		}
	}
}

// TestEndSessionURLAbsent checks a provider without the endpoint yields no
// redirect rather than a broken one.
func TestEndSessionURLAbsent(t *testing.T) {
	idp := newFakeIdP(t) // endSession left empty
	a := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, nil)
	if _, err := a.discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got := a.EndSessionURL(); got != "" {
		t.Fatalf("EndSessionURL = %q, want empty when the IdP advertises none", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}())
}
