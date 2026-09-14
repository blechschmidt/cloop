package oidcauth

// Tests for bounded authorization staleness (Task 20273).
//
// The property under test is not "claims eventually update" — lifecycle_test.go
// already covers that, driven by the janitor. It is that a demotion at the
// identity provider reaches the *next privileged call* rather than the next
// scheduled pass, including on a hub where the scheduled pass is switched off,
// and that it cannot be outrun by sending more requests.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// newClaimFreshAuth builds an authenticator whose background revalidation is
// switched off entirely.
//
// That is the point rather than a convenience. Every test in this file would
// pass trivially if the janitor were running and happened to tick, so they
// disable it: whatever freshness these tests observe was established by the
// synchronous path and by nothing else.
func newClaimFreshAuth(t *testing.T, idp *fakeIdP, clk *clock, mutate func(*Config)) *Authenticator {
	t.Helper()
	return newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.RefreshInterval = -1 // background pass disabled
		c.MaxClaimAge = 5 * time.Minute
		c.EffectiveRole = stubRoleLadder
		if mutate != nil {
			mutate(c)
		}
	})
}

// signedInAdmin creates a session holding the admin group, with claims stamped
// as of the current clock.
func signedInAdmin(t *testing.T, a *Authenticator, refreshToken string) string {
	t.Helper()
	sid, err := a.createSession(
		Identity{Sub: "u1", Email: "alice@example.com", Groups: []string{"admins", "engineering"}},
		reqWithCookie("x"), refreshToken, &tokenResponse{ExpiresIn: 3600})
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	return sid
}

// sessionIDFor maps a cookie to the stored session's id.
func sessionIDFor(sid string) string { return HashSessionID(sid) }

// ── the headline ────────────────────────────────────────────────────────────

// TestGroupRemovalTakesEffectOnNextPrivilegedCall is the defect this work
// exists to close.
//
// Before it, an administrator removed from the admin group at the IdP kept hub
// admin until the janitor's next pass — RefreshInterval, 15 minutes by default,
// and never if an operator had disabled it. The janitor here is disabled, so
// the only thing that can narrow this session is the privileged call itself.
func TestGroupRemovalTakesEffectOnNextPrivilegedCall(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newClaimFreshAuth(t, idp, clk, nil)
	idp.refreshIDToken = adminThenDemoted(idp)

	sid := signedInAdmin(t, a, "rt-1")
	id := sessionIDFor(sid)

	// Inside the bound: no IdP contact at all, claims as signed in.
	clk.advance(time.Minute)
	rec, err := a.EnsureFreshClaims(context.Background(), id)
	if err != nil {
		t.Fatalf("fresh claims must not error: %v", err)
	}
	if !hasClaim(rec.Identity.Groups, "admins") {
		t.Fatalf("claims inside the bound must be served as-is, got %v", rec.Identity.Groups)
	}
	if n := idp.refreshRequests; n != 0 {
		t.Fatalf("claims inside the bound cost %d IdP round trips, want 0 — "+
			"a freshness check that always calls out is a hot-path regression", n)
	}

	// Past the bound: the provider is asked, and still says admin.
	clk.advance(6 * time.Minute)
	rec, err = a.EnsureFreshClaims(context.Background(), id)
	if err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}
	if !hasClaim(rec.Identity.Groups, "admins") {
		t.Fatalf("the IdP still released admins; claims = %v", rec.Identity.Groups)
	}
	if idp.refreshRequests != 1 {
		t.Fatalf("refresh requests = %d, want exactly 1", idp.refreshRequests)
	}

	// The group is now gone at the provider. This is the assertion that
	// matters: nothing scheduled runs between here and the answer.
	clk.advance(6 * time.Minute)
	rec, err = a.EnsureFreshClaims(context.Background(), id)
	if err != nil {
		t.Fatalf("a narrowed session must still resolve, got error: %v", err)
	}
	if hasClaim(rec.Identity.Groups, "admins") {
		t.Fatalf("session still carries the admin group after the IdP withdrew it: %v — "+
			"the demotion is waiting for a background pass that is disabled", rec.Identity.Groups)
	}
	if !hasClaim(rec.Identity.Groups, "engineering") {
		t.Fatalf("the groups the user kept were dropped too: %v", rec.Identity.Groups)
	}

	// And it is durable: the narrowing was written, not merely returned.
	stored, err := a.store.Get(id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if hasClaim(stored.Identity.Groups, "admins") {
		t.Fatalf("stored claims still admin: %v — the next request would re-grant it",
			stored.Identity.Groups)
	}
}

// TestClaimFreshnessHoldsWithRefreshIntervalDisabled states the same property
// as a configuration contract.
//
// refresh_interval_minutes: -1 is a supported setting and means "do not poll
// the IdP in the background". It must not also mean "never re-check before
// granting a credential": those are different promises, and collapsing them is
// how a hub ends up honouring sign-in-time claims for the life of a session.
func TestClaimFreshnessHoldsWithRefreshIntervalDisabled(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newClaimFreshAuth(t, idp, clk, nil)
	idp.refreshIDToken = func(n int) map[string]any {
		return idp.refreshClaims(map[string]any{"groups": []string{"engineering"}})
	}

	sid := signedInAdmin(t, a, "rt-1")

	// Two hours: far past any refresh interval a hub would configure, and still
	// inside both session clocks, so what follows is about claim freshness and
	// not about a session that quietly expired.
	clk.advance(2 * time.Hour)
	// Prove the background path really is inert before relying on the result.
	if checked, _ := a.RevalidateDue(context.Background()); checked != 0 {
		t.Fatalf("RevalidateDue checked %d sessions with the interval disabled", checked)
	}
	if id := a.IdentityFromRequest(reqWithCookie(sid)); id == nil || !hasClaim(id.Groups, "admins") {
		t.Fatal("with the background pass off, the read path must still serve the old claims")
	}

	rec, err := a.EnsureFreshClaims(context.Background(), sessionIDFor(sid))
	if err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}
	if hasClaim(rec.Identity.Groups, "admins") {
		t.Fatalf("refresh_interval_minutes: -1 left claims frozen for a privileged call: %v",
			rec.Identity.Groups)
	}
}

// TestSelfDemotionCannotBeOutrun fires a burst of privileged checks at the
// instant the provider narrows the claims.
//
// Two things must hold, and they pull in opposite directions. Every caller must
// see the *new* claims — otherwise an administrator being demoted keeps admin
// simply by having several requests in flight, which is the easiest possible
// way to outrun the check. And the burst must cost one round trip, not N —
// otherwise the fix is a way to make any dashboard panel a load generator
// against the identity provider.
func TestSelfDemotionCannotBeOutrun(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newClaimFreshAuth(t, idp, clk, nil)
	// Demoted from the very first refresh: the demotion is already true at the
	// provider when the burst arrives.
	idp.refreshIDToken = func(n int) map[string]any {
		return idp.refreshClaims(map[string]any{"groups": []string{"engineering"}})
	}

	sid := signedInAdmin(t, a, "rt-1")
	id := sessionIDFor(sid)
	clk.advance(6 * time.Minute)

	const callers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []SessionRecord
		errs    []error
	)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec, err := a.EnsureFreshClaims(context.Background(), id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			results = append(results, rec)
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("concurrent freshness checks errored: %v", errs)
	}
	if len(results) != callers {
		t.Fatalf("got %d results, want %d", len(results), callers)
	}
	for i, rec := range results {
		if hasClaim(rec.Identity.Groups, "admins") {
			t.Fatalf("caller %d was served the pre-demotion claims %v — "+
				"a demotion can be outrun by sending more requests", i, rec.Identity.Groups)
		}
	}

	idp.mu.Lock()
	requests := idp.refreshRequests
	idp.mu.Unlock()
	if requests != 1 {
		t.Fatalf("a burst of %d privileged calls cost %d IdP round trips, want 1 — "+
			"single-flighting is not collapsing them", callers, requests)
	}
	if n := a.claimFlightsInProgress(); n != 0 {
		t.Fatalf("%d flights left registered after completion (leak)", n)
	}
}

// ── the userinfo 401 ────────────────────────────────────────────────────────

// TestUserinfoRejectionRepudiatesClaims covers the response that used to be
// explicitly ignored.
//
// The provider renews the grant and then refuses the access token it just
// minted at its own userinfo endpoint. Before this task the 401 was read and
// discarded with a comment saying so, and the session kept its sign-in claims
// indefinitely — the one answer in which the IdP declines to vouch for a
// session was the answer that changed nothing.
//
// The session must survive (a scope misconfiguration must not sign the fleet
// out), reads must keep working, and anything above operator must be refused
// until a later read succeeds.
func TestUserinfoRejectionRepudiatesClaims(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newClaimFreshAuth(t, idp, clk, func(c *Config) { c.Audit = rec.sink })
	// A userinfo endpoint that is advertised and answers 401.
	idp.userinfo = func(int) map[string]any { return map[string]any{"sub": "u1"} }
	idp.userinfoStatus = 401

	sid := signedInAdmin(t, a, "rt-1")
	id := sessionIDFor(sid)
	clk.advance(6 * time.Minute)

	_, err := a.EnsureFreshClaims(context.Background(), id)
	if err == nil {
		t.Fatal("a repudiated claim set must not authorise a privileged action")
	}
	if !errors.Is(err, ErrClaimsUnverifiable) {
		t.Fatalf("error = %v, want one wrapping ErrClaimsUnverifiable", err)
	}
	var cf *ClaimFreshnessError
	if !errors.As(err, &cf) || cf.Reason != reasonClaimsRejected {
		t.Fatalf("error = %v, want reason %q so the operator is sent to the IdP "+
			"rather than to their role bindings", err, reasonClaimsRejected)
	}

	// The session is alive and reads still work. This is the half that keeps a
	// misconfigured scope from becoming a logout bug.
	if got := a.IdentityFromRequest(reqWithCookie(sid)); got == nil {
		t.Fatal("a userinfo 401 must not end the session")
	}
	if rec.countOf(AuditSessionIdPRevoked) != 0 {
		t.Fatal("a userinfo 401 is not a revoked grant and must not be audited as one")
	}
	if rec.countOf(AuditSessionClaimsRejected) != 1 {
		t.Fatalf("claims_rejected events = %d, want 1 — a silently ignored refusal is "+
			"what this task exists to stop", rec.countOf(AuditSessionClaimsRejected))
	}
	if rec.countOf(AuditSessionClaimsStale) != 1 {
		t.Fatalf("claims_stale events = %d, want 1 (the refused action)",
			rec.countOf(AuditSessionClaimsStale))
	}
	if a.ClaimsRefused() != 1 {
		t.Fatalf("ClaimsRefused() = %d, want 1", a.ClaimsRefused())
	}

	// And it stays refused: the repudiation is durable, not a one-shot.
	stored, serr := a.store.Get(id)
	if serr != nil {
		t.Fatalf("store.Get: %v", serr)
	}
	if !stored.ClaimsStale(clk.now(), 5*time.Minute) {
		t.Fatal("the repudiation was not recorded; the next call would be allowed")
	}

	// Once the provider answers properly again, the session recovers without
	// anybody signing in again.
	idp.mu.Lock()
	idp.userinfoStatus = 0
	idp.userinfo = func(int) map[string]any {
		return map[string]any{"sub": "u1", "groups": []string{"engineering"}}
	}
	idp.mu.Unlock()

	healed, herr := a.EnsureFreshClaims(context.Background(), id)
	if herr != nil {
		t.Fatalf("a recovered userinfo endpoint must heal the session: %v", herr)
	}
	if hasClaim(healed.Identity.Groups, "admins") {
		t.Fatalf("claims after recovery = %v, want the provider's current set",
			healed.Identity.Groups)
	}
}

// TestUserinfoForbiddenWithoutInvalidTokenIsNotRepudiation guards the boundary
// in the other direction.
//
// A bare 403 is what a provider returns when the token is perfectly valid and
// simply lacks a scope. Reading that as "the IdP declines to vouch for this
// user" would turn a deployment-side misconfiguration into a verdict about a
// person, so only an explicit invalid_token counts.
func TestUserinfoForbiddenWithoutInvalidTokenIsNotRepudiation(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newClaimFreshAuth(t, idp, clk, func(c *Config) { c.Audit = rec.sink })
	idp.userinfo = func(int) map[string]any { return map[string]any{"sub": "u1"} }
	idp.userinfoStatus = 403

	sid := signedInAdmin(t, a, "rt-1")
	clk.advance(6 * time.Minute)

	_, err := a.EnsureFreshClaims(context.Background(), sessionIDFor(sid))
	var cf *ClaimFreshnessError
	if !errors.As(err, &cf) {
		t.Fatalf("error = %v, want a ClaimFreshnessError", err)
	}
	if cf.Reason != reasonIdPUnreachable {
		t.Fatalf("reason = %q, want %q: a scope problem is not the provider "+
			"repudiating the user", cf.Reason, reasonIdPUnreachable)
	}
	if rec.countOf(AuditSessionClaimsRejected) != 0 {
		t.Fatal("a bare 403 must not be recorded as a repudiation")
	}

	// With the header RFC 6750 calls for, it is one.
	idp.mu.Lock()
	idp.userinfoAuthHeader = `Bearer error="invalid_token", error_description="expired"`
	idp.mu.Unlock()
	clk.advance(6 * time.Minute)
	if _, err := a.EnsureFreshClaims(context.Background(), sessionIDFor(sid)); err == nil {
		t.Fatal("expected a refusal")
	}
	if rec.countOf(AuditSessionClaimsRejected) != 1 {
		t.Fatalf("claims_rejected = %d, want 1 once the provider named invalid_token",
			rec.countOf(AuditSessionClaimsRejected))
	}
}

// ── the provider's own clock ────────────────────────────────────────────────

// TestAccessTokenExpiryTightensClaimFreshness proves expires_in is honoured
// rather than parsed and dropped.
//
// A provider issuing 60-second access tokens is stating how long it stands
// behind the authorization that produced these claims. cloop's own bound here
// is five minutes, so if the field were still ignored the session would sail
// past the provider's deadline untouched.
func TestAccessTokenExpiryTightensClaimFreshness(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newClaimFreshAuth(t, idp, clk, nil)
	idp.refreshExpiresIn = 60
	idp.refreshIDToken = func(n int) map[string]any {
		return idp.refreshClaims(map[string]any{"groups": []string{"admins"}})
	}

	sid := signedInAdmin(t, a, "rt-1")
	id := sessionIDFor(sid)

	// One assertion, carrying the provider's 60-second deadline.
	clk.advance(6 * time.Minute)
	if _, err := a.EnsureFreshClaims(context.Background(), id); err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}
	if idp.refreshRequests != 1 {
		t.Fatalf("refresh requests = %d, want 1", idp.refreshRequests)
	}

	// Ninety seconds later cloop's own five-minute bound has plenty left, so
	// only the provider's deadline can force another read.
	clk.advance(90 * time.Second)
	if _, err := a.EnsureFreshClaims(context.Background(), id); err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}
	if idp.refreshRequests != 2 {
		t.Fatalf("refresh requests = %d, want 2 — the access token's expires_in is "+
			"being stored and never read, so the provider's own freshness policy "+
			"has no effect", idp.refreshRequests)
	}

	// And it can only tighten, never loosen: a long-lived access token does not
	// buy a session past cloop's bound.
	idp.mu.Lock()
	idp.refreshExpiresIn = 86400
	idp.mu.Unlock()
	if _, err := a.EnsureFreshClaims(context.Background(), id); err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}
	before := idp.refreshRequests
	clk.advance(6 * time.Minute)
	if _, err := a.EnsureFreshClaims(context.Background(), id); err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}
	if idp.refreshRequests != before+1 {
		t.Fatalf("a 24h access token suppressed cloop's own 5m bound "+
			"(requests %d → %d)", before, idp.refreshRequests)
	}
}

// TestReassertedClaimsClearAStaleProviderDeadline covers the bug that a
// deadline must be replaced, not inherited.
//
// A provider that states expires_in intermittently would otherwise have every
// silent response measured against the previous response's deadline — which is
// already in the past — leaving the session permanently unable to act however
// often its claims are re-read.
func TestReassertedClaimsClearAStaleProviderDeadline(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newClaimFreshAuth(t, idp, clk, nil)
	idp.refreshExpiresIn = 60
	idp.refreshIDToken = func(n int) map[string]any {
		return idp.refreshClaims(map[string]any{"groups": []string{"admins"}})
	}

	sid := signedInAdmin(t, a, "rt-1")
	id := sessionIDFor(sid)

	clk.advance(6 * time.Minute)
	if _, err := a.EnsureFreshClaims(context.Background(), id); err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}

	// The provider stops stating one.
	idp.mu.Lock()
	idp.refreshExpiresIn = -1 // omitted / zero on the wire
	idp.mu.Unlock()
	clk.advance(2 * time.Minute)
	if _, err := a.EnsureFreshClaims(context.Background(), id); err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}

	stored, err := a.store.Get(id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.ClaimsStale(clk.now(), 5*time.Minute) {
		t.Fatal("freshly asserted claims read as stale: the previous response's " +
			"expires_in deadline was inherited instead of replaced")
	}
}

// ── refusal paths ───────────────────────────────────────────────────────────

// TestClaimFreshnessRefusesWithoutRefreshToken covers the hub that cannot ask.
//
// No CLOOP_SECRET_KEY means no sealed refresh token, which means claims can
// never be re-asserted. Failing closed is the security-correct answer and it is
// also a lockout, so the message has to name both remedies — that is asserted
// here, because an unhelpful refusal on this path is indistinguishable from a
// broken hub.
func TestClaimFreshnessRefusesWithoutRefreshToken(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newClaimFreshAuth(t, idp, clk, func(c *Config) { c.Audit = rec.sink })

	sid := signedInAdmin(t, a, "") // no refresh token retained
	clk.advance(6 * time.Minute)

	_, err := a.EnsureFreshClaims(context.Background(), sessionIDFor(sid))
	if !errors.Is(err, ErrClaimsUnverifiable) {
		t.Fatalf("error = %v, want one wrapping ErrClaimsUnverifiable", err)
	}
	var cf *ClaimFreshnessError
	if !errors.As(err, &cf) || cf.Reason != reasonNoRefreshToken {
		t.Fatalf("reason = %+v, want %q", cf, reasonNoRefreshToken)
	}
	for _, want := range []string{"CLOOP_SECRET_KEY", "max_claim_age_minutes"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal message does not mention %q — an administrator locked "+
				"out here has nothing to act on: %v", want, err)
		}
	}
	if idp.tokenRequests != 0 {
		t.Fatalf("token requests = %d, want 0: there was nothing to present", idp.tokenRequests)
	}
	if rec.countOf(AuditSessionClaimsStale) != 1 {
		t.Fatalf("claims_stale events = %d, want 1", rec.countOf(AuditSessionClaimsStale))
	}

	// Reads are unaffected. The degradation is scoped to privileged actions.
	if a.IdentityFromRequest(reqWithCookie(sid)) == nil {
		t.Fatal("a session that cannot be revalidated must still authenticate reads")
	}
}

// TestClaimFreshnessDisabledNeverContactsIdP covers the documented opt-out. It
// is the setting a hub without an encryption key is told to use, so it has to
// actually be free.
func TestClaimFreshnessDisabledNeverContactsIdP(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newClaimFreshAuth(t, idp, clk, func(c *Config) { c.MaxClaimAge = -1 })

	sid := signedInAdmin(t, a, "")
	clk.advance(30 * 24 * time.Hour)

	rec, err := a.EnsureFreshClaims(context.Background(), sessionIDFor(sid))
	if err != nil {
		t.Fatalf("with the check disabled nothing may be refused: %v", err)
	}
	if !hasClaim(rec.Identity.Groups, "admins") {
		t.Fatalf("claims = %v, want the sign-in set", rec.Identity.Groups)
	}
	if idp.tokenRequests != 0 {
		t.Fatalf("token requests = %d, want 0 with the check disabled", idp.tokenRequests)
	}
}

// TestUnreachableIdPRefusesPrivilegedButKeepsSession is the availability
// trade stated as a test: a provider outage must cost privileged actions and
// nothing else. Failing open would defeat the point; ending sessions would turn
// an IdP outage into a total one.
func TestUnreachableIdPRefusesPrivilegedButKeepsSession(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := newClaimFreshAuth(t, idp, clk, nil)
	idp.refreshStatus = 503
	idp.refreshBody = `{"error":"temporarily_unavailable"}`

	sid := signedInAdmin(t, a, "rt-1")
	clk.advance(6 * time.Minute)

	_, err := a.EnsureFreshClaims(context.Background(), sessionIDFor(sid))
	if !errors.Is(err, ErrClaimsUnverifiable) {
		t.Fatalf("error = %v, want one wrapping ErrClaimsUnverifiable", err)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) == nil {
		t.Fatal("an IdP outage must not sign users out")
	}
}

// TestEnsureFreshClaimsReportsARevokedSessionAsGone covers the overlap with
// IdP-initiated revocation: if the provider withdraws the grant during the
// synchronous check, the session is terminated by the same code the background
// pass uses, and the caller is told there is no session rather than that they
// lack a permission.
func TestEnsureFreshClaimsReportsARevokedSessionAsGone(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newClaimFreshAuth(t, idp, clk, func(c *Config) { c.Audit = rec.sink })
	idp.refreshStatus = 400
	idp.refreshBody = `{"error":"invalid_grant"}`

	sid := signedInAdmin(t, a, "rt-1")
	clk.advance(6 * time.Minute)

	_, err := a.EnsureFreshClaims(context.Background(), sessionIDFor(sid))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("error = %v, want ErrSessionNotFound", err)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("a withdrawn grant must end the session on the synchronous path too")
	}
	if rec.countOf(AuditSessionIdPRevoked) != 1 {
		t.Fatalf("idp_revoked events = %d, want 1", rec.countOf(AuditSessionIdPRevoked))
	}
}

// ── the upgrade ─────────────────────────────────────────────────────────────

// TestLegacySessionDatesClaimsFromSignIn covers rows written before the claim
// columns existed.
//
// Reporting them as "never asserted" would be the safe-looking choice and is
// the wrong one: such a session did have exactly one verified assertion, at
// sign-in, and treating it as undated would make every live session on the hub
// unable to perform a privileged action the instant the binary rolls — a
// self-inflicted outage during an upgrade.
func TestLegacySessionDatesClaimsFromSignIn(t *testing.T) {
	clk := newClock()
	issued := clk.now().Add(-2 * time.Minute)
	rec := SessionRecord{
		ID:       "legacy",
		IssuedAt: issued,
		LastSeen: issued,
		// ClaimsAsOf and ClaimsExpireAt deliberately zero.
	}
	if got := rec.ClaimsAssertedAt(); !got.Equal(issued) {
		t.Fatalf("ClaimsAssertedAt() = %v, want the issue time %v", got, issued)
	}
	if rec.ClaimsStale(clk.now(), 5*time.Minute) {
		t.Fatal("a two-minute-old session read as claim-stale: every live session " +
			"would be locked out of privileged actions by the upgrade itself")
	}
	if !rec.ClaimsStale(clk.now(), time.Minute) {
		t.Fatal("the fallback must still be subject to the bound")
	}
}

// TestClaimsStaleHonoursBothDeadlines pins the comparison itself, since it is
// the one expression every other assertion in this file rests on.
func TestClaimsStaleHonoursBothDeadlines(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		rec    SessionRecord
		maxAge time.Duration
		want   bool
	}{
		{
			name:   "inside both",
			rec:    SessionRecord{ClaimsAsOf: now.Add(-time.Minute), ClaimsExpireAt: now.Add(time.Hour)},
			maxAge: 5 * time.Minute,
			want:   false,
		},
		{
			name:   "past cloop's bound",
			rec:    SessionRecord{ClaimsAsOf: now.Add(-6 * time.Minute), ClaimsExpireAt: now.Add(time.Hour)},
			maxAge: 5 * time.Minute,
			want:   true,
		},
		{
			name:   "past the provider's deadline",
			rec:    SessionRecord{ClaimsAsOf: now.Add(-time.Minute), ClaimsExpireAt: now.Add(-time.Second)},
			maxAge: 5 * time.Minute,
			want:   true,
		},
		{
			name:   "provider stated none",
			rec:    SessionRecord{ClaimsAsOf: now.Add(-time.Minute)},
			maxAge: 5 * time.Minute,
			want:   false,
		},
		{
			name:   "check disabled",
			rec:    SessionRecord{ClaimsAsOf: now.Add(-30 * 24 * time.Hour), ClaimsExpireAt: now.Add(-time.Hour)},
			maxAge: -1,
			want:   false,
		},
		{
			name:   "undatable row fails closed",
			rec:    SessionRecord{},
			maxAge: 5 * time.Minute,
			want:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.ClaimsStale(now, tc.maxAge); got != tc.want {
				t.Fatalf("ClaimsStale() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMaxClaimAgeIsBounded covers the config validation. An hour is where the
// setting stops being a freshness bound; refusing rather than clamping means an
// operator who wrote a day finds out, instead of quietly getting an hour.
func TestMaxClaimAgeIsBounded(t *testing.T) {
	idp := newFakeIdP(t)
	base := func(d time.Duration) Config {
		return Config{
			Enabled: true, Issuer: idp.server.URL,
			ClientID: "c", ClientSecret: "s",
			RedirectURL: "https://cloop.example.com/auth/callback",
			MaxClaimAge: d,
		}
	}
	if _, err := New(base(24 * time.Hour)); err == nil {
		t.Fatal("a 24h claim age must be refused, not silently clamped")
	}
	a, err := New(base(0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.MaxClaimAge() != DefaultMaxClaimAge {
		t.Fatalf("MaxClaimAge() = %v, want the default %v", a.MaxClaimAge(), DefaultMaxClaimAge)
	}
	off, err := New(base(-time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if off.MaxClaimAge() > 0 {
		t.Fatalf("MaxClaimAge() = %v, want the negative opt-out preserved", off.MaxClaimAge())
	}
}
