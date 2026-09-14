package oidcauth

// Claim re-assertion from userinfo (Task 20261).
//
// The defect these cover: revalidate() only re-asserted a session's groups when
// the refresh response carried an id_token, and most providers do not return
// one. On those deployments an administrator removed from the admin group at
// the IdP kept admin here until the absolute session TTL — days, on a hub
// configured for a working week.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// userinfoDroppingAdmin is a provider whose userinfo endpoint releases the
// admin group on the first call and withholds it from then on: a user removed
// from a group at the IdP, expressed on the wire, on a provider that returns no
// id_token from the refresh grant.
func userinfoDroppingAdmin() func(int) map[string]any {
	return func(n int) map[string]any {
		groups := []string{"admins", "engineering"}
		if n > 1 {
			groups = []string{"engineering"}
		}
		return map[string]any{
			"sub":    "u1",
			"email":  "alice@example.com",
			"groups": groups,
		}
	}
}

func newUserinfoAuth(t *testing.T, idp *fakeIdP, rec *auditRecorder, clk *clock) *Authenticator {
	t.Helper()
	return newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.RefreshInterval = 15 * time.Minute
		c.Audit = rec.sink
		c.EffectiveRole = stubRoleLadder
	})
}

func adminSession(t *testing.T, a *Authenticator) string {
	t.Helper()
	sid, err := a.createSession(
		Identity{Sub: "u1", Email: "alice@example.com", Groups: []string{"admins", "engineering"}},
		reqWithCookie("x"), "rt-1")
	if err != nil {
		t.Fatal(err)
	}
	// Warm the read cache, so the test also proves re-assertion reaches
	// through it rather than only reaching the stored row.
	if id := a.IdentityFromRequest(reqWithCookie(sid)); id == nil || !hasClaim(id.Groups, "admins") {
		t.Fatalf("session should start as admin, got %+v", id)
	}
	return sid
}

// TestUserinfoNarrowsClaimsWhenRefreshOmitsIDToken is the defect this work
// closes. The refresh grant succeeds and returns no id_token — the common case
// — so before this the session kept its sign-in claims forever. Asking
// userinfo with the access token from that very response makes a group removal
// take effect within one revalidation interval instead of at absolute TTL.
func TestUserinfoNarrowsClaimsWhenRefreshOmitsIDToken(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	// refreshIDToken stays nil: the provider returns no id_token, ever.
	idp.userinfo = userinfoDroppingAdmin()
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	// First interval: userinfo still says admin, so nothing changes.
	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())
	if id := a.IdentityFromRequest(reqWithCookie(sid)); id == nil || !hasClaim(id.Groups, "admins") {
		t.Fatalf("re-asserting the same claims must not disturb them, got %+v", id)
	}

	// Second interval: the group is gone at the provider.
	clk.advance(16 * time.Minute)
	if _, terminated := a.RevalidateDue(context.Background()); terminated != 0 {
		t.Fatal("losing a group must narrow the session, not end it")
	}

	id := a.IdentityFromRequest(reqWithCookie(sid))
	if id == nil {
		t.Fatal("narrowing must leave the session alive")
	}
	if hasClaim(id.Groups, "admins") {
		t.Fatalf("session still carries the admin group after the IdP withdrew it: %v — "+
			"deprivileging at the IdP does not reach live sessions on a provider "+
			"that omits the id_token", id.Groups)
	}
	if !hasClaim(id.Groups, "engineering") {
		t.Fatalf("the groups the user kept were dropped too: %v", id.Groups)
	}

	// The narrowing must be visible in the trail, and the "we could not check"
	// event must NOT be: claims were checked, from userinfo.
	if got := rec.countOf(AuditSessionRoleNarrowed); got != 1 {
		t.Fatalf("role_narrowed events = %d, want 1", got)
	}
	if got := rec.countOf(AuditSessionClaimsUnverified); got != 0 {
		t.Fatalf("claims_unverified events = %d, want 0 — claims were verified, "+
			"just not from an id_token", got)
	}
	if asserted, unverified := a.RefreshClaimStats(); asserted != 2 || unverified != 0 {
		t.Fatalf("RefreshClaimStats() = (%d asserted, %d unverified), want (2, 0)",
			asserted, unverified)
	}

	// The endpoint must have been asked once per revalidation, authorised with
	// the access token the refresh returned — not the original sign-in token,
	// which may already have expired.
	if idp.userinfoRequests != 2 {
		t.Fatalf("userinfo requests = %d, want 2 (one per revalidation)", idp.userinfoRequests)
	}
	if idp.lastUserinfoAuth != "Bearer at-refreshed" {
		t.Fatalf("userinfo Authorization = %q, want the refreshed access token",
			idp.lastUserinfoAuth)
	}
}

// TestUserinfoSignedResponseIsVerified covers OIDC Core 5.3.2: a provider may
// return the claim set as a signed JWT. It must be signature-verified against
// the same JWKS as an id_token, because accepting it unverified would let
// anything that can answer the endpoint rewrite a session's groups.
func TestUserinfoSignedResponseIsVerified(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	idp.userinfo = userinfoDroppingAdmin()
	idp.userinfoSigned = true
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())
	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())

	id := a.IdentityFromRequest(reqWithCookie(sid))
	if id == nil || hasClaim(id.Groups, "admins") {
		t.Fatalf("a signed userinfo response must narrow the session too, got %+v", id)
	}
	if got := rec.countOf(AuditSessionRoleNarrowed); got != 1 {
		t.Fatalf("role_narrowed events = %d, want 1", got)
	}
}

// TestUserinfoForgedSignatureIsRejected is the other half of the signed case.
// A response signed by a key that is not the issuer's must not be able to
// change what a session may do — the failure mode would be silent privilege
// *escalation*, since a forger would add groups rather than remove them.
func TestUserinfoForgedSignatureIsRejected(t *testing.T) {
	idp := newFakeIdP(t)
	forger := newFakeIdP(t) // a different key entirely
	clk := newClock()
	rec := &auditRecorder{}

	idp.userinfo = func(int) map[string]any { return map[string]any{"sub": "u1"} }
	idp.userinfoSigned = true
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	// Swap in a body signed by the wrong key, claiming a group the user does
	// not have.
	idp.userinfo = func(int) map[string]any {
		return map[string]any{
			"iss": idp.server.URL, "sub": "u1",
			"groups": []string{"admins", "engineering", "superusers"},
		}
	}
	idp.signWith(forger)

	clk.advance(16 * time.Minute)
	if _, terminated := a.RevalidateDue(context.Background()); terminated != 0 {
		t.Fatal("a bad userinfo signature must not end the session; the grant was fine")
	}
	id := a.IdentityFromRequest(reqWithCookie(sid))
	if id == nil {
		t.Fatal("session must survive an unusable userinfo response")
	}
	if hasClaim(id.Groups, "superusers") {
		t.Fatalf("claims from a forged userinfo response were applied: %v", id.Groups)
	}
	// Unusable means unverified, and that has to be recorded — otherwise an
	// operator believes claims are being re-checked when they are not.
	if got := rec.countOf(AuditSessionClaimsUnverified); got != 1 {
		t.Fatalf("claims_unverified events = %d, want 1", got)
	}
}

// TestUserinfoSubjectMismatchEndsSession: a userinfo response describing a
// different person cannot be applied to this session. Applying it would hand
// somebody else's groups to this cookie.
func TestUserinfoSubjectMismatchEndsSession(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	idp.userinfo = func(int) map[string]any {
		return map[string]any{"sub": "someone-else", "groups": []string{"admins"}}
	}
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	clk.advance(16 * time.Minute)
	if _, terminated := a.RevalidateDue(context.Background()); terminated != 1 {
		t.Fatal("a userinfo response for another subject must end the session")
	}
	if id := a.IdentityFromRequest(reqWithCookie(sid)); id != nil {
		t.Fatalf("session survived a subject mismatch: %+v", id)
	}
	if got := rec.countOf(AuditSessionIdPRevoked); got != 1 {
		t.Fatalf("idp_revoked events = %d, want 1", got)
	}
}

// TestUserinfoUnavailableDegradesGracefully: an endpoint that is down, or one
// that refuses the access token, must leave the session exactly as it was. This
// is the state the feature exists to improve, not a reason to sign everyone
// out — a userinfo outage that logged out the whole hub would be a far worse
// failure than stale claims.
func TestUserinfoUnavailableDegradesGracefully(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"endpoint is down", 503},
		{"access token refused", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			clk := newClock()
			rec := &auditRecorder{}
			idp.userinfo = userinfoDroppingAdmin()
			idp.userinfoStatus = tc.status
			a := newUserinfoAuth(t, idp, rec, clk)
			sid := adminSession(t, a)

			clk.advance(16 * time.Minute)
			if _, terminated := a.RevalidateDue(context.Background()); terminated != 0 {
				t.Fatalf("userinfo returning %d must not end the session", tc.status)
			}
			id := a.IdentityFromRequest(reqWithCookie(sid))
			if id == nil {
				t.Fatal("session must survive an unusable userinfo endpoint")
			}
			if !hasClaim(id.Groups, "admins") || !hasClaim(id.Groups, "engineering") {
				t.Fatalf("claims must be left as captured at sign-in, got %v", id.Groups)
			}
			if got := rec.countOf(AuditSessionClaimsUnverified); got != 1 {
				t.Fatalf("claims_unverified events = %d, want 1 — an operator has to "+
					"be able to see that claims are not being re-checked", got)
			}
		})
	}
}

// TestNoUserinfoEndpointRecordsUnverified: a provider advertising no userinfo
// endpoint is a valid configuration. It must not error, and it must still be
// recorded as a deployment where claims are not re-asserted.
func TestNoUserinfoEndpointRecordsUnverified(t *testing.T) {
	idp := newFakeIdP(t) // userinfo left nil: not advertised
	clk := newClock()
	rec := &auditRecorder{}
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	clk.advance(16 * time.Minute)
	if _, terminated := a.RevalidateDue(context.Background()); terminated != 0 {
		t.Fatal("a provider with no userinfo endpoint must not end sessions")
	}
	if idp.userinfoRequests != 0 {
		t.Fatalf("userinfo was fetched (%d) though it is not advertised", idp.userinfoRequests)
	}
	if id := a.IdentityFromRequest(reqWithCookie(sid)); id == nil || !hasClaim(id.Groups, "admins") {
		t.Fatalf("claims must be left untouched, got %+v", id)
	}
	if got := rec.countOf(AuditSessionClaimsUnverified); got != 1 {
		t.Fatalf("claims_unverified events = %d, want 1", got)
	}
}

// TestUserinfoWrongIssuerRejected: a validly-signed response from another
// tenant of a shared IdP must not be accepted on its signature alone.
func TestUserinfoWrongIssuerRejected(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	idp.userinfoSigned = true
	idp.userinfo = func(int) map[string]any {
		return map[string]any{
			"iss": "https://another-tenant.example.com",
			"sub": "u1", "groups": []string{"admins", "engineering", "superusers"},
		}
	}
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())

	id := a.IdentityFromRequest(reqWithCookie(sid))
	if id == nil {
		t.Fatal("session must survive a rejected userinfo response")
	}
	if hasClaim(id.Groups, "superusers") {
		t.Fatalf("claims from a foreign issuer were applied: %v", id.Groups)
	}
	if got := rec.countOf(AuditSessionClaimsUnverified); got != 1 {
		t.Fatalf("claims_unverified events = %d, want 1", got)
	}
}

// TestUserinfoNoSubRejected: OIDC requires sub, and without it there is nothing
// binding the response to this session.
func TestUserinfoNoSubRejected(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	idp.userinfo = func(int) map[string]any {
		return map[string]any{"groups": []string{"admins", "superusers"}}
	}
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	clk.advance(16 * time.Minute)
	if _, terminated := a.RevalidateDue(context.Background()); terminated != 0 {
		t.Fatal("a userinfo response with no sub must not end the session")
	}
	id := a.IdentityFromRequest(reqWithCookie(sid))
	if id == nil || hasClaim(id.Groups, "superusers") {
		t.Fatalf("an unbindable userinfo response must change nothing, got %+v", id)
	}
	if got := rec.countOf(AuditSessionClaimsUnverified); got != 1 {
		t.Fatalf("claims_unverified events = %d, want 1", got)
	}
}

// TestUserinfoNotUsedWhenIDTokenPresent: the id_token is the stronger
// statement — it is bound to the client and carries an expiry — so a provider
// that returns one must not trigger an extra network round trip per session
// per interval.
func TestUserinfoNotUsedWhenIDTokenPresent(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	idp.refreshIDToken = adminThenDemoted(idp)
	idp.userinfo = func(int) map[string]any {
		return map[string]any{"sub": "u1", "groups": []string{"admins"}}
	}
	a := newUserinfoAuth(t, idp, rec, clk)
	sid := adminSession(t, a)

	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())
	clk.advance(16 * time.Minute)
	a.RevalidateDue(context.Background())

	if idp.userinfoRequests != 0 {
		t.Fatalf("userinfo was fetched %d time(s) though the id_token was present — "+
			"that is a network round trip per session per interval for nothing",
			idp.userinfoRequests)
	}
	// And the id_token's narrowing still applied, rather than being overwritten
	// by the (stale, admin-granting) userinfo body.
	if id := a.IdentityFromRequest(reqWithCookie(sid)); id == nil || hasClaim(id.Groups, "admins") {
		t.Fatalf("the id_token's claims must win, got %+v", id)
	}
}

// TestUserinfoRejectsUnsignedWhenJWTAdvertised guards the content-type branch:
// a body served as application/jwt that is not a JWS must be refused rather
// than parsed as JSON, which would skip signature verification entirely.
func TestUserinfoRejectsUnsignedWhenJWTAdvertised(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := newUserinfoAuth(t, idp, rec, clk)

	_, err := a.decodeUserinfo(context.Background(), "application/jwt",
		[]byte(`{"sub":"u1","groups":["admins"]}`))
	if err == nil {
		t.Fatal("a JSON body served as application/jwt was accepted; signature " +
			"verification can be skipped by setting a header")
	}
	if !strings.Contains(err.Error(), "compact JWS") {
		t.Fatalf("unexpected error: %v", err)
	}
}
