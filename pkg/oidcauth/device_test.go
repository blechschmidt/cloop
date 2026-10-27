package oidcauth

// Tests for the device authorization grant that signs a terminal in (Task
// 20412). The properties worth pinning are the ones a careless change would
// quietly lose: the codes' alphabet and entropy, every answer the token
// endpoint gives, a code's single use, that only a browser may approve and
// only as itself, that the result is a session with its own clocks never
// longer than a browser's, and that nothing the hub hands out is a credential.

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// deviceAuth is a lifecycle authenticator with terminal sign-in on.
func deviceAuth(t *testing.T, idp *fakeIdP, clk *clock, rec *auditRecorder, mutate func(*Config)) *Authenticator {
	t.Helper()
	return newLifecycleAuth(t, idp, NewMemorySessionStore(0), clk, func(c *Config) {
		c.DeviceLogin = true
		// These tests are about the device window. Sudo mode (Task 20448)
		// adds its own reason to ask — a browser whose sign-in is not recent
		// — which sudo_test.go covers with it on.
		c.SudoMaxAge = -1
		if rec != nil {
			c.Audit = rec.sink
		}
		if mutate != nil {
			mutate(c)
		}
	})
}

// newTerminal is one `cloop login`: a credential and the code it asked for.
type terminal struct {
	credential string
	digest     string
	grant      DeviceGrant
}

// sessionID is the id the hub stores the terminal's session under.
func (tm terminal) sessionID() string { return CLISessionID(tm.digest) }

func askForCode(t *testing.T, a *Authenticator) terminal {
	t.Helper()
	cred, digest, err := NewCLICredential()
	if err != nil {
		t.Fatal(err)
	}
	g, err := a.BeginDeviceAuthorization(DeviceRequest{
		CredentialHash: digest, Hostname: "dev-laptop", IP: "198.51.100.20", UserAgent: "cloop/test (linux/amd64)",
	})
	if err != nil {
		t.Fatalf("BeginDeviceAuthorization: %v", err)
	}
	return terminal{credential: cred, digest: digest, grant: g}
}

// browserReq is a request from a signed-in browser.
func browserReq(sid string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/device/approve", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sid})
	r.RemoteAddr = "198.51.100.20:5555"
	return r
}

// approve runs an approval end to end: begin, the provider's code, the
// callback. It returns the callback's recorder and the authorization request.
func approve(t *testing.T, a *Authenticator, idp *fakeIdP, sid, userCode string) (*httptest.ResponseRecorder, url.Values) {
	t.Helper()
	ap, err := a.BeginDeviceApproval(context.Background(), browserReq(sid), userCode)
	if err != nil {
		t.Fatalf("BeginDeviceApproval: %v", err)
	}
	loc, err := url.Parse(ap.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	idp.nonce = q.Get("nonce")
	rec := httptest.NewRecorder()
	// The provider's redirect back carries no cookie, as the real
	// cross-site navigation under a Strict cookie does not.
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?"+url.Values{
		"state": {q.Get("state")}, "code": {"authcode-device"},
	}.Encode(), nil)
	if out := a.HandleCallback(rec, cb); out != LoginDevice {
		t.Fatalf("callback outcome %q, want %q", out, LoginDevice)
	}
	return rec, q
}

func pollCode(a *Authenticator, tm terminal) (DeviceSession, *DeviceTokenError) {
	s, err := a.ExchangeDeviceCode(tm.grant.DeviceCode)
	var te *DeviceTokenError
	if err != nil && errors.As(err, &te) {
		return s, te
	}
	if err != nil {
		return s, &DeviceTokenError{Code: "unexpected: " + err.Error()}
	}
	return s, nil
}

func cliReq(cred string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	r.Header.Set("Authorization", "Bearer "+cred)
	return r
}

// ── codes ───────────────────────────────────────────────────────────────────

func TestUserCodesAreUnambiguousAndCarryFortyBits(t *testing.T) {
	bits := float64(UserCodeLength) * math.Log2(float64(len(userCodeAlphabet)))
	if bits < 40 {
		t.Fatalf("a user code carries %.1f bits, want at least 40", bits)
	}
	for _, c := range userCodeAlphabet {
		if strings.ContainsRune("AEIOUY0123456789", c) {
			t.Errorf("alphabet contains %q: vowels spell words and digits read as letters", c)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := newUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != UserCodeLength || NormalizeUserCode(c) != c {
			t.Fatalf("drew %q, which is not canonical", c)
		}
		seen[c] = true
	}
	if len(seen) < 199 {
		t.Errorf("200 draws gave only %d distinct codes", len(seen))
	}
}

func TestNormalizeUserCodeForgivesCaseAndSeparatorsOnly(t *testing.T) {
	for in, want := range map[string]string{
		"BCDFG-HJKLM":     "BCDFGHJKLM",
		"bcdfg hjklm":     "BCDFGHJKLM",
		" bcdfghjklm ":    "BCDFGHJKLM",
		"BCDFG-HJKL":      "",
		"BCDFG-HJKLMN":    "",
		"BCDFG-HJKLA":     "",
		"BCDFG-HJKL0":     "",
		"BCDFG/HJKLM":     "",
		"ＢCDFG-HJKLM":     "",
		"<script>BCDFGHJ": "",
	} {
		if got := NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := FormatUserCode("BCDFGHJKLM"); got != "BCDFG-HJKLM" {
		t.Errorf("FormatUserCode = %q", got)
	}
}

func TestCLICredentialShape(t *testing.T) {
	cred, digest, err := NewCLICredential()
	if err != nil {
		t.Fatal(err)
	}
	if !IsCLICredential(cred) || digest != HashSessionID(cred) || !validCredentialHash(digest) {
		t.Fatalf("credential %q / digest %q do not have the expected shape", cred[:12]+"…", digest)
	}
	for _, bad := range []string{"", CLICredentialPrefix, "cloop_pat_x", cred + "x", cred[:len(cred)-1] + "!"} {
		if IsCLICredential(bad) {
			t.Errorf("IsCLICredential(%q) = true", bad)
		}
	}
}

// ── issuing ─────────────────────────────────────────────────────────────────

func TestIssuingNeedsTheFeatureAndACommitment(t *testing.T) {
	idp := newFakeIdP(t)
	off := newLifecycleAuth(t, idp, NewMemorySessionStore(0), nil, nil)
	if _, err := off.BeginDeviceAuthorization(DeviceRequest{CredentialHash: strings.Repeat("a", 64)}); !errors.Is(err, ErrDeviceLoginDisabled) {
		t.Fatalf("with device_login off: %v, want ErrDeviceLoginDisabled", err)
	}
	a := deviceAuth(t, idp, nil, nil, nil)
	for _, h := range []string{"", "abc", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if _, err := a.BeginDeviceAuthorization(DeviceRequest{CredentialHash: h}); !errors.Is(err, ErrDeviceRequestInvalid) {
			t.Errorf("credential_hash %q: %v, want ErrDeviceRequestInvalid", h, err)
		}
	}
}

func TestIssuingRecordsWhoAskedAndStoresNoCode(t *testing.T) {
	idp := newFakeIdP(t)
	rec := &auditRecorder{}
	a := deviceAuth(t, idp, newClock(), rec, nil)
	tm := askForCode(t, a)
	if tm.grant.ExpiresIn != DeviceCodeLifetime || tm.grant.Interval != DefaultDevicePollInterval {
		t.Errorf("grant %+v, want a ten-minute code polled every five seconds", tm.grant)
	}
	d, err := a.devices.GetDevice(deviceDigest(tm.grant.DeviceCode))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.DeviceHash+d.UserCodeHash, tm.grant.DeviceCode) ||
		strings.Contains(d.UserCodeHash, NormalizeUserCode(tm.grant.UserCode)) {
		t.Error("the store holds a code rather than its digest")
	}
	if d.CredentialHash != tm.digest || d.ClientHostname != "dev-laptop" || d.ClientIP != "198.51.100.20" {
		t.Errorf("record %+v does not say who asked", d)
	}
	ev, ok := rec.last(AuditDeviceCodeIssued)
	if !ok || ev.Device == nil || ev.Device.ID != DeviceID(d.DeviceHash) || ev.Device.ClientHostname != "dev-laptop" {
		t.Fatalf("device.code_issued %+v", ev)
	}
}

// ── the token endpoint's answers ────────────────────────────────────────────

func TestPollingIsPendingThenSlowDownWhenTooFast(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := deviceAuth(t, idp, clk, nil, nil)
	tm := askForCode(t, a)

	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrPending {
		t.Fatalf("first poll: %+v, want authorization_pending", te)
	}
	clk.advance(2 * time.Second)
	_, te := pollCode(a, tm)
	if te == nil || te.Code != DeviceErrSlowDown || te.Interval != 10*time.Second {
		t.Fatalf("a poll two seconds later: %+v, want slow_down with the interval raised to 10s", te)
	}
	// RFC 8628: the larger interval holds for every later poll.
	clk.advance(6 * time.Second)
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrSlowDown || te.Interval != 15*time.Second {
		t.Fatalf("six seconds later, against a 10s interval: %+v, want slow_down at 15s", te)
	}
	clk.advance(16 * time.Second)
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrPending {
		t.Fatalf("after waiting out the interval: %+v, want authorization_pending", te)
	}
}

func TestAnUnapprovedCodeExpires(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := deviceAuth(t, idp, clk, nil, nil)
	tm := askForCode(t, a)
	clk.advance(DeviceCodeLifetime)
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrExpired {
		t.Fatalf("poll at expiry: %+v, want expired_token", te)
	}
	// And it can no longer be approved.
	sid := signIn(t, a, idp)
	if _, err := a.BeginDeviceApproval(context.Background(), browserReq(sid), tm.grant.UserCode); !errors.Is(err, ErrDeviceExpired) {
		t.Fatalf("approving an expired code: %v, want ErrDeviceExpired", err)
	}
	// Swept with its grace, after which nothing is known about it.
	clk.advance(deviceSweepGrace + time.Second)
	if n := a.SweepDevices(); n != 1 {
		t.Fatalf("SweepDevices removed %d, want 1", n)
	}
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrInvalidGrant {
		t.Fatalf("poll after the sweep: %+v, want invalid_grant", te)
	}
}

func TestAnUnknownCodeIsInvalidGrant(t *testing.T) {
	a := deviceAuth(t, newFakeIdP(t), nil, nil, nil)
	if _, err := a.ExchangeDeviceCode("not-a-code"); err == nil {
		t.Fatal("an unknown device code was accepted")
	} else if te := (*DeviceTokenError)(nil); !errors.As(err, &te) || te.Code != DeviceErrInvalidGrant {
		t.Fatalf("unknown code: %v, want invalid_grant", err)
	}
}

func TestDenialIsAccessDeniedAndFinal(t *testing.T) {
	idp := newFakeIdP(t)
	rec := &auditRecorder{}
	a := deviceAuth(t, idp, newClock(), rec, nil)
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	if err := a.DenyDevice(browserReq(sid), strings.ToLower(tm.grant.UserCode)); err != nil {
		t.Fatalf("DenyDevice: %v", err)
	}
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrDenied {
		t.Fatalf("poll after denial: %+v, want access_denied", te)
	}
	if err := a.DenyDevice(browserReq(sid), tm.grant.UserCode); !errors.Is(err, ErrDeviceDecided) {
		t.Errorf("denying twice: %v, want ErrDeviceDecided", err)
	}
	if _, err := a.BeginDeviceApproval(context.Background(), browserReq(sid), tm.grant.UserCode); !errors.Is(err, ErrDeviceDecided) {
		t.Errorf("approving a denied code: %v, want ErrDeviceDecided", err)
	}
	ev, ok := rec.last(AuditDeviceDenied)
	if !ok || ev.Reason != "denied_at_approval_page" || ev.Subject != "user-123" {
		t.Fatalf("device.denied %+v", ev)
	}
	if _, err := a.store.Get(tm.sessionID()); err == nil {
		t.Error("a denied code left a session behind")
	}
}

// ── approval ────────────────────────────────────────────────────────────────

func TestApprovalWritesACLISessionUnderTheIDItsCommitmentNames(t *testing.T) {
	idp := newFakeIdP(t)
	idp.issueRefresh = "rt-browser"
	clk := newClock()
	rec := &auditRecorder{}
	a := deviceAuth(t, idp, clk, rec, func(c *Config) {
		c.CLISessionTTL = 12 * time.Hour
		c.CLIIdleTimeout = 2 * time.Hour
	})
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)

	// The provider issues the terminal a grant of its own.
	idp.codeRefreshToken = "rt-terminal"
	idp.codeClaims = map[string]any{"groups": []string{"engineers"}}
	cb, q := approve(t, a, idp, sid, tm.grant.UserCode)
	if cb.Code != http.StatusFound && cb.Code != http.StatusOK {
		t.Fatalf("callback %d: %s", cb.Code, cb.Body.String())
	}
	if loc := cb.Header().Get("Location"); cb.Code == http.StatusFound && !strings.HasPrefix(loc, DevicePath+"?code=") {
		t.Errorf("the approval returned to %q, want the approval page", loc)
	}
	// A fresh browser session is not asked to sign in again — but the
	// provider is asked to, should its own sign-in be older than two hours.
	if !strings.EqualFold(q.Get("login_hint"), "alice@example.com") || q.Get("prompt") != "" || q.Get("max_age") != "7200" {
		t.Errorf("a fresh browser session's approval asked %v", q)
	}

	sess, te := pollCode(a, tm)
	if te != nil {
		t.Fatalf("poll after approval: %+v", te)
	}
	if sess.SessionID != tm.sessionID() || sess.SessionID == tm.digest || !sess.Revalidated || sess.IdleTimeout != 2*time.Hour {
		t.Errorf("session %+v", sess)
	}
	stored, err := a.store.Get(tm.sessionID())
	if err != nil {
		t.Fatal(err)
	}
	if !stored.IsCLI() || stored.Client != "dev-laptop" || stored.IP != "198.51.100.20" {
		t.Errorf("stored session %+v is not the terminal's", stored)
	}
	if stored.RefreshToken != "rt-terminal" {
		t.Errorf("the session holds refresh token %q: it must be the terminal's own grant, never the browser's", stored.RefreshToken)
	}
	if !stored.ExpiresAt.Equal(clk.now().Add(12 * time.Hour)) {
		t.Errorf("expires %s, want twelve hours from approval", stored.ExpiresAt)
	}
	if len(stored.Identity.Groups) != 1 || stored.Identity.Groups[0] != "engineers" {
		t.Errorf("claims %v, want the ones the provider just asserted", stored.Identity.Groups)
	}
	if ev, ok := rec.last(AuditSessionCreated); !ok || ev.Kind != SessionKindCLI || ev.Via != "device_grant" || ev.Client != "dev-laptop" {
		t.Errorf("session.created %+v", ev)
	}
	if ev, ok := rec.last(AuditDeviceApproved); !ok || ev.SessionID != tm.sessionID() || ev.Device == nil {
		t.Errorf("device.approved %+v", ev)
	}

	// The terminal authenticates by its bearer, and only by its bearer.
	if got, ok := a.SessionFromRequest(cliReq(tm.credential)); !ok || got.ID != tm.sessionID() {
		t.Fatal("the terminal's credential does not authenticate")
	}
	asCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	asCookie.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tm.credential})
	if _, ok := a.SessionFromRequest(asCookie); ok {
		t.Error("a terminal's credential presented as a cookie authenticated a browser")
	}
	if _, ok := a.SessionFromRequest(cliReq(CLICredentialPrefix + sid)); ok {
		t.Error("a browser's cookie presented as a terminal bearer authenticated")
	}

	// Single use: the second exchange of the same code is refused.
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrInvalidGrant {
		t.Fatalf("second exchange: %+v, want invalid_grant", te)
	}
}

func TestTheTokenEndpointNeverHandsOutACredential(t *testing.T) {
	idp := newFakeIdP(t)
	a := deviceAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	approve(t, a, idp, sid, tm.grant.UserCode)
	sess, te := pollCode(a, tm)
	if te != nil {
		t.Fatal(te)
	}
	if strings.Contains(sess.SessionID, tm.credential) || strings.Contains(sess.Identity.Sub+sess.Identity.Email, tm.credential) {
		t.Fatal("the exchange returned the credential")
	}
	d, err := a.devices.GetDevice(deviceDigest(tm.grant.DeviceCode))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.CredentialHash, tm.credential) || d.Status != DeviceStatusConsumed {
		t.Errorf("record after exchange %+v", d)
	}
}

func TestOnlyABrowserSessionMayApprove(t *testing.T) {
	idp := newFakeIdP(t)
	a := deviceAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)
	first := askForCode(t, a)
	approve(t, a, idp, sid, first.grant.UserCode)
	if _, te := pollCode(a, first); te != nil {
		t.Fatal(te)
	}

	second := askForCode(t, a)
	// A terminal session approving another terminal: refused.
	r := cliReq(first.credential)
	if _, err := a.BeginDeviceApproval(context.Background(), r, second.grant.UserCode); !errors.Is(err, ErrNeedsBrowserSession) {
		t.Errorf("a terminal approving: %v, want ErrNeedsBrowserSession", err)
	}
	// Even with a browser cookie riding along.
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sid})
	if _, err := a.LookupDevice(r, second.grant.UserCode); !errors.Is(err, ErrNeedsBrowserSession) {
		t.Errorf("a terminal carrying a cookie looking a code up: %v, want ErrNeedsBrowserSession", err)
	}
	// No session at all.
	if err := a.DenyDevice(httptest.NewRequest(http.MethodPost, "/", nil), second.grant.UserCode); !errors.Is(err, ErrNeedsBrowserSession) {
		t.Errorf("an anonymous denial: %v, want ErrNeedsBrowserSession", err)
	}
}

func TestApprovalRefusesAnotherSubjectAtTheProvider(t *testing.T) {
	idp := newFakeIdP(t)
	a := deviceAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	idp.codeSub = "somebody-else"
	cb, _ := approve(t, a, idp, sid, tm.grant.UserCode)
	if cb.Code != http.StatusForbidden || !strings.Contains(cb.Body.String(), "different account") {
		t.Fatalf("callback %d: %s", cb.Code, cb.Body.String())
	}
	if _, err := a.store.Get(tm.sessionID()); err == nil {
		t.Fatal("a session was written for the other subject")
	}
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrPending {
		t.Errorf("the code after a refused approval: %+v, want still pending", te)
	}
}

func TestAnOldBrowserSessionMustSignInAgainToApprove(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := deviceAuth(t, idp, clk, nil, func(c *Config) { c.DeviceApprovalMaxAge = time.Hour })
	sid := signIn(t, a, idp)
	clk.advance(2 * time.Hour)
	tm := askForCode(t, a)

	v, err := a.LookupDevice(browserReq(sid), tm.grant.UserCode)
	if err != nil || !v.Reauth {
		t.Fatalf("lookup %+v, %v: want reauth", v, err)
	}
	// The provider ignores prompt=login, and its auth_time gives it away:
	// the sign-in it reports is from before the request. Refused.
	idp.codeClaims = map[string]any{"auth_time": time.Now().Add(-3 * time.Hour).Unix()}
	cb, q := approve(t, a, idp, sid, tm.grant.UserCode)
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("authorization request %v, want prompt=login&max_age=0", q)
	}
	if cb.Code != http.StatusForbidden || !strings.Contains(cb.Body.String(), "auth_time") {
		t.Fatalf("callback with a stale auth_time: %d %s", cb.Code, cb.Body.String())
	}
	// A provider that did re-authenticate says so.
	idp.codeClaims = map[string]any{"auth_time": time.Now().Unix()}
	cb, _ = approve(t, a, idp, sid, tm.grant.UserCode)
	if cb.Code != http.StatusFound && cb.Code != http.StatusOK {
		t.Fatalf("callback with a fresh auth_time: %d %s", cb.Code, cb.Body.String())
	}
	if _, te := pollCode(a, tm); te != nil {
		t.Fatalf("poll: %+v", te)
	}

	// A provider that never says when (Entra ID without the optional claim)
	// cannot be checked, and is trusted to have honoured prompt=login —
	// refusing would only send the person to sign out and in again.
	idp.codeClaims = nil
	quiet := askForCode(t, a)
	cb, q = approve(t, a, idp, sid, quiet.grant.UserCode)
	if q.Get("prompt") != "login" || (cb.Code != http.StatusFound && cb.Code != http.StatusOK) {
		t.Fatalf("approval without auth_time: asked %v, answered %d %s", q, cb.Code, cb.Body.String())
	}
	if _, te := pollCode(a, quiet); te != nil {
		t.Fatalf("poll: %+v", te)
	}
}

func TestAFreshSessionOnAnOldProviderSignInMustSignInAgain(t *testing.T) {
	idp := newFakeIdP(t)
	a := deviceAuth(t, idp, newClock(), nil, func(c *Config) { c.DeviceApprovalMaxAge = time.Hour })
	// A dashboard session minutes old — signed in silently, on a provider
	// session three hours old, at a provider that ignores max_age.
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	idp.codeClaims = map[string]any{"auth_time": time.Now().Add(-3 * time.Hour).Unix()}
	cb, q := approve(t, a, idp, sid, tm.grant.UserCode)
	if q.Get("max_age") != "3600" || q.Get("prompt") != "" {
		t.Fatalf("authorization request %v, want max_age=3600 and no prompt", q)
	}
	loc, err := url.Parse(cb.Header().Get("Location"))
	if cb.Code != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), idp.server.URL) {
		t.Fatalf("callback %d to %q: want a second round trip at the provider", cb.Code, cb.Header().Get("Location"))
	}
	again := loc.Query()
	if again.Get("prompt") != "login" || again.Get("max_age") != "0" {
		t.Fatalf("second authorization request %v, want prompt=login&max_age=0", again)
	}
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrPending {
		t.Fatalf("poll before the fresh sign-in: %+v, want still pending", te)
	}

	// The provider asks this time, and says so.
	idp.codeClaims = map[string]any{"auth_time": time.Now().Unix()}
	idp.nonce = again.Get("nonce")
	rec := httptest.NewRecorder()
	back := httptest.NewRequest(http.MethodGet, "/auth/callback?"+url.Values{
		"state": {again.Get("state")}, "code": {"authcode-device-again"},
	}.Encode(), nil)
	if out := a.HandleCallback(rec, back); out != LoginDevice {
		t.Fatalf("second callback outcome %q", out)
	}
	if l := rec.Header().Get("Location"); rec.Code == http.StatusFound && !strings.HasPrefix(l, DevicePath+"?code=") {
		t.Fatalf("second callback went to %q, want the approval page", l)
	}
	if _, te := pollCode(a, tm); te != nil {
		t.Fatalf("poll after the fresh sign-in: %+v", te)
	}
}

func TestAnEndedSessionCannotBeTakenOverByCommittingToItsID(t *testing.T) {
	idp := newFakeIdP(t)
	a := deviceAuth(t, idp, newClock(), nil, nil)
	alice := signIn(t, a, idp)
	victim := askForCode(t, a)
	approve(t, a, idp, alice, victim.grant.UserCode)
	sess, te := pollCode(a, victim)
	if te != nil {
		t.Fatal(te)
	}
	// The commitment is spent once the session is collected.
	if d, err := a.devices.GetDevice(deviceDigest(victim.grant.DeviceCode)); err != nil || d.CredentialHash != "" {
		t.Errorf("the collected authorization still holds its commitment: %+v, %v", d, err)
	}
	// The session ends. Its id is public: the audit trail, the Active
	// Sessions panel and `cloop hub session list` show it.
	if ok, err := a.RevokeSession(sess.SessionID, "admin@example.com", ""); !ok || err != nil {
		t.Fatalf("revoke: %v %v", ok, err)
	}

	// Mallory asks for a code committing to that id, and approves it as
	// herself.
	idp.codeSub = "mallory"
	mallory := signIn(t, a, idp)
	planted, err := a.BeginDeviceAuthorization(DeviceRequest{CredentialHash: sess.SessionID, Hostname: "dev-laptop"})
	if err != nil {
		t.Fatal(err)
	}
	approve(t, a, idp, mallory, planted.UserCode)
	if _, te := pollCode(a, terminal{grant: planted}); te != nil {
		t.Fatal(te)
	}

	// Alice's terminal, still presenting the ended session's credential, is
	// signed in as nobody — not as Mallory.
	if got, ok := a.SessionFromRequest(cliReq(victim.credential)); ok {
		t.Fatalf("the ended session's credential authenticates, as %q", got.Identity.Sub)
	}
}

// approvalSpy is a device store that looks at the moment an approval is
// recorded — and can make the recording lose a race to a denial.
type approvalSpy struct {
	DeviceStore
	sessions SessionStore
	updates  int
	// sawSession reports that the session existed when its approval was
	// recorded.
	sawSession bool
	// racing has every update find the code just denied.
	racing bool
}

func (s *approvalSpy) UpdateDevice(hash string, change func(*DeviceRecord) (bool, error)) (DeviceRecord, error) {
	s.updates++
	return s.DeviceStore.UpdateDevice(hash, func(d *DeviceRecord) (bool, error) {
		if s.racing {
			d.Status = DeviceStatusDenied
		}
		before := d.Status
		changed, err := change(d)
		if before == DeviceStatusPending && d.Status == DeviceStatusApproved {
			_, gerr := s.sessions.Get(CLISessionID(d.CredentialHash))
			s.sawSession = gerr == nil
		}
		return changed, err
	})
}

func TestTheSessionIsWrittenBeforeTheApprovalIsRecorded(t *testing.T) {
	idp := newFakeIdP(t)
	rec := &auditRecorder{}
	spy := &approvalSpy{DeviceStore: NewMemoryDeviceStore()}
	a := deviceAuth(t, idp, newClock(), rec, func(c *Config) { c.Devices = spy })
	spy.sessions = a.store
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	approve(t, a, idp, sid, tm.grant.UserCode)
	if !spy.sawSession {
		t.Fatal("the code was recorded approved before its session existed: a poll in between is told the session ended, and the session is orphaned")
	}

	// An approval that loses the race to a denial: the session written for
	// it goes, and is never announced.
	lost := askForCode(t, a)
	created := rec.countOf(AuditSessionCreated)
	spy.racing = true
	cb, _ := approve(t, a, idp, sid, lost.grant.UserCode)
	spy.racing = false
	if cb.Code != http.StatusConflict {
		t.Fatalf("callback %d %s, want 409", cb.Code, cb.Body.String())
	}
	if _, err := a.store.Get(lost.sessionID()); err == nil {
		t.Fatal("the session of an approval that was never recorded survived")
	}
	if n := rec.countOf(AuditSessionCreated); n != created {
		t.Errorf("session.created was audited for a session that was discarded")
	}
}

func TestGuessingOrHammeringACodeStopsWriting(t *testing.T) {
	spy := &approvalSpy{DeviceStore: NewMemoryDeviceStore()}
	a := deviceAuth(t, newFakeIdP(t), newClock(), nil, func(c *Config) { c.Devices = spy })
	if _, te := pollCode(a, terminal{grant: DeviceGrant{DeviceCode: "guessed"}}); te == nil || te.Code != DeviceErrInvalidGrant {
		t.Fatalf("poll: %+v, want invalid_grant", te)
	}
	if spy.updates != 0 {
		t.Errorf("an unknown code took %d locked updates, want none", spy.updates)
	}

	// A terminal polling as fast as it can grows its interval to the
	// longest there is, and from then on costs reads only.
	tm := askForCode(t, a)
	var last *DeviceTokenError
	for i := 0; i < 50; i++ {
		_, last = pollCode(a, tm)
	}
	if last == nil || last.Code != DeviceErrSlowDown || last.Interval != maxDevicePollInterval {
		t.Fatalf("after hammering: %+v, want slow_down at %s", last, maxDevicePollInterval)
	}
	if steps := int(maxDevicePollInterval/deviceSlowDownStep) + 1; spy.updates > steps {
		t.Errorf("fifty polls took %d locked updates, want at most %d", spy.updates, steps)
	}
}

func TestTheSweepEndsTheSessionOfAnInterruptedApproval(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := deviceAuth(t, idp, clk, nil, nil)
	tm := askForCode(t, a)
	d, err := a.devices.GetDevice(deviceDigest(tm.grant.DeviceCode))
	if err != nil {
		t.Fatal(err)
	}
	// The hub stopped between writing the session and recording the approval.
	if _, err := a.createCLISession(Identity{Sub: "user-123", Email: "alice@example.com"}, d, &tokenResponse{}, clk.now(), clk.now()); err != nil {
		t.Fatal(err)
	}
	clk.advance(DeviceCodeLifetime + deviceSweepGrace + time.Second)
	if a.SweepDevices() != 1 {
		t.Fatal("the sweep did not remove the authorization")
	}
	if _, err := a.store.Get(tm.sessionID()); err == nil {
		t.Fatal("the session of an approval that was never recorded outlived its code")
	}
}

func TestTheSessionGateRefusesAnIdentity(t *testing.T) {
	idp := newFakeIdP(t)
	rec := &auditRecorder{}
	a := deviceAuth(t, idp, newClock(), rec, func(c *Config) {
		c.SessionGate = func(id Identity) error {
			if id.Sub == "user-123" {
				return errors.New("offboarded")
			}
			return nil
		}
	})
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	cb, _ := approve(t, a, idp, sid, tm.grant.UserCode)
	if cb.Code != http.StatusForbidden {
		t.Fatalf("callback %d, want 403", cb.Code)
	}
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrDenied {
		t.Fatalf("poll: %+v, want access_denied", te)
	}
	if ev, ok := rec.last(AuditDeviceDenied); !ok || ev.Reason != "identity_refused" || ev.Actor != "hub" {
		t.Errorf("device.denied %+v", ev)
	}
}

func TestASessionEndedBeforeCollectionIsDenied(t *testing.T) {
	idp := newFakeIdP(t)
	a := deviceAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	approve(t, a, idp, sid, tm.grant.UserCode)
	// "Sign out everywhere" between approval and the terminal's next poll.
	if _, err := a.LogoutAll("user-123", "", "user"); err != nil {
		t.Fatal(err)
	}
	if _, te := pollCode(a, tm); te == nil || te.Code != DeviceErrDenied {
		t.Fatalf("poll: %+v, want access_denied", te)
	}
}

func TestAnUncollectedApprovalEndsItsSession(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	rec := &auditRecorder{}
	a := deviceAuth(t, idp, clk, rec, nil)
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	approve(t, a, idp, sid, tm.grant.UserCode)
	clk.advance(DeviceCodeLifetime + deviceSweepGrace + time.Second)
	if a.SweepDevices() != 1 {
		t.Fatal("the sweep did not remove the authorization")
	}
	if _, err := a.store.Get(tm.sessionID()); err == nil {
		t.Fatal("a session nobody collected outlived its code")
	}
	if ev, ok := rec.last(AuditSessionRevoked); !ok || ev.Reason != ReasonDeviceUncollected {
		t.Errorf("session.revoked %+v", ev)
	}
}

// ── the CLI session's clocks ────────────────────────────────────────────────

func TestCLIClocksNeverExceedTheBrowsers(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		ttl, idle, cTTL, cIdl time.Duration
		wantTTL, wantIdle     time.Duration
	}{
		{"defaults follow the browser", 24 * time.Hour, 8 * time.Hour, 0, 0, 24 * time.Hour, 8 * time.Hour},
		{"shorter is kept", 24 * time.Hour, 8 * time.Hour, 6 * time.Hour, time.Hour, 6 * time.Hour, time.Hour},
		{"longer is clamped", 24 * time.Hour, 8 * time.Hour, 72 * time.Hour, 20 * time.Hour, 24 * time.Hour, 8 * time.Hour},
		{"idle within its own ttl", 24 * time.Hour, 8 * time.Hour, 4 * time.Hour, 0, 4 * time.Hour, 4 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{SessionTTL: tc.ttl, IdleTimeout: tc.idle, CLISessionTTL: tc.cTTL, CLIIdleTimeout: tc.cIdl}
			normalizeDeviceConfig(&cfg)
			if cfg.CLISessionTTL != tc.wantTTL || cfg.CLIIdleTimeout != tc.wantIdle {
				t.Fatalf("got ttl %s idle %s, want %s %s", cfg.CLISessionTTL, cfg.CLIIdleTimeout, tc.wantTTL, tc.wantIdle)
			}
		})
	}
}

func TestACLISessionIdlesOutOnItsOwnClock(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := deviceAuth(t, idp, clk, nil, func(c *Config) { c.CLIIdleTimeout = time.Hour })
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	approve(t, a, idp, sid, tm.grant.UserCode)
	if _, te := pollCode(a, tm); te != nil {
		t.Fatal(te)
	}
	clk.advance(90 * time.Minute)
	if _, ok := a.SessionFromRequest(cliReq(tm.credential)); ok {
		t.Fatal("the terminal session outlived its one-hour idle window")
	}
	if _, ok := a.SessionFromRequest(reqWithCookie(sid)); !ok {
		t.Fatal("the browser session, on its eight-hour clock, ended with it")
	}

	// The sweep applies the same per-kind rule.
	tm2 := askForCode(t, a)
	approve(t, a, idp, sid, tm2.grant.UserCode)
	clk.advance(61 * time.Minute)
	if n := a.SweepExpired(); n != 1 {
		t.Fatalf("SweepExpired removed %d sessions, want the idle terminal only", n)
	}
	if _, err := a.store.Get(tm2.sessionID()); err == nil {
		t.Error("the idle terminal session survived the sweep")
	}
}

func TestAnEndedCLICredentialIsNotATokenOrACookie(t *testing.T) {
	a := deviceAuth(t, newFakeIdP(t), nil, nil, nil)
	cred, _, _ := NewCLICredential()
	r := cliReq(cred)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "whatever"})
	if !PresentsCLICredential(r) {
		t.Fatal("PresentsCLICredential missed a bearer")
	}
	if _, ok := a.SessionFromRequest(r); ok {
		t.Fatal("an unknown terminal credential authenticated")
	}
}

func TestBrowserRenewalSkipsCLISessions(t *testing.T) {
	idp := newFakeIdP(t)
	a := deviceAuth(t, idp, newClock(), nil, func(c *Config) { c.MaxClaimAge = 5 * time.Minute })
	sid := signIn(t, a, idp)
	tm := askForCode(t, a)
	approve(t, a, idp, sid, tm.grant.UserCode)
	if _, renew := a.BrowserRenewIn(tm.sessionID()); renew {
		t.Error("a terminal session was scheduled for a browser renewal it has no browser to run")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/renew", nil)
	req.Header.Set("Authorization", "Bearer "+tm.credential)
	if out := a.BeginRenew(rec, req); out != RenewNoSession {
		t.Errorf("a renewal on a terminal's credential: %q, want %q", out, RenewNoSession)
	}
}

func TestCleanLabelBoundsAndStripsControls(t *testing.T) {
	got := cleanLabel("dev\x1b[31m-box\n", 64)
	if got != "dev[31m-box" {
		t.Errorf("cleanLabel = %q", got)
	}
	long := strings.Repeat("é", 100)
	if c := cleanLabel(long, 9); len(c) > 9 || !strings.HasPrefix(long, c) {
		t.Errorf("cleanLabel cut %q mid-rune", c)
	}
}
