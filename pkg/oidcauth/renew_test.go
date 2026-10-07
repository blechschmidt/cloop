package oidcauth

// Tests for silent re-assertion of a session's claims (Task 20359).
//
// The property under test throughout is narrow and worth stating once: a silent
// flow may refresh a session's *claims* and do nothing else. It cannot mint a
// session, extend one, keep an idle one alive, move one to another subject, or
// be driven by a browser that has not already presented a valid cookie. Each of
// those is a test of its own rather than an assertion buried in a happy path,
// because they are the reasons the flow is safe to run unattended.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// signIn drives a full interactive sign-in and returns the session cookie.
func signIn(t *testing.T, a *Authenticator, idp *fakeIdP) string {
	t.Helper()
	state, nonce := beginLogin(t, a)
	idp.nonce = nonce
	rec := doCallback(a, state)
	if rec.Code != http.StatusFound && rec.Code != http.StatusOK {
		t.Fatalf("sign-in: status %d (body %s)", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("sign-in set no session cookie")
	return ""
}

// beginRenew drives BeginRenew for sid and returns the recorder plus the query
// of the authorization request it redirected to (nil when it did not redirect).
func beginRenew(t *testing.T, a *Authenticator, sid string) (*httptest.ResponseRecorder, url.Values) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/renew", nil)
	if sid != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sid})
	}
	a.BeginRenew(rec, req)
	if rec.Code != http.StatusFound {
		return rec, nil
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("renew redirect: %v", err)
	}
	return rec, loc.Query()
}

// renewCallback delivers the provider's answer to the renewal frame. It carries
// no cookie, as the real cross-site navigation does not.
func renewCallback(a *Authenticator, q url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+q.Encode(), nil)
	req.RemoteAddr = "198.51.100.7:40000"
	a.HandleCallback(rec, req)
	return rec
}

// completeRenewal runs a renewal end to end: begin, the provider's code, the
// callback. It returns the callback's recorder.
func completeRenewal(t *testing.T, a *Authenticator, idp *fakeIdP, sid string) *httptest.ResponseRecorder {
	t.Helper()
	_, q := beginRenew(t, a, sid)
	if q == nil {
		t.Fatal("BeginRenew did not redirect to the provider")
	}
	idp.nonce = q.Get("nonce")
	return renewCallback(a, url.Values{"state": {q.Get("state")}, "code": {"authcode-renew"}})
}

// renewMessage reads the posted message out of the document the frame
// received. The body rather than the Go return value, on purpose: the body is
// what the browser acts on.
var renewFieldRe = regexp.MustCompile(`(type|outcome|detail|renew_in|changed): ("(?:[^"\\]|\\.)*"|-?\d+|true|false)`)

func renewMessage(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	body := rec.Body.String()
	i := strings.Index(body, "parent.postMessage(")
	if i < 0 {
		t.Fatalf("the renewal document posts nothing to its parent:\n%s", body)
	}
	out := map[string]string{}
	for _, m := range renewFieldRe.FindAllStringSubmatch(body[i:], -1) {
		v := m[2]
		if s, err := strconv.Unquote(v); err == nil {
			v = s
		}
		out[m[1]] = v
	}
	if out["type"] != renewMessageType {
		t.Fatalf("message type = %q, want %q:\n%s", out["type"], renewMessageType, body)
	}
	return out
}

// renewAuth builds an authenticator with a controllable clock and the
// freshness bound at its default, retaining no refresh token unless the test's
// IdP issues one: the deployment silent renewal exists for.
func renewAuth(t *testing.T, idp *fakeIdP, clk *clock, store SessionStore, mutate func(*Config)) *Authenticator {
	t.Helper()
	if store == nil {
		store = NewMemorySessionStore(0)
	}
	return newLifecycleAuth(t, idp, store, clk, func(c *Config) {
		c.MaxClaimAge = 5 * time.Minute
		c.RefreshInterval = -1
		if mutate != nil {
			mutate(c)
		}
	})
}

// ── what a renewal does ─────────────────────────────────────────────────────

func TestSilentRenewRefreshesClaims(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	audit := &auditRecorder{}
	store := NewMemorySessionStore(0)
	a := renewAuth(t, idp, clk, store, func(c *Config) {
		c.Audit = audit.sink
		c.EffectiveRole = stubRoleLadder
	})

	idp.codeClaims = map[string]any{"groups": []string{"admins", "devs"}}
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)
	before, err := store.Get(hash)
	if err != nil {
		t.Fatalf("session after sign-in: %v", err)
	}

	// Past the bound: exactly the state that produces the refusal this
	// feature removes. And the provider now releases one group fewer — a
	// demotion that arrives through the renewal.
	clk.advance(10 * time.Minute)
	idp.codeClaims = map[string]any{"groups": []string{"devs"}}

	msg := renewMessage(t, completeRenewal(t, a, idp, sid))
	if msg["outcome"] != string(RenewOK) {
		t.Fatalf("renewal outcome = %q, want ok (%v)", msg["outcome"], msg)
	}
	after, err := store.Get(hash)
	if err != nil {
		t.Fatalf("session after renewal: %v", err)
	}
	if !after.ClaimsAsOf.Equal(clk.now()) {
		t.Errorf("claims asserted at %v, want the renewal's instant %v", after.ClaimsAsOf, clk.now())
	}
	if after.ClaimsStale(clk.now(), 5*time.Minute) {
		t.Error("claims are still stale after a successful renewal")
	}
	if len(after.Identity.Groups) != 1 || after.Identity.Groups[0] != "devs" {
		t.Errorf("groups = %v, want the narrowed set the provider just released", after.Identity.Groups)
	}
	// Not re-keyed: ownership everywhere else in the hub is recorded under the
	// email captured at sign-in.
	if after.Identity.Sub != before.Identity.Sub || after.Identity.Email != before.Identity.Email {
		t.Errorf("identity moved: %+v -> %+v", before.Identity, after.Identity)
	}
	if msg["changed"] != "true" {
		t.Errorf("changed = %q, want true — the dashboard must re-read its permissions after a narrowing", msg["changed"])
	}

	// Audited exactly as a server-side refresh's narrowing is, and saying
	// which way it came.
	ev, ok := audit.last(AuditSessionRoleNarrowed)
	if !ok {
		t.Fatal("a demotion that arrived through a renewal wrote no session.role_narrowed")
	}
	if ev.Via != viaBrowserRenewal || ev.PriorRole != "admin" || ev.Role != "viewer" {
		t.Errorf("role_narrowed = %+v, want via=%s and admin -> viewer", ev, viaBrowserRenewal)
	}
}

func TestSilentRenewNeverSetsACookie(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)

	rec := completeRenewal(t, a, idp, sid)
	// The property that makes the flow safe to run in a frame whose callback
	// carries no credential: it can refresh a session and cannot establish one.
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("a silent renewal set %d cookie(s): %+v", len(cookies), cookies)
	}
}

func TestSilentRenewDoesNotExtendTheAbsoluteCeiling(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	a := renewAuth(t, idp, clk, store, nil)
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)
	before, _ := store.Get(hash)

	clk.advance(10 * time.Minute)
	completeRenewal(t, a, idp, sid)

	after, _ := store.Get(hash)
	if !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Errorf("absolute expiry moved %v -> %v — a renewal must never lift the ceiling",
			before.ExpiresAt, after.ExpiresAt)
	}
}

// TestSilentRenewLeavesTheIdleClockAlone: a renewal is the dashboard keeping
// its authority current, not the user doing anything. If it counted as
// activity, an unattended tab renewing every few minutes would hold its
// session open until the absolute ceiling, and idle_timeout would bound
// nothing.
func TestSilentRenewLeavesTheIdleClockAlone(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	a := renewAuth(t, idp, clk, store, func(c *Config) { c.IdleTimeout = 30 * time.Minute })
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)
	before, _ := store.Get(hash)

	// Renew every few minutes for most of the idle window, the way an open tab
	// nobody is looking at would.
	for i := 0; i < 7; i++ {
		clk.advance(4 * time.Minute)
		if got := renewMessage(t, completeRenewal(t, a, idp, sid))["outcome"]; got != string(RenewOK) {
			t.Fatalf("renewal %d = %q, want ok", i, got)
		}
	}
	after, err := store.Get(hash)
	if err != nil {
		t.Fatalf("session gone inside its idle window: %v", err)
	}
	if after.LastSeen.After(before.LastSeen) {
		t.Fatalf("renewals advanced LastSeen %v -> %v", before.LastSeen, after.LastSeen)
	}
	// 32 minutes after the last real use, past a 30-minute idle window: the
	// session is over, renewals or not, and the next renewal says so.
	clk.advance(4 * time.Minute)
	rec, q := beginRenew(t, a, sid)
	if q != nil {
		t.Fatal("renewals kept an idle session alive past idle_timeout")
	}
	if got := renewMessage(t, rec)["outcome"]; got != string(RenewNoSession) {
		t.Fatalf("outcome = %q, want no_session", got)
	}
	if a.IdentityFromRequest(reqWithCookie(sid)) != nil {
		t.Fatal("the session outlived its idle window")
	}
}

func TestSilentRenewRequiresASession(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)

	for name, sid := range map[string]string{"no cookie": "", "unknown cookie": "not-a-session"} {
		t.Run(name, func(t *testing.T) {
			rec, q := beginRenew(t, a, sid)
			if q != nil {
				t.Fatal("BeginRenew redirected to the provider without a session")
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 — a frame cannot surface a 401", rec.Code)
			}
			if got := renewMessage(t, rec)["outcome"]; got != string(RenewNoSession) {
				t.Fatalf("outcome = %q, want no_session", got)
			}
		})
	}
}

func TestSilentRenewAsksForNoInteraction(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)

	_, q := beginRenew(t, a, sid)
	if got := q.Get("prompt"); got != "none" {
		t.Errorf("prompt = %q, want none — without it the frame can render a login form", got)
	}
	if got := q.Get("login_hint"); got != "alice@example.com" {
		t.Errorf("login_hint = %q, want the session's email", got)
	}
	// Not weakened by being silent.
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("renewal dropped PKCE: %v", q)
	}
	if q.Get("nonce") == "" || q.Get("state") == "" {
		t.Errorf("renewal dropped nonce or state: %v", q)
	}
}

func TestSilentRenewReportsInteractionRequired(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	a := renewAuth(t, idp, clk, store, nil)
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)
	before, _ := store.Get(hash)

	for _, code := range []string{"login_required", "interaction_required", "consent_required", "account_selection_required"} {
		t.Run(code, func(t *testing.T) {
			_, q := beginRenew(t, a, sid)
			rec := renewCallback(a, url.Values{"state": {q.Get("state")}, "error": {code}})
			if got := renewMessage(t, rec)["outcome"]; got != string(RenewInteractionRequired) {
				t.Fatalf("outcome for %s = %q, want interaction_required", code, got)
			}
			// The session survives. A provider declining to answer silently
			// says nothing about whether this person is signed in here.
			after, err := store.Get(hash)
			if err != nil {
				t.Fatalf("session gone after a silent refusal: %v", err)
			}
			if !after.ClaimsAsOf.Equal(before.ClaimsAsOf) {
				t.Error("a refusal advanced the claim clock")
			}
		})
	}
}

func TestSilentRenewOtherIdPErrorIsNotASignOut(t *testing.T) {
	idp := newFakeIdP(t)
	store := NewMemorySessionStore(0)
	a := renewAuth(t, idp, newClock(), store, nil)
	sid := signIn(t, a, idp)

	_, q := beginRenew(t, a, sid)
	rec := renewCallback(a, url.Values{
		"state":             {q.Get("state")},
		"error":             {"temporarily_unavailable"},
		"error_description": {"try again"},
	})
	msg := renewMessage(t, rec)
	if msg["outcome"] != string(RenewIdPError) {
		t.Fatalf("outcome = %q, want idp_error", msg["outcome"])
	}
	if !strings.Contains(msg["detail"], "temporarily_unavailable") {
		t.Errorf("detail = %q, want the provider's error", msg["detail"])
	}
	if _, err := store.Get(HashSessionID(sid)); err != nil {
		t.Fatalf("session ended over a transient provider error: %v", err)
	}
}

func TestSilentRenewRefusesADifferentSubject(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	audit := &auditRecorder{}
	a := renewAuth(t, idp, clk, store, func(c *Config) { c.Audit = audit.sink })
	idp.codeClaims = map[string]any{"groups": []string{"devs"}}
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)
	before, _ := store.Get(hash)

	clk.advance(10 * time.Minute)
	_, q := beginRenew(t, a, sid)
	idp.nonce = q.Get("nonce")
	// The browser is now signed in at the provider as somebody else, with
	// wider groups — whether by an account switch or by design.
	idp.codeSub = "someone-else"
	idp.codeClaims = map[string]any{"groups": []string{"admins", "devs", "sre"}}

	rec := renewCallback(a, url.Values{"state": {q.Get("state")}, "code": {"authcode-renew"}})
	if got := renewMessage(t, rec)["outcome"]; got != string(RenewSubjectMismatch) {
		t.Fatalf("outcome = %q, want subject_mismatch", got)
	}
	after, err := store.Get(hash)
	if err != nil {
		t.Fatalf("a mismatched renewal ended the session: %v", err)
	}
	if after.Identity.Sub != before.Identity.Sub {
		t.Errorf("session re-keyed to %q", after.Identity.Sub)
	}
	if len(after.Identity.Groups) != 1 || after.Identity.Groups[0] != "devs" {
		t.Errorf("groups = %v — the other subject's authority was adopted", after.Identity.Groups)
	}
	if !after.ClaimsAsOf.Equal(before.ClaimsAsOf) {
		t.Error("a mismatched renewal advanced the claim clock")
	}

	ev, ok := audit.last(AuditSessionRenewalMismatch)
	if !ok {
		t.Fatal("a renewal answered for somebody else wrote no audit row")
	}
	if ev.SessionID != hash || ev.Subject != before.Identity.Sub || ev.IP != "198.51.100.7" {
		t.Errorf("audit row = %+v, want this session, its own subject and the renewing browser's address", ev)
	}
	if strings.Contains(ev.Subject+ev.Email+ev.Reason, "someone-else") {
		t.Errorf("the other identity leaked into the trail: %+v", ev)
	}
}

func TestSilentRenewStateIsOneShot(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)

	_, q := beginRenew(t, a, sid)
	idp.nonce = q.Get("nonce")
	first := renewCallback(a, url.Values{"state": {q.Get("state")}, "code": {"authcode-renew"}})
	if got := renewMessage(t, first)["outcome"]; got != string(RenewOK) {
		t.Fatalf("first callback = %q, want ok", got)
	}
	// Replayed: the state is gone, so this is no longer a renewal at all and
	// falls through to the sign-in path's refusal — which sets no cookie.
	second := renewCallback(a, url.Values{"state": {q.Get("state")}, "code": {"authcode-renew"}})
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed state: status %d, want 400 (body: %s)", second.Code, second.Body.String())
	}
	if len(second.Result().Cookies()) != 0 {
		t.Error("a replayed renewal state set a cookie")
	}
}

// TestSilentRenewClearsAClaimFreshnessRefusal is the end-to-end statement of
// what the feature is for: a hub holding no refresh token refuses a privileged
// action on claim age, and a renewal from the browser makes it stop refusing.
func TestSilentRenewClearsAClaimFreshnessRefusal(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := renewAuth(t, idp, clk, nil, nil)
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)

	clk.advance(10 * time.Minute)
	_, err := a.EnsureFreshClaims(context.Background(), hash)
	var cf *ClaimFreshnessError
	if !errors.As(err, &cf) || cf.Reason != reasonNoRefreshToken {
		t.Fatalf("precondition: want a no_refresh_token refusal, got %v", err)
	}
	if !cf.Renewable() {
		t.Fatal("a no_refresh_token refusal must be reported as renewable")
	}

	if got := renewMessage(t, completeRenewal(t, a, idp, sid))["outcome"]; got != string(RenewOK) {
		t.Fatalf("renewal outcome = %q, want ok", got)
	}
	if _, err := a.EnsureFreshClaims(context.Background(), hash); err != nil {
		t.Fatalf("still refused after a successful renewal: %v", err)
	}
}

func TestClaimFreshnessRenewable(t *testing.T) {
	for reason, want := range map[string]bool{
		reasonNoRefreshToken: true,
		reasonIdPUnreachable: true,
		// The provider looked and declined to vouch: asking again from the
		// browser cannot change the next server-side answer.
		reasonClaimsRejected:   false,
		"a_reason_added_later": false,
	} {
		if got := (&ClaimFreshnessError{Reason: reason}).Renewable(); got != want {
			t.Errorf("Renewable() for %s = %v, want %v", reason, got, want)
		}
	}
	var nilErr *ClaimFreshnessError
	if nilErr.Renewable() {
		t.Error("a nil refusal is not renewable")
	}
}

// TestSilentRenewKeepsOrReplacesTheRefreshToken: the renewal is a separate
// grant. A provider that hands back a refresh token with it has given the hub
// the means to re-assert claims by itself, which hands the job back to the
// server-side layer; one that hands back none has said nothing about the token
// the hub already holds.
func TestSilentRenewKeepsOrReplacesTheRefreshToken(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	a := renewAuth(t, idp, clk, store, nil)
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)

	if _, ok := a.BrowserRenewIn(hash); !ok {
		t.Fatal("a session with no refresh token must be renewed by its browser")
	}
	idp.codeRefreshToken = "rt-from-renewal"
	msg := renewMessage(t, completeRenewal(t, a, idp, sid))
	if msg["outcome"] != string(RenewOK) {
		t.Fatalf("outcome = %q", msg["outcome"])
	}
	rec, _ := store.Get(hash)
	if rec.RefreshToken != "rt-from-renewal" {
		t.Fatalf("refresh token = %q, want the one the renewal returned", rec.RefreshToken)
	}
	if _, ok := msg["renew_in"]; ok {
		t.Errorf("the answer still schedules browser renewals (%v) although the hub can now refresh by itself", msg)
	}
	if _, ok := a.BrowserRenewIn(hash); ok {
		t.Error("BrowserRenewIn still asks the browser to renew a session holding a refresh token")
	}

	// No refresh token this time: the one held is kept.
	clk.advance(10 * time.Minute)
	completeRenewal(t, a, idp, sid)
	if rec, _ := store.Get(hash); rec.RefreshToken != "rt-from-renewal" {
		t.Fatalf("refresh token = %q after a renewal that returned none, want it kept", rec.RefreshToken)
	}
}

func TestRenewObserverSeesEveryVerdict(t *testing.T) {
	idp := newFakeIdP(t)
	var mu sync.Mutex
	var seen []RenewOutcome
	a := renewAuth(t, idp, newClock(), nil, func(c *Config) {
		c.RenewObserver = func(o RenewOutcome) {
			mu.Lock()
			seen = append(seen, o)
			mu.Unlock()
		}
	})
	sid := signIn(t, a, idp)

	// The redirect is not a verdict.
	_, q := beginRenew(t, a, sid)
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("the redirect to the provider was counted: %v", seen)
	}
	idp.nonce = q.Get("nonce")
	renewCallback(a, url.Values{"state": {q.Get("state")}, "code": {"authcode-renew"}})
	beginRenew(t, a, "")
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != RenewOK || seen[1] != RenewNoSession {
		t.Fatalf("observed %v, want [ok no_session]", seen)
	}
}

func TestRenewalIsNotCountedAsALogin(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)

	_, q := beginRenew(t, a, sid)
	idp.nonce = q.Get("nonce")
	rec := httptest.NewRecorder()
	outcome := a.HandleCallback(rec, httptest.NewRequest(http.MethodGet,
		"/auth/callback?state="+url.QueryEscape(q.Get("state"))+"&code=authcode-renew", nil))
	if outcome != LoginRenewal {
		t.Fatalf("HandleCallback = %q, want renewal", outcome)
	}
	if outcome.Recorded() {
		t.Error("a renewal must not enter the sign-in success ratio")
	}
}

// TestSilentRenewCarriesTheStatePrefix: on a hub cluster the provider's answer
// reaches whichever process the load balancer picks, and the pending record
// lives in the one that began it. The prefix is what routes it home.
func TestSilentRenewCarriesTheStatePrefix(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, func(c *Config) { c.StatePrefix = "hub_member7" })
	sid := signIn(t, a, idp)
	_, q := beginRenew(t, a, sid)
	if got := StateOwner(q.Get("state")); got != "hub_member7" {
		t.Fatalf("renewal state %q belongs to %q, want hub_member7", q.Get("state"), got)
	}
}

// TestSilentRenewTakesTheRefreshLock: a renewal writes a session's claims, so
// it serialises with every refresh-token redemption of that session across hub
// processes, and re-reads the row once it holds the right.
func TestSilentRenewTakesTheRefreshLock(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)

	var lockMu sync.Mutex
	var locked []string
	held := make(chan struct{})
	release := make(chan struct{})
	lock := func(ctx context.Context, id string) (func(), error) {
		lockMu.Lock()
		locked = append(locked, id)
		first := len(locked) == 1
		lockMu.Unlock()
		if first {
			close(held)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return func() {}, nil
	}
	a := renewAuth(t, idp, clk, store, func(c *Config) { c.RefreshLock = lock })
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)
	clk.advance(10 * time.Minute)

	_, q := beginRenew(t, a, sid)
	idp.nonce = q.Get("nonce")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- renewCallback(a, url.Values{"state": {q.Get("state")}, "code": {"authcode-renew"}})
	}()
	<-held
	// While another process holds the lock nothing may be written.
	if rec, _ := store.Get(hash); !rec.ClaimsAsOf.Before(clk.now()) {
		t.Fatal("the renewal wrote claims while another process held the refresh lock")
	}
	close(release)
	rec := <-done
	if got := renewMessage(t, rec)["outcome"]; got != string(RenewOK) {
		t.Fatalf("outcome = %q, want ok", got)
	}
	lockMu.Lock()
	defer lockMu.Unlock()
	if len(locked) != 1 || locked[0] != hash {
		t.Fatalf("lock taken for %v, want once for this session", locked)
	}
}

// TestSilentRenewAnnouncesTheChange: other hub processes cache this session,
// and must drop their copy rather than serve the stale claims for another
// thirty seconds.
func TestSilentRenewAnnouncesTheChange(t *testing.T) {
	idp := newFakeIdP(t)
	var mu sync.Mutex
	var announced []string
	a := renewAuth(t, idp, newClock(), nil, func(c *Config) {
		c.OnCacheInvalidate = func(id string) {
			mu.Lock()
			announced = append(announced, id)
			mu.Unlock()
		}
	})
	sid := signIn(t, a, idp)
	completeRenewal(t, a, idp, sid)
	mu.Lock()
	defer mu.Unlock()
	for _, id := range announced {
		if id == HashSessionID(sid) {
			return
		}
	}
	t.Fatalf("announced %v, want the renewed session", announced)
}

// ── the schedule ────────────────────────────────────────────────────────────

func TestRenewAfter(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		rec    SessionRecord
		maxAge time.Duration
		want   time.Duration
	}{
		{"cloop's bound", SessionRecord{ClaimsAsOf: now}, 5 * time.Minute, 5*time.Minute - renewSlack},
		{"the provider's deadline when sooner",
			SessionRecord{ClaimsAsOf: now, ClaimsExpireAt: now.Add(6 * time.Minute)},
			10 * time.Minute, 6*time.Minute - renewSlack},
		{"never negative", SessionRecord{ClaimsAsOf: now.Add(-time.Hour)}, 5 * time.Minute, 0},
		// The narrowest bound an operator can configure. A flat slack would
		// make this negative, and every schedule — including the one issued
		// right after a renewal — would say "now".
		{"a one-minute bound", SessionRecord{ClaimsAsOf: now}, time.Minute, 40 * time.Second},
		// The same trap from the provider's side: access tokens that live
		// shorter than the flat slack.
		{"a sixty-second access token",
			SessionRecord{ClaimsAsOf: now, ClaimsExpireAt: now.Add(time.Minute)},
			5 * time.Minute, 40 * time.Second},
		{"a session from before the claim clock", SessionRecord{IssuedAt: now}, 5 * time.Minute, 5*time.Minute - renewSlack},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renewAfter(tc.rec, tc.maxAge, now); got != tc.want {
				t.Fatalf("renewAfter = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBrowserRenewIn(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	store := NewMemorySessionStore(0)
	a := renewAuth(t, idp, clk, store, nil)
	sid := signIn(t, a, idp)
	hash := HashSessionID(sid)

	d, ok := a.BrowserRenewIn(hash)
	if !ok || d != 5*time.Minute-renewSlack {
		t.Fatalf("BrowserRenewIn = %v, %v; want %v, true", d, ok, 5*time.Minute-renewSlack)
	}
	clk.advance(time.Minute)
	if d, _ := a.BrowserRenewIn(hash); d != 4*time.Minute-renewSlack {
		t.Fatalf("a minute later = %v, want %v", d, 4*time.Minute-renewSlack)
	}

	t.Run("the server refreshes this one itself", func(t *testing.T) {
		idp.issueRefresh = "rt-1"
		sid := signIn(t, a, idp)
		idp.issueRefresh = ""
		if _, ok := a.BrowserRenewIn(HashSessionID(sid)); ok {
			t.Fatal("a session holding a refresh token was handed to the browser — the server-side " +
				"refresh is the first layer, and a frame on top of it raises banners for nothing " +
				"wherever third-party cookies are blocked")
		}
	})
	t.Run("the bound is off", func(t *testing.T) {
		off := renewAuth(t, idp, clk, store, func(c *Config) { c.MaxClaimAge = -1 })
		if _, ok := off.BrowserRenewIn(hash); ok {
			t.Fatal("a hub with the freshness check off scheduled a renewal")
		}
	})
	t.Run("no such session", func(t *testing.T) {
		if _, ok := a.BrowserRenewIn(HashSessionID("gone")); ok {
			t.Fatal("scheduled a renewal for a session that does not exist")
		}
	})
}

// ── framing ─────────────────────────────────────────────────────────────────

func TestFrameOriginsNamesTheProvider(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)

	// Before discovery only the issuer is known — the right answer for every
	// provider that serves both from one host.
	if got := a.FrameOrigins(); len(got) != 1 || got[0] != idp.server.URL {
		t.Fatalf("FrameOrigins before discovery = %v, want [%s]", got, idp.server.URL)
	}
	if _, err := a.discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}
	// Same origin here, so the set must not grow: a duplicate widens nothing
	// but costs a reader a second look.
	if got := a.FrameOrigins(); len(got) != 1 {
		t.Fatalf("FrameOrigins after discovery = %v, want one origin", got)
	}

	var off *Authenticator
	if got := off.FrameOrigins(); got != nil {
		t.Fatalf("a hub without OIDC named frame sources: %v", got)
	}
}

func TestFrameOriginsAddsASeparateAuthorizationHost(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	a.noteFrameOrigins(&discoveryDoc{AuthorizationEndpoint: "https://Login.Example.com/oauth2/authorize"})
	got := a.FrameOrigins()
	if len(got) != 2 || got[0] != idp.server.URL || got[1] != "https://login.example.com" {
		t.Fatalf("FrameOrigins = %v, want the issuer and the authorization host", got)
	}
}

// TestFrameOriginsDoesNotWaitForDiscovery: the hub reads FrameOrigins for every
// response it sends. Discovery holds its mutex across the round trip to the
// provider, so a FrameOrigins that took that mutex would stall the whole hub
// behind an IdP that is slow to answer.
func TestFrameOriginsDoesNotWaitForDiscovery(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	a.discMu.Lock()
	defer a.discMu.Unlock()
	done := make(chan []string, 1)
	go func() { done <- a.FrameOrigins() }()
	select {
	case got := <-done:
		if len(got) == 0 {
			t.Fatal("no frame origins while discovery is in flight")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FrameOrigins blocked behind discovery")
	}
}

// ── the document ────────────────────────────────────────────────────────────

func TestRenewDocumentPostsOnlyToItsOwnOrigin(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)
	rec := completeRenewal(t, a, idp, sid)

	body := rec.Body.String()
	// "/" is the sending document's own origin. "*" would publish the fact
	// that a named user is signed in here to any page holding the frame.
	if !strings.Contains(body, `, "/"); }`) {
		t.Errorf("the renewal document does not address its own origin:\n%s", body)
	}
	if strings.Contains(body, `"*"`) || strings.Contains(body, `'*'`) {
		t.Errorf("the renewal document posts to a wildcard origin:\n%s", body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q, want SAMEORIGIN", got)
	}
}

func TestRenewDocumentCarriesTheNextSchedule(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	a := renewAuth(t, idp, clk, nil, nil)
	sid := signIn(t, a, idp)
	clk.advance(10 * time.Minute)

	msg := renewMessage(t, completeRenewal(t, a, idp, sid))
	// The dashboard re-arms from this rather than asking /api/me, whose
	// request would count as activity.
	if got, want := msg["renew_in"], strconv.Itoa(int((5*time.Minute-renewSlack)/time.Second)); got != want {
		t.Errorf("renew_in = %q, want %s", got, want)
	}
	if msg["changed"] != "false" {
		t.Errorf("changed = %q, want false — the provider released the same claims", msg["changed"])
	}
}

func TestRenewDocumentEscapesProviderText(t *testing.T) {
	idp := newFakeIdP(t)
	a := renewAuth(t, idp, newClock(), nil, nil)
	sid := signIn(t, a, idp)

	_, q := beginRenew(t, a, sid)
	rec := renewCallback(a, url.Values{
		"state":             {q.Get("state")},
		"error":             {"server_error"},
		"error_description": {`</script><script>alert(1)</script>"); evil("`},
	})
	body := rec.Body.String()
	if strings.Count(body, "</script>") != 1 {
		t.Fatalf("provider text closed the script element:\n%s", body)
	}
	if strings.Contains(body, `"); evil("`) {
		t.Fatalf("provider text escaped its string literal:\n%s", body)
	}
	if got := renewMessage(t, rec)["outcome"]; got != string(RenewIdPError) {
		t.Fatalf("outcome = %q, want idp_error", got)
	}
}

func TestRenewWithoutOIDC(t *testing.T) {
	var a *Authenticator
	rec := httptest.NewRecorder()
	if got := a.BeginRenew(rec, httptest.NewRequest(http.MethodGet, "/auth/renew", nil)); got != RenewDisabled {
		t.Fatalf("BeginRenew on a hub without OIDC = %q, want not_enabled", got)
	}
	if got := renewMessage(t, rec)["outcome"]; got != string(RenewDisabled) {
		t.Fatalf("document outcome = %q", got)
	}
	if _, ok := a.BrowserRenewIn("x"); ok {
		t.Fatal("a hub without OIDC scheduled a renewal")
	}
}

// ── the return path ─────────────────────────────────────────────────────────

func TestSafeReturnPath(t *testing.T) {
	// A value that reaches a Location header, an HTML attribute and a script.
	// The refusals matter more than the acceptances: each is a spelling a
	// browser reads as somewhere other than this origin.
	accept := []string{"/", "/tasks", "/?project_idx=3", "/a/b?q=1#frag", "/x%20y", "/%2F%2Fevil.example"}
	reject := []string{
		"",                            // nothing to go to
		"tasks",                       // relative: resolves against the callback path
		"//evil.example/",             // protocol-relative absolute URL
		"//user@evil.example/",        // with userinfo
		`/\evil.example`,              // normalised to // by browsers
		`/\/evil.example`,             //
		"https://evil.example/",       // absolute
		"javascript:alert(1)",         // scheme
		"data:text/html,<b>x</b>",     //
		"/x\r\nSet-Cookie: a=b",       // header splitting
		"/x\nLocation: https://evil/", //
		"/\t/evil.example",            // browsers strip the tab, leaving //
		"/x\x00y",                     // control character
		"/x\x7fy",                     //
		"/" + strings.Repeat("a", maxReturnPathLen), // longer than the bound
	}
	for _, p := range accept {
		if got := safeReturnPath(p); got != p {
			t.Errorf("safeReturnPath(%q) = %q, want it accepted unchanged", p, got)
		}
	}
	for _, p := range reject {
		if got := safeReturnPath(p); got != "" {
			t.Errorf("safeReturnPath(%q) = %q, want it refused", p, got)
		}
	}
}

func TestLoginReturnsToWhereTheUserWas(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)

	rec := httptest.NewRecorder()
	a.BeginLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return=%2F%3Fproject_idx%3D2%23tasks", nil))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize redirect: %v", err)
	}
	idp.nonce = loc.Query().Get("nonce")
	done := doCallback(a, loc.Query().Get("state"))
	// Plain http redirect_url, so a Lax cookie and a plain 302.
	if done.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body: %s)", done.Code, done.Body.String())
	}
	if got := done.Header().Get("Location"); got != "/?project_idx=2#tasks" {
		t.Fatalf("landed at %q, want the page the user was on", got)
	}
}

func TestLoginRefusesAnOffSiteReturn(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)

	for _, ret := range []string{"https://evil.example/", "//evil.example/", `/\evil.example`} {
		rec := httptest.NewRecorder()
		a.BeginLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return="+url.QueryEscape(ret), nil))
		loc, _ := url.Parse(rec.Header().Get("Location"))
		idp.nonce = loc.Query().Get("nonce")
		done := doCallback(a, loc.Query().Get("state"))
		if got := done.Header().Get("Location"); got != "/" {
			t.Errorf("return=%q landed at %q, want / — an off-site return must be dropped", ret, got)
		}
	}
}

// TestLoginLandingEscapesDestination: the landing page puts the destination
// into three parsers at once, and html.EscapeString alone is not enough for the
// script — an HTML-escaped quote is a quote again by the time JavaScript sees it.
func TestLoginLandingEscapesDestination(t *testing.T) {
	dest := safeReturnPath(`/x?a="+alert(1)+"&b=</script><img src=x>`)
	if dest == "" {
		t.Fatal("precondition: the hostile query should survive safeReturnPath, which only vets the origin")
	}
	page := loginLandingHTML(dest)
	if n := strings.Count(page, "</script>"); n != 1 {
		t.Errorf("found %d closing script tags, want 1:\n%s", n, page)
	}
	if strings.Contains(page, "<img") {
		t.Errorf("the destination injected markup:\n%s", page)
	}
	line := page[strings.Index(page, "location.replace("):]
	line = line[:strings.Index(line, "\n")]
	if strings.Contains(line, `"+alert(1)+"`) {
		t.Errorf("an unescaped quote closed the script's string literal: %s", line)
	}
	for _, frag := range []string{`url=/x?a="`, `href="/x?a="`} {
		if strings.Contains(page, frag) {
			t.Errorf("the destination broke out of an HTML attribute (%q):\n%s", frag, page)
		}
	}
}

// TestSecureLoginLandsOnTheReturnPath: over TLS the session cookie is Strict
// and the hub answers the callback with a landing page rather than a 302 (see
// completeLogin). The destination must survive that path too.
func TestSecureLoginLandsOnTheReturnPath(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	rec := httptest.NewRecorder()
	a.BeginLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return=%2F%3Fproject_idx%3D4", nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	idp.nonce = loc.Query().Get("nonce")

	done := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	req.RemoteAddr = "127.0.0.1:40000" // TLS terminated by a proxy on this machine
	req.Header.Set("X-Forwarded-Proto", "https")
	a.HandleCallback(done, req)
	if done.Code != http.StatusOK {
		t.Fatalf("status = %d, want the 200 landing page", done.Code)
	}
	if !strings.Contains(done.Body.String(), `location.replace("/?project_idx=4")`) {
		t.Fatalf("the landing page does not continue to the return path:\n%s", done.Body.String())
	}
}
