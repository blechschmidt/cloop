package oidcauth

// Sudo mode (Task 20448): when a session's owner last authenticated, and the
// confirm-it's-you sign-in that brings it up to date.

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// clockAt is a settable clock that starts at the real time, so the identity
// provider's auth_time (real seconds) and the hub's clock agree until a test
// moves the hub's on.
func clockAt(now time.Time) *clock { return &clock{t: now} }

// sudoAuth is an authenticator over a memory store with a recording audit sink.
func sudoAuth(t *testing.T, idp *fakeIdP, clk *clock, mutate func(*Config)) (*Authenticator, *auditRecorder, SessionStore) {
	t.Helper()
	rec := &auditRecorder{}
	store := NewMemorySessionStore(0)
	a := newLifecycleAuth(t, idp, store, clk, func(c *Config) {
		c.Audit = rec.sink
		if mutate != nil {
			mutate(c)
		}
	})
	return a, rec, store
}

// sessionOf reads back the session a cookie names.
func sessionOf(t *testing.T, store SessionStore, cookie string) SessionRecord {
	t.Helper()
	rec, err := store.Get(HashSessionID(cookie))
	if err != nil {
		t.Fatalf("the session behind the cookie is not stored: %v", err)
	}
	return rec
}

// beginReauth starts a confirm-it's-you sign-in from the browser holding
// cookie ("" for none) and returns the authorization request's query.
func beginReauth(t *testing.T, a *Authenticator, cookie, mode string) url.Values {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, LoginPath+"?"+ReauthParam+"="+mode+"&return=%2Fsettings&"+
		ReauthNonceParam+"="+testNonce, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	a.BeginLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("BeginLogin(reauth) = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query()
}

// testNonce is the dialog nonce the tests' windows carry.
const testNonce = "0123456789abcdef0123456789abcdef"

// finishReauth delivers the provider's answer, with no cookie — the real
// callback is a cross-site navigation.
func finishReauth(a *Authenticator, idp *fakeIdP, q url.Values) *httptest.ResponseRecorder {
	idp.nonce = q.Get("nonce")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=authcode-1&state="+url.QueryEscape(q.Get("state")), nil)
	req.RemoteAddr = "198.51.100.7:40000"
	a.HandleCallback(rec, req)
	return rec
}

func newCookie(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// TestAuthTimeIsTheSignInARecentActionIsMeasuredFrom: a provider that reports
// auth_time is believed, and the window runs from it — not from the session's
// own sign-in, which may have been answered from a provider session hours old.
func TestAuthTimeIsTheSignInARecentActionIsMeasuredFrom(t *testing.T) {
	idp := newFakeIdP(t)
	clk := clockAt(time.Now())
	a, _, store := sudoAuth(t, idp, clk, nil)

	signedIn := clk.now().Add(-30 * time.Minute).Truncate(time.Second)
	idp.codeClaims = map[string]any{"auth_time": signedIn.Unix()}
	rec := sessionOf(t, store, signIn(t, a, idp))
	if !rec.AuthenticatedAt.Equal(signedIn) {
		t.Fatalf("AuthenticatedAt = %v, want the provider's auth_time %v", rec.AuthenticatedAt, signedIn)
	}
	st := a.RecentSignIn(rec)
	if !st.Required || !st.Recent || st.MaxAge != DefaultSudoMaxAge {
		t.Fatalf("a sign-in 30m ago under the default window: %+v", st)
	}
	if left := st.Remaining; left < 89*time.Minute || left > 91*time.Minute {
		t.Errorf("Remaining = %v, want about 90m", left)
	}
	clk.advance(91 * time.Minute)
	if st := a.RecentSignIn(rec); st.Recent || st.Remaining != 0 {
		t.Errorf("two hours and a minute after the sign-in the session still reads recent: %+v", st)
	}

	// A silent dashboard sign-in on a provider session three hours old: the
	// session is new, the sign-in behind it is not.
	idp.codeClaims = map[string]any{"auth_time": clk.now().Add(-3 * time.Hour).Unix()}
	old := sessionOf(t, store, signIn(t, a, idp))
	if a.RecentSignIn(old).Recent {
		t.Error("a session whose provider sign-in is three hours old reads recent")
	}
}

// TestNoAuthTimeMeansNoRecentSignIn: without auth_time an ordinary sign-in
// proves nothing recent — the provider may have answered from a session of its
// own — and only one the hub itself started with prompt=login counts, from
// its callback (Entra ID without the auth_time optional claim).
func TestNoAuthTimeMeansNoRecentSignIn(t *testing.T) {
	idp := newFakeIdP(t)
	clk := clockAt(time.Now())
	a, audits, store := sudoAuth(t, idp, clk, nil)

	cookie := signIn(t, a, idp) // the fake reports no auth_time by default
	rec := sessionOf(t, store, cookie)
	if !rec.AuthenticatedAt.IsZero() {
		t.Fatalf("an ordinary sign-in with no auth_time recorded AuthenticatedAt %v", rec.AuthenticatedAt)
	}
	if st := a.RecentSignIn(rec); !st.Required || st.Recent {
		t.Fatalf("a session with no known interactive sign-in reads %+v, want required and not recent", st)
	}

	q := beginReauth(t, a, cookie, "1")
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("a confirm-it's-you sign-in must ask for prompt=login&max_age=0, got prompt=%q max_age=%q",
			q.Get("prompt"), q.Get("max_age"))
	}
	if !strings.EqualFold(q.Get("login_hint"), "alice@example.com") {
		t.Errorf("login_hint = %q, want the signed-in person", q.Get("login_hint"))
	}
	before := clk.now()
	res := finishReauth(a, idp, q)
	fresh := newCookie(res)
	if fresh == "" || fresh == cookie {
		t.Fatalf("the confirm-it's-you sign-in must set a new session cookie (status %d)", res.Code)
	}
	// The landing page (the redirect URL is https, so the cookie is Strict and
	// the browser moves on from a page of ours) continues to where it was asked.
	if !strings.Contains(res.Body.String(), `href="/settings"`) && res.Header().Get("Location") != "/settings" {
		t.Errorf("it does not land on the page it was asked from:\n%s", res.Body.String())
	}
	frec := sessionOf(t, store, fresh)
	if !frec.AuthenticatedAt.Equal(before) {
		t.Errorf("AuthenticatedAt = %v, want the callback's own time %v", frec.AuthenticatedAt, before)
	}
	if !a.RecentSignIn(frec).Recent {
		t.Error("the session a prompted sign-in created is not recent")
	}
	// The session that asked is left alone: still live, still not recent.
	if _, st := a.CheckSession(HashSessionID(cookie)); st != SessionLive {
		t.Errorf("the session that asked reads %q, want live", st)
	}
	if a.RecentSignIn(sessionOf(t, store, cookie)).Recent {
		t.Error("the confirm-it's-you sign-in freshened the session that asked instead of creating one")
	}
	ev, ok := audits.last(AuditSessionReauth)
	if !ok || ev.Reauth == nil || ev.Reauth.Outcome != ReauthGranted {
		t.Fatalf("want a session.reauth granted row, got %+v (found=%v)", ev, ok)
	}
	if ev.SessionID != frec.ID || ev.Reauth.Replaces != rec.ID {
		t.Errorf("granted row names session %q replacing %q, want %q replacing %q",
			ev.SessionID, ev.Reauth.Replaces, frec.ID, rec.ID)
	}
}

// TestSilentRenewalDoesNotRefreshTheSignIn: neither renewal path is the person
// proving anything, so neither may move AuthenticatedAt — a tab left open on
// an old provider session would otherwise stay recent for ever.
func TestSilentRenewalDoesNotRefreshTheSignIn(t *testing.T) {
	idp := newFakeIdP(t)
	clk := clockAt(time.Now())
	idp.issueRefresh = "rt-1"
	idp.nextRefreshToken = "rt-2"
	// The refresh grant restates the claims, with an auth_time of now: the
	// provider's own session was used, which is not the person signing in.
	idp.refreshIDToken = func(int) map[string]any {
		return idp.refreshClaims(map[string]any{"sub": "user-123", "auth_time": time.Now().Unix()})
	}
	a, _, store := sudoAuth(t, idp, clk, func(c *Config) { c.MaxClaimAge = 5 * time.Minute })

	signedIn := clk.now().Add(-90 * time.Minute).Truncate(time.Second)
	idp.codeClaims = map[string]any{"auth_time": signedIn.Unix()}
	cookie := signIn(t, a, idp)

	// The browser's prompt=none renewal, answered by a provider that reports
	// a newer auth_time (its session was used, not the person's password).
	idp.codeClaims = map[string]any{"auth_time": clk.now().Unix()}
	if res := completeRenewal(t, a, idp, cookie); res.Code != http.StatusOK {
		t.Fatalf("silent renewal: %d %s", res.Code, res.Body.String())
	}
	// And the server-side refresh.
	clk.advance(10 * time.Minute)
	if _, err := a.EnsureFreshClaims(t.Context(), HashSessionID(cookie)); err != nil {
		t.Fatalf("EnsureFreshClaims: %v", err)
	}
	if idp.refreshRequests == 0 {
		t.Fatal("the server-side refresh never reached the provider")
	}
	rec := sessionOf(t, store, cookie)
	if !rec.AuthenticatedAt.Equal(signedIn) {
		t.Fatalf("renewal moved AuthenticatedAt from %v to %v", signedIn, rec.AuthenticatedAt)
	}
	clk.advance(25 * time.Minute)
	if a.RecentSignIn(rec).Recent {
		t.Error("two hours after the sign-in, renewals kept the session recent")
	}
}

// TestAuthTimeAcrossClockSkew: a provider clock a little fast buys nothing —
// its auth_time is read as now — and one far ahead is not believed at all; a
// provider clock a little slow does not fail a confirm-it's-you sign-in it
// really did ask for, while an auth_time well before the request means it did
// not ask.
func TestAuthTimeAcrossClockSkew(t *testing.T) {
	idp := newFakeIdP(t)
	clk := clockAt(time.Now())
	a, audits, store := sudoAuth(t, idp, clk, func(c *Config) { c.ClockSkew = 2 * time.Minute })

	// Ahead by less than the allowance: clamped to now.
	idp.codeClaims = map[string]any{"auth_time": clk.now().Add(time.Minute).Unix()}
	rec := sessionOf(t, store, signIn(t, a, idp))
	if !rec.AuthenticatedAt.Equal(clk.now()) {
		t.Errorf("an auth_time a minute fast recorded %v, want now (%v)", rec.AuthenticatedAt, clk.now())
	}
	if st := a.RecentSignIn(rec); st.Remaining > DefaultSudoMaxAge {
		t.Errorf("a fast provider clock lengthened the window: %v left", st.Remaining)
	}

	// Ahead by more: not a sign-in anybody can vouch for.
	idp.codeClaims = map[string]any{"auth_time": clk.now().Add(time.Hour).Unix()}
	rec = sessionOf(t, store, signIn(t, a, idp))
	if !rec.AuthenticatedAt.IsZero() {
		t.Errorf("an auth_time an hour in the future was believed: %v", rec.AuthenticatedAt)
	}

	// Behind by less than the allowance, on a confirm-it's-you sign-in.
	cookie := signIn(t, a, idp)
	q := beginReauth(t, a, cookie, "1")
	idp.codeClaims = map[string]any{"auth_time": time.Now().Add(-time.Minute).Unix()}
	res := finishReauth(a, idp, q)
	fresh := newCookie(res)
	if fresh == "" {
		t.Fatalf("a provider clock a minute slow failed the sign-in it asked for: %d %s", res.Code, res.Body.String())
	}
	if !a.RecentSignIn(sessionOf(t, store, fresh)).Recent {
		t.Error("the confirm-it's-you session from a slightly slow provider is not recent")
	}

	// Behind by more: the provider answered from an older session.
	q = beginReauth(t, a, cookie, "1")
	idp.codeClaims = map[string]any{"auth_time": time.Now().Add(-10 * time.Minute).Unix()}
	res = finishReauth(a, idp, q)
	if newCookie(res) != "" || res.Code != http.StatusForbidden {
		t.Fatalf("a provider that did not ask was believed: %d, cookie set=%v", res.Code, newCookie(res) != "")
	}
	ev, ok := audits.last(AuditSessionReauth)
	if !ok || ev.Reauth.Outcome != ReauthRefused || ev.Reason != ReauthReasonNotReauthenticated {
		t.Errorf("want session.reauth refused/%s, got %+v", ReauthReasonNotReauthenticated, ev)
	}
}

// TestReauthRefusesAnotherAccount: the confirm-it's-you sign-in is for the
// person whose session asked; another account at the provider creates nothing.
func TestReauthRefusesAnotherAccount(t *testing.T) {
	idp := newFakeIdP(t)
	clk := clockAt(time.Now())
	a, audits, _ := sudoAuth(t, idp, clk, nil)
	cookie := signIn(t, a, idp)
	before := a.SessionCount()

	idp.codeSub = "somebody-else"
	res := finishReauth(a, idp, beginReauth(t, a, cookie, ReauthWindow))
	if res.Code != http.StatusForbidden || newCookie(res) != "" {
		t.Fatalf("another account's sign-in: %d, cookie set=%v", res.Code, newCookie(res) != "")
	}
	if a.SessionCount() != before {
		t.Error("a refused confirm-it's-you sign-in created a session")
	}
	msg := reauthDocument(t, res)
	if msg["outcome"] != string(ReauthRefused) || !strings.Contains(msg["message"], "different account") {
		t.Errorf("the window was told %v", msg)
	}
	ev, ok := audits.last(AuditSessionReauth)
	if !ok || ev.Reauth.Outcome != ReauthRefused || ev.Reason != ReauthReasonSubjectMismatch {
		t.Errorf("want session.reauth refused/%s, got %+v", ReauthReasonSubjectMismatch, ev)
	}
	if ev.SessionID != HashSessionID(cookie) {
		t.Errorf("the refusal is filed under %q, want the session that asked", ev.SessionID)
	}
}

// TestReauthWindowAnswersWithAResultDocument: from a window of its own, the
// sign-in answers with a document that tells the dashboard tab, by data the
// sign-in script reads — never script of its own.
func TestReauthWindowAnswersWithAResultDocument(t *testing.T) {
	idp := newFakeIdP(t)
	a, _, _ := sudoAuth(t, idp, clockAt(time.Now()), nil)
	cookie := signIn(t, a, idp)
	res := finishReauth(a, idp, beginReauth(t, a, cookie, ReauthWindow))
	if res.Code != http.StatusOK || newCookie(res) == "" {
		t.Fatalf("window sign-in: %d, cookie set=%v", res.Code, newCookie(res) != "")
	}
	if msg := reauthDocument(t, res); msg["outcome"] != string(ReauthGranted) || msg["type"] != ReauthMessageType ||
		msg["nonce"] != testNonce {
		t.Errorf("the window was told %v, want granted with the dialog's nonce", msg)
	}
	// A nonce that is not plainly one is not echoed.
	for _, bad := range []string{"short", strings.Repeat("a", 65), "0123456789abcdef<script>", ""} {
		if got := reauthNonce(bad); got != "" {
			t.Errorf("reauthNonce(%q) = %q, want it dropped", bad, got)
		}
	}

	// The provider refusing — the person cancelled — is the window's
	// verdict too, not an error page nobody is waiting on, and it is no
	// sign-in verdict: the person is still signed in as they were.
	q := beginReauth(t, a, cookie, ReauthWindow)
	refused := httptest.NewRecorder()
	if out := a.HandleCallback(refused, httptest.NewRequest(http.MethodGet,
		"/auth/callback?error=access_denied&state="+url.QueryEscape(q.Get("state")), nil)); out != LoginReauthRefused || out.Recorded() {
		t.Errorf("a cancelled confirmation = %q (recorded %v), want an unrecorded %q", out, out.Recorded(), LoginReauthRefused)
	}
	if msg := reauthDocument(t, refused); msg["outcome"] != string(ReauthRefused) || msg["nonce"] != testNonce {
		t.Errorf("a cancelled confirmation told the window %v", msg)
	}
	if !strings.Contains(signInScript, "data-reauth") || !strings.Contains(signInScript, ReauthChannel) {
		t.Error("the sign-in script does not read the result document")
	}
}

var reauthAttrRe = regexp.MustCompile(`<html lang="en" data-reauth="([^"]*)">`)

func reauthDocument(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	body := rec.Body.String()
	m := reauthAttrRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no result document:\n%s", body)
	}
	if !strings.Contains(body, `<script src="`+ScriptPath+`"></script>`) || strings.Contains(body, "<script>") {
		t.Fatalf("the result document must load only the sign-in script:\n%s", body)
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &out); err != nil {
		t.Fatalf("message: %v", err)
	}
	return out
}

// TestTerminalSessionsCountFromTheSignInBehindTheirApproval: a `cloop login`
// session is held to the sudo window from the approval when the approval was
// itself a sign-in, and otherwise from the sign-in the approving browser rode
// on — so a browser too stale for any privileged action cannot mint a terminal
// session fresh enough for all of them, whatever the device window says.
func TestTerminalSessionsCountFromTheSignInBehindTheirApproval(t *testing.T) {
	idp := newFakeIdP(t)
	clk := clockAt(time.Now())
	store := NewMemorySessionStore(0)
	a := newLifecycleAuth(t, idp, store, clk, func(c *Config) {
		c.DeviceLogin = true
		c.DeviceApprovalMaxAge = -1 // the device window never asks
	})
	cliRecord := func(tm terminal) SessionRecord {
		t.Helper()
		if _, te := pollCode(a, tm); te != nil {
			t.Fatalf("poll: %+v", te)
		}
		rec, err := store.Get(tm.sessionID())
		if err != nil {
			t.Fatalf("the terminal's session: %v", err)
		}
		return rec
	}

	// A browser whose sign-in is three hours old: the approval must be a
	// sign-in, and a provider that answers from its old session is refused.
	idp.codeClaims = map[string]any{"auth_time": time.Now().Add(-3 * time.Hour).Unix()}
	stale := signIn(t, a, idp)
	tm := askForCode(t, a)
	cb, q := approve(t, a, idp, stale, tm.grant.UserCode)
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("a stale browser approving: authorization request %v, want prompt=login&max_age=0", q)
	}
	if cb.Code != http.StatusForbidden {
		t.Fatalf("a provider that did not ask was believed: %d %s", cb.Code, cb.Body.String())
	}
	// It asks this time, and the terminal counts from then.
	idp.codeClaims = map[string]any{"auth_time": time.Now().Unix()}
	approve(t, a, idp, stale, tm.grant.UserCode)
	if st := a.RecentSignIn(cliRecord(tm)); !st.Recent || st.Remaining < DefaultSudoMaxAge-time.Minute {
		t.Errorf("a terminal approved through a fresh sign-in: %+v, want the whole window", st)
	}

	// A provider that never reports auth_time, asked for prompt=login: the
	// approval's own time.
	idp.codeClaims = nil
	quiet := askForCode(t, a)
	approve(t, a, idp, stale, quiet.grant.UserCode)
	if rec := cliRecord(quiet); !rec.AuthenticatedAt.Equal(clk.now()) {
		t.Errorf("a prompted approval with no auth_time recorded %v, want the approval %v", rec.AuthenticatedAt, clk.now())
	}

	// A browser that signed in half an hour ago approves silently, and the
	// terminal inherits its sign-in rather than the approval's time.
	signedIn := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	idp.codeClaims = map[string]any{"auth_time": signedIn.Unix()}
	recent := signIn(t, a, idp)
	inherit := askForCode(t, a)
	_, q = approve(t, a, idp, recent, inherit.grant.UserCode)
	if q.Get("prompt") != "" {
		t.Fatalf("a recent browser approving was asked to sign in: %v", q)
	}
	rec := cliRecord(inherit)
	if !rec.AuthenticatedAt.Equal(signedIn) {
		t.Errorf("a silent approval recorded %v, want the browser's sign-in %v", rec.AuthenticatedAt, signedIn)
	}
	if st := a.RecentSignIn(rec); st.Remaining > DefaultSudoMaxAge-29*time.Minute {
		t.Errorf("a silent approval lengthened the window: %v left", st.Remaining)
	}
}

// TestSudoWindowConfiguration: zero is the default, negative turns the rule
// off — every session then passes, and nothing is required — and a window past
// a day is held to one.
func TestSudoWindowConfiguration(t *testing.T) {
	idp := newFakeIdP(t)
	for _, c := range []struct {
		in, want time.Duration
	}{
		{0, DefaultSudoMaxAge},
		{-5 * time.Minute, -1},
		{30 * time.Minute, 30 * time.Minute},
		{48 * time.Hour, MaxSudoMaxAge},
	} {
		a, _, _ := sudoAuth(t, idp, nil, func(cfg *Config) { cfg.SudoMaxAge = c.in })
		if got := a.SudoMaxAge(); got != c.want {
			t.Errorf("SudoMaxAge(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	off, _, _ := sudoAuth(t, idp, nil, func(cfg *Config) { cfg.SudoMaxAge = -1 })
	if st := off.RecentSignIn(SessionRecord{}); !st.Recent || st.Required {
		t.Errorf("with the rule off a session with no sign-in on record reads %+v", st)
	}
	var nilAuth *Authenticator
	if st := nilAuth.RecentSignIn(SessionRecord{}); !st.Recent {
		t.Error("a hub without single sign-on must not ask anything")
	}
}

// TestReauthAuditRecordsStaleRefusals: the request half of the row.
func TestReauthAuditRecordsStaleRefusals(t *testing.T) {
	idp := newFakeIdP(t)
	clk := clockAt(time.Now())
	a, audits, store := sudoAuth(t, idp, clk, nil)
	rec := sessionOf(t, store, signIn(t, a, idp))
	req := httptest.NewRequest(http.MethodPost, "/api/secrets", nil)
	a.NoteStaleRefused(rec, req, a.RecentSignIn(rec), 3)
	ev, ok := audits.last(AuditSessionReauth)
	if !ok || ev.Reauth.Outcome != ReauthStaleRefused || ev.Reauth.Method != "POST" ||
		ev.Reauth.Path != "/api/secrets" || ev.Reauth.Suppressed != 3 || ev.SessionID != rec.ID {
		t.Fatalf("stale-refused row: %+v / %+v", ev, ev.Reauth)
	}
}
