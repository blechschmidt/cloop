package oidcauth

// Silent re-assertion of a session's claims, from the user's browser
// (Task 20359, re-landing Tasks 20322 and 20330).
//
// # The failure this removes
//
// Task 20273 bounded authorization staleness: a permission above operator needs
// claims no older than max_claim_age, and the hub re-asserts them by redeeming
// the session's refresh token. That is the first layer and it stays the first
// layer. But a hub retains no refresh token in two ordinary cases — no
// CLOOP_SECRET_KEY, or a provider that issued none — and there it has exactly
// one answer once the bound lapses:
//
//	this session's group and role claims are 7m12s old (limit 5m0s) and cannot
//	be re-checked: no refresh token is retained for it
//
// The browser can settle the question the hub cannot, because the user is still
// signed in at the identity provider.
//
// # The mechanism
//
//	GET /auth/renew          in a hidden frame, with the session cookie
//	  → authorize?prompt=none        answered from the provider's own session
//	  → <callback>?code=…&state=…    back into the same frame
//	  → postMessage to the parent    {outcome:"ok"}; nothing on screen moved
//
// prompt=none tells the provider to answer from its own session or not at all,
// so the frame is only ever a redirect chain and never renders a form. A
// provider that cannot answer says so — login_required, interaction_required —
// which is the dashboard's cue to stop being silent and offer a visible sign-in.
//
// # Why the callback carries no cookie, and why that is fine
//
// The provider's redirect back into the frame is a cross-site navigation in a
// nested browsing context, so neither a Lax nor a Strict cookie rides on it.
// The callback cannot read the session it renews and does not try: the state
// was minted by /auth/renew, which did present the cookie, and the pending
// record carries the session's hashed id and subject forward. A silent flow can
// therefore re-assert the claims of the session that asked and do nothing else.
// It sets no cookie, so it cannot create a session; it does not move the
// absolute expiry, so it cannot extend one; it compares subjects twice, so it
// cannot move one to somebody else; and it does not advance the idle clock, so
// a tab left open does not keep an unattended session alive by renewing it.

import (
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RenewOutcome is the verdict of one silent renewal: the metric label, and the
// value the dashboard switches on. A closed set.
type RenewOutcome string

const (
	// RenewPending is the zero value: the frame was sent to the provider and
	// there is no verdict yet. Returned by BeginRenew on the redirect, the way
	// BeginLogin returns LoginPending.
	RenewPending RenewOutcome = ""

	// RenewOK: the provider re-asserted the claims and the session holds them.
	RenewOK RenewOutcome = "ok"

	// RenewNoSession: there is no live session to renew — the request carried
	// no valid cookie, or the session ended during the round trip.
	RenewNoSession RenewOutcome = "no_session"

	// RenewDisabled: this hub does not use single sign-on.
	RenewDisabled RenewOutcome = "not_enabled"

	// RenewInteractionRequired: the provider will not answer without showing
	// the user something. It is what prompt=none is *for*, not a fault — and
	// it is also what a browser that blocks the provider's cookies in a frame
	// produces, since the provider then cannot see its own session.
	RenewInteractionRequired RenewOutcome = "interaction_required"

	// RenewIdPError: the provider refused for some other reason it named.
	RenewIdPError RenewOutcome = "idp_error"

	// RenewDiscoveryFailed: the issuer could not be resolved.
	RenewDiscoveryFailed RenewOutcome = "discovery_failed"

	// RenewStateError: the CSPRNG failed. Enumerated so no branch is unaccounted for.
	RenewStateError RenewOutcome = "state_error"

	// RenewInvalidState: the provider came back without an authorization code
	// or an error.
	RenewInvalidState RenewOutcome = "invalid_state"

	// RenewExchangeFailed: the token endpoint refused the code.
	RenewExchangeFailed RenewOutcome = "exchange_failed"

	// RenewTokenInvalid: the returned id_token failed validation.
	RenewTokenInvalid RenewOutcome = "token_invalid"

	// RenewSubjectMismatch: the provider answered for a different user than the
	// session belongs to. The session is left exactly as it was — adopting the
	// other subject's claims would hand it somebody else's authority.
	RenewSubjectMismatch RenewOutcome = "subject_mismatch"

	// RenewStoreError: the re-asserted claims could not be written.
	RenewStoreError RenewOutcome = "store_error"
)

// Recorded reports whether o is a verdict worth counting.
func (o RenewOutcome) Recorded() bool { return o != RenewPending }

// renewSlack is how long before the claims' deadline a renewal should land.
//
// It covers two redirects and a token exchange with room to spare. Renewing
// early costs one request nobody sees; renewing late costs the refusal this
// file exists to remove.
const renewSlack = 90 * time.Second

// renewAfter is how long from now the browser should wait before renewing rec's
// claims under a bound of maxAge. Never negative: claims already past their
// deadline renew now.
//
// The deadline is whichever claim clock falls first — maxAge after the claims
// were asserted, or the provider's own ClaimsExpireAt — and the slack scales
// with the window between assertion and deadline (see renewSlackFor), so a
// provider whose access tokens live shorter than the flat slack still gets a
// positive schedule instead of "renew now", forever.
func renewAfter(rec SessionRecord, maxAge time.Duration, now time.Time) time.Duration {
	asserted := rec.ClaimsAssertedAt()
	deadline := asserted.Add(maxAge)
	if !rec.ClaimsExpireAt.IsZero() && rec.ClaimsExpireAt.Before(deadline) {
		deadline = rec.ClaimsExpireAt
	}
	d := deadline.Add(-renewSlackFor(deadline.Sub(asserted))).Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// renewSlackFor is renewSlack, or a third of the window when that is smaller.
//
// A flat 90 seconds is wrong at the bottom of the range: max_claim_age goes
// down to a minute, and a provider may issue a sixty-second access token, so
// window - 90s would be negative and every schedule — including the one issued
// right after a successful renewal — would say "renew now". A third keeps the
// renewal landing with two thirds of the window still to run.
func renewSlackFor(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	if third := window / 3; third < renewSlack {
		return third
	}
	return renewSlack
}

// BrowserRenewIn reports how long the browser holding session id should wait
// before re-asserting its claims through /auth/renew, and whether it should on
// a timer at all.
//
// It should not when the freshness bound is off — the claims never go stale —
// or when the hub holds a refresh token for the session. The server-side
// refresh is the first layer: EnsureFreshClaims redeems the token on the
// request that needs current claims, no browser involved. A timer on top of it
// would cost an IdP round trip per open tab per window and, wherever a browser
// blocks third-party cookies, raise a sign-in banner over a session the hub
// could renew by itself. The dashboard still renews reactively when that layer
// fails; see ClaimFreshnessError.Renewable.
//
// The stored row is read rather than the cached one: the cache holds no refresh
// token by design, and may be a moment behind a renewal another hub process
// just applied.
func (a *Authenticator) BrowserRenewIn(id string) (time.Duration, bool) {
	if !a.Enabled() || a.cfg.MaxClaimAge <= 0 || id == "" {
		return 0, false
	}
	rec, err := a.storedSession(id)
	if err != nil || rec.RefreshToken != "" {
		return 0, false
	}
	return renewAfter(rec, a.cfg.MaxClaimAge, a.now()), true
}

// SessionClock is what a browser is told about the clocks on its session, so
// it can act before they run out rather than meet them as a refused click.
type SessionClock struct {
	// ClaimAge is how old the session's claims are, and MaxClaimAge the bound
	// they are held to; zero MaxClaimAge means the bound is off.
	ClaimAge    time.Duration
	MaxClaimAge time.Duration

	// Renew reports whether the browser should re-assert the claims through
	// /auth/renew on a timer, and RenewIn when. See BrowserRenewIn.
	Renew   bool
	RenewIn time.Duration

	// ExpiresIn is what is left of the absolute lifetime, which no renewal
	// lifts. Meaningful when HasExpiry.
	ExpiresIn time.Duration
	HasExpiry bool
}

// SessionClock reports rec's clocks as of now, on this authenticator's clock.
func (a *Authenticator) SessionClock(rec SessionRecord) SessionClock {
	var c SessionClock
	if !a.Enabled() {
		return c
	}
	now := a.now()
	if a.cfg.MaxClaimAge > 0 {
		c.MaxClaimAge = a.cfg.MaxClaimAge
		c.ClaimAge = rec.ClaimAge(now)
	}
	c.RenewIn, c.Renew = a.BrowserRenewIn(rec.ID)
	if !rec.ExpiresAt.IsZero() {
		c.HasExpiry = true
		if left := rec.ExpiresAt.Sub(now); left > 0 {
			c.ExpiresIn = left
		}
	}
	return c
}

// BeginRenew starts a silent re-assertion of the caller's session's claims.
//
// Every response is a document that reports its verdict to the parent frame,
// failures included: a frame cannot surface an HTTP status, so a 401 here would
// be a renewal that hangs until the dashboard's own timeout rather than one
// that fails in milliseconds.
func (a *Authenticator) BeginRenew(w http.ResponseWriter, r *http.Request) RenewOutcome {
	if !a.Enabled() {
		return a.renewResult(w, renewVerdict{outcome: RenewDisabled})
	}
	// Looked up without advancing the idle clock: a renewal is the dashboard
	// keeping its authority current, not the user doing anything, and counting
	// it as activity would keep an unattended tab's session alive forever.
	rec, ok := a.peekSession(r)
	if !ok {
		return a.renewResult(w, renewVerdict{outcome: RenewNoSession})
	}
	disc, err := a.discover(r.Context())
	if err != nil {
		return a.renewResult(w, renewVerdict{outcome: RenewDiscoveryFailed, detail: err.Error()})
	}
	p, state, err := a.newPendingLogin(pendingLogin{
		silent:      true,
		sessionHash: rec.ID,
		subject:     rec.Identity.Sub,
	})
	if err != nil {
		return a.renewResult(w, renewVerdict{outcome: RenewStateError, detail: err.Error()})
	}
	extra := url.Values{}
	// The whole point: answer from your own session or refuse, but show this
	// person nothing — there is no room for it and nobody is looking.
	extra.Set("prompt", "none")
	// Raises the hit rate where the browser holds several accounts: without
	// it "which one?" is an interaction, and under prompt=none a refusal.
	extra.Set("login_hint", renewLoginHint(rec.Identity))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, a.authorizeURL(disc, state, p, extra), http.StatusFound)
	return RenewPending
}

// renewLoginHint picks login_hint: the email, which providers match on, and the
// subject where there is none.
func renewLoginHint(id Identity) string {
	if id.Email != "" {
		return id.Email
	}
	return id.Sub
}

// completeRenew finishes a silent flow: it checks what the provider said,
// applies the re-asserted claims to the session that asked, and answers the
// frame.
func (a *Authenticator) completeRenew(w http.ResponseWriter, r *http.Request, p *pendingLogin, q url.Values) RenewOutcome {
	if e := q.Get("error"); e != "" {
		if isInteractionRequired(e) {
			return a.renewResult(w, renewVerdict{outcome: RenewInteractionRequired, detail: e})
		}
		return a.renewResult(w, renewVerdict{outcome: RenewIdPError,
			detail: strings.TrimSpace(e + " " + q.Get("error_description"))})
	}
	code := q.Get("code")
	if code == "" {
		return a.renewResult(w, renewVerdict{outcome: RenewInvalidState,
			detail: "the provider returned neither an authorization code nor an error"})
	}

	ctx, cancel := context.WithTimeout(r.Context(), httpTimeout)
	defer cancel()
	tok, err := a.exchangeCode(ctx, code, p.verifier)
	if err != nil {
		if isPreflightFailure(err) {
			return a.renewResult(w, renewVerdict{outcome: RenewDiscoveryFailed, detail: err.Error()})
		}
		return a.renewResult(w, renewVerdict{outcome: RenewExchangeFailed, detail: err.Error()})
	}
	id, err := a.verifyIDToken(ctx, tok.IDToken, p.nonce)
	if err != nil {
		if isPreflightFailure(err) {
			return a.renewResult(w, renewVerdict{outcome: RenewDiscoveryFailed, detail: err.Error()})
		}
		return a.renewResult(w, renewVerdict{outcome: RenewTokenInvalid, detail: err.Error()})
	}
	// Bound to the subject captured when the renewal began, from a session
	// this browser proved it held. The provider answering for anyone else is a
	// user who switched accounts in another tab, or somebody having signed the
	// browser into their own account at the provider; either way the right move
	// is to change nothing.
	if id.Sub != p.subject {
		a.noteRenewalMismatch(r, p.sessionHash, p.subject)
		return a.renewResult(w, renewVerdict{outcome: RenewSubjectMismatch})
	}
	return a.applyRenewedClaims(ctx, w, r, p, id, tok)
}

// applyRenewedClaims writes the re-asserted claims to the session and answers
// the frame.
//
// Under the cross-process refresh lock, like every other write of a session's
// claims: on a hub cluster another process may be redeeming this session's
// refresh token at the same moment, and two writers racing to the same row
// would leave whichever landed last deciding the claims — possibly the older
// answer.
func (a *Authenticator) applyRenewedClaims(ctx context.Context, w http.ResponseWriter, r *http.Request, p *pendingLogin, id *Identity, tok *tokenResponse) RenewOutcome {
	release, err := a.lockRefresh(ctx, p.sessionHash)
	if err != nil {
		return a.renewResult(w, renewVerdict{outcome: RenewStoreError, detail: err.Error()})
	}
	defer release()

	rec, err := a.storedSession(p.sessionHash)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			// Ended between the redirect and the answer. From the browser's
			// side there is nothing left to renew.
			return a.renewResult(w, renewVerdict{outcome: RenewNoSession})
		}
		return a.renewResult(w, renewVerdict{outcome: RenewStoreError, detail: err.Error()})
	}
	now := a.now()
	// A session that lapsed during the round trip stays lapsed: refreshing
	// the claims of a dead row would be harmless, and reporting it as renewed
	// would send the dashboard on to a 401 it did not expect.
	if rec.Expired(now) || rec.Idle(now, a.cfg.IdleTimeout) {
		return a.renewResult(w, renewVerdict{outcome: RenewNoSession})
	}
	// Re-checked against the row rather than trusted from the pending record:
	// authority is about to be written for the identity in front of us.
	if rec.Identity.Sub != id.Sub {
		a.noteRenewalMismatch(r, p.sessionHash, rec.Identity.Sub)
		return a.renewResult(w, renewVerdict{outcome: RenewSubjectMismatch})
	}

	res := RefreshResult{
		// Kept unless the provider handed back a new one. This grant is a
		// separate authorization, and a provider that issued no refresh token
		// here has said nothing about the one the hub already holds.
		RefreshToken: rec.RefreshToken,
		// Not stamped. RefreshCheckedAt bounds IdP-side revocation and is
		// earned by redeeming the refresh token; a renewal proves the *user*
		// is still signed in at the provider, which is a different question,
		// and advancing the wrong clock here would push the background
		// revalidation of a possibly-revoked grant out on every renewal.
		CheckedAt:      rec.RefreshCheckedAt,
		ClaimsAsserted: true,
		Groups:         id.Groups,
		Roles:          id.Roles,
		ClaimsAsOf:     now,
		ClaimsExpireAt: accessTokenExpiry(tok, now),
	}
	if tok.RefreshToken != "" {
		res.RefreshToken = tok.RefreshToken
	}
	if err := a.store.ApplyRefresh(rec.ID, res); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return a.renewResult(w, renewVerdict{outcome: RenewNoSession})
		}
		return a.renewResult(w, renewVerdict{outcome: RenewStoreError, detail: err.Error()})
	}
	// Evicted after the write, here and on every other hub process, for the
	// same reason revalidate does it last: a request landing in the gap would
	// refill the cache from the row being replaced.
	a.invalidateCache(rec.ID)
	// Audited on exactly the terms a server-side refresh is, so a narrowing
	// that arrives this way is as visible in the trail as one that arrives on
	// the interval — with via saying which way it came.
	a.noteClaimAssertion(rec, id, now, viaBrowserRenewal)

	v := renewVerdict{outcome: RenewOK, changed: !sameClaimSet(rec.Identity, *id)}
	v.renewIn, v.schedule = a.BrowserRenewIn(rec.ID)
	return a.renewResult(w, v)
}

// viaBrowserRenewal is the `via` an audit row carries when what it records
// arrived through a silent renewal rather than the hub's own refresh.
const viaBrowserRenewal = "browser_renewal"

// noteRenewalMismatch audits a renewal the provider answered for a different
// subject than the session's.
//
// Rare, and worth a row precisely because it is: the benign reading is a user
// who switched accounts at the provider in another tab, and the other is a
// browser signed into somebody else's account — at the provider, where cloop
// cannot see it — in the hope that its renewal adopts that account's authority.
// It does not; this row is how a reviewer finds out somebody tried. Neither
// identity's claims are recorded, only the session's own subject.
func (a *Authenticator) noteRenewalMismatch(r *http.Request, sessionHash, subject string) {
	a.audit(SessionAudit{
		Event:     AuditSessionRenewalMismatch,
		SessionID: sessionHash,
		Subject:   subject,
		Actor:     "idp",
		Reason:    string(RenewSubjectMismatch),
		IP:        RequestIP(r),
		UserAgent: truncate(userAgent(r), 300),
		At:        a.now(),
		Via:       viaBrowserRenewal,
	})
}

// sameClaimSet reports whether two identities carry the same groups and roles,
// compared the way they are consumed: case-insensitively, a leading path
// separator ignored, order and duplicates irrelevant.
func sameClaimSet(a, b Identity) bool {
	set := func(id Identity) map[string]struct{} {
		out := make(map[string]struct{}, len(id.Groups)+len(id.Roles))
		for _, v := range id.Groups {
			out["g:"+normalizeClaim(v)] = struct{}{}
		}
		for _, v := range id.Roles {
			out["r:"+normalizeClaim(v)] = struct{}{}
		}
		return out
	}
	x, y := set(a), set(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if _, ok := y[k]; !ok {
			return false
		}
	}
	return true
}

// isInteractionRequired reports whether an OAuth error from a prompt=none
// request means "I would have had to ask the user": the four codes OpenID
// Connect Core §3.1.2.6 defines for exactly that.
func isInteractionRequired(code string) bool {
	switch code {
	case "login_required", "interaction_required", "consent_required", "account_selection_required":
		return true
	}
	return false
}

// FrameOrigins returns the identity provider origins a renewal frame navigates
// to, for the hub's Content-Security-Policy frame-src.
//
// A frame's navigations, redirects included, are checked against the *framing*
// document's frame-src, with hosts compared exactly — so under a bare
// frame-src 'self' the browser blocks the hop from /auth/renew to the provider
// and the renewal fails in a way that looks like the provider timing out.
//
// The issuer and the authorization endpoint are both reported, since a provider
// may serve them from different hosts. The latter is known once discovery has
// run, which the hub does at startup. Lock-free: the hub reads this for every
// response it sends.
func (a *Authenticator) FrameOrigins() []string {
	if !a.Enabled() {
		return nil
	}
	if p := a.frameOrigins.Load(); p != nil {
		return *p
	}
	return nil
}

// noteFrameOrigins recomputes FrameOrigins from the configured issuer and, when
// discovery has resolved, its authorization endpoint.
func (a *Authenticator) noteFrameOrigins(disc *discoveryDoc) {
	out := make([]string, 0, 2)
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return
		}
		origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
		for _, have := range out {
			if have == origin {
				return
			}
		}
		out = append(out, origin)
	}
	add(a.cfg.Issuer)
	if disc != nil {
		add(disc.AuthorizationEndpoint)
	}
	a.frameOrigins.Store(&out)
}

// ── the document the frame loads ────────────────────────────────────────────

// renewVerdict is everything the frame tells the dashboard.
type renewVerdict struct {
	outcome RenewOutcome
	detail  string

	// renewIn is when to renew next, meaningful only with schedule: whether the
	// browser should keep renewing on a timer at all (BrowserRenewIn). Carried
	// in the answer so the dashboard re-arms without asking /api/me, whose
	// request would advance the idle clock that a renewal must leave alone.
	renewIn  time.Duration
	schedule bool

	// changed reports that the provider released different groups or roles
	// than the session held, so the dashboard re-reads its permissions.
	changed bool
}

// renewMessageType is the discriminator on the posted message, so the
// dashboard's listener can ignore everything else that posts to a window.
const renewMessageType = "cloop.oidc.renew"

// renewResult writes the document the frame loads and reports the verdict to
// Config.RenewObserver.
//
// Always 200. The status of a framed document is invisible to its parent, so
// an honest 4xx would tell the dashboard nothing and would be logged by every
// proxy as a failure on a path doing exactly what it is for.
func (a *Authenticator) renewResult(w http.ResponseWriter, v renewVerdict) RenewOutcome {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Alongside the hub's frame-ancestors 'self': only a document already on
	// this origin may frame the one page whose purpose is to talk to its parent.
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, renewResultHTML(v))
	if a != nil && a.cfg.RenewObserver != nil && v.outcome.Recorded() {
		a.cfg.RenewObserver(v.outcome)
	}
	return v.outcome
}

// renewResultHTML renders the result document.
//
// The message is addressed to "/" — the sending document's own origin — rather
// than "*" or a configured URL. The browser then delivers it only to a parent
// on exactly this origin: a page elsewhere that framed this document learns
// nothing, not even that somebody is signed in here, and no spelling of the
// redirect URL (an explicit :443, a different case) can make the hub address a
// message to an origin the browser does not consider its own.
//
// Every interpolated value is escaped, the provider's error text above all: a
// provider may put anything in error_description.
func renewResultHTML(v renewVerdict) string {
	var msg strings.Builder
	msg.WriteString("{type: " + jsString(renewMessageType))
	msg.WriteString(", outcome: " + jsString(string(v.outcome)))
	msg.WriteString(", detail: " + jsString(truncate(v.detail, 300)))
	if v.schedule {
		msg.WriteString(", renew_in: " + strconv.FormatInt(int64(v.renewIn/time.Second), 10))
	}
	msg.WriteString(", changed: " + strconv.FormatBool(v.changed) + "}")
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Renewing sign-in…</title></head>
<body>
<p>` + html.EscapeString(renewSummary(v.outcome)) + `</p>
<script>
try { parent.postMessage(` + msg.String() + `, "/"); } catch (e) {}
</script>
</body></html>
`
}

// renewSummary is the line a human sees if they look at the document directly,
// which happens when an operator opens /auth/renew by hand to check the flow.
func renewSummary(outcome RenewOutcome) string {
	switch outcome {
	case RenewOK:
		return "Sign-in renewed."
	case RenewInteractionRequired, RenewNoSession:
		return "Your sign-in needs renewing. Please sign in again."
	case RenewDisabled:
		return "This hub does not use single sign-on."
	default:
		return "Could not renew the sign-in (" + string(outcome) + ")."
	}
}
