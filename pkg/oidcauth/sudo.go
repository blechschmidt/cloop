package oidcauth

// Sudo mode: a privileged action needs a recent interactive sign-in, not just a
// live cookie (Task 20448).
//
// A session cookie carries its owner's authority for its whole absolute
// lifetime, and silent renewal (renew.go, prompt=none) keeps it alive without
// the person ever authenticating again. So a cookie lifted from a laptop is, for
// up to a day, everything its owner may do. Approving a terminal's code was the
// one action that asked for more (device.go): a sign-in no older than
// device_approval_max_age_minutes, held to the provider's auth_time. This file
// generalises that rule to every privileged action the hub's route table marks
// (pkg/ui/routes.go), the way a forge's sudo mode does.
//
// # What "recent" is measured from
//
// SessionRecord.AuthenticatedAt: the last time the person behind the session
// proved who they are to the identity provider, as far as the hub can know it.
//
//	the id_token's auth_time    when the provider reports it — the provider's
//	                            own account of when it last asked
//	the callback's own time     when it does not, but the hub itself started
//	                            the sign-in with prompt=login: the provider
//	                            was told to ask, so the callback is the sign-in
//	                            (Entra ID without the auth_time optional claim)
//	nothing                     an ordinary sign-in with no auth_time: the
//	                            provider may have answered from a session of
//	                            its own days old, so it proves nothing recent
//
// A terminal session counts from the sign-in behind its approval: an approval
// from a browser whose own sign-in is not recent is itself a prompt=login
// sign-in (device.go, deviceReauth), and a silent one leaves the terminal no
// fresher than that browser. Silent renewal and the server-side refresh never
// move the time — neither is the person doing anything — and it lives on the
// durable session row, so every hub member reads the same answer.
//
// # The confirm-it's-you sign-in
//
// A stale session's privileged request is refused with a typed 401
// (pkg/ui), and the dashboard answers it by sending the person to
// LoginPath?reauth=… — a sign-in like any other, except that it asks for
// prompt=login&max_age=0 and the callback holds the provider to it: a token
// whose auth_time predates the request did not ask, and is refused rather than
// believed. It must be the same person; another account signing in is refused
// too.
//
// It creates a new session, with a new cookie, rather than freshening the one
// that asked. The fresh credential therefore lands in the browser that did the
// authenticating: somebody holding a stolen cookie who phishes its owner into
// completing a confirm-it's-you sign-in they started gains nothing, since the
// fresh session is set in the owner's browser and the stolen one stays as stale
// as it was. The session that asked is left to its own clocks: ending it would
// close the asking tab's live streams with a "signed out" notice at the very
// moment the person proved they are there.

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultSudoMaxAge is used when Config.SudoMaxAge is zero: a privileged
	// action needs a sign-in from the last two hours, the window device
	// approval has used since Task 20412 and the one forges use for sudo mode.
	DefaultSudoMaxAge = 2 * time.Hour

	// MaxSudoMaxAge is the longest window Config.SudoMaxAge is held to. A day,
	// the default session lifetime: past it the window no longer asks
	// anything of a session that its expiry does not.
	MaxSudoMaxAge = 24 * time.Hour

	// ReauthParam is LoginPath's query parameter asking for a confirm-it's-you
	// sign-in. Any non-empty value asks; ReauthWindow additionally has the
	// callback answer with a document that tells the dashboard tab that opened
	// the window, instead of landing on a dashboard page of its own.
	ReauthParam  = "reauth"
	ReauthWindow = "window"

	// ReauthNonceParam carries the dashboard dialog's nonce on a window's
	// sign-in, echoed in the result document's message: the dialog replays
	// its refused request only on a result that names its own nonce, so a
	// result some other sign-in produced in this browser — one somebody else
	// started and lured it through — replays nothing.
	ReauthNonceParam = "n"

	// ReauthChannel is the BroadcastChannel the result document posts on, and
	// ReauthMessageType the type its message carries. The dashboard tab whose
	// privileged request was refused listens on it.
	ReauthChannel     = "cloop-reauth"
	ReauthMessageType = "cloop.oidc.reauth"
)

// ReauthOutcome is a session.reauth row's outcome and the label of
// cloop_session_reauth_total. A closed set.
type ReauthOutcome string

const (
	// ReauthGranted: a confirm-it's-you sign-in completed, and the fresh
	// session it created is recent.
	ReauthGranted ReauthOutcome = "granted"
	// ReauthRefused: a confirm-it's-you sign-in did not count — another
	// account, a provider that did not ask, or a provider error.
	ReauthRefused ReauthOutcome = "refused"
	// ReauthStaleRefused: a privileged request was refused because the
	// session's last interactive sign-in is older than the window.
	ReauthStaleRefused ReauthOutcome = "stale-refused"
)

// The reasons a refused confirm-it's-you sign-in carries.
const (
	ReauthReasonSubjectMismatch    = "subject_mismatch"
	ReauthReasonNotReauthenticated = "not_reauthenticated"
)

// ReauthAuditDetail is what a session.reauth row says beyond the session.
type ReauthAuditDetail struct {
	Outcome ReauthOutcome
	// MaxAge is the window in force.
	MaxAge time.Duration
	// AuthenticatedAt is the session's last interactive sign-in as recorded:
	// for a refused request, what missed the window (zero: none on record).
	AuthenticatedAt time.Time
	// Method and Path name the refused request.
	Method string
	Path   string
	// Replaces is, for a granted sign-in, the session that asked for it.
	Replaces string
	// Suppressed counts refusals not written since the last row that was
	// (pkg/ui rate-limits stale-refused rows).
	Suppressed int
}

// normalizeSudoConfig fills in and clamps the window: zero is the default, a
// negative value is the explicit "never ask", and anything longer than
// MaxSudoMaxAge is held to it.
func normalizeSudoConfig(cfg *Config) {
	switch {
	case cfg.SudoMaxAge == 0:
		cfg.SudoMaxAge = DefaultSudoMaxAge
	case cfg.SudoMaxAge < 0:
		cfg.SudoMaxAge = -1
	case cfg.SudoMaxAge > MaxSudoMaxAge:
		cfg.SudoMaxAge = MaxSudoMaxAge
	}
}

// SudoMaxAge is how recent a session's last interactive sign-in must be for a
// privileged action (zero or less: never asked).
func (a *Authenticator) SudoMaxAge() time.Duration {
	if a == nil {
		return 0
	}
	return a.cfg.SudoMaxAge
}

// interactiveAt is the AuthenticatedAt a session created now records: the
// provider's auth_time when it reported a usable one, else now when the hub
// itself asked the provider to make the person sign in (prompted), else zero.
//
// An auth_time a little ahead of the hub's clock — the provider's runs fast —
// is read as now, so a fast clock never buys a session more than the window.
// One further ahead than the clock-skew allowance is not believed at all: it
// is either a broken clock or a broken token, and neither proves a sign-in.
func (a *Authenticator) interactiveAt(authTime time.Time, prompted bool, now time.Time) time.Time {
	if !authTime.IsZero() && !authTime.After(now.Add(a.clockSkew())) {
		if authTime.After(now) {
			return now
		}
		return authTime
	}
	if prompted {
		return now
	}
	return time.Time{}
}

// SignInRecency is how a session stands against the sudo window.
type SignInRecency struct {
	// Required is false when the window is off; the rest is then unset.
	Required bool
	// Recent reports whether a privileged action may go ahead.
	Recent bool
	// At is the session's last interactive sign-in, zero when none is known.
	At time.Time
	// MaxAge is the window, and Remaining how much of it is left (zero once
	// it has run out).
	MaxAge    time.Duration
	Remaining time.Duration
}

// RecentSignIn measures rec against the sudo window. A session whose last
// interactive sign-in is unknown is not recent; one exactly MaxAge old is not
// either.
func (a *Authenticator) RecentSignIn(rec SessionRecord) SignInRecency {
	limit := a.SudoMaxAge()
	if !a.Enabled() || limit <= 0 {
		return SignInRecency{Recent: true}
	}
	out := SignInRecency{Required: true, At: rec.AuthenticatedAt, MaxAge: limit}
	if rec.AuthenticatedAt.IsZero() {
		return out
	}
	left := rec.AuthenticatedAt.Add(limit).Sub(a.now())
	if left > 0 {
		out.Recent, out.Remaining = true, left
	}
	return out
}

// NoteStaleRefused records a privileged request refused for want of a recent
// sign-in. The caller decides whether this refusal is written at all (it
// rate-limits them) and says how many were not.
func (a *Authenticator) NoteStaleRefused(rec SessionRecord, r *http.Request, st SignInRecency, suppressed int) {
	if a == nil {
		return
	}
	ev := SessionAudit{
		Event:     AuditSessionReauth,
		SessionID: rec.ID,
		Subject:   rec.Identity.Sub,
		Email:     rec.Identity.Email,
		Actor:     rec.Identity.OwnerKey(),
		At:        a.now(),
		Kind:      rec.Kind,
		Client:    rec.Client,
		Reauth: &ReauthAuditDetail{
			Outcome:         ReauthStaleRefused,
			MaxAge:          st.MaxAge,
			AuthenticatedAt: st.At,
			Suppressed:      suppressed,
		},
	}
	if r != nil {
		ev.IP = RequestIP(r)
		ev.UserAgent = truncate(userAgent(r), 300)
		ev.Reauth.Method = r.Method
		ev.Reauth.Path = truncate(r.URL.Path, 300)
	}
	a.audit(ev)
}

// ReauthURL is where a browser goes to confirm it is the person behind its
// session: the sign-in, asking for prompt=login. window has the callback
// answer with the result document; otherwise the sign-in lands on returnTo, a
// dashboard path, as any sign-in does.
func ReauthURL(returnTo string, window bool) string {
	q := url.Values{}
	if window {
		// The dialog adds its nonce (ReauthNonceParam).
		q.Set(ReauthParam, ReauthWindow)
	} else {
		q.Set(ReauthParam, "1")
		if p := safeReturnPath(returnTo); p != "" {
			q.Set("return", p)
		}
	}
	return LoginPath + "?" + q.Encode()
}

// reauthRefusal decides whether the provider's answer to a confirm-it's-you
// sign-in counts, returning the reason it does not, or "".
//
// Two ways it does not. Another account signed in: a fresh session for them
// would be a sign-in the dashboard tab did not ask for, in a browser that then
// holds two people's cookies in turn. And the provider did not ask: its
// auth_time predates the request, so it answered from a session of its own,
// prompt=login notwithstanding — the case device.go refuses for the same
// reason. A provider that reports no auth_time is trusted to have asked; the
// callback's own time stands for the sign-in then.
func (a *Authenticator) reauthRefusal(p *pendingLogin, id *Identity) string {
	if p.subject != "" && id.Sub != p.subject {
		return ReauthReasonSubjectMismatch
	}
	if !id.AuthTime.IsZero() && id.AuthTime.Before(p.created.Add(-a.clockSkew())) {
		return ReauthReasonNotReauthenticated
	}
	return ""
}

// auditReauth records a confirm-it's-you sign-in's verdict, filed under the
// session it created, or — when it created none — the session that asked.
func (a *Authenticator) auditReauth(p *pendingLogin, r *http.Request, id Identity, outcome ReauthOutcome, reason, sessionID string) {
	detail := &ReauthAuditDetail{Outcome: outcome, MaxAge: a.SudoMaxAge()}
	if outcome == ReauthGranted {
		detail.Replaces = p.sessionHash
	}
	if sessionID == "" {
		sessionID = p.sessionHash
	}
	a.audit(SessionAudit{
		Event:     AuditSessionReauth,
		SessionID: sessionID,
		Subject:   id.Sub,
		Email:     id.Email,
		Actor:     id.OwnerKey(),
		Reason:    reason,
		IP:        RequestIP(r),
		UserAgent: truncate(userAgent(r), 300),
		At:        a.now(),
		Kind:      SessionKindBrowser,
		Reauth:    detail,
	})
}

// reauthMessages are the sentences a refused confirm-it's-you sign-in shows.
var reauthMessages = map[string]string{
	ReauthReasonSubjectMismatch: "You signed in at the identity provider as a different account from the one " +
		"this dashboard session belongs to. Nothing changed: sign in as yourself to confirm it is you.",
	ReauthReasonNotReauthenticated: "The identity provider did not ask you to sign in again (its token reports " +
		"an earlier sign-in), so this does not confirm it is you. Nothing changed: try again, and sign in when " +
		"the provider asks.",
}

// reauthReasonMessage is the sentence for a refusal reason.
func reauthReasonMessage(reason string) string {
	if m, ok := reauthMessages[reason]; ok {
		return m
	}
	return "The identity provider did not complete the sign-in (" + reason + "). Nothing changed: try again."
}

// reauthNonce keeps a dialog nonce that is plainly one — 16 to 64 letters,
// digits, '-' or '_' — and drops anything else, so the value echoed into the
// result document is never more than a token.
func reauthNonce(v string) string {
	if len(v) < 16 || len(v) > 64 {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return ""
		}
	}
	return v
}

// reauthFailure answers a confirm-it's-you sign-in that did not count: the
// result document in a window — the dashboard tab waiting on it shows the
// message — and an error page in a tab.
func (a *Authenticator) reauthFailure(w http.ResponseWriter, p *pendingLogin, status int, msg string, err error) {
	if p.window {
		reauthResult(w, status, ReauthRefused, msg, p.windowNonce)
		return
	}
	a.errorPage(w, status, msg, err)
}

// reauthResult answers a confirm-it's-you sign-in started from a window
// (ReauthWindow): a document that tells the dashboard tab which opened it, on
// ReauthChannel and to its opener, and closes itself when it can. Its message
// is data in an attribute, read by the sign-in script — never script of its
// own (script.go).
func reauthResult(w http.ResponseWriter, status int, outcome ReauthOutcome, message, nonce string) {
	payload, _ := json.Marshal(map[string]string{
		"type": ReauthMessageType, "outcome": string(outcome), "message": message, "nonce": nonce,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!DOCTYPE html>
<html lang="en" data-reauth="`+html.EscapeString(string(payload))+`"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm it's you</title>
<style>body{font:14px system-ui,sans-serif;margin:3rem auto;max-width:28rem;padding:0 1rem;text-align:center;color:#333}</style>
</head><body>
<p>`+html.EscapeString(message)+`</p>
<p>You can close this window and return to the dashboard.</p>
<script src="`+ScriptPath+`"></script>
</body></html>
`)
}
