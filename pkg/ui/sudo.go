package ui

// Sudo mode on the request path (Task 20448).
//
// pkg/oidcauth knows when the person behind a session last authenticated
// (SessionRecord.AuthenticatedAt) and how recent that has to be
// (ui.oidc.sudo_max_age_minutes). This file decides which requests ask, and
// answers the ones that fall short.
//
// # Which requests ask
//
// The route table says, beside each route's permission: routeSpec.Sudo. gate()
// enforces it after authorization — a caller who may not do something at all is
// told that, not asked to sign in for nothing — and before the handler, so a
// handler cannot forget it. TestPrivilegedRoutesAskForARecentSignIn fails when a
// route whose permission authz.RequiresRecentSignIn names neither asks nor sits
// on its exempt list with a reason. Two routes ask only sometimes — granting a
// project membership at maintainer, ending somebody else's session — and their
// handlers ask through requireSudo once they know; sudoHandler marks them, and
// TestSudoHandlerRoutesAskInTheirHandler holds the handler to it.
//
// # Who is asked
//
// Sessions: a browser's cookie, a terminal's `cloop login` bearer. API tokens
// and the static token are not sessions — they carry their own lifecycle and
// nobody signs in behind them — so they are never asked, and neither is anything
// on a hub without single sign-on.
//
// # The answer
//
// 401 REAUTH_REQUIRED, never a bare 403: the caller may do this, and the session
// stays live; what falls short is how long ago its owner proved who they are.
// The body carries max_age_seconds and where to confirm, and the response
// carries X-Cloop-Reauth, which is what the dashboard keys its "Confirm it's
// you" dialog on — and not X-Cloop-Sign-In, which would send the tab through
// the identity provider on its own and lose the page. A terminal is told to run
// `cloop login`.

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// sudoRule is what a route asks of the session's last interactive sign-in.
type sudoRule uint8

const (
	// sudoNone asks nothing: any live session will do.
	sudoNone sudoRule = iota
	// sudoWrites asks on the route's unsafe methods; a read of the same
	// pattern stays open.
	sudoWrites
	// sudoAll asks on every method the route serves, reads included: for a
	// GET that is an action, like opening a sandbox terminal.
	sudoAll
	// sudoHandler leaves it to the handler, which asks through requireSudo
	// once it knows whether this request is the privileged case.
	sudoHandler
)

// reauthHeader marks a REAUTH_REQUIRED refusal, carrying the window in
// seconds, so a client can tell it from a session that ended without reading
// the body.
const reauthHeader = "X-Cloop-Reauth"

// sudoFor is what the route asks of a request with this method.
func (rs routeSpec) sudoFor(method string) sudoRule {
	if rs.Sudo == sudoWrites && safeMethod(method) {
		return sudoNone
	}
	return rs.Sudo
}

// validateSudo rejects a route whose sudo rule could not be enforced as
// declared.
func (rs routeSpec) validateSudo() error {
	if rs.Sudo == sudoNone || rs.Sudo == sudoHandler {
		// A handler that decides may sit on a public route: minting a glasses
		// link is self-service, and asks only of a session that is there.
		return nil
	}
	for _, m := range rs.methods() {
		if rs.permFor(m) == "public" {
			// The gate passes a public route before anybody is identified;
			// there is no session for it to ask about.
			return fmt.Errorf("route %q is public for %s and cannot ask for a recent sign-in", rs.Pattern, m)
		}
	}
	if rs.Sudo == sudoWrites {
		for _, m := range rs.methods() {
			if !safeMethod(m) {
				return nil
			}
		}
		return fmt.Errorf("route %q asks for a recent sign-in on writes but serves none (use sudoAll)", rs.Pattern)
	}
	return nil
}

// sudoGate enforces rs's sudo rule for r. It reports whether the request may
// go on; when it may not, the response is written.
func (s *Server) sudoGate(w http.ResponseWriter, r *http.Request, rs routeSpec) bool {
	switch rs.sudoFor(r.Method) {
	case sudoWrites, sudoAll:
		return s.requireSudo(w, r)
	}
	return true
}

// requireSudo asks the session behind r for a recent interactive sign-in. It
// reports whether the request may go on; when it may not, the 401 is written.
// The gate calls it for the routes that always ask, and the handlers of the
// routes that ask only sometimes call it themselves.
func (s *Server) requireSudo(w http.ResponseWriter, r *http.Request) bool {
	rec, st, asked, ended := s.sudoStanding(r)
	switch {
	case ended:
		// A session that ended in the moment since it was authenticated:
		// never read as the absence of one.
		setSignInHint(w)
		apierror.WriteError(w, apierror.New(apierror.CodeUnauthorized,
			"your session has ended. Sign in again."))
		return false
	case !asked || st.Recent:
		return true
	}
	s.refuseStaleSignIn(w, r, rec, st)
	return false
}

// sudoStanding is how the session behind r stands against the sudo window.
// asked is false when nothing asks it: no single sign-on, the window off, or a
// credential that is not a session (an API token, the static token). ended
// reports a session credential whose session no longer resolves.
func (s *Server) sudoStanding(r *http.Request) (rec oidcauth.SessionRecord, st oidcauth.SignInRecency, asked, ended bool) {
	if !s.oidcEnabled() || s.OIDC.SudoMaxAge() <= 0 {
		return rec, st, false, false
	}
	if tokenFromRequest(r) != nil || admittedByStaticToken(r) {
		// Not sessions: nobody signs in behind them.
		return rec, st, false, false
	}
	rec, ok := s.OIDC.SessionFromRequest(r)
	if !ok {
		return rec, st, false, presentsSessionCredential(r)
	}
	return rec, s.OIDC.RecentSignIn(rec), true, false
}

// refuseStaleSignIn answers a privileged request whose session last signed in
// too long ago, counts it, and records it — at most refusalAuditPerMinute rows
// a minute, the next one saying how many were not.
func (s *Server) refuseStaleSignIn(w http.ResponseWriter, r *http.Request, rec oidcauth.SessionRecord, st oidcauth.SignInRecency) {
	hubmetrics.SessionReauth.Inc(string(oidcauth.ReauthStaleRefused))
	if ok, suppressed := s.sudoRefusals.admit(time.Now()); ok {
		s.OIDC.NoteStaleRefused(rec, r, st, suppressed)
	}

	window := humanDuration(st.MaxAge)
	details := map[string]any{
		"max_age_seconds": int64(st.MaxAge / time.Second),
		"session_kind":    rec.KindName(),
	}
	if !st.At.IsZero() {
		details["signed_in_seconds_ago"] = int64(time.Since(st.At) / time.Second)
	}
	var msg string
	if rec.IsCLI() {
		msg = "this action needs a terminal session approved in the last " + window +
			", and this one is older: run `cloop login` again, then retry"
		details["remedy"] = "cloop login"
	} else {
		msg = "this action needs a sign-in from the last " + window + ": confirm it's you at the identity provider, then try again"
		details["reauth_url"] = oidcauth.ReauthURL("", true)
	}
	w.Header().Set(reauthHeader, strconv.FormatInt(int64(st.MaxAge/time.Second), 10))
	w.Header().Set("Cache-Control", "no-store")
	apierror.WriteError(w, apierror.New(apierror.CodeReauthRequired, msg).WithDetails(details))
}

// humanDuration renders a window in the largest whole unit that states it:
// "2 hours", "90 minutes", "1 minute".
func humanDuration(d time.Duration) string {
	unit := func(n int64, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.FormatInt(n, 10) + " " + one + "s"
	}
	if d >= time.Hour && d%time.Hour == 0 {
		return unit(int64(d/time.Hour), "hour")
	}
	if m := int64(d / time.Minute); m >= 1 {
		return unit(m, "minute")
	}
	return unit(int64(d/time.Second), "second")
}
