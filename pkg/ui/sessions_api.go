package ui

// Session lifecycle: durable storage, the admin surface, and the audit sink
// (Task 20176).
//
//	POST   /api/session/logout-all   end my other sessions (self-service)
//	GET    /api/sessions             list every session      (session.admin)
//	DELETE /api/sessions/{id}        terminate one           (session.admin)
//
// # Why self-service logout is ungated
//
// Ending one's own sessions can never be an escalation, and the case it exists
// for — "I left a session on a machine I no longer control" — is one where
// requiring an operator to act first is exactly the wrong delay. It is
// authenticated (the auth middleware has already run) but carries no
// permission, and the handler scopes the deletion to the caller's own subject
// rather than accepting an id, so there is no parameter to tamper with.
//
// # Why the admin list is not `user.manage`
//
// Terminating a session is containment, not administration: it changes nobody's
// standing rights. Splitting it out means the on-call operator who needs to
// kill a session at 3am does not also need the ability to rewrite role
// bindings. See authz.PermSessionAdmin.
//
// # What a session id is
//
// Every id on this wire is the SHA-256 of a session cookie, never the cookie.
// It is safe to list, log, and put in a URL for the same reason a username is:
// possessing it does not let anyone authenticate. Nothing here can return a
// value a caller could present as a credential — not the cookie, and not the
// refresh token, which never leaves the store unsealed except into the token
// endpoint request that redeems it.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ---------------------------------------------------------------------------
// store lifecycle
// ---------------------------------------------------------------------------

// sessionStoreState holds the durable session store and the database handle it
// was built on. The handle is retained solely so Shutdown can close it.
type sessionStoreState struct {
	mu    sync.Mutex
	store *sessionstore.Store
	db    *statedb.DB
}

// OpenSessionStore returns a durable session store backed by the hub's own
// control-plane database, opening it on first call.
//
// The error return is a *warning*, not a failure: a caller that gets one
// receives a nil store and is expected to fall back to process-local sessions.
// Refusing to start a dashboard because its session table is unavailable would
// trade a degraded property (sessions do not survive a restart) for a total
// outage, and that is not a trade an authentication layer should make on the
// operator's behalf.
//
// The database is the hub's, never a managed project's — the same rule as API
// tokens and executor bindings, and for a sharper reason here: a tenant able to
// write to the file holding the sessions table could insert a row for any
// subject and authenticate as them.
func (s *Server) OpenSessionStore() (oidcauth.SessionStore, error) {
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	if s.sessions.store != nil {
		return s.sessions.store, nil
	}
	dbPath := state.DBPath(s.WorkDir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("the control plane has no state database at %s yet", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	store, err := sessionstore.New(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.sessions.db, s.sessions.store = db, store
	return store, nil
}

// SessionStoreSealsRefreshTokens reports whether the durable store has an
// encryption key, and therefore whether IdP-side revocation is armed.
func (s *Server) SessionStoreSealsRefreshTokens() bool {
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	return s.sessions.store.Available()
}

// sessionStoreDurable reports whether sessions survive a restart.
func (s *Server) sessionStoreDurable() bool {
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	return s.sessions.store != nil
}

// closeSessionStore releases the session database handle.
func (s *Server) closeSessionStore() {
	s.sessions.mu.Lock()
	db := s.sessions.db
	s.sessions.db, s.sessions.store = nil, nil
	s.sessions.mu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}

// ---------------------------------------------------------------------------
// audit sink
// ---------------------------------------------------------------------------

// SessionAuditSink returns the callback pkg/oidcauth uses to record session
// lifecycle events in the hash-chained trail.
//
// Best-effort, matching auditTokenEvent: a wedged journal must not turn signing
// in — or being signed out — into an error path. Nothing passed through here
// can carry credential material: SessionAudit has no field a cookie or a
// refresh token could be written to, and the session id it does carry is a
// digest.
func (s *Server) SessionAuditSink() func(oidcauth.SessionAudit) {
	return func(ev oidcauth.SessionAudit) {
		payload := map[string]any{
			"subject": ev.Subject,
			"ip":      ev.IP,
		}
		if ev.Email != "" {
			payload["email"] = ev.Email
		}
		if ev.Reason != "" {
			payload["reason"] = ev.Reason
		}
		if ev.UserAgent != "" {
			payload["user_agent"] = ev.UserAgent
		}
		actor := ev.Actor
		if actor == "" {
			actor = "system"
		}
		log, err := eventlog.Open(s.WorkDir)
		if err != nil {
			if !errors.Is(err, eventlog.ErrNoProject) {
				s.log().Warn(logger.EventAuthz, 0, "session audit: open event log",
					map[string]interface{}{"error": err.Error()})
			}
			return
		}
		defer log.Close()
		if err := log.Append(&eventlog.AuditEvent{
			Timestamp:  ev.At,
			Actor:      actor,
			EventType:  ev.Event,
			EntityType: "session",
			EntityID:   ev.SessionID,
			Payload:    statedb.MarshalAuditPayload(payload),
		}); err != nil {
			s.log().Warn(logger.EventAuthz, 0, "session audit: append",
				map[string]interface{}{"error": err.Error(), "event": ev.Event})
		}
	}
}

// ---------------------------------------------------------------------------
// janitor
// ---------------------------------------------------------------------------

// startSessionJanitor runs the expiry sweep and IdP revalidation for as long as
// ctx lives. A no-op when OIDC is off.
//
// Expiry is also enforced on every read (see oidcauth.SessionFromRequest), so
// a janitor that never starts costs storage hygiene and revocation latency —
// never authorization.
func (s *Server) startSessionJanitor(ctx context.Context) {
	if !s.oidcEnabled() {
		return
	}
	go s.OIDC.RunJanitor(ctx)
}

// ---------------------------------------------------------------------------
// wire types
// ---------------------------------------------------------------------------

// sessionView is one row of GET /api/sessions.
type sessionView struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	IP          string `json:"ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	IssuedAt    string `json:"issued_at,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`

	// IdleSeconds and ExpiresInSeconds are derived server-side so the panel
	// cannot disagree with the authentication path about how much life a
	// session has left.
	IdleSeconds      int64 `json:"idle_seconds"`
	ExpiresInSeconds int64 `json:"expires_in_seconds"`

	// IdPChecked is when the identity provider last confirmed this session,
	// empty when it never has. An operator auditing after a suspected account
	// compromise needs to distinguish "the IdP vouched for this five minutes
	// ago" from "nobody has asked since sign-in".
	IdPChecked string `json:"idp_checked_at,omitempty"`

	// Current marks the caller's own session so the panel can label it and
	// warn before terminating it.
	Current bool `json:"current"`
}

type sessionsListResponse struct {
	Sessions []sessionView `json:"sessions"`

	// Policy lets the panel state the rules rather than restate the numbers
	// from a config file the reader may not have.
	AbsoluteTTLSeconds int64 `json:"absolute_ttl_seconds"`
	IdleTimeoutSeconds int64 `json:"idle_timeout_seconds"`

	// Durable is false when sessions live only in this process, and
	// IdPRevocation false when no refresh token is retained. Both are
	// degradations an operator should see where they act on them, not only in
	// a startup line they scrolled past.
	Durable       bool `json:"durable"`
	IdPRevocation bool `json:"idp_revocation"`

	// Total is how many sessions exist, which differs from len(Sessions) only
	// when the response was capped. Reported rather than silently truncated:
	// a list that quietly drops rows reads as "these are all the sessions",
	// which is exactly the wrong thing to believe while hunting one.
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

// maxSessionsInResponse bounds one list response. A hub with a large signed-in
// population must not serialise its entire session table into a single JSON
// body — the rows are ordered most-recently-active first, so the cap keeps the
// useful end.
const maxSessionsInResponse = 500

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleSessionsList serves GET /api/sessions.
func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"OIDC authentication is not enabled on this server, so there are no sessions to manage"))
		return
	}
	rows, err := s.OIDC.ListSessions()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	now := time.Now()
	currentID := ""
	if rec, ok := s.OIDC.SessionFromRequest(r); ok {
		currentID = rec.ID
	}
	total := len(rows)
	truncated := false
	if len(rows) > maxSessionsInResponse {
		rows, truncated = rows[:maxSessionsInResponse], true
	}
	views := make([]sessionView, 0, len(rows))
	for _, rec := range rows {
		views = append(views, toSessionView(rec, now, currentID))
	}
	jsonOK(w, sessionsListResponse{
		Sessions:           views,
		AbsoluteTTLSeconds: int64(s.OIDC.SessionTTL().Seconds()),
		IdleTimeoutSeconds: int64(s.OIDC.IdleTimeout().Seconds()),
		Durable:            s.sessionStoreDurable(),
		IdPRevocation:      s.SessionStoreSealsRefreshTokens(),
		Total:              total,
		Truncated:          truncated,
	})
}

// handleSessionRevoke serves DELETE /api/sessions/{id}.
func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"OIDC authentication is not enabled on this server"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "a session id is required"))
		return
	}
	actor := s.grantFor(r).subjectLabel()
	ok, err := s.OIDC.RevokeSession(id, actor, "admin_revoked")
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	if !ok {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such session"))
		return
	}
	jsonOK(w, map[string]any{"ok": true, "id": id})
}

// handleLogoutAll serves POST /api/session/logout-all.
//
// Ends every session for the calling subject *except* the caller's own, so the
// operator issuing it is not immediately signed out of the page they issued it
// from — the frequent case is "I left a session somewhere", not "I want to be
// logged out here too", and the latter is one more click on Sign out.
func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"OIDC authentication is not enabled on this server"))
		return
	}
	rec, ok := s.OIDC.SessionFromRequest(r)
	if !ok {
		// Reached by a static-token or PAT client, which has no session and
		// therefore no subject whose sessions could be scoped to it. There is
		// deliberately no parameter to name one instead: that would turn this
		// ungated route into a way to sign out an arbitrary user.
		apierror.WriteError(w, apierror.New(apierror.CodeUnauthorized,
			"this endpoint ends your own sessions and requires a browser session"))
		return
	}
	n, err := s.OIDC.LogoutAll(rec.Identity.Sub, rec.ID, rec.Identity.OwnerKey())
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	jsonOK(w, map[string]any{"ok": true, "ended": n})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func toSessionView(rec oidcauth.SessionRecord, now time.Time, currentID string) sessionView {
	v := sessionView{
		ID:          rec.ID,
		Subject:     rec.Identity.Sub,
		Email:       rec.Identity.Email,
		DisplayName: rec.Identity.Name,
		IP:          rec.IP,
		UserAgent:   rec.UserAgent,
		IssuedAt:    formatSessionTime(rec.IssuedAt),
		LastSeen:    formatSessionTime(rec.LastSeen),
		ExpiresAt:   formatSessionTime(rec.ExpiresAt),
		IdPChecked:  formatSessionTime(rec.RefreshCheckedAt),
		Current:     currentID != "" && rec.ID == currentID,
	}
	if !rec.LastSeen.IsZero() {
		v.IdleSeconds = int64(now.Sub(rec.LastSeen).Seconds())
	}
	if !rec.ExpiresAt.IsZero() {
		v.ExpiresInSeconds = int64(rec.ExpiresAt.Sub(now).Seconds())
	}
	return v
}

func formatSessionTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
