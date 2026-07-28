package ui

// OIDC single sign-on and per-user project scoping for the web dashboard
// (Task 20152). Everything in this file is inert unless Server.OIDC is set,
// which only happens when ui.oidc.enabled is true in .cloop/config.yaml —
// with OIDC disabled the dashboard behaves exactly as before.

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// oidcEnabled reports whether OIDC authentication is active on this server.
func (s *Server) oidcEnabled() bool {
	return s.OIDC.Enabled()
}

// sessionIdentity returns the authenticated dashboard user for the request,
// or nil when OIDC is disabled, the request has no session, or it
// authenticated via the static bearer token instead.
func (s *Server) sessionIdentity(r *http.Request) *oidcauth.Identity {
	return s.OIDC.IdentityFromRequest(r)
}

// oidcGate is the authentication path used by authMiddleware when OIDC is
// enabled. Order of acceptance:
//
//  1. /auth/* (the login machinery itself) and static assets pass through.
//  2. A valid session cookie passes.
//  3. The static bearer token (--token / CLOOP_UI_TOKEN) passes — API
//     automation keeps working without a browser session. A *supplied but
//     wrong* token counts toward the per-IP auth-failure lockout exactly
//     like in token-only mode.
//  4. Everything else: browser navigations are redirected to /auth/login;
//     API/XHR/WebSocket requests receive 401 JSON. Requests without
//     credentials do NOT count as auth failures — a fresh browser hitting
//     "/" is the normal login entry point, not an attack.
func (s *Server) oidcGate(next http.Handler, w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/auth/") || strings.HasPrefix(p, "/assets/") {
		next.ServeHTTP(w, r)
		return
	}
	if id := s.sessionIdentity(r); id != nil {
		next.ServeHTTP(w, r)
		return
	}
	if s.Token != "" {
		supplied := false
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			supplied = true
			if !s.authLockoutActive(clientIP(r)) &&
				subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(s.Token)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		if tok := r.URL.Query().Get("token"); tok != "" {
			supplied = true
			if !s.authLockoutActive(clientIP(r)) &&
				subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		if supplied {
			s.recordAuthFailure(clientIP(r))
			jsonErr(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	if wantsHTMLNavigation(r) {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	jsonErr(w, "authentication required", http.StatusUnauthorized)
}

// wantsHTMLNavigation distinguishes a browser page navigation (redirect to
// the login flow) from API/XHR/EventSource/WebSocket traffic (401 JSON so
// clients fail fast instead of parsing a login page).
func wantsHTMLNavigation(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		!strings.HasPrefix(r.URL.Path, "/api/") &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

// ── /auth/* + /api/me handlers ──────────────────────────────────────────────

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		jsonErr(w, "OIDC authentication is not enabled on this server", http.StatusNotFound)
		return
	}
	s.OIDC.BeginLogin(w, r)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		jsonErr(w, "OIDC authentication is not enabled on this server", http.StatusNotFound)
		return
	}
	s.OIDC.HandleCallback(w, r)
}

func (s *Server) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		jsonErr(w, "OIDC authentication is not enabled on this server", http.StatusNotFound)
		return
	}
	s.OIDC.Logout(w, r)
	jsonOK(w, map[string]interface{}{"ok": true})
}

// handleMe reports the caller's authentication status so the frontend can
// decide whether to render the user chip + sign-out button. With OIDC
// disabled it reports oidc_enabled=false and the frontend renders nothing.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		jsonOK(w, map[string]interface{}{"oidc_enabled": false, "authenticated": true})
		return
	}
	id := s.sessionIdentity(r)
	if id == nil {
		// Reached with the static bearer token (automation clients).
		jsonOK(w, map[string]interface{}{"oidc_enabled": true, "authenticated": false})
		return
	}
	jsonOK(w, map[string]interface{}{
		"oidc_enabled":  true,
		"authenticated": true,
		"sub":           id.Sub,
		"email":         id.Email,
		"name":          id.Name,
		"admin":         s.OIDC.IsAdmin(id),
	})
}

// ── Per-user project scoping ────────────────────────────────────────────────

// identityCanSeeEntry reports whether user may see entry. Shared projects
// (no owner) are visible to everyone; owned projects only to their owner
// and admins. A nil user means either OIDC is off or the caller
// authenticated via the static bearer token — both see everything.
func (s *Server) identityCanSeeEntry(user *oidcauth.Identity, entry multiui.ProjectEntry) bool {
	if !s.oidcEnabled() || user == nil || entry.Owner == "" {
		return true
	}
	if s.OIDC.IsAdmin(user) {
		return true
	}
	return strings.EqualFold(entry.Owner, user.OwnerKey())
}

// filterEntriesForIdentity returns the subset of entries visible to user,
// preserving order. The returned slice is freshly allocated only when
// filtering actually removes something.
func (s *Server) filterEntriesForIdentity(user *oidcauth.Identity, entries []multiui.ProjectEntry) []multiui.ProjectEntry {
	if !s.oidcEnabled() || user == nil {
		return entries
	}
	visible := entries[:0:0]
	for _, e := range entries {
		if s.identityCanSeeEntry(user, e) {
			visible = append(visible, e)
		}
	}
	return visible
}

// visibleProjectEntries is the request-scoped project list: with OIDC
// enabled the entries (and therefore the project_idx namespace used by the
// frontend) are filtered to what the session user may see. resolveWorkDir
// and every /api/projects/{idx} handler resolve indices through this, so
// list rendering and index resolution always agree per user and one user
// can never address another user's project by index.
func (s *Server) visibleProjectEntries(r *http.Request) []multiui.ProjectEntry {
	entries := s.allProjectEntries()
	if !s.oidcEnabled() {
		return entries
	}
	return s.filterEntriesForIdentity(s.sessionIdentity(r), entries)
}

// visibilityKey groups broadcast recipients that see the same project list:
// "" for the unfiltered view (OIDC off, token clients, admins), otherwise
// the user's owner key. Used to marshal each distinct filtered payload once
// per broadcast instead of once per client.
func (s *Server) visibilityKey(user *oidcauth.Identity) string {
	if !s.oidcEnabled() || user == nil || s.OIDC.IsAdmin(user) {
		return ""
	}
	return user.OwnerKey()
}

// filterStatusesForIdentity returns the project statuses visible to user
// plus the aggregate stats recomputed over that subset. entries supplies
// the ownership metadata (statuses themselves don't carry Owner).
func (s *Server) filterStatusesForIdentity(user *oidcauth.Identity, entries []multiui.ProjectEntry, statuses []multiui.ProjectStatus) ([]multiui.ProjectStatus, multiui.AggregateStats) {
	if !s.oidcEnabled() || user == nil || s.OIDC.IsAdmin(user) {
		return statuses, multiui.Aggregate(statuses)
	}
	visiblePaths := make(map[string]bool, len(entries))
	for _, e := range entries {
		if s.identityCanSeeEntry(user, e) {
			visiblePaths[e.Path] = true
		}
	}
	filtered := make([]multiui.ProjectStatus, 0, len(statuses))
	for _, st := range statuses {
		if visiblePaths[st.Path] {
			filtered = append(filtered, st)
		}
	}
	return filtered, multiui.Aggregate(filtered)
}
