package ui

// OIDC single sign-on and per-user project scoping for the web dashboard
// (Task 20152). Everything in this file is inert unless Server.OIDC is set,
// which only happens when ui.oidc.enabled is true in .cloop/config.yaml —
// with OIDC disabled the dashboard behaves exactly as before.

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
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

// identityFromOwner reconstructs the minting user from a token's owner
// binding, so an owner-bound token is filtered by exactly the rules its
// owner's browser session is filtered by — including admin_emails, which is
// read from the live config rather than frozen at mint time.
func identityFromOwner(o *apitoken.Owner) *oidcauth.Identity {
	if o == nil {
		return nil
	}
	return &oidcauth.Identity{
		Sub:    o.Sub,
		Email:  o.Email,
		Name:   o.Name,
		Groups: o.Groups,
		Roles:  o.Roles,
	}
}

// recipientIdentity is the user a request (or a long-lived stream) acts as:
// the session user, or — for a token minted on someone's behalf — that
// someone.
//
// Every per-user filter goes through this rather than sessionIdentity, because
// a delegated token has no session and would otherwise read as nil, which is
// the *unfiltered* case: a display-glasses link would see every tenant's
// projects. Returning the owner instead makes the link show exactly what its
// owner's own dashboard shows.
func (s *Server) recipientIdentity(r *http.Request) *oidcauth.Identity {
	if id := s.sessionIdentity(r); id != nil {
		return id
	}
	return identityFromOwner(tokenFromRequest(r).OwnerBinding())
}

// localViewer is the viewer key for a deployment with no OIDC: one dashboard,
// one person, so their view preferences need a stable name to be stored under.
//
// It cannot collide with a real OwnerKey, which is always either an email
// (contains "@") or "sub:"-prefixed.
const localViewer = "local"

// viewerKey names whose dashboard preferences a request acts on — currently
// which projects to hide. It is the recipient identity's OwnerKey, so a
// delegated token adjusts its owner's view rather than a view of its own,
// and localViewer when OIDC is off.
//
// Distinct from the authorization identity on purpose: preferences are about
// whose screen this is, not what they are allowed to reach. An admin who
// hides a noisy project hides it from their own dashboard only, and hiding
// grants nobody sight of a project they could not already see.
func (s *Server) viewerKey(r *http.Request) string {
	return viewerKeyFor(s.recipientIdentity(r))
}

// viewerKeyFor is viewerKey for a resolved identity, used by the broadcast
// fan-out where recipients are stored rather than re-derived per request.
//
// An identity carrying neither an email nor a subject is treated as no
// identity at all. OwnerKey renders that case as the bare prefix "sub:",
// which is a *shared* key: two unrelated malformed identities would land in
// the same preference bucket and see each other's hidden projects. A
// validated ID token always carries a subject, so this is a guard against
// an identity assembled somewhere other than the token path rather than
// against a real IdP.
func viewerKeyFor(user *oidcauth.Identity) string {
	if user == nil || (user.Email == "" && user.Sub == "") {
		return localViewer
	}
	if key := user.OwnerKey(); key != "" {
		return key
	}
	return localViewer
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
	// A scoped API token authenticates before the static one is considered,
	// so a deployment can migrate to PATs without turning --token off first
	// (Task 20175). authenticateAPIToken writes its own 401 on a supplied
	// but bad token and reports handled=true.
	if r2, ok, handled := s.authenticateAPIToken(w, r); handled {
		return
	} else if ok {
		next.ServeHTTP(w, r2)
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

// handleOIDCLogout ends the caller's session here and tells the browser where
// to finish the job at the identity provider.
//
// Returning a redirect target rather than issuing a 302 keeps this callable
// from fetch(): the frontend clears its own state and then navigates. An empty
// "redirect" means the provider advertises no end_session_endpoint, in which
// case the browser's session at the IdP outlives cloop's — the next sign-in
// completes without a prompt, which is worth knowing but is the provider's
// behaviour to change, not something the hub can paper over.
func (s *Server) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		jsonErr(w, "OIDC authentication is not enabled on this server", http.StatusNotFound)
		return
	}
	s.OIDC.Logout(w, r)
	jsonOK(w, map[string]interface{}{
		"ok":       true,
		"redirect": s.OIDC.EndSessionURL(),
	})
}

// handleMe reports the caller's authentication status and effective
// permissions so the frontend can decide what to render. With OIDC disabled
// it reports oidc_enabled=false and a full permission set, so the UI gates
// on the same field in every deployment instead of special-casing.
//
// Permissions are resolved for the scope the request names (?project_idx=N)
// so a user who is maintainer on one project and viewer on another sees the
// right controls as they switch tabs.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	scope := s.projectScope(r)
	decision := s.permissionsFor(r, scope)
	body := map[string]interface{}{
		"oidc_enabled": s.oidcEnabled(),
		"role":         string(decision.Role),
		"permissions":  permissionStrings(decision.Permissions()),
		// Global permissions gate the fleet-wide tabs (executors, global
		// budget), which are not about the selected project.
		"global_permissions": permissionStrings(s.permissionsFor(r, authz.GlobalScope).Permissions()),
	}
	if !s.oidcEnabled() {
		body["authenticated"] = true
		jsonOK(w, body)
		return
	}
	id := s.sessionIdentity(r)
	if id == nil {
		// Reached with the static bearer token (automation clients).
		body["authenticated"] = false
		jsonOK(w, body)
		return
	}
	body["authenticated"] = true
	body["sub"] = id.Sub
	body["email"] = id.Email
	body["name"] = id.Name
	body["admin"] = s.OIDC.IsAdmin(id)
	jsonOK(w, body)
}

// permissionStrings renders a permission slice for JSON. It returns an empty
// (non-nil) slice for the deny case so the frontend always receives an array
// and can call .includes() without a null guard.
func permissionStrings(perms []authz.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
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
	// A project-scoped API token is filtered regardless of whether OIDC is
	// on: its scope is a property of the credential, not of the deployment's
	// identity configuration (Task 20175). Applied here rather than in each
	// handler because this list *is* the ?project_idx index space that
	// resolveWorkDir maps through — so an out-of-scope project is not merely
	// hidden from the list, it has no index the token could name.
	entries = filterEntriesForToken(tokenFromRequest(r), entries)
	if !s.oidcEnabled() {
		return entries
	}
	return s.filterEntriesForIdentity(s.recipientIdentity(r), entries)
}

// filterEntriesForToken narrows entries to a token's ProjectScope. A nil token
// or an unscoped one passes everything through untouched.
func filterEntriesForToken(tok *apitoken.Token, entries []multiui.ProjectEntry) []multiui.ProjectEntry {
	if tok == nil || len(tok.ProjectScope) == 0 {
		return entries
	}
	visible := entries[:0:0]
	for _, e := range entries {
		if tok.AllowsProject(e.Name, e.Path) {
			visible = append(visible, e)
		}
	}
	return visible
}

// visibilityKey groups broadcast recipients that see the same project list:
// "" for the unfiltered view (OIDC off, static-token clients, admins),
// otherwise a key derived from whatever narrows this recipient. Used to
// marshal each distinct filtered payload once per broadcast instead of once
// per client.
//
// A project-scoped API token contributes its scope to the key, because two
// recipients with different scopes must not share a payload — which is what
// would happen if the key considered only the OIDC identity, since a token
// client has none (Task 20175).
// A token minted on a user's behalf contributes its *owner* here, because
// callers resolve it through recipientIdentity: two links owned by different
// users must not share a payload any more than two browser sessions would.
func (s *Server) visibilityKey(user *oidcauth.Identity, tok *apitoken.Token) string {
	key := ""
	if s.oidcEnabled() && user != nil && !s.OIDC.IsAdmin(user) {
		key = user.OwnerKey()
	}
	if tok != nil && len(tok.ProjectScope) > 0 {
		key += "\x00tok:" + tok.ID
	}
	return key
}

// projectsPayloadKey is visibilityKey extended with whose *preferences* shape
// the payload, for the broadcast fan-out's marshal-once cache.
//
// visibilityKey alone is not enough once projects can be hidden. It collapses
// every admin, every unscoped-token client and — with OIDC off — every
// browser onto the key "", because authorization gives them all the same
// list. Hiding does not: two admins who hid different projects need different
// payloads, and keying on authorization alone would serve whichever of them
// broadcast first to both.
//
// anyHidden keeps the collapse when nobody has hidden anything, which is the
// overwhelmingly common case and the one the cache exists for.
func (s *Server) projectsPayloadKey(user *oidcauth.Identity, tok *apitoken.Token, anyHidden bool) string {
	key := s.visibilityKey(user, tok)
	if anyHidden {
		key += "\x00view:" + viewerKeyFor(user)
	}
	return key
}

// entriesHaveHidden reports whether any registered project is hidden by
// anyone, i.e. whether per-viewer payloads are needed at all.
func entriesHaveHidden(entries []multiui.ProjectEntry) bool {
	for _, e := range entries {
		if len(e.HiddenFor) > 0 {
			return true
		}
	}
	return false
}

// filterStatusesForRecipient narrows project statuses to what one recipient
// may see, applying both the API-token scope and the OIDC ownership rule, and
// recomputes the aggregate stats over the surviving subset.
//
// Both filters are applied here rather than at each call site because there
// are four of them — the REST list, the SSE stream, the WebSocket stream, and
// the broadcast fan-out — and a project list that leaks is a project list that
// leaked from whichever one was forgotten.
func (s *Server) filterStatusesForRecipient(user *oidcauth.Identity, tok *apitoken.Token, entries []multiui.ProjectEntry, statuses []multiui.ProjectStatus) ([]multiui.ProjectStatus, multiui.AggregateStats) {
	if tok != nil && len(tok.ProjectScope) > 0 {
		scoped := make([]multiui.ProjectStatus, 0, len(statuses))
		for _, st := range statuses {
			if tok.AllowsProject(st.Name, st.Path) {
				scoped = append(scoped, st)
			}
		}
		statuses = scoped
	}
	statuses, stats := s.filterStatusesForIdentity(user, entries, statuses)
	// Marking runs last, over the set this recipient may actually see, and
	// re-derives the stats because Aggregate discounts hidden projects.
	marked, changed := markHiddenFor(viewerKeyFor(user), entries, statuses)
	if !changed {
		return statuses, stats
	}
	return marked, multiui.Aggregate(marked)
}

// markHiddenFor returns statuses with Hidden stamped for the projects viewer
// has hidden, reporting whether anything was marked.
//
// It copies before writing rather than stamping in place: statuses aliases
// the server's shared status cache, which every connected client reads. One
// recipient's preference written into it would be served to all of them, and
// concurrently at that.
func markHiddenFor(viewer string, entries []multiui.ProjectEntry, statuses []multiui.ProjectStatus) ([]multiui.ProjectStatus, bool) {
	hidden := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.HiddenForViewer(viewer) {
			hidden[e.Path] = true
		}
	}
	if len(hidden) == 0 {
		return statuses, false
	}
	marked := make([]multiui.ProjectStatus, len(statuses))
	copy(marked, statuses)
	any := false
	for i := range marked {
		if hidden[marked[i].Path] {
			marked[i].Hidden = true
			any = true
		}
	}
	return marked, any
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
