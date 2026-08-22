package ui

// Claim-based RBAC enforcement for the dashboard (Task 20164).
//
// Three pieces live here:
//
//   - authzMiddleware resolves the request's identity into an authz.Subject
//     once and parks it on the request context, so a handler chain that
//     checks several permissions pays for claim extraction once.
//   - require(perm, scope) is the single enforcement point. Route
//     registration supplies the permission (see routes.go), so a route
//     cannot be wired up without stating what it requires.
//   - auditAuthz appends an audit record for every denial and every
//     privileged grant.
//
// Behavior with OIDC disabled is unchanged from before RBAC existed: every
// request is granted everything. Single-tenant local use stays frictionless
// and no existing deployment changes behavior by upgrading.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// authzActive reports whether RBAC is in force. Two conditions must hold:
//
//   - OIDC is enabled. Without an IdP there are no claims to map, and a
//     resolver alone would lock the operator out of their own local
//     dashboard. This is what keeps single-tenant local use frictionless.
//   - A policy was actually configured (see authz.Resolver.Configured).
//     Enabling SSO must not silently enable deny-by-default and lock out a
//     deployment that upgraded without writing any role mappings.
//
// When RBAC is inactive every request is granted everything, which is
// exactly the pre-RBAC behavior — including the admin_emails check that
// requireExecutorAdmin still applies on top.
func (s *Server) authzActive() bool {
	return s.oidcEnabled() && s.Authz.Configured()
}

// subjectFromIdentity converts a validated OIDC identity into the claim
// bundle pkg/authz resolves against.
func subjectFromIdentity(id *oidcauth.Identity) *authz.Subject {
	if id == nil {
		return nil
	}
	return &authz.Subject{
		Sub:    id.Sub,
		Email:  id.Email,
		Groups: id.Groups,
		Roles:  id.Roles,
	}
}

// grant is the per-request authorization context: the resolved subject plus
// a memo table of decisions keyed by scope. Building it is cheap; resolving
// a scope walks the binding list, so the memo keeps a handler that checks
// several permissions against one project from re-walking it each time.
//
// A grant is created per request and normally used by one goroutine, but
// the WebSocket and SSE handlers fan out, so the memo is mutex-guarded.
type grant struct {
	server  *Server
	subject *authz.Subject

	// bypass is non-empty when RBAC does not apply to this caller:
	// authz_disabled (OIDC off) or static_token (deployment credential).
	bypass authz.Source

	mu    sync.Mutex
	cache map[authz.Scope]authz.Decision
}

// decide returns the caller's decision for scope, memoized.
func (g *grant) decide(scope authz.Scope) authz.Decision {
	if g == nil {
		// Fail closed: a missing grant must never read as "allowed".
		return authz.Deny(authz.SourceUnauthenticated, "", scope)
	}
	if g.bypass != "" {
		return authz.AllowAll(g.bypass, g.subjectLabel())
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if d, ok := g.cache[scope]; ok {
		return d
	}
	d := g.server.Authz.Resolve(g.subject, scope)
	if g.cache == nil {
		g.cache = make(map[authz.Scope]authz.Decision, 4)
	}
	g.cache[scope] = d
	return d
}

func (g *grant) subjectLabel() string {
	if g == nil {
		return "anonymous"
	}
	if g.bypass == authz.SourceStaticToken {
		return "static-token"
	}
	if g.bypass == authz.SourceAuthzDisabled {
		return "local"
	}
	return g.subject.Label()
}

type authzCtxKey struct{}

// authzMiddleware attaches a grant to every request that reaches the mux.
// It runs immediately below authMiddleware, so by the time it executes the
// caller has already been authenticated (or the request rejected).
func (s *Server) authzMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), authzCtxKey{}, s.newGrant(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// newGrant builds the authorization context for r.
func (s *Server) newGrant(r *http.Request) *grant {
	if !s.authzActive() {
		return &grant{server: s, bypass: authz.SourceAuthzDisabled}
	}
	id := s.sessionIdentity(r)
	if id == nil {
		// OIDC is on but there is no session: the request got past
		// authMiddleware on the static bearer token, which is the
		// deployment's own secret and therefore an operator credential.
		// This matches the pre-RBAC behavior of requireExecutorAdmin.
		return &grant{server: s, bypass: authz.SourceStaticToken}
	}
	return &grant{server: s, subject: subjectFromIdentity(id)}
}

// grantFor returns the request's grant, computing it on demand when the
// request did not pass through authzMiddleware. The context entry is a pure
// memoization — recomputing yields the same answer — so handlers invoked
// directly in tests behave identically to handlers reached through the
// middleware chain.
func (s *Server) grantFor(r *http.Request) *grant {
	if g, ok := r.Context().Value(authzCtxKey{}).(*grant); ok && g != nil {
		return g
	}
	return s.newGrant(r)
}

// permissionsFor returns the caller's permission list for scope, for the
// /api/me payload the frontend gates its UI on.
func (s *Server) permissionsFor(r *http.Request, scope authz.Scope) authz.Decision {
	return s.grantFor(r).decide(scope)
}

// ── Scope construction ──────────────────────────────────────────────────────

// projectScope builds the authz scope for a project-scoped request. The
// project is identified by both its registry name and its filesystem path so
// operators may bind either in config.
func (s *Server) projectScope(r *http.Request) authz.Scope {
	path := s.resolveWorkDir(r)
	return authz.Scope{
		Project:     s.projectNameForPath(path),
		ProjectPath: path,
	}
}

// projectNameForPath looks up a project's registry name. Returns "" when the
// path is not registered (single-project mode), in which case only
// path-based and unscoped bindings can match.
func (s *Server) projectNameForPath(path string) string {
	if path == "" {
		return ""
	}
	for _, e := range s.allProjectEntries() {
		if e.Path == path {
			return e.Name
		}
	}
	return ""
}

// executorScope builds the scope for an executor-scoped request, reading the
// executor ID from the {id} path segment. Executor actions are also fleet
// actions, so the project fields stay empty: a project-scoped binding must
// not confer fleet management.
func executorScope(r *http.Request) authz.Scope {
	return authz.Scope{Executor: strings.TrimSpace(r.PathValue("id"))}
}

// ── Enforcement ─────────────────────────────────────────────────────────────

// require enforces perm within scope. It returns true when the caller may
// proceed; otherwise it has already written the response and the handler
// must return immediately.
//
// Denials distinguish two cases so an unauthorized caller cannot use error
// codes as an existence oracle:
//
//   - The caller cannot even read the scope → 404 NOT_FOUND, the same
//     answer they would get for a project that does not exist.
//   - The caller can read the scope but not perform this action → 403
//     FORBIDDEN, naming the permission so the UI can explain it.
func (s *Server) require(w http.ResponseWriter, r *http.Request, perm authz.Permission, scope authz.Scope) bool {
	if perm == authz.PermPublic {
		return true
	}
	g := s.grantFor(r)
	d := g.decide(scope)
	if d.Allows(perm) {
		s.auditAuthz(r, d, perm, scope, true)
		return true
	}
	s.auditAuthz(r, d, perm, scope, false)

	// Withhold existence for scopes the caller may not read at all.
	if !scope.IsGlobal() && !d.Allows(authz.PermProjectRead) {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"the requested resource does not exist"))
		return false
	}
	apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
		"your role does not permit this action").
		WithDetails(map[string]any{
			"required_permission": string(perm),
			"role":                string(d.Role),
			"scope":               scope.String(),
		}))
	return false
}

// requireVisibleProject rejects a request that names a project index the
// caller cannot see. Without this an out-of-range index silently falls back
// to the server's own workdir, which under multi-tenancy would let one user
// address another tenant's data by supplying a wild index.
//
// Only enforced when RBAC is active; with OIDC disabled the historical
// fallback behavior is preserved exactly.
func (s *Server) requireVisibleProject(w http.ResponseWriter, r *http.Request) bool {
	if !s.authzActive() {
		return true
	}
	raw := r.URL.Query().Get("project_idx")
	if raw == "" {
		return true
	}
	i, err := strconv.Atoi(raw)
	if err != nil || i < 0 || i >= len(s.visibleProjectEntries(r)) {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"the requested resource does not exist"))
		return false
	}
	return true
}

// ── Audit ───────────────────────────────────────────────────────────────────

// isPrivileged reports whether granting perm is worth an audit record.
// Reads are excluded: every dashboard poll would otherwise append a row and
// bury the events an auditor actually cares about. Denials are always
// recorded regardless of permission.
func isPrivileged(perm authz.Permission) bool {
	switch perm {
	case authz.PermProjectRead, authz.PermExecutorRead, authz.PermPublic:
		return false
	}
	return true
}

// auditAuthz appends an authorization record naming the acting subject.
//
// Best-effort by design, matching pkg/eventlog's contract: a wedged or
// missing database must not block user work or turn an authorization check
// into an error path. Failures are logged, not surfaced. Write volume is
// bounded by the per-IP rate limiter that sits above this layer.
func (s *Server) auditAuthz(r *http.Request, d authz.Decision, perm authz.Permission, scope authz.Scope, allowed bool) {
	// Only record decisions when RBAC is actually in force. With OIDC
	// disabled there is no acting subject and no decision was made — every
	// request is granted everything — so a record would say nothing beyond
	// "a request happened", while costing a SQLite open on the mutation
	// hot path. The mutations themselves are already journalled by
	// pkg/statedb; this log is specifically about who was allowed to ask.
	if !s.authzActive() {
		return
	}
	if allowed && !isPrivileged(perm) {
		return
	}

	// Project-scoped events land in that project's journal; global events
	// in the hub's own. A workdir without a state.db yields ErrNoProject
	// and the record is skipped.
	workDir := scope.ProjectPath
	if workDir == "" {
		workDir = s.WorkDir
	}

	outcome := "denied"
	if allowed {
		outcome = "granted"
	}
	payload := map[string]any{
		"outcome":    outcome,
		"permission": string(perm),
		"role":       string(d.Role),
		"source":     string(d.Source),
		"scope":      scope.String(),
		"subject":    d.SubjectLabel,
		"method":     r.Method,
		"path":       r.URL.Path,
	}
	if d.Binding != nil {
		payload["binding"] = map[string]any{
			"claim": string(d.Binding.Claim),
			"value": d.Binding.Value,
			"role":  string(d.Binding.Role),
		}
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "authz audit: marshal payload",
			map[string]interface{}{"error": err.Error()})
		return
	}

	actor := d.SubjectLabel
	if actor == "" {
		actor = "anonymous"
	}
	log, err := eventlog.Open(workDir)
	if err != nil {
		// ErrNoProject is routine (uninitialized workdir); anything else
		// is worth a line so a broken journal is visible to operators.
		if err != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "authz audit: open event log",
				map[string]interface{}{"error": err.Error(), "workdir": workDir})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  "authz." + outcome,
		EntityType: "permission",
		EntityID:   string(perm),
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "authz audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}
