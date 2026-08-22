package ui

// The dashboard's route table (Task 20164).
//
// Every route is declared as a routeSpec carrying the permission required to
// reach it. registerRoutes wires the table onto the mux through gate(), which
// enforces that permission before the handler runs. Because the spec struct
// has no usable zero value for Perm — an empty permission is rejected at
// registration time by validate(), and by TestEveryRouteDeclaresAPermission
// at build time — a new route cannot quietly ship without an access
// decision. Adding `mux.HandleFunc` directly bypasses the gate, so
// TestRegisterRoutesUsesTheRouteTable fails if anyone does.
//
// Routes that must stay reachable before authorization can be evaluated (the
// login flow, the SPA shell, static assets, /api/me) declare authz.PermPublic
// — an explicit, greppable opt-out rather than an omission.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/logger"
)

// scopeKind selects how a route's authz.Scope is derived from the request.
type scopeKind int

const (
	// scopeGlobal is for actions that are not about one project or one
	// executor: the project registry, the executor fleet, global budget.
	scopeGlobal scopeKind = iota

	// scopeProject derives the project from ?project_idx=N via
	// resolveWorkDir — the convention for per-project API calls.
	scopeProject

	// scopeProjectIdx derives the project from the {idx} path segment,
	// used by /api/projects/{idx}/….
	scopeProjectIdx

	// scopeExecutor derives the executor from the {id} path segment.
	scopeExecutor
)

// routeSpec declares one route and the permission needed to reach it.
type routeSpec struct {
	// Pattern is the http.ServeMux pattern, optionally method-prefixed.
	Pattern string

	// Handler runs only after the permission check passes.
	Handler http.HandlerFunc

	// Perm is required for every method the route accepts, unless
	// MethodPerms overrides it for a specific method.
	Perm authz.Permission

	// MethodPerms overrides Perm per HTTP method. Needed for the handful
	// of legacy routes registered without a method prefix that multiplex
	// a read and a write behind one pattern (/api/config, /api/goal,
	// /api/instructions): the read must stay available to viewers while
	// the write requires more.
	MethodPerms map[string]authz.Permission

	// Scope selects how the request's authz scope is derived.
	Scope scopeKind
}

// permFor returns the permission required for this request's method.
func (rs routeSpec) permFor(method string) authz.Permission {
	if p, ok := rs.MethodPerms[method]; ok {
		return p
	}
	return rs.Perm
}

// validate rejects a spec that would register an unenforceable route. Called
// from registerRoutes so a malformed entry fails at startup rather than
// serving unguarded traffic.
func (rs routeSpec) validate() error {
	if rs.Pattern == "" {
		return fmt.Errorf("route has an empty pattern")
	}
	if rs.Handler == nil {
		return fmt.Errorf("route %q has a nil handler", rs.Pattern)
	}
	if rs.Perm == "" && len(rs.MethodPerms) == 0 {
		return fmt.Errorf("route %q declares no permission (use authz.PermPublic to opt out explicitly)", rs.Pattern)
	}
	if rs.Perm != "" && rs.Perm != authz.PermPublic && !rs.Perm.Valid() {
		return fmt.Errorf("route %q declares unknown permission %q", rs.Pattern, rs.Perm)
	}
	for method, p := range rs.MethodPerms {
		if p == "" {
			return fmt.Errorf("route %q declares an empty permission for %s", rs.Pattern, method)
		}
		if p != authz.PermPublic && !p.Valid() {
			return fmt.Errorf("route %q declares unknown permission %q for %s", rs.Pattern, p, method)
		}
	}
	return nil
}

// scopeFor builds the authz scope this request is evaluated against. ok is
// false when the request names a resource that does not resolve, which the
// caller must treat as a refusal rather than falling back to a broader scope.
func (s *Server) scopeFor(kind scopeKind, r *http.Request) (authz.Scope, bool) {
	switch kind {
	case scopeProject:
		return s.projectScope(r), true
	case scopeProjectIdx:
		return s.projectScopeFromIdx(r)
	case scopeExecutor:
		return executorScope(r), true
	}
	return authz.GlobalScope, true
}

// projectScopeFromIdx resolves the {idx} path segment against the caller's
// visible project list. ok is false when the index does not resolve.
//
// Callers must not substitute the zero Scope for an unresolved index: the
// zero Scope *is* the global scope, so an unresolvable index would be
// evaluated against the caller's fleet-wide authority and a user holding
// global run.start could pass the gate for a project they cannot see. gate()
// therefore refuses the request outright instead.
func (s *Server) projectScopeFromIdx(r *http.Request) (authz.Scope, bool) {
	i, err := strconv.Atoi(strings.TrimSpace(r.PathValue("idx")))
	if err != nil {
		return authz.Scope{}, false
	}
	entries := s.visibleProjectEntries(r)
	if i < 0 || i >= len(entries) {
		return authz.Scope{}, false
	}
	return authz.Scope{Project: entries[i].Name, ProjectPath: entries[i].Path}, true
}

// gate wraps a spec's handler with its permission check.
func (s *Server) gate(rs routeSpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// With RBAC inactive every request is granted everything, so the
		// entire layer collapses to one boolean. This is not just an
		// optimization: deriving a scope calls allProjectEntries(), which
		// resolves and stats every registered project. Paying that on each
		// request would be a real regression for the single-tenant local
		// use this feature promises to leave untouched.
		if !s.authzActive() {
			rs.Handler(w, r)
			return
		}

		perm := rs.permFor(r.Method)
		if perm == "" {
			// A method the route did not anticipate. Fail closed rather
			// than guess, and make the gap loud enough to fix.
			s.log().Error(logger.EventAuthz, 0, "route declares no permission for method",
				map[string]interface{}{"pattern": rs.Pattern, "method": r.Method})
			apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
				"your role does not permit this action"))
			return
		}
		if perm == authz.PermPublic {
			rs.Handler(w, r)
			return
		}
		// A project_idx the caller cannot see is indistinguishable from a
		// project that does not exist.
		if rs.Scope == scopeProject && !s.requireVisibleProject(w, r) {
			return
		}
		scope, ok := s.scopeFor(rs.Scope, r)
		if !ok {
			// The request names a resource that does not resolve for this
			// caller. Refuse here rather than evaluating the permission
			// against a broader scope — see projectScopeFromIdx.
			apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
				"the requested resource does not exist"))
			return
		}
		if !s.require(w, r, perm, scope) {
			return
		}
		rs.Handler(w, r)
	}
}

// registerRoutes wires every route in routeTable onto mux, gated by the
// permission each one declares.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	for _, rs := range s.routeTable() {
		if err := rs.validate(); err != nil {
			// Registration happens once at startup with a table that is
			// fixed at compile time, so this is a programming error, not
			// an operator error: refuse to serve a route we cannot
			// enforce rather than serve it unguarded.
			panic("ui: invalid route registration: " + err.Error())
		}
		mux.HandleFunc(rs.Pattern, s.gate(rs))
	}
}

// routeTable is the complete set of dashboard routes with their access
// requirements. It is a method (not a package var) because the handlers are
// Server methods; tests walk the same table the server registers, so a route
// cannot be covered by tests and unenforced in production.
func (s *Server) routeTable() []routeSpec {
	// Shorthands keep the table scannable: the permission and scope of
	// each row should be readable at a glance.
	const (
		read      = authz.PermProjectRead
		write     = authz.PermProjectWrite
		task      = authz.PermTaskMutate
		start     = authz.PermRunStart
		stop      = authz.PermRunStop
		cfgWrite  = authz.PermConfigWrite
		execRead  = authz.PermExecutorRead
		execMgmt  = authz.PermExecutorManage
		auditRead = authz.PermAuditRead
		secGrant  = authz.PermSecretGrant
		secRevoke = authz.PermSecretRevoke
		public    = authz.PermPublic
	)

	return []routeSpec{
		// ── Unauthenticated surface ──────────────────────────────────
		// The SPA shell and its assets: authMiddleware already decided
		// whether this caller may load the dashboard at all, and the app
		// renders only what /api/me says the user can do.
		{Pattern: "/", Handler: s.handleDashboard, Perm: public},
		{Pattern: "/assets/chart.umd.min.js", Handler: s.handleChartJS, Perm: public},

		// OIDC login machinery. Gating these on a permission would make
		// signing in require being signed in.
		{Pattern: "GET /auth/login", Handler: s.handleOIDCLogin, Perm: public},
		{Pattern: "GET /auth/callback", Handler: s.handleOIDCCallback, Perm: public},
		{Pattern: "POST /auth/logout", Handler: s.handleOIDCLogout, Perm: public},

		// Reports the caller's own identity and permission set; the
		// frontend cannot decide what to render without it.
		{Pattern: "GET /api/me", Handler: s.handleMe, Perm: public},

		// Browser error reports. Writes no state, and the error boundary
		// must keep working for a user whose role grants nothing.
		{Pattern: "POST /api/client-error", Handler: s.handleClientError, Perm: public},

		// ── Project state (read) ─────────────────────────────────────
		{Pattern: "/api/state", Handler: s.handleState, Perm: read, Scope: scopeProject},
		{Pattern: "/api/steps", Handler: s.handleSteps, Perm: read, Scope: scopeProject},
		{Pattern: "/api/ws", Handler: s.handleWS, Perm: read, Scope: scopeProject},
		{Pattern: "/api/events", Handler: s.handleEvents, Perm: read, Scope: scopeProject},
		{Pattern: "/api/event-history", Handler: s.handleEventHistory, Perm: read, Scope: scopeProject},
		{Pattern: "/api/livelog", Handler: s.handleLiveLog, Perm: read, Scope: scopeProject},
		{Pattern: "/api/timeline", Handler: s.handleTimeline, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/deps", Handler: s.handleDeps, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/risk-matrix", Handler: s.handleRiskMatrix, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/analytics", Handler: s.handleAnalytics, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/epics", Handler: s.handleEpics, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/queue", Handler: s.handleQueue, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/queue/stats", Handler: s.handleQueueStats, Perm: read, Scope: scopeProject},
		{Pattern: "/api/chat/history", Handler: s.handleChatHistory, Perm: read, Scope: scopeProject},
		{Pattern: "/api/suggest/status", Handler: s.handleSuggestStatus, Perm: read, Scope: scopeProject},

		// ── Run controls ─────────────────────────────────────────────
		// Starting a run spends the token budget; stopping one is a
		// safety action, so the two are separate permissions and an
		// operator who cannot start can still halt a runaway plan.
		{Pattern: "/api/run", Handler: s.handleRun, Perm: start, Scope: scopeProject},
		{Pattern: "/api/stop", Handler: s.handleStop, Perm: stop, Scope: scopeProject},

		// ── Task management (legacy endpoints) ───────────────────────
		{Pattern: "/api/task/add", Handler: s.handleTaskAdd, Perm: task, Scope: scopeProject},
		{Pattern: "/api/task/status", Handler: s.handleTaskStatus, Perm: task, Scope: scopeProject},
		{Pattern: "/api/task/move", Handler: s.handleTaskMove, Perm: task, Scope: scopeProject},
		{Pattern: "/api/task/edit", Handler: s.handleTaskEdit, Perm: task, Scope: scopeProject},
		{Pattern: "/api/task/remove", Handler: s.handleTaskRemove, Perm: task, Scope: scopeProject},

		// ── Task management (RESTful) ────────────────────────────────
		{Pattern: "GET /api/tasks", Handler: s.handleGetTasks, Perm: read, Scope: scopeProject},
		{Pattern: "POST /api/tasks", Handler: s.handlePostTasks, Perm: task, Scope: scopeProject},
		{Pattern: "POST /api/tasks/reorder", Handler: s.handleReorderTasks, Perm: task, Scope: scopeProject},
		{Pattern: "PUT /api/tasks/{id}", Handler: s.handlePutTask, Perm: task, Scope: scopeProject},
		{Pattern: "PATCH /api/tasks/{id}", Handler: s.handlePutTask, Perm: task, Scope: scopeProject},
		{Pattern: "DELETE /api/tasks/{id}", Handler: s.handleDeleteTask, Perm: task, Scope: scopeProject},
		{Pattern: "GET /api/tasks/{id}/blocker", Handler: s.handleTaskBlocker, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/tasks/{id}/details", Handler: s.handleTaskDetails, Perm: read, Scope: scopeProject},
		// Decomposition previews mutate nothing, but they call a provider
		// and therefore spend the project's budget — gated at the same
		// level as the mutation they precede rather than as a read.
		{Pattern: "POST /api/tasks/{id}/decompose", Handler: s.handleTaskDecompose, Perm: task, Scope: scopeProject},
		{Pattern: "POST /api/tasks/{id}/decompose/apply", Handler: s.handleTaskDecomposeApply, Perm: task, Scope: scopeProject},

		// ── Suggestions, chat, voice ─────────────────────────────────
		// All three spend provider budget and feed the plan, so viewers
		// cannot invoke them.
		{Pattern: "/api/suggest/generate", Handler: s.handleSuggestGenerate, Perm: task, Scope: scopeProject},
		{Pattern: "/api/suggest/add", Handler: s.handleSuggestAdd, Perm: task, Scope: scopeProject},
		{Pattern: "/api/chat", Handler: s.handleChat, Perm: task, Scope: scopeProject},
		{Pattern: "POST /api/chat/plan", Handler: s.handlePlanChat, Perm: task, Scope: scopeProject},
		{Pattern: "/api/voice", Handler: s.handleVoice, Perm: task, Scope: scopeProject},

		// ── Knowledge base ───────────────────────────────────────────
		{Pattern: "GET /api/kb", Handler: s.handleKBList, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/kb/search", Handler: s.handleKBSearch, Perm: read, Scope: scopeProject},
		{Pattern: "POST /api/kb", Handler: s.handleKBAdd, Perm: task, Scope: scopeProject},
		{Pattern: "DELETE /api/kb/{id}", Handler: s.handleKBDelete, Perm: task, Scope: scopeProject},

		// ── Replay ───────────────────────────────────────────────────
		{Pattern: "GET /api/replay-runs", Handler: s.handleReplayRunsList, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/replay-runs/{id}", Handler: s.handleReplayRunGet, Perm: read, Scope: scopeProject},
		{Pattern: "POST /api/replay-runs", Handler: s.handleReplayRunCreate, Perm: task, Scope: scopeProject},

		// ── Provider call inspector ──────────────────────────────────
		{Pattern: "GET /api/provider-calls", Handler: s.handleProviderCallsList, Perm: read, Scope: scopeProject},
		{Pattern: "GET /api/provider-calls/{id}", Handler: s.handleProviderCallDetail, Perm: read, Scope: scopeProject},
		{Pattern: "POST /api/provider-calls/{id}/replay", Handler: s.handleProviderCallReplay, Perm: task, Scope: scopeProject},

		// ── Project identity and lifecycle ───────────────────────────
		{Pattern: "/api/init", Handler: s.handleInit, Perm: write, Scope: scopeProject},
		{Pattern: "/api/reset", Handler: s.handleReset, Perm: write, Scope: scopeProject},
		// GET returns the current value and must stay available to
		// viewers; the writes require project.write.
		{
			Pattern: "/api/goal", Handler: s.handleGoal, Perm: write, Scope: scopeProject,
			MethodPerms: map[string]authz.Permission{http.MethodGet: read},
		},
		{
			Pattern: "/api/instructions", Handler: s.handleInstructions, Perm: write, Scope: scopeProject,
			MethodPerms: map[string]authz.Permission{http.MethodGet: read},
		},

		// ── Configuration ────────────────────────────────────────────
		{
			Pattern: "/api/config", Handler: s.handleConfig, Perm: cfgWrite, Scope: scopeProject,
			MethodPerms: map[string]authz.Permission{http.MethodGet: read},
		},
		{Pattern: "/api/config/set", Handler: s.handleConfigSet, Perm: cfgWrite, Scope: scopeProject},
		{Pattern: "POST /api/options/toggle", Handler: s.handleOptionsToggle, Perm: cfgWrite, Scope: scopeProject},
		{Pattern: "POST /api/options/max-parallel", Handler: s.handleMaxParallelSet, Perm: cfgWrite, Scope: scopeProject},
		{Pattern: "POST /api/options/step-timeout", Handler: s.handleStepTimeoutSet, Perm: cfgWrite, Scope: scopeProject},
		{Pattern: "POST /api/options/task-timeout", Handler: s.handleTaskTimeoutSet, Perm: cfgWrite, Scope: scopeProject},
		{Pattern: "POST /api/options/provider", Handler: s.handleProviderModelSet, Perm: cfgWrite, Scope: scopeProject},

		// ── Budgets and usage ────────────────────────────────────────
		{Pattern: "GET /api/budget", Handler: s.handleBudgetGet, Perm: read, Scope: scopeProject},
		{Pattern: "PUT /api/budget/project", Handler: s.handleBudgetProjectSave, Perm: cfgWrite, Scope: scopeProject},
		{Pattern: "PUT /api/budget/global", Handler: s.handleBudgetGlobalSave, Perm: cfgWrite, Scope: scopeGlobal},
		{Pattern: "GET /api/ratelimits", Handler: s.handleRateLimits, Perm: read, Scope: scopeGlobal},
		{Pattern: "GET /api/claude-usage", Handler: s.handleClaudeUsage, Perm: read, Scope: scopeGlobal},
		{Pattern: "GET /api/claudecode-limits", Handler: s.handleClaudeCodeLimitsGet, Perm: read, Scope: scopeProject},
		{Pattern: "PUT /api/claudecode-limits", Handler: s.handleClaudeCodeLimitsSave, Perm: cfgWrite, Scope: scopeProject},

		// ── Claude Code authentication ───────────────────────────────
		// Login/logout changes the credential every project on this hub
		// executes with, so it is a configuration change, not a per-user
		// preference.
		{Pattern: "GET /api/claudecode/auth/status", Handler: s.handleClaudeCodeAuthStatus, Perm: read, Scope: scopeGlobal},
		{Pattern: "POST /api/claudecode/auth/login", Handler: s.handleClaudeCodeAuthLoginStart, Perm: cfgWrite, Scope: scopeGlobal},
		{Pattern: "POST /api/claudecode/auth/login/code", Handler: s.handleClaudeCodeAuthLoginCode, Perm: cfgWrite, Scope: scopeGlobal},
		{Pattern: "POST /api/claudecode/auth/login/cancel", Handler: s.handleClaudeCodeAuthLoginCancel, Perm: cfgWrite, Scope: scopeGlobal},
		{Pattern: "POST /api/claudecode/auth/logout", Handler: s.handleClaudeCodeAuthLogout, Perm: cfgWrite, Scope: scopeGlobal},

		// ── Multi-project registry ───────────────────────────────────
		// The list itself is already filtered per identity by
		// visibleProjectEntries; project.read gates seeing the tab at all.
		{Pattern: "/api/projects", Handler: s.handleProjects, Perm: read, Scope: scopeGlobal},
		{Pattern: "GET /api/projects/events", Handler: s.handleProjectsEvents, Perm: read, Scope: scopeGlobal},
		{Pattern: "POST /api/projects/new", Handler: s.handleProjectNew, Perm: write, Scope: scopeGlobal},
		{Pattern: "POST /api/projects/{idx}/run", Handler: s.handleProjectRun, Perm: start, Scope: scopeProjectIdx},
		{Pattern: "POST /api/projects/{idx}/stop", Handler: s.handleProjectStop, Perm: stop, Scope: scopeProjectIdx},
		{Pattern: "DELETE /api/projects/{idx}", Handler: s.handleProjectDelete, Perm: write, Scope: scopeProjectIdx},
		// Choosing where a project's code runs is a fleet decision, not a
		// project one.
		{Pattern: "POST /api/projects/{idx}/executor", Handler: s.handleProjectExecutorBind, Perm: execMgmt, Scope: scopeProjectIdx},

		// ── Executor fleet ───────────────────────────────────────────
		// Registered without a method prefix so the handler's own method
		// check stays reachable: with `GET /api/executors`, any other verb
		// falls through to "/" and answers a JSON client with an HTML page.
		{Pattern: "/api/executors", Handler: s.handleExecutorsList, Perm: execRead, Scope: scopeGlobal},
		{Pattern: "POST /api/executors/enroll", Handler: s.handleExecutorEnroll, Perm: execMgmt, Scope: scopeGlobal},
		// The edge-device bootstrap script (Task 20172). Same permission as
		// minting a token, because it is the other half of the same action:
		// it discloses the hub's URL and certificate pin, and it is useful
		// only to someone who can also mint the token that goes with it.
		// The handler additionally refuses to answer over plaintext HTTP.
		//
		// Written as a literal, like every other row: the table is also read
		// by the authz drift tests, which parse it as source. The literal is
		// checked against installScriptPath by
		// TestInstallScriptRouteMatchesTheConstant.
		{Pattern: "/install.sh", Handler: s.handleInstallScript, Perm: execMgmt, Scope: scopeGlobal},
		{Pattern: "DELETE /api/executors/{id}", Handler: s.handleExecutorDelete, Perm: execMgmt, Scope: scopeExecutor},
		{Pattern: "POST /api/executors/{id}/cordon", Handler: s.handleExecutorCordon, Perm: execMgmt, Scope: scopeExecutor},
		{Pattern: "POST /api/executors/{id}/uncordon", Handler: s.handleExecutorUncordon, Perm: execMgmt, Scope: scopeExecutor},
		{Pattern: "POST /api/executors/{id}/drain", Handler: s.handleExecutorDrain, Perm: execMgmt, Scope: scopeExecutor},

		// ── Compliance audit trail ───────────────────────────────────
		// Admin-only, and global: the trail records the actions of every
		// role including those above the reader, so it is not something a
		// project-scoped grant should ever confer. See authz.PermAuditRead.
		{Pattern: "GET /api/audit", Handler: s.handleAuditList, Perm: auditRead, Scope: scopeGlobal},
		{Pattern: "GET /api/audit/verify", Handler: s.handleAuditVerify, Perm: auditRead, Scope: scopeGlobal},

		// ── Secrets, grants, and leases ──────────────────────────────
		// Global, and never below maintainer. Reads are gated on
		// secret.grant rather than project.read because the list of which
		// credentials exist, which executor holds them, and what each one
		// may reach is reconnaissance: the roles that cannot broker access
		// have no reason to enumerate it. Deletions and lease revocations
		// take secret.revoke, so an operator can be given the ability to
		// pull a leaked credential without the ability to issue one.
		{Pattern: "GET /api/secrets", Handler: s.handleSecretsList, Perm: secGrant, Scope: scopeGlobal},
		{Pattern: "POST /api/secrets", Handler: s.handleSecretCreate, Perm: secGrant, Scope: scopeGlobal},
		{Pattern: "DELETE /api/secrets/{id}", Handler: s.handleSecretDelete, Perm: secRevoke, Scope: scopeGlobal},
		{Pattern: "GET /api/grants", Handler: s.handleGrantsList, Perm: secGrant, Scope: scopeGlobal},
		{Pattern: "POST /api/grants", Handler: s.handleGrantCreate, Perm: secGrant, Scope: scopeGlobal},
		{Pattern: "DELETE /api/grants/{id}", Handler: s.handleGrantDelete, Perm: secRevoke, Scope: scopeGlobal},
		{Pattern: "GET /api/leases", Handler: s.handleLeasesList, Perm: secGrant, Scope: scopeGlobal},
		{Pattern: "POST /api/leases/{id}/revoke", Handler: s.handleLeaseRevoke, Perm: secRevoke, Scope: scopeGlobal},
	}
}
