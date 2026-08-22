package ui

// Per-identity quotas and admission control for the multi-tenant hub
// (Task 20182).
//
// Three things live here: the admission helpers every enforcement point
// calls, the RBAC-gated admin API behind the Quotas panel, and the hub's
// /metrics endpoint.
//
//	GET    /api/quotas             every identity's limits and live usage
//	PUT    /api/quotas/{identity}  set one identity's override
//	DELETE /api/quotas/{identity}  drop the override, back to policy
//	GET    /api/quota/me           the caller's own limits and usage
//	GET    /metrics                Prometheus gauges
//
// # Where enforcement actually happens
//
// Admission is at the point the resource is committed, never in the browser:
//
//	handleRun            → max_concurrent_tasks, plus the daily budgets
//	handleProjectNew     → max_projects
//	handleExecutorEnroll → max_executors
//	oidcauth.createSession → max_sessions (by eviction; see SessionLimitFor)
//
// The frontend hides what it cannot do, as it does for every permission, but
// the panel is a convenience and the gate is the server. A client that skips
// the UI entirely gets the same typed QUOTA_EXCEEDED refusal.
//
// # Why the admin routes cannot raise their own caller's quota
//
// PUT and DELETE are gated on authz.PermUserManage, which the default role
// ladder grants to admin alone. There is no self-service path: no route reads
// a limit out of a request body except these two, and no code outside
// Enforcer.SetOverride writes an override. A tenant who wants more headroom
// has to ask somebody who holds user.manage — which is the whole point of
// having a quota. TestNonAdminCannotRaiseOwnQuota holds this down against
// every route in the table.

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/quotastore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// SetQuotaPolicy installs the resolved quota policy. Called from cmd/ui_cmd.go
// after config is read; a hub that never calls it enforces nothing.
func (s *Server) SetQuotaPolicy(resolver *quota.Resolver) {
	store, err := s.openQuotaStore()
	if err != nil {
		// In-memory fallback rather than no enforcement. A hub whose state
		// database is unreachable should still hold its caps for the life
		// of the process: the failure mode we are avoiding is one tenant
		// starving the rest, and "the DB was down" is not a reason to let
		// that happen. What is lost is only survival across restart, which
		// Reconcile would rebuild anyway for every gauge.
		s.log().Warn(logger.EventAuthz, 0, "quota: persistence unavailable, caps are process-local",
			map[string]interface{}{"error": err.Error()})
		store = nil
	}
	enforcer := quota.NewEnforcer(resolver, store,
		quota.WithStoreErrorHandler(func(err error) {
			s.log().Warn(logger.EventAuthz, 0, "quota: persist counter",
				map[string]interface{}{"error": err.Error()})
		}))
	if err := enforcer.Load(); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "quota: load persisted state",
			map[string]interface{}{"error": err.Error()})
	}
	s.quotaMu.Lock()
	s.quotaEnforcer = enforcer
	s.quotaMu.Unlock()
}

// quotas returns the active enforcer, or nil when no policy was installed.
// Every helper below is nil-safe, so callers never branch on it.
func (s *Server) quotas() *quota.Enforcer {
	s.quotaMu.RLock()
	defer s.quotaMu.RUnlock()
	return s.quotaEnforcer
}

// openQuotaStore opens the control-plane database and wraps it.
//
// The handle is deliberately long-lived and never closed: unlike the
// executor endpoints, which open a connection per request, admission sits on
// the hot path of every run start and login. Opening SQLite per admission
// would put a file open inside the critical section that must stay short for
// concurrent admission to be correct.
func (s *Server) openQuotaStore() (quota.Store, error) {
	db, err := statedb.Open(state.DBPath(s.WorkDir))
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	return quotastore.New(db)
}

// ── the subject a request is accounted against ──────────────────────────────

// quotaSubject returns the identity this request consumes against, or nil
// when there is nothing to account.
//
// The API-token case is the one worth spelling out. A PAT resolves to its
// *minter's* identity, not to the token, so "hit your concurrency cap, mint a
// token, keep going" is not a bypass — it spends the same budget. The token's
// roles are carried along so role-claim quota bindings still apply, which
// means a CI token minted by an engineer is capped by whichever of the two
// limits is tighter.
func (s *Server) quotaSubject(r *http.Request) *authz.Subject {
	g := s.grantFor(r)
	if g == nil {
		return nil
	}
	if g.token != nil {
		if g.token.CreatedBy == "" {
			return nil
		}
		subj := quota.SubjectForIdentity(g.token.CreatedBy)
		subj.Roles = g.token.Roles
		return subj
	}
	if g.bypass != "" {
		// OIDC is off, or the caller used the deployment's own credential.
		// Quotas are a multi-tenancy control and have nothing to say.
		return nil
	}
	return g.subject
}

// admitQuota reserves n units of res for the request's identity. It returns
// true when the caller may proceed; otherwise it has already written the
// response and the handler must return immediately.
func (s *Server) admitQuota(w http.ResponseWriter, r *http.Request, res quota.Resource, n float64) bool {
	e := s.quotas()
	if e == nil {
		return true
	}
	subject := s.quotaSubject(r)
	if subject == nil {
		return true
	}
	if _, err := e.Admit(subject, res, n); err != nil {
		s.writeQuotaDenial(w, r, err)
		return false
	}
	return true
}

// admitSpend refuses a request whose identity has already spent its daily
// budget. Separate from admitQuota because there is nothing to reserve: the
// cost of a run is unknown until it has run, so the gate is "has this tenant
// already blown its budget?" and the accounting happens afterwards in
// RecordQuotaSpend.
func (s *Server) admitSpend(w http.ResponseWriter, r *http.Request) bool {
	e := s.quotas()
	if e == nil {
		return true
	}
	subject := s.quotaSubject(r)
	if subject == nil {
		return true
	}
	if err := e.CheckSpend(subject); err != nil {
		s.writeQuotaDenial(w, r, err)
		return false
	}
	return true
}

// releaseQuota returns a gauge reservation. Safe to call with an empty
// identity, which is what every non-quota'd request produces.
func (s *Server) releaseQuota(identity string, res quota.Resource, n float64) {
	if e := s.quotas(); e != nil {
		e.Release(identity, res, n)
	}
}

// quotaIdentity returns the identity string a request accounts against, for
// the deferred release that outlives the request.
func (s *Server) quotaIdentity(r *http.Request) string {
	subj := s.quotaSubject(r)
	if subj == nil {
		return ""
	}
	return subj.Label()
}

// RecordQuotaSpend books token and dollar consumption against an identity.
// Exported so the run-accounting path can call it once a run reports cost.
func (s *Server) RecordQuotaSpend(identity string, tokens, usd float64) {
	if e := s.quotas(); e != nil {
		e.Spend(identity, tokens, usd)
	}
}

// writeQuotaDenial renders a *quota.Denial as the wire contract.
//
// One stable code, two statuses. 429 with Retry-After when waiting alone
// clears the denial (a concurrency slot frees, a UTC day rolls over); 403
// with no Retry-After when it does not (projects, executors and sessions stay
// held until somebody removes one or raises the cap). Sending a Retry-After
// that will never come true trains clients to poll a wall.
func (s *Server) writeQuotaDenial(w http.ResponseWriter, r *http.Request, err error) {
	denial, ok := err.(*quota.Denial)
	if !ok {
		apierror.WriteFromError(w, err)
		return
	}

	details := map[string]any{
		"resource":  string(denial.Resource),
		"limit":     denial.Limit,
		"used":      denial.Used,
		"identity":  denial.Identity,
		"source":    denial.Source,
		"transient": denial.Transient(),
	}
	if denial.Requested > 0 {
		details["requested"] = denial.Requested
	}

	e := apierror.New(apierror.CodeQuotaExceeded, quotaDenialMessage(denial)).
		WithDetails(details).
		WithCause(denial)

	if denial.Transient() {
		secs := int(math.Ceil(denial.RetryAfter.Seconds()))
		if secs < 1 {
			secs = 1
		}
		details["retry_after_seconds"] = secs
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	} else {
		e = e.WithStatus(http.StatusForbidden)
	}

	s.auditQuotaDenial(r, denial)
	apierror.WriteError(w, e)
}

// quotaDenialMessage explains the refusal in the terms the tenant can act on.
// A quota message that only states the number is a support ticket; one that
// names the remedy is not.
func quotaDenialMessage(d *quota.Denial) string {
	switch d.Resource {
	case quota.ResConcurrentTasks:
		return fmt.Sprintf("you already have %.0f of %.0f runs in progress — "+
			"wait for one to finish, or ask an administrator to raise your concurrency quota",
			d.Used, d.Limit)
	case quota.ResProjects:
		return fmt.Sprintf("you own %.0f of %.0f permitted projects — "+
			"delete one, or ask an administrator to raise your project quota", d.Used, d.Limit)
	case quota.ResExecutors:
		return fmt.Sprintf("you have enrolled %.0f of %.0f permitted executors — "+
			"revoke one, or ask an administrator to raise your executor quota", d.Used, d.Limit)
	case quota.ResSessions:
		return fmt.Sprintf("you hold %.0f of %.0f permitted sessions", d.Used, d.Limit)
	case quota.ResDailyTokens:
		return fmt.Sprintf("your daily token budget is spent (%.0f of %.0f) — "+
			"it resets at 00:00 UTC", d.Used, d.Limit)
	case quota.ResDailyCostUSD:
		return fmt.Sprintf("your daily cost budget is spent ($%.2f of $%.2f) — "+
			"it resets at 00:00 UTC", d.Used, d.Limit)
	}
	return d.Error()
}

// auditQuotaDenial records the refusal.
//
// Denials are audited, always. A quota that silently refuses work is
// indistinguishable from a hub that is broken, and the trail is where an
// operator answers "why did this tenant stop being able to run anything?"
// without needing to have been watching /metrics at the time.
func (s *Server) auditQuotaDenial(r *http.Request, d *quota.Denial) {
	path, method := "", ""
	if r != nil {
		method = r.Method
		if r.URL != nil {
			path = r.URL.Path
		}
	}
	s.auditQuotaEvent(d.Identity, "quota.denied", string(d.Resource), map[string]any{
		"limit":     d.Limit,
		"used":      d.Used,
		"requested": d.Requested,
		"source":    d.Source,
		"transient": d.Transient(),
		"method":    method,
		"path":      path,
	})
}

// auditQuotaEvent appends one record to the hub's own journal. Quota events
// are fleet-level rather than project-level — a cap is a property of an
// identity across the whole hub — so they land in s.WorkDir's log, next to
// the executor and token lifecycle records an auditor reads alongside them.
//
// Best-effort, matching every other emitter: a wedged journal must not turn a
// refusal into an admission, nor block an admin from editing a quota.
func (s *Server) auditQuotaEvent(actor, eventType, entityID string, payload map[string]any) {
	if actor == "" {
		actor = "anonymous"
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return
	}
	log, err := eventlog.Open(s.WorkDir)
	if err != nil {
		if err != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "quota audit: open event log",
				map[string]interface{}{"error": err.Error()})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  eventType,
		EntityType: "quota",
		EntityID:   entityID,
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "quota audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}

// ── startup reconciliation ──────────────────────────────────────────────────

// ReconcileQuotas rebuilds every gauge counter from live state.
//
// Called once at startup, and this is the load-bearing half of the design.
// A persisted counter is a claim about the world that nothing corrects: a hub
// killed while three runs were in flight comes back believing that tenant
// still holds three slots, and no code path decrements a counter for a
// process that no longer exists. Left alone, a crash permanently narrows the
// tenant it happened to and the only symptom is "my runs are refused".
//
// So the counters are treated as a cache and rebuilt from the things that
// actually exist: the project registry, the enrolment records, the session
// table, and the projects whose persisted state says a run is in progress.
// Daily spend is deliberately not rebuilt — see pkg/quota.
//
// Startup only. This *replaces* the gauge set rather than adjusting it, so
// calling it on a live hub would erase in-flight admissions — a run started
// two seconds ago has no representation in any of the sources read below
// until its project's state file says "running". cmd/ui_cmd.go therefore
// calls it once, synchronously, before the listener binds.
func (s *Server) ReconcileQuotas() {
	e := s.quotas()
	if e == nil {
		return
	}
	live := quota.LiveState{
		Projects:  make(map[string]float64),
		Tasks:     make(map[string]float64),
		Executors: make(map[string]float64),
		Sessions:  make(map[string]float64),
	}

	entries := s.allProjectEntries()
	for _, entry := range entries {
		if entry.Owner == "" {
			continue // shared project: owned by the deployment, not a tenant
		}
		live.Projects[entry.Owner]++

		// A run in flight is attributed to the project's owner. That is the
		// only attribution derivable after a restart — the identity that
		// pressed Run did not survive the process — and it is the right one:
		// the owner is who the run's spend lands on either way.
		if st, err := state.LoadLite(entry.Path); err == nil && st != nil {
			if st.Status == "running" || st.Status == "evolving" {
				live.Tasks[entry.Owner]++
			}
		}
	}

	// Executors are counted from the enrollment records rather than from the
	// executors table, because the enrollment is where the minting identity
	// is recorded — ExecutorRow.EnrolledBy holds a token id, not a person.
	// It also counts the right thing: the reservation is taken at mint, so
	// a token that has been issued but not yet redeemed is already spent
	// against the cap. Otherwise a tenant could stockpile credentials
	// against a limit that only sees connected devices.
	if db, err := statedb.Open(state.DBPath(s.WorkDir)); err == nil {
		if store, serr := executorstore.New(db); serr == nil {
			agents := make(map[string]bool)
			if list, lerr := store.ListAgents(); lerr == nil {
				for _, a := range list {
					agents[a.AgentID] = !a.Revoked()
				}
			}
			now := time.Now()
			for _, rec := range enrollmentsOrNil(store) {
				if rec.CreatedBy == "" || rec.Revoked() {
					continue
				}
				if rec.Redeemed() {
					// Still held only while the device it minted is live.
					if agents[rec.RedeemedAgentID] {
						live.Executors[rec.CreatedBy]++
					}
					continue
				}
				// Unredeemed: held until the token lapses.
				if !rec.Expired(now) {
					live.Executors[rec.CreatedBy]++
				}
			}
		}
		_ = db.Close()
	}

	if s.OIDC != nil {
		if sessions, err := s.OIDC.ListSessions(); err == nil {
			for _, rec := range sessions {
				if key := rec.Identity.OwnerKey(); key != "" {
					live.Sessions[key]++
				}
			}
		}
	}

	if err := e.Reconcile(live); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "quota: reconcile from live state",
			map[string]interface{}{"error": err.Error()})
		return
	}
	s.log().Info(logger.EventAuthz, 0, "quota: reconciled from live state",
		map[string]interface{}{
			"identities_with_projects":  len(live.Projects),
			"identities_with_runs":      len(live.Tasks),
			"identities_with_executors": len(live.Executors),
			"identities_with_sessions":  len(live.Sessions),
		})
}

// SessionLimitFor reports how many sessions identity may hold, for the
// eviction hook in pkg/oidcauth. Zero means unlimited.
//
// Sessions are the one resource enforced by evicting the oldest rather than
// refusing the newest, because refusing a login is a lockout: the user ends
// up with no session, and the self-service remedy (POST
// /api/session/logout-all) needs one. Eviction preserves the invariant the
// cap exists for without ever locking anyone out of their own account.
func (s *Server) SessionLimitFor(identity string, groups, roles []string) int {
	e := s.quotas()
	if e == nil || identity == "" {
		return 0
	}
	subj := quota.SubjectForIdentity(identity)
	subj.Groups, subj.Roles = groups, roles
	limit, ok := e.Effective(subj).Limits.Get(quota.ResSessions)
	if !ok || limit <= 0 {
		return 0
	}
	return int(limit)
}

// ── the admin API ───────────────────────────────────────────────────────────

type quotaView struct {
	Identity   string             `json:"identity"`
	Limits     map[string]float64 `json:"limits"`
	Usage      map[string]float64 `json:"usage"`
	Sources    map[string]string  `json:"sources,omitempty"`
	Overridden bool               `json:"overridden"`
}

func renderQuotaView(v quota.View) quotaView {
	out := quotaView{
		Identity:   v.Identity,
		Limits:     make(map[string]float64, len(v.Limits)),
		Usage:      make(map[string]float64, len(v.Usage)),
		Sources:    make(map[string]string, len(v.Sources)),
		Overridden: v.Overridden,
	}
	for res, limit := range v.Limits {
		out.Limits[string(res)] = limit
	}
	for res, used := range v.Usage {
		out.Usage[string(res)] = used
	}
	for res, src := range v.Sources {
		out.Sources[string(res)] = src
	}
	return out
}

// handleQuotasList serves GET /api/quotas.
func (s *Server) handleQuotasList(w http.ResponseWriter, r *http.Request) {
	e := s.quotas()
	if e == nil {
		jsonOK(w, map[string]interface{}{
			"enabled":   false,
			"quotas":    []quotaView{},
			"resources": quotaResourceNames(),
			"notice": "No quota policy is configured. Set ui.quotas in .cloop/config.yaml, " +
				"or edit one identity below to cap it individually.",
		})
		return
	}

	// The registry knows about owners who have never made a request, so a
	// freshly restarted hub still lists every tenant rather than only those
	// who happen to have been active since boot.
	var known []string
	for _, entry := range s.allProjectEntries() {
		if entry.Owner != "" {
			known = append(known, entry.Owner)
		}
	}
	if s.OIDC != nil {
		if sessions, err := s.OIDC.ListSessions(); err == nil {
			for _, rec := range sessions {
				if key := rec.Identity.OwnerKey(); key != "" {
					known = append(known, key)
				}
			}
		}
	}

	snapshot := e.Snapshot(known)
	views := make([]quotaView, 0, len(snapshot))
	for _, v := range snapshot {
		views = append(views, renderQuotaView(v))
	}
	jsonOK(w, map[string]interface{}{
		"enabled":   true,
		"quotas":    views,
		"resources": quotaResourceNames(),
	})
}

// handleQuotaMe serves GET /api/quota/me: the caller's own limits and usage.
//
// Ungated on purpose, like POST /api/session/logout-all. Seeing your own
// ceiling is never an escalation, and a tenant who cannot see why a run was
// refused files a support ticket instead of waiting for the counter to fall.
func (s *Server) handleQuotaMe(w http.ResponseWriter, r *http.Request) {
	e := s.quotas()
	subject := s.quotaSubject(r)
	if e == nil || subject == nil {
		jsonOK(w, map[string]interface{}{"enabled": false})
		return
	}
	view := renderQuotaView(e.ViewFor(subject))
	jsonOK(w, map[string]interface{}{"enabled": true, "quota": view})
}

type quotaUpdateRequest struct {
	// Limits is sparse: only the resources named are set. A resource mapped
	// to null (or a negative number) is cleared, returning it to policy.
	Limits map[string]*float64 `json:"limits"`
}

// handleQuotaSet serves PUT /api/quotas/{identity}.
func (s *Server) handleQuotaSet(w http.ResponseWriter, r *http.Request) {
	e := s.quotas()
	if e == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"quota enforcement is not initialised on this hub"))
		return
	}
	identity := strings.TrimSpace(r.PathValue("identity"))
	if identity == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "identity is required"))
		return
	}

	var req quotaUpdateRequest
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"invalid JSON body: "+err.Error()))
		return
	}

	limits := make(quota.Limits, len(req.Limits))
	for name, value := range req.Limits {
		res := quota.Resource(strings.ToLower(strings.TrimSpace(name)))
		if !res.Valid() {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
				fmt.Sprintf("unknown quota resource %q", name)).
				WithDetails(map[string]any{"valid": quotaResourceNames()}))
			return
		}
		if value == nil || *value < 0 {
			continue // cleared: falls back to configured policy
		}
		if math.IsNaN(*value) || math.IsInf(*value, 0) {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
				fmt.Sprintf("%s must be a finite number", name)))
			return
		}
		limits[res] = *value
	}

	actor := s.grantFor(r).subjectLabel()
	if err := e.SetOverride(identity, limits, actor); err != nil {
		apierror.WriteFromError(w, err)
		return
	}
	s.auditQuotaChange(r, identity, "quota.override_set", limits)

	subj := quota.SubjectForIdentity(identity)
	jsonOK(w, map[string]interface{}{"ok": true, "quota": renderQuotaView(e.ViewFor(subj))})
}

// handleQuotaClear serves DELETE /api/quotas/{identity}.
func (s *Server) handleQuotaClear(w http.ResponseWriter, r *http.Request) {
	e := s.quotas()
	if e == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"quota enforcement is not initialised on this hub"))
		return
	}
	identity := strings.TrimSpace(r.PathValue("identity"))
	if identity == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "identity is required"))
		return
	}
	existed, err := e.ClearOverride(identity)
	if err != nil {
		apierror.WriteFromError(w, err)
		return
	}
	if !existed {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"no quota override exists for this identity"))
		return
	}
	s.auditQuotaChange(r, identity, "quota.override_cleared", nil)
	jsonOK(w, map[string]interface{}{"ok": true})
}

func (s *Server) auditQuotaChange(r *http.Request, identity, event string, limits quota.Limits) {
	payload := map[string]any{"target": identity}
	for res, v := range limits {
		payload[string(res)] = v
	}
	s.auditQuotaEvent(s.grantFor(r).subjectLabel(), event, identity, payload)
}

// enrollmentsOrNil lists enrollment records, swallowing the error: a
// reconciliation that cannot read one input should reconcile the rest rather
// than leave every gauge at whatever a crash left behind.
func enrollmentsOrNil(store *executorstore.Store) []remote.EnrollmentRecord {
	list, err := store.ListEnrollments()
	if err != nil {
		return nil
	}
	return list
}

// firstNonEmpty returns the first non-blank string, for the "prefer the quota
// identity, fall back to the audit actor" pattern.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func quotaResourceNames() []string {
	out := make([]string, 0, len(quota.AllResources))
	for _, r := range quota.AllResources {
		out = append(out, string(r))
	}
	return out
}

// ── /metrics ────────────────────────────────────────────────────────────────

// handleMetrics serves GET /metrics in Prometheus text exposition format.
//
// `cloop ui` served no metrics at all before this; `cloop serve` served only
// a replay of a static .cloop/metrics.json, which says nothing about the hub
// and nothing about tenants. A quota that nobody can graph is a quota nobody
// notices saturating, so the gauges are the point of the endpoint.
//
// Gated on audit.read rather than left open. The payload names every signed-in
// identity and what each one spends — that is oversight-grade data of exactly
// the class the audit trail carries, and a wide-open /metrics on a hosted hub
// is a tenant roster for anyone who can reach the port. A Prometheus scraper
// authenticates with an API token holding a role that grants it.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder

	e := s.quotas()
	b.WriteString("# HELP cloop_quota_enforcement_enabled Whether a per-identity quota policy is in force.\n")
	b.WriteString("# TYPE cloop_quota_enforcement_enabled gauge\n")
	if e != nil && e.Enabled() {
		b.WriteString("cloop_quota_enforcement_enabled 1\n")
	} else {
		b.WriteString("cloop_quota_enforcement_enabled 0\n")
	}

	if e != nil {
		var known []string
		for _, entry := range s.allProjectEntries() {
			if entry.Owner != "" {
				known = append(known, entry.Owner)
			}
		}
		snapshot := e.Snapshot(known)

		b.WriteString("\n# HELP cloop_quota_limit Configured ceiling per identity and resource.\n")
		b.WriteString("# TYPE cloop_quota_limit gauge\n")
		for _, v := range snapshot {
			for _, res := range quota.AllResources {
				if limit, ok := v.Limits.Get(res); ok {
					writeGauge(&b, "cloop_quota_limit", v.Identity, string(res), limit)
				}
			}
		}

		b.WriteString("\n# HELP cloop_quota_usage Live consumption per identity and resource.\n")
		b.WriteString("# TYPE cloop_quota_usage gauge\n")
		for _, v := range snapshot {
			for _, res := range quota.AllResources {
				writeGauge(&b, "cloop_quota_usage", v.Identity, string(res), v.Usage[res])
			}
		}

		b.WriteString("\n# HELP cloop_quota_denials_total Admission refusals since this hub started.\n")
		b.WriteString("# TYPE cloop_quota_denials_total counter\n")
		denials := e.Denials()
		for _, res := range quota.AllResources {
			b.WriteString(fmt.Sprintf("cloop_quota_denials_total{resource=%q} %d\n",
				string(res), denials[res]))
		}

		b.WriteString("\n# HELP cloop_quota_identities Identities the hub is currently accounting.\n")
		b.WriteString("# TYPE cloop_quota_identities gauge\n")
		b.WriteString(fmt.Sprintf("cloop_quota_identities %d\n", len(snapshot)))
	}

	// Fleet-level context a quota alert needs to be actionable: how many
	// projects and executors exist at all.
	entries := s.allProjectEntries()
	b.WriteString("\n# HELP cloop_projects_registered Projects in the hub registry.\n")
	b.WriteString("# TYPE cloop_projects_registered gauge\n")
	b.WriteString(fmt.Sprintf("cloop_projects_registered %d\n", len(entries)))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// writeGauge emits one sample. Label values are escaped per the exposition
// format: an identity is user-influenced (an IdP can release any email), and
// an unescaped quote or newline there would let a tenant inject metric lines
// into a scrape — the metrics equivalent of log injection.
func writeGauge(b *strings.Builder, name, identity, resource string, value float64) {
	fmt.Fprintf(b, "%s{identity=\"%s\",resource=\"%s\"} %s\n",
		name, escapeLabelValue(identity), escapeLabelValue(resource), formatMetricValue(value))
}

func escapeLabelValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

func formatMetricValue(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
