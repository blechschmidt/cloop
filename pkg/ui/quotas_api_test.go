package ui

// The HTTP half of Task 20182.
//
// Two things are held down here. First the escalation property that makes the
// whole feature meaningful: a tenant who can reach the hub must not be able to
// raise their own ceiling through *any* route, not merely through the one that
// was written for it. Second the wire contract — a stable QUOTA_EXCEEDED code,
// a Retry-After only where waiting helps — because a scripted client is the
// caller a quota most needs to refuse correctly.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/quota"
)

// installQuotas gives srv an enforcer over an in-memory store.
func installQuotas(t *testing.T, srv *Server, cfg quota.Config) *quota.Enforcer {
	t.Helper()
	resolver, err := quota.New(cfg)
	if err != nil {
		t.Fatalf("quota.New: %v", err)
	}
	e := quota.NewEnforcer(resolver, nil)
	srv.quotaMu.Lock()
	srv.quotaEnforcer = e
	srv.quotaMu.Unlock()
	return e
}

// ── the escalation property ─────────────────────────────────────────────────

// TestNonAdminCannotRaiseOwnQuotaThroughAnyRoute is the test the feature
// exists for.
//
// It does not check the two quota routes by hand — that would only prove the
// routes somebody remembered to check are gated. Instead it walks the whole
// route table and asserts a structural property: every route that could write
// a limit requires user.manage, which the default ladder grants to admin
// alone. A future route that accepts a `limits` body and forgets the gate
// fails here rather than in production.
func TestNonAdminCannotRaiseOwnQuotaThroughAnyRoute(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}

	// Every handler that writes a quota, by name. Adding a writer without
	// adding it here is caught by the completeness check below.
	quotaWriters := map[string]bool{
		"handleQuotaSet":   true,
		"handleQuotaClear": true,
	}

	handlers := handlerNamesByPattern()
	seen := map[string]bool{}
	for _, rs := range srv.routeTable() {
		handler := handlers[rs.Pattern]
		if !quotaWriters[handler] {
			continue
		}
		seen[handler] = true

		method, _ := splitPattern(rs.Pattern)
		perm := rs.permFor(method)
		if perm != authz.PermUserManage {
			t.Errorf("route %q writes a quota but requires %q — anything short of "+
				"user.manage means a tenant can raise their own ceiling, which is "+
				"the same as not having one", rs.Pattern, perm)
		}
		// user.manage must remain admin-only, or the gate above is theatre.
		for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleMaintainer} {
			if roleHasPermission(role, authz.PermUserManage) {
				t.Errorf("role %q holds user.manage — it could raise its own quota via %q",
					role, rs.Pattern)
			}
		}
	}
	for name := range quotaWriters {
		if !seen[name] {
			t.Errorf("handler %s is listed as a quota writer but no route reaches it — "+
				"either it was removed (drop it from this list) or it is registered "+
				"outside the gated route table", name)
		}
	}

	// And no *other* route may accept a limits payload. This is the check
	// that generalises: it reads the source rather than the table, so a
	// handler that quietly grew a quota write is caught even if its route
	// declares something plausible.
	for _, rs := range srv.routeTable() {
		handler := handlers[rs.Pattern]
		if handler == "" || quotaWriters[handler] {
			continue
		}
		body := handlerBody(quotasAPISource+"\n"+serverSource+"\n"+executorsAPISource, handler)
		if body == "" {
			continue // handler lives in a file this test does not embed
		}
		for _, marker := range []string{"SetOverride(", "ClearOverride("} {
			if strings.Contains(body, marker) {
				t.Errorf("route %q (handler %s) calls %s but is not a declared quota "+
					"writer — every path that changes a ceiling must be gated on "+
					"user.manage", rs.Pattern, handler, marker)
			}
		}
	}
}

// roleHasPermission reports whether role's default permission set includes p.
func roleHasPermission(role authz.Role, p authz.Permission) bool {
	for _, have := range role.Permissions() {
		if have == p {
			return true
		}
	}
	return false
}

// TestNonAdminIsRefusedByTheLiveQuotaRoutes is the end-to-end companion: an
// operator signed in through the real OIDC flow gets 403 from both writers and
// from the list, and the enforcer is unchanged afterwards.
func TestNonAdminIsRefusedByTheLiveQuotaRoutes(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.groups = []string{"engineering"}
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.RoleNone,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "engineering", Role: authz.RoleOperator},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	e := installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResProjects: 1}})

	c := jarClient(t)
	login(t, c, ts)

	self := strings.ToLower(idp.email)
	raise := `{"limits":{"max_projects":9999}}`

	// Every shape a tenant might reach for.
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/quotas/" + self, raise},
		{http.MethodPut, "/api/quotas/" + strings.ToUpper(self), raise},
		{http.MethodDelete, "/api/quotas/" + self, ""},
		{http.MethodGet, "/api/quotas", ""},
	} {
		code, body := do(t, c, tc.method, ts.URL+tc.path, tc.body)
		if code != http.StatusForbidden {
			t.Errorf("%s %s as an operator = %d, want 403 (body: %s)",
				tc.method, tc.path, code, body)
		}
	}

	// The ceiling must be exactly what policy says, not what was asked for.
	subj := &authz.Subject{Sub: idp.sub, Email: idp.email, Groups: idp.groups}
	if got, ok := e.Effective(subj).Limit(quota.ResProjects); !ok || got != 1 {
		t.Fatalf("max_projects = (%v, %v) after the escalation attempts, want (1, true)", got, ok)
	}

	// But reading one's own quota is fine — it is scoped by construction and
	// is how a refused user learns why.
	if code, body := do(t, c, http.MethodGet, ts.URL+"/api/quota/me", ""); code != http.StatusOK {
		t.Errorf("GET /api/quota/me as an operator = %d, want 200 (body: %s)", code, body)
	}
}

// TestAdminCanEditQuotasEndToEnd — the other half: the panel has to work for
// the role it was built for, and the edit has to actually bind.
func TestAdminCanEditQuotasEndToEnd(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.groups = []string{"cloop-admins"}
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.RoleNone,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "cloop-admins", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	e := installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResProjects: 1}})

	c := jarClient(t)
	login(t, c, ts)

	if code, body := do(t, c, http.MethodGet, ts.URL+"/api/quotas", ""); code != http.StatusOK {
		t.Fatalf("GET /api/quotas as admin = %d, want 200 (body: %s)", code, body)
	}

	target := "bob@example.com"
	code, body := do(t, c, http.MethodPut, ts.URL+"/api/quotas/"+target,
		`{"limits":{"max_projects":4,"max_concurrent_tasks":null}}`)
	if code != http.StatusOK {
		t.Fatalf("PUT /api/quotas/%s as admin = %d, want 200 (body: %s)", target, code, body)
	}

	bob := &authz.Subject{Email: target}
	if got, ok := e.Effective(bob).Limit(quota.ResProjects); !ok || got != 4 {
		t.Fatalf("bob's max_projects = (%v, %v) after the edit, want (4, true)", got, ok)
	}
	// A null clears rather than caps at zero, which is the difference between
	// "inherit" and "allowed none".
	if got, ok := e.Effective(bob).Limit(quota.ResConcurrentTasks); ok {
		t.Errorf("max_concurrent_tasks resolved to %v after being sent as null, want unset", got)
	}

	if code, body := do(t, c, http.MethodDelete, ts.URL+"/api/quotas/"+target, ""); code != http.StatusOK {
		t.Fatalf("DELETE /api/quotas/%s = %d, want 200 (body: %s)", target, code, body)
	}
	if got, _ := e.Effective(bob).Limit(quota.ResProjects); got != 1 {
		t.Errorf("bob's max_projects = %v after the override was cleared, want the policy's 1", got)
	}

	// An unknown resource must be rejected outright rather than stored and
	// silently ignored — that is how "my quota is not enforced" happens.
	if code, _ := do(t, c, http.MethodPut, ts.URL+"/api/quotas/"+target,
		`{"limits":{"max_widgets":5}}`); code != http.StatusBadRequest {
		t.Errorf("PUT with an unknown resource = %d, want 400", code)
	}
}

// ── the wire contract ───────────────────────────────────────────────────────

// TestQuotaDenialWireContract: one stable code, and a Retry-After exactly
// where waiting is worth anything.
func TestQuotaDenialWireContract(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	e := installQuotas(t, srv, quota.Config{Defaults: quota.Limits{
		quota.ResConcurrentTasks: 0,
		quota.ResProjects:        0,
	}})
	subj := &authz.Subject{Email: "alice@example.com"}

	for _, tc := range []struct {
		res        quota.Resource
		wantStatus int
		wantRetry  bool
	}{
		// A run will finish, so waiting helps: 429 + Retry-After.
		{quota.ResConcurrentTasks, http.StatusTooManyRequests, true},
		// Somebody must delete a project, so waiting does not: 403, no header.
		{quota.ResProjects, http.StatusForbidden, false},
	} {
		_, err := e.Admit(subj, tc.res, 1)
		if err == nil {
			t.Fatalf("%s: admission succeeded against a zero limit", tc.res)
		}
		rr := httptest.NewRecorder()
		srv.writeQuotaDenial(rr, httptest.NewRequest(http.MethodPost, "/api/run", nil), err)

		if rr.Code != tc.wantStatus {
			t.Errorf("%s: status %d, want %d", tc.res, rr.Code, tc.wantStatus)
		}
		retry := rr.Header().Get("Retry-After")
		if tc.wantRetry {
			if retry == "" {
				t.Errorf("%s: no Retry-After on a transient denial", tc.res)
			} else if n, convErr := strconv.Atoi(retry); convErr != nil || n < 1 {
				t.Errorf("%s: Retry-After = %q, want a positive integer", tc.res, retry)
			}
		} else if retry != "" {
			t.Errorf("%s: Retry-After = %q on a denial that waiting cannot clear — "+
				"it trains clients to poll a wall", tc.res, retry)
		}

		var payload struct {
			Error struct {
				Code    string         `json:"code"`
				Message string         `json:"message"`
				Details map[string]any `json:"details"`
			} `json:"error"`
		}
		if uerr := json.Unmarshal(rr.Body.Bytes(), &payload); uerr != nil {
			t.Fatalf("%s: response is not the structured error envelope: %v (body %s)",
				tc.res, uerr, rr.Body.String())
		}
		if payload.Error.Code != string(apierror.CodeQuotaExceeded) {
			t.Errorf("%s: code %q, want %q — the code is the client contract and must "+
				"not vary with the status", tc.res, payload.Error.Code, apierror.CodeQuotaExceeded)
		}
		if got := payload.Error.Details["resource"]; got != string(tc.res) {
			t.Errorf("%s: details.resource = %v, want the resource name", tc.res, got)
		}
		if payload.Error.Message == "" {
			t.Errorf("%s: empty message — a denial the tenant cannot act on is a support ticket", tc.res)
		}
	}
}

// TestQuotaEnforcementIsInertWithoutPolicy is the single-tenant guarantee: a
// hub with no quota config and no OIDC must behave exactly as before.
func TestQuotaEnforcementIsInertWithoutPolicy(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/run", nil)

	// No enforcer at all.
	for i := 0; i < 50; i++ {
		if !srv.admitQuota(rr, req, quota.ResConcurrentTasks, 1) {
			t.Fatalf("admission %d refused on a hub with no quota policy", i)
		}
	}

	// An enforcer with a policy, but a caller with no identity: RBAC is off,
	// so there is no tenant to charge and charging a shared "" identity would
	// let one local user's runs deny another's.
	installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResConcurrentTasks: 1}})
	for i := 0; i < 50; i++ {
		if !srv.admitQuota(rr, req, quota.ResConcurrentTasks, 1) {
			t.Fatalf("admission %d refused for an unidentified caller with OIDC off", i)
		}
	}
}

// ── restart reconciliation ──────────────────────────────────────────────────

// TestReconcileQuotasClearsCountersLeftByACrash exercises the real
// ReconcileQuotas — registry read, executor store, session store — rather than
// the enforcer's Reconcile in isolation.
//
// The scenario is the one that matters: the hub died while runs were in
// flight, so the persisted counters claim slots that no process holds. Nothing
// decrements those, so without reconciliation the tenant is narrowed forever
// and the only symptom is "my runs are refused".
func TestReconcileQuotasClearsCountersLeftByACrash(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	e := installQuotas(t, srv, quota.Config{Defaults: quota.Limits{
		quota.ResConcurrentTasks: 1,
		quota.ResExecutors:       1,
	}})
	subj := &authz.Subject{Email: "alice@example.com"}

	// Pre-crash state: a run and an enrolment are both held.
	if _, err := e.Admit(subj, quota.ResConcurrentTasks, 1); err != nil {
		t.Fatalf("seed run slot: %v", err)
	}
	if _, err := e.Admit(subj, quota.ResExecutors, 1); err != nil {
		t.Fatalf("seed executor slot: %v", err)
	}
	if _, err := e.Admit(subj, quota.ResConcurrentTasks, 1); err == nil {
		t.Fatal("the concurrency cap was not holding before the simulated crash")
	}

	// Restart. Nothing is actually running, nothing is enrolled, and the
	// project registry has no entry owned by alice.
	srv.ReconcileQuotas()

	usage := e.Usage("alice@example.com")
	if usage[quota.ResConcurrentTasks] != 0 {
		t.Errorf("concurrent-task counter is %v after reconciliation, want 0 — "+
			"a slot is held by a process that no longer exists", usage[quota.ResConcurrentTasks])
	}
	if usage[quota.ResExecutors] != 0 {
		t.Errorf("executor counter is %v after reconciliation, want 0 — "+
			"no enrolment record names alice", usage[quota.ResExecutors])
	}
	if _, err := e.Admit(subj, quota.ResConcurrentTasks, 1); err != nil {
		t.Fatalf("admission still refused after reconciliation: %v", err)
	}

	// Deterministic: the same live state yields the same counters, so a
	// second pass neither double-counts nor drifts.
	//
	// Note what this also demonstrates — reconciliation *replaces* the gauge
	// set from ground truth, so the slot admitted just above is discarded
	// too. That is why it runs once, before the listener binds: calling it on
	// a live hub would erase in-flight admissions. See ReconcileQuotas.
	srv.ReconcileQuotas()
	if got := e.Usage("alice@example.com")[quota.ResConcurrentTasks]; got != 0 {
		t.Errorf("concurrent-task counter is %v after a second reconciliation against "+
			"unchanged live state, want 0 — reconciliation must be deterministic", got)
	}
}

// TestReconcileQuotasIsSafeWithoutAPolicy — it runs unconditionally at
// startup, including on the single-tenant hub that has no enforcer at all.
func TestReconcileQuotasIsSafeWithoutAPolicy(t *testing.T) {
	t.Parallel()
	srv := &Server{WorkDir: t.TempDir()}
	srv.ReconcileQuotas() // must not panic on a nil enforcer
}

// ── /metrics ────────────────────────────────────────────────────────────────

// TestMetricsExposesQuotaGauges — the endpoint `cloop ui` did not have.
func TestMetricsExposesQuotaGauges(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	e := installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResProjects: 3}})
	if _, err := e.Admit(&authz.Subject{Email: "alice@example.com"}, quota.ResProjects, 2); err != nil {
		t.Fatalf("admit: %v", err)
	}

	rr := httptest.NewRecorder()
	srv.handleMetrics(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want the Prometheus text exposition format", ct)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`cloop_quota_enforcement_enabled 1`,
		`cloop_quota_limit{identity="alice@example.com",resource="max_projects"} 3`,
		`cloop_quota_usage{identity="alice@example.com",resource="max_projects"} 2`,
		`cloop_quota_denials_total{resource="max_projects"}`,
		`# TYPE cloop_quota_usage gauge`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics is missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// TestMetricsEscapesLabelValues. An identity is attacker-influenced — an IdP
// can release any email — and an unescaped quote there lets a tenant inject
// metric lines into a scrape, which is log injection with extra steps.
func TestMetricsEscapesLabelValues(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	e := installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResProjects: 1}})
	hostile := `evil"} 999
cloop_quota_usage{identity="injected`
	if _, err := e.Admit(&authz.Subject{Sub: hostile}, quota.ResProjects, 1); err != nil {
		t.Fatalf("admit: %v", err)
	}

	rr := httptest.NewRecorder()
	srv.handleMetrics(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()

	if strings.Contains(body, "injected") && strings.Contains(body, "\ncloop_quota_usage{identity=\"injected") {
		t.Fatal("a hostile identity injected a synthetic metric line into the scrape")
	}
	if !strings.Contains(body, `\"`) || !strings.Contains(body, `\n`) {
		t.Errorf("label value was not escaped\n--- body ---\n%s", body)
	}

	// The precise property: the injected "999" may appear *inside* an escaped
	// label value (that is what escaping looks like), but must never be a
	// sample value. Reading the value is what a scraper does, so that is
	// where the check belongs.
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "cloop_quota_") {
			continue
		}
		value := line
		if brace := strings.LastIndex(line, "}"); brace >= 0 {
			value = line[brace+1:]
		}
		if strings.Contains(value, "999") {
			t.Errorf("injected sample value survived escaping: %q", line)
		}
	}
}

// TestMetricsRequiresAuditRead: the payload is a tenant roster and what each
// one spends, so it must not be reachable by a role that cannot read the
// audit trail.
func TestMetricsRequiresAuditRead(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	var found bool
	for _, rs := range srv.routeTable() {
		if rs.Pattern != "GET /metrics" {
			continue
		}
		found = true
		if rs.Perm != authz.PermAuditRead {
			t.Errorf("GET /metrics requires %q, want audit.read — the payload names "+
				"every identity and its spend", rs.Perm)
		}
		if rs.Scope != scopeGlobal {
			t.Errorf("GET /metrics is scoped %v, want global", rs.Scope)
		}
	}
	if !found {
		t.Fatal("GET /metrics is not in the route table")
	}
}
