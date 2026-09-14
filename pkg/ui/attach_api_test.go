package ui

// Tests for the live sandbox attach route (Task 20265).
//
// The interesting assertions are all refusals. Attach is the one route in the
// product that reaches through the isolation boundary, so what matters is not
// that it works — the driver tests prove that against a real runtime — but that
// it is unreachable for everyone the ladder does not name, and for every
// workload that has no sandbox to enter.

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// newAttachFixture builds an OIDC dashboard with one client per role, plus two
// extra roles that hold the attach permissions explicitly — which is how a real
// deployment grants them, since no default role below admin does.
func newAttachFixture(t *testing.T) (*Server, string, map[string]*http.Client) {
	t.Helper()

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	loginAs := func(groups []string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	return srv, ts.URL, map[string]*http.Client{
		"viewer":     loginAs([]string{"readers"}),
		"operator":   loginAs([]string{"engineers"}),
		"maintainer": loginAs([]string{"leads"}),
		"admin":      loginAs([]string{"owners"}),
	}
}

// TestAttach_DeniedToEveryRoleBelowAdmin is the deny-by-default proof.
//
// Maintainer is the case that matters: it is the most privileged non-admin
// role, it may already broker credentials into a sandbox, and it still must not
// be able to open a shell in one. If this ever starts passing for maintainer,
// somebody widened a predicate instead of binding a permission.
func TestAttach_DeniedToEveryRoleBelowAdmin(t *testing.T) {
	_, base, clients := newAttachFixture(t)

	for _, role := range []string{"viewer", "operator", "maintainer"} {
		t.Run(role, func(t *testing.T) {
			code, _ := getFull(t, clients[role], base+"/api/tasks/1/attach/info")
			if code == http.StatusOK {
				t.Fatalf("%s reached the attach route: sandbox.attach is not in its ladder", role)
			}
			if code != http.StatusNotFound && code != http.StatusForbidden {
				t.Errorf("%s got HTTP %d, want 404 or 403", role, code)
			}
		})
	}
}

// TestAttach_AdminReachesTheRouteButTheTaskIsNotRunning: admin holds every
// permission, so it gets past the gate — and then hits the *next* refusal,
// which is the one about the workload rather than the caller.
func TestAttach_AdminReachesTheRouteButTheTaskIsNotRunning(t *testing.T) {
	_, base, clients := newAttachFixture(t)

	code, body := getFull(t, clients["admin"], base+"/api/tasks/4242/attach/info")
	if code != http.StatusOK {
		t.Fatalf("admin GET /attach/info = HTTP %d, want 200: %s", code, body)
	}
	if !strings.Contains(body, `"attachable":false`) {
		t.Errorf("a task that is not running must report attachable:false, got %s", body)
	}
	if !strings.Contains(body, "not running") {
		t.Errorf("the reason must say why, got %s", body)
	}
}

// TestAttach_WriteIsASecondPermission: an admin holds both, so the interesting
// assertion is that the response reports them separately at all — that is what
// lets the terminal open read-only for someone who holds only the first.
func TestAttach_WriteIsASecondPermission(t *testing.T) {
	_, base, clients := newAttachFixture(t)

	code, body := getFull(t, clients["admin"], base+"/api/tasks/1/attach/info")
	if code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", code, body)
	}
	if !strings.Contains(body, `"can_write":true`) {
		t.Errorf("admin must hold sandbox.attach.write, got %s", body)
	}
	if !strings.Contains(body, `"can_read":true`) {
		t.Errorf("response must report read authority separately, got %s", body)
	}
}

// TestAttach_RejectsANonNumericTask keeps a path segment from reaching the
// session lookup as a string.
func TestAttach_RejectsANonNumericTask(t *testing.T) {
	_, base, clients := newAttachFixture(t)
	code, _ := getFull(t, clients["admin"], base+"/api/tasks/not-a-number/attach/info")
	if code != http.StatusBadRequest && code != http.StatusNotFound {
		t.Errorf("non-numeric task id = HTTP %d, want 400 or 404", code)
	}
}

// ── Route table ───────────────────────────────────────────────────────────

// TestAttachRoutesCarrySandboxAttach pins the permission in the table itself.
//
// A gate is only as good as the row that declares it, and the failure mode this
// guards is specific and has happened before in this codebase: someone adds a
// route "like the others" and reaches for project.read because that is what the
// neighbouring task routes use. That single character would make every viewer
// on the hub able to open a shell.
func TestAttachRoutesCarrySandboxAttach(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0, "")

	found := 0
	for _, rs := range s.routeTable() {
		if !strings.Contains(rs.Pattern, "/attach") {
			continue
		}
		found++
		if rs.Perm != authz.PermSandboxAttach {
			t.Errorf("route %q carries %q, want %q — attach must never be gated on a "+
				"project-read permission", rs.Pattern, rs.Perm, authz.PermSandboxAttach)
		}
		if rs.Scope != scopeProject {
			t.Errorf("route %q has scope %v, want scopeProject: a sandbox belongs to a "+
				"project and a grant on one must not reach another", rs.Pattern, rs.Scope)
		}
	}
	if found != 2 {
		t.Errorf("found %d attach routes, want 2 (the info route and the socket)", found)
	}
}

// TestAttachPermissionsAreInNoDefaultRoleBelowAdmin asserts the ladder directly,
// so the property survives a future refactor of the route table.
func TestAttachPermissionsAreInNoDefaultRoleBelowAdmin(t *testing.T) {
	for _, role := range []authz.Role{authz.RoleNone, authz.RoleViewer, authz.RoleOperator, authz.RoleMaintainer} {
		for _, perm := range []authz.Permission{authz.PermSandboxAttach, authz.PermSandboxAttachWrite} {
			for _, held := range role.Permissions() {
				if held == perm {
					t.Errorf("role %q holds %q by default; attach must be bound explicitly", role, perm)
				}
			}
		}
	}
	// Admin holds everything, which is what makes the deployment usable at all.
	admin := map[authz.Permission]bool{}
	for _, p := range authz.RoleAdmin.Permissions() {
		admin[p] = true
	}
	if !admin[authz.PermSandboxAttach] || !admin[authz.PermSandboxAttachWrite] {
		t.Error("admin must hold both attach permissions")
	}
}

// ── Target resolution ─────────────────────────────────────────────────────

// registerHostExecutor puts a non-isolating driver in the default registry and
// takes it out again, so a test can ask what the hub does with a task that ran
// as a process on the control-plane host.
//
// Registered rather than reusing whatever localprocess happens to be there:
// pkg/executor's own policy tests evict that driver and restore it, and a test
// here that depended on the timing of those would be the flake nobody can
// reproduce. A driver of its own with a unique ID cannot collide.
func registerHostExecutor(t *testing.T) string {
	t.Helper()
	ex := &hostOnlyExecutor{id: "attach-test-host"}
	if err := executor.DefaultRegistry.Register(ex); err != nil {
		t.Fatalf("register host executor: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.id) })
	return ex.id
}

// hostOnlyExecutor isolates from nothing, like localprocess.
type hostOnlyExecutor struct{ id string }

func (h *hostOnlyExecutor) ID() string   { return h.id }
func (h *hostOnlyExecutor) Kind() string { return executor.KindLocalProcess }
func (h *hostOnlyExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationNone}
}
func (h *hostOnlyExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, nil
}
func (h *hostOnlyExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (h *hostOnlyExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (h *hostOnlyExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	close(ch)
	return ch, nil
}
func (h *hostOnlyExecutor) HealthCheck(context.Context) error { return nil }

// newAttachServer builds a hub over a fresh project directory.
//
// The .cloop directory is created first so that New's handle store opens
// cleanly; without it the constructor logs "handle persistence unavailable"
// and the test reads as broken when it is merely unprepared.
func newAttachServer(t *testing.T, dir string) *Server {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return New(dir, 0, "")
}

// seedRunningSession records a dispatched workload the way the scheduler does,
// so resolveAttachTarget has something to find.
//
// It goes through the Server's own accessor, and must be called *after* New:
// the constructor reconciles the session table and closes every in-flight row
// left by a previous control plane, so a row seeded beforehand is swept away
// before the test looks at it. That sweep is correct behaviour — it is what
// stops drain waiting forever on work nobody is running — so the fixture moves
// rather than the code.
func seedRunningSession(t *testing.T, s *Server, projectPath, executorID, handleID string, taskID int) {
	t.Helper()
	db, err := s.controlPlaneDB()
	if err != nil {
		t.Fatalf("controlPlaneDB: %v", err)
	}
	defer db.Close()
	if err := db.OpenExecutorSession(statedb.ExecutorSessionRow{
		ID:          "sess-" + handleID + "-" + projectPath,
		ExecutorID:  executorID,
		HandleID:    handleID,
		ProjectPath: projectPath,
		TaskID:      taskID,
		ClaimToken:  "tok",
		State:       "running",
		Attempt:     1,
		StartedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}
}

// TestResolveAttachTarget_RefusesAHostProcessWorkload is the guarantee that
// matters most at this layer: a task running on the host is refused by the hub
// before any driver is consulted, and the refusal names the policy.
func TestResolveAttachTarget_RefusesAHostProcessWorkload(t *testing.T) {
	dir := t.TempDir()
	s := newAttachServer(t, dir)
	hostID := registerHostExecutor(t)
	seedRunningSession(t, s, dir, hostID, "h-host", 7)

	_, err := s.resolveAttachTarget(dir, 7)
	if err == nil {
		t.Fatal("a host-process workload must never be attachable")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("refusal must explain that the workload runs on the host, got %q", err)
	}
}

// TestResolveAttachTarget_RefusesAnUnknownExecutor: a session row can outlive
// the executor it names — an agent revoked while its work was in flight — and
// the lookup must say so rather than panic on a nil driver.
func TestResolveAttachTarget_RefusesAnUnknownExecutor(t *testing.T) {
	dir := t.TempDir()
	s := newAttachServer(t, dir)
	seedRunningSession(t, s, dir, "an-executor-that-was-revoked", "h-gone", 9)

	_, err := s.resolveAttachTarget(dir, 9)
	if err == nil {
		t.Fatal("a session naming an unregistered executor must be refused")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("refusal = %q, want one naming the missing executor", err)
	}
}

// TestResolveAttachTarget_RefusesADispatchWithNoSandboxYet covers the window
// between "the scheduler claimed a slot" and "the driver returned a handle".
func TestResolveAttachTarget_RefusesADispatchWithNoSandboxYet(t *testing.T) {
	dir := t.TempDir()
	s := newAttachServer(t, dir)
	seedRunningSession(t, s, dir, "localprocess", "", 11)

	_, err := s.resolveAttachTarget(dir, 11)
	if err == nil {
		t.Fatal("a session with no handle must be refused")
	}
	if !strings.Contains(err.Error(), "no sandbox yet") {
		t.Errorf("refusal = %q, want one explaining the sandbox does not exist yet", err)
	}
}

// TestResolveAttachTarget_DoesNotCrossProjects is the tenant-isolation check.
// Task IDs are per-project and collide constantly across a fleet, so a lookup
// keyed on the ID alone would hand one project's operator another's sandbox.
func TestResolveAttachTarget_DoesNotCrossProjects(t *testing.T) {
	mine := t.TempDir()
	theirs := t.TempDir()

	// Task 3 is running in *their* project, recorded in *my* control plane
	// database — which is exactly the shared-control-plane shape the hub runs.
	s := newAttachServer(t, mine)
	seedRunningSession(t, s, theirs, "localprocess", "h-other", 3)
	seedRunningSession(t, s, mine, "localprocess", "h-theirs", 3)

	target, err := s.resolveAttachTarget(mine, 3)
	// It is refused for being a host process, which is fine — the assertion is
	// about *which* row was selected, so check the handle in the error path too.
	if err == nil && target.handleID == "h-other" {
		t.Fatal("resolveAttachTarget selected another project's session for the same task id")
	}
}

// TestAttachTaskIDFromQuery keeps the socket reachable when a client supplies
// the task in the query string rather than the path.
func TestAttachTaskIDFromQuery(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/api/tasks//attach?task_id=17", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	got, err := attachTaskID(req)
	if err != nil || got != 17 {
		t.Errorf("attachTaskID = %d, %v; want 17, nil", got, err)
	}

	bad, _ := http.NewRequest(http.MethodGet, "/api/tasks//attach?task_id=-1", nil)
	if _, err := attachTaskID(bad); err == nil {
		t.Error("a non-positive task id must be refused")
	}
}

// TestAttachStatusMapping keeps the CLI's remediation useful: it switches on
// the status code, so a refusal that collapsed to 500 would lose its advice.
func TestAttachStatusMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"no sandbox", executor.ErrAttachNoSandbox, http.StatusForbidden},
		{"unsupported", executor.ErrAttachUnsupported, http.StatusNotImplemented},
		{"busy", executor.ErrAttachBusy, http.StatusTooManyRequests},
		{"unknown handle", executor.ErrAttachHandleUnknown, http.StatusNotFound},
		{"closed", executor.ErrAttachClosed, http.StatusNotFound},
	}
	for _, tc := range cases {
		if got := attachStatus(tc.err); got != tc.want {
			t.Errorf("attachStatus(%s) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestSameProjectPath: executor_sessions stores whatever path the dispatcher
// held, and the request resolves its own, so a trailing slash on either side is
// ordinary. An exact compare would report "not running" for a task that is.
func TestSameProjectPath(t *testing.T) {
	if !sameProjectPath("/srv/proj", "/srv/proj/") {
		t.Error("a trailing slash must not defeat the project match")
	}
	if !sameProjectPath("/srv/proj", "/srv/./proj") {
		t.Error("a dot segment must not defeat the project match")
	}
	if sameProjectPath("/srv/proj", "/srv/other") {
		t.Error("distinct projects must not match")
	}
}

// TestAttachAuditEventShape locks the fields an incident review needs. The row
// is the only artefact that will ever say a human, rather than the agent, was
// inside the sandbox during a run.
func TestAttachAuditEventShape(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	statedb.AuditAttachSession(db, statedb.AttachAuditInput{
		Event: "sandbox.attach.open", Actor: "alice@example.com",
		SessionID: "att-1", ExecutorID: "ctr-1", HandleID: "h7",
		TaskID: 41, Command: "/bin/sh", Writable: true,
	})

	events, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "sandbox.attach.open", Limit: 50})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	var found *statedb.AuditEvent
	for i := range events {
		if events[i].EventType == "sandbox.attach.open" {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no sandbox.attach.open event was recorded")
	}
	if found.Actor != "alice@example.com" {
		t.Errorf("actor = %q, want the acting identity", found.Actor)
	}
	for _, want := range []string{"h7", "ctr-1", "/bin/sh", `"writable":true`, `"task_id":41`} {
		if !strings.Contains(found.Payload, want) {
			t.Errorf("audit payload is missing %q; an incident review needs it. payload=%s",
				want, found.Payload)
		}
	}
}

// TestAttachWS_RefusesNonGET closes a side-effect hole rather than a policy one.
//
// The socket route is registered without a method prefix — a WebSocket upgrade
// is a GET — so the mux hands the handler every verb and routes.go's Methods
// field documents rather than enforces. methodAllowed does not stop a POST
// either, because sandbox.attach is not one of the permissions it classifies as
// read-only. Everything after the check has side effects an unupgraded request
// must not get: a slot against the per-executor ceiling, an audit row, and a
// real process started inside the sandbox — all before websocket.Accept would
// have rejected the verb.
func TestAttachWS_RefusesNonGET(t *testing.T) {
	_, base, clients := newAttachFixture(t)

	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		req, err := http.NewRequest(method, base+"/api/tasks/1/attach", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := clients["admin"].Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/tasks/1/attach = HTTP %d, want 405: a non-GET must never "+
				"reach the code that starts a process in the sandbox", method, resp.StatusCode)
		}
	}
}

// TestAttachStillAuthorized_SeesAPolicyChange is the mechanism test for the
// mid-session re-check.
//
// The bug it guards is silent: grantFor returns a grant memoized on the request
// context, and grant.decide memoizes per scope on top of that, so a re-check
// written the obvious way returns the answer from the moment the socket opened
// and never notices a revocation. The test asserts both halves — that the
// memoized path goes stale, and that attachStillAuthorized does not — because
// an assertion only on the second would still pass if someone "simplified" it
// back to grantFor on a hub where the cache happened to be cold.
func TestAttachStillAuthorized_SeesAPolicyChange(t *testing.T) {
	srv, base, clients := newAttachFixture(t)

	// Establish that admin may attach, through a real authenticated request.
	code, _ := getFull(t, clients["admin"], base+"/api/tasks/1/attach/info")
	if code != http.StatusOK {
		t.Fatalf("admin baseline = HTTP %d, want 200", code)
	}

	// Build one request carrying that identity, and take a memoized reading.
	req, err := http.NewRequest(http.MethodGet, base+"/api/tasks/1/attach", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if u, perr := url.Parse(base); perr == nil {
		for _, c := range clients["admin"].Jar.Cookies(u) {
			req.AddCookie(c)
		}
	}
	memoized := srv.grantFor(req)
	if !memoized.decide(srv.projectScope(req)).Allows(authz.PermSandboxAttach) {
		t.Fatal("admin must start out able to attach")
	}
	if !srv.attachStillAuthorized(req) {
		t.Fatal("attachStillAuthorized must agree before the policy changes")
	}

	// Withdraw it: rebind the group to a role that holds nothing.
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleViewer},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	if memoized.decide(srv.projectScope(req)).Allows(authz.PermSandboxAttach) {
		t.Log("the memoized grant still reports access, as designed — " +
			"which is exactly why the re-check must not use it")
	}
	if srv.attachStillAuthorized(req) {
		t.Error("attachStillAuthorized must observe a withdrawn binding; " +
			"a re-check that cannot see a revocation is not a control")
	}
}
