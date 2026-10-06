package ui

// The Projects grid's Run button and a new project's auto-run start the same
// run on the same executor as POST /api/run, so they meet the same admission
// gates (Task 20391). Before, they were the way round them: an identity left
// off a restricted executor's access list, or one at its concurrency cap, was
// refused by the Overview's Run and admitted by these.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/quota"
)

func TestProjectGridRunHonoursTheExecutorAudience(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	dir := srv.WorkDir
	hubWithControlPlane(t, dir)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
		{Claim: authz.ClaimGroup, Value: "contractors", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	loginAs := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	insider := loginAs("platform")
	outsider := loginAs("contractors")

	if status, got := doJSON(t, insider, http.MethodPost,
		ts.URL+"/api/executors/"+localprocess.DefaultID+"/audience",
		`{"kind":"group","value":"platform"}`); status != http.StatusOK {
		t.Fatalf("restrict the executor = HTTP %d (%v)", status, got)
	}
	if err := executor.Bind(dir, localprocess.DefaultID); err != nil {
		t.Fatal(err)
	}

	status, got := doJSON(t, outsider, http.MethodPost, ts.URL+"/api/projects/0/run", `{}`)
	if status != http.StatusForbidden || got["code"] != "executor_audience_denied" {
		t.Fatalf("the grid's Run for an unlisted user = HTTP %d %v, want 403 executor_audience_denied — "+
			"the same refusal /api/run gives", status, got)
	}
}

func TestProjectGridRunTakesAConcurrencySlot(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	hubWithControlPlane(t, srv.WorkDir)

	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	policy, err := quota.New(quota.Config{Defaults: quota.Limits{quota.ResConcurrentTasks: 1}})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetQuotaPolicy(policy)

	idp.groups = []string{"platform"}
	c := jarClient(t)
	login(t, c, ts)

	// The tenant's one slot is taken by a run already going.
	req := httptest.NewRequest(http.MethodPost, ts.URL+"/api/projects/0/run", nil)
	u, _ := url.Parse(ts.URL)
	for _, ck := range c.Jar.Cookies(u) {
		req.AddCookie(ck)
	}
	subject := srv.quotaSubject(req)
	if subject == nil {
		t.Fatal("the signed-in user resolves to no quota subject; the test cannot take their slot")
	}
	if _, err := srv.quotas().Admit(subject, quota.ResConcurrentTasks, 1); err != nil {
		t.Fatal(err)
	}

	status, got := doJSON(t, c, http.MethodPost, ts.URL+"/api/projects/0/run", `{}`)
	if status != http.StatusTooManyRequests {
		t.Fatalf("the grid's Run past the concurrency cap = HTTP %d %v, want 429", status, got)
	}
	if u := srv.quotas().Usage(subject.Label()); u[quota.ResConcurrentTasks] != 1 {
		t.Fatalf("a refused run left the tenant's slots at %v, want the one already held", u[quota.ResConcurrentTasks])
	}
}

func TestNewProjectAutorunHonoursTheExecutorAudience(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	hubWithControlPlane(t, srv.WorkDir)

	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
		{Claim: authz.ClaimGroup, Value: "contractors", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	loginAs := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	insider := loginAs("platform")
	outsider := loginAs("contractors")

	// The default executor every new project lands on is restricted.
	if status, got := doJSON(t, insider, http.MethodPost,
		ts.URL+"/api/executors/"+localprocess.DefaultID+"/audience",
		`{"kind":"group","value":"platform"}`); status != http.StatusOK {
		t.Fatalf("restrict the executor = HTTP %d (%v)", status, got)
	}

	newDir := t.TempDir()
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(newDir) })
	status, got := doJSON(t, outsider, http.MethodPost, ts.URL+"/api/projects/new",
		`{"dir":"`+newDir+`","goal":"g","autoRun":true}`)
	if status != http.StatusOK {
		t.Fatalf("create = HTTP %d (%v)", status, got)
	}
	refused, _ := got["autorun_refused"].(map[string]any)
	if refused == nil || refused["code"] != "executor_audience_denied" {
		t.Fatalf("the new project's auto-run for an unlisted user was not refused: %v", got)
	}
	if srv.projectExecuting(newDir) {
		t.Fatal("the refused auto-run is running")
	}
}
