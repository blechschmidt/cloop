package ui

// What `cloop remote init` (Task 20417) needs of the hub: POST
// /api/projects/new creating a project by name under the projects root,
// refusing to initialise a directory that already holds a project, and
// applying the executor's access list with the creation — and the approvers a
// grant request names.

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestProjectNewByNameGoesUnderTheProjectsRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := setupProjectDir(t, "the hub", nil)
	ts := newTestServer(t, dir, nil)
	create := ts.URL + "/api/projects/new"

	// No ui.projects_root: projects/ in the hub's home.
	status, got := doJSON(t, ts.Client(), http.MethodPost, create, `{"name":"widgets","goal":"Ship widgets"}`)
	want := filepath.Join(home, "projects", "widgets")
	if status != http.StatusOK || got["dir"] != want {
		t.Fatalf("create by name = %d %v, want %s", status, got, want)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Fatalf("the project directory was not made: %v", err)
	}

	// ui.projects_root, when set.
	root := filepath.Join(t.TempDir(), "srv-projects")
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.UI.ProjectsRoot = root
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	status, got = doJSON(t, ts.Client(), http.MethodPost, create, `{"name":"gadgets","goal":"Ship gadgets"}`)
	if status != http.StatusOK || got["dir"] != filepath.Join(root, "gadgets") {
		t.Fatalf("create under ui.projects_root = %d %v", status, got)
	}
	// A directory given wins over a name.
	explicit := filepath.Join(t.TempDir(), "explicit")
	status, got = doJSON(t, ts.Client(), http.MethodPost, create,
		`{"dir":"`+explicit+`","name":"ignored","goal":"Ship it"}`)
	if status != http.StatusOK || got["dir"] != explicit {
		t.Fatalf("create with dir and name = %d %v", status, got)
	}

	// A name is one safe path segment.
	for _, bad := range []string{"../escape", "a/b", ".hidden", "-flag", "has space", strings.Repeat("x", 101)} {
		status, got := doJSON(t, ts.Client(), http.MethodPost, create, `{"name":"`+bad+`","goal":"g"}`)
		if status != http.StatusBadRequest {
			t.Errorf("create named %q = %d %v, want 400", bad, status, got)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "..", "escape")); !os.IsNotExist(err) {
		t.Fatal("a name climbed out of the projects root")
	}

	// A relative root is a configuration mistake, said as one.
	cfg.UI.ProjectsRoot = "relative/projects"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	status, got = doJSON(t, ts.Client(), http.MethodPost, create, `{"name":"third","goal":"g"}`)
	errObj, _ := got["error"].(map[string]any)
	if status != http.StatusConflict || !strings.Contains(errObj["message"].(string), "ui.projects_root") {
		t.Fatalf("create under a relative root = %d %v", status, got)
	}
	// Neither a directory nor a name.
	if status, _ := doJSON(t, ts.Client(), http.MethodPost, create, `{"goal":"g"}`); status != http.StatusBadRequest {
		t.Errorf("create with neither dir nor name = %d, want 400", status)
	}
}

// TestProjectNewRefusesADirectoryThatHoldsAProject: `cloop init` overwrites
// the state it finds, so a second creation where a project exists — a re-run
// of `cloop remote init`, or a path whose project the caller cannot see —
// must be refused, not turned into a wipe.
func TestProjectNewRefusesADirectoryThatHoldsAProject(t *testing.T) {
	dir := setupProjectDir(t, "the hub", nil)
	ts := newTestServer(t, dir, nil)
	existing := setupProjectDir(t, "a project with a plan", nil)

	for _, target := range []string{existing, dir} {
		status, got := doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/new",
			`{"dir":"`+target+`","goal":"start over"}`)
		errObj, _ := got["error"].(map[string]any)
		if status != http.StatusConflict || errObj["code"] != "CONFLICT" ||
			!strings.Contains(errObj["message"].(string), target) {
			t.Fatalf("create where a project exists (%s) = %d %v, want 409 naming it", target, status, got)
		}
		st, err := state.LoadLite(target)
		if err != nil || st.Goal == "start over" {
			t.Fatalf("the existing project at %s was touched: goal %q, %v", target, st.Goal, err)
		}
	}
	// A project from before state.db is a project too.
	legacy := filepath.Join(t.TempDir(), "legacy")
	if err := os.MkdirAll(filepath.Join(legacy, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state.StatePath(legacy), []byte(`{"goal":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, got := doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/new",
		`{"dir":"`+legacy+`","goal":"start over"}`); status != http.StatusConflict {
		t.Fatalf("create where a legacy project exists = %d %v, want 409", status, got)
	}
	// A directory that exists without a project is still created in, as the
	// New Project dialog always allowed.
	empty := filepath.Join(t.TempDir(), "plain")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if status, got := doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/new",
		`{"dir":"`+empty+`","goal":"fresh"}`); status != http.StatusOK {
		t.Fatalf("create in an existing empty directory = %d %v", status, got)
	}
}

// TestProjectNewAppliesTheExecutorsAccessList: a binding made in the creation
// request is refused exactly when POST /api/projects/{idx}/executor would
// refuse it, and nothing is created.
func TestProjectNewAppliesTheExecutorsAccessList(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	db := hubWithControlPlane(t, srv.WorkDir)
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
		{Claim: authz.ClaimGroup, Value: "contractors", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver

	const id = "audience-box"
	registerBuiltinExecutors()
	if err := executor.Register(newMetricsStub(id, "audience-stub", executor.IsolationContainer)); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: id, Name: id, Kind: "audience-stub",
		Status: statedb.ExecutorStatusOnline, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddExecutorAudience(id, "group", "platform", "test"); err != nil {
		t.Fatal(err)
	}

	loginAs := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	outsider := loginAs("contractors")
	target := filepath.Join(t.TempDir(), "outsider-project")
	status, got := doJSON(t, outsider, http.MethodPost, ts.URL+"/api/projects/new",
		`{"dir":"`+target+`","goal":"g","executor_id":"`+id+`"}`)
	if status != http.StatusForbidden || got["code"] != "executor_audience_denied" {
		t.Fatalf("create bound to an executor outside the access list = %d %v", status, got)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("the refused creation made %s", target)
	}

	insider := loginAs("platform")
	target = filepath.Join(t.TempDir(), "insider-project")
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(target) })
	status, got = doJSON(t, insider, http.MethodPost, ts.URL+"/api/projects/new",
		`{"dir":"`+target+`","goal":"g","executor_id":"`+id+`"}`)
	if status != http.StatusOK {
		t.Fatalf("create bound to an executor on the access list = %d %v", status, got)
	}
	if bound, ok, err := db.ProjectExecutor(target); err != nil || !ok || bound != id {
		t.Fatalf("the project is bound to %q (%v, %v)", bound, ok, err)
	}
}

// staticRuntime is a fixed set of runtime bindings.
type staticRuntime []authz.Binding

func (r staticRuntime) RuntimeBindings() []authz.Binding { return r }

func TestRequestApproversNamesWhoMayApprove(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, _ := newOIDCTestServer(t, idp, "", nil)
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
			{Claim: authz.ClaimEmail, Value: "bob@example.com", Role: authz.RoleMaintainer},
			{Claim: authz.ClaimEmail, Value: "alice@example.com", Role: authz.RoleAdmin},
			// Scoped to one project or executor: not a hub-wide approver.
			{Claim: authz.ClaimEmail, Value: "pm@example.com", Role: authz.RoleMaintainer, Project: "api"},
			{Claim: authz.ClaimEmail, Value: "edge@example.com", Role: authz.RoleAdmin, Executor: "edge-01"},
			// Below secret.grant.
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
		},
		AdminEmails: []string{"root@example.com"},
		Runtime: staticRuntime{
			{Claim: authz.ClaimEmail, Value: "bob@example.com", Deny: true},
			{Claim: authz.ClaimEmail, Value: "carol@example.com", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver

	named := srv.requestApprovers("alice@example.com", false)
	wantNamed := []string{
		"carol@example.com (admin)", "root@example.com (admin)", "members of group platform (admin)",
		"members of group leads (maintainer)",
	}
	if strings.Join(named, "|") != strings.Join(wantNamed, "|") {
		t.Fatalf("approvers of a named-project request:\n got %q\nwant %q", named, wantNamed)
	}
	wildcard := srv.requestApprovers("alice@example.com", true)
	if strings.Join(wildcard, "|") != strings.Join(wantNamed[:3], "|") {
		t.Fatalf("approvers of a fleet-wide request: %q, want administrators only", wildcard)
	}
	// The requester is never their own approver.
	for _, a := range srv.requestApprovers("root@example.com", false) {
		if strings.HasPrefix(a, "root@example.com") {
			t.Fatalf("root is offered as approver of their own request: %q", a)
		}
	}
	// What decides which list a request gets.
	cache := srv.newApproverCache("alice@example.com")
	for subject, want := range map[string]int{"project:/srv/api": len(wantNamed), "project:*": 3, "executor:edge-01": len(wantNamed),
		"label:zone=edge": 3, "any": 3} {
		sub, err := secretbroker.ParseSubject(subject)
		if err != nil {
			t.Fatalf("ParseSubject(%s): %v", subject, err)
		}
		if got := cache.forSubject(sub); len(got) != want {
			t.Errorf("a request for %s is approved by %q, want %d entries", subject, got, want)
		}
	}

	// Single sign-on without a policy: everyone holds secret.grant.
	open, err := authz.New(authz.Config{AdminEmails: []string{"root@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = open
	if got := srv.requestApprovers("alice@example.com", false); len(got) != 1 || !strings.Contains(got[0], "anyone signed in") {
		t.Fatalf("approvers on a hub with no role policy: %q", got)
	}
}
