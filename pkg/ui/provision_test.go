package ui

// Tests for project provisioning (Task 20187).
//
// The scenario these protect is "create a project that can already reach my
// cluster and my checkouts, on the sandbox I picked". The interesting failures
// are not in the happy path — they are the two ways this endpoint could be
// wrong in a way nobody would notice:
//
//   - It could become a privilege escalation. POST /api/projects/new needs
//     project.write; minting a grant needs secret.grant. A route that accepts
//     grants as a field without re-checking hands the lower permission the
//     higher one's authority, and every test of /api/grants still passes.
//   - It could half-succeed. A project created with the executor bound and the
//     grants missing looks fine in the response and fails at the first run,
//     by which point nobody connects the two.

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// permExecutorManageName is the string a denial names, kept as a symbol so a
// rename of the permission breaks this test rather than silently weakening it.
var permExecutorManageName = authz.PermExecutorManage

// sampleKubeconfig is a minimal but real kubeconfig, so a grant against it is
// validated against the same parser production uses.
var sampleKubeconfig = []byte(`apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster: {server: https://prod.example.com}
contexts:
- name: prod
  context: {cluster: prod, user: dev, namespace: default}
current-context: prod
users:
- name: dev
  user: {token: not-a-real-token}
`)

// newProvisionTestBroker builds a broker over a throwaway control-plane
// database. Grants live in the control plane's database in production too, so
// this is the same shape rather than a simplified stand-in.
func newProvisionTestBroker(t *testing.T) *secretbroker.Broker {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "provision-test-passphrase")

	dir := t.TempDir()
	if _, err := state.Init(dir, "provision test", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	return b
}

func mintForTest(t *testing.T, b *secretbroker.Broker, name string, kind secretbroker.Kind, payload []byte) {
	t.Helper()
	if _, err := b.Mint(t.Context(), secretbroker.MintRequest{
		Name: name, Kind: kind, Payload: payload, Actor: "test",
	}); err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
}

func TestProjectAccessRequestedOnlyWhenAsked(t *testing.T) {
	// The predicate that keeps an ordinary creation off every permission check
	// and database open in this file. If it ever reported true for an empty
	// request, plain project.write users would start getting 403s for
	// something they did not ask for.
	if (projectAccessRequest{}).requested() {
		t.Error("an empty access request reports as requested")
	}
	if (projectAccessRequest{ExecutorID: "   "}).requested() {
		t.Error("a whitespace-only executor id reports as requested")
	}
	if !(projectAccessRequest{ExecutorID: "container-1"}).requested() {
		t.Error("an executor id does not report as requested")
	}
	if !(projectAccessRequest{Grants: []projectGrantRequest{{SecretRef: "x"}}}).requested() {
		t.Error("a grant does not report as requested")
	}
}

func TestProjectGrantConstraintsMapAllDimensions(t *testing.T) {
	g := projectGrantRequest{
		Repos:       []string{" api ", ""},
		Permissions: []string{"contents:read"},
		Namespaces:  []string{"default"},
		Contexts:    []string{"prod"},
		Hosts:       []string{"example.com"},
		Registries:  []string{"ghcr.io"},
		EnvKeys:     []string{"TOKEN"},
		Writable:    true,
	}
	c := g.constraints()
	// cleanList is what drops the empty entry and trims — a grant carrying a
	// stray "" would be refused by validatePattern with a message about an
	// empty pattern, which is a confusing thing to show someone who just left
	// a trailing comma in a text field.
	if len(c.Repos) != 1 || c.Repos[0] != "api" {
		t.Errorf("Repos = %v, want [api] (trimmed, empties dropped)", c.Repos)
	}
	if !c.Writable {
		t.Error("Writable did not survive the mapping")
	}
	for name, got := range map[string][]string{
		"Permissions": c.Permissions, "Namespaces": c.Namespaces, "Contexts": c.Contexts,
		"Hosts": c.Hosts, "Registries": c.Registries, "EnvKeys": c.EnvKeys,
	} {
		if len(got) != 1 {
			t.Errorf("%s = %v, want one entry — a dropped dimension silently widens or "+
				"narrows the grant", name, got)
		}
	}
}

func TestValidateProjectAccessRejectsUnknownExecutor(t *testing.T) {
	err := validateProjectAccess(nil, projectAccessRequest{ExecutorID: "no-such-executor"})
	if err == nil {
		t.Fatal("accepted a binding to an executor that does not exist; the project would " +
			"be created and then fail at its first run")
	}
	if !strings.Contains(err.Error(), "no-such-executor") {
		t.Errorf("error %q does not name the executor", err)
	}
}

func TestValidateProjectAccessRefusesGrantsWithNoBroker(t *testing.T) {
	// A hub with no CLOOP_SECRET_KEY cannot mint grants. Saying so is better
	// than creating the project and leaving the grants silently absent.
	err := validateProjectAccess(nil, projectAccessRequest{
		Grants: []projectGrantRequest{{SecretRef: "prod-cluster", Contexts: []string{"prod"}}},
	})
	if err == nil {
		t.Fatal("accepted grants with no secret broker configured")
	}
	if !strings.Contains(err.Error(), "broker") {
		t.Errorf("error %q does not explain that the broker is unconfigured", err)
	}
}

func TestValidateProjectAccessRequiresSecretRef(t *testing.T) {
	bs := &brokerSet{secret: newProvisionTestBroker(t)}
	err := validateProjectAccess(bs, projectAccessRequest{
		Grants: []projectGrantRequest{{Contexts: []string{"prod"}}},
	})
	if err == nil || !strings.Contains(err.Error(), "secret_ref") {
		t.Fatalf("err = %v, want a complaint about the missing secret_ref", err)
	}
}

func TestValidateProjectAccessRejectsUnknownSecret(t *testing.T) {
	bs := &brokerSet{secret: newProvisionTestBroker(t)}
	err := validateProjectAccess(bs, projectAccessRequest{
		Grants: []projectGrantRequest{{SecretRef: "not-a-secret", Contexts: []string{"prod"}}},
	})
	if err == nil {
		t.Fatal("accepted a grant naming a secret that does not exist")
	}
	if !strings.Contains(err.Error(), "grants[0]") {
		t.Errorf("error %q does not say which grant is at fault", err)
	}
}

// TestValidateProjectAccessEnforcesConstraintsPerKind is the check that keeps
// this path from drifting away from POST /api/grants. Both must refuse a
// kubeconfig grant with no contexts and no namespaces, and they must do it by
// calling the same ValidateFor rather than by each restating the rule.
func TestValidateProjectAccessEnforcesConstraintsPerKind(t *testing.T) {
	b := newProvisionTestBroker(t)
	mintForTest(t, b, "prod-cluster", secretbroker.KindKubeconfig, sampleKubeconfig)
	mintForTest(t, b, "dev-src", secretbroker.KindLocalRepo, []byte(t.TempDir()))
	bs := &brokerSet{secret: b}

	t.Run("kubeconfig with no scoping is refused", func(t *testing.T) {
		err := validateProjectAccess(bs, projectAccessRequest{
			Grants: []projectGrantRequest{{SecretRef: "prod-cluster"}},
		})
		if err == nil {
			t.Fatal("accepted a kubeconfig grant with neither contexts nor namespaces")
		}
		if !strings.Contains(err.Error(), "kubeconfig") {
			t.Errorf("error %q does not name the kind", err)
		}
	})

	t.Run("local_repo with no allowlist is refused", func(t *testing.T) {
		err := validateProjectAccess(bs, projectAccessRequest{
			Grants: []projectGrantRequest{{SecretRef: "dev-src"}},
		})
		if err == nil {
			t.Fatal("accepted a local_repo grant with no repository allowlist, which is the whole root")
		}
	})

	t.Run("well-formed grants pass", func(t *testing.T) {
		err := validateProjectAccess(bs, projectAccessRequest{
			Grants: []projectGrantRequest{
				{SecretRef: "prod-cluster", Contexts: []string{"prod"}, Namespaces: []string{"default"}},
				{SecretRef: "dev-src", Repos: []string{"api", "shared-*"}},
			},
		})
		if err != nil {
			t.Fatalf("refused the scenario this task exists for: %v", err)
		}
	})
}

func TestValidateProjectAccessRejectsOutOfRangeTTL(t *testing.T) {
	b := newProvisionTestBroker(t)
	mintForTest(t, b, "dev-src", secretbroker.KindLocalRepo, []byte(t.TempDir()))
	err := validateProjectAccess(&brokerSet{secret: b}, projectAccessRequest{
		Grants: []projectGrantRequest{{
			SecretRef: "dev-src", Repos: []string{"api"}, TTLMinutes: -5,
		}},
	})
	if err == nil {
		t.Fatal("accepted a negative grant lifetime")
	}
}

// --- the escalation guard ----------------------------------------------------

// TestProjectNewDoesNotGrantWhatTheCallerMayNotGrant is the security property
// of this feature.
//
// The role ladder puts project.write and secret.grant at maintainer, and
// executor.manage at admin. A maintainer may therefore create a project and may
// create grants — but may not choose which machine it runs on. If POST
// /api/projects/new honoured executor_id on the strength of project.write
// alone, it would be a way to bind executors that POST
// /api/projects/{idx}/executor refuses, and every existing test of that route
// would still pass because that route is still correct.
func TestProjectNewDoesNotGrantWhatTheCallerMayNotGrant(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "keepers", Role: authz.RoleMaintainer},
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
	maintainer := loginAs([]string{"keepers"})

	base := filepath.Join(t.TempDir(), "escalation")

	t.Run("maintainer cannot bind an executor", func(t *testing.T) {
		code, resp := do(t, maintainer, http.MethodPost, ts.URL+"/api/projects/new",
			`{"dir":`+quote(base+"-exec")+`,"goal":"test","executor_id":"localprocess"}`)
		if code != http.StatusForbidden {
			t.Fatalf("maintainer binding an executor = %d, want 403 — otherwise this route "+
				"hands project.write the authority of executor.manage (body: %s)", code, resp)
		}
		if !strings.Contains(resp, string(permExecutorManageName)) {
			t.Errorf("denial %q does not name executor.manage as the missing permission", resp)
		}
	})

	t.Run("an ordinary creation is unaffected", func(t *testing.T) {
		// The gating must be conditional on asking. A maintainer creating a
		// plain project is doing something they are entitled to do, and a
		// blanket check here would break it.
		code, resp := do(t, maintainer, http.MethodPost, ts.URL+"/api/projects/new",
			`{"dir":`+quote(base+"-plain")+`,"goal":"ordinary project"}`)
		if code == http.StatusForbidden {
			t.Fatalf("maintainer refused an ordinary project creation: %s", resp)
		}
	})

	t.Run("maintainer may still ask for grants", func(t *testing.T) {
		// secret.grant is a maintainer permission, so this must not be a 403.
		// It fails for an unrelated reason (no such secret), which is the
		// point: the refusal is about the request, not about the role.
		code, resp := do(t, maintainer, http.MethodPost, ts.URL+"/api/projects/new",
			`{"dir":`+quote(base+"-grant")+`,"goal":"test",`+
				`"grants":[{"secret_ref":"no-such-secret","repos":["*"]}]}`)
		if code == http.StatusForbidden {
			t.Fatalf("maintainer refused permission to create a grant: %s", resp)
		}
	})
}

// TestProjectNewRefusesBeforeCreatingAnything asserts the ordering that makes a
// failed provisioning cheap: a request naming an executor that does not exist
// must be refused with no directory left behind.
func TestProjectNewRefusesBeforeCreatingAnything(t *testing.T) {
	dir := t.TempDir()
	ts := newTestServer(t, dir, nil)

	target := filepath.Join(t.TempDir(), "never-created")
	code, resp := do(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/new",
		`{"dir":`+quote(target)+`,"goal":"test","executor_id":"no-such-executor"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", code, resp)
	}
	if !strings.Contains(resp, "no-such-executor") {
		t.Errorf("response %q does not name the executor", resp)
	}
	if _, err := filepath.Glob(filepath.Join(target, "*")); err == nil {
		if entries, _ := filepath.Glob(filepath.Join(target, ".cloop")); len(entries) > 0 {
			t.Error("the project was initialised despite the access request being invalid")
		}
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- regressions found by review ---------------------------------------------

// TestRepoEnvKeyRendersOrWithholds covers the rendering half. Collision
// handling lives in applyRepoGrants, which needs the whole set.
func TestRepoEnvKeyRendersOrWithholds(t *testing.T) {
	for name, want := range map[string]string{
		"api":        "CLOOP_LOCAL_REPO_API",
		"my-service": "CLOOP_LOCAL_REPO_MY_SERVICE",
		"my.api":     "CLOOP_LOCAL_REPO_MY_API",
		"v1_2":       "CLOOP_LOCAL_REPO_V1_2",
	} {
		if got := repoEnvKey(name); got != want {
			t.Errorf("repoEnvKey(%q) = %q, want %q", name, got, want)
		}
	}
	// Nothing that would produce a variable name a shell cannot address.
	for _, name := range []string{"repo!", "a b", "ünïcode"} {
		if got := repoEnvKey(name); got != "" {
			t.Errorf("repoEnvKey(%q) = %q, want \"\" — an unrenderable name must be "+
				"withheld rather than mangled", name, got)
		}
	}
}

// TestApplyRepoGrantsRefusesExecutorsThatCannotReceiveRepos is the
// straightforward-scenario counterpart of the placement check: the developer
// clicking Run on a project whose grants and whose executor are incompatible
// must be told so, naming both.
func TestApplyRepoGrantsRefusesExecutorsThatCannotReceiveRepos(t *testing.T) {
	// A lease with no mounts must be a no-op on every executor, including the
	// ones that cannot bind — otherwise every project on Kubernetes breaks.
	spec, err := applyRepoGrants(executor.Spec{WorkDir: "/srv/app"}, stubExec{
		id: "k8s", caps: executor.Capabilities{Isolation: executor.IsolationRemote},
	}, nil)
	if err != nil {
		t.Fatalf("a project with no local_repo grant was refused: %v", err)
	}
	if len(spec.HostMounts) != 0 {
		t.Error("host mounts appeared from a nil lease")
	}
}

// stubExec is an Executor whose capabilities are the only thing under test.
type stubExec struct {
	id   string
	caps executor.Capabilities
}

func (e stubExec) ID() string                          { return e.id }
func (e stubExec) Kind() string                        { return "stub" }
func (e stubExec) Capabilities() executor.Capabilities { return e.caps }
func (e stubExec) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, nil
}
func (e stubExec) Signal(context.Context, string, executor.Signal) error { return nil }
func (e stubExec) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e stubExec) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	close(ch)
	return ch, nil
}
func (e stubExec) HealthCheck(context.Context) error { return nil }
