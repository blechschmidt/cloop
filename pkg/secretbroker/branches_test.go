package secretbroker

// Tests for a GitHub grant's branch allowlist (Task 20340): which lists are
// accepted, and what each delivery path does with one.
//
// The property the delivery tests hold is the one the feature rests on. A
// branch list is only ever enforced by the git proxy, so a credential that is
// about to reach git any other way must not carry the push the list restricts.
// Each test below is about what the workload ends up able to do, not about
// which function ran.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// writeApp is the constraint set a project's "read and write" assignment
// produces, narrowed to branches.
func writeApp(branches ...string) Constraints {
	return Constraints{
		Repos:       []string{"acme/api"},
		Permissions: []string{"contents:write", "pull_requests:write"},
		Branches:    branches,
	}
}

func TestBranchAllowlistAcceptsGitBranchGlobs(t *testing.T) {
	for _, p := range []string{
		"cloop/*",
		"feature/**",
		"**",
		"develop",
		"release-?",
		"refs/heads/main", // the prefix is accepted and means the same thing
		"users/a.b/x_y-z",
		"v1.2-hotfix",
	} {
		if err := writeApp(p).ValidateFor(KindGitHubApp); err != nil {
			t.Errorf("branch pattern %q was refused: %v", p, err)
		}
	}
}

func TestBranchAllowlistRefusesWhatGitOrTheProxyWouldMisread(t *testing.T) {
	for _, p := range []string{
		"",
		"   ",
		"refs/tags/v1",   // a branch list is not a tag list
		"refs/remotes/x", // nor any other namespace
		"../main",
		"a..b",
		"feature/",
		"/feature",
		"a//b",
		".hidden",
		"feature/.x",
		"main.lock",
		"-rf",
		"name.",
		"a b",
		"a,b",  // would split into two entries in every comma-joined rendering
		"a:b",  // git refspec syntax
		"a~1",  // git forbids
		"@{u}", // reflog syntax
		"x\\y", // backslash
		"[ab]", // bracket classes are outside the documented syntax
		"a**",  // "**" is only a whole final component
		"x/**/y",
		"x/***",
		strings.Repeat("a", 201),
	} {
		err := writeApp(p).ValidateFor(KindGitHubApp)
		if err == nil {
			t.Errorf("branch pattern %q was accepted", p)
			continue
		}
		if !errors.Is(err, ErrInvalidConstraint) {
			t.Errorf("branch pattern %q: error %v does not wrap ErrInvalidConstraint", p, err)
		}
	}
}

func TestBranchAllowlistIsBounded(t *testing.T) {
	var many []string
	for i := 0; i <= MaxBranchPatterns; i++ {
		many = append(many, "b"+strings.Repeat("x", i))
	}
	if err := writeApp(many...).ValidateFor(KindGitHubApp); err == nil {
		t.Fatalf("%d branch patterns were accepted; the ceiling is %d", len(many), MaxBranchPatterns)
	}
	if err := writeApp(many[:MaxBranchPatterns]...).ValidateFor(KindGitHubApp); err != nil {
		t.Fatalf("exactly %d branch patterns were refused: %v", MaxBranchPatterns, err)
	}
}

// TestBranchAllowlistNeedsAGrantThatCanPush: a list saying where pushes may go
// is meaningless on a grant that cannot push, and an operator who wrote one
// believes they granted something.
func TestBranchAllowlistNeedsAGrantThatCanPush(t *testing.T) {
	refused := []struct {
		name string
		kind Kind
		c    Constraints
	}{
		{"app, read only", KindGitHubApp,
			Constraints{Repos: []string{"acme/api"}, Permissions: []string{"contents:read"}, Branches: []string{"x"}}},
		{"app, a write that is not contents", KindGitHubApp,
			Constraints{Repos: []string{"acme/api"}, Permissions: []string{"pull_requests:write"}, Branches: []string{"x"}}},
		// An unenumerated PAT grant authorises nothing beyond read, which is
		// the reading the git guard applies too.
		{"pat, no permissions", KindGitHubPAT,
			Constraints{Repos: []string{"acme/api"}, Branches: []string{"x"}}},
	}
	for _, tc := range refused {
		err := tc.c.ValidateFor(tc.kind)
		if err == nil {
			t.Errorf("%s: a branch list on a grant that cannot push was accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), "authorises no push") {
			t.Errorf("%s: error %q does not say why", tc.name, err)
		}
	}

	for _, perms := range [][]string{{"contents:write"}, {"contents"}, {"*"}} {
		c := Constraints{Repos: []string{"acme/api"}, Permissions: perms, Branches: []string{"x"}}
		if err := c.ValidateFor(KindGitHubPAT); err != nil {
			t.Errorf("permissions %v authorise a push, but a branch list was refused: %v", perms, err)
		}
	}
}

func TestBranchAllowlistOnlyAppliesToGitHubGrants(t *testing.T) {
	cases := map[Kind]Constraints{
		KindKubeconfig: {Namespaces: []string{"team-a"}, Branches: []string{"x"}},
		KindEnv:        {Branches: []string{"x"}},
		KindRegistry:   {Registries: []string{"ghcr.io"}, Branches: []string{"x"}},
		KindLocalRepo:  {Repos: []string{"svc"}, Branches: []string{"x"}},
	}
	for kind, c := range cases {
		err := c.ValidateFor(kind)
		if err == nil || !strings.Contains(err.Error(), "branch allowlist applies to github") {
			t.Errorf("%s grant with a branch list: err = %v, want a refusal naming the github kinds", kind, err)
		}
	}
}

func TestBranchHelpers(t *testing.T) {
	c := writeApp("cloop/*", "refs/heads/main")
	if got, want := c.BranchRefPatterns(), []string{"refs/heads/cloop/*", "refs/heads/main"}; !reflect.DeepEqual(got, want) {
		t.Errorf("BranchRefPatterns() = %q, want %q", got, want)
	}
	if got, want := c.BranchNames(), []string{"cloop/*", "main"}; !reflect.DeepEqual(got, want) {
		t.Errorf("BranchNames() = %q, want %q", got, want)
	}
	if !c.RestrictsBranches() {
		t.Error("RestrictsBranches() = false for a write grant with a list")
	}
	if (Constraints{Repos: []string{"a/b"}, Permissions: []string{"contents:write"}}).RestrictsBranches() {
		t.Error("RestrictsBranches() = true for a grant with no list")
	}
	if !strings.Contains(c.Summary(), "branches=cloop/*|refs/heads/main") {
		t.Errorf("Summary() = %q; the audit trail would not show the restriction", c.Summary())
	}
}

// --- delivery: github_pat ------------------------------------------------------

// TestGuardedPATCarriesTheBranchesToTheProxy: the guard is what enforces the
// list, so it has to be handed it, and the workload has to be told where its
// pushes will land.
func TestGuardedPATCarriesTheBranchesToTheProxy(t *testing.T) {
	g := workingGuard()
	g.result.PushRefs = []string{"refs/heads/**"}
	c := Constraints{Repos: []string{"acme/*"}, Permissions: []string{"contents:write"},
		Branches: []string{"feature/*"}}
	mat, err := guardedMaterial(t, g, c)
	if err != nil {
		t.Fatalf("guarded delivery of a branch-restricted PAT: %v", err)
	}
	if !reflect.DeepEqual(g.seen.Branches, []string{"feature/*"}) {
		t.Errorf("the guard was handed branches %q, want the grant's list", g.seen.Branches)
	}
	if got := mat.Env[GitHubPushBranchesEnvKey]; got != "feature/*" {
		t.Errorf("%s = %q, want the grant's branch list", GitHubPushBranchesEnvKey, got)
	}
	if got := mat.Env[GitPushRefsEnvKey]; got != "refs/heads/**" {
		t.Errorf("%s = %q, want the hub's ceiling", GitPushRefsEnvKey, got)
	}
	for _, f := range mat.Files {
		if strings.Contains(string(f.Content), theBroadPAT) {
			t.Errorf("file %s carries the PAT", f.Name)
		}
	}
}

// TestUnguardedPATWithBranchesIsNotDelivered is the fail-closed case. With no
// proxy the PAT itself would enter the sandbox, a PAT cannot be narrowed, and
// git never says which ref a push is for — so there is nothing that could hold
// the list, and delivering it would hand over a push to every branch.
func TestUnguardedPATWithBranchesIsNotDelivered(t *testing.T) {
	c := Constraints{Repos: []string{"acme/*"}, Permissions: []string{"contents:write"},
		Branches: []string{"feature/*"}}

	for name, guard := range map[string]GitGuard{
		"no guard at all":   nil,
		"a guard declining": &fakeGuard{}, // zero result, nil error
	} {
		t.Run(name, func(t *testing.T) {
			b := &Broker{GitGuard: guard}
			mat, err := b.githubMaterial(context.Background(), Material{
				SecretName: "my-pat", GrantID: "grant-7", Kind: KindGitHubPAT,
				Constraints: c, Env: map[string]string{},
			}, []byte(theBroadPAT))
			if !errors.Is(err, ErrBranchesUnenforced) {
				t.Fatalf("err = %v, want ErrBranchesUnenforced", err)
			}
			if len(mat.Files) != 0 || len(mat.Env) != 0 {
				t.Errorf("material was returned alongside the refusal: %+v", mat)
			}
			for _, want := range []string{"grant-7", "feature/*", "executors.git_proxy"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not mention %q", err, want)
				}
			}
		})
	}

	// The same grant without a list is delivered exactly as before.
	c.Branches = nil
	b := &Broker{}
	if _, err := b.githubMaterial(context.Background(), Material{
		SecretName: "my-pat", Kind: KindGitHubPAT, Constraints: c, Env: map[string]string{},
	}, []byte(theBroadPAT)); err != nil {
		t.Fatalf("an unrestricted PAT grant stopped being delivered: %v", err)
	}
}

// TestPATHeldByTheProxyKeepsItsPush: workspace provisioning through the proxy
// decorator hands the token to the proxy, not the sandbox, and the decorator
// applies the list. Refusing there would break the pushes the grant allows.
func TestPATHeldByTheProxyKeepsItsPush(t *testing.T) {
	b := &Broker{}
	mat, err := b.githubMaterial(context.Background(), Material{
		SecretName: "my-pat", Kind: KindGitHubPAT, Env: map[string]string{},
		Constraints: Constraints{Repos: []string{"acme/*"}, Permissions: []string{"contents:write"},
			Branches: []string{"feature/*"}},
		heldByProxy: true,
	}, []byte(theBroadPAT))
	if err != nil {
		t.Fatalf("a proxy-held PAT with a branch list was refused: %v", err)
	}
	if tok, ok := mat.GitHubToken(); !ok || tok != theBroadPAT {
		t.Errorf("GitHubToken() = %q/%v; the proxy would have nothing to push with", tok, ok)
	}
}

// --- delivery: github_app ------------------------------------------------------

// TestUnguardedAppWithBranchesIsMintedReadOnly: with no proxy, the App kind can
// do better than refusing — GitHub itself enforces a read-only token — so the
// grant keeps its reads and loses only the push nothing here could hold.
func TestUnguardedAppWithBranchesIsMintedReadOnly(t *testing.T) {
	repos := []InstallationRepo{{ID: 1, FullName: "acme/api"}}
	mat, gh, err := appMaterialWithGuard(t, nil, repos, writeApp("cloop/*"))
	if err != nil {
		t.Fatalf("githubAppMaterial: %v", err)
	}

	// What GitHub was asked for is the whole of the enforcement, so it is what
	// is asserted: every scope capped at read.
	req := gh.deliveredCreate(t)
	want := map[string]string{"contents": "read", "pull_requests": "read"}
	if !reflect.DeepEqual(req.Permissions, want) {
		t.Fatalf("minted with permissions %v, want %v — the token could push", req.Permissions, want)
	}

	reason := mat.Env[GitHubWriteWithheldEnvKey]
	if reason == "" || !strings.Contains(reason, "cloop/*") || !strings.Contains(reason, "git proxy") {
		t.Errorf("%s = %q; the workload is not told why its push will fail", GitHubWriteWithheldEnvKey, reason)
	}
	if got := mat.Env["CLOOP_GITHUB_PERMISSIONS"]; strings.Contains(got, "write") {
		t.Errorf("CLOOP_GITHUB_PERMISSIONS = %q announces a write the token does not have", got)
	}
	if _, ok := mat.Env[GitHubPushBranchesEnvKey]; ok {
		t.Error("a read-only delivery announced branches to push to")
	}
	if !strings.Contains(mat.Summary, "write withheld") {
		t.Errorf("summary %q does not record that the push was withheld", mat.Summary)
	}
	if len(mat.Constraints.Branches) != 0 {
		t.Errorf("the delivered material still carries branches %q", mat.Constraints.Branches)
	}
}

func TestUnguardedWildcardAppWithBranchesIsMintedContentsRead(t *testing.T) {
	repos := []InstallationRepo{{ID: 1, FullName: "acme/api"}}
	c := Constraints{Repos: []string{"acme/api"}, Permissions: []string{"*"}, Branches: []string{"x"}}
	_, gh, err := appMaterialWithGuard(t, nil, repos, c)
	if err != nil {
		t.Fatalf("githubAppMaterial: %v", err)
	}
	// "*" means every permission the installation has, which cannot be capped
	// scope by scope; it becomes the one read an App grant always carries.
	if got := gh.deliveredCreate(t).Permissions; !reflect.DeepEqual(got, map[string]string{"contents": "read"}) {
		t.Fatalf("a wildcard grant was minted with %v, want contents:read only", got)
	}
}

// TestGuardedAppWithBranchesKeepsItsPush: behind the proxy the token can push,
// and the proxy is handed the list that bounds where.
func TestGuardedAppWithBranchesKeepsItsPush(t *testing.T) {
	g := workingGuard()
	repos := []InstallationRepo{{ID: 1, FullName: "acme/api"}}
	mat, gh, err := appMaterialWithGuard(t, g, repos, writeApp("cloop/*"))
	if err != nil {
		t.Fatalf("githubAppMaterial: %v", err)
	}
	if got := gh.deliveredCreate(t).Permissions["contents"]; got != "write" {
		t.Errorf("contents = %q behind a guard; the proxy could not push", got)
	}
	if !reflect.DeepEqual(g.seen.Branches, []string{"cloop/*"}) {
		t.Errorf("the guard was handed branches %q, want [cloop/*]", g.seen.Branches)
	}
	if _, ok := mat.Env[GitHubWriteWithheldEnvKey]; ok {
		t.Error("a guarded delivery claims its write was withheld")
	}
}

// TestDecliningGuardDestroysAWriteTokenMintedForBranches: the token was minted
// able to push on the expectation that the proxy would hold it. When the guard
// declines instead, that token is exactly what the grant ruled out, so it dies
// at GitHub and nothing is delivered.
func TestDecliningGuardDestroysAWriteTokenMintedForBranches(t *testing.T) {
	repos := []InstallationRepo{{ID: 1, FullName: "acme/api"}}
	mat, gh, err := appMaterialWithGuard(t, &fakeGuard{}, repos, writeApp("cloop/*"))
	if !errors.Is(err, ErrBranchesUnenforced) {
		t.Fatalf("err = %v, want ErrBranchesUnenforced", err)
	}
	if len(mat.Files) != 0 {
		t.Errorf("files delivered alongside the refusal: %+v", mat.Files)
	}
	if live := gh.liveTokens(); len(live) != 0 {
		t.Errorf("the write-capable token is still live at GitHub: %v", live)
	}
}

// TestLeaseHonoursGitHubProxied drives the whole broker: the same grant is
// minted able to push for a caller that routes the token through the proxy,
// and read-only for one that does not.
func TestLeaseHonoursGitHubProxied(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "acme/api"})
	b, _, _, clk := newTestBroker(t)
	gh.clock = clk.Now
	b.appMinter = newGitHubAppMinter(gh, clk.Now)
	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "prod-app", Kind: KindGitHubApp, Payload: appPayloadJSON(t),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   sec.ID,
		Subject:     Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: writeApp("cloop/*"),
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	for _, tc := range []struct {
		proxied bool
		want    string
	}{
		{proxied: false, want: "read"},
		{proxied: true, want: "write"},
	} {
		lease, err := b.LeaseFor(context.Background(),
			Requester{ExecutorID: "exec-1", ProjectID: "/srv/app", GitHubProxied: tc.proxied}, "test")
		if err != nil {
			t.Fatalf("LeaseFor(proxied=%v): %v", tc.proxied, err)
		}
		if len(lease.Materials) != 1 {
			t.Fatalf("proxied=%v: %d materials, want 1", tc.proxied, len(lease.Materials))
		}
		if got := gh.deliveredCreate(t).Permissions["contents"]; got != tc.want {
			t.Errorf("proxied=%v: minted contents:%s, want contents:%s", tc.proxied, got, tc.want)
		}
		b.Release(lease.ID)
	}
}
