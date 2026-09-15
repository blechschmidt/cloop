package ui

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// TestGuardPolicyNarrowsByPermission is where "more restricted permissions"
// actually happens: a grant's permission set decides whether the session the
// sandbox gets can push at all, however broad the PAT behind it is.
func TestGuardPolicyNarrowsByPermission(t *testing.T) {
	// The shape config.GitProxyConfig.Policy() produces: create + update inside
	// refs/heads/cloop/**, and fetch on. Fetch matters here because guardPolicy
	// inherits it rather than forcing it — see the ceiling test below.
	base := gitproxy.WriteBackPolicy()
	base.AllowFetch = true

	cases := []struct {
		name        string
		permissions []string
		wantWrite   bool
	}{
		// The documented reading of an unenumerated permission set: an
		// operator who listed nothing has authorised nothing beyond read.
		{"empty means read-only", nil, false},
		{"read only", []string{"contents:read"}, false},
		{"write", []string{"contents:write"}, true},
		// A bare scope covers both levels, matching Constraints.AllowsPermission.
		{"bare scope covers write", []string{"contents"}, true},
		{"wildcard covers write", []string{"*"}, true},
		{"an unrelated write is not contents", []string{"pull_requests:write"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol, readOnly := guardPolicy(base, tc.permissions)
			gotWrite := pol.AllowCreate || pol.AllowUpdate
			if gotWrite != tc.wantWrite {
				t.Errorf("write allowed = %v, want %v (policy %+v)", gotWrite, tc.wantWrite, pol)
			}
			if readOnly == tc.wantWrite {
				t.Errorf("readOnly = %v alongside write = %v; they must disagree", readOnly, gotWrite)
			}
			// Reading is what a grant is for; it is never withheld.
			if !pol.AllowFetch {
				t.Error("fetch was not allowed")
			}
			// Deleting a branch is never something a grant implies.
			if pol.AllowDelete {
				t.Error("delete was allowed")
			}
		})
	}
}

// TestGuardPolicyCannotWidenTheOperatorsCeiling is the composition rule: the
// hub's configured policy bounds every grant, and no permission set reaches
// past it.
func TestGuardPolicyCannotWidenTheOperatorsCeiling(t *testing.T) {
	// An operator who allows only fetch.
	readOnlyHub := gitproxy.Policy{AllowedRefs: []string{"refs/heads/cloop/**"}, AllowFetch: true}
	pol, readOnly := guardPolicy(readOnlyHub, []string{"contents:write", "*"})
	if pol.AllowCreate || pol.AllowUpdate || pol.AllowDelete {
		t.Errorf("a grant widened a read-only hub policy: %+v", pol)
	}
	if !readOnly {
		t.Error("readOnly = false against a hub policy that permits no writes")
	}

	// An operator who narrowed the ref namespace.
	narrow := gitproxy.Policy{
		AllowedRefs: []string{"refs/heads/sandbox/**"},
		AllowCreate: true,
	}
	pol, _ = guardPolicy(narrow, []string{"*"})
	if len(pol.AllowedRefs) != 1 || pol.AllowedRefs[0] != "refs/heads/sandbox/**" {
		t.Errorf("AllowedRefs = %v, want the operator's namespace", pol.AllowedRefs)
	}
	if pol.AllowUpdate {
		t.Error("update was granted although the hub policy did not allow it")
	}
	// Fetch is the one dimension guardPolicy used to force on, which made the
	// name of this test false. It is inherited now, so a hub that withheld
	// reading keeps withholding it.
	if pol.AllowFetch {
		t.Error("fetch was granted although the hub policy did not allow it")
	}
}

// TestGuardPolicyDefaultsWhenNothingIsConfigured covers the one case where
// there is no ceiling to inherit: a zero base is not a narrow policy somebody
// wrote, it is the absence of one, so a usable default is chosen instead.
func TestGuardPolicyDefaultsWhenNothingIsConfigured(t *testing.T) {
	pol, readOnly := guardPolicy(gitproxy.Policy{}, []string{"contents:write"})
	if !pol.AllowFetch {
		t.Error("the default policy cannot read, which makes a PAT grant useless")
	}
	if !pol.AllowCreate || !pol.AllowUpdate {
		t.Error("a write grant against the default policy cannot push")
	}
	if pol.AllowDelete {
		t.Error("the default policy permits deletes")
	}
	if readOnly {
		t.Error("readOnly = true for a policy that can push")
	}
	if len(pol.AllowedRefs) == 0 {
		t.Error("the default policy has no ref allowlist, so it would admit nothing")
	}
}

// TestGuardPolicyDoesNotMutateItsInput catches the aliasing bug that would make
// the first read-only grant narrow the hub's policy for every later session.
//
// Policy is copied by value but its AllowedRefs slice is not, so a narrowing
// that wrote through the shared backing array would be invisible here and
// permanent in production.
func TestGuardPolicyDoesNotMutateItsInput(t *testing.T) {
	base := gitproxy.WriteBackPolicy()
	base.AllowFetch = true
	before := append([]string(nil), base.AllowedRefs...)

	pol, _ := guardPolicy(base, nil) // read-only: the most aggressive narrowing
	pol.AllowedRefs[0] = "refs/heads/mutated/**"

	if !base.AllowCreate || !base.AllowUpdate {
		t.Error("guardPolicy cleared the caller's write flags")
	}
	for i := range before {
		if base.AllowedRefs[i] != before[i] {
			t.Errorf("guardPolicy wrote through into the caller's allowlist: %v, want %v",
				base.AllowedRefs, before)
		}
	}
}

// TestNilGuardDeclinesRatherThanFails keeps a hub with no proxy configured
// delivering credentials the way it always did.
func TestNilGuardDeclinesRatherThanFails(t *testing.T) {
	res, err := gitGuard{}.GuardGitHub(context.Background(), secretbroker.GitGuardRequest{
		Token: "tok", Repos: []string{"acme/*"},
	})
	if err != nil {
		t.Fatalf("a nil service returned an error instead of declining: %v", err)
	}
	if res.Guarded() {
		t.Error("a nil service returned a credential")
	}
}

// TestUnavailableGuardFailsClosed is the other half: a hub that asked for
// interception and has not got it must refuse, not fall back.
func TestUnavailableGuardFailsClosed(t *testing.T) {
	_, err := unavailableGitGuard().GuardGitHub(context.Background(), secretbroker.GitGuardRequest{
		Token: "tok", Repos: []string{"acme/*"},
	})
	if err == nil {
		t.Fatal("the unavailable guard produced a credential")
	}
	if !strings.Contains(err.Error(), "git_proxy") {
		t.Errorf("err = %v; it should name the configuration that is not in effect", err)
	}
}

// TestGuardMintsAScopedSession drives the real registry, so the request the
// guard builds is one Mint actually accepts — the shape of a scoped session is
// easy to get wrong in a way no type would catch.
func TestGuardMintsAScopedSession(t *testing.T) {
	reg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	g := gitGuard{svc: &gitProxyService{reg: reg, baseURL: "https://hub.internal:8443", policy: pol}}

	const pat = "ghp_broadTokenReachingEverything0000"
	res, err := g.GuardGitHub(context.Background(), secretbroker.GitGuardRequest{
		Token:       pat,
		Repos:       []string{"acme/*"},
		Permissions: []string{"contents:read"},
		GrantID:     "grant-1",
		ProjectID:   "/srv/app",
		ExecutorID:  "exec-1",
		Owner:       "dev@example.com",
	})
	if err != nil {
		t.Fatalf("GuardGitHub: %v", err)
	}
	if !res.Guarded() {
		t.Fatal("the guard declined when a proxy was available")
	}
	if res.Password == pat || res.Username == pat {
		t.Fatal("the guard handed back the token it was given")
	}
	if !res.ReadOnly {
		t.Error("a contents:read grant did not produce a read-only session")
	}
	if strings.Contains(res.Summary, pat) {
		t.Error("the audit summary contains the token")
	}

	sess, err := reg.Session(res.SessionID)
	if err != nil {
		t.Fatalf("the minted session is not in the registry: %v", err)
	}
	if !sess.Scoped() {
		t.Error("the guard minted a pinned session for an allowlist")
	}
	if !sess.AllowsRepo("acme/tool") || sess.AllowsRepo("somebody-else/private") {
		t.Error("the minted session does not enforce the grant's allowlist")
	}
	if sess.Policy.AllowCreate || sess.Policy.AllowUpdate {
		t.Error("a read-only grant minted a session that can push")
	}
	if sess.Actor != "dev@example.com" {
		t.Errorf("session actor = %q, want the credential's owner", sess.Actor)
	}
}

// TestClosingALeaseRevokesItsProxySessions is the revocation half.
//
// Wiping the lease directory takes the session token out of the sandbox, but a
// workload that copied it first would keep PAT-backed access to the whole
// allowlist until the session's own TTL ran out — an hour by default, outliving
// both the task and any revocation the operator performed. The session is where
// the authority lives, so releasing the lease has to end it.
func TestClosingALeaseRevokesItsProxySessions(t *testing.T) {
	reg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	svc := &gitProxyService{reg: reg, baseURL: "https://hub.internal:8443", policy: pol}

	res, err := gitGuard{svc: svc}.GuardGitHub(context.Background(), secretbroker.GitGuardRequest{
		Token: "ghp_broadTokenReachingEverything0000",
		Repos: []string{"acme/*"},
	})
	if err != nil {
		t.Fatalf("GuardGitHub: %v", err)
	}
	if _, err := reg.Session(res.SessionID); err != nil {
		t.Fatalf("the session was not registered: %v", err)
	}

	// The lease carries the session id in the material's environment, which is
	// how closeGuardedSessions finds it again without the broker knowing what a
	// proxy session is.
	lease := &secretbroker.Lease{Materials: []secretbroker.Material{{
		Kind: secretbroker.KindGitHubPAT,
		Env:  map[string]string{secretbroker.GitProxySessionEnvKey: res.SessionID},
	}}}

	// The singleton is what closeGuardedSessions reads, so point it at this
	// service for the duration of the test and put it back afterwards.
	prev := gitProxySingleton.Load()
	gitProxySingleton.Store(svc)
	t.Cleanup(func() { gitProxySingleton.Store(prev) })

	closeGuardedSessions(lease)

	if _, err := reg.Session(res.SessionID); err == nil {
		t.Error("the proxy session survived the lease that created it")
	}
	// Idempotent: Close runs from a defer and a lease may be closed twice.
	closeGuardedSessions(lease)
}

// TestGuardRefusesAGrantWithNoAllowlist avoids minting a session that would
// admit nothing and fail every clone with a misleading message.
func TestGuardRefusesAGrantWithNoAllowlist(t *testing.T) {
	reg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	g := gitGuard{svc: &gitProxyService{reg: reg, baseURL: "https://hub.internal:8443"}}
	if _, err := g.GuardGitHub(context.Background(), secretbroker.GitGuardRequest{
		Token: "tok", GrantID: "grant-1",
	}); err == nil {
		t.Fatal("a grant with no repository allowlist was guarded")
	}
}
