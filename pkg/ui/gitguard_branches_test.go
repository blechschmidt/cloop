package ui

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Tests for how the git guard applies a grant's branch allowlist (Task 20340).

// TestGuardPolicyNarrowsByBranches: the grant's list becomes the second list a
// push must clear, and the hub's list stays the first.
func TestGuardPolicyNarrowsByBranches(t *testing.T) {
	base := gitproxy.Policy{
		AllowedRefs: []string{"refs/heads/**"},
		AllowCreate: true, AllowUpdate: true, AllowFetch: true,
	}
	pol, readOnly := guardPolicy(base, []string{"contents:write"}, []string{"feature/*", "refs/heads/main"})
	if readOnly {
		t.Fatal("a write grant came out read-only")
	}
	if !reflect.DeepEqual(pol.AllowedRefs, []string{"refs/heads/**"}) {
		t.Errorf("AllowedRefs = %q; the hub's ceiling must be left as configured", pol.AllowedRefs)
	}
	if want := []string{"refs/heads/feature/*", "refs/heads/main"}; !reflect.DeepEqual(pol.RestrictRefs, want) {
		t.Errorf("RestrictRefs = %q, want %q", pol.RestrictRefs, want)
	}

	pol.Normalize()
	for ref, want := range map[string]bool{
		"refs/heads/feature/login": true,
		"refs/heads/main":          true,
		"refs/heads/develop":       false, // inside the ceiling, outside the grant
		"refs/tags/v1":             false,
	} {
		if got := pol.AllowsRef(ref); got != want {
			t.Errorf("AllowsRef(%q) = %v, want %v", ref, got, want)
		}
	}

	// The base is the service's own policy value, shared by every session: the
	// narrowing must not write through into it.
	if base.RestrictRefs != nil {
		t.Errorf("guardPolicy wrote a restriction into the hub's policy: %q", base.RestrictRefs)
	}
}

// TestGuardPolicyGivesAReadOnlySessionNoRestriction: there is no push for a
// list to narrow, and a read-only grant carrying one is refused at grant time.
func TestGuardPolicyGivesAReadOnlySessionNoRestriction(t *testing.T) {
	base := gitproxy.WriteBackPolicy()
	base.AllowFetch = true
	pol, readOnly := guardPolicy(base, []string{"contents:read"}, []string{"feature/*"})
	if !readOnly {
		t.Fatal("a read grant came out able to push")
	}
	if len(pol.RestrictRefs) != 0 {
		t.Errorf("a read-only session carries a restriction: %q", pol.RestrictRefs)
	}
}

// TestGuardPolicyFailsClosedOnABlankList: a list that named something and
// narrows to nothing must not become "no restriction".
func TestGuardPolicyFailsClosedOnABlankList(t *testing.T) {
	base := gitproxy.WriteBackPolicy()
	base.AllowFetch = true
	pol, _ := guardPolicy(base, []string{"contents:write"}, []string{"  ", ""})
	pol.Normalize()
	if err := pol.Validate(); err == nil {
		t.Fatalf("a policy restricted by a blank list validated: %+v", pol)
	}
}

// TestGuardMintsASessionNarrowedToTheGrantsBranches drives the real registry,
// so the session the proxy will authenticate against is the one asserted on.
func TestGuardMintsASessionNarrowedToTheGrantsBranches(t *testing.T) {
	reg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	pol := gitproxy.WriteBackPolicy() // the default ceiling: refs/heads/cloop/**
	pol.AllowFetch = true
	g := gitGuard{svc: &gitProxyService{reg: reg, baseURL: "https://hub.internal:8443", policy: pol}}

	res, err := g.GuardGitHub(context.Background(), secretbroker.GitGuardRequest{
		Token:       "ghp_broadTokenReachingEverything0000",
		Repos:       []string{"acme/*"},
		Permissions: []string{"contents:write"},
		Branches:    []string{"cloop/feature-*"},
		GrantID:     "grant-1",
	})
	if err != nil {
		t.Fatalf("GuardGitHub: %v", err)
	}
	if res.ReadOnly {
		t.Fatal("a write grant produced a read-only session")
	}
	if !reflect.DeepEqual(res.PushRefs, []string{"refs/heads/cloop/**"}) {
		t.Errorf("PushRefs = %q; the workload is told the wrong ceiling", res.PushRefs)
	}
	if !strings.Contains(res.Summary, "narrowed to refs/heads/cloop/feature-*") {
		t.Errorf("summary %q does not record the grant's narrowing", res.Summary)
	}

	sess, err := reg.Session(res.SessionID)
	if err != nil {
		t.Fatalf("the minted session is not in the registry: %v", err)
	}
	for ref, want := range map[string]bool{
		"refs/heads/cloop/feature-login": true,
		"refs/heads/cloop/task-42":       false, // the ceiling admits it, the grant does not
		"refs/heads/main":                false,
	} {
		if got := sess.Policy.AllowsRef(ref); got != want {
			t.Errorf("session AllowsRef(%q) = %v, want %v", ref, got, want)
		}
	}
}

// TestBranchEnforcementTellsTheTruthAboutThisHub pins the verdict the panels
// render against the broker's actual behaviour in each hub state.
func TestBranchEnforcementTellsTheTruthAboutThisHub(t *testing.T) {
	prevSvc, prevReq := gitProxySingleton.Load(), gitProxyRequired.Load()
	t.Cleanup(func() {
		gitProxySingleton.Store(prevSvc)
		gitProxyRequired.Store(prevReq)
	})

	restricted := secretbroker.Constraints{
		Repos: []string{"acme/api"}, Permissions: []string{"contents:write"}, Branches: []string{"x/*"},
	}
	unrestricted := secretbroker.Constraints{Repos: []string{"acme/api"}, Permissions: []string{"contents:write"}}

	reg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatal(err)
	}
	running := &gitProxyService{reg: reg, baseURL: "https://hub.internal:8443", policy: gitproxy.WriteBackPolicy()}

	cases := []struct {
		name     string
		svc      *gitProxyService
		required bool
		kind     secretbroker.Kind
		c        secretbroker.Constraints
		want     string
	}{
		{"no list is not a question", nil, false, secretbroker.KindGitHubApp, unrestricted, ""},
		{"proxy running", running, true, secretbroker.KindGitHubPAT, restricted, branchesByProxy},
		{"proxy required and down", nil, true, secretbroker.KindGitHubApp, restricted, branchesProxyDown},
		{"no proxy, app", nil, false, secretbroker.KindGitHubApp, restricted, branchesReadOnly},
		{"no proxy, pat", nil, false, secretbroker.KindGitHubPAT, restricted, branchesNotDelivered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gitProxySingleton.Store(tc.svc)
			gitProxyRequired.Store(tc.required)
			if got := branchEnforcement(tc.kind, tc.c); got != tc.want {
				t.Errorf("branchEnforcement = %q, want %q", got, tc.want)
			}
		})
	}

	// And the status a panel reads before anyone types a branch.
	gitProxySingleton.Store(running)
	gitProxyRequired.Store(true)
	st := gitProxyStatus()
	if !st.Running || !reflect.DeepEqual(st.PushRefs, []string{"refs/heads/cloop/**"}) {
		t.Errorf("gitProxyStatus() = %+v with the default policy running", st)
	}
	gitProxySingleton.Store(nil)
	gitProxyRequired.Store(false)
	if st := gitProxyStatus(); st.Running || len(st.PushRefs) != 0 {
		t.Errorf("gitProxyStatus() = %+v with no proxy", st)
	}
}
