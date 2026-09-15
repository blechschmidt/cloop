package kubeguard

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestReadOnlyPolicyIsTheDefault(t *testing.T) {
	var zero Policy
	zero.Normalize()
	if !zero.ReadOnly() {
		t.Fatalf("the zero policy is not read-only: %s", zero.Summary())
	}
	if got := strings.Join(zero.Verbs, ","); got != "get,list,watch" {
		t.Errorf("default verbs = %q, want get,list,watch", got)
	}
	if err := zero.Validate(); err != nil {
		t.Errorf("the normalised zero policy does not validate: %v", err)
	}
}

func TestPolicyRefusesWritesUnderReadOnly(t *testing.T) {
	p := ReadOnlyPolicy()
	writes := []struct{ method, target string }{
		{http.MethodPost, "/api/v1/namespaces/app/pods"},
		{http.MethodPut, "/api/v1/namespaces/app/pods/web-0"},
		{http.MethodPatch, "/api/v1/namespaces/app/pods/web-0"},
		{http.MethodDelete, "/api/v1/namespaces/app/pods/web-0"},
		{http.MethodDelete, "/api/v1/namespaces/app/pods"},
		{http.MethodPost, "/apis/apps/v1/namespaces/app/deployments"},
		{http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},
	}
	for _, w := range writes {
		t.Run(w.method+" "+w.target, func(t *testing.T) {
			err := p.Decide(mustParse(t, w.method, w.target))
			if err == nil {
				t.Fatalf("%s %s allowed under a read-only policy", w.method, w.target)
			}
			if !errors.Is(err, ErrDenied) {
				t.Errorf("error does not wrap ErrDenied: %v", err)
			}
			if reason, ok := DenyReasonOf(err); !ok || reason != DenyVerbNotAllowed {
				t.Errorf("reason = %q, want %q", reason, DenyVerbNotAllowed)
			}
		})
	}
}

func TestPolicyAllowsReadsUnderReadOnly(t *testing.T) {
	p := ReadOnlyPolicy()
	for _, target := range []string{
		"/api/v1/pods",
		"/api/v1/namespaces/app/pods",
		"/api/v1/namespaces/app/pods/web-0",
		"/api/v1/namespaces/app/pods/web-0/log",
		"/api/v1/namespaces/app/pods?watch=true",
		"/apis/apps/v1/namespaces/app/deployments/web",
		"/api", "/apis", "/api/v1", "/apis/apps/v1", "/version", "/openapi/v2",
	} {
		t.Run(target, func(t *testing.T) {
			if err := p.Decide(mustParse(t, http.MethodGet, target)); err != nil {
				t.Errorf("GET %s refused under a read-only policy: %v", target, err)
			}
		})
	}
}

// TestPolicyRefusesDangerousSubresourcesForEveryVerb is the regression test
// for the bypass a verb-only allowlist has: GET on pods/exec is a shell, and
// under {get,list,watch} it reads as an ordinary get.
func TestPolicyRefusesDangerousSubresourcesForEveryVerb(t *testing.T) {
	// The most permissive policy this package can express. Even here the
	// capability subresources stay shut: they are not something a policy can
	// opt back into.
	wideOpen := Policy{Verbs: allVerbs()}
	wideOpen.Normalize()

	for _, p := range []Policy{ReadOnlyPolicy(), wideOpen} {
		for _, sub := range []string{"exec", "attach", "portforward", "proxy"} {
			for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
				name := method + " pods/" + sub + " verbs=" + strings.Join(p.Verbs, ",")
				t.Run(name, func(t *testing.T) {
					err := p.Decide(mustParse(t, method, "/api/v1/namespaces/app/pods/web-0/"+sub))
					if err == nil {
						t.Fatalf("%s reached the cluster", name)
					}
					if reason, _ := DenyReasonOf(err); reason != DenyDangerousSubresource {
						t.Errorf("reason = %q, want %q (%v)", reason, DenyDangerousSubresource, err)
					}
				})
			}
		}
	}
}

func TestPolicyRefusesProtocolUpgrades(t *testing.T) {
	p := ReadOnlyPolicy()
	r := mustParse(t, http.MethodGet, "/api/v1/namespaces/app/pods?watch=true")
	r.Upgrade = true
	err := p.Decide(r)
	if err == nil {
		t.Fatal("an upgrade request was allowed")
	}
	if reason, _ := DenyReasonOf(err); reason != DenyProtocolUpgrade {
		t.Errorf("reason = %q, want %q", reason, DenyProtocolUpgrade)
	}
}

// TestNamespaceAllowlistRefusesClusterWideReads is the enforcement a
// kubeconfig's default namespace could never provide: `kubectl get pods
// --all-namespaces` names no namespace and reads every one, so letting it
// through because "no namespace was violated" would make the allowlist
// decorative.
func TestNamespaceAllowlistRefusesClusterWideReads(t *testing.T) {
	p := Policy{Namespaces: []string{"app", "app-staging"}}
	p.Normalize()

	t.Run("allowed namespace", func(t *testing.T) {
		if err := p.Decide(mustParse(t, http.MethodGet, "/api/v1/namespaces/app/pods")); err != nil {
			t.Errorf("reading the granted namespace was refused: %v", err)
		}
	})
	t.Run("kubectl -n kube-system", func(t *testing.T) {
		err := p.Decide(mustParse(t, http.MethodGet, "/api/v1/namespaces/kube-system/secrets"))
		if err == nil {
			t.Fatal("reading kube-system was allowed")
		}
		if reason, _ := DenyReasonOf(err); reason != DenyNamespaceNotAllowed {
			t.Errorf("reason = %q, want %q", reason, DenyNamespaceNotAllowed)
		}
	})
	t.Run("all namespaces", func(t *testing.T) {
		err := p.Decide(mustParse(t, http.MethodGet, "/api/v1/pods"))
		if err == nil {
			t.Fatal("a cluster-wide pod list was allowed")
		}
		if reason, _ := DenyReasonOf(err); reason != DenyClusterScope {
			t.Errorf("reason = %q, want %q", reason, DenyClusterScope)
		}
	})
	t.Run("cluster scoped resource", func(t *testing.T) {
		// A grant confined to namespaces has not been given the cluster.
		if err := p.Decide(mustParse(t, http.MethodGet, "/api/v1/nodes")); err == nil {
			t.Error("listing nodes was allowed under a namespace-confined policy")
		}
	})
	t.Run("empty allowlist means no confinement", func(t *testing.T) {
		open := ReadOnlyPolicy()
		if err := open.Decide(mustParse(t, http.MethodGet, "/api/v1/pods")); err != nil {
			t.Errorf("a policy with no namespace list refused a cluster-wide read: %v", err)
		}
	})
}

func TestNamespaceGlobs(t *testing.T) {
	p := Policy{Namespaces: []string{"app-*"}}
	p.Normalize()
	if !p.AllowsNamespace("app-one") {
		t.Error("app-* does not admit app-one")
	}
	// path.Match's "*" does not cross a "/", and a namespace has none, so the
	// interesting negative is a prefix that is not covered.
	if p.AllowsNamespace("kube-system") {
		t.Error("app-* admits kube-system")
	}
	star := Policy{Namespaces: []string{"*"}}
	star.Normalize()
	if !star.AllowsNamespace("anything") {
		t.Error(`"*" does not admit everything`)
	}
}

func TestResourceAllowlist(t *testing.T) {
	p := Policy{Resources: []string{"pods", "apps/deployments"}}
	p.Normalize()

	if err := p.Decide(mustParse(t, http.MethodGet, "/api/v1/namespaces/app/pods")); err != nil {
		t.Errorf("pods refused: %v", err)
	}
	// A subresource rides on its parent: the resource allowlist matches the
	// resource, and the subresource is governed by the verb and the dangerous
	// set instead.
	if err := p.Decide(mustParse(t, http.MethodGet, "/api/v1/namespaces/app/pods/web-0/log")); err != nil {
		t.Errorf("pods/log refused by a pods allowlist: %v", err)
	}
	if err := p.Decide(mustParse(t, http.MethodGet, "/apis/apps/v1/namespaces/app/deployments")); err != nil {
		t.Errorf("apps/deployments refused: %v", err)
	}
	err := p.Decide(mustParse(t, http.MethodGet, "/api/v1/namespaces/app/secrets"))
	if err == nil {
		t.Fatal("secrets allowed by a pods+deployments allowlist")
	}
	if reason, _ := DenyReasonOf(err); reason != DenyResourceNotAllowed {
		t.Errorf("reason = %q, want %q", reason, DenyResourceNotAllowed)
	}
}

func TestNonResourcePathsAreReadOnlyAndAllowlisted(t *testing.T) {
	p := Policy{Verbs: allVerbs()}
	p.Normalize()

	// Even with every verb, a non-resource URL is only ever readable.
	err := p.Decide(mustParse(t, http.MethodPost, "/healthz"))
	if err == nil {
		t.Fatal("POST /healthz was allowed")
	}
	if reason, _ := DenyReasonOf(err); reason != DenyNonResourcePath {
		t.Errorf("reason = %q, want %q", reason, DenyNonResourcePath)
	}

	// And one outside the allowlist is refused.
	if err := p.Decide(mustParse(t, http.MethodGet, "/metrics")); err == nil {
		t.Error("GET /metrics was allowed by the default non-resource allowlist")
	}
	if err := p.Decide(mustParse(t, http.MethodGet, "/logs/kube-apiserver.log")); err == nil {
		t.Error("GET /logs/... was allowed by the default non-resource allowlist")
	}
}

func TestMatchAnyPathHandlesDoubleStar(t *testing.T) {
	pats := []string{"/openapi/**"}
	for _, ok := range []string{"/openapi", "/openapi/v2", "/openapi/v3/apis/apps/v1"} {
		if !matchAnyPath(pats, ok) {
			t.Errorf("/openapi/** does not admit %q", ok)
		}
	}
	for _, no := range []string{"/openapix", "/", "/api/v1"} {
		if matchAnyPath(pats, no) {
			t.Errorf("/openapi/** admits %q", no)
		}
	}
}

func TestPolicyValidateRejectsUnknownVerbs(t *testing.T) {
	p := Policy{Verbs: []string{"get", "frobnicate"}}
	p.Normalize()
	if err := p.Validate(); err == nil {
		t.Fatal("an unknown verb validated")
	}
}

func TestPolicyValidateRejectsTraversalPatterns(t *testing.T) {
	p := Policy{Namespaces: []string{"../kube-system"}}
	p.Normalize()
	if err := p.Validate(); err == nil {
		t.Fatal(`a namespace pattern containing ".." validated`)
	}
}

// --- Intersect ------------------------------------------------------------

func TestIntersectNarrowsVerbsToWhatBothAllow(t *testing.T) {
	floor := Policy{Verbs: ReadVerbs}
	grant := Policy{Verbs: []string{"get", "list", "create", "delete"}}

	got, err := floor.Intersect(grant)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !got.ReadOnly() {
		t.Errorf("a read-only floor did not make the session read-only: %s", got.Summary())
	}
	if strings.Join(got.Verbs, ",") != "get,list" {
		t.Errorf("verbs = %v, want [get list]", got.Verbs)
	}
}

func TestIntersectRefusesWhenNothingIsInCommon(t *testing.T) {
	floor := Policy{Verbs: ReadVerbs}
	grant := Policy{Verbs: []string{"create", "delete"}}

	got, err := floor.Intersect(grant)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if err := got.Validate(); err == nil {
		t.Fatalf("a policy permitting nothing validated: %s", got.Summary())
	}
}

// TestIntersectDoesNotWidenNamespacesWhenTheFloorExcludesTheGrant is the
// regression test for a fail-open this package shipped with briefly.
//
// narrowGlobs used to return an empty slice when no grant pattern was
// literally admitted by the floor. An empty Namespaces list does not mean "no
// namespaces" — it means "no namespace confinement" — so the narrowing
// function produced a session that could read *every* namespace in the
// cluster, including kube-system, out of two policies neither of which
// allowed that.
func TestIntersectDoesNotWidenNamespacesWhenTheFloorExcludesTheGrant(t *testing.T) {
	cases := []struct {
		name         string
		floor, grant []string
	}{
		{"disjoint literals", []string{"team-a"}, []string{"team-b"}},
		{"grant glob wider than floor literal", []string{"app-1"}, []string{"app-*"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			floor := Policy{Namespaces: tc.floor}
			got, err := floor.Intersect(Policy{Namespaces: tc.grant})
			if err == nil {
				t.Fatalf("Intersect(%v, %v) succeeded with namespaces %v; AllowsNamespace(kube-system)=%v",
					tc.floor, tc.grant, got.Namespaces, got.AllowsNamespace("kube-system"))
			}
			if !strings.Contains(err.Error(), "namespaces") {
				t.Errorf("error does not name the dimension: %v", err)
			}
		})
	}
}

func TestIntersectCarriesOneSideThroughWhenTheOtherIsEmpty(t *testing.T) {
	// The common deployment: no configured floor, so the grant decides.
	got, err := (Policy{}).Intersect(Policy{Namespaces: []string{"app"}})
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if strings.Join(got.Namespaces, ",") != "app" {
		t.Errorf("namespaces = %v, want [app]", got.Namespaces)
	}
	if !got.AllowsNamespace("app") || got.AllowsNamespace("kube-system") {
		t.Errorf("the grant's confinement did not survive: %s", got.Summary())
	}

	// And a floor with no grant narrowing keeps the floor.
	got, err = (Policy{Namespaces: []string{"app"}}).Intersect(Policy{})
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if got.AllowsNamespace("kube-system") {
		t.Errorf("the floor's confinement did not survive: %s", got.Summary())
	}
}

func TestIntersectTakesTheSmallerBodyCap(t *testing.T) {
	a := Policy{MaxBodyBytes: 1000}
	b := Policy{MaxBodyBytes: 500}
	got, err := a.Intersect(b)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if got.MaxBodyBytes != 500 {
		t.Errorf("MaxBodyBytes = %d, want 500", got.MaxBodyBytes)
	}
}

func TestSummaryNamesReadOnly(t *testing.T) {
	p := ReadOnlyPolicy()
	p.Namespaces = []string{"app"}
	if got := p.Summary(); !strings.Contains(got, "read-only") || !strings.Contains(got, "app") {
		t.Errorf("Summary() = %q, want it to name read-only and the namespace", got)
	}
	rw := Policy{Verbs: []string{"get", "create"}}
	rw.Normalize()
	if got := rw.Summary(); strings.Contains(got, "read-only") {
		t.Errorf("Summary() = %q claims read-only for a policy that may create", got)
	}
}

// TestIntersectTreatsAnUnsetFloorAsNoCeiling is the regression test for a bug
// that made `cloop secret grant --verbs create` look broken.
//
// Intersect used to Normalize() both sides first, which substitutes the
// read-only set for an empty verb list. On a hub whose
// executors.kube_guard.verbs was unset — the default, and the documented way
// to let each grant speak for itself — that turned "no ceiling" into a
// hub-wide read-only ceiling, so a grant that explicitly asked to create got a
// read-only session and no error explaining why.
//
// The read-only default belongs on the *grant* (Constraints.KubeVerbs, where
// "nobody said" means "nobody asked to write"), not on the floor.
func TestIntersectTreatsAnUnsetFloorAsNoCeiling(t *testing.T) {
	var unset Policy // as config.KubeGuardConfig.Policy() renders an unset section
	grant := Policy{Verbs: []string{"get", "list", "watch", "create", "patch"}}

	got, err := unset.Intersect(grant)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ReadOnly() {
		t.Fatalf("an unset floor clamped a write grant to read-only: %s", got.Summary())
	}
	for _, v := range []string{"create", "patch"} {
		if !got.AllowsVerb(v) {
			t.Errorf("verb %q did not survive an unset floor", v)
		}
	}

	// The mirror image still holds: a floor that *is* set is a real ceiling.
	readOnlyFloor := Policy{Verbs: ReadVerbs}
	got, err = readOnlyFloor.Intersect(grant)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if !got.ReadOnly() {
		t.Errorf("an explicit read-only floor was widened by a grant: %s", got.Summary())
	}

	// And a grant that says nothing under an unset floor still resolves to
	// read-only, because the session policy's own Normalize supplies it.
	got, err = unset.Intersect(Policy{})
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	got.Normalize()
	if !got.ReadOnly() {
		t.Errorf("a grant that named no verbs is not read-only: %s", got.Summary())
	}
}
