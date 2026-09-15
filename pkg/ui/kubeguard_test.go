package ui

// kubeguard_test.go covers the wiring, not the monitor: pkg/kubeguard has its
// own tests for parsing and deciding. What is only testable here is the seam —
// how a grant's constraints become a session policy, what happens when the
// operator's floor and the grant disagree, and whether a released lease takes
// its sessions with it.

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// testKubeconfigYAML carries a known plaintext, so "the cluster credential did
// not reach the sandbox" is a substring assertion rather than a structural one.
const testKubeClusterToken = "REAL-CLUSTER-TOKEN-ui-wiring"

func testKubeconfigYAML() []byte {
	return []byte(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: c
  cluster: {server: "https://kube.internal:6443", insecure-skip-tls-verify: true}
contexts:
- name: prod
  context: {cluster: c, user: u, namespace: team-a}
users:
- name: u
  user: {token: ` + testKubeClusterToken + `}
`)
}

// newTestKubeGuardService returns a service whose policy floor is rendered the
// way config.KubeGuardConfig.Policy() renders one.
//
// That means *not* calling Normalize: it would substitute the read-only set
// for an empty verb list, turning "no ceiling configured" into a hub-wide
// read-only ceiling — the exact bug TestGuardHonoursAGrantThatAsksForWrites
// caught, and a helper that normalised here would have hidden it again.
func newTestKubeGuardService(t *testing.T, floor kubeguard.Policy) *kubeGuardService {
	t.Helper()
	reg, err := kubeguard.NewRegistry("https://hub.internal:8444")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	floor.Verbs = kubeguard.NormalizeVerbs(floor.Verbs)
	return &kubeGuardService{reg: reg, baseURL: "https://hub.internal:8444", policy: floor}
}

// TestGuardMintsAReadOnlySessionByDefault is the headline: a grant that names
// no verbs produces a session that cannot change the cluster, and the document
// the sandbox receives carries no cluster credential.
func TestGuardMintsAReadOnlySessionByDefault(t *testing.T) {
	svc := newTestKubeGuardService(t, kubeguard.Policy{})

	res, err := kubeGuard{svc: svc}.GuardKubeconfig(context.Background(), secretbroker.KubeGuardRequest{
		Kubeconfig: testKubeconfigYAML(),
		// What Constraints.KubeVerbs() returns for a grant that said nothing.
		Verbs:      []string{"get", "list", "watch"},
		Namespaces: []string{"team-a"},
		GrantID:    "grant-1",
		LeaseID:    "lease-1",
		ProjectID:  "/srv/app",
		Owner:      "dev@example.com",
	})
	if err != nil {
		t.Fatalf("GuardKubeconfig: %v", err)
	}
	if !res.Guarded() {
		t.Fatal("the guard declined when a service was configured")
	}
	if !res.ReadOnly {
		t.Errorf("session is not read-only: %s", res.Summary)
	}
	if strings.Contains(string(res.Kubeconfig), testKubeClusterToken) {
		t.Error("the cluster credential reached the delivered kubeconfig")
	}
	if !strings.Contains(string(res.Kubeconfig), svc.baseURL) {
		t.Error("the delivered kubeconfig does not point at the monitor")
	}

	sess, ok := svc.reg.Session(res.SessionID)
	if !ok {
		t.Fatal("the session was not registered")
	}
	if sess.Policy.AllowsNamespace("kube-system") {
		t.Error("the grant's namespace allowlist did not reach the session")
	}
	// The audit rows should name the person whose credential is being spent,
	// not the executor that happened to run the task.
	if sess.Actor != "dev@example.com" {
		t.Errorf("session actor = %q, want the credential's owner", sess.Actor)
	}
}

// TestGuardHonoursAGrantThatAsksForWrites: the default is read-only, but a
// grant that names write verbs gets them when the floor permits.
func TestGuardHonoursAGrantThatAsksForWrites(t *testing.T) {
	svc := newTestKubeGuardService(t, kubeguard.Policy{})

	res, err := kubeGuard{svc: svc}.GuardKubeconfig(context.Background(), secretbroker.KubeGuardRequest{
		Kubeconfig: testKubeconfigYAML(),
		Verbs:      []string{"get", "list", "watch", "create", "patch"},
		Namespaces: []string{"team-a"},
	})
	if err != nil {
		t.Fatalf("GuardKubeconfig: %v", err)
	}
	if res.ReadOnly {
		t.Errorf("a grant naming create/patch produced a read-only session: %s", res.Summary)
	}
	sess, _ := svc.reg.Session(res.SessionID)
	if !sess.Policy.AllowsVerb("create") {
		t.Error("the grant's create verb did not reach the session")
	}
}

// TestOperatorFloorCannotBeWidenedByAGrant is the composition rule: a hub set
// to read-only stays read-only however much a grant asks for.
func TestOperatorFloorCannotBeWidenedByAGrant(t *testing.T) {
	svc := newTestKubeGuardService(t, kubeguard.Policy{Verbs: kubeguard.ReadVerbs})

	res, err := kubeGuard{svc: svc}.GuardKubeconfig(context.Background(), secretbroker.KubeGuardRequest{
		Kubeconfig: testKubeconfigYAML(),
		Verbs:      []string{"get", "list", "watch", "create", "delete"},
		Namespaces: []string{"team-a"},
	})
	if err != nil {
		t.Fatalf("GuardKubeconfig: %v", err)
	}
	if !res.ReadOnly {
		t.Fatalf("a read-only hub floor was widened by a grant: %s", res.Summary)
	}
	sess, _ := svc.reg.Session(res.SessionID)
	for _, v := range []string{"create", "delete"} {
		if sess.Policy.AllowsVerb(v) {
			t.Errorf("verb %q survived a read-only floor", v)
		}
	}
}

// TestGuardRefusesWhenFloorAndGrantShareNothing: refusing is the only safe
// answer, and it has to be an error rather than a default — see the
// fail-open this replaced, covered in pkg/kubeguard's Intersect tests.
func TestGuardRefusesWhenFloorAndGrantShareNothing(t *testing.T) {
	cases := []struct {
		name  string
		floor kubeguard.Policy
		req   secretbroker.KubeGuardRequest
		want  string
	}{
		{
			name:  "no verb in common",
			floor: kubeguard.Policy{Verbs: kubeguard.ReadVerbs},
			req: secretbroker.KubeGuardRequest{
				Verbs: []string{"create"}, Namespaces: []string{"team-a"},
			},
			want: "permits no verbs",
		},
		{
			name:  "no namespace in common",
			floor: kubeguard.Policy{Namespaces: []string{"team-a"}},
			req: secretbroker.KubeGuardRequest{
				Verbs: []string{"get"}, Namespaces: []string{"team-b"},
			},
			want: "namespaces",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestKubeGuardService(t, tc.floor)
			tc.req.Kubeconfig = testKubeconfigYAML()
			tc.req.GrantID = "grant-x"

			res, err := kubeGuard{svc: svc}.GuardKubeconfig(context.Background(), tc.req)
			if err == nil {
				t.Fatalf("the lease was honoured; session policy would have been %q",
					res.Summary)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not say which dimension failed: %v", err)
			}
			if !strings.Contains(err.Error(), "grant-x") {
				t.Errorf("error does not name the grant: %v", err)
			}
			if len(svc.reg.Sessions()) != 0 {
				t.Error("a session was minted for a refused lease")
			}
		})
	}
}

// TestNilKubeGuardDeclinesRatherThanFails is how a hub with no monitor keeps
// delivering kubeconfigs the old way.
func TestNilKubeGuardDeclinesRatherThanFails(t *testing.T) {
	res, err := kubeGuard{svc: nil}.GuardKubeconfig(context.Background(),
		secretbroker.KubeGuardRequest{Kubeconfig: testKubeconfigYAML()})
	if err != nil {
		t.Fatalf("a hub with no monitor failed the lease: %v", err)
	}
	if res.Guarded() {
		t.Error("a nil service claimed to have guarded the credential")
	}
}

// TestUnavailableKubeGuardFailsClosed is the opposite case, and the difference
// matters: "this deployment does not intercept" is a valid configuration,
// "it was supposed to and is not" must not silently deliver the credential.
func TestUnavailableKubeGuardFailsClosed(t *testing.T) {
	_, err := unavailableKubeGuard().GuardKubeconfig(context.Background(),
		secretbroker.KubeGuardRequest{Kubeconfig: testKubeconfigYAML()})
	if err == nil {
		t.Fatal("the unavailable guard delivered a credential")
	}
	if !strings.Contains(err.Error(), "executors.kube_guard") {
		t.Errorf("error does not name the configuration that is not in effect: %v", err)
	}
}

// TestAttachKubeGuardFailsClosedWhenRequired: a hub whose config asked for the
// monitor and has none must refuse, not fall back.
func TestAttachKubeGuardFailsClosedWhenRequired(t *testing.T) {
	prevSvc, prevReq := kubeGuardSingleton.Load(), kubeGuardRequired.Load()
	t.Cleanup(func() {
		kubeGuardSingleton.Store(prevSvc)
		kubeGuardRequired.Store(prevReq)
	})
	kubeGuardSingleton.Store(nil)

	b := &secretbroker.Broker{}

	kubeGuardRequired.Store(false)
	if got := attachKubeGuard(b); got.KubeGuard != nil {
		t.Error("a hub that never asked for a monitor got a guard attached")
	}

	b = &secretbroker.Broker{}
	kubeGuardRequired.Store(true)
	if got := attachKubeGuard(b); got.KubeGuard == nil {
		t.Fatal("a hub that asked for a monitor and has none was left unguarded")
	}
	if _, err := b.KubeGuard.GuardKubeconfig(context.Background(),
		secretbroker.KubeGuardRequest{Kubeconfig: testKubeconfigYAML()}); err == nil {
		t.Error("the attached guard did not fail closed")
	}
}

// TestClosingALeaseRevokesItsMonitorSessions is the gap Task 20178 closed for
// the other kinds: without it a released lease wipes the kubeconfig file while
// the session it already authenticated with keeps working until its TTL.
func TestClosingALeaseRevokesItsMonitorSessions(t *testing.T) {
	svc := newTestKubeGuardService(t, kubeguard.Policy{})

	res, err := kubeGuard{svc: svc}.GuardKubeconfig(context.Background(), secretbroker.KubeGuardRequest{
		Kubeconfig: testKubeconfigYAML(),
		Verbs:      []string{"get"},
		Namespaces: []string{"team-a"},
		LeaseID:    "lease-1",
	})
	if err != nil {
		t.Fatalf("GuardKubeconfig: %v", err)
	}
	sess, ok := svc.reg.Session(res.SessionID)
	if !ok {
		t.Fatal("the session was not registered")
	}

	// The lease carries the session id in the material's environment, which is
	// how closeKubeGuardSessions finds it again without the broker knowing
	// what a monitor session is.
	lease := &secretbroker.Lease{Materials: []secretbroker.Material{{
		Kind: secretbroker.KindKubeconfig,
		Env:  map[string]string{secretbroker.KubeGuardSessionEnvKey: res.SessionID},
	}}}

	prev := kubeGuardSingleton.Load()
	kubeGuardSingleton.Store(svc)
	t.Cleanup(func() { kubeGuardSingleton.Store(prev) })

	closeKubeGuardSessions(lease)
	if !sess.Closed() {
		t.Error("the monitor session survived the lease that created it")
	}
	// Idempotent: Close runs from a defer and a lease may be released twice.
	closeKubeGuardSessions(lease)
	closeKubeGuardSessions(nil)
}

// TestGrantEnforcementReportsKubeconfig: a grant row must not claim the
// stronger mode when the monitor is not running — a promise the hub is not
// keeping is worse than the weaker honest answer.
func TestGrantEnforcementReportsKubeconfig(t *testing.T) {
	prev := kubeGuardSingleton.Load()
	t.Cleanup(func() { kubeGuardSingleton.Store(prev) })

	kubeGuardSingleton.Store(nil)
	if got := grantEnforcement(secretbroker.KindKubeconfig); got != enforcementUnguarded {
		t.Errorf("with no monitor, enforcement = %q, want %q", got, enforcementUnguarded)
	}

	kubeGuardSingleton.Store(newTestKubeGuardService(t, kubeguard.Policy{}))
	if got := grantEnforcement(secretbroker.KindKubeconfig); got != enforcementProxy {
		t.Errorf("with a monitor, enforcement = %q, want %q", got, enforcementProxy)
	}
	// Kinds whose payload is narrowed by rewriting have no gap to report.
	if got := grantEnforcement(secretbroker.KindEnv); got != "" {
		t.Errorf("env grant reported enforcement %q, want none", got)
	}
}

// TestGuardRefusesAnEmptyKubeconfig avoids minting a session against nothing.
func TestGuardRefusesAnEmptyKubeconfig(t *testing.T) {
	svc := newTestKubeGuardService(t, kubeguard.Policy{})
	if _, err := (kubeGuard{svc: svc}).GuardKubeconfig(context.Background(),
		secretbroker.KubeGuardRequest{Verbs: []string{"get"}}); err == nil {
		t.Fatal("an empty kubeconfig was guarded")
	}
}
