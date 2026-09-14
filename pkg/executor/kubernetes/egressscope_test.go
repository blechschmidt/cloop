package kubernetes

// egressscope_test.go covers the half of this feature that is not the probe:
// what the driver actually does with a project's capabilities.egress once
// placement has stopped refusing it.
//
// The pairing matters. Advertising SupportsEgressScope without honouring the
// scope would be a worse bug than refusing it was: the project would be placed,
// told it succeeded, and run with the executor's own policy — which is the
// silent over-permission, arrived at from the opposite direction.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// scopedRequest is a podRequest carrying a project's egress scope.
func scopedRequest(scope executor.EgressScope) podRequest {
	req := testPodRequest()
	req.EgressScope = scope
	if scope.RemovesNetwork() {
		req.DisableNetwork = true
	}
	return req
}

// TestForScope_OnlyEverNarrows is the invariant the whole feature rests on.
func TestForScope_OnlyEverNarrows(t *testing.T) {
	t.Run("an unset scope leaves the executor's filter alone", func(t *testing.T) {
		in := filteredExecutor()
		got, err := in.forScope(executor.EgressScopeUnset)
		if err != nil {
			t.Fatalf("forScope: %v", err)
		}
		if !equalStrings(got.CIDRs, in.CIDRs) || got.AllowPublicInternet != in.AllowPublicInternet {
			t.Errorf("an unset scope changed the filter: %+v -> %+v", in, got)
		}
	})

	t.Run("public on an unfiltered executor installs a policy", func(t *testing.T) {
		// The case that makes SupportsEgressScope meaningful on a deployment
		// with no executors.kubernetes.egress_filter at all: the project's own
		// request is what turns the policy on.
		got, err := EgressFilter{}.forScope(executor.EgressScopePublic)
		if err != nil {
			t.Fatalf("forScope: %v", err)
		}
		if !got.Enabled {
			t.Fatal("a project asking for `egress: public` on an unfiltered executor got no filter, " +
				"so no NetworkPolicy would be created and the scope would be silently ignored")
		}
		if !got.AllowPublicInternet || !got.AllowAllPorts {
			t.Errorf("the public scope did not compile to public-on-any-port: %+v", got)
		}
		if len(got.CIDRs) != 0 {
			t.Errorf("the public scope kept private CIDRs: %v", got.CIDRs)
		}
	})

	t.Run("public drops the executor's private-space grants", func(t *testing.T) {
		in := EgressFilter{
			Enabled: true, AllowPublicInternet: true,
			CIDRs: []string{"10.8.0.0/24"}, Ports: []int{443},
			Resolvers: []string{"10.96.0.10"},
		}
		got, err := in.forScope(executor.EgressScopePublic)
		if err != nil {
			t.Fatalf("forScope: %v", err)
		}
		if len(got.CIDRs) != 0 {
			t.Errorf("the operator's private-space grant survived the project's narrowing: %v", got.CIDRs)
		}
		if !equalStrings(got.Resolvers, in.Resolvers) {
			t.Errorf("resolvers were dropped (%v); a sandbox that cannot resolve a name has no "+
				"usable Internet access and the symptom reads as a blocked network", got.Resolvers)
		}
	})

	t.Run("public is refused when the executor grants no public reach", func(t *testing.T) {
		// The one case that cannot be honoured. The executor's Pods reach only
		// the CIDRs an operator named; "the public Internet" is more than that,
		// so honouring it literally would be a widening dressed as a narrowing.
		in := EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0/24"}, Ports: []int{443}}
		_, err := in.forScope(executor.EgressScopePublic)
		if !errors.Is(err, executor.ErrUnsupported) {
			t.Fatalf("err = %v, want ErrUnsupported — a scope that asks for more reach than the "+
				"executor grants must be refused, not widened and not silently narrowed to nothing", err)
		}
		if !strings.Contains(err.Error(), "allow_public_internet") {
			t.Errorf("the refusal does not name the config key that would resolve it: %v", err)
		}
	})
}

// TestBuildNetworkPolicy_HonoursProjectScope proves the resolution reaches the
// object, not just the filter struct.
func TestBuildNetworkPolicy_HonoursProjectScope(t *testing.T) {
	t.Run("public on an unfiltered executor produces a policy", func(t *testing.T) {
		np, err := buildNetworkPolicy(scopedRequest(executor.EgressScopePublic), EgressFilter{})
		if err != nil {
			t.Fatalf("buildNetworkPolicy: %v", err)
		}
		if np == nil {
			t.Fatal("no NetworkPolicy for a project that asked to be confined")
		}
		if got := np.Metadata.Annotations[AnnotationEgressMode]; got == "" {
			t.Error("the policy records no egress mode")
		}
		// Still selects exactly one Pod: a scope must not widen the selector
		// any more than it widens the allowance.
		if len(np.Spec.PodSelector.MatchLabels) != 1 {
			t.Errorf("podSelector = %v, want exactly the handle id", np.Spec.PodSelector.MatchLabels)
		}
		// And it really does drop private space, which is the entire request.
		for _, rule := range np.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock == nil {
					continue
				}
				if strings.HasPrefix(peer.IPBlock.CIDR, "10.") || strings.HasPrefix(peer.IPBlock.CIDR, "192.168.") {
					t.Errorf("the public scope allows private range %q", peer.IPBlock.CIDR)
				}
			}
		}
	})

	t.Run("none denies everything even on an unfiltered executor", func(t *testing.T) {
		// `egress: none` is carried by DisableNetwork, which podRequestFor sets
		// from the scope. Without an executor filter there is no policy to
		// build — the driver has no mechanism — so this asserts the wiring that
		// makes the two spellings mean the same thing.
		req := scopedRequest(executor.EgressScopeNone)
		np, err := buildNetworkPolicy(req, filteredExecutor())
		if err != nil {
			t.Fatalf("buildNetworkPolicy: %v", err)
		}
		if np == nil {
			t.Fatal("no NetworkPolicy for a no-network Pod on a filtering executor")
		}
		if len(np.Spec.Egress) != 0 {
			t.Errorf("a no-network Pod has %d egress rule(s)", len(np.Spec.Egress))
		}
	})

	t.Run("a refused scope surfaces as an error, not a wider policy", func(t *testing.T) {
		narrow := EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0/24"}, Ports: []int{443}}
		if _, err := buildNetworkPolicy(scopedRequest(executor.EgressScopePublic), narrow); err == nil {
			t.Fatal("buildNetworkPolicy accepted a scope the executor cannot honour")
		}
	})
}

// TestPodRequestFor_CarriesTheScope closes the gap between the Spec and the
// object: a scope the driver never reads is a scope the driver never applies.
func TestPodRequestFor_CarriesTheScope(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	spec := testSpec()
	spec.EgressScope = executor.EgressScopePublic

	req, err := ex.podRequestFor(context.Background(), spec, "h-scope", "cloop", "")
	if err != nil {
		t.Fatalf("podRequestFor: %v", err)
	}
	if req.EgressScope != executor.EgressScopePublic {
		t.Errorf("podRequest.EgressScope = %q, want %q — the Pod would be built from the "+
			"executor's policy and the project's request would vanish", req.EgressScope,
			executor.EgressScopePublic)
	}

	spec.EgressScope = executor.EgressScopeNone
	req, err = ex.podRequestFor(context.Background(), spec, "h-none", "cloop", "")
	if err != nil {
		t.Fatalf("podRequestFor: %v", err)
	}
	if !req.DisableNetwork {
		t.Error("`egress: none` did not disable the network; the two spellings of the same " +
			"request must end in the same place")
	}
}

// TestCapabilities_EgressScopeFollowsEnforcement is the gate itself.
func TestCapabilities_EgressScopeFollowsEnforcement(t *testing.T) {
	cases := []struct {
		name string
		set  func(*Options)
		want bool
	}{
		{"unverified refuses", func(o *Options) {}, false},
		{"an operator assertion grants", func(o *Options) {
			o.NetworkPolicyEnforcement.Assertion = boolp(true)
		}, true},
		{"an explicit denial refuses", func(o *Options) {
			o.NetworkPolicyEnforcement.Assertion = boolp(false)
		}, false},
		{"a fresh proof grants", func(o *Options) {
			o.NetworkPolicyEnforcement.Verdict = freshVerdict(true, "k8s-test")
		}, true},
		{"a refutation refuses even with an assertion", func(o *Options) {
			o.NetworkPolicyEnforcement.Assertion = boolp(true)
			o.NetworkPolicyEnforcement.Verdict = freshVerdict(false, "k8s-test")
		}, false},
		{"an enabled egress filter alone is not enough", func(o *Options) {
			// The distinction this whole task exists for: creating the object
			// and having it applied are different claims.
			o.EgressFilter = filteredExecutor()
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex, _, _ := newTestExecutor(t, tc.set)
			if got := ex.Capabilities().SupportsEgressScope; got != tc.want {
				t.Errorf("SupportsEgressScope = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPlacement_RefusalNamesTheProbe: the refusal an operator actually sees has
// to carry the command that resolves it, or it gets resolved by deleting the
// capability from sandbox.yaml.
func TestPlacement_RefusalNamesTheProbe(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)

	_, err := executor.Select(
		[]executor.Candidate{{Executor: ex}},
		executor.Requirements{RequireEgressScope: true},
	)
	if err == nil {
		t.Fatal("placement accepted an egress-scoped project on an unverified cluster")
	}

	var pe *executor.PlacementError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %T (%v), want *executor.PlacementError", err, err)
	}
	if pe.Constraint != executor.ConstraintEgressScope {
		t.Errorf("constraint = %q, want %q", pe.Constraint, executor.ConstraintEgressScope)
	}

	// The message is the product here: it is the only thing most operators will
	// ever read about this feature.
	msg := err.Error()
	if !strings.Contains(msg, "--probe-network-policy") {
		t.Errorf("the placement refusal does not name the probe: %q", msg)
	}
	if strings.Contains(msg, "nft(8)") {
		t.Errorf("a Kubernetes refusal offers the container driver's remedy, which does not "+
			"apply to this deployment: %q", msg)
	}
}

// TestStart_ScopedProjectGetsAPolicyAndLosesItAtTheEnd is the new path end to
// end: an executor with no egress_filter of its own, a project that asked to be
// confined, and a cluster proven to enforce.
//
// Before this feature that combination was unplaceable. The risk in making it
// placeable is that the policy is created and then never removed — the
// executor's own filter is off, so every filter-gated cleanup path would skip
// it, and the namespace would accumulate one dead firewall per task.
func TestStart_ScopedProjectGetsAPolicyAndLosesItAtTheEnd(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		o.NetworkPolicyEnforcement.Assertion = boolp(true)
	})
	if ex.opts.EgressFilter.Enabled {
		t.Fatal("this case is only meaningful with the executor filter off")
	}

	spec := testSpec()
	spec.EgressScope = executor.EgressScopePublic
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Created, and before the Pod: a Pod that starts first has a window of
	// unfiltered egress, and a window is all an exfiltration needs.
	if got := api.creates(); len(got) != 2 || got[0] != "networkpolicy" || got[1] != "pod" {
		t.Fatalf("create order = %v, want the NetworkPolicy before the Pod", got)
	}
	name := networkPolicyName(handle.ID)
	np := api.policy(name)
	if np == nil {
		t.Fatalf("a project that asked for `egress: public` got no policy; have %v", api.policyNames())
	}
	if np.Spec.PodSelector.MatchLabels[LabelHandleID] != sanitizeLabelValue(handle.ID) {
		t.Errorf("the policy selects %v, not the Pod it was created for", np.Spec.PodSelector.MatchLabels)
	}

	// And removed when the run ends, even though the executor's own filter —
	// the thing every other cleanup path keys off — is switched off.
	podName := api.onlyPodName(t)
	api.run(podName)
	api.terminate(podName, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)
	waitPolicyDeleted(t, api, name, 5*time.Second)
}

// TestReconcile_SweepsPolicyWhenOnlyScopesCreateThem.
//
// The leak this guards against was introduced by the feature itself. Before
// per-project scopes, only a configured egress_filter created policies, so the
// sweep could skip executors that had none. Now a *project* can cause one on an
// executor whose own filter is off — and a hub that restarted mid-run would
// strand it.
func TestReconcile_SweepsPolicyWhenOnlyScopesCreateThem(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		// No egress_filter at all: policies here can only come from a project.
		o.NetworkPolicyEnforcement.Assertion = boolp(true)
		o.OrphanGracePeriod = time.Minute
	})
	if ex.opts.EgressFilter.Enabled {
		t.Fatal("this case is only meaningful with the executor filter off")
	}

	// A policy from a run this process has no handle for: what a control-plane
	// restart leaves behind.
	orphan := networkPolicyName("h-from-a-previous-life")
	api.seedNetworkPolicy(orphan, map[string]string{
		LabelManaged:    "true",
		LabelExecutorID: ex.ID(),
		// Required, not decorative: executorLabelSelector ends in a bare
		// task-id, which is an existence requirement, so an object without one
		// is invisible to the sweep.
		LabelTaskID:   "7",
		LabelHandleID: "h-from-a-previous-life",
	}, 2*time.Hour)

	removed, err := ex.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if !containsString(removed, "cloop/networkpolicy/"+orphan) {
		t.Errorf("the sweep did not collect %q (removed %v) — an orphaned policy outlived the run "+
			"it belonged to", orphan, removed)
	}
	if containsString(api.policyNames(), orphan) {
		t.Errorf("the policy still exists after the sweep: %v", api.policyNames())
	}
}

// TestReconcile_LeavesATrackedPolicyAlone is the other direction, and the more
// dangerous one: deleting a live Pod's policy unfilters a running workload
// without stopping it.
func TestReconcile_LeavesATrackedPolicyAlone(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		o.EgressFilter = filteredExecutor()
		o.OrphanGracePeriod = time.Minute
	})

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	live := networkPolicyName(handle.ID)
	if api.policy(live) == nil {
		t.Fatalf("Start created no policy; the case cannot run")
	}

	removed, err := ex.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if containsString(removed, "cloop/networkpolicy/"+live) {
		t.Fatal("the sweep deleted the firewall of a Pod that is still running")
	}
	if api.policy(live) == nil {
		t.Fatal("the running Pod's policy is gone")
	}
}

// TestCreatesNetworkPolicies covers the predicate the sweep gates on directly,
// since getting it wrong is invisible until something leaks.
func TestCreatesNetworkPolicies(t *testing.T) {
	cases := []struct {
		name string
		set  func(*Options)
		want bool
	}{
		{"neither", func(o *Options) {}, false},
		{"a configured filter", func(o *Options) { o.EgressFilter = filteredExecutor() }, true},
		{"scope-capable only", func(o *Options) {
			o.NetworkPolicyEnforcement.Assertion = boolp(true)
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex, _, _ := newTestExecutor(t, tc.set)
			if got := ex.createsNetworkPolicies(); got != tc.want {
				t.Errorf("createsNetworkPolicies() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPreflight_EnforcementFindingTracksTheEvidence.
//
// The severity of this finding is the operator's whole view of the question, and
// it is chosen by what each state *costs* rather than by how it sounds. A
// refutation is a fail: the operator has an egress filter that is decorative and
// every confined project will be refused. Unverified is a warn, because that is
// where every deployment starts and nobody has looked. Proven and asserted are
// passes — and they are distinguishable, because "somebody typed true" and "a
// probe watched a connection die" are different grades of evidence and an
// auditor reading this report has to be able to tell them apart.
func TestPreflight_EnforcementFindingTracksTheEvidence(t *testing.T) {
	cases := []struct {
		name      string
		set       func(*Options)
		wantLevel string
		wantIn    string
	}{
		{"unverified warns", func(o *Options) {}, LevelWarn, "--probe-network-policy"},
		{"asserted passes and says so", func(o *Options) {
			o.NetworkPolicyEnforcement.Assertion = boolp(true)
		}, LevelOK, "network_policy_enforced"},
		{"proven passes", func(o *Options) {
			o.NetworkPolicyEnforcement.Verdict = freshVerdict(true, "k8s-test")
		}, LevelOK, "probe proved"},
		{"refuted fails", func(o *Options) {
			o.NetworkPolicyEnforcement.Verdict = freshVerdict(false, "k8s-test")
		}, LevelFail, "CNI"},
		{"denied warns", func(o *Options) {
			o.NetworkPolicyEnforcement.Assertion = boolp(false)
		}, LevelWarn, "network_policy_enforced"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex, _, _ := newTestExecutor(t, tc.set)
			report := ex.Preflight(context.Background())
			f := findingNamed(t, report, "egress-enforcement")
			if f.Level != tc.wantLevel {
				t.Errorf("level = %s, want %s (message: %s)", f.Level, tc.wantLevel, f.Message)
			}
			if !strings.Contains(f.Message+" "+f.Fix, tc.wantIn) {
				t.Errorf("finding does not mention %q:\n  message: %s\n  fix: %s",
					tc.wantIn, f.Message, f.Fix)
			}
		})
	}
}
