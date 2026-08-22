package kubernetes

// networkpolicy_test.go asserts the properties that make the egress filter
// worth having. They are all properties of the *object*, because that is what
// the cluster acts on: a policy that selects the wrong Pods, allows more than
// it says, or arrives after the Pod it governs is a policy that reads correctly
// in config and enforces nothing anyone chose.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// testPodRequest is the minimum a policy can be built from.
func testPodRequest() podRequest {
	return podRequest{
		ExecutorID: "k8s-test",
		HandleID:   "h-abc123",
		Namespace:  "cloop",
		Image:      "ghcr.io/example/harness:v1",
		Argv:       []string{"cloop", "run"},
		Labels:     map[string]string{"project": "/srv/app", "task_id": "42"},
	}
}

// filteredExecutor is an egress filter with a narrow, realistic allowance.
func filteredExecutor() EgressFilter {
	return EgressFilter{
		Enabled: true,
		CIDRs:   []string{"10.8.0.0/24"},
		Ports:   []int{443, 6443},
	}
}

// TestBuildNetworkPolicy_DisabledFilterBuildsNothing is the backward
// compatibility guarantee, and it is a security-relevant one in the other
// direction: an upgrade that started firewalling existing deployments would be
// a total outage delivered by a version bump.
func TestBuildNetworkPolicy_DisabledFilterBuildsNothing(t *testing.T) {
	np, err := buildNetworkPolicy(testPodRequest(), EgressFilter{})
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	if np != nil {
		t.Fatalf("a disabled egress filter produced a NetworkPolicy: %+v", np)
	}

	// Including for a Pod that asked for no network: without a filter the
	// driver has no enforcement mechanism, and inventing one for this case
	// only would make "enabled" mean two different things.
	req := testPodRequest()
	req.DisableNetwork = true
	np, err = buildNetworkPolicy(req, EgressFilter{})
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	if np != nil {
		t.Fatalf("a disabled egress filter produced a NetworkPolicy for a no-network Pod: %+v", np)
	}
}

// TestBuildNetworkPolicy_DisableNetworkDeniesEverything: a Spec that asked for
// no network must produce a policy with no way out at all — not the executor's
// allowance, and not cluster DNS either. A sandbox that can still reach kube-dns
// has a DNS tunnel, which is an exfiltration channel with a mature toolchain.
func TestBuildNetworkPolicy_DisableNetworkDeniesEverything(t *testing.T) {
	req := testPodRequest()
	req.DisableNetwork = true

	np, err := buildNetworkPolicy(req, filteredExecutor())
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	if np == nil {
		t.Fatal("an enabled filter produced no NetworkPolicy for a no-network Pod")
	}
	if len(np.Spec.Egress) != 0 {
		t.Errorf("deny-all policy has %d egress rule(s), want none: %s", len(np.Spec.Egress), mustJSON(t, np.Spec.Egress))
	}
	for _, r := range np.Spec.Egress {
		for _, peer := range r.To {
			if peer.IPBlock != nil {
				t.Errorf("deny-all policy names an ipBlock peer %q", peer.IPBlock.CIDR)
			}
		}
	}
	// Naming both policy types with no rules of either is what denies both
	// directions; omitting Ingress would leave inbound ungoverned.
	if want := []string{"Egress", "Ingress"}; !equalStrings(np.Spec.PolicyTypes, want) {
		t.Errorf("policyTypes = %v, want %v", np.Spec.PolicyTypes, want)
	}
	if got := np.Metadata.Annotations[AnnotationEgressMode]; got != "isolated" {
		t.Errorf("egress mode annotation = %q, want %q", got, "isolated")
	}
}

// TestBuildNetworkPolicy_SelectorIsTheUniqueHandleLabel is the most important
// assertion in this file.
//
// A NetworkPolicy governs whatever its podSelector matches, and an empty
// selector in Kubernetes means *every Pod in the namespace*. A cloop policy
// that selected broadly — an empty map, or a shared label like the executor id
// or cloop.dev/managed — would apply its default-deny egress to every other
// tenant's Pods in that namespace: an outage they did not cause, cannot see the
// cause of, and did not consent to. So the selector is the per-run handle-id
// label and nothing else, and a request without one is refused rather than
// sanitised into the shared value "none".
func TestBuildNetworkPolicy_SelectorIsTheUniqueHandleLabel(t *testing.T) {
	np, err := buildNetworkPolicy(testPodRequest(), filteredExecutor())
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	sel := np.Spec.PodSelector.MatchLabels
	if len(sel) != 1 {
		t.Fatalf("podSelector has %d labels, want exactly the handle id: %v", len(sel), sel)
	}
	if got := sel[LabelHandleID]; got != "h-abc123" {
		t.Errorf("podSelector[%s] = %q, want the handle id", LabelHandleID, got)
	}
	for _, shared := range []string{LabelManaged, LabelExecutorID, LabelProject, LabelTaskID, LabelEgress} {
		if _, ok := sel[shared]; ok {
			t.Errorf("podSelector carries the shared label %q; a policy selecting it would "+
				"firewall every other run in the namespace", shared)
		}
	}

	// And the Pod built from the same request must actually carry it, or the
	// policy governs nothing while looking correct.
	pod, err := buildPod(testPodRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if pod.Metadata.Labels[LabelHandleID] != sel[LabelHandleID] {
		t.Errorf("Pod label %s = %q but the policy selects %q — the policy governs no Pod",
			LabelHandleID, pod.Metadata.Labels[LabelHandleID], sel[LabelHandleID])
	}

	req := testPodRequest()
	req.HandleID = "   "
	if _, err := buildNetworkPolicy(req, filteredExecutor()); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("buildNetworkPolicy with no handle id = %v, want ErrInvalidSpec — an empty id "+
			"sanitises to \"none\", a label every other empty-id run would share", err)
	}
}

// TestBuildNetworkPolicy_LabelsMatchTheSweepSelector: the orphan sweep finds
// policies with the selector it already uses for Pods, so a policy missing any
// of those labels is one no sweep will ever collect.
func TestBuildNetworkPolicy_LabelsMatchTheSweepSelector(t *testing.T) {
	np, err := buildNetworkPolicy(testPodRequest(), filteredExecutor())
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	if !matchesSelector(np.Metadata.Labels, executorLabelSelector("k8s-test")) {
		t.Errorf("labels %v do not match the sweep selector %q",
			np.Metadata.Labels, executorLabelSelector("k8s-test"))
	}
	for key, want := range map[string]string{
		LabelManaged:    "true",
		LabelExecutorID: "k8s-test",
		LabelHandleID:   "h-abc123",
		LabelTaskID:     "42",
		LabelProject:    "app",
	} {
		if got := np.Metadata.Labels[key]; got != want {
			t.Errorf("label %s = %q, want %q", key, got, want)
		}
	}
}

// TestNetworkPolicyName is deterministic and DNS-safe: the name is how a
// cleanup path that holds nothing but a handle id finds the object, including
// one running in a control plane that has restarted since.
func TestNetworkPolicyName(t *testing.T) {
	if a, b := networkPolicyName("h-abc123"), networkPolicyName("h-abc123"); a != b {
		t.Errorf("networkPolicyName is not deterministic: %q != %q", a, b)
	}
	if networkPolicyName("h-abc123") == networkPolicyName("h-def456") {
		t.Error("two handles produced the same policy name; one run would delete another's firewall")
	}
	for _, id := range []string{"h-abc123", "H_ABC/123", "", "  ", strings.Repeat("z", 200), "42"} {
		name := networkPolicyName(id)
		if err := validateDNSSubdomain(name, "networkpolicy name"); err != nil {
			t.Errorf("networkPolicyName(%q) = %q, which the API server would reject: %v", id, name, err)
		}
		if !strings.HasPrefix(name, networkPolicyPrefix) {
			t.Errorf("networkPolicyName(%q) = %q, want the %q prefix so an operator can tell cloop's "+
				"policies from the cluster's own", id, name, networkPolicyPrefix)
		}
	}
}

// TestBuildNetworkPolicy_CIDRAllowance checks the translation that carries the
// most meaning: the ordered "allow this CIDR, drop the private ranges" policy
// becomes an unordered set of peers, and the block set survives as ipBlock
// excepts. Losing an except would silently reopen the metadata endpoint.
func TestBuildNetworkPolicy_CIDRAllowance(t *testing.T) {
	filter := filteredExecutor()
	filter.AllowPublicInternet = true

	np, err := buildNetworkPolicy(testPodRequest(), filter)
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}

	var (
		granted  bool
		wideV4   *netfilter.IPBlock
		gotPorts = map[int]bool{}
	)
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock == nil {
				continue
			}
			switch peer.IPBlock.CIDR {
			case "10.8.0.0/24":
				granted = true
			case "0.0.0.0/0":
				wideV4 = peer.IPBlock
			}
		}
		for _, p := range rule.Ports {
			if p.Port != nil && p.Protocol == "TCP" {
				gotPorts[*p.Port] = true
			}
		}
	}
	if !granted {
		t.Errorf("the granted CIDR is not a peer: %s", mustJSON(t, np.Spec.Egress))
	}
	if !gotPorts[443] || !gotPorts[6443] {
		t.Errorf("configured ports missing from the rendered policy: %s", mustJSON(t, np.Spec.Egress))
	}
	if wideV4 == nil {
		t.Fatalf("allow_public_internet produced no 0.0.0.0/0 peer: %s", mustJSON(t, np.Spec.Egress))
	}
	// The excepts are the block set expressed as set arithmetic. These three
	// are the ones whose loss is a breach rather than an inconvenience.
	for _, want := range []string{"169.254.169.254/32", "169.254.0.0/16", "172.16.0.0/12"} {
		if !containsString(wideV4.Except, want) {
			t.Errorf("0.0.0.0/0 peer does not except %s: %v", want, wideV4.Except)
		}
	}
	// The granted CIDR is inside 10.0.0.0/8, which is blocked. Union semantics
	// re-allow it through its own peer, so leaving it in except would be
	// harmless — and a lie in an object operators read.
	if containsString(wideV4.Except, "10.8.0.0/24") {
		t.Errorf("the granted CIDR appears in except as well as in its own peer: %v", wideV4.Except)
	}

	// Cluster DNS defaults on: a default-deny egress policy without it breaks
	// name resolution, and that failure reads as a broken network.
	if !hasClusterDNSRule(np) {
		t.Errorf("no cluster DNS rule: %s", mustJSON(t, np.Spec.Egress))
	}
}

// TestBuildNetworkPolicy_ClusterDNSCanBeTurnedOff proves the pointer's "unset
// means true" is a real tri-state and not an unreachable branch.
func TestBuildNetworkPolicy_ClusterDNSCanBeTurnedOff(t *testing.T) {
	filter := filteredExecutor()
	off := false
	filter.AllowClusterDNS = &off

	np, err := buildNetworkPolicy(testPodRequest(), filter)
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	if hasClusterDNSRule(np) {
		t.Errorf("allow_cluster_dns=false still opened kube-system: %s", mustJSON(t, np.Spec.Egress))
	}
}

// TestBuildNetworkPolicy_WarningsLandInAnnotation: a hostname allowlist becomes
// the public Internet at layer 3. The rendered spec cannot show that — a
// 0.0.0.0/0 peer with excepts looks like a deliberate choice — so the sentence
// saying how much wider the filter is than the grant has to travel with the
// object, where `kubectl describe netpol` shows it.
func TestBuildNetworkPolicy_WarningsLandInAnnotation(t *testing.T) {
	filter := EgressFilter{Enabled: true, AllowPublicInternet: true, Ports: []int{443}}

	np, err := buildNetworkPolicy(testPodRequest(), filter)
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	got := np.Metadata.Annotations[AnnotationEgressWarnings]
	if got == "" {
		t.Fatalf("no %s annotation on a policy that opened the public Internet: %v",
			AnnotationEgressWarnings, np.Metadata.Annotations)
	}
	if !strings.Contains(got, "every public address") {
		t.Errorf("warning annotation %q does not say how wide the filter is", got)
	}
	if mode := np.Metadata.Annotations[AnnotationEgressMode]; mode != "filtered" {
		t.Errorf("egress mode annotation = %q, want %q", mode, "filtered")
	}

	// A deny-all policy warns too, for the opposite reason: "nothing can leave
	// this sandbox" is the other surprise worth reading in a describe.
	req := testPodRequest()
	req.DisableNetwork = true
	np, err = buildNetworkPolicy(req, filter)
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	if w := np.Metadata.Annotations[AnnotationEgressWarnings]; !strings.Contains(w, "drops every packet") {
		t.Errorf("deny-all warning annotation = %q, want it to say nothing leaves", w)
	}
}

// TestEgressFilter_Input rejects what cannot be enforced, naming the key.
func TestEgressFilter_Input(t *testing.T) {
	cases := map[string]struct {
		filter EgressFilter
		want   string
	}{
		"bad cidr":     {EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0"}, Ports: []int{443}}, "cidrs[0]"},
		"bad port":     {EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0/24"}, Ports: []int{0}}, "ports[0]"},
		"huge port":    {EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0/24"}, Ports: []int{70000}}, "ports[0]"},
		"bad resolver": {EgressFilter{Enabled: true, Resolvers: []string{"dns.example.com"}}, "resolvers[0]"},
		// A destination with no ports is a hole, and netfilter refuses to guess
		// which one was meant.
		"no ports": {EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0/24"}}, "no ports"},
		// A /0 waives the entire block set, including the metadata endpoint —
		// and the NetworkPolicy renderer could not express that even if it
		// wanted to, because its excepts have no ordering to override.
		"default route": {EgressFilter{Enabled: true, CIDRs: []string{"0.0.0.0/0"}, Ports: []int{443}}, "not an allowlist entry"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tc.filter.Compile()
			if err == nil {
				t.Fatalf("Compile(%+v) = nil, want an error", tc.filter)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	// A bare resolver address means port 53, which is what an operator writing
	// "10.96.0.10" means.
	f := EgressFilter{Enabled: true, Resolvers: []string{"10.96.0.10"}}
	in, err := f.Input()
	if err != nil {
		t.Fatalf("Input: %v", err)
	}
	if len(in.Resolvers) != 1 || in.Resolvers[0].Port() != 53 {
		t.Errorf("bare resolver = %v, want port 53 assumed", in.Resolvers)
	}
}

// TestEgressFilter_AllowsEgress: what Capabilities reports, and therefore what
// placement believes. A filter that names no destination must not advertise
// egress, or a project requiring the network is scheduled into a Pod whose
// every packet is dropped.
func TestEgressFilter_AllowsEgress(t *testing.T) {
	cases := map[string]struct {
		filter EgressFilter
		want   bool
	}{
		"no filter":        {EgressFilter{}, true},
		"cidrs":            {EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0/24"}, Ports: []int{443}}, true},
		"public internet":  {EgressFilter{Enabled: true, AllowPublicInternet: true, Ports: []int{443}}, true},
		"nothing at all":   {EgressFilter{Enabled: true}, false},
		"resolvers only":   {EgressFilter{Enabled: true, Resolvers: []string{"10.96.0.10"}}, false},
		"cluster dns only": {EgressFilter{Enabled: true, AllowClusterDNS: boolPtr(true)}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.filter.AllowsEgress(); got != tc.want {
				t.Errorf("AllowsEgress() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- lifecycle --------------------------------------------------------

// TestStart_CreatesPolicyBeforePod is the ordering guarantee. A Pod that starts
// before its policy exists reaches the network unfiltered for as long as it
// takes the second API call to land, and "briefly unfiltered" is not a
// property of a firewall.
func TestStart_CreatesPolicyBeforePod(t *testing.T) {
	ex, api, src := newTestExecutor(t, func(o *Options) { o.EgressFilter = filteredExecutor() })

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := api.creates(); len(got) != 2 || got[0] != "networkpolicy" || got[1] != "pod" {
		t.Fatalf("create order = %v, want the NetworkPolicy before the Pod", got)
	}

	name := networkPolicyName(handle.ID)
	np := api.policy(name)
	if np == nil {
		t.Fatalf("no policy named %q; have %v", name, api.policyNames())
	}
	podName := api.onlyPodName(t)
	if np.Spec.PodSelector.MatchLabels[LabelHandleID] != sanitizeLabelValue(handle.ID) {
		t.Errorf("policy selects %v, not the Pod it was created for", np.Spec.PodSelector.MatchLabels)
	}

	// And it is removed when the run ends: a policy that outlived every Pod it
	// governed would accumulate one object per task in the namespace.
	api.run(podName)
	api.terminate(podName, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)
	waitPolicyDeleted(t, api, name, 5*time.Second)
	src.waitOutstandingEmpty(t, 5*time.Second)
}

// TestClose_LeavesPoliciesOnRunningPods: Close deliberately leaves running
// Pods alone so an upgrade does not destroy work in flight. Their policies have
// to stay too — a hub restart that removed the firewall from every workload it
// was following would be the exact hole this feature closes, delivered by a
// routine deploy. ReconcileOrphans collects them on the way back up, after the
// Pods they govern.
func TestClose_LeavesPoliciesOnRunningPods(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.EgressFilter = filteredExecutor() })

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	api.run(api.onlyPodName(t))
	ex.Close()

	if deleted := api.policyDeleteNames(); containsString(deleted, networkPolicyName(handle.ID)) {
		t.Errorf("Close deleted the policy of a Pod it left running: %v", deleted)
	}
	if got := api.policyNames(); len(got) != 1 {
		t.Errorf("policies after Close = %v, want the running Pod's policy still in place", got)
	}
}

// TestStart_RefusesWhenPolicyCannotBeCreated: with the filter on, a 403 on
// NetworkPolicies must fail the Start. Falling through to an unfiltered Pod
// would turn the operator's egress allowlist into a suggestion honoured only
// when RBAC happens to be right — the failure mode this whole feature exists to
// remove.
func TestStart_RefusesWhenPolicyCannotBeCreated(t *testing.T) {
	ex, api, src := newTestExecutor(t, func(o *Options) { o.EgressFilter = filteredExecutor() })
	api.failAlways("POST /networkpolicies", apiFailure{
		Code: http.StatusForbidden, Reason: "Forbidden",
		Message: "networkpolicies.networking.k8s.io is forbidden",
	})

	_, err := ex.Start(context.Background(), testSpec())
	if err == nil {
		t.Fatal("Start succeeded with no NetworkPolicy; the Pod would have had unfiltered egress")
	}
	if !strings.Contains(err.Error(), "networkpolicies") {
		t.Errorf("error %q does not name the RBAC rule the operator has to add", err)
	}
	if names := api.podNames(); len(names) != 0 {
		t.Errorf("a Pod was created despite the policy failing: %v", names)
	}
	if out := src.outstanding(); len(out) != 0 {
		t.Errorf("a refused Start leaked leases: %v", out)
	}
}

// TestStart_PolicyIsRemovedWhenThePodIsRefused: the Pod create is the call most
// likely to fail (quota, admission, PodSecurity), and it happens after the
// policy exists. Leaving the policy behind would leak one object per refused
// Start until the next sweep.
func TestStart_PolicyIsRemovedWhenThePodIsRefused(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.EgressFilter = filteredExecutor() })
	api.failAlways("POST /pods", apiFailure{
		Code: http.StatusForbidden, Reason: "Forbidden", Message: "pods is forbidden",
	})

	if _, err := ex.Start(context.Background(), testSpec()); err == nil {
		t.Fatal("Start succeeded against an API server refusing Pods")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(api.policyNames()) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("policies left behind by a refused Start: %v", api.policyNames())
}

// TestStart_NoPolicyWhenFilterIsDisabled: the default path must make no
// NetworkPolicy call at all. An executor whose RBAC has no networkpolicies rule
// is the overwhelming majority, and a driver that probed the endpoint anyway
// would fill their logs with authorization failures for a feature they do not
// use.
func TestStart_NoPolicyWhenFilterIsDisabled(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)

	if _, err := ex.Start(context.Background(), testSpec()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := api.creates(); len(got) != 1 || got[0] != "pod" {
		t.Errorf("create order = %v, want the Pod alone", got)
	}
	if calls := api.requestsMatching("networkpolicies"); len(calls) != 0 {
		t.Errorf("the driver called %v with the egress filter disabled", calls)
	}
}

// TestReconcileOrphans_SweepsPolicies: a control plane killed mid-run leaves
// the policy behind with the Pod. The sweep collects both, and — the part that
// matters — leaves alone anything young enough to belong to a Start still in
// flight, because removing a live Pod's policy unfilters it silently.
func TestReconcileOrphans_SweepsPolicies(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		o.EgressFilter = filteredExecutor()
		o.OrphanGracePeriod = 10 * time.Minute
	})
	labels := map[string]string{
		LabelManaged:    "true",
		LabelExecutorID: "k8s-test",
		LabelTaskID:     "7",
		LabelHandleID:   "h-old",
	}
	api.seedNetworkPolicy("cloop-egress-h-old", labels, time.Hour)
	api.seedNetworkPolicy("cloop-egress-h-young", labels, time.Minute)

	removed, err := ex.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if !containsString(removed, "cloop/networkpolicy/cloop-egress-h-old") {
		t.Errorf("removed = %v, want the aged orphan policy", removed)
	}
	if got := api.policyNames(); len(got) != 1 || got[0] != "cloop-egress-h-young" {
		t.Errorf("policies after sweep = %v, want the young one left alone: a policy created "+
			"moments ago belongs to a Start still in flight", got)
	}
}

// TestReconcileOrphans_LeavesPoliciesAloneWhenDisabled: an executor that does
// not filter egress must not call the endpoint. It creates no policies and its
// identity has no reason to hold the RBAC to list them; a 403 per startup is
// how operators learn to ignore logs.
func TestReconcileOrphans_LeavesPoliciesAloneWhenDisabled(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	api.seedNetworkPolicy("cloop-egress-h-old", map[string]string{
		LabelManaged: "true", LabelExecutorID: "k8s-test", LabelTaskID: "7",
	}, time.Hour)

	if _, err := ex.ReconcileOrphans(context.Background()); err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if calls := api.requestsMatching("networkpolicies"); len(calls) != 0 {
		t.Errorf("the sweep called %v with the egress filter disabled", calls)
	}
	if got := api.policyNames(); len(got) != 1 {
		t.Errorf("policies = %v, want the seeded one untouched", got)
	}
}

// TestPreflight_EgressFindings covers both honest answers: no filter is a
// warning that says so, and a filter is only as real as the RBAC behind it.
func TestPreflight_EgressFindings(t *testing.T) {
	t.Run("disabled warns", func(t *testing.T) {
		ex, _, _ := newTestExecutor(t, nil)
		f := findingNamed(t, ex.Preflight(context.Background()), "egress")
		if f.Level != LevelWarn {
			t.Errorf("egress finding = %s, want %s when nothing is filtered", f.Level, LevelWarn)
		}
		if !strings.Contains(f.Message, "unrestricted egress") {
			t.Errorf("message %q no longer says egress is unrestricted", f.Message)
		}
	})

	t.Run("enabled checks RBAC", func(t *testing.T) {
		ex, _, _ := newTestExecutor(t, func(o *Options) { o.EgressFilter = filteredExecutor() })
		report := ex.Preflight(context.Background())
		if f := findingNamed(t, report, "egress"); f.Level != LevelOK {
			t.Errorf("egress finding = %s (%s), want ok when the endpoint answers", f.Level, f.Message)
		}
		// Always a warning, even on the happy path: creating the object proves
		// the API server stored it, not that any CNI enforces it.
		f := findingNamed(t, report, "egress-enforcement")
		if f.Level != LevelWarn || !strings.Contains(f.Message, "CNI") {
			t.Errorf("egress-enforcement finding = %+v, want a warning naming the CNI", f)
		}
	})

	t.Run("enabled without RBAC fails", func(t *testing.T) {
		ex, api, _ := newTestExecutor(t, func(o *Options) { o.EgressFilter = filteredExecutor() })
		api.failAlways("GET /networkpolicies", apiFailure{
			Code: http.StatusForbidden, Reason: "Forbidden", Message: "networkpolicies is forbidden",
		})
		report := ex.Preflight(context.Background())
		f := findingNamed(t, report, "egress")
		if f.Level != LevelFail {
			t.Errorf("egress finding = %s, want %s when the identity cannot manage policies", f.Level, LevelFail)
		}
		if !strings.Contains(f.Fix, "networkpolicies") {
			t.Errorf("fix %q does not name the missing rule", f.Fix)
		}
		if report.OK() {
			t.Error("a report with an unenforceable egress filter must not be OK")
		}
	})
}

// --- helpers ----------------------------------------------------------

func findingNamed(t *testing.T, report PreflightReport, name string) Finding {
	t.Helper()
	for _, f := range report.Findings {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no %q finding in %+v", name, report.Findings)
	return Finding{}
}

func hasClusterDNSRule(np *netfilter.NetworkPolicy) bool {
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.NamespaceSelector != nil {
				return true
			}
		}
	}
	return false
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func waitPolicyDeleted(t *testing.T, api *fakeAPI, name string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if containsString(api.policyDeleteNames(), name) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("policy %q was not deleted within %s; deletes = %v", name, d, api.policyDeleteNames())
}

// TestCapabilitiesReportFilteredEgress: the fleet view an operator audits is
// built from Capabilities, so a driver that installs a NetworkPolicy and
// reports filtered_egress=false is invisible in exactly the report meant to
// find unfiltered executors.
//
// The field says what cloop did, not what the cluster enforces — a
// NetworkPolicy is applied by the CNI, and whether one is running is not
// something the API answers. Preflight carries that caveat.
func TestCapabilitiesReportFilteredEgress(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		e := &Executor{opts: Options{EgressFilter: EgressFilter{
			Enabled:             enabled,
			AllowPublicInternet: true,
			Ports:               []int{443},
		}}}
		caps := e.Capabilities()
		if caps.FilteredEgress != enabled {
			t.Errorf("EgressFilter.Enabled=%t produced FilteredEgress=%t", enabled, caps.FilteredEgress)
		}
		// And it stays distinct from NetworkEgress, which answers "does the
		// workload have an interface at all" — the question placement asks.
		if !caps.NetworkEgress {
			t.Errorf("EgressFilter.Enabled=%t made NetworkEgress false; a filtered Pod still has a network", enabled)
		}
	}
}
