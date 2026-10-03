package kubernetes

// Tests for the Kubernetes driver's half of the stored firewall levels (Task
// 20363): a Pod's firewall rules become its NetworkPolicy, rules reaching
// further than the executor's egress_filter are refused, and no rules are
// installed on a cluster that has not shown it enforces NetworkPolicy.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
)

func TestForRulesRendersTheRulesWithTheirDenies(t *testing.T) {
	cfg := EgressFilter{Enabled: true, AllowPublicInternet: true, CIDRs: []string{"10.8.0.0/16"}, Ports: []int{443}}
	rules := executor.FirewallRules{AllowCIDRs: []string{"10.8.0.0/16"}, DenyCIDRs: []string{"10.8.9.0/24"},
		AllowPorts: []int{443}}
	req := testPodRequest()
	req.EgressRules = &rules
	np, err := buildNetworkPolicy(req, cfg)
	if err != nil {
		t.Fatalf("buildNetworkPolicy: %v", err)
	}
	if np == nil {
		t.Fatal("a Pod carrying rules must get a policy")
	}
	raw := ""
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				raw += peer.IPBlock.CIDR + " except " + strings.Join(peer.IPBlock.Except, ",") + "; "
			}
		}
	}
	if !strings.Contains(raw, "10.8.0.0/16 except 10.8.9.0/24") {
		t.Errorf("the denied range must be carved out of the allow: %s", raw)
	}
	if strings.Contains(raw, "0.0.0.0/0") {
		t.Errorf("the rules do not allow the public Internet, but the policy does: %s", raw)
	}
}

func TestForRulesRefusesRulesWiderThanTheEgressFilter(t *testing.T) {
	cfg := EgressFilter{Enabled: true, CIDRs: []string{"10.8.0.0/16"}, Ports: []int{443}}
	for name, rules := range map[string]executor.FirewallRules{
		"the Internet": {AllowPublicInternet: true, AllowPorts: []int{443}},
		"wider range":  {AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}},
		"another port": {AllowCIDRs: []string{"10.8.1.0/24"}, AllowPorts: []int{22}},
	} {
		req := testPodRequest()
		r := rules
		req.EgressRules = &r
		if _, err := buildNetworkPolicy(req, cfg); !fwpolicy.IsExceeds(err) {
			t.Errorf("%s: buildNetworkPolicy = %v, want a containment refusal", name, err)
		}
	}
	// An unfiltered executor bounds nothing: the rules alone become the policy.
	req := testPodRequest()
	req.EgressRules = &executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
	if np, err := buildNetworkPolicy(req, EgressFilter{}); err != nil || np == nil {
		t.Errorf("rules on an unfiltered executor = %v, %v; want a policy", np, err)
	}
}

func TestRulesNeedAClusterThatEnforcesNetworkPolicy(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	rules := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
	spec := testSpec()
	spec.EgressRules = &rules

	if p := ex.EgressPosture(); p.Enforceable || !strings.Contains(p.Reason, "probe-network-policy") {
		t.Errorf("an unverified cluster must not claim to enforce rules: %+v", p)
	}
	_, err := ex.Start(context.Background(), spec)
	if err == nil || !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "enforces NetworkPolicy") {
		t.Fatalf("Start under rules on an unverified cluster = %v", err)
	}

	ex.RecordNetworkPolicyVerdict(freshVerdict(true, ex.ID()))
	if p := ex.EgressPosture(); !p.Enforceable || !p.RemovesNetwork {
		t.Errorf("a proven cluster enforces rules: %+v", p)
	}
	if err := ex.checkRules(spec); err != nil {
		t.Errorf("checkRules on a proven cluster: %v", err)
	}
}
