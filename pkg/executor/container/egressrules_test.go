package container

// Tests for the container driver's half of the stored firewall levels (Task
// 20363): what the driver reports as its own bound, how it builds a filter from
// a workload's rules — refusing rules that reach further — and how it keys the
// bridge and table those rules run on. Pure, like egressscope_test.go:
// installing the ruleset needs nft(8) and is covered by the firewall
// integration test and the end-to-end run on a device.

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

var labFilter = EgressFilter{
	Enabled:             true,
	AllowPublicInternet: true,
	AllowCIDRs:          []string{"10.20.0.0/16"},
	DenyCIDRs:           []string{"203.0.113.0/24"},
	AllowPorts:          []int{80, 443},
	Resolvers:           []string{"1.1.1.1"},
	Broker:              "10.7.0.2:8118",
	HostPatterns:        []string{"*.github.com"},
}

func TestOwnRulesDistinguishesUnboundedFromClosed(t *testing.T) {
	if got := scopedExecutor(t, EgressFilter{}).OwnRules(); got != nil {
		t.Errorf("an unfiltered bridge bounds nothing, got %v", got.Describe())
	}
	for name, ex := range map[string]*Executor{
		"no network":    {id: "a", opts: Options{Network: NetworkNone}},
		"internal only": scopedExecutor(t, EgressFilter{Enabled: true, Internal: true}),
	} {
		got := ex.OwnRules()
		if got == nil || got.HasDestination() {
			t.Errorf("%s must bound everything down to nothing, got %+v", name, got)
		}
	}
	got := scopedExecutor(t, labFilter).OwnRules()
	want := executor.FirewallRules{AllowPublicInternet: true, AllowCIDRs: []string{"10.20.0.0/16"},
		DenyCIDRs: []string{"203.0.113.0/24"}, AllowPorts: []int{80, 443}, Resolvers: []string{"1.1.1.1"}}
	if got == nil || !fwpolicy.Equal(*got, want) {
		t.Errorf("OwnRules = %+v, want the configured allow list", got)
	}
	// A virtual executor's filter says "every port" with AllowAllPorts, which
	// reads back as the empty port list the form means by it.
	vx, _ := FilterFromRules(&executor.FirewallRules{AllowPublicInternet: true}, "")
	if got := scopedExecutor(t, vx).OwnRules(); got == nil || len(got.AllowPorts) != 0 || !got.AllowPublicInternet {
		t.Errorf("a virtual executor's own rules = %+v", got)
	}
}

func TestFilterForRulesRefusesRulesWiderThanTheExecutor(t *testing.T) {
	ex := scopedExecutor(t, labFilter)
	for name, want := range map[string]executor.FirewallRules{
		"a private range": {AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}},
		"another port":    {AllowPublicInternet: true, AllowPorts: []int{22}},
		"every port":      {AllowPublicInternet: true},
		"metadata":        {AllowCIDRs: []string{"169.254.169.254"}, AllowPorts: []int{80}},
	} {
		_, err := ex.filterForRules(want)
		if !fwpolicy.IsExceeds(err) || !errors.Is(err, executor.ErrUnsupported) {
			t.Errorf("%s: filterForRules = %v, want a containment refusal", name, err)
		}
	}
}

func TestFilterForRulesInstallsANarrowingAndKeepsTheOperatorsBridge(t *testing.T) {
	ex := scopedExecutor(t, labFilter)
	want := executor.FirewallRules{AllowCIDRs: []string{"10.20.5.0/24"}, AllowPorts: []int{443},
		Resolvers: []string{"1.1.1.1"}, DenyCIDRs: []string{"203.0.113.0/24"}}
	f, err := ex.filterForRules(want)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Enabled || f.AllowPublicInternet || strings.Join(f.AllowCIDRs, ",") != "10.20.5.0/24" {
		t.Errorf("filter = %+v", f)
	}
	if f.Broker != labFilter.Broker || strings.Join(f.HostPatterns, ",") != "*.github.com" {
		t.Errorf("the operator's broker and host patterns are not a workload's to drop: %+v", f)
	}
	policy, err := f.Policy()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		addr string
		port uint16
		want netfilter.Verdict
	}{
		{"10.20.5.9", 443, netfilter.VerdictAllow},
		{"10.20.6.9", 443, netfilter.VerdictDrop},
		{"93.184.216.34", 443, netfilter.VerdictDrop},
		{"10.20.5.9", 80, netfilter.VerdictDrop},
	} {
		if v, why := policy.Evaluate(mustAddr(t, c.addr), c.port, netfilter.ProtoTCP); v != c.want {
			t.Errorf("%s:%d = %v (%s), want %v", c.addr, c.port, v, why, c.want)
		}
	}
	if _, err := ex.filterForRules(executor.FirewallRules{}); err == nil {
		t.Error("rules that reach nothing need no network, not an enabled filter allowing nothing")
	}
}

func TestRulesNamingNeverSharesABridgeBetweenDifferentRules(t *testing.T) {
	a := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
	b := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{80}}
	aAgain := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443, 443}}
	na, nb := networkName("vx-1", confinement{rules: &a}), networkName("vx-1", confinement{rules: &b})
	if na == nb || firewallTable("vx-1", confinement{rules: &a}) == firewallTable("vx-1", confinement{rules: &b}) {
		t.Fatal("two rule sets must never share a bridge or a table: the second Apply would replace the first")
	}
	if networkName("vx-1", confinement{rules: &aAgain}) != na {
		t.Error("two spellings of one rule set must share a bridge")
	}
	if networkName("vx-1", confinement{}) != "cloop-sbx-vx-1" {
		t.Error("a workload carrying nothing must keep the executor's own bridge")
	}
	if !strings.HasPrefix(na, "cloop-sbx-vx-1-r") || validateNetworkName(na) != nil {
		t.Errorf("rules network %q", na)
	}
	if err := netfilter.ValidateNftName(firewallTable("vx-1", confinement{rules: &a})); err != nil {
		t.Errorf("rules table: %v", err)
	}
	// Rules take precedence over a scope: the hub has folded the scope in.
	if networkName("vx-1", confinement{scope: executor.EgressScopePublic, rules: &a}) != na {
		t.Error("rules must key the bridge even when a scope is also present")
	}
}

func TestStartProvesRulesBeforeAnythingIsStaged(t *testing.T) {
	ex := scopedExecutor(t, labFilter)
	wide := executor.FirewallRules{AllowCIDRs: []string{"192.168.0.0/16"}, AllowPorts: []int{443}}
	err := ex.checkRules(executor.Spec{EgressRules: &wide})
	if !fwpolicy.IsExceeds(err) || !strings.Contains(err.Error(), "192.168.0.0/16") {
		t.Fatalf("checkRules = %v", err)
	}
	narrow := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
	bound := executor.FirewallRules{AllowCIDRs: []string{"1.1.1.0/24"}, AllowPorts: []int{443}}
	if err := ex.checkRules(executor.Spec{EgressRules: &narrow, EgressBound: &bound}); !fwpolicy.IsExceeds(err) {
		t.Errorf("rules wider than the device bound the dispatch carried must be refused: %v", err)
	}
	if err := ex.checkRules(executor.Spec{EgressRules: &narrow}); err != nil {
		t.Errorf("a narrowing must pass: %v", err)
	}
}

func TestEgressPostureOfTheHubsContainerExecutor(t *testing.T) {
	p := scopedExecutor(t, labFilter).EgressPosture()
	if p.DeviceID != "sbx-test" || !p.Enforceable || !p.RemovesNetwork || p.Config == nil {
		t.Errorf("posture = %+v", p)
	}
	rootless := &Executor{id: "rl", opts: Options{Network: NetworkBridge}, rt: Runtime{Name: "podman", Rootless: true}}
	if p := rootless.EgressPosture(); p.Enforceable || !strings.Contains(p.Reason, "rootless") {
		t.Errorf("rootless posture = %+v", p)
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
