package container

// Tests for the per-project egress scope (Task 20236): one project asking to be
// cut off from non-public address space while its neighbours on the same
// executor are not.
//
// The compilation tests are the substance here. Installing the ruleset needs
// nft(8) and CAP_NET_ADMIN and is covered by the existing firewall integration
// test; what is specific to a *scope* is which policy gets compiled from the
// pair (executor filter, project request), and that is pure — which is exactly
// why effectiveFilter and EgressFilter.Policy are.

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// scopedExecutor builds an executor with the given filter, without touching a
// runtime: effectiveFilter and Policy are pure and this keeps the table of cases
// below readable.
func scopedExecutor(t *testing.T, f EgressFilter) *Executor {
	t.Helper()
	return &Executor{id: "sbx-test", opts: Options{Network: NetworkBridge, EgressFilter: f}}
}

// TestEgressScopePublicDropsPrivateSpace is requirement 2 stated as a test: a
// project that asks for the public Internet is allowed out and refused the
// operator's internal network, with the cloud metadata endpoint among the drops.
func TestEgressScopePublicDropsPrivateSpace(t *testing.T) {
	// An executor with no filter of its own: the plainest form of the request,
	// and the one an operator gets by default.
	ex := scopedExecutor(t, EgressFilter{Resolvers: []string{"9.9.9.9:53"}})

	f, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err != nil {
		t.Fatalf("effectiveFilter: %v", err)
	}
	policy, err := f.Policy()
	if err != nil {
		t.Fatalf("compiling the scope's policy: %v", err)
	}

	// Evaluate is the policy's own matcher, so this asserts the ordering the
	// compiler produced rather than the text of a ruleset.
	cases := []struct {
		addr string
		port uint16
		want netfilter.Verdict
		why  string
	}{
		{"93.184.216.34", 443, netfilter.VerdictAllow, "a public address is the whole point of the scope"},
		{"10.4.5.6", 443, netfilter.VerdictDrop, "RFC1918 is the operator's internal network"},
		{"172.16.9.9", 22, netfilter.VerdictDrop, "RFC1918, the 172.16/12 block"},
		{"192.168.1.1", 80, netfilter.VerdictDrop, "RFC1918, the home/office block"},
		{"169.254.169.254", 80, netfilter.VerdictDrop, "the cloud metadata endpoint hands out instance credentials"},
		{"100.64.0.1", 443, netfilter.VerdictDrop, "carrier-grade NAT is not the public Internet"},
		{"fc00::1", 443, netfilter.VerdictDrop, "IPv6 ULA is private space too"},
		{"fe80::1", 443, netfilter.VerdictDrop, "IPv6 link-local"},
	}
	for _, tc := range cases {
		addr, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("bad test address %q: %v", tc.addr, err)
		}
		got, reason := policy.Evaluate(addr, tc.port, netfilter.ProtoTCP)
		if got != tc.want {
			t.Errorf("%s:%d = %v (%s), want %v — %s", tc.addr, tc.port, got, reason, tc.want, tc.why)
		}
	}
}

// TestEgressScopePublicAllowsEveryPort is the consequence of the scope's bound
// being the block set rather than a port list. A project that renounced the
// intranet did not thereby ask to be limited to 443, and demanding it name ports
// would be a restriction finer than the one requested.
func TestEgressScopePublicAllowsEveryPort(t *testing.T) {
	ex := scopedExecutor(t, EgressFilter{Resolvers: []string{"9.9.9.9:53"}})
	f, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err != nil {
		t.Fatalf("effectiveFilter: %v", err)
	}
	if !f.AllowAllPorts {
		t.Fatal("the public scope did not set AllowAllPorts, so netfilter.Compile will " +
			"refuse it for naming destinations with no ports")
	}
	policy, err := f.Policy()
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	addr := netip.MustParseAddr("93.184.216.34")
	for _, port := range []uint16{22, 443, 5432, 9418} {
		if got, reason := policy.Evaluate(addr, port, netfilter.ProtoTCP); got != netfilter.VerdictAllow {
			t.Errorf("public address on port %d = %v (%s), want allow", port, got, reason)
		}
	}
}

// TestEgressScopeNarrowsAnOperatorsCIDRGrant is the invariant the whole feature
// rests on: a scope removes reach and never adds it. An executor configured to
// let sandboxes into 10.0.0.0/8 must not let a scoped project in there just
// because the executor's policy says so.
func TestEgressScopeNarrowsAnOperatorsCIDRGrant(t *testing.T) {
	ex := scopedExecutor(t, EgressFilter{
		Enabled:    true,
		AllowCIDRs: []string{"10.0.0.0/8"},
		AllowPorts: []int{443},
		Resolvers:  []string{"10.0.0.53:53"},
	})

	// Without a scope the executor's own grant stands — the control, without
	// which the assertion below could pass on a policy that allows nothing.
	base, err := ex.effectiveFilter(executor.EgressScopeUnset)
	if err != nil {
		t.Fatalf("effectiveFilter(unset): %v", err)
	}
	basePolicy, err := base.Policy()
	if err != nil {
		t.Fatalf("Policy(unset): %v", err)
	}
	if got, _ := basePolicy.Evaluate(netip.MustParseAddr("10.4.5.6"), 443, netfilter.ProtoTCP); got != netfilter.VerdictAllow {
		t.Fatalf("the executor's own CIDR grant does not allow 10.4.5.6:443 (%v); the "+
			"narrowing assertion below would be vacuous", got)
	}

	scoped, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err != nil {
		t.Fatalf("effectiveFilter(public): %v", err)
	}
	if len(scoped.AllowCIDRs) != 0 {
		t.Errorf("the scope kept the executor's CIDR allow list %v; a scope may only "+
			"remove reach", scoped.AllowCIDRs)
	}
	scopedPolicy, err := scoped.Policy()
	if err != nil {
		t.Fatalf("Policy(public): %v", err)
	}
	if got, _ := scopedPolicy.Evaluate(netip.MustParseAddr("10.4.5.6"), 443, netfilter.ProtoTCP); got != netfilter.VerdictDrop {
		t.Errorf("a project that asked for the public scope can still reach 10.4.5.6:443 "+
			"(%v); the executor's grant leaked through the narrowing", got)
	}
}

// TestEgressScopePublicRefusedOnABrokerOnlyExecutor is the case that must not be
// silently downgraded. On an internal network the sandbox's only path out is the
// broker's hostname allowlist, so "the public Internet" is more reach than the
// operator granted.
func TestEgressScopePublicRefusedOnABrokerOnlyExecutor(t *testing.T) {
	ex := scopedExecutor(t, EgressFilter{Enabled: true, Internal: true})

	_, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err == nil {
		t.Fatal("accepted the public scope on an internal-network executor, which would " +
			"widen the sandbox's reach on the strength of a repo-committed file")
	}
	if !strings.Contains(err.Error(), "internal") {
		t.Errorf("error %q does not explain that the executor is internal-only", err)
	}
}

// TestEgressScopePublicNeedsResolvers covers the failure that would otherwise be
// invisible. Dropping private space drops whatever resolver the runtime handed
// the sandbox, and the symptom — every hostname failing — reads as "the Internet
// is blocked" and is not fixed by anything in the allow list.
func TestEgressScopePublicNeedsResolvers(t *testing.T) {
	ex := scopedExecutor(t, EgressFilter{})

	_, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err == nil {
		t.Fatal("accepted the public scope with no resolvers configured, producing a " +
			"sandbox with working IP egress and no working DNS")
	}
	if !strings.Contains(err.Error(), "resolvers") {
		t.Errorf("error %q does not name the config key that fixes it", err)
	}
}

// TestEgressScopeResolversStayReachable is the other half of that: once named,
// the resolver has to survive the drop it would otherwise fall under. A DNS
// server on 10.0.0.53 is in private space by address and infrastructure by role.
func TestEgressScopeResolversStayReachable(t *testing.T) {
	ex := scopedExecutor(t, EgressFilter{Resolvers: []string{"10.0.0.53:53"}})
	f, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err != nil {
		t.Fatalf("effectiveFilter: %v", err)
	}
	policy, err := f.Policy()
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	resolver := netip.MustParseAddr("10.0.0.53")
	for _, proto := range []netfilter.Proto{netfilter.ProtoUDP, netfilter.ProtoTCP} {
		if got, reason := policy.Evaluate(resolver, 53, proto); got != netfilter.VerdictAllow {
			t.Errorf("the configured resolver 10.0.0.53:53/%v = %v (%s), want allow — DNS "+
				"would fail for every name in the sandbox", proto, got, reason)
		}
	}
	// The waiver must be exactly the resolver, not its whole subnet.
	if got, _ := policy.Evaluate(netip.MustParseAddr("10.0.0.54"), 443, netfilter.ProtoTCP); got != netfilter.VerdictDrop {
		t.Errorf("naming a resolver at 10.0.0.53 also opened 10.0.0.54:443 (%v); the "+
			"waiver is meant to be one address and one port", got)
	}
}

// TestEgressScopeNoneNeedsNoFilter keeps the strongest scope available on the
// hosts least able to install a ruleset. Taking the interfaces away needs no
// nft, no CAP_NET_ADMIN and no bridge.
func TestEgressScopeNoneNeedsNoFilter(t *testing.T) {
	if executor.EgressScopeNone.NeedsFilter() {
		t.Error("the none scope claims to need a filter, which would make the strongest " +
			"confinement depend on nft(8) being installed")
	}
	if !executor.EgressScopeNone.RemovesNetwork() {
		t.Error("the none scope does not remove the network")
	}
	if executor.EgressScopePublic.RemovesNetwork() {
		t.Error("the public scope removes the network, which would silently confine every " +
			"project that asked to reach the Internet")
	}
}

// TestEgressScopeGetsItsOwnBridgeAndTable is what keeps one project's
// confinement from becoming its neighbour's. Two scopes sharing a bridge would
// share a ruleset, and the second Apply would replace the first's.
func TestEgressScopeGetsItsOwnBridgeAndTable(t *testing.T) {
	unscopedNet := networkName("sbx-a", executor.EgressScopeUnset)
	publicNet := networkName("sbx-a", executor.EgressScopePublic)
	if unscopedNet == publicNet {
		t.Fatalf("a scoped and an unscoped project share the bridge %q, so they would "+
			"share one nftables ruleset", unscopedNet)
	}
	// validateNetworkName, not netfilter.ValidateInterfaceName: this string is a
	// *runtime network* name passed to `podman network create` as argv, and the
	// bridge interface — which is what becomes an nft iifname, and what is
	// bound by IFNAMSIZ — is derived by the runtime and read back by
	// inspectNetwork. Checking the 15-byte limit here would be checking the
	// wrong string against the wrong bound.
	if err := validateNetworkName(publicNet); err != nil {
		t.Errorf("scoped network name %q is not a valid network name: %v", publicNet, err)
	}

	unscopedTable := firewallTable("sbx-a", executor.EgressScopeUnset)
	publicTable := firewallTable("sbx-a", executor.EgressScopePublic)
	if unscopedTable == publicTable {
		t.Fatalf("both scopes compile into the nftables table %q", unscopedTable)
	}
	if err := netfilter.ValidateNftName(publicTable); err != nil {
		t.Errorf("scoped table name %q is not a valid nft name: %v", publicTable, err)
	}
	// The unsuffixed name has to stay exactly what it was, or an upgrade
	// orphans every running sandbox's bridge.
	if want := "cloop-sbx-sbx-a"; unscopedNet != want {
		t.Errorf("the unscoped network name changed to %q (want %q); sandboxes already "+
			"attached to the old bridge would be orphaned by an upgrade", unscopedNet, want)
	}
}

// TestEgressScopeRequiresACapableExecutor pins the placement consequence. A
// driver that cannot confine one project independently must refuse the work
// rather than run it unconfined.
func TestEgressScopeRequiresACapableExecutor(t *testing.T) {
	spec := executor.Spec{Argv: []string{"/bin/true"}, EgressScope: executor.EgressScopePublic}
	req := spec.SandboxRequirements()
	if !req.RequireEgressScope {
		t.Error("a spec with an egress scope implies no RequireEgressScope, so it could be " +
			"placed on a driver that ignores the field")
	}
	if !req.RequireNetworkEgress {
		t.Error("the public scope does not require network egress, so it could be placed " +
			"on an executor with --network=none and report success")
	}

	none := executor.Spec{Argv: []string{"/bin/true"}, EgressScope: executor.EgressScopeNone}
	if none.SandboxRequirements().RequireEgressScope {
		t.Error("the none scope requires SupportsEgressScope, which would refuse executors " +
			"that can deliver exactly what it asks for")
	}
}
