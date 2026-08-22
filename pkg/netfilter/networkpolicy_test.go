package netfilter

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
)

// networkpolicy_test.go guards the translation from an ordered filter to an
// unordered one.
//
// A Policy is a first-match-wins list with two verdicts. A NetworkPolicy is a
// union of allows with no deny rule at all, so every drop has to survive as an
// `ipBlock.except` and every "allow this before dropping that" has to survive
// as set arithmetic. That is the kind of rewrite where an omission is invisible
// — the object still applies, the Pod still runs, and the only difference is
// that something the compiler decided to drop is reachable. So the assertions
// here are about which peers exist and, just as importantly, which do not.

// mustRenderNP renders a NetworkPolicy or fails the test.
func mustRenderNP(t *testing.T, p Policy, opts NetworkPolicyOptions) *NetworkPolicy {
	t.Helper()
	np, err := RenderNetworkPolicy(p, opts)
	if err != nil {
		t.Fatalf("RenderNetworkPolicy: %v", err)
	}
	return np
}

// npOpts is a minimally valid set of options: a name and a selector that
// matches one sandbox.
func npOpts() NetworkPolicyOptions {
	return NetworkPolicyOptions{
		Name:        "cloop-sbx-1",
		Namespace:   "cloop",
		PodSelector: map[string]string{"cloop.dev/sandbox": "sbx-1"},
	}
}

// npIPBlocks flattens every ipBlock peer in the egress rules.
func npIPBlocks(np *NetworkPolicy) []*IPBlock {
	var out []*IPBlock
	for _, r := range np.Spec.Egress {
		for _, peer := range r.To {
			if peer.IPBlock != nil {
				out = append(out, peer.IPBlock)
			}
		}
	}
	return out
}

// npFindIPBlock returns the ipBlock peer for a cidr, or nil.
func npFindIPBlock(np *NetworkPolicy, cidr string) *IPBlock {
	for _, b := range npIPBlocks(np) {
		if b.CIDR == cidr {
			return b
		}
	}
	return nil
}

// npPortSignature renders a rule's ports as comparable strings.
func npPortSignature(ports []NetworkPolicyPort) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.Port == nil {
			out = append(out, p.Protocol+"/*")
			continue
		}
		out = append(out, fmt.Sprintf("%s/%d", p.Protocol, *p.Port))
	}
	sort.Strings(out)
	return out
}

// npHasString reports whether a list contains s.
func npHasString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// npWidePolicy is the public-Internet shape: the one where the drops have to
// become excepts, because it is the only one with a peer wide enough to need
// them.
func npWidePolicy(t *testing.T) Policy {
	t.Helper()
	return mustCompilePolicy(t, Input{AllowPublicInternet: true, AllowPorts: []uint16{443}})
}

// TestNetworkPolicyRefusesAnEmptyPodSelector: an empty podSelector in
// Kubernetes does not mean "no Pods", it means *every* Pod in the namespace.
// Rendering one would apply a sandbox's deny-all egress policy to every other
// tenant sharing the namespace, and because a NetworkPolicy is additive there
// is no second policy that could undo it. The failure would also not look like
// a firewall bug: the neighbours would simply lose the network.
func TestNetworkPolicyRefusesAnEmptyPodSelector(t *testing.T) {
	p := mustCompilePolicy(t, Input{})
	for name, sel := range map[string]map[string]string{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			opts := npOpts()
			opts.PodSelector = sel
			np, err := RenderNetworkPolicy(p, opts)
			if err == nil {
				t.Fatalf("RenderNetworkPolicy accepted an empty pod selector: %+v", np)
			}
			if np != nil {
				t.Error("RenderNetworkPolicy returned an object alongside its error")
			}
		})
	}
}

// TestNetworkPolicyRefusesAnEmptyName: the API server rejects a nameless
// object, but it rejects it at apply time, which is after the sandbox has been
// created and is running. Refusing here keeps the failure on the side of the
// ordering where nothing is running unfiltered yet.
func TestNetworkPolicyRefusesAnEmptyName(t *testing.T) {
	opts := npOpts()
	opts.Name = ""
	if np, err := RenderNetworkPolicy(mustCompilePolicy(t, Input{}), opts); err == nil {
		t.Fatalf("RenderNetworkPolicy accepted an empty name: %+v", np)
	}
}

// TestPolicyTypesNameIngressWithNoIngressRules: in a NetworkPolicy, listing a
// policy type with an empty rule list is the *only* way to deny that direction.
// Omitting "Ingress" from policyTypes does not deny inbound, it leaves inbound
// ungoverned — so a sandbox that would otherwise be unreachable stays reachable
// by anything in the cluster that can find its Pod IP. The difference between
// the two is one string, and nothing about the applied object looks wrong.
func TestPolicyTypesNameIngressWithNoIngressRules(t *testing.T) {
	np := mustRenderNP(t, npWidePolicy(t), npOpts())

	for _, want := range []string{"Egress", "Ingress"} {
		if !npHasString(np.Spec.PolicyTypes, want) {
			t.Errorf("policyTypes = %v, missing %q", np.Spec.PolicyTypes, want)
		}
	}
	if len(np.Spec.Ingress) != 0 {
		t.Errorf("ingress rules = %+v, want none: an empty list is what denies inbound", np.Spec.Ingress)
	}
}

// TestIsolatedPolicyRendersNoPeers: an isolated sandbox has no egress at all,
// and in this model that is expressed by naming Egress in policyTypes and then
// listing nothing. A single stray peer — the loopback rule leaking through, a
// "harmless" default — would be the entire difference between a sealed sandbox
// and one with a hole, so the assertion is on the count, not on the contents.
func TestIsolatedPolicyRendersNoPeers(t *testing.T) {
	np := mustRenderNP(t, mustCompilePolicy(t, Input{}), npOpts())

	if blocks := npIPBlocks(np); len(blocks) != 0 {
		t.Errorf("isolated policy rendered %d ipBlock peers, want none: %+v", len(blocks), blocks)
	}
	for _, r := range np.Spec.Egress {
		if len(r.To) != 0 {
			t.Errorf("isolated policy rendered an egress rule with peers: %+v", r)
		}
	}
	if !npHasString(np.Spec.PolicyTypes, "Egress") {
		t.Errorf("policyTypes = %v: without Egress the empty rule list denies nothing", np.Spec.PolicyTypes)
	}
}

// TestBlockSetBecomesIPBlockExcepts is the heart of the translation. The
// ordered form opens the Internet *after* the drops, so "allow everything" and
// "never the metadata service" coexist. A NetworkPolicy has no drop rule and no
// order, so the only construction that means the same thing is a 0.0.0.0/0 peer
// with every blocked prefix carved out of it. Miss one except and a policy that
// reads "the public Internet" hands the sandbox the cloud metadata endpoint —
// which is to say, the node's credentials.
func TestBlockSetBecomesIPBlockExcepts(t *testing.T) {
	np := mustRenderNP(t, npWidePolicy(t), npOpts())

	v4 := npFindIPBlock(np, "0.0.0.0/0")
	if v4 == nil {
		t.Fatalf("no 0.0.0.0/0 peer for a public-Internet allow: %+v", np.Spec.Egress)
	}
	for _, want := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
		"169.254.169.254/32", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4",
	} {
		if !npHasString(v4.Except, want) {
			t.Errorf("0.0.0.0/0 peer does not except %s: %v", want, v4.Except)
		}
	}

	// IPv6 is not an afterthought here: a v6-only except set that forgot ULA
	// or link-local would be the same hole reached over a AAAA record.
	v6 := npFindIPBlock(np, "::/0")
	if v6 == nil {
		t.Fatalf("no ::/0 peer for a public-Internet allow: %+v", np.Spec.Egress)
	}
	for _, want := range []string{"fc00::/7", "fe80::/10", "ff00::/8", "::1/128"} {
		if !npHasString(v6.Except, want) {
			t.Errorf("::/0 peer does not except %s: %v", want, v6.Except)
		}
	}

	// Every except must sit strictly inside the cidr it carves, or the API
	// server rejects the object and the sandbox gets no policy at all.
	for _, e := range v4.Except {
		pfx, err := netip.ParsePrefix(e)
		if err != nil {
			t.Errorf("except %q is not a prefix: %v", e, err)
			continue
		}
		if !pfx.Addr().Is4() || pfx.Bits() == 0 {
			t.Errorf("except %q is not a v4 prefix inside 0.0.0.0/0", e)
		}
	}
	for _, e := range v6.Except {
		pfx, err := netip.ParsePrefix(e)
		if err != nil {
			t.Errorf("except %q is not a prefix: %v", e, err)
			continue
		}
		if pfx.Addr().Is4() || pfx.Bits() == 0 {
			t.Errorf("except %q is not a v6 prefix inside ::/0", e)
		}
	}
}

// TestGrantedCIDRIsItsOwnPeerWhileTheBlockStays is "allow before drop"
// expressed without order. The ordered filter allows a granted 10.8.0.0/24 and
// then drops 10.0.0.0/8, and the narrow allow wins because it is first. Here
// there is no first, so the grant becomes a second peer and the broad block
// stays in the wide peer's except list — peers are a union, so the union
// re-allows exactly the granted prefix.
//
// Doing this the "obvious" way instead — lifting 10.0.0.0/8 out of except
// because part of it was granted — would hand the sandbox the whole of RFC1918
// on the strength of a /24 grant.
func TestGrantedCIDRIsItsOwnPeerWhileTheBlockStays(t *testing.T) {
	p := mustCompilePolicy(t, Input{
		AllowCIDRs:          []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		AllowPorts:          []uint16{443},
		AllowPublicInternet: true,
	})
	np := mustRenderNP(t, p, npOpts())

	if npFindIPBlock(np, "10.8.0.0/24") == nil {
		t.Errorf("the granted CIDR has no peer of its own: %+v", npIPBlocks(np))
	}
	wide := npFindIPBlock(np, "0.0.0.0/0")
	if wide == nil {
		t.Fatalf("no 0.0.0.0/0 peer: %+v", np.Spec.Egress)
	}
	if !npHasString(wide.Except, "10.0.0.0/8") {
		t.Errorf("granting 10.8.0.0/24 lifted the 10.0.0.0/8 block: %v", wide.Except)
	}
	// And the grant did not quietly widen itself.
	if npFindIPBlock(np, "10.0.0.0/8") != nil {
		t.Error("a /24 grant produced a 10.0.0.0/8 peer")
	}
}

// TestPeersWithDifferentPortsAreSeparateRules: inside a single egress rule,
// `to` and `ports` form a cross product — every peer gets every port. Merging
// the broker (8118/TCP) with the resolvers (53/UDP and 53/TCP) into one rule
// would therefore not be a tidier rendering of the same policy; it would open
// 53 on the broker and 8118 on the DNS server, neither of which any grant
// named. The grouping is a security property, not a formatting choice.
func TestPeersWithDifferentPortsAreSeparateRules(t *testing.T) {
	p := mustCompilePolicy(t, Input{
		Brokers:   []netip.AddrPort{netip.MustParseAddrPort("10.7.0.2:8118")},
		Resolvers: []netip.AddrPort{netip.MustParseAddrPort("10.7.0.10:53")},
	})
	np := mustRenderNP(t, p, npOpts())

	// Collect, per rule, the peers and the port signature.
	type seen struct {
		ports []string
		peers []string
	}
	var rules []seen
	for _, r := range np.Spec.Egress {
		var peers []string
		for _, peer := range r.To {
			if peer.IPBlock != nil {
				peers = append(peers, peer.IPBlock.CIDR)
			}
		}
		rules = append(rules, seen{ports: npPortSignature(r.Ports), peers: peers})
	}

	want := map[string][]string{
		"TCP/8118": {"10.7.0.2/32"},
		"UDP/53":   {"10.7.0.10/32"},
		"TCP/53":   {"10.7.0.10/32"},
	}
	got := map[string][]string{}
	for _, r := range rules {
		sig := strings.Join(r.ports, ",")
		if _, dup := got[sig]; dup {
			t.Errorf("port signature %q appears in two egress rules; they should have been one", sig)
		}
		got[sig] = r.peers
	}
	for sig, wantPeers := range want {
		peers, ok := got[sig]
		if !ok {
			t.Errorf("no egress rule with ports %s; got signatures %v", sig, keysOf(got))
			continue
		}
		if len(peers) != len(wantPeers) || (len(peers) > 0 && peers[0] != wantPeers[0]) {
			t.Errorf("rule for %s has peers %v, want %v — a peer inherited another's ports",
				sig, peers, wantPeers)
		}
	}

	// The broker and the resolver must never share a rule.
	for _, r := range rules {
		var hasBroker, hasResolver bool
		for _, peer := range r.peers {
			if peer == "10.7.0.2/32" {
				hasBroker = true
			}
			if peer == "10.7.0.10/32" {
				hasResolver = true
			}
		}
		if hasBroker && hasResolver {
			t.Errorf("broker and resolver share an egress rule %+v: each acquires the other's ports", r)
		}
	}
}

// keysOf lists a map's keys for an error message.
func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestLoopbackRulesProduceNoPeer: the loopback allows are ScopeLocal — the
// sandbox talking to itself, on a packet that never reaches an interface. A
// NetworkPolicy governs traffic leaving the Pod, so it never sees that packet;
// rendering a 127.0.0.0/8 peer would be a rule that matches nothing and, worse,
// reads to whoever audits the object as though the sandbox were granted reach
// into loopback space on the node.
func TestLoopbackRulesProduceNoPeer(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowPublicInternet: true, AllowPorts: []uint16{443}})
	np := mustRenderNP(t, p, npOpts())

	for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
		if b := npFindIPBlock(np, cidr); b != nil {
			t.Errorf("a ScopeLocal rule became an egress peer %q", b.CIDR)
		}
	}
	// They do still have to appear as carve-outs of the wide allow, which is
	// a different claim: "do not send loopback-addressed packets out" rather
	// than "you may reach loopback".
	if wide := npFindIPBlock(np, "0.0.0.0/0"); wide == nil || !npHasString(wide.Except, "127.0.0.0/8") {
		t.Error("127.0.0.0/8 is neither a peer nor an except; the block-set drop vanished")
	}
}

// TestClusterDNSIsASelectorNotAnAddress: cluster DNS lives on a Service
// ClusterIP in private space, which a deny-all egress policy blocks, and which
// side of the policy the CNI applies its DNAT on varies by CNI — so an ipBlock
// for the Service CIDR works until it doesn't. Selecting the namespace works
// everywhere. Without the rule the sandbox cannot resolve anything and the
// symptom reads as "the network is broken" rather than "DNS is denied", which
// is the kind of failure an operator debugs for an hour.
func TestClusterDNSIsASelectorNotAnAddress(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowPublicInternet: true, AllowPorts: []uint16{443}})

	opts := npOpts()
	opts.AllowClusterDNS = true
	np := mustRenderNP(t, p, opts)

	var found bool
	for _, r := range np.Spec.Egress {
		for _, peer := range r.To {
			if peer.NamespaceSelector == nil {
				continue
			}
			found = true
			if got := peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]; got != "kube-system" {
				t.Errorf("DNS namespaceSelector matches %q, want kube-system", got)
			}
			// Both transports: a truncated answer retries over TCP, and a
			// UDP-only rule fails on large responses in a way that looks
			// like a DNS outage rather than a firewall rule.
			sig := npPortSignature(r.Ports)
			for _, want := range []string{"UDP/53", "TCP/53"} {
				if !npHasString(sig, want) {
					t.Errorf("cluster DNS rule ports = %v, missing %s", sig, want)
				}
			}
		}
	}
	if !found {
		t.Fatalf("AllowClusterDNS produced no namespaceSelector peer: %+v", np.Spec.Egress)
	}

	// And it is opt-in: a caller that did not ask must not get a hole into
	// kube-system, which is where the API server's own clients live.
	off := mustRenderNP(t, p, npOpts())
	for _, r := range off.Spec.Egress {
		for _, peer := range r.To {
			if peer.NamespaceSelector != nil {
				t.Errorf("AllowClusterDNS=false still rendered a namespaceSelector peer: %+v", peer.NamespaceSelector)
			}
		}
	}
}

// TestDNSNamespaceLabelsOverrideTheDefault: kubernetes.io/metadata.name is set
// automatically since 1.21, but a cluster running its DNS somewhere else — or
// an older one — needs the label it actually uses. Ignoring the override would
// render a rule that selects nothing, and a rule that selects nothing fails
// exactly like no rule at all: silently, at resolve time.
func TestDNSNamespaceLabelsOverrideTheDefault(t *testing.T) {
	opts := npOpts()
	opts.AllowClusterDNS = true
	opts.DNSNamespaceLabels = map[string]string{"name": "openshift-dns"}
	np := mustRenderNP(t, mustCompilePolicy(t, Input{}), opts)

	var labels map[string]string
	for _, r := range np.Spec.Egress {
		for _, peer := range r.To {
			if peer.NamespaceSelector != nil {
				labels = peer.NamespaceSelector.MatchLabels
			}
		}
	}
	if labels == nil {
		t.Fatalf("no namespaceSelector peer: %+v", np.Spec.Egress)
	}
	if labels["name"] != "openshift-dns" {
		t.Errorf("namespaceSelector labels = %v, want the caller's override", labels)
	}
	if _, defaulted := labels["kubernetes.io/metadata.name"]; defaulted {
		t.Errorf("the default label survived alongside the override: %v", labels)
	}
}

// TestRenderNetworkPolicyIsDeterministic: the object is applied by a reconcile
// loop that diffs it against what is in the cluster. Map iteration order or an
// unsorted group would make every pass see a change, which means a rewrite of
// the firewall on every pass — and a genuine change, the one an operator wants
// to notice, buried in the churn.
func TestRenderNetworkPolicyIsDeterministic(t *testing.T) {
	p := mustCompilePolicy(t, Input{
		AllowCIDRs:          []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("2001:db8::/32")},
		AllowPorts:          []uint16{6443, 443},
		Brokers:             []netip.AddrPort{netip.MustParseAddrPort("10.7.0.2:8118")},
		Resolvers:           []netip.AddrPort{netip.MustParseAddrPort("10.7.0.10:53")},
		AllowPublicInternet: true,
	})
	opts := npOpts()
	opts.AllowClusterDNS = true
	opts.Labels = map[string]string{"b": "2", "a": "1"}
	opts.Annotations = map[string]string{"z": "26", "y": "25"}

	first, err := json.Marshal(mustRenderNP(t, p, opts))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := json.Marshal(mustRenderNP(t, p, opts))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(again) != string(first) {
			t.Fatalf("render %d differs:\n %s\n %s", i, first, again)
		}
	}
}

// TestRenderedObjectIsAValidAPIShape: the object is serialised straight to the
// API server, so the two fields that decide whether it is a firewall or an
// unrecognised blob have to be right. A wrong apiVersion is rejected; a wrong
// kind is worse, because a NetworkPolicy the cluster never applied looks
// identical from cloop's side to one it did.
func TestRenderedObjectIsAValidAPIShape(t *testing.T) {
	np := mustRenderNP(t, npWidePolicy(t), npOpts())

	if np.APIVersion != "networking.k8s.io/v1" {
		t.Errorf("apiVersion = %q, want networking.k8s.io/v1", np.APIVersion)
	}
	if np.Kind != "NetworkPolicy" {
		t.Errorf("kind = %q, want NetworkPolicy", np.Kind)
	}

	raw, err := json.Marshal(np)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"apiVersion":"networking.k8s.io/v1"`,
		`"kind":"NetworkPolicy"`,
		`"podSelector":{"matchLabels":{"cloop.dev/sandbox":"sbx-1"}}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("rendered JSON is missing %s:\n%s", want, raw)
		}
	}
}
