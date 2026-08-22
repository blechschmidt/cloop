package netfilter

import (
	"fmt"
	"net/netip"
	"sort"
)

// networkpolicy.go renders a Policy as a Kubernetes NetworkPolicy.
//
// The translation is not mechanical, because the two models differ in a way
// that matters. A Policy is ordered and has both verdicts; a NetworkPolicy is
// an unordered union of allows with no deny rule at all. Selecting a Pod with
// `policyTypes: [Egress]` and an empty rule list denies everything, and the
// only way to carve a hole *out* of an allow is `ipBlock.except`.
//
// So the drops become excepts and the ordering becomes set arithmetic:
//
//   - "allow the public Internet" becomes 0.0.0.0/0 with every blocked prefix
//     in except, which is the same thing the ordered form achieves by putting
//     the Internet allow after the drops;
//   - "a granted CIDR waives the block that covers it" becomes a second peer
//     for that CIDR. Peers are a union, so the granted prefix is allowed even
//     though the Internet peer excepts the range containing it — which is the
//     ordered form's "allow before drop", expressed without order.
//
// Ports are the reason peers are grouped rather than emitted one per rule:
// within a single egress rule, peers and ports form a cross product, so a
// granted CIDR on 6443 and the Internet on 443 have to be separate rules or
// each would silently acquire the other's ports.
//
// What this renderer cannot do is guarantee enforcement. A NetworkPolicy is
// inert unless the cluster runs a CNI that implements it; flannel, famously,
// does not. That is a fact about the cluster, so the driver reports it as a
// preflight finding rather than this package pretending otherwise.

// NetworkPolicy is the subset of networking.k8s.io/v1 NetworkPolicy this
// package emits. Only the fields set here are modelled, matching the
// Kubernetes driver's convention for its own object types.
type NetworkPolicy struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   NetworkPolicyMeta `json:"metadata"`
	Spec       NetworkPolicySpec `json:"spec"`
}

// NetworkPolicyMeta is the object metadata the caller fills in.
type NetworkPolicyMeta struct {
	Name        string            `json:"name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// NetworkPolicySpec is the policy body.
type NetworkPolicySpec struct {
	PodSelector LabelSelector       `json:"podSelector"`
	PolicyTypes []string            `json:"policyTypes"`
	Egress      []NetworkPolicyRule `json:"egress,omitempty"`
	Ingress     []NetworkPolicyRule `json:"ingress,omitempty"`
}

// LabelSelector selects the Pods this policy governs.
type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// NetworkPolicyRule is one egress or ingress entry.
type NetworkPolicyRule struct {
	To    []NetworkPolicyPeer `json:"to,omitempty"`
	From  []NetworkPolicyPeer `json:"from,omitempty"`
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyPeer is one destination: an address range, or a selector.
type NetworkPolicyPeer struct {
	IPBlock           *IPBlock       `json:"ipBlock,omitempty"`
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`
	PodSelector       *LabelSelector `json:"podSelector,omitempty"`
}

// IPBlock is a CIDR with holes.
type IPBlock struct {
	CIDR   string   `json:"cidr"`
	Except []string `json:"except,omitempty"`
}

// NetworkPolicyPort is one destination port.
type NetworkPolicyPort struct {
	Protocol string `json:"protocol,omitempty"`
	Port     *int   `json:"port,omitempty"`
}

// NetworkPolicyOptions carry what the Policy cannot express: the Pod
// selector, and the cluster-shaped exceptions.
type NetworkPolicyOptions struct {
	Name      string
	Namespace string
	// PodSelector must match exactly the Pods this policy should govern. An
	// empty selector in Kubernetes means *every* Pod in the namespace, so
	// an empty one here is refused rather than quietly firewalling the
	// namespace's other tenants.
	PodSelector map[string]string
	Labels      map[string]string
	Annotations map[string]string

	// AllowClusterDNS opens UDP and TCP 53 to the kube-dns Pods.
	//
	// It is a selector rather than an address because cluster DNS lives on
	// a Service ClusterIP in private space, and which side of the policy
	// the CNI applies its DNAT on varies by CNI. Selecting the kube-system
	// namespace is the form that works everywhere; an ipBlock for the
	// Service CIDR is the form that works until it doesn't.
	//
	// Without it, a default-deny egress policy breaks name resolution, and
	// the failure reads as "the network is broken" rather than "DNS is
	// denied" — which is why it defaults on in the driver.
	AllowClusterDNS bool
	// DNSNamespaceLabels selects the namespace running cluster DNS.
	// Defaults to kubernetes.io/metadata.name=kube-system, the label the
	// API server sets automatically on every namespace since 1.21.
	DNSNamespaceLabels map[string]string
}

// RenderNetworkPolicy translates the policy into a NetworkPolicy object.
func RenderNetworkPolicy(p Policy, opts NetworkPolicyOptions) (*NetworkPolicy, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("netfilter: NetworkPolicy needs a name")
	}
	if len(opts.PodSelector) == 0 {
		return nil, fmt.Errorf("netfilter: NetworkPolicy needs a pod selector — "+
			"an empty selector governs every Pod in namespace %q", opts.Namespace)
	}

	np := &NetworkPolicy{
		APIVersion: "networking.k8s.io/v1",
		Kind:       "NetworkPolicy",
		Metadata: NetworkPolicyMeta{
			Name:        opts.Name,
			Namespace:   opts.Namespace,
			Labels:      opts.Labels,
			Annotations: opts.Annotations,
		},
		Spec: NetworkPolicySpec{
			PodSelector: LabelSelector{MatchLabels: opts.PodSelector},
			// Naming Ingress with no ingress rules is what denies inbound.
			// Omitting the type would leave inbound ungoverned.
			PolicyTypes: []string{"Egress", "Ingress"},
		},
	}

	if opts.AllowClusterDNS {
		nsLabels := opts.DNSNamespaceLabels
		if len(nsLabels) == 0 {
			nsLabels = map[string]string{"kubernetes.io/metadata.name": "kube-system"}
		}
		port53 := 53
		np.Spec.Egress = append(np.Spec.Egress, NetworkPolicyRule{
			To:    []NetworkPolicyPeer{{NamespaceSelector: &LabelSelector{MatchLabels: nsLabels}}},
			Ports: []NetworkPolicyPort{{Protocol: "UDP", Port: &port53}, {Protocol: "TCP", Port: &port53}},
		})
	}

	// The prefixes that have to be carved out of any wide allow: the block
	// set, minus anything the policy explicitly allowed. A granted CIDR
	// appears as its own peer below, so leaving it in except would be
	// harmless — union semantics re-allow it — but it would also be a lie
	// in the rendered object, and these get read.
	excepts := exceptSets(p)

	// Group allow rules by their port signature so peers that share ports
	// share one rule and never inherit each other's.
	type group struct {
		key   string
		ports []NetworkPolicyPort
		peers []NetworkPolicyPeer
	}
	var groups []*group
	index := map[string]*group{}

	for _, r := range p.Rules {
		if r.Verdict != VerdictAllow || r.Scope != ScopeWire {
			continue
		}
		block := &IPBlock{CIDR: r.Prefix.String()}
		if r.Prefix.Bits() == 0 {
			if r.Prefix.Addr().Is4() {
				block.Except = excepts.v4
			} else {
				block.Except = excepts.v6
			}
		}
		key := portKey(r.Proto, r.Ports)
		g, ok := index[key]
		if !ok {
			g = &group{key: key, ports: renderPorts(r.Proto, r.Ports)}
			index[key] = g
			groups = append(groups, g)
		}
		g.peers = append(g.peers, NetworkPolicyPeer{IPBlock: block})
	}

	// Stable output: two runs of the same policy must produce the same
	// object, or every reconcile looks like a change.
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].key < groups[j].key })
	for _, g := range groups {
		np.Spec.Egress = append(np.Spec.Egress, NetworkPolicyRule{To: g.peers, Ports: g.ports})
	}
	return np, nil
}

// exceptSet holds the carve-outs for the two families.
type exceptSet struct {
	v4 []string
	v6 []string
}

// exceptSets computes the block prefixes a wide allow must exclude, dropping
// any that the policy allows outright.
func exceptSets(p Policy) exceptSet {
	allowed := map[netip.Prefix]bool{}
	for _, r := range p.Rules {
		if r.Verdict == VerdictAllow && r.Scope == ScopeWire && r.Prefix.Bits() > 0 {
			allowed[r.Prefix] = true
		}
	}
	var out exceptSet
	for _, b := range blockSet {
		if allowed[b.Prefix] {
			continue
		}
		// An except must be strictly inside the cidr it carves; ::/0 and
		// 0.0.0.0/0 are the cidrs here, so every block prefix qualifies
		// except a hypothetical /0, which the set does not contain.
		if b.Prefix.Bits() == 0 {
			continue
		}
		if b.Prefix.Addr().Is4() {
			out.v4 = append(out.v4, b.Prefix.String())
		} else {
			out.v6 = append(out.v6, b.Prefix.String())
		}
	}
	sort.Strings(out.v4)
	sort.Strings(out.v6)
	return out
}

// portKey identifies a port signature for grouping.
func portKey(proto Proto, ports []uint16) string {
	return proto.String() + "/" + joinPorts(ports)
}

// renderPorts turns a rule's transport and ports into NetworkPolicy ports.
//
// An empty port list renders as no ports at all, which in a NetworkPolicy
// means every port — the same thing it means in a Policy rule.
//
// ProtoAny expands to every transport a NetworkPolicy can name rather than
// defaulting to TCP. The nftables backend renders the same rule as `th
// dport`, which is transport-agnostic on purpose, and a renderer that quietly
// narrowed it here would make one Policy mean two different things depending
// on which backend enforced it. Compile never emits an allow with ProtoAny
// and ports, so this is unreachable from cloop's own configuration — but both
// renderers are exported and take a caller-supplied Policy, and "unreachable
// today" is not a property to encode a divergence behind.
func renderPorts(proto Proto, ports []uint16) []NetworkPolicyPort {
	if len(ports) == 0 {
		return nil
	}
	var names []string
	switch proto {
	case ProtoUDP:
		names = []string{"UDP"}
	case ProtoTCP:
		names = []string{"TCP"}
	default:
		names = []string{"TCP", "UDP", "SCTP"}
	}
	out := make([]NetworkPolicyPort, 0, len(ports)*len(names))
	for _, name := range names {
		for _, p := range ports {
			v := int(p)
			out = append(out, NetworkPolicyPort{Protocol: name, Port: &v})
		}
	}
	return out
}
