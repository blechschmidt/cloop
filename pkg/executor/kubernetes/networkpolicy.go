package kubernetes

// networkpolicy.go is where this driver stops describing its egress intent and
// starts enforcing it.
//
// Until now the driver set a cloop.dev/egress label reading "allow" or "deny"
// and admitted, in the comment beside it, that the label was documentation. A
// Pod joins the cluster's pod network and nothing in a Pod spec takes that
// away, so model-authored code could reach another tenant's Pods, the node's
// kubelet, an internal service that trusts its network position and the whole
// Internet — whatever the project's sandbox spec had asked for.
//
// A NetworkPolicy is the object that closes that, and this file builds it: one
// per Pod, selecting that Pod alone by its unique handle-id label, compiled
// from the same pkg/netfilter Policy the container driver's nftables ruleset is
// compiled from, so that "allowed" means the same thing on both backends
// instead of two hand-written rule sets that agree until they do not.
//
// Two limits are stated rather than papered over:
//
//   - A NetworkPolicy is inert unless the cluster's CNI implements it. flannel
//     famously does not, and the API server accepts the object regardless. That
//     is a fact about the cluster which cloop cannot read out of the API, so
//     preflight reports it as a warning rather than this file claiming an
//     enforcement it cannot check.
//   - A hostname allowlist does not exist at layer 3. netfilter.Compile widens
//     one to "the public Internet on these ports" and attaches a Warning saying
//     so; those warnings are written into an annotation here so that an
//     operator running `kubectl describe netpol` sees how much wider the
//     firewall is than the grant, instead of discovering it from a breach.

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

const (
	// networkPolicyPrefix names the NetworkPolicies this driver creates. It is
	// a distinct prefix from the workspace Secret's so an operator reading
	// `kubectl get netpol` can tell cloop's objects from the cluster's own
	// default-deny policy at a glance.
	networkPolicyPrefix = "cloop-egress-"

	// AnnotationEgressWarnings carries netfilter's warnings about where the
	// rendered filter is necessarily wider than the authorisation it came from.
	//
	// An annotation and not a label: these are sentences, and the whole point is
	// that a human reads them. The one that matters is "your host allowlist
	// became the public Internet", which is invisible in the rendered spec —
	// 0.0.0.0/0 with a handful of excepts looks like a deliberate choice.
	AnnotationEgressWarnings = "cloop.dev/egress-warnings"

	// AnnotationEgressMode records the shape of the authorisation the policy was
	// compiled from: isolated, brokered or filtered. It answers "was this Pod
	// supposed to reach anything at all" without re-deriving it from the peers.
	AnnotationEgressMode = "cloop.dev/egress-mode"

	// defaultResolverPort is assumed for a resolver written as a bare address.
	// A DNS server on a port other than 53 is rare enough to be worth spelling
	// out, and an operator who writes "10.96.0.10" plainly means the resolver.
	defaultResolverPort = 53
)

// EgressFilter is the executor's egress authorisation, in the shape config
// writes it.
//
// It holds strings and ints rather than netip types because it is a
// deserialised config section; parsing happens once, in Input, and its errors
// name the key that has to change. That keeps the config package free of
// address handling and keeps this the only place that decides what a malformed
// CIDR means.
//
// The zero value is "not filtering", and that is load-bearing: an existing
// deployment upgrading into this code must not have its Pods firewalled by a
// field nobody set. See Enabled.
type EgressFilter struct {
	// Enabled turns the filter on.
	//
	// Off means *no NetworkPolicy is created at all*, not an empty one. An
	// empty one would deny everything, which is the safe default for a new
	// deployment and a silent, total outage for an existing one — and a
	// security feature that arrives without being switched on is a feature
	// operators learn to switch off.
	Enabled bool

	// CIDRs are the destination ranges a workload may reach, as "10.8.0.0/24".
	// They are also the only thing that waives netfilter's block set, exactly as
	// in the egress proxy: naming a private range explicitly buys that range and
	// nothing else.
	CIDRs []string

	// Ports bound every destination allow. Naming destinations without ports is
	// refused rather than guessed at — see netfilter.Compile.
	Ports []int

	// AllowPublicInternet opens every address outside the block set on Ports.
	// It is the only way to express "a hostname allowlist" at layer 3, and it is
	// a separate switch so that widening the filter to the whole Internet is
	// something an operator states rather than something that happens to them.
	AllowPublicInternet bool

	// Resolvers are DNS servers the sandbox may query directly, as "ip:port" or
	// as a bare address (port 53 assumed). Needed only when cluster DNS is not
	// the resolver the workload uses; AllowClusterDNS covers the usual case.
	Resolvers []string

	// AllowClusterDNS opens UDP and TCP 53 to the kube-system namespace.
	//
	// A pointer so that "unset" can mean true. Without it a default-deny egress
	// policy breaks name resolution, and the failure reads to everyone involved
	// as "the network is broken" rather than "DNS is denied" — a diagnosis that
	// costs an afternoon and ends with the filter being turned off.
	AllowClusterDNS *bool
}

// ClusterDNSAllowed reports the effective setting, applying the on-by-default
// rule for an absent one.
func (f EgressFilter) ClusterDNSAllowed() bool {
	return f.AllowClusterDNS == nil || *f.AllowClusterDNS
}

// AllowsEgress reports whether any destination is reachable at all.
//
// It is what Capabilities().NetworkEgress answers with, so a filter that names
// no destination refuses placement for projects that require the network rather
// than accepting them into a Pod that can reach nothing.
//
// Resolvers and cluster DNS deliberately do not count. A sandbox that can
// resolve names and connect to nothing has no egress in any sense a project
// requiring the network means.
func (f EgressFilter) AllowsEgress() bool {
	if !f.Enabled {
		return true
	}
	return f.AllowPublicInternet || len(f.CIDRs) > 0
}

// Input projects the config section onto the authorisation netfilter compiles.
//
// Errors name the config key and the offending value, because the operator
// reading them is looking at YAML, not at a netip.Prefix.
func (f EgressFilter) Input() (netfilter.Input, error) {
	var in netfilter.Input
	for i, raw := range f.CIDRs {
		s := strings.TrimSpace(raw)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netfilter.Input{}, fmt.Errorf("cidrs[%d]: %q is not a CIDR (want a form like 10.8.0.0/24): %w",
				i, raw, err)
		}
		in.AllowCIDRs = append(in.AllowCIDRs, p)
	}
	for i, p := range f.Ports {
		if p < 1 || p > 65535 {
			return netfilter.Input{}, fmt.Errorf("ports[%d]: %d is not a port (1-65535)", i, p)
		}
		in.AllowPorts = append(in.AllowPorts, uint16(p))
	}
	for i, raw := range f.Resolvers {
		s := strings.TrimSpace(raw)
		ap, err := parseResolver(s)
		if err != nil {
			return netfilter.Input{}, fmt.Errorf("resolvers[%d]: %q is not a resolver address "+
				"(want 10.96.0.10 or 10.96.0.10:53): %w", i, raw, err)
		}
		in.Resolvers = append(in.Resolvers, ap)
	}
	in.AllowPublicInternet = f.AllowPublicInternet
	return in, nil
}

// parseResolver accepts "ip:port" and a bare address.
func parseResolver(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, defaultResolverPort), nil
}

// Compile turns the filter into the ordered policy both backends render from.
//
// Callers use it for validation as much as for rendering: compiling at config
// load is what turns a CIDR with a typo in it into a startup error naming the
// key, rather than a Pod that refuses to start at three in the morning.
func (f EgressFilter) Compile() (netfilter.Policy, error) {
	in, err := f.Input()
	if err != nil {
		return netfilter.Policy{}, err
	}
	return netfilter.Compile(in)
}

// Normalize trims the filter's string fields and proves it compiles.
//
// It validates even when Enabled is false, matching the rest of the config
// surface: a broken section should be reported when it is written, not
// discovered months later at the moment someone flips a boolean.
func (f EgressFilter) Normalize() (EgressFilter, error) {
	f.CIDRs = trimmedCopy(f.CIDRs)
	f.Resolvers = trimmedCopy(f.Resolvers)
	if len(f.Ports) > 0 {
		f.Ports = append([]int(nil), f.Ports...)
	}
	if _, err := f.Compile(); err != nil {
		return f, err
	}
	return f, nil
}

// trimmedCopy copies a string slice with each entry trimmed, dropping empties.
//
// A copy because Options must never alias a caller's slice: the executor holds
// this for its lifetime, and a caller that mutated the backing array afterwards
// would silently change a live firewall.
//
// Dropping an empty entry rather than refusing it is the one place here that
// forgives input, and it forgives in the safe direction: a blank YAML list item
// names no destination, so removing it can only narrow what the sandbox
// reaches. Everything else that fails to parse is an error.
func trimmedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Describe renders the filter as a sentence for preflight and `cloop executor
// test`.
//
// It compiles rather than paraphrasing the config, so what it reports is what
// the Pods actually get: the mode is derived by netfilter, and a filter that
// widened to the public Internet says so here rather than reading like the
// narrow allowlist someone thought they wrote.
func (f EgressFilter) Describe() string {
	if !f.Enabled {
		return "not filtered"
	}
	policy, err := f.Compile()
	if err != nil {
		return "misconfigured: " + err.Error()
	}
	parts := []string{"mode " + policy.Mode.String()}
	if len(f.CIDRs) > 0 {
		parts = append(parts, fmt.Sprintf("%d CIDR(s)", len(f.CIDRs)))
	}
	if f.AllowPublicInternet {
		parts = append(parts, "the public Internet")
	}
	if len(f.Ports) > 0 {
		ports := make([]string, len(f.Ports))
		for i, p := range f.Ports {
			ports[i] = fmt.Sprint(p)
		}
		parts = append(parts, "port "+strings.Join(ports, "/"))
	}
	if f.ClusterDNSAllowed() {
		parts = append(parts, "cluster DNS")
	}
	if len(f.Resolvers) > 0 {
		parts = append(parts, fmt.Sprintf("%d resolver(s)", len(f.Resolvers)))
	}
	return strings.Join(parts, ", ")
}

// networkPolicyName derives the NetworkPolicy's name from the handle ID.
//
// Deterministic rather than generateName, for the same reason
// workspaceSecretName is: the object has to be deletable by a cleanup path that
// holds nothing but the handle, including one running in a control plane that
// restarted since. The handle ID is already a short random token, so collision
// is not a concern; sanitising it keeps a future ID format from producing a
// name the API server rejects.
func networkPolicyName(handleID string) string {
	slug := sanitizeDNSLabel(handleID)
	if slug == "" {
		slug = "none"
	}
	return networkPolicyPrefix + slug
}

// buildNetworkPolicy renders the NetworkPolicy that must exist before req's Pod
// does, or nil when this executor is not filtering egress.
//
// It is pure, like buildPod and for the same reason: what a workload can reach
// is a security decision, and a security decision only inspectable by running
// it against a live cluster is one that never gets inspected.
func buildNetworkPolicy(req podRequest, filter EgressFilter) (*netfilter.NetworkPolicy, error) {
	if !filter.Enabled {
		// Unchanged behaviour for every deployment that has not opted in: no
		// object, no selector, no policy types. See EgressFilter.Enabled.
		return nil, nil
	}
	// The selector is the security boundary of this file. LabelHandleID carries
	// a per-run random token, so it selects exactly one Pod; an empty or shared
	// value would make this policy govern every Pod that also carries it, and a
	// deny-egress policy landing on a namespace's other tenants is an outage
	// they cannot diagnose and did not cause. sanitizeLabelValue maps an empty
	// id to "none" — a value every other empty-id run would share — so an empty
	// id is refused here rather than sanitised into a shared selector.
	if strings.TrimSpace(req.HandleID) == "" {
		return nil, fmt.Errorf("%w: a NetworkPolicy needs the Pod's unique handle id to select on, "+
			"and this request carries none", executor.ErrInvalidSpec)
	}
	if strings.TrimSpace(req.Namespace) == "" {
		return nil, fmt.Errorf("%w: a NetworkPolicy is namespaced and this request names no namespace",
			executor.ErrInvalidSpec)
	}

	// A Spec that asked for no network compiles from an empty authorisation,
	// whatever the executor allows: the project's own sandbox spec is the
	// narrower statement, and narrower always wins.
	in := netfilter.Input{}
	if !req.DisableNetwork {
		var err error
		if in, err = filter.Input(); err != nil {
			return nil, fmt.Errorf("kubernetes: egress_filter: %w", err)
		}
	}
	policy, err := netfilter.Compile(in)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: egress_filter: %w", err)
	}

	annotations := map[string]string{AnnotationEgressMode: policy.Mode.String()}
	if p := strings.TrimSpace(req.Labels["project"]); p != "" {
		annotations[AnnotationProjectPath] = p
	}
	if len(policy.Warnings) > 0 {
		annotations[AnnotationEgressWarnings] = strings.Join(policy.Warnings, " | ")
	}

	np, err := netfilter.RenderNetworkPolicy(policy, netfilter.NetworkPolicyOptions{
		Name:        networkPolicyName(req.HandleID),
		Namespace:   req.Namespace,
		PodSelector: map[string]string{LabelHandleID: sanitizeLabelValue(req.HandleID)},
		// The same labels the Pod carries, including the task-id the sweep
		// requires to exist, so the orphan sweep finds a policy with the
		// selector it already uses for Pods and an operator finds both with one
		// `kubectl get`.
		Labels: map[string]string{
			LabelManaged:    "true",
			LabelExecutorID: sanitizeLabelValue(req.ExecutorID),
			LabelHandleID:   sanitizeLabelValue(req.HandleID),
			LabelTaskID:     sanitizeLabelValue(taskIDFrom(req.Labels)),
			LabelProject:    sanitizeLabelValue(projectSlug(req.Labels["project"])),
		},
		Annotations: annotations,
		// Cluster DNS is opened by default, and closed for a Pod that asked for
		// no network at all: a sandbox with no egress that can still query
		// kube-dns has a DNS tunnel, which is an exfiltration channel with a
		// well-known toolchain.
		AllowClusterDNS: !req.DisableNetwork && filter.ClusterDNSAllowed(),
	})
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %w", err)
	}
	return np, nil
}

// explainNetworkPolicyFailure turns a rejected NetworkPolicy create into an
// actionable error.
//
// A sibling of explainCreateFailure and explainSecretFailure rather than a
// branch in either, because the remedy is a rule in a different API group and
// the 404 means something else entirely: the networking.k8s.io group is served
// by every supported cluster, so a 404 here is the namespace, not the endpoint.
func explainNetworkPolicyFailure(namespace, name string, err error) error {
	ae, ok := asAPIError(err)
	if !ok {
		return fmt.Errorf("kubernetes: create egress NetworkPolicy %s/%s: %w", namespace, name, err)
	}
	switch {
	case ae.Code == 403:
		return fmt.Errorf("kubernetes: not allowed to create NetworkPolicies in %q, which the egress "+
			"filter needs: %w — add this rule to the executor's Role:\n"+
			"  - apiGroups: [\"networking.k8s.io\"]\n"+
			"    resources: [\"networkpolicies\"]\n"+
			"    verbs: [\"create\", \"delete\", \"list\"]\n"+
			"or set executors.kubernetes.egress_filter.enabled to false and accept unfiltered egress "+
			"deliberately, rather than by RBAC accident", namespace, err)
	case ae.Code == 404:
		return fmt.Errorf("kubernetes: namespace %q does not exist (or the kubeconfig cannot see it): %w",
			namespace, err)
	case ae.Code == 409:
		// The name comes from the handle ID, so a conflict means a policy from
		// this exact handle survived — a control plane that died between
		// creating it and deleting it.
		return fmt.Errorf("kubernetes: an egress NetworkPolicy named %s already exists in %q, left "+
			"behind by an interrupted run: %w — delete it with `kubectl -n %s delete netpol %s`",
			name, namespace, err, namespace, name)
	default:
		return fmt.Errorf("kubernetes: create egress NetworkPolicy %s/%s: %w", namespace, name, err)
	}
}
