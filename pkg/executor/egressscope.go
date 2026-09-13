package executor

// egressscope.go lets one project confine its own network reach independently
// of the other projects sharing an executor.
//
// # The gap this closes
//
// The IP-layer egress filter (pkg/netfilter, driven by
// executors.container.egress_filter) is configured per executor. On a hub that
// hosts one team that is the right granularity. On a hub hosting several, it
// means every project on a node shares one firewall, and a project that wants
// to be cut off from the operator's internal network cannot ask for it — the
// only project-level network control was DisableNetwork, which is all-or-nothing
// and takes away the Internet along with the intranet.
//
// That is a real request and not a hypothetical one. A task running
// model-authored code on a host that also routes to production wants to reach
// pkg.go.dev and npmjs.com and nothing on 10.0.0.0/8, and it wants that
// regardless of what the *other* projects on the node are allowed to reach.
//
// # Why the enum is tiny, and why it can only narrow
//
// A Scope names a shape of policy, not a set of addresses. There is deliberately
// no way to write "also allow 10.8.0.0/24" here: reaching a private range is
// widening, it needs an operator's authorisation, and that already exists as an
// egress grant (pkg/egressbroker) named from sandbox.yaml's capabilities.network.
// Everything in this file moves in the other direction.
//
// The consequence worth stating is that a Scope is not always satisfiable. On an
// executor whose sandboxes only reach an egress broker, ScopePublic asks for
// *more* than the operator granted, so placement refuses it rather than either
// widening the sandbox or silently handing back something narrower than the
// project asked for. Both of those would be worse: the first is a security
// regression, the second is a project that believes it has Internet access and
// fails on its first fetch.

import (
	"fmt"
	"sort"
	"strings"
)

// EgressScope is a project's request to confine its own IP-layer egress.
type EgressScope string

const (
	// EgressScopeUnset leaves the executor's own configuration in force. It
	// is the zero value, so every deployment that predates this field keeps
	// exactly the behaviour it had.
	EgressScopeUnset EgressScope = ""

	// EgressScopePublic allows the public Internet and drops everything in
	// the non-public block set — RFC1918 and ULA private space, link-local
	// (including the cloud metadata endpoint at 169.254.169.254),
	// carrier-grade NAT, multicast and loopback beyond the sandbox's own.
	//
	// This is the "let it out to the Internet, keep it off our network"
	// policy. It is the useful default for a task on a host that also has
	// routes an operator would rather a harness never discovered, and it is
	// the only scope that leaves the sandbox able to fetch dependencies.
	EgressScopePublic EgressScope = "public"

	// EgressScopeNone removes the sandbox's network interfaces entirely.
	//
	// It overlaps Spec.DisableNetwork and exists so that one field can carry
	// the whole decision: a project that writes `egress: none` and a project
	// that omits capabilities.network end up in the same place, and a reader
	// of the spec does not have to know that the absence of one key means the
	// same thing as the presence of another.
	EgressScopeNone EgressScope = "none"
)

// egressScopeDescriptions is the closed set, with the operator-facing sentence
// for each. A map rather than a switch because the UI, the CLI and the error
// message below all need to enumerate them.
var egressScopeDescriptions = map[EgressScope]string{
	EgressScopePublic: "the public Internet only; private, link-local, metadata and CGNAT address space is dropped",
	EgressScopeNone:   "no network interfaces at all",
}

// Valid reports whether s is a known scope. The unset scope is valid: it means
// "no opinion", which is a legitimate thing for a spec not to have.
func (s EgressScope) Valid() bool {
	if s == EgressScopeUnset {
		return true
	}
	_, ok := egressScopeDescriptions[s]
	return ok
}

// Describe returns the operator-facing sentence for this scope.
func (s EgressScope) Describe() string {
	if s == EgressScopeUnset {
		return "the executor's configured egress policy"
	}
	if d := egressScopeDescriptions[s]; d != "" {
		return d
	}
	return string(s)
}

// EgressScopes returns every nameable scope, sorted, for CLI help and
// validation messages. EgressScopeUnset is omitted: it is spelled by leaving
// the key out, not by naming it.
func EgressScopes() []EgressScope {
	out := make([]EgressScope, 0, len(egressScopeDescriptions))
	for s := range egressScopeDescriptions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseEgressScope validates and normalises a user-supplied scope string.
func ParseEgressScope(raw string) (EgressScope, error) {
	s := EgressScope(strings.ToLower(strings.TrimSpace(raw)))
	if s.Valid() {
		return s, nil
	}
	names := make([]string, 0, len(egressScopeDescriptions))
	for _, v := range EgressScopes() {
		names = append(names, string(v))
	}
	return "", fmt.Errorf("%w: unknown egress scope %q (want one of: %s)",
		ErrInvalidSpec, raw, strings.Join(names, ", "))
}

// joinEgressScopes renders the nameable scopes for an error message.
func joinEgressScopes() string {
	names := make([]string, 0, len(egressScopeDescriptions))
	for _, s := range EgressScopes() {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}

// RemovesNetwork reports whether this scope leaves the sandbox with no
// interfaces, in which case no filter has to be installed for it.
func (s EgressScope) RemovesNetwork() bool { return s == EgressScopeNone }

// NeedsFilter reports whether honouring this scope requires the driver to
// install a per-workload IP-layer policy.
//
// EgressScopeNone does not: taking the interfaces away is not a filter, and it
// needs neither nft nor CAP_NET_ADMIN. That distinction is what lets a project
// on an unprivileged host still express the strongest of these scopes.
func (s EgressScope) NeedsFilter() bool { return s == EgressScopePublic }
