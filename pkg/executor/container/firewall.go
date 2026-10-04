package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// firewall.go gives the container driver an IP-layer egress filter.
//
// Until now this file's absence was the driver's largest honesty problem. The
// package comment said "it does not filter egress", and it meant it: Network
// was either "none" — no interfaces at all — or a runtime network with
// unrestricted outbound access. The egress broker's allowlist bound only a
// workload that chose to honour $HTTP_PROXY, and a harness that opened a raw
// socket ignored every host, port and CIDR an operator had configured.
//
// Two mechanisms close that, and which one applies is decided by the shape of
// the authorisation rather than by a separate switch:
//
//   - An --internal runtime network. The runtime installs no route off the
//     bridge, so nothing on it reaches the Internet at all. Put the egress
//     broker on the same network and it becomes the only way out — which
//     makes the broker's host allowlist enforceable rather than advisory.
//     This needs no privileges and no nft, and it is the strongest option
//     because the L3 filter and the L7 allowlist then describe the same set.
//
//   - A host-side nftables ruleset scoped to the sandbox bridge, for the case
//     where the authorisation names addresses the sandbox must dial directly
//     — a Kubernetes API server, an internal registry. pkg/netfilter compiles
//     the same authorisation the broker enforces into rules, so the two
//     agree by construction rather than by an operator keeping them in sync.
//
// The ordering problem the second mechanism has to solve is that a workload
// which starts before its filter exists has a window of unrestricted egress.
// Filtering on the *host* side rather than inside the container's namespace
// removes it: the bridge exists from the moment the network is created, which
// is strictly before any container can join, so the rules are always in place
// first. The alternative — start the container, find its PID, nsenter into
// its namespace — has no such guarantee and is why it is not what this does.

// EgressFilter is the operator's declaration of what a sandbox on this
// executor may reach.
//
// The zero value means "no filter", which preserves the behaviour of every
// deployment predating this type: the configured Network is used as-is. That
// default is deliberate. Silently firewalling a running deployment on upgrade
// would break it in a way that looks like a network outage, so switching this
// on is something an operator does.
type EgressFilter struct {
	// Enabled turns the filter on. Without it the remaining fields are
	// inert and the driver reports no filtering.
	Enabled bool

	// Internal puts the sandbox on a runtime network with no route off the
	// host, making the broker the only path out. It is the recommended
	// setting and needs no host privileges.
	Internal bool

	// AllowCIDRs, AllowPorts, AllowPublicInternet and Resolvers describe
	// direct egress, compiled by pkg/netfilter into nftables rules on the
	// sandbox bridge. Naming any of them requires nft(8) and CAP_NET_ADMIN
	// on the host.
	AllowCIDRs          []string
	AllowPorts          []int
	AllowPublicInternet bool
	Resolvers           []string

	// DenyCIDRs are ranges the sandbox may never reach, dropped ahead of
	// every allow (Task 20345). A deny list only ever takes reach away, so
	// unlike the allow list it needs no port list and no privilege beyond
	// the one the filter already has.
	DenyCIDRs []string

	// AllowAllPorts waives the port restriction that accompanies a
	// destination allow. It is not operator-settable — pkg/config has no key
	// for it — and exists for the per-project scopes in effectiveFilter,
	// where the policy's bound is the block set rather than a port list.
	//
	// Keeping it off the config surface is deliberate. An operator naming
	// allow_cidrs with no ports has described a hole, and netfilter.Compile
	// refuses that on purpose; this field would turn that refusal into a
	// footgun with a yaml key.
	AllowAllPorts bool

	// Broker is the egress proxy endpoint ("10.7.0.2:8118") the sandbox
	// must reach. Only needed alongside a direct-egress filter; on an
	// --internal network the broker is reachable because it shares the
	// bridge.
	Broker string

	// HostPatterns carries the L7 allowlist purely so the compiled policy
	// can warn that it is not enforcing it.
	HostPatterns []string

	// hubProxy is the hub's egress proxy as one workload reaches it — the
	// gateway of its bridge, or the address its route names — opened like
	// Broker (Task 20378). Unexported because it is never configuration: it is
	// derived per workload, from the route its Spec carries, by
	// provisionNetwork.
	hubProxy netip.AddrPort
}

// filtersDirectly reports whether this filter needs an nftables ruleset, as
// opposed to relying on an --internal network alone.
func (f EgressFilter) filtersDirectly() bool {
	return f.Enabled && (len(f.AllowCIDRs) > 0 || f.AllowPublicInternet || f.Broker != "" || len(f.Resolvers) > 0)
}

// Policy compiles the filter for use, refusing a filter that is switched off.
//
// It is exported and pure so that `cloop egress firewall` can render what a
// given configuration would install without touching the host. Callers that
// want to *validate* an authorisation rather than apply it want Compile,
// which does not care whether the switch is on.
func (f EgressFilter) Policy() (netfilter.Policy, error) {
	if !f.Enabled {
		return netfilter.Policy{}, fmt.Errorf("container: egress filter is not enabled")
	}
	p, err := f.Compile()
	if err != nil {
		return netfilter.Policy{}, fmt.Errorf("container: egress filter: %w", err)
	}
	return p, nil
}

// Compile turns the filter into the policy the nftables renderer consumes,
// whether or not Enabled is set.
//
// The Enabled-independence is the point, and it mirrors
// kubernetes.EgressFilter.Compile. pkg/config compiles at load so that a CIDR
// with a typo in it is a startup error naming the key; if that check skipped
// switched-off sections, the typo would sit in the file until the day an
// operator flipped the boolean, and would surface then as a sandbox whose
// every network request fails — the furthest possible point from the edit
// that caused it.
//
// Errors name the YAML key and the offending value, unprefixed, because the
// operator reading one is looking at their config file. Callers applying a
// filter rather than checking one (Policy, Validate) add the driver context.
func (f EgressFilter) Compile() (netfilter.Policy, error) {
	in, err := f.input()
	if err != nil {
		return netfilter.Policy{}, err
	}
	return netfilter.Compile(in)
}

// input projects the filter onto the authorisation netfilter compiles.
func (f EgressFilter) input() (netfilter.Input, error) {
	in := netfilter.Input{
		AllowPublicInternet: f.AllowPublicInternet,
		AllowAllPorts:       f.AllowAllPorts,
		HostPatterns:        f.HostPatterns,
	}
	for i, c := range f.AllowCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return netfilter.Input{}, fmt.Errorf(
				"allow_cidrs[%d]: %q is not a CIDR (want a form like 10.0.0.0/8 or 2001:db8::/32)", i, c)
		}
		in.AllowCIDRs = append(in.AllowCIDRs, p)
	}
	for i, c := range f.DenyCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return netfilter.Input{}, fmt.Errorf(
				"deny_cidrs[%d]: %q is not a CIDR (want a form like 10.0.0.0/8 or 2001:db8::/32)", i, c)
		}
		in.DenyCIDRs = append(in.DenyCIDRs, p)
	}
	for i, p := range f.AllowPorts {
		if p <= 0 || p > 65535 {
			return netfilter.Input{}, fmt.Errorf("allow_ports[%d]: %d is not a port (1-65535)", i, p)
		}
		in.AllowPorts = append(in.AllowPorts, uint16(p))
	}
	if f.Broker != "" {
		ap, err := parseEndpoint(f.Broker, 0)
		if err != nil {
			return netfilter.Input{}, fmt.Errorf("broker: %q: %w", f.Broker, err)
		}
		in.Brokers = append(in.Brokers, ap)
	}
	if f.hubProxy.IsValid() {
		in.Brokers = append(in.Brokers, f.hubProxy)
	}
	for i, r := range f.Resolvers {
		// A resolver written without a port means the standard one. That is
		// the only defaulting here: a broker endpoint has no standard port,
		// so it must be spelled out.
		ap, err := parseEndpoint(r, 53)
		if err != nil {
			return netfilter.Input{}, fmt.Errorf("resolvers[%d]: %q: %w", i, r, err)
		}
		in.Resolvers = append(in.Resolvers, ap)
	}
	return in, nil
}

// parseEndpoint accepts "addr:port" or, when defaultPort is non-zero, a bare
// address.
//
// Only address literals are accepted, never names. A packet filter matches
// addresses, so a name here would have to be resolved once at configuration
// time and then silently pinned — which is a DNS rebinding hazard dressed up
// as a convenience, and the opposite of what the broker's resolve-once
// discipline exists to provide.
func parseEndpoint(s string, defaultPort uint16) (netip.AddrPort, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	if defaultPort != 0 {
		if a, err := netip.ParseAddr(s); err == nil {
			return netip.AddrPortFrom(a, defaultPort), nil
		}
	}
	if defaultPort != 0 {
		return netip.AddrPort{}, fmt.Errorf("want an address literal (10.0.0.53) or address:port (10.0.0.53:53)")
	}
	return netip.AddrPort{}, fmt.Errorf("want an address:port literal (10.7.0.2:8118); host names are not accepted " +
		"because a packet filter matches addresses, and resolving one here would pin it silently")
}

// Validate checks the filter without touching the host.
//
// A switched-off filter is accepted unconditionally: this runs when the driver
// builds an executor, and refusing to register one over a typo in an inert
// section would turn a latent misconfiguration into an outage. Reporting that
// typo is pkg/config's job, where the operator is looking at the file.
func (f EgressFilter) Validate() error {
	if !f.Enabled {
		return nil
	}
	if !f.Internal && !f.filtersDirectly() {
		return fmt.Errorf("container: egress filter is enabled but allows nothing and is not internal — " +
			"set internal: true to route the sandbox through the broker, or name the CIDRs it may reach")
	}
	// Compiled even when the filter relies on an --internal network alone and
	// installs no ruleset. A port list that cannot be compiled is still a port
	// list the operator wrote, and a per-project egress scope can add the
	// destinations that turn it into a ruleset later — at which point the
	// error would surface against a project rather than against the config.
	if _, err := f.Compile(); err != nil {
		return fmt.Errorf("container: egress filter: %w", err)
	}
	return nil
}

// confinement is everything one workload asked for about its own reach: the
// coarse scope from its repo-committed sandbox spec, and the firewall rules the
// hub composed for it from the levels stored in the control plane (Task 20363).
//
// The two travel together because they answer the same question and because
// the bridge a workload lands on has to be keyed by both. When the rules are
// present they win: the hub folds the scope into them before dispatch, and they
// are the more specific statement, made by identities the hub authenticated.
//
// proxy rides along for the same reason (Task 20378): a workload the hub gave
// an egress session has to reach the hub's proxy through its ruleset, and a
// ruleset that opens the proxy is a different ruleset from one that does not.
type confinement struct {
	scope executor.EgressScope
	rules *executor.FirewallRules
	proxy *executor.EgressProxyRoute
}

// confineTo reads the confinement out of a Spec.
func confineTo(spec executor.Spec) confinement {
	return confinement{scope: spec.EgressScope, rules: spec.EgressRules, proxy: spec.EgressProxy}
}

// scoped is the confinement of a workload that carries only a scope.
func scoped(scope executor.EgressScope) confinement { return confinement{scope: scope} }

// key distinguishes one confinement's bridge and ruleset from another's; empty
// means "the executor's own policy, unmodified".
//
// Rules are keyed by their fingerprint rather than by anything an admin typed,
// so two workloads granted identical reach share one bridge and two granted
// different reach can never share one — the second Apply would replace the
// first's ruleset, and one of them would run under the other's firewall. The
// "r" prefix keeps a fingerprint from ever colliding with a scope name.
//
// A proxy route adds its port, so a workload whose ruleset opens the hub's
// proxy never shares a bridge — and so a table — with one whose ruleset does
// not: the second Apply would close the first's way out, or open the proxy to a
// workload that was given no session for it. Only the port: the address opened
// is the bridge's own gateway, which the bridge already determines. The "x"
// keeps it from reading as part of a fingerprint.
func (c confinement) key() string {
	var base string
	switch {
	case c.rules != nil:
		base = "r" + fwpolicy.Fingerprint(*c.rules)
	case c.scope != executor.EgressScopeUnset:
		base = string(c.scope)
	}
	if c.proxy == nil {
		return base
	}
	px := "x" + strconv.Itoa(c.proxy.Port)
	if base == "" {
		return px
	}
	return base + "-" + px
}

// networkName derives the runtime network a filter needs.
//
// It is keyed by executor *and* by confinement, because those are exactly the
// two things that decide which ruleset applies. Deriving the name rather than
// accepting one keeps an operator from pointing two differently-filtered
// executors at the same bridge, where the second Apply would silently replace
// the first's rules; adding the confinement extends the same guarantee to two
// differently-confined workloads on one executor.
//
// Workloads confined identically do share a bridge. That is the pre-existing
// model — every project on an executor shared one — and the sharing is bounded
// by the policy itself: under a filter that drops private space the bridge
// subnet is private, so a sandbox's neighbours are on the far side of a drop
// rule rather than merely uninteresting to it.
func networkName(executorID string, c confinement) string {
	base := "cloop-sbx-" + sanitizeNetworkPart(executorID)
	k := c.key()
	if k == "" {
		// Unsuffixed, so every deployment predating per-workload confinement
		// keeps the bridge it already has and no running sandbox is orphaned.
		return base
	}
	return base + "-" + sanitizeNetworkPart(k)
}

// firewallTable derives the nftables table name for one (executor,
// confinement) pair, matching networkName so that a bridge and its ruleset are
// never mismatched.
func firewallTable(executorID string, c confinement) string {
	k := c.key()
	if k == "" {
		return netfilter.TableName("sbx", executorID)
	}
	return netfilter.TableName("sbx", executorID+"-"+k)
}

func sanitizeNetworkPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "default"
	}
	if len(out) > 32 {
		out = strings.TrimRight(out[:32], "-")
	}
	return out
}

// ensureNetwork creates the sandbox network if it does not exist and returns
// its bridge interface name.
//
// Creation is idempotent by inspection rather than by ignoring the error from
// `network create`: "already exists" is the one failure that must not be
// fatal, and every other one — a driver that is unavailable, a subnet that
// collides — must be. Distinguishing them by string match on the runtime's
// stderr would break on a runtime update or a translated locale.
func (e *Executor) ensureNetwork(ctx context.Context, name string, internal bool) (string, error) {
	if bridge, gotInternal, err := e.inspectNetwork(ctx, name); err == nil {
		// Reuse only if the existing network still means what the current
		// configuration says. The name is derived from the executor ID and
		// therefore does not change when the filter does, so an operator who
		// switches internal on would otherwise keep running on the
		// non-internal bridge created before the change — believing egress is
		// blocked when it is not. Refusing is the only safe answer: the
		// network cannot be recreated underneath containers that are already
		// attached to it.
		if gotInternal != internal {
			return "", fmt.Errorf(
				"container: network %s exists with internal=%t but the egress filter needs internal=%t. "+
					"Stop the sandboxes on it and run `%s network rm %s`; it will be recreated correctly",
				name, gotInternal, internal, e.rt.Name, name)
		}
		return bridge, nil
	}

	args := []string{"network", "create", "--driver", "bridge"}
	if internal {
		args = append(args, "--internal")
	}
	args = append(args, name)
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, args...)
	if err != nil {
		return "", fmt.Errorf("container: creating network %s: %w", name, err)
	}
	if res.ExitCode != 0 {
		// Another hub process may have won the race between the inspect
		// above and this create. Re-inspecting settles it without parsing
		// the runtime's prose — and re-checks the internal flag, because a
		// network created by a differently-configured peer is exactly the
		// mismatch the reuse path above refuses.
		if bridge, gotInternal, ierr := e.inspectNetwork(ctx, name); ierr == nil {
			if gotInternal != internal {
				return "", fmt.Errorf(
					"container: network %s was created concurrently with internal=%t, but this "+
						"executor's egress filter needs internal=%t", name, gotInternal, internal)
			}
			return bridge, nil
		}
		return "", fmt.Errorf("container: creating network %s: %s", name, firstLine(res.Stderr))
	}
	bridge, _, err := e.inspectNetwork(ctx, name)
	return bridge, err
}

// networkInspection is the union of what the two runtimes report about a
// network. They agree on nothing but the concepts:
//
//	docker  {"Id": "...", "Internal": false}
//	podman  {"id": "...", "internal": false, "network_interface": "podman1"}
//
// Both spellings are decoded because a --format template naming a field the
// runtime does not have is a *template error*, not an empty string — asking
// docker for .NetworkInterface fails the whole inspect. Decoding `{{json .}}`
// and looking for either spelling is the only form that works on both, and
// getting this wrong produced a driver that worked under podman and could not
// start a sandbox under docker.
type networkInspection struct {
	ID               string `json:"Id"`
	IDLower          string `json:"id"`
	Internal         *bool  `json:"Internal"`
	InternalLower    *bool  `json:"internal"`
	NetworkInterface string `json:"network_interface"`
}

// inspectNetwork returns the host interface backing a runtime network and
// whether that network is internal.
//
// podman names the interface itself ("podman1") and reports it; docker does
// not report one at all, and its bridge is br-<first 12 of the network id>.
// Deriving the docker name is therefore a fallback, not the primary path —
// podman's interface is not derivable from its id, so a driver that only
// derived would attach rules to an interface that does not exist and filter
// nothing.
func (e *Executor) inspectNetwork(ctx context.Context, name string) (bridge string, internal bool, err error) {
	if err := validateNetworkName(name); err != nil {
		return "", false, err
	}
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout,
		"network", "inspect", name, "--format", "{{json .}}")
	if err != nil {
		return "", false, err
	}
	if res.ExitCode != 0 {
		return "", false, fmt.Errorf("container: network %s does not exist", name)
	}

	var got networkInspection
	if err := json.Unmarshal([]byte(strings.TrimSpace(firstLine(res.Stdout))), &got); err != nil {
		return "", false, fmt.Errorf("container: %s reported an unreadable description of network %s: %w",
			e.rt.Name, name, err)
	}
	// Absent reads as not-internal. That is the fail-closed direction: an
	// answer this code could not parse must never be mistaken for "no route
	// off this bridge", which is a security claim.
	switch {
	case got.Internal != nil:
		internal = *got.Internal
	case got.InternalLower != nil:
		internal = *got.InternalLower
	}

	if iface := strings.TrimSpace(got.NetworkInterface); iface != "" {
		if err := netfilter.ValidateInterfaceName(iface); err != nil {
			return "", false, err
		}
		return iface, internal, nil
	}
	id := strings.TrimSpace(got.ID)
	if id == "" {
		id = strings.TrimSpace(got.IDLower)
	}
	if len(id) < 12 {
		return "", false, fmt.Errorf("container: network %s reported no usable interface or id", name)
	}
	bridge = "br-" + id[:12]
	if err := netfilter.ValidateInterfaceName(bridge); err != nil {
		return "", false, err
	}
	return bridge, internal, nil
}

// validateNetworkName guards the name before it reaches the runtime CLI.
func validateNetworkName(name string) error {
	if name == "" {
		return fmt.Errorf("container: network name is empty")
	}
	if len(name) > 128 {
		return fmt.Errorf("container: network name is too long (%d bytes)", len(name))
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("container: network name %q may not begin with '-'", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return fmt.Errorf("container: network name %q contains an invalid character %q", name, r)
		}
	}
	return nil
}

// installFirewall provisions the sandbox network and installs the compiled
// ruleset on its bridge. It returns the network name the workload should
// join.
//
// A failure here fails the caller. Starting a sandbox whose filter could not
// be installed would produce exactly the unrestricted egress the filter was
// configured to prevent, and it would do it silently — the operator asked for
// a firewall and would get a working sandbox with no sign that it has none.
//
// The second return is the resolvers the sandbox should be told to use (Task
// 20345). A filter that drops private address space also drops the resolver
// the runtime hands a container by default — on a cloud VM that is usually a
// provider resolver in CGNAT or link-local space, 100.100.2.136 on the host
// this was measured on — and the embedded DNS forwarder sends its upstream
// queries from the container's own namespace, through this filter. Opening
// the configured resolvers without also pointing the sandbox at them would
// leave every lookup going somewhere the filter drops.
func (e *Executor) installFirewall(ctx context.Context, c confinement) (string, []string, error) {
	n, err := e.provisionNetwork(ctx, c)
	return n.name, n.dns, err
}

// sandboxNet is what provisioning one workload's network produced.
type sandboxNet struct {
	// name is the runtime network the workload joins.
	name string
	// dns is the resolvers it should be pointed at, when the filter opened
	// exactly these.
	dns []string
	// keyed is the confinement the network and its table are named after:
	// the workload's, less a proxy route when no ruleset was installed for it
	// to open.
	keyed confinement
	// gateway is the network's gateway, when the workload's proxy route asked
	// for it while the network was being built.
	gateway netip.Addr
}

// provisionNetwork is installFirewall with everything the caller needs back.
func (e *Executor) provisionNetwork(ctx context.Context, c confinement) (sandboxNet, error) {
	f, err := e.effectiveFilter(c)
	if err != nil {
		return sandboxNet{}, err
	}
	if !f.Enabled {
		return sandboxNet{name: e.opts.Network}, nil
	}
	if e.rootless() {
		// Rootless podman creates the bridge inside a network namespace the
		// invoking user owns. The ruleset below would be installed in the
		// host's namespace, keyed to an interface name that exists only in the
		// other one — it would load cleanly and match nothing, and the sandbox
		// would run with unrestricted egress under a firewall that reported
		// success (Task 20345).
		return sandboxNet{}, fmt.Errorf("%w: executor %s runs %s rootless, and a rootless engine's networks "+
			"live in a network namespace the host's packet filter cannot see, so an egress filter "+
			"installed for one would filter nothing; run the engine as root (docker, or podman as "+
			"root) for a filtered sandbox, or remove the filter", executor.ErrUnsupported, e.id, e.rt.Name)
	}

	// The proxy route is part of a bridge's identity only when a ruleset is
	// installed on it, because the ruleset is what has to open the proxy. An
	// --internal bridge with no ruleset reaches its gateway on-link already,
	// so every workload on the executor can keep sharing one.
	if !f.filtersDirectly() {
		c.proxy = nil
	}
	name := networkName(e.id, c)
	bridge, err := e.ensureNetwork(ctx, name, f.Internal)
	if err != nil {
		return sandboxNet{}, err
	}
	out := sandboxNet{name: name, keyed: c}
	if c.proxy != nil {
		ap, gw, err := e.proxyEndpoint(ctx, name, *c.proxy)
		if err != nil {
			return sandboxNet{}, err
		}
		f.hubProxy, out.gateway = ap, gw
	}
	if !f.filtersDirectly() {
		// --internal alone: the runtime installs no route off the bridge,
		// so there is nothing for nft to add and no privilege to require.
		//
		// Any ruleset a previous configuration left behind has to go, and
		// this is the only place that can know. The table name is derived
		// from the executor ID, so it does not change when the filter does:
		// an operator who narrows a direct-egress filter down to internal
		// would otherwise keep running under the old, wider allow list on
		// the same bridge. Removing an absent table is success, so this
		// costs one nft call on the common path and closes the case where
		// the configuration moved and the kernel did not.
		if err := e.removeFirewall(ctx, c); err != nil {
			return sandboxNet{}, err
		}
		return out, nil
	}

	policy, err := f.Policy()
	if err != nil {
		return sandboxNet{}, err
	}
	// The proof, before anything is installed: the compiled policy's own
	// semantics must let the workload reach the hub's proxy. A deny list that
	// covers the bridge's gateway shadows the opening (the deny wins, as it
	// must), and a sandbox started under it would time out on every request
	// its session was issued for.
	if f.hubProxy.IsValid() {
		if verdict, why := policy.Evaluate(f.hubProxy.Addr(), f.hubProxy.Port(), netfilter.ProtoTCP); verdict != netfilter.VerdictAllow {
			return sandboxNet{}, fmt.Errorf("%w: the hub's egress proxy at %s is unreachable through executor %s's "+
				"firewall (%s), so the egress session this workload was given could not be used; remove "+
				"the deny that covers it, or the project's egress grant", executor.ErrUnsupported, f.hubProxy, e.id, why)
		}
	}
	applier, err := netfilter.NewApplier()
	if err != nil {
		return sandboxNet{}, err
	}
	if err := applier.Apply(ctx, policy, netfilter.NftablesOptions{
		Table:  firewallTable(e.id, c),
		Bridge: bridge,
	}); err != nil {
		return sandboxNet{}, err
	}
	out.dns = sandboxResolvers(f.Resolvers)
	return out, nil
}

// sandboxResolvers turns the filter's resolver list into the addresses the
// runtime's --dns flag takes.
//
// Only resolvers on the standard port qualify: --dns names an address and
// nothing else, so a resolver on :5353 is reachable through the filter but
// cannot be made the sandbox's default, and naming it anyway would send
// lookups to port 53 of a host that is not listening there.
func sandboxResolvers(resolvers []string) []string {
	var out []string
	for _, r := range resolvers {
		ap, err := parseEndpoint(r, 53)
		if err != nil || ap.Port() != 53 {
			continue
		}
		out = append(out, ap.Addr().String())
	}
	return out
}

// effectiveFilter resolves the executor's configured filter against one
// project's requested scope.
//
// The whole security argument of per-project egress lives in this function, and
// it is one sentence: a scope may only ever *remove* reach. Everything below is
// that sentence applied to the three shapes an executor's own configuration can
// take.
func (e *Executor) effectiveFilter(c confinement) (EgressFilter, error) {
	f := e.opts.EgressFilter
	// Rules from the hub are the more specific statement and supersede the
	// scope; filterForRules proves them against this executor once more.
	if c.rules != nil {
		return e.filterForRules(*c.rules)
	}
	scope := c.scope
	// EgressScopeNone never reaches here needing a filter — buildRequest has
	// already set --network=none — and an unset scope is "no opinion", which
	// leaves the executor's configuration exactly as it was.
	if !scope.NeedsFilter() {
		return f, nil
	}
	if scope != executor.EgressScopePublic {
		// Unreachable while EgressScopePublic is the only filtering scope, and
		// deliberately not a default case that guesses: the next scope added
		// must come here and state its own compilation.
		return EgressFilter{}, fmt.Errorf("container: egress scope %q has no filter mapping", scope)
	}

	// Case 1: the executor is unfiltered. The project is narrowing "everything"
	// down to "public only", which is the plainest form of the request.
	//
	// Case 2: the executor already filters direct egress *and* lets sandboxes
	// out to the public Internet. The project's scope narrows it further, so
	// the CIDR allow list — the operator's grant of reach into private space —
	// is dropped and the rest is kept. What survives is the infrastructure a
	// sandbox cannot work without: the resolvers, the broker if one is
	// configured, and the operator's deny list, which a narrowing must never
	// shed.
	//
	// Cases 3 and 4 are the ones that cannot be honoured, and they are
	// handled below.
	if f.Enabled && f.filtersDirectly() && !f.AllowPublicInternet {
		// Case 4 (Task 20345): the executor filters direct egress but never
		// allowed the public Internet — it reaches, say, 10.8.0.0/24 and
		// nothing else. "The public Internet only" is not a subset of that; it
		// trades the operator's private grant for every public address, on the
		// strength of a repo-committed file. Until Task 20345 this case fell
		// through to case 2 and did exactly that.
		return EgressFilter{}, fmt.Errorf(
			"%w: this project requests the %q egress scope, but executor %s's firewall does not "+
				"allow the public Internet — the scope asks for more reach than the executor "+
				"grants, not less. Drop capabilities.egress from .cloop/sandbox.yaml to inherit "+
				"the executor's firewall, or bind the project to an executor whose firewall allows "+
				"the public Internet",
			executor.ErrUnsupported, scope, e.id)
	}
	if f.Enabled && f.Internal && !f.filtersDirectly() {
		// Internal means the runtime installs no route off the bridge: the
		// sandbox's only path out is the egress broker's hostname allowlist.
		// "The public Internet" is strictly more than that, so this is a
		// widening request and the answer is no.
		//
		// Downgrading it to the internal network instead would be worse than
		// refusing. The project asked to be able to reach the Internet and
		// would be told it succeeded, then fail on its first fetch with a DNS
		// error, on an executor whose configuration is not visible to it.
		return EgressFilter{}, fmt.Errorf(
			"%w: this project requests the %q egress scope, but executor %s puts sandboxes on an "+
				"internal network whose only route out is the egress broker — the scope asks for "+
				"more reach than the executor grants, not less. Either drop capabilities.egress "+
				"from .cloop/sandbox.yaml and use an egress grant for the hosts this project "+
				"needs, or bind it to an executor configured with "+
				"executors.container.egress_filter.allow_public_internet",
			executor.ErrUnsupported, scope, e.id)
	}

	out := EgressFilter{
		Enabled:             true,
		AllowPublicInternet: true,
		// No ports named, and that is the request rather than an omission: the
		// scope's bound is the block set, not a port list. See
		// netfilter.Input.AllowAllPorts.
		AllowAllPorts: true,
		// Carried over so the compiled policy can still warn that an L7
		// allowlist is not being enforced at layer 3.
		HostPatterns: f.HostPatterns,
		Resolvers:    f.Resolvers,
		Broker:       f.Broker,
		// The operator's denylist survives every narrowing: a scope removes
		// reach, and dropping a deny would add some back.
		DenyCIDRs: f.DenyCIDRs,
	}
	if len(out.Resolvers) == 0 {
		// DNS is the failure this check exists to prevent, and it is invisible
		// otherwise. A container on a bridge network resolves through an address
		// the runtime hands it — the host's stub resolver, or the bridge gateway
		// — and both are private. Dropping private space therefore breaks name
		// resolution, and the symptom is every hostname failing to resolve:
		// which reads as "the Internet is blocked", sends the reader to the
		// allow list, and is not fixed by anything they find there.
		//
		// Refusing with the remedy named beats installing a policy that is
		// technically correct and practically a sandbox with no working DNS.
		return EgressFilter{}, fmt.Errorf(
			"%w: the %q egress scope drops all private address space, which includes whatever "+
				"resolver the container runtime hands the sandbox, so DNS would fail for every "+
				"name. Set executors.container.egress_filter.resolvers on executor %s to the "+
				"resolvers sandboxes may query directly (a public resolver, or one of yours "+
				"reachable from the sandbox bridge)",
			executor.ErrInvalidSpec, scope, e.id)
	}
	return out, nil
}

// removeFirewall deletes this executor's nftables table, for a workload whose
// bridge is --internal and carries no ruleset of its own.
//
// A host with no nft at all is not an error: there is nothing installed to
// remove, which is the outcome the caller wanted. Nor is a process that may
// not use nft — a hub running without CAP_NET_ADMIN, which is exactly what
// `internal: true` promises to need nothing beyond (Task 20378's container
// test found this path refusing every run on such a hub, CI's included). Such
// a process installed no table, and a table some privileged process left on an
// --internal bridge can only narrow it: the bridge has no route off the host
// for the table's forward allows to open, and its input chain drops more of
// the host than an unfiltered bridge does. Any other failure is returned — an
// nft this process may use and that still refuses is a fault worth a refusal.
func (e *Executor) removeFirewall(ctx context.Context, c confinement) error {
	applier, err := netfilter.NewApplier()
	if err != nil {
		if errors.Is(err, netfilter.ErrUnavailable) {
			return nil
		}
		return err
	}
	if err := applier.Remove(ctx, firewallTable(e.id, c)); err != nil && !errors.Is(err, netfilter.ErrUnavailable) {
		return err
	}
	return nil
}

// preflightEgressFilter reports what the configured filter will and will not
// enforce.
//
// The unconfigured case gets a warning rather than silence. A driver that
// says nothing about egress reads as a driver that constrains it, and the
// default — a runtime network with unrestricted outbound access — is exactly
// the thing an operator would want to be told about before a harness runs on
// it with their credentials.
func (e *Executor) preflightEgressFilter(ctx context.Context, add func(name, level, msg, fix string)) {
	f := e.opts.EgressFilter

	if !f.Enabled {
		if e.opts.Network == NetworkNone {
			add("egress", LevelOK,
				"network is \"none\": the sandbox has no interfaces but loopback", "")
			return
		}
		add("egress", LevelWarn,
			fmt.Sprintf("network %q has unrestricted outbound access; cloop does not filter it", e.opts.Network),
			"set executors.container.egress_filter.enabled with internal: true to route sandboxes "+
				"through the egress broker, or name the CIDRs they may reach")
		return
	}

	policy, err := f.Policy()
	if f.filtersDirectly() && err != nil {
		add("egress", LevelFail, fmt.Sprintf("the egress filter does not compile: %v", err),
			"correct executors.container.egress_filter")
		return
	}

	if !f.filtersDirectly() {
		add("egress", LevelOK,
			"sandboxes run on an --internal runtime network: the kernel installs no route off the "+
				"bridge, so the egress broker is the only way out",
			"")
		return
	}

	// Direct egress needs nft on the host, and needs it to work. Reporting
	// this as OK when it cannot be applied would promise a firewall that
	// Start is about to refuse to install.
	applier, err := netfilter.NewApplier()
	if err == nil {
		err = applier.Available(ctx)
	}
	if err != nil {
		add("egress", LevelFail,
			fmt.Sprintf("the egress filter needs host packet filtering, which is unavailable: %v", err),
			"install nftables and grant the control plane CAP_NET_ADMIN, or switch the filter to "+
				"internal: true, which needs neither")
		return
	}

	msg := fmt.Sprintf("nftables egress filter (%s) will be installed on the sandbox bridge: %d rules",
		policy.Mode, len(policy.Rules))
	add("egress", LevelOK, msg, "")

	// The compiler's own warnings, surfaced individually: "your host
	// allowlist became the public Internet" is the finding an operator most
	// needs to see, and burying it inside an OK line would hide it.
	for _, w := range policy.Warnings {
		add("egress-scope", LevelWarn, w,
			"route the sandbox through the egress broker to have the host allowlist enforced")
	}
}

// ─── firewall rules from the hub (Task 20363) ──────────────────────────────

// FilterFromRules translates a firewall rule set into this driver's filter and
// the network a sandbox under it joins.
//
// A nil rule set is no filter on the given network; one that reaches nothing
// is no filter and no network, rather than an enabled filter with no
// destination, which Validate refuses as a configuration mistake — "no
// interfaces at all" is the same policy without needing nft, a bridge or a
// privilege. An empty port list next to a destination means every port: the
// form says so, so the omission is the request, where in config.yaml it is
// usually a forgotten line and stays refused.
func FilterFromRules(fw *executor.FirewallRules, network string) (EgressFilter, string) {
	if fw == nil {
		return EgressFilter{}, network
	}
	if !fw.HasDestination() {
		return EgressFilter{}, NetworkNone
	}
	allowsDestinations := fw.AllowPublicInternet || len(fw.AllowCIDRs) > 0
	return EgressFilter{
		Enabled:             true,
		AllowPublicInternet: fw.AllowPublicInternet,
		AllowCIDRs:          append([]string(nil), fw.AllowCIDRs...),
		DenyCIDRs:           append([]string(nil), fw.DenyCIDRs...),
		AllowPorts:          append([]int(nil), fw.AllowPorts...),
		AllowAllPorts:       allowsDestinations && len(fw.AllowPorts) == 0,
		Resolvers:           append([]string(nil), fw.Resolvers...),
	}, NetworkBridge
}

// OwnRules reports, as a rule set, what this executor's own configuration lets
// a sandbox reach: nil when it does not filter, an empty rule set when its
// sandboxes get no network or reach only through the broker.
//
// Three configurations collapse onto "reaches nothing", and all three are
// honest: network "none"; an --internal bridge with no direct rules, whose only
// way out is the broker's hostname allowlist — an L7 construct no rule set can
// name; and a filter that allows nothing. A configuration this binary cannot
// read back as rules also reads as "reaches nothing", the fail-closed answer.
func (e *Executor) OwnRules() *executor.FirewallRules {
	if e.opts.Network == NetworkNone {
		return &executor.FirewallRules{}
	}
	f := e.opts.EgressFilter
	if !f.Enabled {
		return nil
	}
	if !f.filtersDirectly() {
		return &executor.FirewallRules{}
	}
	r := executor.FirewallRules{
		AllowPublicInternet: f.AllowPublicInternet,
		AllowCIDRs:          append([]string(nil), f.AllowCIDRs...),
		DenyCIDRs:           append([]string(nil), f.DenyCIDRs...),
		Resolvers:           append([]string(nil), f.Resolvers...),
	}
	if !f.AllowAllPorts {
		r.AllowPorts = append([]int(nil), f.AllowPorts...)
	}
	n, err := r.Normalize()
	if err != nil {
		return &executor.FirewallRules{}
	}
	return &n
}

// EgressPosture implements executor.EgressPostured for the hub's own container
// executor: its configuration is the outermost level, and it can install rules
// for one workload on a bridge of their own unless its engine is rootless.
func (e *Executor) EgressPosture() executor.EgressPosture {
	p := executor.EgressPosture{
		DeviceID:       e.id,
		Config:         e.OwnRules(),
		RemovesNetwork: true,
	}
	if e.rootless() {
		p.Reason = fmt.Sprintf("executor %s runs %s rootless, and a rootless engine's networks live where "+
			"the host's packet filter cannot see them", e.id, e.rt.Name)
		return p
	}
	p.Enforceable = true
	return p
}

// checkRules is the driver's own proof that the rules a workload carries fit
// inside this executor's configured firewall and the device's — and, in a
// process holding the control plane, inside the device's rules as stored now.
func (e *Executor) checkRules(spec executor.Spec) error {
	return fwpolicy.CheckAtDriver(spec, e.OwnRules(), "executor "+e.id+"'s own firewall", e.id)
}

// filterForRules builds the filter for one workload's rules, proving once more
// that they fit inside this executor's configuration.
//
// What the configuration says about the bridge rather than about reach is kept:
// Internal, the broker and the host patterns are the operator's, none of them is
// a workload's to choose, and dropping Internal alone would put the sandbox on a
// bridge with a route off the host.
func (e *Executor) filterForRules(want executor.FirewallRules) (EgressFilter, error) {
	if reasons := fwpolicy.Permits(e.OwnRules(), want); len(reasons) > 0 {
		return EgressFilter{}, &fwpolicy.ExceedsError{Level: "this workload's firewall rules",
			Bound: "executor " + e.id + "'s own firewall", Reasons: reasons}
	}
	n, err := want.Normalize()
	if err != nil {
		return EgressFilter{}, err
	}
	if !n.HasDestination() {
		// Start gives such a workload no network and never asks for a filter;
		// an enabled filter allowing nothing would read as an unfiltered bridge
		// below, so refuse rather than build one.
		return EgressFilter{}, fmt.Errorf("%w: firewall rules that reach nothing take the network away; "+
			"they need no filter", executor.ErrInvalidSpec)
	}
	f, _ := FilterFromRules(&n, NetworkBridge)
	cfg := e.opts.EgressFilter
	f.Internal, f.Broker, f.HostPatterns = cfg.Internal, cfg.Broker, cfg.HostPatterns
	return f, nil
}

// rulesNetUse counts the live workloads on one rules-keyed network.
type rulesNetUse struct {
	refs  int
	table string
}

// installRulesAware installs the firewall for a confinement, and for one
// carrying rules records the workload on its network under rulesMu.
func (e *Executor) installRulesAware(ctx context.Context, c confinement) (sandboxNet, error) {
	if c.rules == nil {
		return e.provisionNetwork(ctx, c)
	}
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()
	n, err := e.provisionNetwork(ctx, c)
	if err != nil {
		return sandboxNet{}, err
	}
	if e.rulesNets == nil {
		e.rulesNets = map[string]*rulesNetUse{}
	}
	u := e.rulesNets[n.name]
	if u == nil {
		u = &rulesNetUse{table: firewallTable(e.id, n.keyed)}
		e.rulesNets[n.name] = u
	}
	u.refs++
	return n, nil
}

// releaseRulesNetwork drops one workload from a rules-keyed network and, when
// it was the last this executor knows of, removes the network and its ruleset.
//
// The scope networks and a virtual executor's own bridge are kept for the
// executor's life, because there are a handful of them. Rules networks are
// keyed by a fingerprint, so every edit to a rule set mints a new one, and an
// engine has a finite pool of subnets to give bridges: kept forever, they
// would exhaust it. Removal is best-effort — a network another process's
// workload still uses refuses to go, and is left with its ruleset intact.
func (e *Executor) releaseRulesNetwork(name string) {
	if name == "" {
		return
	}
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()
	u := e.rulesNets[name]
	if u == nil {
		return
	}
	if u.refs--; u.refs > 0 {
		return
	}
	delete(e.rulesNets, name)
	ctx, cancel := context.WithTimeout(context.Background(), 2*shortCmdTimeout)
	defer cancel()
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "network", "rm", name)
	if err != nil || res.ExitCode != 0 {
		return
	}
	if applier, err := netfilter.NewApplier(); err == nil {
		_ = applier.Remove(ctx, u.table)
	}
}
