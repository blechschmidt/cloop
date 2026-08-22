package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

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

	// Broker is the egress proxy endpoint ("10.7.0.2:8118") the sandbox
	// must reach. Only needed alongside a direct-egress filter; on an
	// --internal network the broker is reachable because it shares the
	// bridge.
	Broker string

	// HostPatterns carries the L7 allowlist purely so the compiled policy
	// can warn that it is not enforcing it.
	HostPatterns []string
}

// filtersDirectly reports whether this filter needs an nftables ruleset, as
// opposed to relying on an --internal network alone.
func (f EgressFilter) filtersDirectly() bool {
	return f.Enabled && (len(f.AllowCIDRs) > 0 || f.AllowPublicInternet || f.Broker != "" || len(f.Resolvers) > 0)
}

// Policy compiles the filter.
//
// It is exported and pure so that pkg/config can validate an operator's YAML
// against exactly the rules the driver will apply, and so `cloop egress
// firewall` can render what a given configuration would install without
// touching the host.
func (f EgressFilter) Policy() (netfilter.Policy, error) {
	if !f.Enabled {
		return netfilter.Policy{}, fmt.Errorf("container: egress filter is not enabled")
	}
	in := netfilter.Input{
		AllowPublicInternet: f.AllowPublicInternet,
		HostPatterns:        f.HostPatterns,
	}
	for _, c := range f.AllowCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return netfilter.Policy{}, fmt.Errorf(
				"container: egress filter CIDR %q is not a prefix (want 10.0.0.0/8 or 2001:db8::/32)", c)
		}
		in.AllowCIDRs = append(in.AllowCIDRs, p)
	}
	for _, p := range f.AllowPorts {
		if p <= 0 || p > 65535 {
			return netfilter.Policy{}, fmt.Errorf("container: egress filter port %d is out of range", p)
		}
		in.AllowPorts = append(in.AllowPorts, uint16(p))
	}
	if f.Broker != "" {
		ap, err := parseEndpoint(f.Broker, 0)
		if err != nil {
			return netfilter.Policy{}, fmt.Errorf("container: egress filter broker %q: %w", f.Broker, err)
		}
		in.Brokers = append(in.Brokers, ap)
	}
	for _, r := range f.Resolvers {
		// A resolver written without a port means the standard one. That is
		// the only defaulting here: a broker endpoint has no standard port,
		// so it must be spelled out.
		ap, err := parseEndpoint(r, 53)
		if err != nil {
			return netfilter.Policy{}, fmt.Errorf("container: egress filter resolver %q: %w", r, err)
		}
		in.Resolvers = append(in.Resolvers, ap)
	}
	return netfilter.Compile(in)
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
func (f EgressFilter) Validate() error {
	if !f.Enabled {
		return nil
	}
	if !f.Internal && !f.filtersDirectly() {
		return fmt.Errorf("container: egress filter is enabled but allows nothing and is not internal — " +
			"set internal: true to route the sandbox through the broker, or name the CIDRs it may reach")
	}
	if f.filtersDirectly() {
		if _, err := f.Policy(); err != nil {
			return err
		}
	}
	return nil
}

// networkName derives the runtime network this filter needs.
//
// It is per-executor rather than per-task because Network is per-executor
// config: one filter, one network, one ruleset. Deriving the name from the
// executor ID rather than accepting one keeps an operator from pointing two
// differently-filtered executors at the same bridge, where the second Apply
// would silently replace the first's rules.
func networkName(executorID string) string {
	return "cloop-sbx-" + sanitizeNetworkPart(executorID)
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
func (e *Executor) installFirewall(ctx context.Context) (string, error) {
	f := e.opts.EgressFilter
	if !f.Enabled {
		return e.opts.Network, nil
	}

	name := networkName(e.id)
	bridge, err := e.ensureNetwork(ctx, name, f.Internal)
	if err != nil {
		return "", err
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
		if err := e.removeFirewall(ctx); err != nil {
			return "", err
		}
		return name, nil
	}

	policy, err := f.Policy()
	if err != nil {
		return "", err
	}
	applier, err := netfilter.NewApplier()
	if err != nil {
		return "", err
	}
	if err := applier.Apply(ctx, policy, netfilter.NftablesOptions{
		Table:  netfilter.TableName("sbx", e.id),
		Bridge: bridge,
	}); err != nil {
		return "", err
	}
	return name, nil
}

// removeFirewall deletes this executor's nftables table.
//
// A host with no nft at all is not an error: there is nothing installed to
// remove, which is the outcome the caller wanted. Any other failure is
// returned, because on the path that calls this — narrowing a filter down to
// an internal network — a table that survives is a *wider* policy than the
// configuration says, and swallowing that would be the same class of silent
// over-permission this package exists to remove.
func (e *Executor) removeFirewall(ctx context.Context) error {
	applier, err := netfilter.NewApplier()
	if err != nil {
		if errors.Is(err, netfilter.ErrUnavailable) {
			return nil
		}
		return err
	}
	return applier.Remove(ctx, netfilter.TableName("sbx", e.id))
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
