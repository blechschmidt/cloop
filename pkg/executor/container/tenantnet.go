package container

// tenantnet.go keeps the sandboxes of different projects on different
// networks (Task 20502).
//
// Two runs of different projects on one executor must not reach each other.
// Until this file they could, in three ways that all came down to a shared
// bridge: an unfiltered executor put every sandbox on the engine's default
// bridge, where a container reaches its neighbours' listeners directly; an
// --internal filter put every project on one internal bridge, a Layer 2
// segment with nothing in between; and a direct-egress filter shared one
// bridge between every project confined identically, which only stood between
// two sandboxes on hosts that pass bridged traffic through the IP hooks
// (br_netfilter) and only while the allow list did not cover the subnet.
//
// So every bridge this driver makes belongs to one project — its tenant — and
// to nobody else:
//
//   - the network is named after the tenant (networkName), and so is its
//     nftables table (firewallTable);
//   - its bridge interface is named clsb<digest> (bridgeName), so one pattern,
//     siblingBridges, matches every sandbox bridge on the host, and every
//     ruleset refuses traffic to and from the others (netfilter.Siblings);
//   - podman creates it with isolate=true, without which netavark routes
//     between its networks; docker keeps user-defined networks apart already;
//   - it is counted while workloads use it and removed with its table once
//     the last has gone, because an engine has a finite pool of subnets, and
//     a startup sweep removes what a dead process left behind.
//
// A project's own workloads still share its network: two runs of one project
// talking to each other is not a boundary anyone asked for, and a network per
// workload would spend a subnet on every dashboard model call.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

const (
	// sandboxBridgePrefix begins the name of every bridge interface this
	// driver creates. Four characters leave eleven for the digest inside
	// IFNAMSIZ's fifteen.
	sandboxBridgePrefix = "clsb"
	// siblingBridges is the nft pattern matching every sandbox bridge.
	siblingBridges = sandboxBridgePrefix + "*"

	// labelNetTenant records the tenant tag a network belongs to.
	labelNetTenant = "cloop.tenant"
	// labelNetTable records the nftables table filtering a network's bridge,
	// so the idle-network sweep removes the two together.
	labelNetTable = "cloop.nft_table"

	// metaNetwork and metaNetworkTable carry a container's tenant network
	// and its table on the handle row, so a restarted control plane that
	// adopts the container counts it on its network again.
	metaNetwork      = "network"
	metaNetworkTable = "network_table"

	// networkIdleGrace is how old an unused tenant network must be before the
	// startup sweep removes it. Generous on purpose: Start creates a network
	// before it resolves the image, which can build for minutes, and a peer
	// hub process sharing the engine may be inside that window — a network
	// removed from under it fails its start.
	networkIdleGrace = time.Hour
)

// tenantOf names the tenant a workload's network belongs to: its project
// (executor.NetworkTenant), or, for a workload that names none, its own
// handle — such a workload shares a network with nothing.
func tenantOf(spec executor.Spec, handleID string) string {
	if t := executor.NetworkTenant(spec); t != "" {
		return "project:" + t
	}
	return "handle:" + handleID
}

// tenantTag is the short, stable stand-in for a tenant in network, bridge and
// table names: a digest, so a project's path never appears in `docker network
// ls` and two paths that sanitise alike can never share a network.
func tenantTag(tenant string) string {
	sum := sha256.Sum256([]byte("cloop-network-tenant\x00" + tenant))
	return hex.EncodeToString(sum[:])[:10]
}

// bridgeName names the bridge interface of a sandbox network: the prefix every
// sandbox bridge shares, and a digest of the network's name.
func bridgeName(network string) string {
	sum := sha256.Sum256([]byte(network))
	return sandboxBridgePrefix + hex.EncodeToString(sum[:])[:11]
}

// netUse counts the live workloads on one tenant network.
type netUse struct {
	refs  int
	table string
}

// ─── the host-wide network lock ────────────────────────────────────────────

// netLockDir holds one lock file per sandbox network. A network and its table
// are named by executor, confinement and project, not by process: two hub
// processes sharing an engine, or two of an agent's driver instances, can hold
// the same network. Every step that creates, joins or removes one takes its
// lock, so one process's release — `network rm`, then the table's delete — can
// never interleave with another's creation and table install: that
// interleaving deleted the table of a network a sandbox was about to join, and
// the sandbox ran with no firewall.
func netLockDir() string {
	if fi, err := os.Stat("/run/lock"); err == nil && fi.IsDir() {
		return "/run/lock"
	}
	return os.TempDir()
}

func netLockPath(network string) string {
	return filepath.Join(netLockDir(), "cloop-net-"+network+".lock")
}

// lockNetwork takes the host-wide lock on one sandbox network, waiting until
// ctx ends, and returns its release, which is safe to call more than once.
func lockNetwork(ctx context.Context, network string) (func(), error) {
	if err := validateNetworkName(network); err != nil {
		return nil, err
	}
	// Read-only is enough to flock, so a lock file another account created
	// with 0644 still serves this one.
	f, err := os.OpenFile(netLockPath(network), os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("container: lock for network %s: %w", network, err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("container: lock for network %s: %w", network, err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("container: waiting for network %s, which another start or release "+
				"holds: %w", network, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
		})
	}, nil
}

// tryLockNetwork takes the lock only if nobody holds it.
func tryLockNetwork(network string) (func(), bool) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unlock, err := lockNetwork(ctx, network)
	return unlock, err == nil
}

// joinTenantNetwork provisions a planned network under its host-wide lock and,
// when it is a tenant network, counts the workload on it. The lock stays held
// — the returned unlock releases it — until the caller's container has joined
// the network, so no release, here or in another process, removes the network
// or its table in between.
func (e *Executor) joinTenantNetwork(ctx context.Context, plan networkPlan) (sandboxNet, func(), error) {
	if !plan.tenant {
		n, err := e.provisionPlan(ctx, plan)
		return n, func() {}, err
	}
	lockCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	unlock, err := lockNetwork(lockCtx, plan.name)
	if err != nil {
		return sandboxNet{}, nil, err
	}
	n, err := e.provisionPlan(ctx, plan)
	if err != nil {
		unlock()
		return sandboxNet{}, nil, err
	}
	e.countOnNetwork(n.name, n.table)
	return n, unlock, nil
}

// adoptTenantNetwork counts an adopted container on the network it joined
// under the control plane that started it.
func (e *Executor) adoptTenantNetwork(name, table string) {
	if name != "" {
		e.countOnNetwork(name, table)
	}
}

func (e *Executor) countOnNetwork(name, table string) {
	e.netMu.Lock()
	defer e.netMu.Unlock()
	if e.netUses == nil {
		e.netUses = map[string]*netUse{}
	}
	u := e.netUses[name]
	if u == nil {
		u = &netUse{}
		e.netUses[name] = u
	}
	if table != "" {
		u.table = table
	}
	u.refs++
}

// releaseTenantNetwork drops one workload from a tenant network and, when it
// was the last this executor knows of, removes the network and its ruleset,
// under the network's host-wide lock.
//
// Removal is best-effort: a network another process's workload still uses
// refuses to go, and is left with its ruleset intact. The table goes only
// after the network has — a table outliving its bridge filters nothing, but a
// bridge outliving its table would be a sandbox network with no firewall. A
// network left behind is removed by the startup sweep once idle.
func (e *Executor) releaseTenantNetwork(name string) {
	if name == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	unlock, err := lockNetwork(ctx, name)
	if err != nil {
		e.netMu.Lock()
		if u := e.netUses[name]; u != nil {
			if u.refs--; u.refs <= 0 {
				delete(e.netUses, name)
			}
		}
		e.netMu.Unlock()
		fmt.Fprintf(os.Stderr, "container: not removing network %s: %v\n", name, err)
		return
	}
	defer unlock()
	e.netMu.Lock()
	u := e.netUses[name]
	if u == nil {
		e.netMu.Unlock()
		return
	}
	if u.refs--; u.refs > 0 {
		e.netMu.Unlock()
		return
	}
	delete(e.netUses, name)
	table := u.table
	e.netMu.Unlock()
	e.removeNetwork(ctx, name, table)
}

// removeNetwork removes one network and then its table, reporting whether the
// network went. Callers hold the network's lock.
func (e *Executor) removeNetwork(ctx context.Context, name, table string) bool {
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "network", "rm", name)
	if err != nil || res.ExitCode != 0 {
		return false
	}
	if table != "" {
		if applier, err := netfilter.NewApplier(); err == nil {
			_ = applier.Remove(ctx, table)
		}
	}
	return true
}

// heldNetwork reports whether a live workload of this process is counted on
// name.
func (e *Executor) heldNetwork(name string) bool {
	e.netMu.Lock()
	defer e.netMu.Unlock()
	return e.netUses[name] != nil
}

// reapIdleNetworks removes this executor's tenant networks that no container
// is attached to and that are older than networkIdleGrace, with the tables
// recorded on them: what a control plane that died left behind, and what an
// adopted container's network became once it ended. It returns the networks
// it removed.
//
// The engine is the judge of "unused": `network rm` refuses a network a
// running container is on, so a network another process's sandbox holds
// survives the sweep whatever this process thinks of it. The age is the
// judge of "not about to be used": see networkIdleGrace.
func (e *Executor) reapIdleNetworks(ctx context.Context) []string {
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "network", "ls",
		"--filter", "label="+LabelExecutor+"="+e.id, "--format", "{{.Name}}")
	if err != nil || res.ExitCode != 0 {
		return nil
	}
	var removed []string
	for _, name := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		name = strings.TrimSpace(name)
		if name == "" || validateNetworkName(name) != nil || e.heldNetwork(name) {
			continue
		}
		// Skipped while any process holds it: a start between creating the
		// network and its container joining holds the lock throughout.
		unlock, ok := tryLockNetwork(name)
		if !ok {
			continue
		}
		if e.reapIdleNetwork(ctx, name) {
			removed = append(removed, name)
		}
		unlock()
	}
	return removed
}

// reapIdleNetwork removes one of this executor's tenant networks if it is
// old enough, under its lock.
func (e *Executor) reapIdleNetwork(ctx context.Context, name string) bool {
	facts, err := e.inspectNetwork(ctx, name)
	if err != nil || facts.labels[LabelExecutor] != e.id || facts.labels[labelNetTenant] == "" {
		return false
	}
	if facts.created.IsZero() || time.Since(facts.created) < networkIdleGrace {
		return false
	}
	table := facts.labels[labelNetTable]
	if table != "" && netfilter.ValidateNftName(table) != nil {
		table = ""
	}
	return e.removeNetwork(ctx, name, table)
}

// ReapIdleNetworks removes this executor's idle tenant networks and their
// rulesets, for an agent, which runs no orphan sweep: see reapIdleNetworks.
func (e *Executor) ReapIdleNetworks(ctx context.Context) []string { return e.reapIdleNetworks(ctx) }

// withNetworkMeta records a container's tenant network on its handle row.
func withNetworkMeta(meta map[string]string, network, table string) map[string]string {
	if network == "" {
		return meta
	}
	if meta == nil {
		meta = map[string]string{}
	}
	meta[metaNetwork] = network
	if table != "" {
		meta[metaNetworkTable] = table
	}
	return meta
}

// restoreNetworkMeta reads a handle row's tenant network back, refusing what
// this driver would never have written.
func restoreNetworkMeta(meta map[string]string) (network, table string) {
	network = strings.TrimSpace(meta[metaNetwork])
	if network == "" || validateNetworkName(network) != nil || !strings.HasPrefix(network, "cloop-sbx-") {
		return "", ""
	}
	table = strings.TrimSpace(meta[metaNetworkTable])
	if table != "" && netfilter.ValidateNftName(table) != nil {
		table = ""
	}
	return network, table
}

// ─── the host's resolvers, for an unfiltered sandbox on docker ──────────────

// hostResolvConfPaths is where the host's resolver configuration is read: the
// file the libc reads, then systemd-resolved's list of its upstream servers,
// for a host whose resolv.conf names only the 127.0.0.53 stub.
var hostResolvConfPaths = []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"}

// hostResolvers returns the host's resolvers as an unfiltered sandbox on the
// default bridge saw them — what docker copies into a container there: the
// nameservers that are not loopback (a sandbox's loopback is its own), IPv4
// only (the sandbox network has no IPv6), with the search list and options.
// A host with none of those gets what docker falls back to on the default
// bridge, its two public resolvers, so a gVisor or Kata sandbox, which cannot
// reach the engine's embedded resolver, still resolves names.
func hostResolvers(paths []string) (servers, search, options []string) {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		srv, sr, op := parseResolvConf(string(data))
		if len(srv) > 0 {
			return srv, sr, op
		}
		if search == nil {
			search, options = sr, op
		}
	}
	return dockerFallbackResolvers, search, options
}

// dockerFallbackResolvers are docker's defaults for a default-bridge container
// on a host whose resolvers are all loopback.
var dockerFallbackResolvers = []string{"8.8.8.8", "8.8.4.4"}

// parseResolvConf reads the nameservers a sandbox can use out of a
// resolv.conf, and its search list and options.
func parseResolvConf(text string) (servers, search, options []string) {
	const maxServers, maxSearch, maxOptions = 3, 6, 8
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			a, err := netip.ParseAddr(f[1])
			if err != nil || !a.Is4() || a.IsLoopback() || a.IsUnspecified() {
				continue
			}
			if len(servers) < maxServers {
				servers = append(servers, a.String())
			}
		case "search", "domain":
			search = search[:0]
			for _, d := range f[1:] {
				if len(search) < maxSearch && resolvToken(d) {
					search = append(search, d)
				}
			}
		case "options":
			for _, o := range f[1:] {
				if len(options) < maxOptions && resolvToken(o) {
					options = append(options, o)
				}
			}
		}
	}
	return servers, search, options
}

// resolvToken admits a search domain or option made of the characters either
// can hold, so nothing read from the host can add a line to the file written.
func resolvToken(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == ':':
		default:
			return false
		}
	}
	return true
}

// hostResolvConf stages a resolv.conf naming the host's resolvers.
func (e *Executor) hostResolvConf() (string, error) {
	servers, search, options := hostResolvers(hostResolvConfPaths)
	path, err := e.writeResolvConf("# Written by cloop: the host's resolvers, as the engine's default bridge gives them.\n",
		servers, search, options)
	if err != nil {
		return "", fmt.Errorf("container: the host's resolvers: %w", err)
	}
	return path, nil
}

// hasDNSFlag reports whether operator extra args set the sandbox's resolvers.
func hasDNSFlag(args []string) bool {
	for _, a := range args {
		if a == "--dns" || strings.HasPrefix(a, "--dns=") {
			return true
		}
	}
	return false
}

// preflightNetworkIsolation reports how this executor keeps one project's
// sandbox from reaching another's (Task 20502).
//
// An operator's own network is the one configuration it cannot: every
// sandbox joins that network as configured, so every project's sandboxes
// share it, and nothing cloop installs stands between them. That is a choice
// the operator may have made for a reason — a broker container on it, say —
// so it is a warning naming the alternative, not a refusal.
func (e *Executor) preflightNetworkIsolation(ctx context.Context, add func(name, level, msg, fix string)) {
	f := e.opts.EgressFilter
	own := "each project's sandboxes get a network of their own, never the engine's default bridge"
	switch {
	case e.opts.Network == NetworkNone && !f.Enabled:
		add("network-isolation", LevelOK, "sandboxes have no network, so none can reach another", "")
	case f.Enabled && f.filtersDirectly():
		add("network-isolation", LevelOK, own+"; every sandbox's ruleset refuses connections opened into it "+
			"from anywhere else, and its own to other sandboxes", "")
	case f.Enabled || e.opts.Network == NetworkBridge:
		_, err := e.nftForGuards(ctx)
		switch {
		case err == nil:
			add("network-isolation", LevelOK, own+", and a ruleset on each refuses every connection opened "+
				"into it from outside its network", "")
		case e.rt.Name == RuntimePodman:
			add("network-isolation", LevelWarn,
				own+", isolated from one another by podman, but this process cannot install rulesets ("+
					err.Error()+"), and podman's isolation does not cover its default network: a container "+
					"there can open connections into a sandbox",
				"run the control plane with nft(8) and CAP_NET_ADMIN, or use docker, which keeps its default "+
					"bridge apart from other networks")
		default:
			add("network-isolation", LevelOK, own+", which "+e.rt.Name+" keeps apart from its other networks "+
				"(no ruleset of cloop's: "+err.Error()+")", "")
		}
	default:
		add("network-isolation", LevelWarn,
			fmt.Sprintf("every project's sandboxes join the operator's network %q, so they can reach one another",
				e.opts.Network),
			"set executors.container.network to bridge, which gives each project a network of its own, unless "+
				"the sandboxes are meant to share this one")
	}
}

// SandboxBridgePrefixes returns the address ranges of this host's sandbox
// bridges — the interfaces this driver names clsb… — read from the kernel.
func SandboxBridgePrefixes() []netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, i := range ifs {
		if !strings.HasPrefix(i.Name, sandboxBridgePrefix) {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			bits, _ := n.Mask.Size()
			if p, err := ip.Unmap().Prefix(bits); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// SandboxAddressRefusal names an address on one of this host's sandbox
// networks, for the hub's egress proxy (egressbroker.Options.Refuse): a run's
// session may never reach a sandbox network through the hub, whatever its
// grant's CIDRs cover (Task 20502). The bridges are read at every call — a
// network made a moment ago is one a cache would not have seen yet — which
// costs a netlink dump per destination the proxy is asked for.
func SandboxAddressRefusal(a netip.Addr) string {
	a = a.Unmap()
	for _, p := range SandboxBridgePrefixes() {
		if p.Contains(a) {
			return "an address on a sandbox network of this host"
		}
	}
	return ""
}

// nftForGuards returns an applier when this process may install rulesets,
// asked once per executor: an unfiltered sandbox network gets its inbound
// guard only where nft is usable, and is not refused where it is not.
func (e *Executor) nftForGuards(ctx context.Context) (*netfilter.Applier, error) {
	if e.rootless() {
		// A rootless engine's bridges are in a namespace the host's rules
		// cannot see; a guard installed here would match nothing.
		return nil, fmt.Errorf("container: %s runs rootless", e.rt.Name)
	}
	e.guardOnce.Do(func() {
		a, err := netfilter.NewApplier()
		if err == nil {
			err = a.Available(ctx)
		}
		e.guardNft, e.guardErr = a, err
	})
	if e.guardErr != nil {
		return nil, e.guardErr
	}
	return e.guardNft, nil
}

// isolatedBuildNetwork creates a network for one derived-image build on
// podman, isolated like a sandbox network, and returns its removal (Task
// 20502). Its tenant label is "build", so the startup sweep finds one a dead
// process left.
func (e *Executor) isolatedBuildNetwork(ctx context.Context) (string, func(), error) {
	var raw [5]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, fmt.Errorf("container: name a build network: %w", err)
	}
	name := "cloop-bld-" + sanitizeNetworkPart(e.id) + "-" + hex.EncodeToString(raw[:])
	if _, err := e.ensureNetwork(ctx, networkSpec{name: name, bridge: bridgeName(name), tenant: "build"}); err != nil {
		return "", nil, err
	}
	return name, func() {
		rmCtx, cancel := context.WithTimeout(context.Background(), shortCmdTimeout)
		defer cancel()
		_, _ = runCLITimeout(rmCtx, e.rt, shortCmdTimeout, "network", "rm", name)
	}, nil
}
