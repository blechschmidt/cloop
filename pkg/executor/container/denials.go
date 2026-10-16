package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/denylog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// denials.go is what this driver tells pkg/denylog about a filtered sandbox
// (Task 20437): which NFLOG group its ruleset logs to and under which rule
// set, and — once the engine has given the container an address — which run
// a packet from that address on that bridge belongs to.
//
// Everything here is best effort in one direction only. A ruleset is never
// installed without its deny verdicts because the log could not be set up; at
// worst it is installed without log statements, and the run's refusals are
// fast and unrecorded rather than slow and unrecorded. A sandbox whose address
// could not be read back still runs, and its log lines are counted as
// unattributed.

// HandleRecord.Meta keys carrying a sandbox's attribution across a restart of
// the process that started it: the rule set's fingerprint, the bridge, and the
// addresses the engine gave the container.
const (
	metaDenyFingerprint = "deny_fp"
	metaDenyBridge      = "deny_bridge"
	metaDenyAddrs       = "deny_addrs"
)

// denialTrack is one sandbox's attribution.
type denialTrack struct {
	fingerprint string
	bridge      string
	addrs       []netip.Addr
}

// filterFingerprint names the rule set an EgressFilter installs, in the form
// fwpolicy.Fingerprint gives a stored rule set: so the fingerprint a workload
// carrying rules from the hub logs under is the one the hub computes from
// Spec.EgressRules, and one under this executor's own filter is stable across
// restarts. The broker and the hub's proxy are not part of it — they are
// infrastructure every rule set opens — and neither are the host patterns,
// which no packet filter enforces.
func filterFingerprint(f EgressFilter) string {
	r := executor.FirewallRules{
		AllowPublicInternet: f.AllowPublicInternet,
		AllowCIDRs:          f.AllowCIDRs,
		DenyCIDRs:           f.DenyCIDRs,
		Resolvers:           f.Resolvers,
		DropDenied:          f.DropDenied,
	}
	if !f.AllowAllPorts {
		r.AllowPorts = f.AllowPorts
	}
	return fwpolicy.Fingerprint(r)
}

// tableFingerprint is the fingerprint a confinement's ruleset logs under.
func tableFingerprint(c confinement, f EgressFilter) string {
	if c.rules != nil {
		return fwpolicy.Fingerprint(*c.rules)
	}
	return filterFingerprint(f)
}

// denialLogOptions turns the packet log on for a ruleset this process installs,
// when this process reads it. A process with no sink — `cloop run` with a
// container executor, a CLI preview — or one that cannot bind a group renders
// no log statements: it has nothing to read them with.
func denialLogOptions(fingerprint string) *netfilter.LogOptions {
	m, err := denylog.Shared()
	if err != nil {
		return nil
	}
	return &netfilter.LogOptions{Group: m.Group(), Fingerprint: fingerprint}
}

// containerAddrs reads back the addresses the engine gave a container on one
// network. docker and podman both report NetworkSettings.Networks keyed by
// network name, with IPAddress and GlobalIPv6Address.
func (e *Executor) containerAddrs(ctx context.Context, name, network string) ([]netip.Addr, error) {
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout,
		"inspect", "--format", "{{json .NetworkSettings.Networks}}", name)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("container: inspect %s: %s", name, firstLine(res.Stderr))
	}
	var nets map[string]struct {
		IPAddress         string `json:"IPAddress"`
		GlobalIPv6Address string `json:"GlobalIPv6Address"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(firstLine(res.Stdout))), &nets); err != nil {
		return nil, fmt.Errorf("container: %s reported unreadable networks for %s: %w", e.rt.Name, name, err)
	}
	n, ok := nets[network]
	if !ok {
		return nil, fmt.Errorf("container: %s is not on network %s", name, network)
	}
	var out []netip.Addr
	for _, raw := range []string{n.IPAddress, n.GlobalIPv6Address} {
		if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			out = append(out, a.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("container: %s has no address on network %s", name, network)
	}
	return out, nil
}

// trackDenials attributes a started sandbox's refusals to its handle. Errors
// are reported, not returned: the sandbox is already running under its
// firewall, and a log line that cannot be attributed is a diagnostic lost,
// not a hole.
func (e *Executor) trackDenials(rec *record, t *denialTrack) {
	if t == nil {
		return
	}
	m, err := denylog.Shared()
	if err != nil {
		return
	}
	ifc, err := net.InterfaceByName(t.bridge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "container: %s: refusals on bridge %s cannot be attributed: %v\n", rec.id, t.bridge, err)
		return
	}
	if err := m.Track(denylog.Run{ID: rec.id, Executor: e.id}, t.fingerprint, uint32(ifc.Index), t.addrs); err != nil {
		fmt.Fprintf(os.Stderr, "container: %s: refusals cannot be attributed: %v\n", rec.id, err)
		return
	}
	rec.mu.Lock()
	rec.denials = t
	rec.mu.Unlock()
}

// releaseDenials tells the monitor a sandbox is gone.
func releaseDenials(rec *record) {
	rec.mu.Lock()
	t := rec.denials
	rec.mu.Unlock()
	if t == nil {
		return
	}
	if m, err := denylog.Shared(); err == nil {
		m.Release(rec.id)
	}
}

// denialMeta records a sandbox's attribution on its handle row, so the process
// that adopts it after a restart attributes its refusals too.
func denialMeta(meta map[string]string, t *denialTrack) map[string]string {
	if t == nil {
		return meta
	}
	if meta == nil {
		meta = map[string]string{}
	}
	addrs := make([]string, len(t.addrs))
	for i, a := range t.addrs {
		addrs[i] = a.String()
	}
	meta[metaDenyFingerprint] = t.fingerprint
	meta[metaDenyBridge] = t.bridge
	meta[metaDenyAddrs] = strings.Join(addrs, ",")
	return meta
}

// denialFromMeta reads an adopted handle's attribution back, or nil.
func denialFromMeta(meta map[string]string) *denialTrack {
	bridge := meta[metaDenyBridge]
	if bridge == "" || netfilter.ValidateInterfaceName(bridge) != nil {
		return nil
	}
	t := &denialTrack{fingerprint: meta[metaDenyFingerprint], bridge: bridge}
	for _, raw := range strings.Split(meta[metaDenyAddrs], ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			t.addrs = append(t.addrs, a)
		}
	}
	if len(t.addrs) == 0 {
		return nil
	}
	return t
}

// FlushDenials reports what is left of a finished workload's refusals and
// forgets them: the call a process makes after the workload has exited and
// before it reports the run's end, so the last refusals are not lost in the
// kernel's queue. A handle with none is no work.
func FlushDenials(ctx context.Context, handleID string) error {
	m, err := denylog.Shared()
	if err != nil {
		return nil
	}
	return m.FlushFinal(ctx, handleID)
}

// DenialsObservable says whether this process records what its sandboxes'
// firewalls refuse, and if not, why.
func DenialsObservable() (bool, string) { return denylog.Running() }
