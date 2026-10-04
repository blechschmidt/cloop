package remote

// egressrules.go is the device path's half of the stored firewall levels (Task
// 20363): what a device and a virtual executor report to the dispatch step that
// composes the levels, and the check made here, on the hub, before a start
// frame carrying rules is sent. The agent proves the same containment again on
// the device before it installs a rule; see the container driver's checkRules.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
)

// networkLevel and virtualLevel are fwpolicy's, named here for brevity.
var (
	networkLevel = fwpolicy.NetworkLevel
	virtualLevel = fwpolicy.VirtualLevel
)

// rulesEnforceable reports whether the device, as last advertised, can install
// a firewall built from rules: it needs the packet filter, and a connected
// agent must speak v15. An offline device is judged by what it advertised; the
// dispatch itself re-checks the live session.
func (e *Executor) rulesEnforceable() (bool, string) {
	caps := e.AgentCapabilities()
	if !caps.PacketFilter {
		return false, fmt.Sprintf("device %s cannot install a packet filter (%s); grant the agent "+
			"CAP_NET_ADMIN with `sudo %s` on the device", e.id, packetFilterIssue(caps),
			executor.PacketFilterGrantProcedure)
	}
	if v := e.ProtocolVersion(); v != 0 && !SupportsEgressRules(v) {
		return false, executor.NeedsProtocol("device "+e.id+"'s agent", v, MinEgressRulesVersion,
			"to have it install firewall rules stored in the hub", "")
	}
	return true, ""
}

// EgressPosture implements executor.EgressPostured for a workload placed on
// the device itself.
func (e *Executor) EgressPosture() executor.EgressPosture {
	p := executor.EgressPosture{DeviceID: e.id}
	sandbox, err := e.opts.sandboxSettings()
	if err != nil {
		p.Reason = fmt.Sprintf("device %s's sandbox configuration could not be read: %v", e.id, err)
		return p
	}
	sandbox = sandbox.Normalize()
	if sandbox.Mode != executor.SandboxModeContainer {
		p.Reason = fmt.Sprintf("device %s runs payloads on its host, where no per-workload firewall can be "+
			"installed; set its sandbox mode to container", e.id)
		return p
	}
	p.Own, p.OwnName = networkLevel(sandbox.Network), "device "+e.id+"'s sandbox network"
	p.RemovesNetwork = true
	p.Enforceable, p.Reason = e.rulesEnforceable()
	return p
}

// EgressPosture implements executor.EgressPostured for a virtual executor: the
// device's rule set bounds it, and its own firewall is the next level in.
func (v *Virtual) EgressPosture() executor.EgressPosture {
	p := executor.EgressPosture{DeviceID: v.parent.ID()}
	vs, err := v.Spec()
	if err != nil {
		// Unreadable is not "no firewall": refusing to know is the only answer
		// that cannot widen anything.
		p.Own = &executor.FirewallRules{}
		p.OwnName = "virtual executor " + v.id + " (unreadable configuration)"
		p.Reason = fmt.Sprintf("virtual executor %s's configuration could not be read: %v", v.id, err)
		return p
	}
	p.Own = virtualLevel(vs)
	p.OwnName = "virtual executor " + v.id + "'s firewall"
	if vs.Firewall == nil {
		p.OwnName = "virtual executor " + v.id + "'s network"
	}
	p.RemovesNetwork = true
	p.Enforceable, p.Reason = v.parent.rulesEnforceable()
	return p
}

// checkEgressRules is the hub's last word before the start frame: the agent
// can carry the rules, and they fit inside the level the payload will run
// under and the device's rule set as stored now.
func (e *Executor) checkEgressRules(sess *Session, spec executor.Spec, sandbox executor.SandboxSettings,
	virtual *VirtualDispatch) error {
	var own *executor.FirewallRules
	ownName := "device " + e.id + "'s sandbox network"
	switch {
	case virtual != nil:
		own, ownName = virtualLevel(virtual.Spec), "virtual executor "+virtual.ID+"'s firewall"
	case sandbox.Mode == executor.SandboxModeContainer:
		own = networkLevel(sandbox.Network)
	}
	if err := fwpolicy.CheckAtDriver(spec, own, ownName, e.id); err != nil {
		return err
	}
	if spec.EgressRules == nil {
		return nil
	}
	if !SupportsEgressRules(sess.Version()) {
		// An older agent would not refuse the rules, it would ignore them.
		return fmt.Errorf("%w: %s", executor.ErrUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinEgressRulesVersion,
			"for the firewall rules stored in the hub that this run carries, which the agent must install "+
				"and check itself — an older one would ignore them", ""))
	}
	if sandbox.Mode != executor.SandboxModeContainer {
		return fmt.Errorf("%w: this run carries firewall rules, but device %s runs payloads on its host, "+
			"where no per-workload firewall can be installed", executor.ErrUnsupported, e.id)
	}
	if spec.EgressRules.HasDestination() {
		if ok, why := e.rulesEnforceable(); !ok {
			return fmt.Errorf("%w: %s", executor.ErrUnsupported, why)
		}
	}
	return nil
}
