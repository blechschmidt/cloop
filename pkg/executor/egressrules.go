package executor

// egressrules.go is what pkg/executor knows about the stored firewall levels
// (Task 20363): the two Spec fields that carry them to a driver, and the
// posture each executor reports so the dispatch step can compose them.
//
// The containment algebra itself lives in pkg/fwpolicy, which imports this
// package for FirewallRules; this file holds only what the drivers and the
// Spec need without importing it back.

import (
	"fmt"
	"strings"
)

// validateEgressRules checks the stored-level fields of a Spec.
func (s Spec) validateEgressRules() error {
	if s.EgressRules == nil {
		if s.EgressBound != nil {
			// The dispatch step sets both or neither. A bound with no rules is a
			// Spec some other path built, and a driver handed one would have to
			// guess whether the bound was meant to apply.
			return fmt.Errorf("%w: egress_bound is set without egress_rules; the dispatch step "+
				"that resolves a device's firewall sets both", ErrInvalidSpec)
		}
		return nil
	}
	if _, err := s.EgressRules.Normalize(); err != nil {
		return fmt.Errorf("egress_rules: %w", err)
	}
	if s.EgressBound != nil {
		if _, err := s.EgressBound.Normalize(); err != nil {
			return fmt.Errorf("egress_bound: %w", err)
		}
	}
	// A host interface is a second way out that no IP firewall on the sandbox
	// bridge sees: it is a link on another segment, handed to the sandbox
	// whole. Under a stored rule set it would be a bypass of the rules, so the
	// two cannot be combined.
	if len(s.Interfaces) > 0 {
		return fmt.Errorf("%w: this workload runs under firewall rules stored in the hub, but it was "+
			"also granted host interface(s) %s, which the firewall cannot filter — a granted link "+
			"is a route around it. Withdraw the host_interface grant, or clear the device's and "+
			"the project's firewall rules", ErrInvalidSpec, strings.Join(InterfaceNames(s.Interfaces), ", "))
	}
	return nil
}

// EgressPosture is what an executor's own configuration says about the network
// its sandboxes get, in the terms the firewall levels compose in.
type EgressPosture struct {
	// DeviceID is the executor whose stored rule set is the superset for this
	// one: its own ID, or for a virtual executor its device's.
	DeviceID string
	// Config is the bound the executor's configuration file sets
	// (executors.*.egress_filter) — the level above the device's stored rules.
	// nil when the configuration does not filter.
	Config *FirewallRules
	// Own is the executor's level between the device's rules and the
	// project's: a virtual executor's firewall, or the network a device's own
	// sandboxes are given. nil when it adds no narrowing of its own; a zero
	// rule set when its sandboxes get no network.
	Own *FirewallRules
	// OwnName names Own for a sentence ("virtual executor vx-… 's firewall").
	OwnName string
	// Enforceable reports whether the executor can install a firewall built
	// from rules for one workload — a filtered bridge, a NetworkPolicy.
	Enforceable bool
	// RemovesNetwork reports whether it can start a workload with no network
	// at all, which is how a rule set that reaches nothing is honoured without
	// a packet filter.
	RemovesNetwork bool
	// Reason says why not Enforceable, for a refusal and for the panel.
	Reason string
}

// EgressPostured is implemented by drivers that can state their posture.
type EgressPostured interface {
	EgressPosture() EgressPosture
}

// PostureOf asks an executor for its posture. A driver that does not implement
// EgressPostured cannot install rules for a workload — that is the
// conservative reading, and it is the true one for the host-process driver.
func PostureOf(ex Executor) EgressPosture {
	if ex == nil {
		return EgressPosture{Reason: "no executor was resolved"}
	}
	if p, ok := ex.(EgressPostured); ok {
		pos := p.EgressPosture()
		if pos.DeviceID == "" {
			pos.DeviceID = ex.ID()
		}
		return pos
	}
	return EgressPosture{
		DeviceID: ex.ID(),
		Reason: fmt.Sprintf("executor %s (%s) runs payloads without a per-workload network namespace, "+
			"so it cannot install a firewall for one", ex.ID(), ex.Kind()),
	}
}
