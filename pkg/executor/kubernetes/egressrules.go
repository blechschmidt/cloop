package kubernetes

// egressrules.go is the Kubernetes half of the stored firewall levels (Task
// 20363): the posture the hub composes against, and the check Start makes
// before a NetworkPolicy built from a workload's rules is created.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
)

// EgressPosture implements executor.EgressPostured.
//
// A NetworkPolicy is only a firewall if the cluster's network plugin enforces
// it, and cloop installs one either way. So rules are enforceable here only on
// a cluster whose enforcement has been proven by the probe or asserted by its
// operator — the same verdict SupportsEgressScope already rests on. On any
// other cluster a rule set would be an object that changes nothing, and the
// dispatch is refused rather than started under it.
func (e *Executor) EgressPosture() executor.EgressPosture {
	status := e.EnforcementStatus()
	p := executor.EgressPosture{
		DeviceID: e.id,
		Config:   e.opts.EgressFilter.OwnRules(),
	}
	if status.Enforced() {
		p.Enforceable, p.RemovesNetwork = true, true
		return p
	}
	p.Reason = fmt.Sprintf("executor %s cannot show that its cluster enforces NetworkPolicy (enforcement is %s), "+
		"so a policy built from the rules might change nothing; prove it with "+
		"`cloop hub doctor --probe-network-policy`", e.id, status)
	return p
}

// checkRules is Start's proof that a workload's rules fit inside this
// executor's egress_filter and the device's rule set, and that the cluster will
// honour the policy they become.
func (e *Executor) checkRules(spec executor.Spec) error {
	if err := fwpolicy.CheckAtDriver(spec, e.opts.EgressFilter.OwnRules(),
		"executor "+e.id+"'s egress_filter", e.id); err != nil {
		return err
	}
	if spec.EgressRules == nil {
		return nil
	}
	if status := e.EnforcementStatus(); !status.Enforced() {
		return fmt.Errorf("%w: this workload runs under firewall rules, but executor %s cannot show that "+
			"its cluster enforces NetworkPolicy (enforcement is %s); refusing rather than starting it "+
			"under a policy that might change nothing", executor.ErrUnsupported, e.id, status)
	}
	return nil
}
