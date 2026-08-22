package reconcile

// ready.go answers the question a Kubernetes readiness probe is really
// asking: can this control plane run anything?
//
// Before Task 20170 /readyz answered a narrower question — "is the SQLite
// state store reachable" — and a hub in strict mode with no isolating
// executor passed it. The rollout went green, the Service started sending it
// traffic, and every run was refused with a 409 that only the person clicking
// the button ever saw. Readiness that ignores the executor registry is
// readiness for a hub that cannot do its job.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// NotReadyError reports that no workload can be dispatched, and why.
//
// It carries the remediation as a separate field rather than only inside the
// message so a probe body, a startup log line and the Executors panel can
// render the cause and the fix in whatever shape each needs.
type NotReadyError struct {
	// Reason is the one-line cause.
	Reason string
	// Remediation is the concrete next action.
	Remediation string
	// Diagnostics are the failed or degraded drivers from the last
	// reconciliation, when there was one. Empty means nothing was even
	// configured — a materially different and more urgent situation than a
	// driver that tried and failed.
	Diagnostics []Diagnostic
}

// Error implements error.
func (e *NotReadyError) Error() string {
	var b strings.Builder
	b.WriteString(e.Reason)
	for _, d := range e.Diagnostics {
		fmt.Fprintf(&b, "; %s (%s) is %s: %s", d.ID, d.Kind, d.Status, d.Message)
	}
	if e.Remediation != "" {
		b.WriteString(". ")
		b.WriteString(e.Remediation)
	}
	return b.String()
}

// Ready reports whether this control plane can dispatch a workload, against
// the default registry.
//
// It is computed live rather than read off the last report on purpose. A hub
// may legitimately start with nothing isolating registered and become usable
// when a remote agent enrolls minutes later; a readiness verdict frozen at
// startup would keep that hub out of service until someone restarted it. The
// last report is consulted only to explain a failure, never to decide one.
func Ready() error { return ReadyIn(executor.DefaultRegistry) }

// ReadyIn is Ready against a specific registry, for tests and embedders that
// keep their own.
func ReadyIn(reg *executor.Registry) error {
	if reg == nil {
		reg = executor.DefaultRegistry
	}
	// Permissive mode: the host driver is a legitimate backend, and a hub
	// with no executor at all still has one registered by bootstrap. Nothing
	// to gate on.
	if executor.HostExecutionAllowed() {
		return nil
	}
	if len(reg.IsolatedIDs()) > 0 {
		return nil
	}

	err := &NotReadyError{
		Reason: "strict mode is on (executors.allow_host_process: false) and no isolating " +
			"executor is registered, so every run would be refused",
	}
	if report, ok := LastReport(); ok {
		err.Diagnostics = report.Problems()
	}
	err.Remediation = readyRemediation(err.Diagnostics)
	return err
}

// readyRemediation prefers a fix for something the operator actually
// configured. Telling someone to "enable executors.container" when they
// already did, and it failed preflight, is the kind of advice that erodes
// trust in every other message the system prints.
func readyRemediation(problems []Diagnostic) string {
	for _, d := range problems {
		if d.Remediation != "" {
			return d.Remediation
		}
	}
	return "enable executors.container or executors.kubernetes in .cloop/config.yaml, " +
		"enroll a remote agent (`cloop executor enroll`), or set " +
		"executors.allow_host_process: true to permit un-isolated host execution"
}
