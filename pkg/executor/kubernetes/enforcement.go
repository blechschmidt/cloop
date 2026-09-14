package kubernetes

// enforcement.go answers the one question this driver cannot answer from the
// Kubernetes API: does this cluster actually enforce the NetworkPolicy objects
// it accepts?
//
// # Why the question has to be asked at all
//
// networkpolicy.go compiles a per-Pod NetworkPolicy from the same pkg/netfilter
// Policy the container driver's nftables ruleset is compiled from, and Start
// creates it before the Pod it governs. That is the whole mechanism a
// per-project egress scope needs — and it is worth exactly nothing on a cluster
// whose CNI does not implement NetworkPolicy. flannel is the well-known case:
// the API server validates the object, persists it, returns 201, and nothing
// ever reads it. `kubectl get netpol` lists a firewall that does not exist.
//
// So a driver that advertised SupportsEgressScope because it *creates the
// object* would be making a claim about someone else's software. A project that
// wrote `capabilities.egress: public` to keep model-authored code off the
// operator's internal network would be placed, would be told it succeeded, and
// would reach the internal network anyway. That is strictly worse than the
// refusal this replaces: a refusal is visible, and silent over-permission is
// what a scope exists to prevent.
//
// # The two ways out, and why there are exactly two
//
// Only the operator or an experiment can settle it, so this file models both:
//
//   - An assertion (executors.kubernetes.network_policy_enforced). The operator
//     states what CNI they run. Cheap, requires no cluster mutation, and is
//     only as good as the person writing it.
//   - A probe (netpolprobe.go). Two throwaway Pods and a default-deny policy:
//     prove the connection works, apply the policy, prove the same connection
//     now fails. That is evidence rather than testimony, so it outranks the
//     assertion — see Resolve.
//
// Everything else is unverified, and unverified fails closed.

import (
	"fmt"
	"strings"
	"time"
)

// DefaultVerdictMaxAge is how long a probe result is allowed to speak for the
// cluster.
//
// A verdict is a measurement of someone else's infrastructure, and a CNI can be
// replaced by a platform team that has never heard of cloop. Expiring the
// record turns that from a silent, permanent over-permission into a placement
// refusal naming the command that refreshes it — the failure mode an operator
// can act on. Thirty days is long enough that nobody re-probes during an
// incident and short enough that a CNI swap is caught within a release cycle.
const DefaultVerdictMaxAge = 30 * 24 * time.Hour

// EnforcementStatus is the resolved answer, and the vocabulary the CLI, the
// preflight report and the placement refusal all use.
type EnforcementStatus string

const (
	// EnforcementUnverified: nobody has said, and nothing has been proved.
	// Fails closed.
	EnforcementUnverified EnforcementStatus = "unverified"

	// EnforcementProven: a probe watched a connection that worked stop working
	// when a policy was applied.
	EnforcementProven EnforcementStatus = "proven"

	// EnforcementAsserted: an operator set network_policy_enforced: true and no
	// probe has contradicted them.
	EnforcementAsserted EnforcementStatus = "asserted"

	// EnforcementRefuted: a probe watched a connection survive a default-deny
	// policy. The cluster accepts NetworkPolicies and ignores them.
	EnforcementRefuted EnforcementStatus = "refuted"

	// EnforcementDenied: an operator set network_policy_enforced: false. It is
	// how you switch the capability off after a CNI change without waiting for
	// a recorded verdict to age out.
	EnforcementDenied EnforcementStatus = "denied"
)

// Enforced reports whether the status is one that may carry a per-project
// egress scope. Only two of the five are, and both of them are a positive
// statement by someone: everything else — including every error, every
// expiry and every absence — lands on false.
func (s EnforcementStatus) Enforced() bool {
	return s == EnforcementProven || s == EnforcementAsserted
}

// ProbeVerdict is one recorded run of the enforcement probe.
//
// It is JSON because it is persisted verbatim by the hub (see
// reconcile.SaveNetworkPolicyVerdict) and rendered by `cloop hub doctor --json`.
// Everything here is an observation, never a conclusion: Enforced says what the
// probe saw, ObservedAt says when, and Detail says how — so that a verdict an
// operator disagrees with can be argued with rather than merely overridden.
type ProbeVerdict struct {
	// Enforced is the measurement: true when the control connection worked and
	// the policed connection did not.
	Enforced bool `json:"enforced"`

	// ObservedAt is when the probe finished. Zero means "no verdict", which is
	// why Resolve checks it before trusting the rest of the struct.
	ObservedAt time.Time `json:"observed_at"`

	// Namespace and ExecutorID scope the claim. A verdict is about one
	// namespace on one cluster; replaying it against a different executor would
	// be a guess wearing a measurement's clothes, so LoadVerdict keys on the
	// executor and Resolve rejects a mismatch.
	Namespace  string `json:"namespace,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`

	// Detail is the operator-facing sentence: what was tried, what happened.
	Detail string `json:"detail,omitempty"`

	// ProbeVersion is the experiment's revision. A future probe that tests
	// something stronger must not silently inherit this one's authority, so a
	// verdict from an older version is treated as absent rather than as
	// evidence for a claim it never made.
	ProbeVersion int `json:"probe_version,omitempty"`
}

// CurrentProbeVersion is the revision of the experiment netpolprobe.go runs.
// Bump it whenever the experiment changes what it proves.
const CurrentProbeVersion = 1

// Recorded reports whether v holds an actual observation rather than a zero
// value that unmarshalled cleanly.
func (v ProbeVerdict) Recorded() bool { return !v.ObservedAt.IsZero() }

// Age is how long ago the probe ran, measured against now.
func (v ProbeVerdict) Age(now time.Time) time.Duration { return now.Sub(v.ObservedAt) }

// Stale reports whether the verdict has aged past maxAge, or was produced by a
// probe version this binary does not recognise.
//
// A verdict from the *future* — a clock that jumped, a record copied from
// another host — is stale too. Trusting it would let a bad timestamp buy
// unlimited authority for a claim nobody re-checked, and the cost of being
// wrong here is a firewall that is not there.
func (v ProbeVerdict) Stale(now time.Time, maxAge time.Duration) bool {
	if !v.Recorded() {
		return true
	}
	if v.ProbeVersion != CurrentProbeVersion {
		return true
	}
	if maxAge <= 0 {
		maxAge = DefaultVerdictMaxAge
	}
	age := v.Age(now)
	return age > maxAge || age < -time.Hour
}

// NetworkPolicyEnforcement is everything known about whether this cluster
// enforces a NetworkPolicy, before it is resolved into a single answer.
//
// Assertion is a *bool so that "the operator said no" is distinguishable from
// "the operator said nothing". They resolve differently and must: the first is
// a deliberate veto, the second is the default every existing deployment
// already has.
type NetworkPolicyEnforcement struct {
	// Assertion is executors.kubernetes.network_policy_enforced.
	Assertion *bool

	// Verdict is the recorded probe result, if the hub has one.
	Verdict ProbeVerdict

	// MaxVerdictAge overrides DefaultVerdictMaxAge. Zero uses the default.
	MaxVerdictAge time.Duration
}

// Resolve reduces the evidence to one status and the sentence explaining it.
//
// The precedence is not arbitrary, and the ordering is the security argument:
//
//  1. An explicit `false` wins outright. It is the restrictive direction, and
//     it is the only control an operator has that takes effect *immediately* —
//     the alternative would be editing config, then racing a recorded verdict
//     that is still inside its expiry.
//  2. A fresh probe wins over an assertion, in both directions. This is the
//     "proof beats testimony" rule the capability rests on: an operator who
//     asserted enforcement on a cluster that demonstrably ignores policies has
//     made a mistake, and the measurement is what catches it.
//  3. An assertion wins over nothing.
//  4. Nothing is unverified, and unverified is not Enforced().
//
// A stale verdict is treated as no verdict — it falls through to the assertion
// — because an expired measurement is not evidence against anything, and
// demoting an asserting operator's cluster because a probe ran 31 days ago
// would be noise, not safety.
func (n NetworkPolicyEnforcement) Resolve(executorID string, now time.Time) (EnforcementStatus, string) {
	status, v := n.resolve(executorID, now)
	switch status {
	case EnforcementDenied:
		return status, "executors.kubernetes.network_policy_enforced is set to false, so " +
			"this executor does not carry per-project egress scopes"
	case EnforcementProven:
		return status, fmt.Sprintf("a probe proved this cluster enforces NetworkPolicy %s",
			describeWhen(v.ObservedAt, now))
	case EnforcementRefuted:
		return status, fmt.Sprintf("a probe found this cluster accepts NetworkPolicy objects "+
			"and does not enforce them (%s); a per-project egress scope here would be a firewall that "+
			"is not applied", describeWhen(v.ObservedAt, now))
	case EnforcementAsserted:
		msg := "executors.kubernetes.network_policy_enforced asserts this cluster's CNI enforces NetworkPolicy"
		if v.Recorded() {
			msg += fmt.Sprintf(" (the recorded probe from %s is no longer current)", describeWhen(v.ObservedAt, now))
		}
		return status, msg
	default:
		if v.Recorded() {
			return status, fmt.Sprintf("the recorded probe from %s is no longer current, and "+
				"nothing asserts that this cluster enforces NetworkPolicy", describeWhen(v.ObservedAt, now))
		}
		return status, "nothing has established that this cluster's CNI enforces NetworkPolicy " +
			"(flannel accepts the objects and ignores them; Calico, Cilium, Antrea and most managed CNIs do not)"
	}
}

// resolve is the decision, separated from the sentence explaining it, and
// returns the verdict the decision was made on — which is not always n.Verdict,
// since one recorded for a different executor is discarded.
//
// Split out because Capabilities() consults this on every placement decision,
// for every candidate, and the explanatory sentence is discarded in all of those
// calls. Formatting a paragraph to answer a boolean is the kind of cost that
// does not show up until a fleet has a few hundred projects in it.
func (n NetworkPolicyEnforcement) resolve(executorID string, now time.Time) (EnforcementStatus, ProbeVerdict) {
	if n.Assertion != nil && !*n.Assertion {
		return EnforcementDenied, ProbeVerdict{}
	}

	v := n.Verdict
	// A verdict recorded for another executor is not this executor's evidence.
	// Executors differ in namespace and in the credential they connect with,
	// and both change what a policy is applied to.
	if v.Recorded() && v.ExecutorID != "" && executorID != "" && v.ExecutorID != executorID {
		v = ProbeVerdict{}
	}
	if v.Recorded() && !v.Stale(now, n.MaxVerdictAge) {
		if v.Enforced {
			return EnforcementProven, v
		}
		return EnforcementRefuted, v
	}
	if n.Assertion != nil && *n.Assertion {
		return EnforcementAsserted, v
	}
	return EnforcementUnverified, v
}

// Status is the decision alone, without building the sentence that explains it.
func (n NetworkPolicyEnforcement) Status(executorID string, now time.Time) EnforcementStatus {
	status, _ := n.resolve(executorID, now)
	return status
}

// describeWhen renders a timestamp as something an operator reads without
// converting time zones in their head.
func describeWhen(at, now time.Time) string {
	d := now.Sub(at)
	switch {
	case d < 0:
		return fmt.Sprintf("at %s (in the future — check the clock on the host that probed)",
			at.UTC().Format(time.RFC3339))
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s) ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d day(s) ago, on %s", int(d.Hours()/24), at.UTC().Format("2006-01-02"))
	}
}

// ExplainEgressScopeRefusal implements executor.EgressScopeExplainer: it says
// why this executor is refusing a project's egress scope, and what to run.
//
// The two refusals are not the same problem and must not read as though they
// were. "Nobody has checked" is settled by running the probe; "the probe found
// your CNI ignores NetworkPolicy" is settled by changing CNI, and telling that
// operator to re-run the probe would send them round a loop that cannot
// terminate.
func (e *Executor) ExplainEgressScopeRefusal() string {
	status, reason, _ := e.EnforcementState()
	switch status {
	case EnforcementRefuted:
		return reason + ". Installing the policy anyway would hand this project a firewall the " +
			"cluster ignores, so placement refuses instead. Move the project to a cluster whose " +
			"CNI implements NetworkPolicy (Calico, Cilium, Antrea), or drop capabilities.egress " +
			"from .cloop/sandbox.yaml"
	case EnforcementDenied:
		return reason + ". Remove that key, or set it to true once you have confirmed the CNI " +
			"enforces NetworkPolicy — `" + ProbeCommand(e.id) + "` proves it against the cluster"
	default:
		return reason + ". Prove it with `" + ProbeCommand(e.id) + "`, which creates two throwaway " +
			"Pods and a default-deny policy, checks that the connection actually stops working, " +
			"and cleans up — or, if you already know your CNI, set " +
			"executors.kubernetes.network_policy_enforced: true"
	}
}

// ProbeCommand is the command an operator runs to settle the question. It is
// quoted in the placement refusal, in preflight and in `cloop hub doctor`,
// because a refusal that does not name its own remedy is a refusal the operator
// resolves by disabling the feature.
func ProbeCommand(executorID string) string {
	id := strings.TrimSpace(executorID)
	if id == "" {
		return "cloop hub doctor --probe-network-policy"
	}
	return fmt.Sprintf("cloop hub doctor --probe-network-policy --executor %s", id)
}
