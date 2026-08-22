package executor

// health.go models an executor's *scheduling* state, as distinct from a
// workload's lifecycle State (pending/running/exited/...). The two are
// deliberately different types: a handle is a thing that finishes, a node is a
// thing that comes and goes.
//
// Before this file, pkg/executor exposed HealthCheck() and nobody called it.
// An edge device that dropped off the network stayed "registered" forever, so
// the next Resolve handed work to a machine that was not there, and the only
// symptom was a run that never produced output. Worse, there was no way to say
// "stop sending work here" short of deleting the executor, which also killed
// whatever was already running on it.
//
// The state set is deliberately small and split by *who owns the transition*:
//
//	ready        probes succeeding; takes new work
//	degraded     probes failing but under the give-up threshold; still takes
//	             work, but placement prefers a ready node
//	unreachable  probes failed past the threshold; takes no new work, and
//	             in-flight sessions are failed over
//	cordoned     an operator took it out of rotation; in-flight work continues
//	draining     an operator is retiring it; in-flight work continues, no new
//	             work, and the node is done when in-flight reaches zero
//
// The first three are *probe-owned*: the supervisor moves between them freely.
// The last two are *admin-owned*, and the invariant that makes cordon usable at
// all is that a probe may never leave them. An operator who cordons a node to
// investigate it must not have that decision silently reverted three seconds
// later because the node answered a health check — that is the whole reason
// cordon exists as a state rather than as "unregister it and hope".

import (
	"fmt"
	"strings"
	"time"
)

// NodeState is the scheduling state of a registered executor.
type NodeState string

const (
	// NodeReady: probes are succeeding and the node accepts new work.
	NodeReady NodeState = "ready"
	// NodeDegraded: probes are failing but the node has not yet been given
	// up on. It still accepts work — a node that is slow to answer a health
	// check is usually still able to run one — but placement treats it as a
	// last resort.
	NodeDegraded NodeState = "degraded"
	// NodeUnreachable: probes have failed past the threshold. The node
	// accepts no new work and its in-flight sessions are failed over.
	NodeUnreachable NodeState = "unreachable"
	// NodeCordoned: an operator removed the node from rotation. In-flight
	// work continues to completion; only new placement is refused.
	NodeCordoned NodeState = "cordoned"
	// NodeDraining: an operator is retiring the node. Like cordoned, but the
	// intent is to reach zero in-flight and stay there.
	NodeDraining NodeState = "draining"
)

// Valid reports whether s is one of the known states.
func (s NodeState) Valid() bool {
	switch s {
	case NodeReady, NodeDegraded, NodeUnreachable, NodeCordoned, NodeDraining:
		return true
	}
	return false
}

// Schedulable reports whether new work may be placed on a node in this state.
//
// Degraded is schedulable on purpose. A health probe is a much weaker signal
// than an actual workload: a node whose probe timed out once may be perfectly
// able to run a task, and refusing to schedule on the first missed probe would
// make a fleet of flaky edge devices permanently unusable. Placement breaks the
// tie by preferring ready nodes, so degraded only ever gets work when nothing
// better exists.
func (s NodeState) Schedulable() bool {
	return s == NodeReady || s == NodeDegraded
}

// AdminHeld reports whether the state was set by an operator rather than by a
// probe. Probe results never move a node out of an admin-held state.
func (s NodeState) AdminHeld() bool {
	return s == NodeCordoned || s == NodeDraining
}

// Health is the supervisor's view of one executor. It is the value persisted
// by a HealthStore and the value placement filters on.
type Health struct {
	// ExecutorID is the registry key this health record describes.
	ExecutorID string `json:"executor_id"`
	// State is the current scheduling state.
	State NodeState `json:"state"`
	// Reason is a short human-readable explanation of the current state:
	// the probe error for unreachable, the operator's note for cordoned.
	Reason string `json:"reason,omitempty"`
	// ConsecutiveFailures counts probe failures since the last success. It
	// keeps counting while a node is cordoned so that uncordoning restores
	// the state the probes actually justify rather than optimistically
	// assuming ready.
	ConsecutiveFailures int `json:"consecutive_failures"`
	// LastSeen is the most recent time a probe succeeded. Zero means the
	// node has never been observed healthy by this control plane.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// LastProbe is the most recent time a probe ran, successful or not. The
	// gap between LastProbe and LastSeen is how long a node has been failing.
	LastProbe time.Time `json:"last_probe,omitempty"`
	// StateChangedAt is when State last took a different value, which is what
	// "cordoned 20m ago" in the UI is computed from.
	StateChangedAt time.Time `json:"state_changed_at,omitempty"`
}

// Normalize fills in a usable zero value. A node with no persisted health
// record is ready: refusing to schedule on an executor merely because the
// supervisor has not reached its first tick would make every fresh control
// plane briefly unable to run anything.
func (h Health) Normalize() Health {
	if !h.State.Valid() {
		h.State = NodeReady
	}
	if h.ConsecutiveFailures < 0 {
		h.ConsecutiveFailures = 0
	}
	return h
}

// Stale reports whether the node has gone longer than ttl without a successful
// probe. A node that has never been seen is stale only once ttl has elapsed
// since ref, so a control plane that just started does not declare its whole
// fleet stale before the first probe lands.
func (h Health) Stale(ref time.Time, ttl time.Duration) bool {
	if ttl <= 0 {
		return false
	}
	if h.LastSeen.IsZero() {
		return !h.StateChangedAt.IsZero() && ref.Sub(h.StateChangedAt) > ttl
	}
	return ref.Sub(h.LastSeen) > ttl
}

// HealthPolicy tunes how many failed probes it takes to give up on a node.
//
// The two thresholds exist because the failure modes are different. One missed
// probe is usually a blip — a wifi roam, a GC pause on a Raspberry Pi — and
// reacting to it by failing over in-flight work would cause more damage than it
// prevents. Sustained failure means the device is genuinely gone, and holding
// its sessions hostage any longer just delays the user's task.
type HealthPolicy struct {
	// DegradeAfter is the consecutive-failure count at which a ready node
	// becomes degraded. Must be >= 1.
	DegradeAfter int
	// UnreachableAfter is the consecutive-failure count at which a node is
	// declared unreachable and its work is failed over. Must be >=
	// DegradeAfter.
	UnreachableAfter int
}

// DefaultHealthPolicy degrades on the first failure and gives up after three.
// With the default 30s probe interval that is roughly a 90-second window before
// failover, which is long enough to ride out a reboot and short enough that a
// user watching a stalled run does not give up first.
func DefaultHealthPolicy() HealthPolicy {
	return HealthPolicy{DegradeAfter: 1, UnreachableAfter: 3}
}

// normalize clamps a policy into a self-consistent shape rather than returning
// an error. A misconfigured threshold must not be able to disable liveness
// supervision for the whole fleet.
func (p HealthPolicy) normalize() HealthPolicy {
	if p.DegradeAfter < 1 {
		p.DegradeAfter = 1
	}
	if p.UnreachableAfter < p.DegradeAfter {
		p.UnreachableAfter = p.DegradeAfter
	}
	return p
}

// Transition records one state change, for the event log and the UI.
type Transition struct {
	ExecutorID string    `json:"executor_id"`
	From       NodeState `json:"from"`
	To         NodeState `json:"to"`
	Reason     string    `json:"reason,omitempty"`
	At         time.Time `json:"at"`
}

// String renders a transition as "id: ready -> unreachable (reason)".
func (t Transition) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s -> %s", t.ExecutorID, t.From, t.To)
	if t.Reason != "" {
		fmt.Fprintf(&b, " (%s)", t.Reason)
	}
	return b.String()
}

// ObserveProbe folds one probe result into h and reports the resulting health
// plus the transition it caused, if any.
//
// It is a pure function of (health, result, time, policy) with no clock, no
// I/O, and no locking, which is what lets the state machine be tested
// exhaustively under a fake clock while the supervisor around it deals with
// timers and goroutines.
//
// probeErr is nil for a successful probe.
func ObserveProbe(h Health, probeErr error, at time.Time, policy HealthPolicy) (Health, *Transition) {
	policy = policy.normalize()
	h = h.Normalize()
	from := h.State
	h.LastProbe = at

	if probeErr == nil {
		h.ConsecutiveFailures = 0
		h.LastSeen = at
		// An admin-held node stays held. Recording LastSeen is still
		// correct and useful — "cordoned, and answering" is exactly what an
		// operator wants to see before uncordoning — but the state is not
		// the probe's to change.
		if from.AdminHeld() {
			return h, nil
		}
		if from == NodeReady {
			return h, nil
		}
		return applyState(h, NodeReady, "probe succeeded", at), transition(h.ExecutorID, from, NodeReady, "probe succeeded", at)
	}

	h.ConsecutiveFailures++
	reason := probeReason(probeErr)

	// Failures are counted while cordoned or draining so that uncordon lands
	// in the state the evidence supports, but they do not move the state.
	if from.AdminHeld() {
		return h, nil
	}

	target := from
	switch {
	case h.ConsecutiveFailures >= policy.UnreachableAfter:
		target = NodeUnreachable
	case h.ConsecutiveFailures >= policy.DegradeAfter:
		// Never walk backwards from unreachable to degraded on a *failed*
		// probe: the node is still failing, and flapping the state would
		// re-arm failover for sessions that were already failed over.
		if from != NodeUnreachable {
			target = NodeDegraded
		}
	}

	if target == from {
		// Same state, fresher reason — a node that has been unreachable for
		// an hour should show why it is failing *now*.
		h.Reason = reason
		return h, nil
	}
	return applyState(h, target, reason, at), transition(h.ExecutorID, from, target, reason, at)
}

// Cordon takes a node out of rotation without disturbing its in-flight work.
func Cordon(h Health, reason string, at time.Time) (Health, *Transition) {
	return adminTransition(h, NodeCordoned, defaultReason(reason, "cordoned by operator"), at)
}

// Drain takes a node out of rotation and marks it for retirement. It differs
// from Cordon only in intent, which the UI and `cloop executor drain` surface:
// draining implies someone is waiting for in-flight to reach zero.
func Drain(h Health, reason string, at time.Time) (Health, *Transition) {
	return adminTransition(h, NodeDraining, defaultReason(reason, "draining by operator"), at)
}

// Uncordon returns an admin-held node to the state its probe history justifies.
//
// It deliberately does not return to ready unconditionally. A node cordoned
// *because* it was misbehaving, then uncordoned, should come back as degraded
// or unreachable if its probes are still failing — otherwise uncordon becomes a
// way to launder a broken node into the schedulable set, and the next task
// placed on it fails for reasons the operator just told the system to ignore.
func Uncordon(h Health, at time.Time, policy HealthPolicy) (Health, *Transition) {
	h = h.Normalize()
	from := h.State
	if !from.AdminHeld() {
		return h, nil
	}
	policy = policy.normalize()

	target := NodeReady
	reason := "uncordoned"
	switch {
	case h.ConsecutiveFailures >= policy.UnreachableAfter:
		target = NodeUnreachable
		reason = "uncordoned; probes still failing"
	case h.ConsecutiveFailures >= policy.DegradeAfter:
		target = NodeDegraded
		reason = "uncordoned; probes still failing"
	}
	return applyState(h, target, reason, at), transition(h.ExecutorID, from, target, reason, at)
}

// applyState sets the state and its bookkeeping fields.
func applyState(h Health, to NodeState, reason string, at time.Time) Health {
	h.State = to
	h.Reason = reason
	h.StateChangedAt = at
	return h
}

func adminTransition(h Health, to NodeState, reason string, at time.Time) (Health, *Transition) {
	h = h.Normalize()
	from := h.State
	if from == to {
		return h, nil
	}
	return applyState(h, to, reason, at), transition(h.ExecutorID, from, to, reason, at)
}

func transition(id string, from, to NodeState, reason string, at time.Time) *Transition {
	return &Transition{ExecutorID: id, From: from, To: to, Reason: reason, At: at}
}

func defaultReason(reason, fallback string) string {
	if strings.TrimSpace(reason) == "" {
		return fallback
	}
	return reason
}

// probeReason renders a probe error as a short, bounded reason string. Probe
// errors can carry an entire HTTP response body; a state reason lands in a
// table cell and an event payload, so it is truncated here rather than at every
// display site.
func probeReason(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "probe failed"
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	const maxReason = 200
	if len(msg) > maxReason {
		msg = msg[:maxReason-1] + "…"
	}
	return msg
}
