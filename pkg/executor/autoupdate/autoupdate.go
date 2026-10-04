// Package autoupdate decides which devices in the fleet should be rolled
// forward, and when (Task 20331).
//
// The decision is separated from the doing, and kept free of I/O, because the
// interesting part of an auto-updater is not the upgrade — pkg/executor/remote
// and pkg/executor/install already do that — but the restraint. An updater that
// simply asks every stale device to upgrade the moment it notices is not a
// feature, it is a scheduled outage: the fleet is what runs the work, and every
// device is unavailable for the minute it takes to restart.
//
// So Plan enforces four rules, and each of them exists because the naive
// version of this feature breaks something real:
//
//  1. Never interrupt running work. An upgrade restarts the agent, which kills
//     whatever it is executing. A task that has been running for forty minutes
//     is worth more than being current by an hour.
//
//  2. Never take the whole fleet down at once. Upgrades are rolled out a few
//     devices at a time, so a release that turns out to be bad strands a
//     bounded number of machines — and so the fleet retains capacity to keep
//     scheduling while the rest roll.
//
//  3. Never act on a device the operator has taken out of service by hand. A
//     cordon is a statement that a human is dealing with this machine, and
//     rebooting it underneath them is exactly the wrong response.
//
//  4. Never "upgrade" a device to something that is not an upgrade. Already
//     current, newer than the target, or running an unparseable build: all
//     three are left alone rather than forced, because forcing is how an
//     automatic system turns one bad assumption into a fleet-wide rollback.
//     Two more shapes of the same rule came from a hub running an unreleased
//     build (Task 20371): a target that is not a release at all — the default
//     target on such a hub is its own "dev+g…" version, which no device can
//     download — and a release whose binaries speak an older protocol than the
//     device already does. The second is judged by protocol before versions
//     are compared, because a device on a dev build cannot be ordered against
//     a release, and "cannot order" is not the reason it must be left alone.
//
// Everything here is a pure function of its inputs, so the rules can be tested
// exhaustively without a device, a network or a clock.
package autoupdate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/version"
)

// DefaultMaxInFlight is how many devices are upgraded at once when a policy
// does not say.
//
// One. The conservative choice is right for the common fleet, which is small
// enough that "a few at a time" and "all of them" are the same thing — and an
// operator with three hundred edge devices who needs this to go faster is in a
// much better position to choose the number than this default is.
const DefaultMaxInFlight = 1

// Policy is the operator's standing instruction for the fleet.
type Policy struct {
	// Enabled turns automatic upgrades on. Off by default, and deliberately:
	// a hub that silently reboots edge devices because it was installed with a
	// helpful default is a hub nobody trusts with hardware.
	Enabled bool `json:"enabled"`

	// TargetVersion is the release every device should converge on. Empty
	// means the control plane's own build, which is the sane default — the
	// hub and its agents are two halves of one protocol, and "match the hub"
	// is the invariant an operator actually wants.
	//
	// A pinned tag is honoured as written, including when it is older than the
	// hub: staged rollouts and rollbacks both need the fleet to sit on a
	// version the control plane is not running.
	TargetVersion string `json:"target_version,omitempty"`

	// MaxInFlight bounds concurrent upgrades. Zero uses DefaultMaxInFlight.
	MaxInFlight int `json:"max_in_flight,omitempty"`
}

// Resolve fills in the defaults, returning the policy as it will actually be
// applied. Callers render this rather than the stored value so the UI shows the
// effective setting rather than a blank that means something.
func (p Policy) Resolve(hubVersion string) Policy {
	out := p
	if strings.TrimSpace(out.TargetVersion) == "" {
		out.TargetVersion = strings.TrimSpace(hubVersion)
	}
	if out.MaxInFlight <= 0 {
		out.MaxInFlight = DefaultMaxInFlight
	}
	return out
}

// Hub is what the planner needs to know about the control plane: the build it
// runs, which is the default target, and the protocol it speaks.
type Hub struct {
	Version  string
	Protocol int
	// Edge is what CI published of the hub's own build (Task 20376): nil when
	// the hub runs a release or a build no edge build can match, else whether
	// "edge:<commit>" exists and the protocol its manifest claims. It is what
	// "match the hub" means for a device on the edge channel.
	Edge *executor.EdgeBuild
}

// Device is what the planner needs to know about one executor. It is a flat
// snapshot rather than a live handle so that planning cannot race the fleet it
// is planning over.
type Device struct {
	ID   string
	Name string
	// Version is the build the device reports. Empty or the legacy placeholder
	// means it has not told us, which Plan treats as "leave alone".
	Version string
	// ProtocolVersion is the negotiated session version, used to tell a device
	// that can be upgraded remotely from one that must be done by hand.
	ProtocolVersion int
	// AgentProtocol is the protocol the agent advertised at hello — more than
	// ProtocolVersion when the device is newer than the hub. A target speaking
	// less than the larger of the two would move the device backwards.
	AgentProtocol int
	// Online is whether there is a live session to send the request on.
	Online bool
	// Busy is whether the device is running work right now.
	Busy bool
	// AdminHeld is whether an operator has cordoned or drained it.
	AdminHeld bool
	// Upgrading is whether this device has already been asked and has not yet
	// come back. It is what keeps MaxInFlight meaningful across sweeps.
	Upgrading bool
	// Channel is the update channel the device reports: "edge" lets it follow
	// the hub's own build, anything else is releases only (Task 20376).
	Channel string
}

// Verdict is what the planner decided about one device.
type Verdict struct {
	Device Device
	// Upgrade is whether to send the request now.
	Upgrade bool
	// Target is what to ask this device for when Upgrade is set. Per device,
	// because "match the hub" is the hub's edge build for a device on the edge
	// channel and is refused outright for one that is not.
	Target string
	// Reason explains the decision either way, in the operator's terms. It is
	// shown in the UI beside the device, so a fleet that is not converging can
	// be understood without reading logs.
	Reason string
}

// Plan decides what to do about each device, in a stable order.
//
// It returns a verdict for every device rather than only the ones to act on,
// because "why is that machine still on the old build" is the question this
// feature generates and a list of the devices it skipped is the answer.
func Plan(p Policy, hub Hub, devices []Device) []Verdict {
	eff := p.Resolve(hub.Version)

	// Sorted so a sweep is deterministic: with MaxInFlight of one, an unsorted
	// input would upgrade an arbitrary device each pass, and a fleet where two
	// devices kept taking the slot from each other would converge slowly for
	// reasons no one could see.
	ordered := append([]Device(nil), devices...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	// Devices already mid-upgrade hold slots. Counted before any decision so
	// the budget spans sweeps rather than resetting each time — otherwise
	// "one at a time" would mean "one more each tick", which is all of them.
	inFlight := 0
	for _, d := range ordered {
		if d.Upgrading {
			inFlight++
		}
	}

	out := make([]Verdict, 0, len(ordered))
	for _, d := range ordered {
		v := Verdict{Device: d}
		switch {
		case !eff.Enabled:
			v.Reason = "automatic upgrades are off for this fleet"
		case d.Upgrading:
			v.Reason = "already upgrading"
		case !d.Online:
			v.Reason = "offline; it will be considered when it reconnects"
		case d.AdminHeld:
			// Rule 3. Phrased as a deferral rather than a refusal because
			// nothing is wrong: the operator will uncordon it eventually.
			v.Reason = "cordoned or draining; an operator is holding this device"
		case d.Busy:
			// Rule 1.
			v.Reason = "running work; upgrading would kill the task"
		case !supportsRemoteUpgrade(d.ProtocolVersion):
			v.Reason = executor.NeedsProtocol("this device's agent", d.ProtocolVersion,
				minRemoteUpgradeProtocol, "to upgrade it remotely", "")
		default:
			target, reason, refused := deviceTarget(d, eff.TargetVersion, hub)
			if refused {
				v.Reason = reason
				break
			}
			reason, ok := compare(d.Version, target)
			if !ok {
				v.Reason = reason
				break
			}
			if inFlight >= eff.MaxInFlight {
				// Rule 2. The device is eligible and is deliberately being
				// made to wait, which is worth saying — an operator watching a
				// stale fleet needs to know it is rolling, not stuck.
				v.Reason = fmt.Sprintf("eligible, waiting for a slot (%d of %d upgrades in "+
					"flight)", inFlight, eff.MaxInFlight)
				break
			}
			v.Upgrade, v.Target = true, target
			v.Reason = fmt.Sprintf("upgrading from %s to %s", displayVersion(d.Version), displayTarget(target, hub))
			inFlight++
		}
		out = append(out, v)
	}
	return out
}

// deviceTarget resolves the policy's target for one device (Task 20376).
//
// On a hub running an unreleased build, "match the hub" — the empty target,
// or the hub's own version written out — names a build no release carries.
// For a device on the edge channel it is the hub's edge build, offered once CI
// has published it and only if it does not lower the device's protocol. For
// any other device it stays refused, now with the step that would change
// that. A pinned edge:<commit> other than the hub's own is refused: the hub can
// judge the protocol of its own build, not of an arbitrary commit.
func deviceTarget(d Device, target string, hub Hub) (string, string, bool) {
	target = strings.TrimSpace(target)
	have := max(d.AgentProtocol, d.ProtocolVersion)
	const subject = "this device's agent"
	edgeDevice := d.Channel == executor.ChannelEdge
	e := hub.Edge
	hubsOwn := e != nil && target != "" &&
		(target == strings.TrimSpace(hub.Version) || version.SameCommit(target, hub.Version) ||
			(version.IsEdgeTarget(target) && e.Target != "" && sameEdgeCommit(target, e.Target)))

	switch {
	case hubsOwn && edgeDevice:
		if !e.Published || e.Target == "" {
			why := strings.TrimSuffix(strings.TrimSpace(e.WhyNot), ".")
			if why == "" {
				why = "CI has not published it"
			}
			return "", "The hub's build (" + e.Short + ") is not offered yet: " + why + ".", true
		}
		if have > 0 && e.Protocol < have {
			return "", executor.ProtocolDrop(subject, have, e.Target, e.Protocol), true
		}
		return e.Target, "", false
	case version.IsEdgeTarget(target) && !edgeDevice:
		return "", executor.EdgeChannelRefusal(subject, target), true
	case version.IsEdgeTarget(target):
		return "", fmt.Sprintf("%s is not this hub's own build, and the auto-update policy follows only that one "+
			"on the edge channel; leave the target empty to follow the hub, or pin a published release.", target), true
	}
	if reason, refused := refuseTarget(d, target, hub); refused {
		if hubsOwn && !strings.Contains(reason, executor.EdgeOptIn) {
			if hint := executor.StableChannelHint(); hint != "" {
				reason += " " + hint
			}
		}
		return "", reason, true
	}
	return target, "", false
}

// sameEdgeCommit reports whether two edge targets name one commit.
func sameEdgeCommit(a, b string) bool {
	ca, errA := version.ParseEdgeTarget(a)
	cb, errB := version.ParseEdgeTarget(b)
	return errA == nil && errB == nil && version.SameCommit(ca, cb)
}

// displayTarget names a target in a verdict: the hub's edge build by its
// label, anything else as written.
func displayTarget(target string, hub Hub) string {
	if hub.Edge != nil && version.IsEdgeTarget(target) && sameEdgeCommit(target, hub.Edge.Target) {
		return hub.Edge.Label()
	}
	return target
}

// refuseTarget is rule 4's protocol half: a target the device cannot be sent at
// all, or one that would lower the protocol it speaks. It runs before compare,
// because the device it matters most for runs a dev build, which compare can
// only call unorderable — true, and not the reason to leave it alone.
func refuseTarget(d Device, target string, hub Hub) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false // compare explains a missing target
	}
	have := max(d.AgentProtocol, d.ProtocolVersion)
	const subject = "this device's agent"
	if strings.EqualFold(target, latestTarget) {
		// The device resolves "latest" itself; this hub can only judge it as
		// the newest release it knows of, and says so.
		newest, ok := version.NewestPublishedRelease()
		if !ok || have <= 0 || newest.Protocol >= have {
			return "", false
		}
		return fmt.Sprintf("the target %q is judged as %s, the newest published release this hub knows of: %s",
			latestTarget, newest.Tag, executor.ProtocolDrop(subject, have, newest.Tag, newest.Protocol)), true
	}
	if !version.IsRelease(target) {
		return executor.UnpublishedTarget("this device", target, have) +
			" Or pin a published release as the auto-update policy's target.", true
	}
	hi := targetProtocolBound(target, hub)
	if have > 0 && hi > 0 && hi < have {
		return executor.ProtocolDrop(subject, have, target, hi), true
	}
	return "", false
}

// targetProtocolBound is the newest protocol target can speak: exactly the
// hub's own when target is the hub's own release, else what the published
// release table bounds it at (0 for unknown).
func targetProtocolBound(target string, hub Hub) int {
	if hub.Protocol > 0 && version.IsRelease(hub.Version) {
		if cmp, ok := version.Compare(target, hub.Version); ok && cmp == 0 {
			return hub.Protocol
		}
	}
	_, hi := version.ReleaseProtocol(target)
	return hi
}

// latestTarget mirrors remote.LatestVersion, for the reason minRemoteUpgradeProtocol
// mirrors remote.MinUpgradeVersion.
const latestTarget = "latest"

// compare decides whether moving from current to target is an upgrade worth
// making, and explains itself when it is not.
//
// Rule 4 lives here. Every "no" is a case where forcing would be worse than
// waiting: a device that is already current has nothing to gain from a restart,
// one that is ahead would be silently downgraded, and one whose build cannot be
// parsed is a device we would be guessing about.
func compare(current, target string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "no target version: the control plane reports no build of its own, so there is " +
			"nothing to converge on. Pin a version in the auto-update policy", false
	}
	current = strings.TrimSpace(current)
	if current == "" || current == version.LegacyAgentVersion {
		return "this device does not report a build version, so there is no way to tell whether " +
			"an upgrade would move it forward", false
	}
	// The hub's edge build: current when the device already runs that commit,
	// and otherwise the move — "follow the hub" is what the channel means, and
	// deviceTarget has already ruled out losing protocol.
	if commit, err := version.ParseEdgeTarget(target); err == nil {
		if version.SameCommit(current, commit) {
			return "already on the hub's build", false
		}
		return "", true
	}
	cmp, ok := version.Compare(current, target)
	if !ok {
		return fmt.Sprintf("cannot order %s against %s, so an automatic upgrade would be a "+
			"guess", displayVersion(current), target), false
	}
	switch {
	case cmp == 0:
		return "already on " + target, false
	case cmp > 0:
		return fmt.Sprintf("running %s, which is newer than the target %s; automatic downgrade "+
			"is not done without an explicit request", current, target), false
	}
	return "", true
}

// supportsRemoteUpgrade mirrors remote.SupportsUpgrade.
//
// Not imported from pkg/executor/remote because that package imports a good
// deal of transport machinery this one has no use for, and a planner that can
// be tested without a websocket stack is worth one integer. pkg/executor keeps
// the same mirror for the advice it writes, so this is that one;
// TestMinRemoteUpgradeProtocolMatchesTheWireConstant keeps both honest.
const minRemoteUpgradeProtocol = executor.MinRemoteUpgradeVersion

func supportsRemoteUpgrade(v int) bool { return v >= minRemoteUpgradeProtocol }

func displayVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "an unreported build"
	}
	return v
}
