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
//
// Everything here is a pure function of its inputs, so the rules can be tested
// exhaustively without a device, a network or a clock.
package autoupdate

import (
	"fmt"
	"sort"
	"strings"

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
	// Online is whether there is a live session to send the request on.
	Online bool
	// Busy is whether the device is running work right now.
	Busy bool
	// AdminHeld is whether an operator has cordoned or drained it.
	AdminHeld bool
	// Upgrading is whether this device has already been asked and has not yet
	// come back. It is what keeps MaxInFlight meaningful across sweeps.
	Upgrading bool
}

// Verdict is what the planner decided about one device.
type Verdict struct {
	Device Device
	// Upgrade is whether to send the request now.
	Upgrade bool
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
func Plan(p Policy, hubVersion string, devices []Device) []Verdict {
	eff := p.Resolve(hubVersion)

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
			v.Reason = fmt.Sprintf("agent speaks protocol v%d, which predates remote upgrade; "+
				"upgrade it once on the device", d.ProtocolVersion)
		default:
			reason, ok := compare(d.Version, eff.TargetVersion)
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
			v.Upgrade = true
			v.Reason = fmt.Sprintf("upgrading from %s to %s", displayVersion(d.Version),
				eff.TargetVersion)
			inFlight++
		}
		out = append(out, v)
	}
	return out
}

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
// Duplicated as a constant rather than imported because pkg/executor/remote
// imports a good deal of transport machinery this package has no use for, and
// a planner that can be tested without a websocket stack is worth one integer.
// TestMinRemoteUpgradeProtocolMatchesTheWireConstant keeps the two honest.
const minRemoteUpgradeProtocol = 11

func supportsRemoteUpgrade(v int) bool { return v >= minRemoteUpgradeProtocol }

func displayVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "an unreported build"
	}
	return v
}
