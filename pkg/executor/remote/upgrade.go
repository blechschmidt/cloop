package remote

// Hub side of the upgrade frame (Task 20331).
//
// The asymmetry worth naming up front: this is the one request in the protocol
// whose success cannot be observed on the connection that made it. A successful
// upgrade restarts the agent, which drops the session — so the best this code
// can ever return is "the device accepted and is trying", and the confirmation
// that it worked is the device reconnecting later with a different build in its
// hello. UpgradeOutcome is shaped to force callers to say which of those two
// they are reporting, because a UI that renders "accepted" as "upgraded" tells
// an operator the fleet is patched when it may not be.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/version"
)

// ErrUpgradeUnsupported reports that a device's agent predates the upgrade
// frame, and so can only be moved forward by hand on the device itself.
var ErrUpgradeUnsupported = errors.New("remote: agent does not support remote upgrade")

// ErrUpgradeTarget reports an upgrade target that is neither LatestVersion nor
// a release tag — most often an unreleased hub's own version, "dev+g8b418e2",
// which the Upgrade dialog used to prefill. A device installs published, signed
// releases and nothing else, so no such request could do what it says.
var ErrUpgradeTarget = errors.New("remote: upgrade target is not a published release")

// ErrUpgradeLowersProtocol reports an upgrade target whose binaries speak an
// older protocol than the device already does (Task 20371). The device's own
// check cannot see it — "dev+g47e68a9" cannot be ordered against "v0.0.4" — so
// it would install the release and lose everything the newer protocol carried.
// UpgradeRequest.Force overrides it, as it overrides a downgrade on the device.
var ErrUpgradeLowersProtocol = errors.New("remote: upgrade would lower the device's protocol")

// ErrUpgradeChannel reports an edge target for a device that does not follow
// the edge channel (Task 20376). The device would refuse it too; refusing here
// says so before a frame is sent, and says that only the device can change it.
var ErrUpgradeChannel = errors.New("remote: the device does not follow the edge channel")

// ErrUpgradeUnavailable reports a device that has said it cannot carry out an
// upgrade — no root helper for an unprivileged agent, or no cosign to verify
// with (Task 20376). Asking anyway would only produce an "accepted" that
// never completes.
var ErrUpgradeUnavailable = errors.New("remote: the device cannot carry out an upgrade")

// UpgradeRequest is what a caller asks for. It is the hub-side mirror of
// UpgradePayload, and it carries no more than that one does on purpose: a field
// here would have to reach the device somehow, and the set of things the device
// will accept is fixed by the security argument in upgradeproto.go.
type UpgradeRequest struct {
	// TargetVersion is a release tag, or LatestVersion / "" for the newest
	// published release. Empty is accepted here and normalised to
	// LatestVersion before it reaches the wire — the strictness in
	// DecodeUpgrade is about frames arriving from elsewhere, and imposing it
	// on in-process callers would only produce a redundant error. Anything
	// else is refused with ErrUpgradeTarget before a frame is sent.
	//
	// A caller that can resolve LatestVersion to a tag should, and send the
	// tag: the device then installs exactly the release that was checked. An
	// unresolved LatestVersion is judged as the newest published release this
	// hub knows of (version.NewestPublishedRelease).
	TargetVersion string
	// Force reinstalls an identical build, and permits a downgrade — including
	// one that lowers the device's protocol (ErrUpgradeLowersProtocol).
	Force bool
	// TargetProtocol is the protocol an edge target's manifest says it
	// speaks, resolved by the caller through GitHub (Task 20376). It never
	// reaches the wire — the device reads the signed manifest itself — and it
	// is what lets the hub keep its promise never to lower a device's
	// protocol for a build of main, which no release table describes. Zero
	// for an edge target refuses it unless Force.
	TargetProtocol int
	// TargetProtocolIssue says why TargetProtocol is unknown, for the refusal.
	TargetProtocolIssue string
	// SettleTimeout bounds the device's wait for its restarted service.
	SettleTimeout time.Duration
	// Reason is recorded in the device's log: who asked, and whether it was a
	// person or the auto-update policy.
	Reason string
}

// UpgradeOutcome reports what the device said when asked.
type UpgradeOutcome struct {
	// Accepted is true when the device has begun the upgrade. It is not a
	// success report — see the file comment.
	Accepted bool
	// AlreadyCurrent marks the benign refusal: the device is already running
	// the requested build and was not asked to force it.
	AlreadyCurrent bool
	// Reason carries the device's explanation for a refusal.
	Reason string
	// FromVersion and TargetVersion are the builds the device is moving
	// between, as the device resolved them. TargetVersion is what "latest"
	// turned out to mean.
	FromVersion   string
	TargetVersion string
}

// Summary renders the outcome as one line for a CLI or a toast.
//
// It exists so the three callers (CLI, REST handler, auto-update reconciler)
// cannot each invent their own phrasing for the accepted-is-not-succeeded
// distinction and drift apart on the only part of this feature an operator
// actually reads.
func (o UpgradeOutcome) Summary(device string) string {
	switch {
	case o.AlreadyCurrent:
		return fmt.Sprintf("%s is already running %s; nothing to do",
			device, displayVersion(o.FromVersion))
	case !o.Accepted:
		reason := strings.TrimSpace(o.Reason)
		if reason == "" {
			reason = "the device refused without giving a reason"
		}
		return fmt.Sprintf("%s refused the upgrade: %s", device, reason)
	default:
		return fmt.Sprintf("%s is upgrading from %s to %s. It will drop off the fleet while it "+
			"restarts; the upgrade is confirmed when it reconnects reporting the new build",
			device, displayVersion(o.FromVersion), displayVersion(o.TargetVersion))
	}
}

func displayVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "an unreported build"
	}
	return v
}

// RequestUpgrade asks the device behind this executor to move to a release.
//
// Three refusals are made before anything is sent, each naming the remedy that
// works rather than just the shortfall:
//
//   - A device too old to be upgraded remotely (ErrUpgradeUnsupported) has to
//     be moved once by hand, after which it can be driven from here forever.
//   - A target that is not a release tag (ErrUpgradeTarget) cannot be installed
//     this way at all: the device resolves a version through its own release
//     channel and verifies the archive's signature, so a dev build's name has
//     nothing behind it.
//   - Unless req.Force, a release whose binaries speak an older protocol than
//     the device does (ErrUpgradeLowersProtocol). This is the check the device
//     cannot make: a dev build cannot be ordered against a release, so its own
//     preflight would install v0.0.4 over a v14 agent and drop it to v13.
func (e *Executor) RequestUpgrade(ctx context.Context, req UpgradeRequest) (UpgradeOutcome, error) {
	sess := e.currentSession()
	if sess == nil {
		return UpgradeOutcome{}, fmt.Errorf("%w: %s (%s) has no live session, so it cannot be "+
			"asked to upgrade; it will be offered the upgrade again when it reconnects",
			ErrAgentUnreachable, e.id, e.name)
	}
	if v := sess.Version(); !SupportsUpgrade(v) {
		return UpgradeOutcome{}, fmt.Errorf("%w: %s", ErrUpgradeUnsupported, executor.NeedsProtocol(
			e.subject(), v, MinUpgradeVersion, "to upgrade it from here", ""))
	}

	target := strings.TrimSpace(req.TargetVersion)
	if target == "" || strings.EqualFold(target, LatestVersion) {
		target = LatestVersion
	}
	have := max(sess.AgentProtocol(), sess.Version())
	caps := sess.Capabilities()
	// A device that says it cannot carry out an upgrade — an unprivileged
	// agent with no root helper, or no cosign — is refused before anything is
	// sent. Absent from agents older than the field, which say nothing.
	if !caps.RemoteUpgrade && strings.TrimSpace(caps.RemoteUpgradeIssue) != "" {
		return UpgradeOutcome{}, fmt.Errorf("%w: %s (%s) says: %s", ErrUpgradeUnavailable, e.id, e.name,
			caps.RemoteUpgradeIssue)
	}
	switch {
	case version.IsEdgeTarget(target):
		commit, err := version.ParseEdgeTarget(target)
		if err != nil {
			return UpgradeOutcome{}, fmt.Errorf("%w: %v", ErrUpgradeTarget, err)
		}
		target = version.EdgeTarget(commit)
		if caps.UpdateChannel != executor.ChannelEdge {
			return UpgradeOutcome{}, fmt.Errorf("%w: %s", ErrUpgradeChannel,
				executor.EdgeChannelRefusal(e.subject(), target))
		}
		if !req.Force {
			if req.TargetProtocol <= 0 {
				return UpgradeOutcome{}, fmt.Errorf("%w: %s Ask with force to install it anyway.",
					ErrUpgradeLowersProtocol, executor.EdgeProtocolUnknown(e.subject(), target, req.TargetProtocolIssue))
			}
			if have > 0 && req.TargetProtocol < have {
				return UpgradeOutcome{}, fmt.Errorf("%w: %s Ask with force to install it anyway.",
					ErrUpgradeLowersProtocol, executor.ProtocolDrop(e.subject(), have, target, req.TargetProtocol))
			}
		}
	case target != LatestVersion && !version.IsRelease(target):
		return UpgradeOutcome{}, fmt.Errorf("%w: %s", ErrUpgradeTarget,
			executor.UnpublishedTarget(e.subject(), target, have))
	case !req.Force:
		if err := checkProtocolDrop(e.subject(), have, target); err != nil {
			return UpgradeOutcome{}, err
		}
	}

	payload := UpgradePayload{
		TargetVersion: target,
		Force:         req.Force,
		Reason:        strings.TrimSpace(req.Reason),
	}
	if req.SettleTimeout > 0 {
		// Rounded up rather than truncated: a sub-second timeout would floor to
		// zero, which the agent reads as "use the default" — so a caller asking
		// for an aggressive settle would silently get the slow one.
		payload.SettleSeconds = int((req.SettleTimeout + time.Second - 1) / time.Second)
	}

	frame, err := sess.frame(TypeUpgrade, newCorrelationID(), "", payload)
	if err != nil {
		return UpgradeOutcome{}, fmt.Errorf("remote: build upgrade frame for %s: %w", e.id, err)
	}
	reply, err := sess.request(ctx, frame, TypeUpgrading)
	if err != nil {
		return UpgradeOutcome{}, fmt.Errorf("remote: ask %s (%s) to upgrade: %w", e.id, e.name, err)
	}
	ack, err := DecodeUpgrading(reply)
	if err != nil {
		return UpgradeOutcome{}, fmt.Errorf("remote: decode upgrade ack from %s: %w", e.id, err)
	}
	return UpgradeOutcome{
		Accepted:       ack.Accepted,
		AlreadyCurrent: ack.AlreadyCurrent,
		Reason:         ack.Reason,
		FromVersion:    ack.FromVersion,
		TargetVersion:  ack.TargetVersion,
	}, nil
}

// checkProtocolDrop refuses target when its binaries are known to speak an
// older protocol than have, the device's. LatestVersion is judged as the newest
// published release this hub knows of, and the refusal says so: a release
// published since this hub was built may well not lower anything, and Force is
// how an operator who knows that proceeds.
func checkProtocolDrop(subject string, have int, target string) error {
	if have <= 0 {
		return nil
	}
	judged, latest := target, false
	var hi int
	switch hub := executor.HubBuild(); {
	case target == LatestVersion:
		newest, ok := version.NewestPublishedRelease()
		if !ok {
			return nil
		}
		judged, hi, latest = newest.Tag, newest.Protocol, true
	case version.IsRelease(hub) && sameRelease(target, hub):
		// This hub's own release speaks exactly what this binary does,
		// whether or not the table has caught up with it.
		hi = ProtocolVersion
	default:
		_, hi = version.ReleaseProtocol(target)
	}
	// hi == 0: a release newer than anything this hub knows of; no bound.
	if hi == 0 || hi >= have {
		return nil
	}
	msg := executor.ProtocolDrop(subject, have, judged, hi)
	if latest {
		msg = fmt.Sprintf("%q could not be looked up, so it was judged as %s, the newest published release "+
			"this hub knows of: %s", LatestVersion, judged, msg)
	}
	return fmt.Errorf("%w: %s Ask with force to install it anyway.", ErrUpgradeLowersProtocol, msg)
}

// sameRelease reports whether a and b are the same release.
func sameRelease(a, b string) bool {
	cmp, ok := version.Compare(a, b)
	return ok && cmp == 0
}
