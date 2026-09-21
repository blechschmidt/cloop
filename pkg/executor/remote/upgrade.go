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
)

// ErrUpgradeUnsupported reports that a device's agent predates the upgrade
// frame, and so can only be moved forward by hand on the device itself.
var ErrUpgradeUnsupported = errors.New("remote: agent does not support remote upgrade")

// UpgradeRequest is what a caller asks for. It is the hub-side mirror of
// UpgradePayload, and it carries no more than that one does on purpose: a field
// here would have to reach the device somehow, and the set of things the device
// will accept is fixed by the security argument in upgradeproto.go.
type UpgradeRequest struct {
	// TargetVersion is a release tag, or LatestVersion / "" for the newest
	// published release. Empty is accepted here and normalised to
	// LatestVersion before it reaches the wire — the strictness in
	// DecodeUpgrade is about frames arriving from elsewhere, and imposing it
	// on in-process callers would only produce a redundant error.
	TargetVersion string
	// Force reinstalls an identical build, and permits a downgrade.
	Force bool
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
// The version gate is checked before anything is sent, and its error names the
// manual remedy rather than just the shortfall: a device too old to be upgraded
// remotely is exactly the device whose operator most needs to be told that the
// one-time fix is a local `cloop executor agent install --upgrade`, after which
// it can be driven from here forever.
func (e *Executor) RequestUpgrade(ctx context.Context, req UpgradeRequest) (UpgradeOutcome, error) {
	sess := e.currentSession()
	if sess == nil {
		return UpgradeOutcome{}, fmt.Errorf("%w: %s (%s) has no live session, so it cannot be "+
			"asked to upgrade; it will be offered the upgrade again when it reconnects",
			ErrAgentUnreachable, e.id, e.name)
	}
	if v := sess.Version(); !SupportsUpgrade(v) {
		return UpgradeOutcome{}, fmt.Errorf("%w: %s (%s) speaks protocol v%d, and remote upgrade "+
			"needs v%d. Upgrade it once on the device with `sudo cloop executor agent install "+
			"--upgrade`; from that build onwards it can be upgraded from here",
			ErrUpgradeUnsupported, e.id, e.name, v, MinUpgradeVersion)
	}

	target := strings.TrimSpace(req.TargetVersion)
	if target == "" {
		target = LatestVersion
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
