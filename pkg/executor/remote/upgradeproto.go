package remote

// The upgrade frame: asking a device to roll its own binary forward
// (Task 20331).
//
// Every other hub→agent frame in this protocol asks the device to do something
// *with* a workload. This one asks it to replace the binary that is running the
// agent itself, which makes it the only frame in the protocol that is a remote
// code execution primitive by design. The whole of its wire shape is therefore
// decided by one question: what can an attacker who can send this frame do?
//
// The answer has to be "ask for a version, and nothing else". That constrains
// the payload in two ways that are easy to get wrong, and both are load-bearing:
//
//  1. There is no source URL, and there must never be one. A `Source string`
//     field would read as a harmless convenience — the hub already knows where
//     releases live, why make every device rediscover it — and it would hand
//     anyone who can forge or inject one frame the ability to install an
//     arbitrary binary as root on every device in the fleet. So the frame names
//     a *version*, and the device resolves that to bytes through its own
//     configured release channel. A hub that has been taken over can ask a
//     device to move to a different published release; it cannot ask it to run
//     something that was never published.
//
//  2. There is no skip-verification field, and there must never be one. The
//     device verifies the binary's Sigstore provenance against a pinned GitHub
//     Actions identity before installing it (pkg/provenance), and that check is
//     what makes (1) true — without it, "resolve the version yourself" only
//     moves the attacker from supplying bytes to supplying a redirect. An
//     operator at an air-gapped site can still pass --insecure-skip-verify to
//     the local `cloop executor agent install --upgrade`, because that is a
//     decision made by someone standing at the device. It is deliberately not a
//     decision the hub can make on their behalf.
//
// TestUpgradePayloadHasNoRemoteCodeExecutionFields in upgradeproto_test.go
// enforces both of these against the struct by reflection, so a later change
// that adds either field fails the build rather than quietly widening the blast
// radius of a hub compromise.
//
// The acknowledgement is "accepted", not "succeeded", and that is not a
// shortcut. A successful upgrade restarts the agent, which tears down the very
// session the request arrived on — so the frame that reports the outcome could
// never be delivered on this link. The device answers with whether it is going
// to try, and the real confirmation is that it reconnects reporting a new build.
// See Executor.RequestUpgrade for how the hub presents that distinction.

import (
	"fmt"
	"strings"
)

const (
	// TypeUpgrade (control plane → agent) asks the agent to replace its own
	// binary with a published release and restart. Added in protocol v11.
	TypeUpgrade FrameType = "upgrade"
	// TypeUpgrading (agent → control plane) answers an upgrade with whether
	// the device is going to attempt it, and why not when it is not.
	//
	// It is emphatically not a completion report: the upgrade restarts the
	// agent and kills this session. See the file comment.
	TypeUpgrading FrameType = "upgrading"
)

// MinUpgradeVersion is the first protocol version whose agents understand the
// upgrade frame.
//
// This gate is stricter than the additive ones above it, and deliberately so. A
// pre-v10 agent that receives a project seed ignores an unknown *field* and
// still runs the workload, so the hub can degrade. An agent that predates this
// version does not know the *frame*, and there is no degraded upgrade: it will
// answer with a protocol error, keep running the build it has, and the operator
// who clicked Upgrade would be looking at a device that reports no error and
// never changes. So the hub refuses before sending, with a message naming the
// only remedy that exists for a device this old — one manual upgrade, on the
// device, to a build new enough to be upgraded remotely from then on.
const MinUpgradeVersion = 11

// SupportsUpgrade reports whether an agent speaking this protocol version can
// be asked to upgrade itself.
func SupportsUpgrade(version int) bool { return version >= MinUpgradeVersion }

// LatestVersion is the TargetVersion meaning "whatever the newest published
// release is", resolved by the device rather than by the hub.
//
// Spelled as a constant rather than as the empty string so that the wire is
// self-describing: a packet capture showing target_version:"latest" says what
// was asked for, where an absent field would leave a reader guessing between
// "latest", "unset" and "the sender forgot".
const LatestVersion = "latest"

// UpgradePayload is the body of TypeUpgrade.
//
// Read the file comment before adding a field. The two fields this struct must
// never gain are a binary source and a verification switch.
type UpgradePayload struct {
	// TargetVersion is the release tag to move to, e.g. "v0.1.4", or
	// LatestVersion to let the device resolve the newest published release.
	//
	// A tag, not a URL: the device turns this into bytes through its own
	// release channel, and verifies the result against a pinned signing
	// identity. That is the whole security model of this frame.
	TargetVersion string `json:"target_version"`

	// Force installs the target even when the device is already running it,
	// and permits moving backwards to an older release.
	//
	// Downgrade is included because the operational reason to reach for this
	// feature at all is often a bad release: the fleet is on a build that
	// misbehaves, and the fix is to put it back on the previous one before
	// diagnosing. Refusing that would leave the rollback path as "SSH to every
	// device", which is the problem this frame exists to remove.
	Force bool `json:"force,omitempty"`

	// SettleSeconds bounds how long the device waits for its restarted service
	// to come back before deciding the new binary is bad and rolling back to
	// the previous one. Zero uses the installer's default.
	SettleSeconds int `json:"settle_seconds,omitempty"`

	// Reason is free text recorded in the device's log, distinguishing an
	// operator who clicked Upgrade from the auto-update policy acting on its
	// own. It is diagnostic only and never affects what is installed.
	Reason string `json:"reason,omitempty"`
}

// UpgradingPayload is the body of TypeUpgrading: whether the device intends to
// attempt the upgrade, and what it is moving between.
type UpgradingPayload struct {
	// Accepted reports that the device has validated the request and is about
	// to begin. It does not report success; see the file comment.
	Accepted bool `json:"accepted"`

	// Reason explains a refusal. Always set when Accepted is false, because a
	// bare "no" leaves an operator with nothing to act on — the common
	// refusals (not installed as a service, already current, no such release)
	// have entirely different fixes.
	Reason string `json:"reason,omitempty"`

	// AlreadyCurrent distinguishes the benign refusal from the rest, so the
	// hub can report "nothing to do" rather than surfacing it as a failure.
	AlreadyCurrent bool `json:"already_current,omitempty"`

	// FromVersion is the build the device is running now, and TargetVersion
	// the one it resolved the request to — which is the newest release when
	// the hub asked for LatestVersion, and is the field that tells the
	// operator what "latest" turned out to mean.
	FromVersion   string `json:"from_version,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
}

// DecodeUpgrade decodes an upgrade frame.
//
// An absent target is rejected rather than defaulted to LatestVersion. The two
// are not the same request: "move to the newest release" is a decision, and a
// frame that lost its target field in transit or was written by a caller that
// forgot to set it is a malformed request. Defaulting would turn the second
// into the first and silently roll a fleet forward on a truncated write.
func DecodeUpgrade(f Frame) (UpgradePayload, error) {
	var p UpgradePayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	p.TargetVersion = strings.TrimSpace(p.TargetVersion)
	if p.TargetVersion == "" {
		return p, fmt.Errorf("%w: upgrade frame has no target_version", ErrProtocol)
	}
	if p.SettleSeconds < 0 {
		return p, fmt.Errorf("%w: upgrade frame has a negative settle_seconds (%d)",
			ErrProtocol, p.SettleSeconds)
	}
	return p, nil
}

// DecodeUpgrading decodes an upgrading acknowledgement.
func DecodeUpgrading(f Frame) (UpgradingPayload, error) {
	var p UpgradingPayload
	err := decodePayload(f, &p)
	return p, err
}
