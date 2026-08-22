package remote

import "errors"

// Sentinel errors for the remote executor. Callers match with errors.Is;
// implementations wrap these with %w and add detail.
//
// The distinction that matters most operationally is between
// ErrAgentUnreachable and everything else. A control plane that hangs waiting
// for a NAT'd device that went offline is indistinguishable, from the UI, from
// a workload that is simply slow — so Start fails fast with this specific
// error and the caller can say "edge-1 is offline" instead of spinning.
var (
	// ErrProtocol: a frame was malformed, out of range, or arrived in a state
	// where it makes no sense.
	ErrProtocol = errors.New("remote: protocol error")

	// ErrVersionUnsupported: the peer's protocol version does not overlap
	// with this build's supported range.
	ErrVersionUnsupported = errors.New("remote: unsupported protocol version")

	// ErrAgentUnreachable: no live session for this agent. Start returns it
	// immediately rather than queueing work for a device that may never come
	// back.
	ErrAgentUnreachable = errors.New("remote: agent is unreachable")

	// ErrAgentBusy: the agent is at its advertised concurrency ceiling.
	ErrAgentBusy = errors.New("remote: agent is at capacity")

	// ErrSessionClosed: the session ended while a request was in flight.
	ErrSessionClosed = errors.New("remote: session closed")

	// ErrTokenInvalid: an enrollment token is malformed, unknown, or its MAC
	// does not verify.
	ErrTokenInvalid = errors.New("remote: invalid enrollment token")

	// ErrTokenExpired: the enrollment token's TTL elapsed before redemption.
	ErrTokenExpired = errors.New("remote: enrollment token expired")

	// ErrTokenAlreadyUsed: the enrollment token was already redeemed. This is
	// the replay case, and it is deliberately distinct from ErrTokenInvalid
	// so an operator can tell "someone captured and replayed this token"
	// apart from "the device typo'd it".
	ErrTokenAlreadyUsed = errors.New("remote: enrollment token already redeemed")

	// ErrRevoked: the enrollment token or agent credential was revoked.
	ErrRevoked = errors.New("remote: credential revoked")

	// ErrCredentialInvalid: an agent credential is malformed or unknown.
	ErrCredentialInvalid = errors.New("remote: invalid agent credential")

	// ErrPathOutsideRoot: a spec's workdir escapes the agent's configured
	// root. Enforced on the device, because the control plane cannot know the
	// device's filesystem, and re-checked as a hard boundary rather than a
	// convention.
	ErrPathOutsideRoot = errors.New("remote: workdir escapes agent root")

	// ErrAgentNotFound: no agent with the requested ID is enrolled.
	ErrAgentNotFound = errors.New("remote: agent not enrolled")

	// ErrRevocationUnsupported: the agent speaks a protocol version older
	// than MinRevocationVersion, so material handed to it could never be
	// taken back mid-run. Placing a workload that carries revocable secrets
	// fails with this rather than proceeding without the guarantee.
	ErrRevocationUnsupported = errors.New("remote: agent does not support lease revocation")

	// ErrWorkspaceUnsupported: the agent speaks a protocol version older than
	// MinWorkspaceVersion, so it would ignore the workspace credential and run
	// the harness against an empty tree. Placing a workload whose source has to
	// be cloned fails with this rather than producing a run that looks fine and
	// operated on no code.
	ErrWorkspaceUnsupported = errors.New("remote: agent does not support workspace provisioning")

	// ErrLeaseNotHeld: the agent was asked to revoke a lease it is not
	// holding. It is reported, not raised — "the material is not here" is
	// the end state a revocation wants — so callers treat it as success
	// with a note rather than as something to retry.
	ErrLeaseNotHeld = errors.New("remote: agent is not holding this lease")
)
