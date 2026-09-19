package remote

import (
	"errors"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
)

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
	//
	// It wraps executor.ErrRevocationUnsupported so a caller that has no
	// reason to know which driver refused — the run panel reporting why a
	// task would not start — can match the one sentinel and still get this
	// driver's far more specific message.
	ErrRevocationUnsupported = fmt.Errorf("remote: agent does not support lease revocation: %w",
		executor.ErrRevocationUnsupported)

	// ErrWorkspaceUnsupported: the agent speaks a protocol version older than
	// MinWorkspaceVersion, so it would ignore the workspace credential and run
	// the harness against an empty tree. Placing a workload whose source has to
	// be cloned fails with this rather than producing a run that looks fine and
	// operated on no code.
	ErrWorkspaceUnsupported = errors.New("remote: agent does not support workspace provisioning")

	// ErrSecretFilesUnsupported: the agent speaks a protocol version older than
	// MinSecretFilesVersion, so it would ignore the credential files and run the
	// harness with an environment naming paths nothing ever created. Placing a
	// workload whose secret lease delivers files fails with this rather than
	// producing a run whose git authentication fails for a reason nothing names.
	ErrSecretFilesUnsupported = errors.New("remote: agent does not support secret credential files")

	// ErrProjectSeedUnsupported: the agent speaks a protocol version older than
	// MinProjectSeedVersion, so it would ignore the project state and run the
	// harness in a clone that holds a source repository but no cloop project.
	// Placing such a workload fails with this rather than producing a run that
	// exits with "no cloop project found" — a message that names the project
	// rather than the device that dropped it.
	ErrProjectSeedUnsupported = errors.New("remote: agent does not support project seeding")

	// ErrSandboxModeUnsupported: the agent speaks a protocol version older than
	// MinSandboxModeVersion, so it would ignore StartPayload.Sandbox and run the
	// payload as a host process — whatever containment an admin configured for
	// this executor. Placing a container-mode workload fails with this rather
	// than running it on the host and reporting success, which is the one
	// failure mode of this feature that nothing downstream could detect.
	ErrSandboxModeUnsupported = errors.New("remote: agent does not support sandbox mode selection")

	// ErrSandboxModeUnavailable: the control plane could not read this
	// executor's configured sandbox mode, so it does not know whether the
	// payload is supposed to be contained. Dispatch fails rather than
	// proceeding: the alternative is running on the host because a database was
	// briefly busy, which is a containment decision made by a storage fault.
	ErrSandboxModeUnavailable = errors.New("remote: executor sandbox configuration is unreadable")

	// ErrVirtualizationUnavailable: this executor is configured to run payloads
	// under a Kata runtime, but the device reported that it cannot open
	// /dev/kvm. Dispatch fails here rather than on the device, where the same
	// condition costs ~50s and surfaces as a QMP socket timeout that names
	// neither KVM nor the executor.
	//
	// Distinct from ErrSandboxModeUnsupported because the remedy is: that one
	// is fixed by upgrading the agent, this one usually cannot be fixed on the
	// device at all — nested virtualization is the hosting hypervisor's
	// decision — so the useful advice is to choose a boundary the machine can
	// actually provide.
	ErrVirtualizationUnavailable = errors.New("remote: device cannot start a virtual machine")

	// ErrLeaseNotHeld: the agent was asked to revoke a lease it is not
	// holding. It is reported, not raised — "the material is not here" is
	// the end state a revocation wants — so callers treat it as success
	// with a note rather than as something to retry.
	ErrLeaseNotHeld = errors.New("remote: agent is not holding this lease")
)
