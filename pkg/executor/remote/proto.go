// Package remote implements the control-plane half of cloop's remote
// executor: a driver that satisfies executor.Executor by proxying frames to a
// cloop agent running on another machine.
//
// The defining constraint is direction. Edge devices, laptops, and build boxes
// generally sit behind NAT or a firewall that permits outbound connections and
// nothing inbound. A control plane cannot dial them. So the agent dials *out*,
// holds one long-lived WebSocket to the control plane, and the control plane
// pushes work down that already-established connection. Everything else in the
// protocol follows from that inversion:
//
//   - the control plane never knows an agent's address, only its identity;
//   - liveness is the agent's job (heartbeats), because the control plane has
//     no way to probe;
//   - reconnects are routine, not exceptional, so log streaming has to be
//     resumable rather than restartable.
//
// proto.go defines the wire format. It is deliberately a separate file from
// the transport: both the control plane (pkg/executor/remote) and the device
// (pkg/executor/agent) encode against these types, and a protocol change that
// only compiles on one side is the bug class this split is meant to prevent.
//
// # Versioning
//
// Every frame carries V. The control plane accepts any version in
// [MinProtocolVersion, ProtocolVersion] and tells the agent which version the
// session settled on in the Welcome frame. Agents older than the floor are
// rejected at hello with a legible error rather than failing later on a field
// they do not understand. Frames are JSON objects with an open payload, so
// adding a field is backward compatible; removing one or changing its meaning
// requires a version bump.
//
// # Authentication
//
// The connection is authenticated once, at the HTTP upgrade, by a bearer
// credential (see enroll.go). Individual frames are not separately signed:
// over an authenticated, ordered, TLS-protected channel a per-frame MAC keyed
// by the same secret proves nothing the handshake did not already prove, and
// pretending otherwise would be security theatre.
//
// What frames *are* subject to is authorization. The session binds the
// connection to exactly one agent identity, and every inbound frame is checked
// against it: an agent may only report on handles the control plane dispatched
// to that same agent. A frame naming another agent's handle is dropped and the
// connection closed, so a compromised agent cannot forge status for or steal
// logs from its peers.
package remote

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// Protocol version bounds. Bump ProtocolVersion for any incompatible change;
// raise MinProtocolVersion only when support for old agents is genuinely
// dropped, since doing so strands every deployed device until it is upgraded.
const (
	// ProtocolVersion is the newest version this build speaks.
	//
	// v2 added the revoke frame (see TypeRevoke): the control plane can take
	// one secret lease back from a task that is already running, rather than
	// waiting for the task to exit.
	//
	// v3 added StartPayload.WorkspaceCredential: the control plane hands the
	// device the short-lived material for one authenticated git fetch, so an
	// agent can materialise a private source tree before the harness starts
	// instead of running it against an empty directory.
	//
	// v4 added the result frames (see TypeResultChunk and TypeResult): the
	// device sends back the work product — a branch and commit SHA, and for a
	// device with no egress the git bundle itself — so a task's edits survive
	// the workload that made them.
	ProtocolVersion = 4
	// MinProtocolVersion is the oldest version this build still accepts.
	MinProtocolVersion = 1
	// MinRevocationVersion is the first version whose agents understand the
	// revoke frame. A v1 agent connects and runs work perfectly well; it just
	// cannot be trusted with material that must be revocable, so the hub
	// refuses to place such a workload there (see Executor.Start).
	//
	// This is a placement rule, not a connectivity rule. Refusing the *device*
	// would strand a fleet mid-upgrade over a capability most of its work does
	// not need; refusing the *workload that depends on it* fails exactly the
	// runs whose guarantee could not be met, and names the reason.
	MinRevocationVersion = 2
	// MinWorkspaceVersion is the first version whose agents provision a git
	// workspace before launching the harness.
	//
	// It is a placement rule for the same reason MinRevocationVersion is, with
	// a sharper edge: an older agent does not *reject* the credential field, it
	// ignores it. It would answer the start frame cheerfully, run the harness
	// in the empty directory it created, and produce a transcript that looks
	// like a working run operating on no code at all — which is the precise
	// failure the workspace contract exists to remove. So the hub refuses to
	// dispatch such a workload rather than trusting the device to complain.
	MinWorkspaceVersion = 3
	// MinWriteBackVersion is the first version whose agents return the work
	// product after a task finishes.
	//
	// A placement rule again, and for the sharpest version of the same reason.
	// An older agent ignores Spec.WriteBack exactly as it would ignore any
	// unknown field: it runs the harness, streams a transcript describing the
	// files it edited, reports success — and then the device's tree, the only
	// copy of that work, stays on the device. The run is indistinguishable from
	// one that delivered. So the hub refuses to dispatch a workload that asks
	// for a write-back to a device that cannot make one, rather than
	// discovering the loss after the work is gone.
	MinWriteBackVersion = 4
)

// SupportsRevocation reports whether an agent speaking this protocol version
// honours the revoke frame.
func SupportsRevocation(version int) bool { return version >= MinRevocationVersion }

// SupportsWorkspaceProvisioning reports whether an agent speaking this protocol
// version materialises a git workspace before starting the harness.
func SupportsWorkspaceProvisioning(version int) bool { return version >= MinWorkspaceVersion }

// SupportsWriteBack reports whether an agent speaking this protocol version
// returns the work product after a task finishes.
func SupportsWriteBack(version int) bool { return version >= MinWriteBackVersion }

// Timing constants. These are protocol-level agreements, not tunables: both
// sides must derive their timeouts from the same numbers or a healthy agent
// gets reaped as dead.
const (
	// HeartbeatInterval is the nominal gap between agent heartbeats. The
	// agent applies jitter (see JitterFraction) so that a fleet reconnecting
	// after a control-plane restart does not resynchronise into a thundering
	// herd that beats in lockstep forever after.
	HeartbeatInterval = 15 * time.Second

	// MissedHeartbeatLimit is how many consecutive intervals may elapse with
	// no traffic before the control plane declares the agent unreachable.
	// Three is chosen so a single dropped packet or a brief radio outage on
	// an LTE edge device does not evict a working executor.
	MissedHeartbeatLimit = 3

	// JitterFraction is the maximum proportional deviation applied to the
	// heartbeat interval and to reconnect backoff, matching the ±25% jitter
	// pkg/provider/retry.go uses for provider calls.
	JitterFraction = 0.25

	// WriteTimeout bounds a single frame write. A wedged TCP connection that
	// never drains must not block the control plane's dispatch goroutine
	// forever; exceeding this closes the session and the agent reconnects.
	WriteTimeout = 20 * time.Second
)

// HeartbeatDeadline is how long the control plane waits for traffic from an
// agent before marking it unreachable. It is derived from the protocol
// constants rather than written as a literal so the two can never drift.
func HeartbeatDeadline() time.Duration {
	return HeartbeatInterval * MissedHeartbeatLimit
}

// MaxFrameBytes bounds a single decoded frame. The dominant frame is a log
// chunk, which the agent already caps at MaxLogChunkBytes; the rest are small.
// This ceiling exists so a malicious or malfunctioning agent cannot make the
// control plane allocate unboundedly from a single read.
const MaxFrameBytes = 1 << 20 // 1 MiB

// MaxLogChunkBytes is the largest amount of workload output an agent puts in
// one log_chunk frame. Output beyond this is split across frames; it is never
// accumulated waiting for a newline, because a harness that prints a progress
// bar with no trailing newline still has to reach the live log panel.
const MaxLogChunkBytes = 32 << 10 // 32 KiB

// FrameType discriminates the payload. Values are strings rather than integers
// so that a packet capture or a debug log is readable without a decoder ring.
type FrameType string

const (
	// TypeHello (agent → control plane) opens a session: protocol version,
	// agent identity, advertised capabilities, and any handles the agent is
	// still running from a previous connection.
	TypeHello FrameType = "hello"
	// TypeWelcome (control plane → agent) accepts a session and states the
	// negotiated version and heartbeat interval.
	TypeWelcome FrameType = "welcome"

	// TypeHeartbeat (agent → control plane) proves liveness and reports
	// which handles the agent still considers running.
	TypeHeartbeat FrameType = "heartbeat"
	// TypeHeartbeatAck (control plane → agent) confirms receipt. An agent
	// that stops seeing acks knows the path is broken in the return
	// direction, which a send-only heartbeat could not detect.
	TypeHeartbeatAck FrameType = "heartbeat_ack"

	// TypeStart (control plane → agent) dispatches a workload.
	TypeStart FrameType = "start"
	// TypeStarted (agent → control plane) answers a start with the handle or
	// the reason it could not run.
	TypeStarted FrameType = "started"

	// TypeSignal (control plane → agent) asks the agent to signal a handle.
	TypeSignal FrameType = "signal"

	// TypeLogChunk (agent → control plane) carries workload output with the
	// byte offset it starts at, which is what makes resume possible.
	TypeLogChunk FrameType = "log_chunk"
	// TypeLogAck (control plane → agent) reports the highest contiguous byte
	// offset durably received, releasing the agent's retained buffer.
	TypeLogAck FrameType = "log_ack"

	// TypeStatusReq (control plane → agent) requests a status refresh.
	TypeStatusReq FrameType = "status_req"
	// TypeStatus (agent → control plane) reports a handle's state; sent both
	// on request and unsolicited when a workload terminates.
	TypeStatus FrameType = "status"

	// TypeResultChunk (agent → control plane) carries a slice of the git
	// bundle holding a finished task's work product, with the byte offset it
	// starts at. Added in protocol v4.
	//
	// It is a separate frame from TypeLogChunk rather than a stream flag on it
	// because the two have opposite requirements. Log output is lossy on
	// purpose — a subscriber that falls behind has chunks dropped so the
	// workload is never blocked — while a bundle with a hole in it is not a
	// smaller bundle, it is not a bundle. So this one is offset-checked,
	// size-capped and digest-verified end to end, and a gap fails the
	// write-back instead of being tolerated.
	TypeResultChunk FrameType = "result_chunk"
	// TypeResult (agent → control plane) closes a write-back: the branch, the
	// commit SHA, the bundle's length and digest, or the reason there is
	// nothing to send. Added in protocol v4.
	//
	// It is what the hub waits for — chunk delivery alone can never signal
	// completeness, since "no more chunks" and "the link dropped" look
	// identical from the receiving end.
	//
	// The frame order for a finished workload is fixed and load-bearing:
	// result chunks, then this frame, then the terminal TypeStatus. The status
	// frame is what closes the log stream, and executor.Run reads Status the
	// instant that stream closes — so a write-back arriving after it would be
	// recorded on a handle whose consumer had already returned. Sending it
	// before means the ordering is a property of the agent's control flow
	// rather than of a flag both sides have to agree about.
	TypeResult FrameType = "result"

	// TypeRevoke (control plane → agent) takes one secret lease back from a
	// running task. Added in protocol v2.
	TypeRevoke FrameType = "revoke"
	// TypeRevoked (agent → control plane) acknowledges a revoke, reporting
	// what was actually scrubbed. The ack is what lets the UI distinguish
	// "revoked" from "revoke pending" from "unreachable" — a fire-and-forget
	// revoke could only ever claim the first.
	TypeRevoked FrameType = "revoked"

	// TypeBye (either direction) announces an orderly shutdown, so the peer
	// can distinguish a planned disconnect from a dropped link.
	TypeBye FrameType = "bye"
	// TypeError (either direction) reports a request-scoped failure without
	// tearing down the session.
	TypeError FrameType = "error"
)

// Frame is the envelope for every message in both directions.
type Frame struct {
	// V is the protocol version of this frame.
	V int `json:"v"`
	// Type discriminates Payload.
	Type FrameType `json:"type"`
	// ID correlates a response with its request. Empty for unsolicited
	// frames such as log chunks and terminal status reports.
	ID string `json:"id,omitempty"`
	// Handle scopes the frame to one workload. Empty for session-level
	// frames (hello, welcome, heartbeat, bye).
	Handle string `json:"handle,omitempty"`
	// Payload is the type-specific body, decoded by the Decode* helpers.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// NewFrame builds a frame of the current protocol version with payload
// marshalled. A payload that cannot be marshalled is a programming error in
// the caller, so it is returned rather than silently dropped.
func NewFrame(t FrameType, id, handle string, payload any) (Frame, error) {
	return NewFrameAt(ProtocolVersion, t, id, handle, payload)
}

// NewFrameAt builds a frame stamped with an explicit protocol version.
//
// Once a session has negotiated a version, every frame it sends must carry
// that version and not this build's maximum. The receiver validates the
// envelope version against its own supported range, so a v2 control plane
// that stamped v2 onto a frame for a v1 agent would have every frame
// rejected as out of range — the negotiation would be decorative. Versions
// above the negotiated one are clamped rather than trusted, so a caller
// cannot accidentally widen a session past what the peer agreed to.
func NewFrameAt(version int, t FrameType, id, handle string, payload any) (Frame, error) {
	if version < MinProtocolVersion || version > ProtocolVersion {
		version = ProtocolVersion
	}
	f := Frame{V: version, Type: t, ID: id, Handle: handle}
	if payload == nil {
		return f, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Frame{}, fmt.Errorf("remote: marshal %s payload: %w", t, err)
	}
	f.Payload = raw
	return f, nil
}

// String renders a frame for a diagnostic, without its payload.
//
// The omission is the point. Since protocol v3 a start frame's payload carries
// the brokered credential for a workspace fetch (see
// StartPayload.WorkspaceCredential), so a single `%v` on a Frame in some future
// log line would write a live token into the control plane's log — and, on the
// device, into the agent's. What identifies a frame is its type, its
// correlation ID, its handle and its size; none of those is a secret, and
// nothing else belongs in a log line anyway.
func (f Frame) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "frame v%d %s", f.V, f.Type)
	if f.ID != "" {
		b.WriteString(" id=" + f.ID)
	}
	if f.Handle != "" {
		b.WriteString(" handle=" + f.Handle)
	}
	fmt.Fprintf(&b, " payload=%dB", len(f.Payload))
	return b.String()
}

// Validate checks envelope-level invariants that every receiver needs, so
// neither side has to re-derive them.
func (f Frame) Validate() error {
	if f.V < MinProtocolVersion || f.V > ProtocolVersion {
		return fmt.Errorf("%w: frame version %d not in [%d,%d]",
			ErrProtocol, f.V, MinProtocolVersion, ProtocolVersion)
	}
	if strings.TrimSpace(string(f.Type)) == "" {
		return fmt.Errorf("%w: frame has no type", ErrProtocol)
	}
	if len(f.Payload) > MaxFrameBytes {
		return fmt.Errorf("%w: payload %d bytes exceeds %d", ErrProtocol, len(f.Payload), MaxFrameBytes)
	}
	// Handle-scoped frames are meaningless without one; catching it here
	// turns a confusing downstream "unknown handle \"\"" into a protocol
	// error naming the frame that was malformed.
	switch f.Type {
	case TypeStart, TypeStarted, TypeSignal, TypeLogChunk, TypeLogAck, TypeStatus, TypeStatusReq:
		if strings.TrimSpace(f.Handle) == "" {
			return fmt.Errorf("%w: %s frame has no handle", ErrProtocol, f.Type)
		}
	}
	return nil
}

// decodePayload unmarshals f.Payload into dst.
func decodePayload(f Frame, dst any) error {
	if len(f.Payload) == 0 {
		return fmt.Errorf("%w: %s frame has empty payload", ErrProtocol, f.Type)
	}
	if err := json.Unmarshal(f.Payload, dst); err != nil {
		return fmt.Errorf("%w: decode %s payload: %v", ErrProtocol, f.Type, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

// HelloPayload opens a session.
type HelloPayload struct {
	// ProtocolVersion is the newest version the agent speaks. The control
	// plane replies with the version actually negotiated.
	ProtocolVersion int `json:"protocol_version"`
	// AgentID is the identity the credential was issued to. It is checked
	// against the authenticated identity, never trusted on its own — a frame
	// claiming to be another agent is a session-fatal error.
	AgentID string `json:"agent_id"`
	// Name is the operator-facing label chosen at enrollment.
	Name string `json:"name,omitempty"`
	// AgentVersion is the cloop build running on the device, for diagnosing
	// version-skew problems from the control plane.
	AgentVersion string `json:"agent_version,omitempty"`
	// Capabilities is what this device can run; the scheduler matches on it.
	Capabilities AgentCapabilities `json:"capabilities"`
	// Resume lists workloads still running from a previous connection,
	// with the offset each one's log stream reached. A reconnecting agent
	// uses this to hand the control plane back its in-flight work instead of
	// orphaning it.
	Resume []ResumeHandle `json:"resume,omitempty"`
}

// ResumeHandle re-attaches one surviving workload after a reconnect.
type ResumeHandle struct {
	HandleID  string    `json:"handle_id"`
	StartedAt time.Time `json:"started_at"`
	// LogOffset is the total number of output bytes the agent has produced
	// for this handle so far. The control plane compares it against what it
	// received and asks for the gap.
	LogOffset int64 `json:"log_offset"`
}

// AgentCapabilities describes the device, so the control plane can decide
// whether a workload belongs here. It is a superset of executor.Capabilities:
// the extra fields (CPU count, memory, container runtimes, harnesses) are what
// a scheduler needs and an in-process driver never had to report.
type AgentCapabilities struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// CPUs is the number of logical cores visible to the agent.
	CPUs int `json:"cpus,omitempty"`
	// MemoryMB is total system memory in megabytes; 0 when undetectable.
	MemoryMB int `json:"memory_mb,omitempty"`
	// ContainerRuntimes lists runtimes found on PATH ("docker", "podman"),
	// so the control plane can route container workloads to a device that
	// can actually honour them.
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
	// Harnesses lists agent CLIs found on PATH ("claude", "codex", ...). A
	// device without the harness a project needs should not be sent its work.
	Harnesses []string `json:"harnesses,omitempty"`
	// WorkDirRoot is the directory the agent confines every workload to.
	// Reported so an operator can see the sandbox boundary from the UI.
	WorkDirRoot string `json:"workdir_root,omitempty"`
	// WorkspaceProvisioning reports that this device can materialise a git
	// workspace itself — it has git on PATH and a build that knows how to use
	// it. Advertised rather than assumed because the failure it prevents is
	// silent: a device without git would answer the start frame and run the
	// harness against an empty tree.
	WorkspaceProvisioning bool `json:"workspace_provisioning,omitempty"`
	// WriteBack reports that this device can return a finished task's work
	// product — it has git and a build that knows how to commit and bundle.
	// Advertised for the same reason WorkspaceProvisioning is, and against the
	// same silent failure at the other end of the run: a device that cannot
	// write back does not say so, it just keeps the work.
	WriteBack bool `json:"write_back,omitempty"`
	// MaxConcurrent is the agent's ceiling on simultaneous workloads.
	MaxConcurrent int `json:"max_concurrent,omitempty"`
	// Labels are free-form selectors (region, site, gpu) set by the operator.
	Labels map[string]string `json:"labels,omitempty"`
}

// Executor projects the device's advertised capabilities onto the
// driver-independent executor.Capabilities the rest of cloop reasons about.
//
// Isolation is always IsolationRemote and SharesHostFilesystem always false:
// whatever the device does internally, from the control plane's perspective
// the workload is on another machine and Spec.WorkDir is not a path it can
// read. Claiming otherwise would let host-side tooling silently look in the
// wrong place.
func (c AgentCapabilities) Executor() executor.Capabilities {
	return executor.Capabilities{
		Isolation:              executor.IsolationRemote,
		SupportsStream:         true,
		SupportsSignal:         true,
		SupportsResourceLimits: false,
		SharesHostFilesystem:   false,
		NetworkEgress:          true,
		// A remote agent is the driver that most needs to provision: it shares
		// no filesystem with the control plane, so "bind" is not available to
		// it and an unprovisioned workspace is necessarily an empty one. The
		// hub narrows this further by protocol version — see
		// Executor.Capabilities — because a device that can clone is no use if
		// the session cannot deliver the credential.
		SupportsWorkspaceProvisioning: c.WorkspaceProvisioning,
		// The device advertised it; the hub narrows it further by protocol
		// version in Executor.Capabilities, because a device that can commit
		// and bundle is no use if the session cannot carry the result frames.
		SupportsWriteBack: c.WriteBack,
		MaxConcurrent:     c.MaxConcurrent,
		Platform:          c.OS,
		Arch:              c.Arch,
	}
}

// WelcomePayload accepts a session.
type WelcomePayload struct {
	// ProtocolVersion is the version the session settled on: the lower of
	// what the two sides support. Both must encode at this version.
	ProtocolVersion int `json:"protocol_version"`
	// ExecutorID is the control plane's ID for this agent, which is also the
	// agent's own identity and the registry key projects bind to. The three
	// are deliberately one value: an operator reading a project binding, an
	// executors-table row, and an agent's log should not have to correlate
	// three different identifiers for the same device.
	ExecutorID string `json:"executor_id"`

	// Credential is the long-lived per-agent credential, sent only on the
	// connection that redeemed an enrollment token. Redemption happens
	// inline on the connect rather than as a separate HTTP call so a device
	// needs exactly one reachable URL and one round trip to enroll.
	//
	// It is the single time this secret crosses the wire; the control plane
	// keeps only its hash. An agent that fails to persist it must re-enroll.
	Credential string `json:"credential,omitempty"`
	// HeartbeatSeconds is the interval the agent must beat at. Sent rather
	// than assumed so the control plane can slow down a large fleet without
	// redeploying every device.
	HeartbeatSeconds int `json:"heartbeat_seconds"`
	// ResumeAccepted lists the handles from Hello.Resume the control plane
	// still knows about. Anything the agent offered that is absent here has
	// been forgotten by the control plane and the agent should abandon it,
	// rather than stream output nobody is listening for.
	ResumeAccepted []ResumeAck `json:"resume_accepted,omitempty"`
}

// ResumeAck tells the agent where to restart one handle's log stream.
type ResumeAck struct {
	HandleID string `json:"handle_id"`
	// FromOffset is the first byte the control plane still needs. The agent
	// resends from here; anything below it was already delivered.
	FromOffset int64 `json:"from_offset"`
}

// HeartbeatPayload proves liveness.
type HeartbeatPayload struct {
	// Seq increments per heartbeat, letting the control plane log gaps.
	Seq uint64 `json:"seq"`
	// ActiveHandles is what the agent believes is still running. The control
	// plane reconciles: a handle it thinks is running but the agent has
	// forgotten is resolved as failed rather than left hanging forever.
	ActiveHandles []string `json:"active_handles,omitempty"`
	// LoadPercent is a coarse 0-100 busy signal for scheduling; -1 unknown.
	LoadPercent int `json:"load_percent,omitempty"`
}

// HeartbeatAckPayload confirms a heartbeat.
type HeartbeatAckPayload struct {
	Seq uint64 `json:"seq"`
	// ServerTime lets the agent log clock skew, which is the usual cause of
	// otherwise inexplicable credential-expiry failures on edge devices with
	// no RTC.
	ServerTime time.Time `json:"server_time"`
}

// StartPayload dispatches a workload. The Spec is the same struct host and
// container drivers consume; it was designed to be serializable for exactly
// this reason.
type StartPayload struct {
	Spec executor.Spec `json:"spec"`
	// HandleID is assigned by the control plane rather than the agent, so a
	// start whose response is lost to a disconnect is still addressable: the
	// control plane can ask about the handle it named, and the agent can
	// treat a repeated start for a known handle as a no-op instead of
	// launching the workload twice.
	HandleID string `json:"handle_id"`
	// WorkspaceCredential is the material for the single authenticated git
	// fetch Spec.Workspace needs, when it needs one. Added in protocol v3; nil
	// for a public repository or a workspace that needs no provisioning.
	//
	// It is a sibling of Spec rather than a field inside it, and that is a
	// hard rule rather than a stylistic one: pkg/executorstore persists the
	// dispatched Spec, the audit trail echoes it, and the reconcile loop
	// re-reads it after a control-plane restart. A token placed anywhere in a
	// Spec would be durable in three places within a second of being minted.
	// Here it is one field of one frame — written to a socket, never to a disk
	// — and the hub releases the lease as soon as the agent confirms the start.
	WorkspaceCredential *WorkspaceCredential `json:"workspace_credential,omitempty"`
}

// WorkspaceCredential is HTTP basic material for one git fetch.
//
// It deliberately carries no lease or grant identifier. The device neither
// renews nor releases the lease — the hub does both — so an identifier here
// would buy nothing and cost the ability to correlate a captured frame with a
// lease in the hub's audit trail.
type WorkspaceCredential struct {
	// Username is the HTTP basic user. Empty means the broker's GitHub
	// convention, "x-access-token", which executor.GitCredential applies.
	Username string `json:"username,omitempty"`
	// Password is the token. This is the secret; everything else in this
	// struct is bookkeeping.
	Password string `json:"password"`
	// ExpiresAt is the lease deadline, so a device can decline to begin a
	// fetch with a credential that will lapse mid-transfer rather than failing
	// halfway through with an opaque 401.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// String renders the credential without its secret, so a `%v` on a start
// payload — or on this struct directly — cannot write a live token into a log.
// Marshalling is unaffected: only fmt goes through here.
func (c WorkspaceCredential) String() string {
	user := strings.TrimSpace(c.Username)
	if user == "" {
		user = "x-access-token"
	}
	return "workspace credential for " + user + " [redacted]"
}

// GoString mirrors String so %#v cannot print the token either.
func (c WorkspaceCredential) GoString() string { return c.String() }

// GitCredential converts the wire form into the type the device's provisioner
// consumes. A payload with no credential yields the zero value, which
// executor.GitCredential.Empty reports as "this fetch is unauthenticated".
func (p StartPayload) GitCredential() executor.GitCredential {
	if p.WorkspaceCredential == nil {
		return executor.GitCredential{}
	}
	return executor.GitCredential{
		Username:  p.WorkspaceCredential.Username,
		Password:  p.WorkspaceCredential.Password,
		ExpiresAt: p.WorkspaceCredential.ExpiresAt,
	}
}

// StartedPayload answers a start.
type StartedPayload struct {
	HandleID  string    `json:"handle_id"`
	PID       int       `json:"pid,omitempty"`
	StartedAt time.Time `json:"started_at"`
	// Error is non-empty when the workload could not be started; the control
	// plane surfaces it verbatim so the operator sees the device's reason
	// (missing binary, workdir outside root) rather than a generic failure.
	Error string `json:"error,omitempty"`
}

// SignalPayload asks the agent to signal a handle.
type SignalPayload struct {
	Signal executor.Signal `json:"signal"`
}

// LogChunkPayload carries workload output.
type LogChunkPayload struct {
	Stream executor.StreamName `json:"stream"`
	// Offset is the byte position of Text's first byte within this handle's
	// output. Offsets, not sequence numbers, are the unit of acknowledgement:
	// after a reconnect the agent may re-chunk the same bytes differently, so
	// only a byte position identifies "where we got to" unambiguously.
	Offset int64  `json:"offset"`
	Text   string `json:"text"`
	// Time is the device's clock when the output was read.
	Time time.Time `json:"time"`
}

// End returns the offset just past this chunk, i.e. the next expected offset.
func (p LogChunkPayload) End() int64 { return p.Offset + int64(len(p.Text)) }

// LogAckPayload releases the agent's retained output buffer.
type LogAckPayload struct {
	// Offset is the highest contiguous byte offset the control plane has
	// accepted. The agent may discard everything below it.
	Offset int64 `json:"offset"`
}

// StatusReqPayload requests a status refresh. It carries no fields today;
// the handle is in the envelope. It exists as a named type so adding one
// later does not change the frame's shape.
type StatusReqPayload struct{}

// StatusPayload reports a handle's state.
type StatusPayload struct {
	Status executor.Status `json:"status"`
	// FinalOffset is the total output byte count when the workload reached a
	// terminal state. The control plane uses it to tell "the stream ended"
	// apart from "the connection dropped mid-stream": if it has fewer bytes
	// than FinalOffset it knows output is still outstanding.
	FinalOffset int64 `json:"final_offset,omitempty"`
}

// MaxResultChunkBytes bounds one bundle slice.
//
// Larger than a log chunk because a bundle is a bulk transfer with no latency
// requirement — nobody is watching it scroll — and well under MaxFrameBytes so
// base64's 4/3 expansion plus the envelope still fits with room to spare.
const MaxResultChunkBytes = 256 << 10 // 256 KiB

// ResultChunkPayload carries a slice of the work product's git bundle.
type ResultChunkPayload struct {
	// Offset is the byte position of Data's first byte within the bundle.
	// Unlike a log chunk's offset this is not merely an acknowledgement
	// token: the hub refuses a chunk that does not start exactly where the
	// previous one ended, because a bundle assembled out of order or with a
	// hole is corrupt in a way git will report as something else entirely.
	Offset int64 `json:"offset"`
	// Data is the raw slice. A []byte marshals to base64 in JSON, so no
	// encoding decision is made here.
	Data []byte `json:"data"`
}

// End returns the offset just past this chunk, i.e. the next expected offset.
func (p ResultChunkPayload) End() int64 { return p.Offset + int64(len(p.Data)) }

// ResultPayload closes a write-back.
type ResultPayload struct {
	// Result is the metadata: mode, branch, commit, digest, or the failure.
	// It never contains bundle bytes — those arrived as chunks — for the same
	// reason executor.Status does not: this struct is logged and persisted.
	Result executor.WriteBackResult `json:"result"`
}

// RevokeAction is what the agent should do about a workload still using the
// material being taken away.
type RevokeAction string

const (
	// RevokeScrub invalidates the material and lets the task keep running.
	// It will fail naturally the next time it reaches for the credential.
	//
	// This is the default because a long autonomous run is usually doing
	// many things, only one of which needed the revoked credential. Killing
	// it to revoke a kubeconfig it used an hour ago throws away hours of
	// work to close a window that scrubbing already closes.
	RevokeScrub RevokeAction = "scrub"
	// RevokeKill scrubs and then terminates every task holding the lease.
	//
	// It exists because scrubbing has one hard limit: a credential handed to
	// a process as an environment variable is in that process's own memory,
	// and no control plane can reach into another process's heap. When the
	// credential itself is compromised rather than merely over-granted,
	// killing the task is the only thing that actually stops its use.
	RevokeKill RevokeAction = "kill"
)

// Valid reports whether the action is one the agent knows.
func (a RevokeAction) Valid() bool {
	return a == RevokeScrub || a == RevokeKill
}

// RevokePayload takes one lease's material back from a running agent.
type RevokePayload struct {
	// LeaseID is the lease being revoked. Required.
	LeaseID string `json:"lease_id"`
	// GrantID narrows the revocation to one grant within the lease. Empty
	// revokes everything the lease delivered.
	GrantID string `json:"grant_id,omitempty"`
	// Reason is operator-facing text carried into the agent's log and the
	// audit trail, so "why did my run lose its token" has an answer on both
	// sides of the link.
	Reason string `json:"reason,omitempty"`
	// Action is scrub or kill. An empty or unknown action is treated as
	// scrub: the conservative reading of a frame from a possibly-newer
	// control plane is the one that does not destroy work.
	Action RevokeAction `json:"action,omitempty"`
}

// Effective returns the action to apply, defaulting an absent or unknown
// value to RevokeScrub.
func (p RevokePayload) Effective() RevokeAction {
	if p.Action.Valid() {
		return p.Action
	}
	return RevokeScrub
}

// RevokedPayload acknowledges a revoke and reports what was actually done.
//
// It is deliberately specific rather than a bare "ok". An operator revoking
// a kubeconfig needs to know whether the file is gone or whether the agent
// merely forgot about it, and an ack that cannot distinguish the two would
// let a UI claim a guarantee the system did not deliver.
type RevokedPayload struct {
	LeaseID string       `json:"lease_id"`
	GrantID string       `json:"grant_id,omitempty"`
	Action  RevokeAction `json:"action,omitempty"`
	// Known reports whether the agent was holding this lease at all. False
	// is a success, not a failure: the material is not here, which is the
	// end state the revoke asked for.
	Known bool `json:"known"`
	// EnvScrubbed names the variables whose values the agent dropped. Names
	// only — echoing a revoked credential back to the control plane would
	// be a fine way to write it into a log.
	EnvScrubbed []string `json:"env_scrubbed,omitempty"`
	// FilesRemoved counts credential files wiped from the device.
	FilesRemoved int `json:"files_removed,omitempty"`
	// EgressDropped reports that the lease's network allowlist entry is gone.
	EgressDropped bool `json:"egress_dropped,omitempty"`
	// Killed lists the handles terminated, for RevokeKill.
	Killed []string `json:"killed,omitempty"`
	// Error is non-empty when part of the scrub failed. The ack is still
	// sent: "I tried and this is what went wrong" is far more actionable
	// than silence, which the hub can only read as unreachable.
	Error string `json:"error,omitempty"`
}

// ByePayload announces an orderly shutdown.
type ByePayload struct {
	Reason string `json:"reason,omitempty"`
	// Reconnect tells the peer whether to come back. False means the
	// credential was revoked or the agent deregistered, so an agent that
	// obeys it stops hammering a control plane that will never accept it.
	Reconnect bool `json:"reconnect"`
}

// ErrorPayload reports a request-scoped failure.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes carried in ErrorPayload.Code. They are matched programmatically,
// so unlike Message they must stay stable.
const (
	// CodeUnauthorized: the credential is unknown, expired, or revoked.
	CodeUnauthorized = "unauthorized"
	// CodeVersionUnsupported: the peer's protocol version is out of range.
	CodeVersionUnsupported = "version_unsupported"
	// CodeUnknownHandle: the handle is not known to the receiver.
	CodeUnknownHandle = "unknown_handle"
	// CodeStartFailed: the workload could not be started.
	CodeStartFailed = "start_failed"
	// CodeForbiddenPath: the spec's workdir escapes the agent's root.
	CodeForbiddenPath = "forbidden_path"
	// CodeProtocol: the frame was malformed or out of sequence.
	CodeProtocol = "protocol"
	// CodeBusy: the agent is at its concurrency ceiling.
	CodeBusy = "busy"
	// CodeRevokeUnsupported: the agent's protocol version predates the
	// revoke frame. Distinct from CodeProtocol so the hub can report
	// "upgrade this device" rather than "the device is broken".
	CodeRevokeUnsupported = "revoke_unsupported"
	// CodeWriteBackFailed: the work product could not be returned. Distinct
	// from CodeStartFailed because the workload ran — the operator's problem
	// is a delivery one, and the transcript they are about to read describes
	// edits that did not arrive.
	CodeWriteBackFailed = "write_back_failed"
)

// Decode helpers. Each returns a typed payload or a wrapped ErrProtocol, so
// callers never hand-roll json.Unmarshal against a RawMessage.

func DecodeHello(f Frame) (HelloPayload, error) {
	var p HelloPayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeWelcome(f Frame) (WelcomePayload, error) {
	var p WelcomePayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeHeartbeat(f Frame) (HeartbeatPayload, error) {
	var p HeartbeatPayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeHeartbeatAck(f Frame) (HeartbeatAckPayload, error) {
	var p HeartbeatAckPayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeStart(f Frame) (StartPayload, error) {
	var p StartPayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeStarted(f Frame) (StartedPayload, error) {
	var p StartedPayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeSignal(f Frame) (SignalPayload, error) {
	var p SignalPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if !p.Signal.Valid() {
		return p, fmt.Errorf("%w: %v", executor.ErrInvalidSignal, p.Signal)
	}
	return p, nil
}

func DecodeLogChunk(f Frame) (LogChunkPayload, error) {
	var p LogChunkPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if p.Offset < 0 {
		return p, fmt.Errorf("%w: negative log offset %d", ErrProtocol, p.Offset)
	}
	if len(p.Text) > MaxLogChunkBytes {
		return p, fmt.Errorf("%w: log chunk %d bytes exceeds %d", ErrProtocol, len(p.Text), MaxLogChunkBytes)
	}
	return p, nil
}

// DecodeResultChunk decodes a bundle slice, refusing one that could not have
// come from a well-behaved agent.
//
// The bounds are enforced at decode rather than at assembly so a malformed
// frame is rejected before its contents are ever appended to anything. An empty
// chunk is refused too: it advances nothing and would let a peer hold a
// write-back open indefinitely at no cost to itself.
func DecodeResultChunk(f Frame) (ResultChunkPayload, error) {
	var p ResultChunkPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	switch {
	case p.Offset < 0:
		return p, fmt.Errorf("%w: negative result offset %d", ErrProtocol, p.Offset)
	case len(p.Data) == 0:
		return p, fmt.Errorf("%w: result chunk carries no data", ErrProtocol)
	case len(p.Data) > MaxResultChunkBytes:
		return p, fmt.Errorf("%w: result chunk %d bytes exceeds %d",
			ErrProtocol, len(p.Data), MaxResultChunkBytes)
	case p.End() > executor.MaxWriteBackBundleBytes:
		return p, fmt.Errorf("%w: result chunk ends at %d, past the %d-byte write-back ceiling",
			ErrProtocol, p.End(), executor.MaxWriteBackBundleBytes)
	}
	return p, nil
}

// DecodeResult decodes the frame that closes a write-back.
func DecodeResult(f Frame) (ResultPayload, error) {
	var p ResultPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if p.Result.BundleBytes < 0 {
		return p, fmt.Errorf("%w: negative bundle length %d", ErrProtocol, p.Result.BundleBytes)
	}
	if p.Result.BundleBytes > executor.MaxWriteBackBundleBytes {
		return p, fmt.Errorf("%w: reported bundle of %d bytes exceeds the %d-byte ceiling",
			ErrProtocol, p.Result.BundleBytes, executor.MaxWriteBackBundleBytes)
	}
	return p, nil
}

func DecodeLogAck(f Frame) (LogAckPayload, error) {
	var p LogAckPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if p.Offset < 0 {
		return p, fmt.Errorf("%w: negative ack offset %d", ErrProtocol, p.Offset)
	}
	return p, nil
}

func DecodeStatus(f Frame) (StatusPayload, error) {
	var p StatusPayload
	err := decodePayload(f, &p)
	return p, err
}

// DecodeRevoke decodes a revoke frame. A revoke with no lease ID is rejected
// rather than treated as "revoke everything": a wildcard revocation is not a
// thing this protocol offers, and silently inventing one from a malformed
// frame would let a truncated write take a whole device's credentials away.
func DecodeRevoke(f Frame) (RevokePayload, error) {
	var p RevokePayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.LeaseID) == "" {
		return p, fmt.Errorf("%w: revoke frame has no lease_id", ErrProtocol)
	}
	return p, nil
}

func DecodeRevoked(f Frame) (RevokedPayload, error) {
	var p RevokedPayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeBye(f Frame) (ByePayload, error) {
	var p ByePayload
	err := decodePayload(f, &p)
	return p, err
}

func DecodeError(f Frame) (ErrorPayload, error) {
	var p ErrorPayload
	err := decodePayload(f, &p)
	return p, err
}

// NegotiateVersion returns the version two peers should speak, or an error
// when their supported ranges do not overlap. Taking the lower of the two
// advertised maxima is what lets a newer control plane keep serving older
// agents through a staged fleet upgrade.
func NegotiateVersion(peerVersion int) (int, error) {
	if peerVersion < MinProtocolVersion {
		return 0, fmt.Errorf("%w: peer speaks v%d, minimum supported is v%d",
			ErrVersionUnsupported, peerVersion, MinProtocolVersion)
	}
	if peerVersion > ProtocolVersion {
		// The peer is newer. Ask it to drop to our maximum rather than
		// refusing: the whole point of an open payload is that a newer peer
		// can speak an older dialect.
		return ProtocolVersion, nil
	}
	return peerVersion, nil
}
