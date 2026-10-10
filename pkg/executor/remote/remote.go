package remote

// remote.go is the control-plane driver: an executor.Executor whose workloads
// run on someone else's machine.
//
// The central structural decision is what outlives what. A *Executor is
// durable — it exists as long as the agent is enrolled, whether or not the
// device is currently connected. A *Session is transient, one per successful
// dial. Handles belong to the Executor, not the Session, because a workload
// keeps running on the device across a dropped link; binding handle state to
// the connection would orphan live work every time an LTE modem re-registered.
//
// That split is also what makes resume expressible: on reconnect the agent
// offers the handles it still has, the Executor recognises them, and streaming
// picks up at the byte offset the control plane had actually received.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

// StatusUnreachable is the executors-table status written when an agent misses
// MissedHeartbeatLimit consecutive heartbeats. It is a distinct value from
// "offline" (a clean bye) so an operator can tell a device that shut down
// tidily apart from one that fell off the network.
const StatusUnreachable = "unreachable"

// Executor status values mirrored into statedb.
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
)

// handleState is the control plane's view of one workload on the device.
type handleState struct {
	id        string
	startedAt time.Time
	bus       *logbus.Bus
	// virtualID is the virtual executor this workload was dispatched through,
	// empty for a dispatch to the device itself (Task 20345). Written once at
	// start, before the handle is published, and read-only thereafter.
	virtualID string

	mu     sync.Mutex
	status executor.Status
	// receivedOffset is the highest contiguous output byte offset accepted
	// from the agent. Acknowledgement is in bytes, not chunks: after a
	// reconnect the agent may re-chunk the same bytes differently, so only a
	// byte position identifies "where we got to" unambiguously.
	receivedOffset int64
	// gapped records that a chunk arrived starting beyond receivedOffset,
	// meaning output was permanently lost (the agent's retained buffer had
	// already evicted it). Surfaced so a consumer knows its log is partial
	// rather than silently showing a truncated run.
	gapped bool
	closed bool
	// closedAt is when this hub saw the handle reach its final state, in the
	// control plane's clock: what an uncollected result's retention is
	// measured from (Task 20399). Zero while the handle is open.
	closedAt time.Time
	// returns is what this workload may send back — a bundle up to its
	// spec's cap, a result frame, a project-state document — fixed at
	// dispatch and persisted with the handle's row so a rehydrated handle
	// keeps it (Task 20399). Written before the handle is published and
	// read-only thereafter; see returns.go.
	returns resultAllowance
	// writeBack is the in-flight assembly of this workload's work product.
	// Nil until the device sends its first result frame; see writeback.go.
	writeBack *writeBackState
	// projectResult is what the device sent back of a seeded run, held until
	// the hub collects it. Nil until a project_result frame arrives; see
	// projectresult.go.
	projectResult *projectResultState
	// releaseWorkspace gives back the workspace credential's lease, parked
	// here when a push write-back will present that credential again once
	// the workload finishes; run once, when the handle closes.
	releaseWorkspace func()
	// heldWorkspace names the parked credential, for the run's owner row
	// (Task 20390). Set and cleared with releaseWorkspace.
	heldWorkspace executor.HeldWorkspaceCredential
	// abandoned marks a workload the control plane gave up after failing its
	// session over to another executor (Task 20396), and abandonReason says
	// why. An abandoned handle is terminal here, and a resume offer for it is
	// answered with "terminate" — see Abandon.
	abandoned     bool
	abandonReason string
}

// takeWorkspaceRelease returns the parked workspace release, at most once.
func (h *handleState) takeWorkspaceRelease() func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.releaseWorkspace
	h.releaseWorkspace = nil
	h.heldWorkspace = executor.HeldWorkspaceCredential{}
	return r
}

// HeldWorkspaceCredential implements executor.WorkspaceCredentialHolder: the
// workspace credential parked on handleID for its push write-back, if any.
func (e *Executor) HeldWorkspaceCredential(handleID string) (executor.HeldWorkspaceCredential, bool) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return executor.HeldWorkspaceCredential{}, false
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.releaseWorkspace == nil || hs.heldWorkspace.LeaseID == "" {
		return executor.HeldWorkspaceCredential{}, false
	}
	return hs.heldWorkspace, true
}

// finishWorkspaceRelease runs the parked workspace release, if any.
func (h *handleState) finishWorkspaceRelease() {
	if h == nil {
		return
	}
	if r := h.takeWorkspaceRelease(); r != nil {
		r()
	}
}

// snapshotStatus returns the last known status under lock.
func (h *handleState) snapshotStatus() executor.Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

// Options configures a remote executor.
type Options struct {
	// ID is the registry key. It is the agent ID, so a project bound to an
	// agent stays bound across reconnects and control-plane restarts.
	ID string
	// Name is the operator-facing label from enrollment.
	Name string
	// Capabilities is what the device advertised at hello.
	Capabilities AgentCapabilities
	// OnStatusChange, when set, is called whenever the executor transitions
	// between online/offline/unreachable. The hub uses it to mirror status
	// into statedb without this package importing storage.
	OnStatusChange func(executorID, status string, at time.Time)
	// OnRevokeAck, when set, is called when an agent acknowledges a lease
	// revocation. It is a callback for the same reason OnStatusChange is:
	// the audit trail lives in storage and this package must not depend on
	// it. Replayed revocations report through here too, which is the only
	// way an operator learns that a queued revocation finally landed.
	OnRevokeAck func(executorID, leaseID string, ack RevokedPayload)
	// Workspace leases the credential a git workspace fetch needs, at dispatch
	// time and for the length of one start.
	//
	// It is an interface (executor.WorkspaceCredentialSource) rather than the
	// broker itself so this package stays free of the hub's secret store —
	// pkg/executor/agent imports pkg/executor/remote, and an edge binary must
	// not carry a secret database because the control plane happens to have
	// one. Nil means no credential can be leased: a workload naming a grant is
	// refused with the same typed error the broker would have raised, rather
	// than dispatched to fetch a private repository anonymously.
	Workspace executor.WorkspaceCredentialSource
	// HandleStore persists handle identity so a hub that restarts still knows
	// which workloads it dispatched to this device (Task 20191). See
	// rehydrate.go.
	//
	// Nil is the pre-Task-20191 behaviour and remains supported: the driver
	// dispatches, streams, signals and reconciles exactly as it did. What it
	// loses is the one thing only a durable row can supply — recognising a
	// reconnecting agent's resume offer after a restart. Without it every offer
	// is refused, and a refusal now stops the workload, so a storeless hub
	// trades a leaked process for a lost run.
	//
	// It is a field rather than a constructor argument because a remote
	// executor is built by the hub from an enrollment record, early and
	// synchronously, while the state database that backs the store is opened
	// later; AttachHandleStore installs it once that has happened.
	HandleStore executor.HandleStore
	// Sandbox resolves this executor's admin-configured sandbox settings —
	// whether payloads run on the device's host or in a container on it, and
	// under which engine, runtime and image (Task 20307).
	//
	// A function rather than a value, consulted on every Start rather than read
	// once here, because the whole point is that an admin can change it from the
	// UI and have the next task honour it. A value captured at construction
	// would go stale the moment the panel was used and would only refresh when
	// the device happened to reconnect.
	//
	// It returns an error rather than just a value, and the error is fatal to
	// the dispatch. That is deliberate: "I could not read whether this executor
	// is supposed to be contained" must not resolve to "run it on the host".
	// See statedb.SandboxSettingsFor, which is the implementation the hub
	// installs, for the full argument.
	//
	// Nil means no configuration source — the pre-Task-20307 behaviour, and what
	// a hub with no control-plane database gets. Payloads run as they did.
	Sandbox func() (executor.SandboxSettings, error)
	// AutoInstallHarness reports whether this hub may ask a device to install
	// a missing harness from that harness's official installer (Task 20336).
	//
	// A function for the same reason Sandbox is one: it is an admin setting
	// that must take effect on the next dispatch rather than at the next
	// reconnect.
	//
	// Nil means enabled, and that default is the feature. The behaviour it
	// replaces is a refusal telling an operator to go and install something by
	// hand on a machine the fleet exists to stop hand-administering. Sites that
	// do not want a vendor script run on a critical host turn it off here, and
	// get the Task 20332 refusal back unchanged.
	AutoInstallHarness func() bool
	// ResultBudget bounds the returned work — write-back bundles and project
	// state documents — this executor may have the hub hold in memory while
	// it waits to be collected (Task 20399). Nil draws on the process-wide
	// DefaultResultBudget, which is what a hub wants: the limit that keeps
	// it alive is one for the whole process. Tests inject their own.
	ResultBudget *ResultBudget
	// Now overrides the clock for tests.
	Now func() time.Time
}

// autoInstallHarness reports whether a missing harness may be installed.
func (o Options) autoInstallHarness() bool {
	return o.AutoInstallHarness == nil || o.AutoInstallHarness()
}

// sandboxSettings resolves the executor's configured sandbox settings.
//
// Normalizing here rather than trusting the source keeps one rule in one place:
// a row written by an older binary, or by a future one with a field this build
// does not know, is reduced to what this build can actually honour before
// anything is decided from it.
func (o Options) sandboxSettings() (executor.SandboxSettings, error) {
	if o.Sandbox == nil {
		return executor.SandboxSettings{}, nil
	}
	s, err := o.Sandbox()
	if err != nil {
		return executor.SandboxSettings{}, err
	}
	return s.Normalize(), nil
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Executor proxies executor.Executor calls to a remote agent.
type Executor struct {
	id   string
	name string
	opts Options

	mu      sync.RWMutex
	caps    AgentCapabilities
	session *Session
	handles map[string]*handleState
	status  string
	// leases maps a secret lease ID to the handles started with its material,
	// so a revocation knows whether this executor is holding the credential at
	// all and which tasks to kill.
	//
	// The shared executor.LeaseIndex rather than a map of this driver's own:
	// it carries the one rule that must be identical across backends — what an
	// *unrecorded* binding on a rehydrated handle means — and a private copy
	// here would be the fourth place that rule could drift. Not guarded by mu;
	// the index locks itself.
	leases *executor.LeaseIndex
	// store persists handle identity across control-plane restarts. It is a
	// field of its own rather than a read of opts.HandleStore because
	// AttachHandleStore may install it after construction, while the session
	// read loop is already calling applyStatus — and opts is otherwise treated
	// as immutable. Guarded by mu; read through handleStore().
	store executor.HandleStore

	// revocations is the log of leases this executor has been told to give
	// back, retained across disconnects so they can be replayed. See
	// revoke.go.
	revocations *executor.RevocationLog

	// budget counts the returned work this executor's handles hold. It
	// belongs to the executor, never to a session: the bytes outlive the
	// link they arrived on, and a budget that came back with each reconnect
	// would be no budget at all. See resultbudget.go.
	budget *ResultBudget
}

// NewExecutor builds a remote executor for an enrolled agent. It starts
// disconnected: Start fails with ErrAgentUnreachable until the device dials in
// and a session attaches.
//
// When Options.HandleStore is set it also rehydrates: every workload this
// executor ID dispatched before the process restarted is put back into the
// handle map, so the agent's reconnect finds a control plane that still
// recognises its work. That happens here, synchronously, because the agent may
// dial in the moment the hub's listener opens and a resume offer that races
// rehydration would be refused — which now means killed.
func NewExecutor(opts Options) (*Executor, error) {
	if opts.ID == "" {
		return nil, fmt.Errorf("%w: remote executor ID is blank", executor.ErrInvalidSpec)
	}
	budget := opts.ResultBudget
	if budget == nil {
		budget = DefaultResultBudget()
	}
	e := &Executor{
		id:          opts.ID,
		name:        opts.Name,
		opts:        opts,
		caps:        opts.Capabilities,
		handles:     make(map[string]*handleState),
		leases:      executor.NewLeaseIndex(),
		revocations: executor.NewRevocationLog(),
		status:      StatusOffline,
		store:       opts.HandleStore,
		budget:      budget,
	}
	e.rehydrate()
	return e, nil
}

// ID implements executor.Executor.
func (e *Executor) ID() string { return e.id }

// Kind implements executor.Executor.
func (e *Executor) Kind() string { return executor.KindRemoteAgent }

// Name reports the operator-facing label.
func (e *Executor) Name() string { return e.name }

// subject names this device's agent at the start of a refusal: "agent
// agent-1 (edge-1)", the ID an operator can search for and the name they know
// it by.
func (e *Executor) subject() string { return fmt.Sprintf("agent %s (%s)", e.id, e.name) }

// AgentCapabilities reports what the device advertised, including the fields
// (CPU count, memory, container runtimes, harnesses) that the driver-agnostic
// executor.Capabilities has no room for.
func (e *Executor) AgentCapabilities() AgentCapabilities {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.caps
}

// Capabilities implements executor.Executor.
//
// Workspace provisioning is reported as the *intersection* of what the device
// advertised and what the live session can actually carry. A device with git on
// PATH is no use if the connection cannot hand it a credential, and claiming
// otherwise would let placement route a private-repository run to an agent that
// would silently start the harness in an empty directory.
//
// When there is no session the last advertised value stands, which is
// deliberate and matches Hub.Restore's reasoning: an enrolled device that is
// merely offline should place and then fail with the truthful
// ErrAgentUnreachable, not vanish from placement behind "no executor can
// provision a workspace".
func (e *Executor) Capabilities() executor.Capabilities {
	sandbox, sandboxErr := e.opts.sandboxSettings()
	return e.capabilitiesFor(sandbox, sandboxErr)
}

// capabilitiesFor is Capabilities with the sandbox settings supplied by the
// caller: the device's own for a direct dispatch, a virtual executor's for one
// of its sub-executors (Task 20345).
func (e *Executor) capabilitiesFor(sandbox executor.SandboxSettings, sandboxErr error) executor.Capabilities {
	caps := e.AgentCapabilities().Executor()
	// What the admin configured, which for two of these is the only thing that
	// can answer the question at all. Whether a payload on this device sits
	// behind a hypervisor or a userspace kernel is not a property of the device
	// — it is a property of the runtime the hub tells the device to use, so
	// before this configuration existed both were necessarily false and a Kata
	// edge device could not be described as one.
	//
	// A read error leaves the capabilities unenriched rather than failing, and
	// that is safe in exactly this direction: Capabilities has no error return
	// and is called to render a card and to filter placement, so the fallback
	// must be the claim that grants the least. Unenriched means "not
	// virtualized, not kernel-isolated" — a placement that requires either is
	// refused, which is the conservative outcome. The dispatch path does not
	// share this fallback: see Start, where the same read failing is fatal.
	if sandboxErr == nil {
		caps.Virtualized = sandbox.IsVirtualized()
		caps.KernelIsolated = sandbox.IsKernelIsolated()
		if sandbox.RunsProjectImages() {
			// Only now are these true. The image and the setup: block are the
			// container driver's abilities, and until the device was told to run
			// one there was nothing on the far side that could honour them — a
			// project naming its own image got the host's environment instead,
			// silently.
			caps.SupportsImageOverride = true
			caps.SupportsSandboxBuild = true
			caps.SupportsResourceLimits = true
			// And the workspace's disk limit, which the device's container
			// driver samples (Task 20405) — from protocol v20; see below.
			caps.DiskEnforcement = executor.DiskEnforcementSampled
		}
	}
	if sess := e.currentSession(); sess != nil {
		// Container mode needs a v8 agent to be honoured at all, and placement
		// has to see that: an executor that advertises containment the link
		// cannot deliver would be chosen for work that Start then refuses. The
		// refusal is correct — better than running on the host — but a
		// capability that is false of the pair should not be true here.
		if !SupportsSandboxMode(sess.Version()) {
			caps.Virtualized = false
			caps.KernelIsolated = false
		}
		// The configured runtime name says what the admin *asked for*; this says
		// what the device can actually deliver. They diverge on any machine
		// without nested virtualization — a cloud VM whose hypervisor does not
		// expose vmx/svm is the common case — and when they do, the name is the
		// one that is wrong. Believing it advertises a hypervisor boundary that
		// cannot exist, which is the false-positive direction virtualization.go
		// singles out as the dangerous one.
		//
		// Only a device that was actually asked can contradict the name: below
		// v9 the field is absent, not false, and demoting on a zero value would
		// strand every Kata device already in the field.
		//
		// KernelIsolated follows only when the isolation *was* the VM. Kata
		// serves the workload's syscalls from a guest kernel, so a hypervisor
		// it cannot start takes that property with it; gVisor's Sentry is a
		// userspace kernel that never opens /dev/kvm, so a runsc sandbox keeps
		// it on a device with no virtualization at all. Clearing both
		// unconditionally would refuse placements this machine can honour.
		if SupportsVirtualizationProbe(sess.Version()) && !e.AgentCapabilities().Virtualization {
			caps.Virtualized = false
			if sandboxErr == nil && !executor.IsUserspaceKernelRuntime(sandbox.Runtime) {
				caps.KernelIsolated = false
			}
		}
		// The device may be able to do it; the session may not be able to
		// carry it. Both narrowings are applied here rather than in
		// AgentCapabilities.Executor because that method has no session to
		// consult, and a capability that is true of the device and false of
		// the link would place work that then has nowhere to go.
		if !SupportsWorkspaceProvisioning(sess.Version()) {
			caps.SupportsWorkspaceProvisioning = false
		}
		if !SupportsWriteBack(sess.Version()) {
			caps.SupportsWriteBack = false
		}
		if !SupportsBranchBundle(sess.Version()) {
			caps.SupportsBranchBundle = false
		}
		// Nothing about the device narrows this one — writing a file needs no
		// tool — so the session's version is the whole question. A pre-v6 agent
		// has no frame field to receive the bytes in, and placement must see
		// that before it routes a lease that delivers files here.
		if !SupportsSecretFiles(sess.Version()) {
			caps.SupportsSecretFiles = false
		}
		// Same shape as SecretFiles above: the device needs no tool to write a
		// file, so the session version is the whole question, and placement has
		// to see it before routing a project-scoped run to an agent whose frame
		// has nowhere to put the plan.
		if !SupportsProjectSeed(sess.Version()) {
			caps.SupportsProjectSeed = false
		}
		// And the return half: a device that places the seed but speaks no
		// frame to send the run's changes back in. Not a placement input —
		// the hub reads it after a run, to say on the project's journal why
		// nothing came back.
		if !SupportsProjectResult(sess.Version()) {
			caps.ReturnsProjectState = false
		}
		// An older agent's container driver refuses a disk limit outright,
		// so placement must not route one there (MinDiskLimitVersion).
		if !SupportsDiskLimit(sess.Version()) {
			caps.DiskEnforcement = executor.DiskEnforcementNone
		}
	}
	return caps
}

// Status reports the executor-level connectivity status (not a handle's).
func (e *Executor) ConnStatus() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

// Connected reports whether a live session is attached.
func (e *Executor) Connected() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.session != nil
}

// HealthCheck implements executor.Executor. It is a liveness question, and
// for a NAT'd device the only honest answer is "is the agent currently
// connected and beating", since the control plane cannot probe it.
func (e *Executor) HealthCheck(ctx context.Context) error {
	sess := e.currentSession()
	if sess == nil {
		return fmt.Errorf("%w: agent %s (%s) has no live session", ErrAgentUnreachable, e.id, e.name)
	}
	if last := sess.LastSeen(); time.Since(last) > HeartbeatDeadline() {
		return fmt.Errorf("%w: agent %s last beat %s ago (limit %s)",
			ErrAgentUnreachable, e.id, time.Since(last).Round(time.Second), HeartbeatDeadline())
	}
	return nil
}

func (e *Executor) currentSession() *Session {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.session
}

// setStatus records a connectivity transition and notifies the hub.
func (e *Executor) setStatus(status string) {
	e.mu.Lock()
	if e.status == status {
		e.mu.Unlock()
		return
	}
	e.status = status
	cb := e.opts.OnStatusChange
	e.mu.Unlock()
	if cb != nil {
		cb(e.id, status, e.opts.now())
	}
}

// Start implements executor.Executor by dispatching the spec to the device.
//
// It fails fast rather than queueing. A control plane that buffers work for an
// offline device looks identical, from the UI, to one that is merely slow —
// and the work may sit there until the device returns days later, by which
// point the run is meaningless. ErrAgentUnreachable lets the caller say
// "edge-1 is offline" immediately.
//
// The named returns are what let the workspace audit's end event observe the
// outcome from a defer: provisioning is bracketed by two rows and the second
// one has to say whether the dispatch it describes worked, from whichever of
// this function's several exits was taken.
func (e *Executor) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	return e.start(ctx, spec, nil)
}

// VirtualDispatch is a start routed through a virtual executor: the sandbox
// configuration comes from it rather than from the device's own row.
type VirtualDispatch struct {
	// ID and Name identify the virtual executor.
	ID   string
	Name string
	// Spec is its configuration, already normalized.
	Spec executor.VirtualSpec
}

// needsAgent reports whether the dispatch carries anything only a v14 agent
// can apply. A virtual executor that only picks an engine and a runtime is
// fully described by the plain Sandbox settings.
func (v *VirtualDispatch) needsAgent() bool {
	return v != nil && (v.Spec.Firewall != nil || len(v.Spec.Devices) > 0)
}

// start is Start, optionally through a virtual executor.
func (e *Executor) start(ctx context.Context, spec executor.Spec, virtual *VirtualDispatch) (handle executor.Handle, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := spec.Validate(); err != nil {
		return executor.Handle{}, err
	}
	sess := e.currentSession()
	if sess == nil {
		return executor.Handle{}, fmt.Errorf("%w: cannot start work on agent %s (%s): not connected",
			ErrAgentUnreachable, e.id, e.name)
	}

	// A workload carrying revocable credentials may not be placed on an agent
	// that cannot give them back. Refusing here — rather than running it and
	// hoping nobody revokes — is what keeps "revoking a lease takes the
	// credential away" a property of the system instead of a property of which
	// devices happen to be up to date. The diagnostic names the device and the
	// fix, because the operator's next question is always "which one, and what
	// do I do about it".
	revocable := spec.RevocableSecrets()
	if len(revocable) > 0 && !SupportsRevocation(sess.Version()) {
		return executor.Handle{}, fmt.Errorf("%w: %s", ErrRevocationUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinRevocationVersion,
			"to revoke "+describeBindings(revocable)+", which this workload carries, mid-run",
			"Or remove the grant from this project."))
	}

	// The same placement rule for the workspace, and the reason it is a refusal
	// rather than a best effort is stated at MinWorkspaceVersion: an older agent
	// does not reject the credential field, it ignores it — and then runs the
	// harness against the empty directory it created.
	if spec.Workspace.NeedsProvisioning() && !SupportsWorkspaceProvisioning(sess.Version()) {
		return executor.Handle{}, fmt.Errorf("%w: %s", ErrWorkspaceUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinWorkspaceVersion,
			"to have the device clone this workload's source tree from "+spec.Workspace.Repo,
			"Or run this project on an executor that shares the control plane's filesystem."))
	}

	// And the same rule for the lease's credential files. An older agent ignores
	// StartPayload.SecretFiles exactly as it ignores any unknown field, then runs
	// the harness with GIT_CONFIG_GLOBAL, KUBECONFIG and CLOOP_LEASE_DIR all
	// naming a directory that was never created on that machine — so the failure
	// surfaces minutes later as an authentication error the transcript cannot
	// explain. Refusing here is the only place it can be named.
	if spec.NeedsSecretFiles() && !SupportsSecretFiles(sess.Version()) {
		return executor.Handle{}, fmt.Errorf("%w: %s", ErrSecretFilesUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinSecretFilesVersion,
			"to deliver "+describeSecretFiles(spec)+" to this workload as credential files the device writes",
			"Or remove the grant from this project."))
	}

	// And again for the project state. Same mechanism as the two above — an
	// older agent ignores a field it does not know — but the symptom is the
	// misleading one: the device clones the tree correctly, starts the harness,
	// and `cloop run` exits on its first line with "no cloop project found"
	// because a source repository is not a cloop project. Nothing in that
	// message points at the agent, so an operator spends the next hour looking
	// at a project that is perfectly intact.
	if len(spec.ProjectSeed) > 0 && !SupportsProjectSeed(sess.Version()) {
		return executor.Handle{}, fmt.Errorf("%w: %s", ErrProjectSeedUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinProjectSeedVersion,
			"to have the device place this workload's project state — its goal, instructions and plan — "+
				"into the cloned tree",
			"Or run this project on an executor that shares the control plane's filesystem."))
	}

	// And for a shipped branch — a feature's. An older agent has no handler
	// for the chunks that carry it and ignores the workspace field that names
	// it, so the harness would start on the feature's base commit with none of
	// the feature's work: a run on the wrong code that reports success.
	if b := spec.Workspace.Branch; b != nil {
		if !SupportsBranchBundle(sess.Version()) {
			return executor.Handle{}, fmt.Errorf("%w: %s", ErrWorkspaceUnsupported, executor.NeedsProtocol(
				e.subject(), sess.Version(), MinBranchBundleVersion,
				"to ship "+b.Describe()+" to it, which a feature's run starts from", ""))
		}
		if !e.AgentCapabilities().BranchBundles {
			return executor.Handle{}, fmt.Errorf(
				"%w: %s cannot receive %s, which a feature's run starts from: the device reported no "+
					"git, which building a tree from a shipped branch needs; install git on it and "+
					"restart the agent, or run the feature on a container executor",
				ErrWorkspaceUnsupported, e.subject(), b.Describe())
		}
		if b.Bytes > 0 {
			if err := b.VerifyFile(spec.BranchBundleFile); err != nil {
				return executor.Handle{}, fmt.Errorf("remote: start on agent %s: %w", e.id, err)
			}
		}
	}

	// And for a route to the hub's egress proxy through a firewall the device
	// installs. An older agent ignores the route and would install the rules
	// without the proxy in them, so the sandbox would hold a proxy session it
	// cannot reach. The hub does not issue one in that case (pkg/ui); this is
	// the backstop for a dispatch that did.
	if spec.EgressProxy != nil && spec.EgressRules != nil && !SupportsEgressProxy(sess.Version()) {
		return executor.Handle{}, fmt.Errorf("%w: %s", executor.ErrUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinEgressProxyVersion,
			"to open the hub's egress proxy in this workload's firewall", ""))
	}

	// Where this payload runs on the device. Read before anything is leased or
	// persisted, because it can refuse the dispatch and the cheapest refusal is
	// the earliest one.
	//
	// An unreadable configuration is fatal rather than defaulted. The whole
	// reason this setting exists in the control plane is that the device does not
	// get to decide its own containment, and "the database was busy" must not be
	// able to decide it either — silently, in the weaker direction, on a hub too
	// unhealthy to report it.
	sandbox, sandboxErr := e.opts.sandboxSettings()
	if virtual != nil {
		// A virtual executor's own configuration replaces the device's row
		// entirely. It was normalized and validated by the virtual executor on
		// this very dispatch; see Virtual.Start.
		sandbox, sandboxErr = virtual.Spec.Sandbox.Normalize(), nil
	}
	if sandboxErr != nil {
		return executor.Handle{}, fmt.Errorf(
			"%w: agent %s (%s): %w — refusing to dispatch rather than run the payload on the "+
				"device's host without knowing whether that is what the operator configured",
			ErrSandboxModeUnavailable, e.id, e.name, sandboxErr)
	}
	if err := e.checkVirtual(sess, virtual); err != nil {
		return executor.Handle{}, err
	}
	if err := e.checkEgressRules(sess, spec, sandbox, virtual); err != nil {
		return executor.Handle{}, err
	}

	// And the same placement rule as the three above, for the same reason and
	// with the least visible failure of the four: a pre-v8 agent does not reject
	// an unknown Sandbox field, it ignores it — and runs the harness as a host
	// process while the fleet view reports the container mode an admin chose.
	// Nothing downstream can tell the difference, so this is the only place it
	// can be named.
	if sandbox.Mode == executor.SandboxModeContainer && !SupportsSandboxMode(sess.Version()) {
		return executor.Handle{}, fmt.Errorf("%w: %s", ErrSandboxModeUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinSandboxModeVersion,
			"to run payloads in a container on the device, as this executor is configured to",
			"Or set this executor's sandbox mode back to host, if running on the device's host is acceptable."))
	}

	// The disk limit (Task 20405): a stated one the device cannot hold is
	// refused, and the ceilings the device cannot read are filled in — the
	// disk one only where the device will hold it. See disklimit.go.
	if err := e.checkDiskLimit(sess, spec, sandbox); err != nil {
		return executor.Handle{}, err
	}
	e.applyDeviceCeiling(&spec, sess, sandbox, virtual)

	// A hypervisor the device does not have. Refused here for the same reason
	// the check above exists — the cheapest refusal is the earliest one — but
	// against a failure that is loud rather than silent, and useless with it:
	// the payload reaches the device, Kata launches QEMU with accel=kvm,
	// /dev/kvm is not there, and ~50s later the shim gives up with "timed out
	// waiting for QMP ready: Connection refused". That error names neither KVM
	// nor nested virtualization nor this executor, and it arrives once per
	// dispatch forever, because nothing in the loop learns from it.
	//
	// Gated on the probe version so a pre-v9 agent behaves exactly as it does
	// today: unknown is not no, and a fleet mid-upgrade keeps running the Kata
	// work it is running now.
	if sandbox.IsVirtualized() && SupportsVirtualizationProbe(sess.Version()) &&
		!e.AgentCapabilities().Virtualization {
		return executor.Handle{}, fmt.Errorf(
			"%w: agent %s (%s) is configured to run payloads under the %q runtime, but the device "+
				"reports no usable %s, so it cannot start a VM; enable nested virtualization on "+
				"the machine hosting this device, or set this executor's sandbox runtime to runsc "+
				"(gVisor keeps syscalls off the host kernel without needing a hypervisor) or leave "+
				"it unset for a plain container",
			ErrVirtualizationUnavailable, e.id, e.name, sandbox.Runtime, agentKVMDevice)
	}

	// The harness the project's provider drives, against what the device said it
	// has. Last of the four placement refusals and the only one whose subject is
	// the payload rather than the boundary around it, which is also why it is the
	// one that was missing: everything above asks "can this device contain the
	// work", and nothing asked "can it run the work at all".
	if err := e.checkHarness(ctx, spec, sandbox); err != nil {
		return executor.Handle{}, err
	}

	// Convert and bound the credential files here, before a credential is leased
	// or a handle row is written, so a lease that cannot fit in a start frame
	// fails naming the files rather than surfacing later as an oversized-payload
	// protocol error from the device. The same check runs on the receiving side;
	// see ValidateSecretFiles for why both.
	secretFiles := NewSecretFiles(spec.SecretFiles)
	if err := ValidateSecretFiles(secretFiles); err != nil {
		return executor.Handle{}, fmt.Errorf("remote: start on agent %s: %w", e.id, err)
	}

	// Lease the workspace credential at the last possible moment and give it
	// back as soon as the agent confirms the start: from that point the device
	// holds the material, and a lease left open here is a credential the broker
	// believes is still out in the world. The release is deferred rather than
	// called at each exit because there are six of them below.
	leaseCtx := ctx
	if virtual != nil {
		// Leased as the virtual executor, which is what the grant chosen
		// before this dispatch was matched against. Leased as this device, a
		// grant issued to the virtual executor was chosen and then missing
		// from the lease (Task 20349).
		leaseCtx = executor.WithRequestingExecutor(ctx, virtual.ID)
	}
	access, releaseCred, credErr := e.leaseWorkspace(leaseCtx, spec)
	// Given back as soon as the agent has the material — unless a push
	// write-back will present the same credential when the workload finishes.
	// Then it is parked on the handle and released when the handle closes:
	// releasing a GitHub App lease destroys the token at GitHub, and the
	// write-back would meet a dead one (Task 20349).
	keepCred := false
	defer func() {
		if !keepCred {
			releaseCred()
		}
	}()
	if credErr != nil {
		return executor.Handle{}, credErr
	}
	cred := access.Credential

	// The control plane names the handle, not the agent. If the start
	// response is lost to a disconnect the workload is still addressable: we
	// can ask about the ID we chose, and a repeated start for a known ID is a
	// no-op on the agent rather than a second copy of the workload.
	handleID, err := randomString(idBytes)
	if err != nil {
		return executor.Handle{}, fmt.Errorf("remote: generate handle id: %w", err)
	}

	// Provisioning gets its own audit rows because this is the moment a
	// brokered credential is used against an external service, and the run's
	// own record cannot answer "which grant fetched which repository onto which
	// device" — the run looks identical whether the tree arrived or not.
	if spec.Workspace.NeedsProvisioning() {
		endWorkspaceAudit := e.auditWorkspaceStart(handleID, spec, cred)
		defer func() { endWorkspaceAudit(err) }()
	}

	now := e.opts.now()
	hs := &handleState{
		id:        handleID,
		startedAt: now,
		virtualID: virtualIDOf(virtual),
		// What the device may send back, from the spec it is about to be
		// given — set before the handle is published, because a hostile
		// agent's first chunk can arrive before the started reply does.
		returns: allowanceFor(spec),
		// Output arrives from a device the hub does not control, so the hub
		// redacts what it sent there rather than trusting the agent to have
		// done it. The agent scrubs too — this is the half that holds when
		// the agent is older than the guarantee, or lying.
		bus: logbus.New(handleID, executor.StreamCombined, logbus.Options{
			Now:    e.opts.now,
			Redact: spec.Redactor(),
		}),
		status: executor.Status{
			HandleID:   handleID,
			ExecutorID: e.id,
			State:      executor.StatePending,
			StartedAt:  now,
		},
	}
	e.mu.Lock()
	e.handles[handleID] = hs
	e.pruneLocked()
	store := e.store
	e.mu.Unlock()

	// Persisted after the map insert and *before* the start frame goes out,
	// which is the opposite of where the container and Kubernetes drivers put
	// it — because for those two the workload does not exist until a local API
	// call returns, and a row written earlier would name nothing. Here the
	// workload comes into existence on another machine, on the far side of a
	// link that may be an LTE modem: the whole round trip is a window in which
	// this process can die while the device is already running the harness.
	// Writing the row first makes that window empty.
	//
	// The cost is a row that may describe a workload the agent never started —
	// the start frame was lost, or refused. That is bounded and self-correcting
	// from both ends: dropHandle deletes it on every failure path inside this
	// process, and after a restart the adopted handle is resolved by the first
	// heartbeat that does not list it (see reconcileActive), which is the same
	// mechanism that already handles a device that lost the process.
	//
	// RecordHandle never fails the start: see its doc for why a busy state
	// database must not become a spurious task failure.
	executor.RecordHandle(store, executor.HandleRecord{
		HandleID:   handleID,
		ExecutorID: e.id,
		Driver:     executor.KindRemoteAgent,
		// The same string as HandleID, and deliberately duplicated rather than
		// left blank: the control plane mints the handle and the agent offers
		// that exact ID back on reconnect, so for this driver the name the
		// "runtime" knows the workload by *is* the handle. Validate refuses a
		// row with no external ID, and a driver whose rows were the only ones
		// missing that column would be invisible to a cross-driver sweep.
		ExternalID: handleID,
		// The project as the audit trail and the lease request see it, so one
		// workload has one identity in the handle table whichever driver ran it.
		ProjectPath: projectOf(spec),
		TaskID:      taskIDFromLabels(spec.Labels),
		// Dispatch time in the control plane's clock, not the device's. The
		// device's StartedAt arrives in the started frame a round trip later and
		// comes from a clock that, on an edge box with no RTC, may be wrong by
		// years — and the orphan sweep compares this field against a grace
		// period.
		StartedAt: now,
		// The lease attribution, persisted so a revocation arriving after a hub
		// restart can rebuild the lease→handle index and still route a frame to
		// this device. Names and paths only — the credential values travel in
		// the start frame's Spec.Env and are never written here.
		//
		// Written before bindLease below rather than after, which is the safe
		// order: the row exists from the moment the device could be holding the
		// material, so a crash between the two loses nothing a revocation needs.
		Secrets:         spec.Secrets,
		SecretsRecorded: true,
		// What the workload may send back (Task 20399), so a hub that
		// restarts — or another member that adopts the run — holds the
		// device to the cap this spec asked for, not to the hard ceiling.
		Meta: hs.returns.meta(),
	})

	payload := StartPayload{Spec: spec, HandleID: handleID, Sandbox: sandbox}
	if virtual.needsAgent() {
		// Only when the device has to apply something: see needsAgent. The
		// version gate in checkVirtual has already refused a session that
		// would ignore this.
		payload.Virtual = &VirtualStart{
			ID:       virtual.ID,
			Name:     virtual.Name,
			Firewall: shippedFirewall(virtual.Spec.Firewall),
			Devices:  virtual.Spec.Devices,
		}
	}
	// Route the *shipped* copy of the workspace, not the one persisted and
	// audited above. When a git proxy is interposed the device must fetch and
	// push through it, while the durable record should keep naming the real
	// repository — an operator reading a run row wants github.com/acme/tool,
	// not a proxy URL whose session died with the run.
	payload.Spec.Workspace = access.Apply(spec.Workspace)
	if !cred.Empty() {
		// Beside the Spec, never inside it. See WorkspaceCredential: a Spec is
		// persisted by pkg/executorstore, so a token in one would outlive the
		// fetch it was minted for by however long the run history is kept.
		payload.WorkspaceCredential = &WorkspaceCredential{
			Username:  cred.Username,
			Password:  cred.Password,
			ExpiresAt: cred.ExpiresAt,
		}
	}
	// The lease's credential files travel beside the Spec too, and for a reason
	// the Spec cannot express: executor.Spec.SecretFiles is json:"-", so the
	// bytes are simply absent from the marshalled Spec however the caller filled
	// it in. Carrying them here is what turns "the environment names a token
	// file" into "the token file exists on the machine running the harness".
	//
	// Guarded by the session version because the field is invisible to an older
	// agent; the Start gate above has already refused the workloads that would
	// notice, so this is the belt to that braces — a spec that needs no files
	// still sends none, and one that does never reaches here on a v5 session.
	if len(secretFiles) > 0 && SupportsSecretFiles(sess.Version()) {
		payload.SecretFiles = secretFiles
	}
	// The project state travels beside the Spec for the same structural reason
	// and a different motive: executor.Spec.ProjectSeed is json:"-" to keep a
	// few hundred kilobytes of plan out of the handle store and the audit
	// trail, so the bytes are absent from the marshalled Spec however the
	// caller filled it in. Guarded by the session version as the belt to the
	// Start gate's braces, exactly as above.
	if len(spec.ProjectSeed) > 0 && SupportsProjectSeed(sess.Version()) {
		payload.ProjectSeed = spec.ProjectSeed
	}

	frame, err := sess.frame(TypeStart, newCorrelationID(), handleID, payload)
	if err != nil {
		e.dropHandle(handleID)
		return executor.Handle{}, err
	}

	// The shipped branch goes first, on the same connection, so every chunk
	// has arrived by the time the device reads the start frame that names it.
	if b := spec.Workspace.Branch; b != nil && b.Bytes > 0 {
		if err := sendBranchBundle(ctx, sess, handleID, spec.BranchBundleFile, b.Bytes); err != nil {
			e.dropHandle(handleID)
			return executor.Handle{}, fmt.Errorf("remote: send %s to agent %s: %w", b.Describe(), e.id, err)
		}
	}

	reply, err := sess.request(ctx, frame, TypeStarted)
	if err != nil {
		e.dropHandle(handleID)
		return executor.Handle{}, fmt.Errorf("remote: start on agent %s: %w", e.id, err)
	}
	started, err := DecodeStarted(reply)
	if err != nil {
		e.dropHandle(handleID)
		return executor.Handle{}, err
	}
	if started.Error != "" {
		e.dropHandle(handleID)
		// A workspace already over its disk limit, which the device names
		// with the measurement (Task 20405): the refusal is the hub's to
		// answer as one, so it comes back typed — bounded first, because it
		// is the device's word.
		if _, b := executor.SanitizeDiskOutcome(executor.OutcomeDiskLimit, started.DiskLimit); b != nil {
			id := e.id
			if virtual != nil {
				id = virtual.ID
			}
			return executor.Handle{}, &executor.DiskLimitError{Executor: id, Breach: *b}
		}
		// The workspace is named in the refusal because the most common reason
		// a device rejects a start is now that it could not materialise the
		// tree, and "agent edge-1 refused the workload" alone sends the
		// operator looking at the harness instead of at the clone.
		return executor.Handle{}, fmt.Errorf("remote: agent %s refused the workload%s: %s",
			e.id, describeWorkspace(spec), started.Error)
	}

	startedAt := started.StartedAt
	if startedAt.IsZero() {
		startedAt = now
	}
	hs.mu.Lock()
	hs.startedAt = startedAt
	// A workload that ended at once may have reported its exit before this
	// reply was handled; that status is final (see applyStatus), and the
	// leases and credential it held were already given back.
	ended := hs.closed
	if !ended {
		hs.status.State = executor.StateRunning
		hs.status.PID = started.PID
		hs.status.StartedAt = startedAt
		if spec.WriteBack.Mode == executor.WriteBackPush && !cred.Empty() {
			hs.releaseWorkspace = releaseCred
			hs.heldWorkspace = executor.HeldWorkspaceCredential{
				LeaseID: cred.LeaseID, GrantID: cred.GrantID, SessionID: cred.SessionID,
			}
			keepCred = true
		}
	}
	hs.mu.Unlock()

	// Recorded only after the agent confirmed the start: a binding for a
	// workload that never ran would make the executor claim to hold a
	// credential it was never given, and a revocation would then wait for an
	// ack that has no reason to exist.
	if !ended {
		e.leases.Bind(handleID, spec.Secrets)
	}

	return executor.Handle{
		ID:         handleID,
		ExecutorID: e.id,
		// PID is the process ID *on the device*. It is reported for
		// diagnostics only — host-side tooling such as the /proc scan behind
		// the Stop button must not act on it, which is why
		// Capabilities().SharesHostFilesystem is false.
		PID:       started.PID,
		StartedAt: startedAt,
	}, nil
}

// HandleStatuses implements executor.Lister from the control plane's last-known view
// of the agent, without dialling the device.
//
// Not round-tripping is the point: this feeds the Executors panel's load
// column, and an offline agent behind NAT would otherwise make that column
// block until the request timed out. The cached view is refreshed by the
// status frames the agent pushes as work progresses, so it is current for a
// connected agent and honestly stale for a disconnected one — which is what
// the card's status dot is already telling the operator.
func (e *Executor) HandleStatuses(ctx context.Context) ([]executor.Status, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	e.mu.RLock()
	states := make([]*handleState, 0, len(e.handles))
	for _, hs := range e.handles {
		states = append(states, hs)
	}
	e.mu.RUnlock()

	out := make([]executor.Status, 0, len(states))
	for _, hs := range states {
		out = append(out, hs.snapshotStatus())
	}
	return out, nil
}

// Signal implements executor.Executor.
//
// Signalling a handle the control plane has already seen terminate returns nil
// without a round trip: the desired end state already holds, and bothering an
// LTE-connected device to tell it so is pure cost.
func (e *Executor) Signal(ctx context.Context, handleID string, sig executor.Signal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !sig.Valid() {
		return fmt.Errorf("%w: %q", executor.ErrInvalidSignal, sig)
	}
	hs, err := e.lookup(handleID)
	if err != nil {
		return err
	}
	if hs.snapshotStatus().State.Terminal() {
		return nil
	}
	sess := e.currentSession()
	if sess == nil {
		return fmt.Errorf("%w: cannot signal %s: agent %s is not connected",
			ErrAgentUnreachable, handleID, e.id)
	}
	frame, err := sess.frame(TypeSignal, newCorrelationID(), handleID, SignalPayload{Signal: sig})
	if err != nil {
		return err
	}
	// The agent answers a signal with the handle's status, which doubles as
	// delivery confirmation — a fire-and-forget signal would leave the UI
	// unable to distinguish "stop was delivered" from "stop was swallowed".
	if _, err := sess.request(ctx, frame, TypeStatus); err != nil {
		return fmt.Errorf("remote: signal %s on agent %s: %w", handleID, e.id, err)
	}
	return nil
}

// maxAbandonReason bounds the reason an abandoned handle carries: it is
// repeated in a resume frame for every such handle the device offers back.
const maxAbandonReason = 256

// Abandon implements executor.Abandoner (Task 20396): the control plane failed
// handleID's session over to another executor, so the workload is no longer
// its project's run.
//
// Three things, in this order. The workload is killed if the agent can still
// hear — after a failover it usually cannot, a device is failed over because
// it stopped answering. The handle becomes terminal here, with reason in its
// status, which closes its output stream: every watcher on the hub lets go of
// it, the run's credential lease with them, and its durable row is forgotten
// so a restarted hub does not rehydrate it. And it stays known as abandoned,
// so a device that comes back offering to resume it is told to terminate it
// (reconcileResume) rather than to carry on beside its replacement.
//
// A signal that could not be delivered is returned, but the handle is
// abandoned all the same: the kill is the part a device out of reach can
// miss, the refusal on its return is the part that holds.
func (e *Executor) Abandon(ctx context.Context, handleID, reason string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	hs, err := e.lookup(handleID)
	if err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "the control plane failed this workload over to another executor"
	}
	if len(reason) > maxAbandonReason {
		reason = reason[:maxAbandonReason]
	}
	hs.mu.Lock()
	already := hs.abandoned
	if !already {
		// The first word stands: it is the one the device will be told.
		hs.abandoned = true
		hs.abandonReason = reason
	}
	hs.mu.Unlock()
	if already {
		return nil
	}
	var signalErr error
	if !hs.snapshotStatus().State.Terminal() && e.currentSession() != nil {
		signalErr = e.Signal(ctx, handleID, executor.SignalKill)
	}
	st := hs.snapshotStatus()
	e.applyStatus(handleID, StatusPayload{Status: executor.Status{
		HandleID:   handleID,
		ExecutorID: e.id,
		State:      executor.StateFailed,
		StartedAt:  st.StartedAt,
		FinishedAt: e.opts.now(),
		Error:      "abandoned by the control plane: " + reason,
	}})
	// Including a verified result, which a terminal status alone keeps for
	// collection: the run moved elsewhere, and nothing should land what this
	// copy of it sent back.
	e.releaseResults(hs, "the control plane abandoned this workload: "+reason)
	return signalErr
}

var _ executor.Abandoner = (*Executor)(nil)

// Status implements executor.Executor.
//
// When the agent is unreachable this returns the last known status with State
// forced to StateUnknown rather than an error. That is the documented meaning
// of StateUnknown, and it matters for the UI: a run whose device dropped off
// should render as "state unknown, last seen running" instead of vanishing
// behind an error banner.
func (e *Executor) Status(ctx context.Context, handleID string) (executor.Status, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	hs, err := e.lookup(handleID)
	if err != nil {
		return executor.Status{}, err
	}
	last := hs.snapshotStatus()
	if last.State.Terminal() {
		return last, nil
	}

	sess := e.currentSession()
	if sess == nil {
		last.State = executor.StateUnknown
		last.Error = fmt.Sprintf("agent %s is not connected", e.id)
		return last, nil
	}
	frame, err := sess.frame(TypeStatusReq, newCorrelationID(), handleID, StatusReqPayload{})
	if err != nil {
		return executor.Status{}, err
	}
	reply, err := sess.request(ctx, frame, TypeStatus)
	if err != nil {
		last.State = executor.StateUnknown
		last.Error = err.Error()
		return last, nil
	}
	payload, err := DecodeStatus(reply)
	if err != nil {
		return executor.Status{}, err
	}
	e.applyStatus(handleID, payload)
	return hs.snapshotStatus(), nil
}

// Stream implements executor.Executor. Output arrives as log_chunk frames and
// is republished through the same logbus every other driver uses, so the
// dropped-chunk and late-subscriber semantics are identical regardless of
// where the workload runs.
func (e *Executor) Stream(ctx context.Context, handleID string) (<-chan executor.LogLine, error) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return nil, err
	}
	return hs.bus.Subscribe(ctx), nil
}

// Handles lists the handle IDs this executor currently tracks.
func (e *Executor) Handles() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.handles))
	for id := range e.handles {
		out = append(out, id)
	}
	return out
}

func (e *Executor) lookup(handleID string) (*handleState, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	hs, ok := e.handles[handleID]
	if !ok {
		return nil, fmt.Errorf("%w: %q on agent %s", executor.ErrHandleNotFound, handleID, e.id)
	}
	return hs, nil
}

// maxRetainedHandles bounds the finished handles kept for post-hoc Status and
// log replay. A control plane is a long-lived process and an agent may run
// thousands of workloads over its life, so without a ceiling the handle map —
// and every finished workload's replay backlog with it — would grow forever.
// The value matches the other drivers so behaviour does not depend on where a
// workload happened to run.
const maxRetainedHandles = 256

// pruneLocked evicts the oldest finished handles once the map exceeds the
// ceiling. Running handles are never evicted: dropping one would orphan a live
// workload the control plane can no longer address. Callers must hold e.mu.
//
// An evicted handle's returned work goes with it, and back to the budget: an
// unreachable handle is bytes nothing can collect (Task 20399).
func (e *Executor) pruneLocked() {
	if len(e.handles) <= maxRetainedHandles {
		return
	}
	type aged struct {
		id string
		at time.Time
	}
	var finished []aged
	for id, hs := range e.handles {
		hs.mu.Lock()
		done := hs.status.State.Terminal()
		at := hs.status.FinishedAt
		hs.mu.Unlock()
		if done {
			finished = append(finished, aged{id: id, at: at})
		}
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].at.Before(finished[j].at) })
	for _, f := range finished {
		if len(e.handles) <= maxRetainedHandles {
			return
		}
		if hs := e.handles[f.id]; hs != nil {
			hs.mu.Lock()
			e.dropResultsLocked(hs, "the hub evicted this finished handle")
			hs.mu.Unlock()
		}
		delete(e.handles, f.id)
	}
}

// dropHandle removes a handle that never successfully started.
//
// The durable row goes with it. Start writes the row before the start frame so
// a hub that dies mid-dispatch can still find the workload, which means every
// path that concludes "there is no workload" has to undo that optimism —
// otherwise a refused start leaves a row the next boot adopts, reports as
// running, and then resolves as a failed run that never ran.
func (e *Executor) dropHandle(handleID string) {
	e.releaseLeases(handleID)
	e.mu.Lock()
	hs := e.handles[handleID]
	delete(e.handles, handleID)
	store := e.store
	e.mu.Unlock()
	executor.ForgetHandle(store, handleID)
	if hs != nil {
		// Closed before its returned work is dropped, under the same lock:
		// a frame that looked the handle up before it left the map is then
		// refused rather than counted against a handle nothing can reach.
		hs.mu.Lock()
		hs.closed = true
		hs.closedAt = e.opts.now()
		e.dropResultsLocked(hs, "the workload never started")
		hs.mu.Unlock()
		hs.bus.Close()
		hs.finishWorkspaceRelease()
	}
}

// ---------------------------------------------------------------------------
// Session callbacks
// ---------------------------------------------------------------------------

// attach binds a new session, replacing any previous one.
//
// Replacing rather than rejecting is deliberate. When a device's network drops
// without a FIN, the control plane keeps a half-open session that will not
// fail until its heartbeat deadline expires — meanwhile the device has already
// noticed and reconnected. Preferring the newest session means a reconnecting
// agent is usable immediately instead of being locked out by its own ghost.
func (e *Executor) attach(sess *Session) {
	// Read the session's capabilities *before* taking e.mu. Session.mu is
	// ordered strictly after Executor.mu everywhere else (a session's read
	// loop calls into the executor while holding nothing), so acquiring them
	// the other way round here would be a lock-order inversion and a genuine
	// deadlock against a concurrent ack flush.
	caps := sess.Capabilities()

	e.mu.Lock()
	prev := e.session
	e.session = sess
	e.caps = caps
	e.mu.Unlock()

	if prev != nil && prev != sess {
		prev.closeWithReason("superseded by a newer session")
	}
	e.setStatus(StatusOnline)

	// Anything revoked while this agent was offline is owed to it now. Done
	// on its own goroutine because attach runs on the handshake path, which
	// must not block on a round trip to the device it is still setting up.
	//
	// What is owed is read here, though, not on that goroutine. Read later, it
	// also caught a revocation recorded after this attach, which its own
	// RevokeLease call was already delivering on this very session: the device
	// was sent the frame twice, and a caller's ack could be the one consumed
	// by the replay while its own request waited out the revoke timeout and
	// reported the device unreachable.
	owed := e.revocations.Pending()
	go func() {
		defer func() {
			// A panic here must not take the control plane down with it: the
			// handshake that spawned this goroutine has already returned.
			if r := recover(); r != nil {
				_ = r
			}
		}()
		e.replayRevocations(sess, owed)
	}()
}

// detach unbinds sess if it is still the current session. The guard matters:
// a stale session's teardown must not clear a newer one that already replaced
// it, or a reconnected agent would be marked offline by its predecessor's
// cleanup goroutine.
func (e *Executor) detach(sess *Session, status string) {
	e.mu.Lock()
	if e.session != sess {
		e.mu.Unlock()
		return
	}
	e.session = nil
	e.mu.Unlock()
	e.setStatus(status)
}

// maxResumeRefusals bounds how many terminate verdicts one welcome may carry.
//
// It is the only part of a welcome whose size is chosen by the *agent*: an
// accepted verdict requires a matching handle, so those are bounded by what
// this hub dispatched, while a refusal is emitted for anything the peer cares
// to list. Without a ceiling a device offering a megabyte of invented handle
// IDs would make the hub assemble a welcome larger than MaxFrameBytes, which
// the peer's own read limit then rejects — an amplification that costs the hub
// the work and the agent its session.
//
// Set to the handle-retention ceiling because a device can never legitimately
// be running more workloads than this hub retains handles for; its own
// MaxConcurrent is smaller by an order of magnitude. Offers past the cap fall
// through to omission, which is the pre-v5 answer and which an upgraded agent
// still reads as "stop this" — so the bound costs nothing but the reason text.
const maxResumeRefusals = maxRetainedHandles

// resumeRefusedReason is what a refused device writes in its own log.
//
// A shared constant rather than a per-handle message naming the executor: the
// text is identical for every refusal in a welcome, and repeating a formatted
// string per entry is what turns a large offer list into a large frame. The
// device already knows which control plane it is talking to.
const resumeRefusedReason = "the control plane has no record of this workload, so nothing there " +
	"can read its output, collect its result, or stop it"

// reconcileResume answers an agent's resume offer, one verdict per offer.
//
// For a handle the control plane still tracks the answer is "resend from the
// offset I actually received", which for a handle rehydrated from the store is
// zero — see rehydrate.go's adopt for why that is the honest number rather than
// a guess.
//
// For a handle it does *not* track the answer is "terminate it", and that is
// the fix for the leak this whole file's resume machinery used to have. The old
// answer was silence, which the agent read as "stop reporting": the device went
// on running a harness whose output nobody would read, whose result nobody
// would collect, and which nothing could signal — forever, invisibly, with no
// reaper anywhere. A refusal that does not stop the work is not a refusal.
//
// version is the session's negotiated protocol version, and it gates only the
// refusal. Below MinResumeTerminateVersion the entry is omitted instead, which
// reproduces the pre-v5 wire byte for byte: an older agent that saw a refusal
// in this list would ignore the action, take the entry as permission to keep
// streaming, and have every chunk answered with CodeUnknownHandle. Omission
// leaves such an agent exactly as it was, which is the floor this change must
// not go below; the leak is closed on its side by upgrading it.
func (e *Executor) reconcileResume(offers []ResumeHandle, version int) []ResumeAck {
	if len(offers) == 0 {
		return nil
	}
	canTerminate := SupportsResumeTerminate(version)
	refusals := 0
	acks := make([]ResumeAck, 0, len(offers))
	for _, offer := range offers {
		hs, err := e.lookup(offer.HandleID)
		if err != nil {
			if !canTerminate || refusals >= maxResumeRefusals {
				continue
			}
			refusals++
			acks = append(acks, ResumeAck{
				HandleID: offer.HandleID,
				Action:   ResumeTerminate,
				Reason:   resumeRefusedReason,
			})
			continue
		}
		hs.mu.Lock()
		from := hs.receivedOffset
		abandoned, why := hs.abandoned, hs.abandonReason
		hs.mu.Unlock()
		if abandoned {
			// The control plane failed this workload's session over while the
			// device was out of reach (Task 20396): its tasks went back to the
			// plan, and a replacement may be running them on another executor.
			// Resumed, it would be a second harness on the same work. Not
			// counted against maxResumeRefusals — that bound is for handles
			// the peer invents, and an abandoned handle is one this hub
			// tracks, so there are at most maxRetainedHandles of them.
			if canTerminate {
				acks = append(acks, ResumeAck{
					HandleID: offer.HandleID,
					Action:   ResumeTerminate,
					Reason:   why,
				})
			}
			continue
		}
		// Action is set explicitly even though it is the default, so the frame
		// says what it means rather than relying on a reader inferring consent
		// from an absent field. An older agent ignores it and behaves as before.
		acks = append(acks, ResumeAck{
			HandleID:   offer.HandleID,
			FromOffset: from,
			Action:     ResumeContinue,
		})
	}
	return acks
}

// reconcileActive resolves handles the control plane believes are running but
// the agent no longer knows about.
//
// Without this, a workload whose device rebooted mid-run stays "running"
// forever in the UI: the agent will never send a terminal status for a process
// it has forgotten, and the control plane has no other way to find out. The
// heartbeat's handle list is the only signal available, so a non-terminal
// handle absent from it is resolved as failed.
func (e *Executor) reconcileActive(active []string) {
	live := make(map[string]struct{}, len(active))
	for _, id := range active {
		live[id] = struct{}{}
	}
	e.mu.RLock()
	tracked := make([]*handleState, 0, len(e.handles))
	for _, hs := range e.handles {
		tracked = append(tracked, hs)
	}
	e.mu.RUnlock()

	for _, hs := range tracked {
		if _, ok := live[hs.id]; ok {
			continue
		}
		st := hs.snapshotStatus()
		if st.State.Terminal() || st.State == executor.StatePending {
			continue
		}
		e.applyStatus(hs.id, StatusPayload{Status: executor.Status{
			HandleID:   hs.id,
			ExecutorID: e.id,
			State:      executor.StateFailed,
			StartedAt:  st.StartedAt,
			FinishedAt: e.opts.now(),
			Error:      "agent no longer reports this workload as running (device restarted or lost the process)",
		}})
	}
}

// appendLog applies one inbound log chunk, returning the new contiguous
// received offset so the session can ack it.
//
// Three cases, all of which happen in practice after a reconnect:
//
//   - the chunk is entirely below receivedOffset: a duplicate resend, ignore;
//   - the chunk straddles receivedOffset: trim the already-seen prefix and
//     emit the remainder, which is the normal resume case;
//   - the chunk starts above receivedOffset: output was lost for good, so
//     emit it and record the gap rather than pretending the log is complete.
func (e *Executor) appendLog(handleID string, p LogChunkPayload) (int64, error) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return 0, err
	}
	hs.mu.Lock()
	if hs.closed {
		offset := hs.receivedOffset
		hs.mu.Unlock()
		return offset, nil
	}
	text := p.Text
	end := p.End()
	switch {
	case end <= hs.receivedOffset:
		offset := hs.receivedOffset
		hs.mu.Unlock()
		return offset, nil
	case p.Offset < hs.receivedOffset:
		text = text[hs.receivedOffset-p.Offset:]
	case p.Offset > hs.receivedOffset:
		hs.gapped = true
	}
	hs.receivedOffset = end
	offset := hs.receivedOffset
	hs.mu.Unlock()

	// Emitted outside the lock: logbus fans out to subscribers and must not
	// run under this handle's mutex, which Status also takes.
	hs.bus.Emit(text)
	return offset, nil
}

// applyStatus records a status update from the agent and, on a terminal state,
// closes the log stream.
//
// Ordering is contractual: the status is recorded *before* the bus is closed,
// because executor.Run reads Status the moment its channel closes and a
// consumer that sees the close is entitled to find a terminal state waiting.
func (e *Executor) applyStatus(handleID string, p StatusPayload) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return
	}
	st := p.Status
	st.HandleID = handleID
	st.ExecutorID = e.id
	// A disk-limit stop as the device tells it (Task 20405): bounded before it
	// reaches the project's journal and pause, because it is the device's word.
	st.Outcome, st.DiskLimit = executor.SanitizeDiskOutcome(st.Outcome, st.DiskLimit)

	hs.mu.Lock()
	if hs.closed && !st.State.Terminal() {
		// Stale: the handle already ended. The agent answers a signal from its
		// frame loop with "running" while the output still drains
		// (workload.draining), and the pump's terminal status can go out
		// first. Applied, that reply reopened a finished handle, and Status
		// then asked the device about a workload it had forgotten and
		// reported "unknown" for a run that had been stopped.
		hs.mu.Unlock()
		return
	}
	if hs.status.StartedAt.IsZero() {
		st.StartedAt = hs.startedAt
	} else if st.StartedAt.IsZero() {
		st.StartedAt = hs.status.StartedAt
	}
	shouldClose := st.State.Terminal() && !hs.closed
	if shouldClose {
		// A bundle whose result frame never came will never be completed: the
		// agent sends the result before the final status and nothing after
		// it. Its bytes are let go of now rather than when the handle is
		// evicted (Task 20399), and why is recorded, so the status below and a
		// collector arriving later say the same thing.
		if wb := hs.writeBack; wb != nil && wb.result == nil {
			if wb.size > 0 && wb.failed == "" {
				wb.failed = fmt.Sprintf("the workload ended with %d bytes of its bundle received and "+
					"no result frame to close it", wb.size)
			}
			e.dropBundleLocked(wb)
		}
	}
	// The write-back is attached to the status rather than reported alongside
	// it because this is the status a consumer reads the instant the log stream
	// closes, and the agent's frame order — chunks, result, then status —
	// guarantees the result has already arrived. A terminal status carrying
	// nothing while a result frame sits on the same handle would make the
	// delivery invisible to executor.Run.
	//
	// Only what this hub received through the write-back frames is reported.
	// A WriteBack the device put in the status frame itself would claim a
	// delivery no result frame was verified for; an honest agent never sends
	// one (pkg/executor/agent strips the write-back from the spec its inner
	// driver runs, and reports the result in its own frame).
	st.WriteBack = nil
	if wb := hs.writeBack; wb != nil {
		switch {
		case wb.result != nil:
			st.WriteBack = wb.result
		case wb.failed != "" && st.State.Terminal():
			// Chunks were refused, and no result frame followed to say so.
			// Without this the run would read as one that returned nothing,
			// rather than one whose work the hub turned away and why.
			st.WriteBack = &executor.WriteBackResult{Mode: executor.WriteBackBundle, Err: wb.failed}
		}
	}
	// The device's prose, kept for as long as the handle is.
	st.Error = clipText(st.Error, maxReturnedTextBytes)
	hs.status = st
	if shouldClose {
		hs.closed = true
		hs.closedAt = e.opts.now()
		// The agent reports the total bytes the workload produced. Receiving
		// fewer means output was lost on the way — the stream is about to be
		// closed, so anything still outstanding will never arrive. Record it
		// rather than presenting a truncated log as complete.
		if p.FinalOffset > hs.receivedOffset {
			hs.gapped = true
		}
	}
	hs.mu.Unlock()

	if shouldClose {
		hs.bus.Close()
		// The workload is over, so whatever material it held is no longer in
		// use. Dropping the binding keeps a revocation from targeting a
		// finished task and reporting "unreachable" for a credential that is
		// already gone with the process that held it.
		e.releaseLeases(handleID)
		// The write-back, if there was one, has run on the device by now.
		hs.finishWorkspaceRelease()
		// And the durable row: nothing can reattach to a workload the device
		// has already reported terminal, and a row that outlived its process
		// would be re-adopted on the next boot, offered by nobody, and then
		// resolved as failed by the first heartbeat — a phantom failed run for
		// a task that exited cleanly.
		//
		// Gated on shouldClose, which is `terminal && !closed`, so it fires
		// exactly once per handle and only for a genuinely terminal state. That
		// gate is the whole of the bug the Kubernetes driver hit: an ungated
		// forget also fires for the handles a graceful shutdown marks unknown
		// while their workloads keep running, erasing the identity of every
		// in-flight run at precisely the moment rehydration exists to serve.
		// failAllHandles is this driver's version of that path and deliberately
		// does not come through here.
		executor.ForgetHandle(e.handleStore(), handleID)
	}
}

// LogGapped reports whether output was permanently lost for a handle, so a
// consumer can label a partial log instead of presenting it as complete.
func (e *Executor) LogGapped(handleID string) bool {
	hs, err := e.lookup(handleID)
	if err != nil {
		return false
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.gapped
}

// failAllHandles marks every non-terminal handle unknown and closes its
// stream. Called when an agent is revoked or deregistered: the workloads may
// still be running on the device, but this control plane will never learn
// their outcome, and leaving subscribers blocked on a channel that will never
// close would hang every caller of executor.Run.
//
// Every handle's returned work goes too, finished handles' included, and back
// to the budget (Task 20399). A revoked device is one the operator no longer
// trusts, so nothing it sent is landed afterwards, and a deregistered
// executor's handles are unreachable by any consumer.
//
// It deliberately does not drop the durable rows, even though the states it
// writes are terminal. The distinction is who ended the workload: applyStatus
// forgets a row because the device said the process is gone, while this marks
// handles failed because the *link* is gone and the processes very likely are
// not. That row is then the only surviving record that a machine we have just
// stopped talking to is running our work — which is exactly what
// HandleRecord.Driver is for, since a cross-driver sweep can act on rows whose
// executor is no longer registered and nothing else can.
func (e *Executor) failAllHandles(reason string) {
	e.mu.RLock()
	tracked := make([]*handleState, 0, len(e.handles))
	for _, hs := range e.handles {
		tracked = append(tracked, hs)
	}
	e.mu.RUnlock()

	for _, hs := range tracked {
		hs.mu.Lock()
		e.dropResultsLocked(hs, reason)
		if hs.closed {
			hs.mu.Unlock()
			continue
		}
		if !hs.status.State.Terminal() {
			hs.status.State = executor.StateFailed
			hs.status.Error = reason
			hs.status.FinishedAt = e.opts.now()
		}
		hs.closed = true
		hs.closedAt = e.opts.now()
		hs.mu.Unlock()
		hs.bus.Close()
		hs.finishWorkspaceRelease()
	}
}

// describeBindings names the credentials in a refusal, so the operator reads
// "the GitHub PAT github-ci" rather than "a secret".
//
// It delegates because every driver refusing a placement has to phrase the
// same sentence, and an operator comparing two refusals should not have to
// work out whether two different wordings mean the same thing.
func describeBindings(bindings []executor.SecretBinding) string {
	return executor.DescribeBindings(bindings)
}

// describeSecretFiles names the credential whose files a device would have to
// place, for a refusal an operator can act on.
//
// It falls back rather than calling describeBindings unconditionally because
// the two ways a Spec can need files are not the same shape: a lease that
// delivered bindings has names to quote, while a Spec carrying only
// SecretFiles — which a caller assembling one by hand may legitimately do — has
// nothing but bytes, and "brokered credentials " with an empty list after it
// would be worse than a generic phrase.
func describeSecretFiles(spec executor.Spec) string {
	if len(spec.Secrets) > 0 {
		return describeBindings(spec.Secrets)
	}
	return "a brokered credential"
}

// newCorrelationID returns an ID for matching a response to its request.
func newCorrelationID() string {
	s, err := randomString(8)
	if err != nil {
		// randomString only fails if the system CSPRNG is broken, at which
		// point every security property in this package is already void. A
		// time-based fallback keeps correlation working rather than failing
		// the request for a reason the caller cannot act on.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return s
}
