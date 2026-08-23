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
	// writeBack is the in-flight assembly of this workload's work product.
	// Nil until the device sends its first result frame; see writeback.go.
	writeBack *writeBackState
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
	// Now overrides the clock for tests.
	Now func() time.Time
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
	// leaseHandles maps a secret lease ID to the handles started with its
	// material, so a revocation knows which tasks to kill and whether this
	// executor is holding the credential at all.
	leaseHandles map[string]map[string]struct{}
	// store persists handle identity across control-plane restarts. It is a
	// field of its own rather than a read of opts.HandleStore because
	// AttachHandleStore may install it after construction, while the session
	// read loop is already calling applyStatus — and opts is otherwise treated
	// as immutable. Guarded by mu; read through handleStore().
	store executor.HandleStore

	// revocations is the log of leases this executor has been told to give
	// back, retained across disconnects so they can be replayed. See
	// revoke.go.
	revocations *revocationLog
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
	e := &Executor{
		id:           opts.ID,
		name:         opts.Name,
		opts:         opts,
		caps:         opts.Capabilities,
		handles:      make(map[string]*handleState),
		leaseHandles: make(map[string]map[string]struct{}),
		revocations:  newRevocationLog(),
		status:       StatusOffline,
		store:        opts.HandleStore,
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
	caps := e.AgentCapabilities().Executor()
	if sess := e.currentSession(); sess != nil {
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
		// Nothing about the device narrows this one — writing a file needs no
		// tool — so the session's version is the whole question. A pre-v6 agent
		// has no frame field to receive the bytes in, and placement must see
		// that before it routes a lease that delivers files here.
		if !SupportsSecretFiles(sess.Version()) {
			caps.SupportsSecretFiles = false
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
func (e *Executor) Start(ctx context.Context, spec executor.Spec) (handle executor.Handle, err error) {
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
		return executor.Handle{}, fmt.Errorf(
			"%w: agent %s (%s) speaks protocol v%d but this workload carries %s, which the control "+
				"plane must be able to revoke mid-run (needs v%d); upgrade the agent with "+
				"`cloop executor agent install --upgrade`, or remove the grant from this project",
			ErrRevocationUnsupported, e.id, e.name, sess.Version(),
			describeBindings(revocable), MinRevocationVersion)
	}

	// The same placement rule for the workspace, and the reason it is a refusal
	// rather than a best effort is stated at MinWorkspaceVersion: an older agent
	// does not reject the credential field, it ignores it — and then runs the
	// harness against the empty directory it created.
	if spec.Workspace.NeedsProvisioning() && !SupportsWorkspaceProvisioning(sess.Version()) {
		return executor.Handle{}, fmt.Errorf(
			"%w: agent %s (%s) speaks protocol v%d but this workload's source tree has to be cloned "+
				"from %s by the device (needs v%d); upgrade the agent with "+
				"`cloop executor agent install --upgrade`, or run this project on an executor that "+
				"shares the control plane's filesystem",
			ErrWorkspaceUnsupported, e.id, e.name, sess.Version(),
			spec.Workspace.Repo, MinWorkspaceVersion)
	}

	// And the same rule for the lease's credential files. An older agent ignores
	// StartPayload.SecretFiles exactly as it ignores any unknown field, then runs
	// the harness with GIT_CONFIG_GLOBAL, KUBECONFIG and CLOOP_LEASE_DIR all
	// naming a directory that was never created on that machine — so the failure
	// surfaces minutes later as an authentication error the transcript cannot
	// explain. Refusing here is the only place it can be named.
	if spec.NeedsSecretFiles() && !SupportsSecretFiles(sess.Version()) {
		return executor.Handle{}, fmt.Errorf(
			"%w: agent %s (%s) speaks protocol v%d but %s is delivered to this workload as credential "+
				"files the device has to write (needs v%d); upgrade the agent with "+
				"`cloop executor agent install --upgrade`, or remove the grant from this project",
			ErrSecretFilesUnsupported, e.id, e.name, sess.Version(),
			describeSecretFiles(spec), MinSecretFilesVersion)
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
	cred, releaseCred, credErr := e.leaseWorkspace(ctx, spec)
	defer releaseCred()
	if credErr != nil {
		return executor.Handle{}, credErr
	}

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
		bus:       logbus.New(handleID, executor.StreamCombined, logbus.Options{Now: e.opts.now}),
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
	})

	payload := StartPayload{Spec: spec, HandleID: handleID}
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

	frame, err := sess.frame(TypeStart, newCorrelationID(), handleID, payload)
	if err != nil {
		e.dropHandle(handleID)
		return executor.Handle{}, err
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
	hs.status.State = executor.StateRunning
	hs.status.PID = started.PID
	hs.status.StartedAt = startedAt
	hs.mu.Unlock()

	// Recorded only after the agent confirmed the start: a binding for a
	// workload that never ran would make the executor claim to hold a
	// credential it was never given, and a revocation would then wait for an
	// ack that has no reason to exist.
	e.bindLease(handleID, bindingsOf(spec))

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
		hs.bus.Close()
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
	go func() {
		defer func() {
			// A panic here must not take the control plane down with it: the
			// handshake that spawned this goroutine has already returned.
			if r := recover(); r != nil {
				_ = r
			}
		}()
		e.replayRevocations(sess)
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
		hs.mu.Unlock()
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

	hs.mu.Lock()
	if hs.status.StartedAt.IsZero() {
		st.StartedAt = hs.startedAt
	} else if st.StartedAt.IsZero() {
		st.StartedAt = hs.status.StartedAt
	}
	// The write-back is attached to the status rather than reported alongside
	// it because this is the status a consumer reads the instant the log stream
	// closes, and the agent's frame order — chunks, result, then status —
	// guarantees the result has already arrived. A terminal status carrying
	// nothing while a result frame sits on the same handle would make the
	// delivery invisible to executor.Run.
	if hs.writeBack != nil && hs.writeBack.result != nil {
		st.WriteBack = hs.writeBack.result
	}
	hs.status = st
	shouldClose := st.State.Terminal() && !hs.closed
	if shouldClose {
		hs.closed = true
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
		hs.mu.Unlock()
		hs.bus.Close()
	}
}

// bindingsOf projects a spec's secret bindings onto the compact form the
// executor tracks. Only revocable bindings are recorded: a binding that
// delivered nothing has nothing to take back.
func bindingsOf(spec executor.Spec) []leaseBinding {
	revocable := spec.RevocableSecrets()
	if len(revocable) == 0 {
		return nil
	}
	out := make([]leaseBinding, 0, len(revocable))
	for _, b := range revocable {
		out = append(out, leaseBinding{leaseID: b.LeaseID, grantID: b.GrantID})
	}
	return out
}

// describeBindings names the credentials in a refusal, so the operator reads
// "the GitHub PAT github-ci" rather than "a secret".
func describeBindings(bindings []executor.SecretBinding) string {
	names := make([]string, 0, len(bindings))
	for _, b := range bindings {
		switch {
		case b.SecretName != "" && b.Kind != "":
			names = append(names, fmt.Sprintf("%s (%s)", b.SecretName, b.Kind))
		case b.SecretName != "":
			names = append(names, b.SecretName)
		case b.Kind != "":
			names = append(names, b.Kind)
		default:
			names = append(names, b.LeaseID)
		}
	}
	sort.Strings(names)
	if len(names) == 1 {
		return "the brokered credential " + names[0]
	}
	return "brokered credentials " + strings.Join(names, ", ")
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
