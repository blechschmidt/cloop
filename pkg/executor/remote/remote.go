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
}

// NewExecutor builds a remote executor for an enrolled agent. It starts
// disconnected: Start fails with ErrAgentUnreachable until the device dials in
// and a session attaches.
func NewExecutor(opts Options) (*Executor, error) {
	if opts.ID == "" {
		return nil, fmt.Errorf("%w: remote executor ID is blank", executor.ErrInvalidSpec)
	}
	return &Executor{
		id:      opts.ID,
		name:    opts.Name,
		opts:    opts,
		caps:    opts.Capabilities,
		handles: make(map[string]*handleState),
		status:  StatusOffline,
	}, nil
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
func (e *Executor) Capabilities() executor.Capabilities {
	return e.AgentCapabilities().Executor()
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
func (e *Executor) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
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

	// The control plane names the handle, not the agent. If the start
	// response is lost to a disconnect the workload is still addressable: we
	// can ask about the ID we chose, and a repeated start for a known ID is a
	// no-op on the agent rather than a second copy of the workload.
	handleID, err := randomString(idBytes)
	if err != nil {
		return executor.Handle{}, fmt.Errorf("remote: generate handle id: %w", err)
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
	e.mu.Unlock()

	frame, err := NewFrame(TypeStart, newCorrelationID(), handleID, StartPayload{
		Spec:     spec,
		HandleID: handleID,
	})
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
		return executor.Handle{}, fmt.Errorf("remote: agent %s refused the workload: %s", e.id, started.Error)
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
	frame, err := NewFrame(TypeSignal, newCorrelationID(), handleID, SignalPayload{Signal: sig})
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
	frame, err := NewFrame(TypeStatusReq, newCorrelationID(), handleID, StatusReqPayload{})
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
func (e *Executor) dropHandle(handleID string) {
	e.mu.Lock()
	hs := e.handles[handleID]
	delete(e.handles, handleID)
	e.mu.Unlock()
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

// reconcileResume answers an agent's resume offer.
//
// For each handle the agent still has and the control plane still tracks, the
// answer is "resend from the offset I actually received". Handles the control
// plane has forgotten are omitted, which tells the agent to abandon them
// rather than stream output nobody is listening for.
func (e *Executor) reconcileResume(offers []ResumeHandle) []ResumeAck {
	if len(offers) == 0 {
		return nil
	}
	acks := make([]ResumeAck, 0, len(offers))
	for _, offer := range offers {
		hs, err := e.lookup(offer.HandleID)
		if err != nil {
			continue
		}
		hs.mu.Lock()
		from := hs.receivedOffset
		hs.mu.Unlock()
		acks = append(acks, ResumeAck{HandleID: offer.HandleID, FromOffset: from})
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
