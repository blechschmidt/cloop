// Package localprocess implements the executor.Executor interface by forking
// child processes on the control-plane host.
//
// This is the legacy execution path, extracted verbatim from the raw
// exec.Command calls that used to live in pkg/ui/server.go. It offers no
// isolation whatsoever: workloads inherit the control plane's user,
// filesystem, and network. It exists so the executor abstraction can be
// introduced without a behavior change, and so single-machine installs keep
// working with zero configuration — not because it is a good place to run
// untrusted agent workloads.
//
// Deployments that must not execute agents on the control-plane host should
// bind their projects to an isolated executor and refuse to fall back here.
//
// Behavior preserved from the pre-abstraction code:
//
//   - cmd.Dir is the project directory; an empty WorkDir inherits the
//     server's cwd (the voice handler relies on this).
//   - The environment is inherited unless the Spec overrides it.
//   - stdout and stderr are merged into one os.Pipe, exactly as the live-log
//     panel expects.
//   - No new process group: children stay in the control plane's group, so a
//     Ctrl-C on an interactively-run server still reaches them.
//   - The real OS PID is reported, which is what the /proc scan in
//     pkg/multiui (CloopRunPIDsInDir → the Stop button) matches against.
//   - Started workloads outlive the request that started them.
package localprocess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// DefaultID is the executor ID used by the zero-config singleton.
const DefaultID = "local"

const (
	// readChunkSize matches the buffer the old handleRun output pump used.
	readChunkSize = 4096

	// subscriberBuffer is how many chunks a single Stream consumer may fall
	// behind before its chunks start being dropped. Dropping is mandatory:
	// blocking the pump would block the child process's writes once the
	// pipe fills, so a stalled log viewer would stall the agent. Consumers
	// detect drops via gaps in LogLine.Seq.
	subscriberBuffer = 512

	// replayBufferBytes bounds the output retained for consumers that
	// subscribe after Start. It only has to cover the gap between Start
	// returning and Stream being called, so it is deliberately small.
	replayBufferBytes = 64 << 10

	// maxRetainedHandles caps how many finished handles stay queryable via
	// Status. Without a cap a long-lived UI server accumulates one record
	// per run forever.
	maxRetainedHandles = 256
)

// Executor is the host-process driver. Use New or Shared to obtain one.
type Executor struct {
	id string

	mu      sync.Mutex
	handles map[string]*record
}

// record is the driver's bookkeeping for one started process.
type record struct {
	id        string
	pid       int
	spec      executor.Spec
	startedAt time.Time

	cmd *exec.Cmd

	// killTimer enforces Spec.TimeoutMinutes; nil when unbounded.
	killTimer *time.Timer

	mu          sync.Mutex
	state       executor.State
	exitCode    int
	finishedAt  time.Time
	errMsg      string
	seq         uint64
	replay      []executor.LogLine
	replayBytes int
	subscribers map[*subscriber]struct{}
	closed      bool
}

// subscriber is one live Stream consumer.
//
// The mutex guards the send/close pair. Without it, a consumer whose context
// is cancelled (browser tab closed) could close ch while the pump goroutine
// is mid-send on the very same channel — a "send on closed channel" panic in
// the middle of a run. A plain non-blocking select cannot avoid it: when both
// the send and the closed-signal are ready, Go picks at random. Since send is
// always non-blocking, holding this mutex is O(1) and cannot deadlock.
type subscriber struct {
	mu     sync.Mutex
	ch     chan executor.LogLine
	done   chan struct{}
	closed bool
}

// send delivers line unless the subscriber is gone or its buffer is full.
// Dropping is deliberate: blocking here would back-pressure into the child
// process's writes, so one stalled log viewer would stall the agent.
// Consumers detect drops via gaps in LogLine.Seq.
func (s *subscriber) send(line executor.LogLine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- line:
	default:
	}
}

// close shuts the subscriber's channel down exactly once. Called both by the
// pump when the workload ends and by the per-subscriber context watcher.
func (s *subscriber) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
	close(s.ch)
}

// New returns a new host-process executor with the given ID. An empty id
// defaults to DefaultID.
func New(id string) *Executor {
	if strings.TrimSpace(id) == "" {
		id = DefaultID
	}
	return &Executor{id: id, handles: make(map[string]*record)}
}

var (
	sharedOnce sync.Once
	shared     *Executor
)

// Shared returns the process-wide singleton host executor.
func Shared() *Executor {
	sharedOnce.Do(func() { shared = New(DefaultID) })
	return shared
}

// Ensure idempotently registers the singleton host executor into reg,
// which may be nil to mean executor.DefaultRegistry. Safe to call from
// several entry points (CLI bootstrap, UI server construction, tests).
func Ensure(reg *executor.Registry) error {
	if reg == nil {
		reg = executor.DefaultRegistry
	}
	return reg.Ensure(Shared())
}

// ID implements executor.Executor.
func (e *Executor) ID() string { return e.id }

// Kind implements executor.Executor.
func (e *Executor) Kind() string { return executor.KindLocalProcess }

// Capabilities implements executor.Executor. Note SupportsResourceLimits is
// false: this driver cannot enforce CPU/memory caps, and Start rejects Specs
// that request them rather than silently ignoring the request.
func (e *Executor) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation:              executor.IsolationNone,
		SupportsStream:         true,
		SupportsSignal:         true,
		SupportsResourceLimits: false,
		SharesHostFilesystem:   true,
		NetworkEgress:          true,
		Platform:               runtime.GOOS,
		Arch:                   runtime.GOARCH,
	}
}

// HealthCheck verifies the host can still hand out the file descriptors a
// Start needs. File-descriptor exhaustion is the realistic failure mode for
// a long-running control plane, and it manifests as os.Pipe failing.
func (e *Executor) HealthCheck(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("localprocess: host cannot allocate pipes: %w", err)
	}
	_ = r.Close()
	_ = w.Close()
	return nil
}

// Start forks the workload described by spec and returns its handle. The
// child outlives ctx: ctx only bounds the act of starting.
func (e *Executor) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return executor.Handle{}, err
		}
	}
	// Strict no-host-execution mode (Task 20160). Registry.Resolve already
	// refuses to hand this driver out when the policy is off, and produces a
	// better message because it knows the project and the alternatives. This
	// check is the backstop for the other path: a caller holding a direct
	// *localprocess.Executor reference — Shared(), a test, a future
	// code path that skips Resolve — must not be able to fork on the host
	// just because it never asked the registry.
	if !executor.HostExecutionAllowed() {
		return executor.Handle{}, &executor.HostExecutionDeniedError{
			ExecutorID:   e.id,
			ProjectPath:  spec.WorkDir,
			Alternatives: executor.IsolatedIDs(),
		}
	}
	if err := spec.Validate(); err != nil {
		return executor.Handle{}, err
	}
	if !spec.ResourceLimits.IsZero() {
		// Fail closed. A caller that asked for a 512 MB cap and silently
		// received none would believe it had a guarantee it does not have.
		return executor.Handle{}, fmt.Errorf(
			"%w: the %s executor cannot enforce resource limits — bind this project to a container or remote executor",
			executor.ErrUnsupported, executor.KindLocalProcess)
	}
	if spec.WorkDir != "" {
		info, err := os.Stat(spec.WorkDir)
		if err != nil {
			return executor.Handle{}, fmt.Errorf("%w: work_dir %q: %w", executor.ErrInvalidSpec, spec.WorkDir, err)
		}
		if !info.IsDir() {
			return executor.Handle{}, fmt.Errorf("%w: work_dir %q is not a directory", executor.ErrInvalidSpec, spec.WorkDir)
		}
	}

	// Merge stdout and stderr into one pipe: the live-log panel renders a
	// single interleaved stream, and splitting them here would reorder
	// output relative to what a terminal user sees.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return executor.Handle{}, fmt.Errorf("localprocess: create output pipe: %w", err)
	}

	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...) //nolint:gosec — argv is caller-supplied, never shell-interpreted
	cmd.Dir = spec.WorkDir
	if spec.Env != nil {
		cmd.Env = spec.Env
	}
	cmd.Stdout = pipeW
	cmd.Stderr = pipeW

	if err := cmd.Start(); err != nil {
		_ = pipeR.Close()
		_ = pipeW.Close()
		return executor.Handle{}, fmt.Errorf("localprocess: start %q: %w", spec.Argv[0], err)
	}
	// The parent never writes to the pipe; closing its end is what makes the
	// reader see EOF once the child (and anything that inherited the fd)
	// exits.
	_ = pipeW.Close()

	rec := &record{
		id:          newHandleID(),
		pid:         cmd.Process.Pid,
		spec:        spec,
		startedAt:   time.Now(),
		cmd:         cmd,
		state:       executor.StateRunning,
		subscribers: make(map[*subscriber]struct{}),
	}

	e.mu.Lock()
	e.handles[rec.id] = rec
	e.pruneLocked()
	e.mu.Unlock()

	if d := spec.Timeout(); d > 0 {
		rec.killTimer = time.AfterFunc(d, func() {
			rec.markKilled(fmt.Sprintf("timeout after %s", d))
			_ = signalProcess(rec.pid, executor.SignalKill)
		})
	}

	go e.pump(rec, pipeR)

	return executor.Handle{
		ID:         rec.id,
		ExecutorID: e.id,
		PID:        rec.pid,
		StartedAt:  rec.startedAt,
	}, nil
}

// pump drains the child's output pipe, fans chunks out to subscribers, reaps
// the process, and finally closes every subscriber channel.
//
// The close happens strictly *after* cmd.Wait() so that a consumer which
// observes the channel closing can immediately read a terminal Status —
// executor.Run depends on that ordering.
func (e *Executor) pump(rec *record, pipeR *os.File) {
	defer func() {
		if r := recover(); r != nil {
			// A panic here would silently strand the handle in "running"
			// forever and leak the subscriber channels.
			fmt.Fprintf(os.Stderr, "localprocess: output pump panic recovered (handle %s): %v\n", rec.id, r)
			rec.finish(executor.StateFailed, -1, fmt.Sprintf("output pump panic: %v", r))
		}
	}()

	buf := make([]byte, readChunkSize)
	for {
		n, readErr := pipeR.Read(buf)
		if n > 0 {
			rec.emit(string(buf[:n]))
		}
		if readErr != nil {
			break
		}
	}
	_ = pipeR.Close()

	waitErr := rec.cmd.Wait()
	if rec.killTimer != nil {
		rec.killTimer.Stop()
	}

	exitCode := 0
	state := executor.StateExited
	errMsg := ""
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
			// ExitCode() is -1 when the process was terminated by a signal.
			if exitCode == -1 {
				state = executor.StateKilled
			}
		} else {
			// Wait itself failed (I/O error, already reaped): we no longer
			// know what happened to the child.
			state = executor.StateFailed
			exitCode = -1
			errMsg = waitErr.Error()
		}
	}
	rec.finish(state, exitCode, errMsg)
}

// Signal implements executor.Executor. Signalling a finished handle is a
// no-op success: the caller wanted it stopped and it is stopped.
func (e *Executor) Signal(ctx context.Context, handleID string, sig executor.Signal) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if !sig.Valid() {
		return fmt.Errorf("%w: %q", executor.ErrInvalidSignal, sig)
	}
	rec, err := e.lookup(handleID)
	if err != nil {
		return err
	}
	rec.mu.Lock()
	running := rec.state == executor.StateRunning || rec.state == executor.StatePending
	pid := rec.pid
	rec.mu.Unlock()
	if !running {
		return nil
	}
	if sig == executor.SignalKill {
		// Record the intent before delivering it so a Status read that
		// races the reaper reports "killed" rather than a bare exit.
		rec.markKilled("killed by signal request")
	}
	if err := signalProcess(pid, sig); err != nil {
		return fmt.Errorf("localprocess: signal %s to pid %d: %w", sig, pid, err)
	}
	return nil
}

// Status implements executor.Executor.
func (e *Executor) Status(ctx context.Context, handleID string) (executor.Status, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return executor.Status{}, err
		}
	}
	rec, err := e.lookup(handleID)
	if err != nil {
		return executor.Status{}, err
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return executor.Status{
		HandleID:   rec.id,
		ExecutorID: e.id,
		State:      rec.state,
		PID:        rec.pid,
		ExitCode:   rec.exitCode,
		StartedAt:  rec.startedAt,
		FinishedAt: rec.finishedAt,
		Error:      rec.errMsg,
	}, nil
}

// HandleStatuses implements executor.Lister: a snapshot of every retained handle,
// running or recently finished. The Executors panel derives its "current
// load" column from this.
func (e *Executor) HandleStatuses(ctx context.Context) ([]executor.Status, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	e.mu.Lock()
	recs := make([]*record, 0, len(e.handles))
	for _, rec := range e.handles {
		recs = append(recs, rec)
	}
	e.mu.Unlock()

	// Per-record locks are taken outside e.mu: the pump goroutine holds a
	// record lock while it appends output, and grabbing e.mu underneath it
	// would invert the driver's lock order.
	out := make([]executor.Status, 0, len(recs))
	for _, rec := range recs {
		rec.mu.Lock()
		out = append(out, executor.Status{
			HandleID:   rec.id,
			ExecutorID: e.id,
			State:      rec.state,
			PID:        rec.pid,
			ExitCode:   rec.exitCode,
			StartedAt:  rec.startedAt,
			FinishedAt: rec.finishedAt,
			Error:      rec.errMsg,
		})
		rec.mu.Unlock()
	}
	return out, nil
}

// Stream implements executor.Executor. The returned channel first replays
// the bounded output backlog produced since Start, then delivers live
// chunks, then closes when the workload has finished and been reaped.
//
// Cancelling ctx unsubscribes this consumer only; the workload and any other
// consumers are unaffected.
func (e *Executor) Stream(ctx context.Context, handleID string) (<-chan executor.LogLine, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec, err := e.lookup(handleID)
	if err != nil {
		return nil, err
	}

	sub := &subscriber{
		ch:   make(chan executor.LogLine, subscriberBuffer),
		done: make(chan struct{}),
	}

	rec.mu.Lock()
	// Replay under the lock so a chunk emitted concurrently cannot slip
	// between the backlog copy and the subscription (which would deliver it
	// out of order or not at all).
	for _, line := range rec.replay {
		sub.send(line)
	}
	alreadyDone := rec.closed
	if !alreadyDone {
		rec.subscribers[sub] = struct{}{}
	}
	rec.mu.Unlock()

	if alreadyDone {
		// Workload already finished: deliver the backlog and close.
		sub.close()
		return sub.ch, nil
	}

	// Watch ctx so an abandoned consumer is unsubscribed. The goroutine is
	// bounded by whichever comes first: ctx cancellation or the workload
	// finishing (which closes sub.closed).
	go func() {
		select {
		case <-ctx.Done():
			rec.removeSubscriber(sub)
		case <-sub.done:
		}
	}()

	return sub.ch, nil
}

// Handles returns the IDs of every handle this executor still knows about,
// newest first. Used for diagnostics and by tests.
func (e *Executor) Handles() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	recs := make([]*record, 0, len(e.handles))
	for _, rec := range e.handles {
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].startedAt.After(recs[j].startedAt) })
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.id)
	}
	return out
}

// lookup resolves a handle ID to its record.
func (e *Executor) lookup(handleID string) (*record, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.handles[handleID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", executor.ErrHandleNotFound, handleID)
	}
	return rec, nil
}

// pruneLocked drops the oldest finished handles once the retention cap is
// exceeded. Running handles are never pruned. Caller holds e.mu.
func (e *Executor) pruneLocked() {
	if len(e.handles) <= maxRetainedHandles {
		return
	}
	type aged struct {
		id string
		at time.Time
	}
	var finished []aged
	for id, rec := range e.handles {
		rec.mu.Lock()
		done := rec.state.Terminal()
		at := rec.finishedAt
		rec.mu.Unlock()
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

// emit fans one output chunk out to every subscriber and appends it to the
// bounded replay backlog.
func (r *record) emit(text string) {
	if text == "" {
		return
	}
	r.mu.Lock()
	r.seq++
	line := executor.LogLine{
		HandleID: r.id,
		Stream:   executor.StreamCombined,
		Text:     text,
		Time:     time.Now(),
		Seq:      r.seq,
	}
	r.replay = append(r.replay, line)
	r.replayBytes += len(text)
	for r.replayBytes > replayBufferBytes && len(r.replay) > 1 {
		r.replayBytes -= len(r.replay[0].Text)
		r.replay = r.replay[1:]
	}
	subs := make([]*subscriber, 0, len(r.subscribers))
	for sub := range r.subscribers {
		subs = append(subs, sub)
	}
	r.mu.Unlock()

	// Sent outside r.mu so a slow consumer cannot serialize the pump against
	// Stream/Status; sub.send does its own locking against a concurrent
	// close.
	for _, sub := range subs {
		sub.send(line)
	}
}

// removeSubscriber unsubscribes and closes sub. Idempotent.
func (r *record) removeSubscriber(sub *subscriber) {
	r.mu.Lock()
	delete(r.subscribers, sub)
	r.mu.Unlock()
	sub.close()
}

// markKilled records that termination was requested, so the final Status
// reports StateKilled instead of a plain non-zero exit. It does not itself
// deliver a signal.
func (r *record) markKilled(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.Terminal() {
		return
	}
	r.state = executor.StateKilled
	if r.errMsg == "" {
		r.errMsg = reason
	}
}

// finish records the terminal state and releases every subscriber. Called
// exactly once per record, from the pump.
func (r *record) finish(state executor.State, exitCode int, errMsg string) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	// A kill we requested wins over the exit status the kernel reports,
	// which would otherwise look like an ordinary signal death.
	if r.state == executor.StateKilled && state == executor.StateExited {
		state = executor.StateKilled
	}
	if r.state == executor.StateKilled && errMsg == "" {
		errMsg = r.errMsg
	}
	r.state = state
	r.exitCode = exitCode
	r.finishedAt = time.Now()
	if errMsg != "" {
		r.errMsg = errMsg
	}
	subs := make([]*subscriber, 0, len(r.subscribers))
	for sub := range r.subscribers {
		subs = append(subs, sub)
	}
	r.subscribers = make(map[*subscriber]struct{})
	r.mu.Unlock()

	for _, sub := range subs {
		sub.close()
	}
}

// signalProcess maps a driver-independent signal onto a POSIX signal and
// delivers it to pid. Delivering to an already-exited process reports
// os.ErrProcessDone / ESRCH, which callers treat as success.
func signalProcess(pid int, sig executor.Signal) error {
	if pid <= 0 {
		return fmt.Errorf("localprocess: refusing to signal pid %d", pid)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	var osSig os.Signal
	switch sig {
	case executor.SignalInterrupt:
		osSig = syscall.SIGINT
	case executor.SignalTerminate:
		osSig = syscall.SIGTERM
	case executor.SignalKill:
		osSig = syscall.SIGKILL
	default:
		return fmt.Errorf("%w: %q", executor.ErrInvalidSignal, sig)
	}
	if err := proc.Signal(osSig); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return nil
}

// newHandleID returns a collision-resistant handle ID. Random rather than
// sequential so IDs stay unique across control-plane restarts, which
// matters once handles are persisted alongside remote executors.
func newHandleID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is catastrophic and essentially impossible;
		// fall back to a time-derived ID rather than panicking a UI server.
		return fmt.Sprintf("h-%d", time.Now().UnixNano())
	}
	return "h-" + hex.EncodeToString(b[:])
}
