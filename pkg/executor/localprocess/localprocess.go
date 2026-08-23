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
	"strconv"
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
	// store persists handle identity so this executor can reattach to the
	// children it forked after the control plane restarts. Guarded by mu
	// because AttachHandleStore installs it long after New has returned, while
	// the output pumps that call ForgetHandle are already running; read it
	// through handleStore(). Nil when the embedder gave none, which degrades to
	// the pre-Task-20191 behaviour. See rehydrate.go.
	store executor.HandleStore
}

// record is the driver's bookkeeping for one started process.
type record struct {
	id        string
	pid       int
	spec      executor.Spec
	startedAt time.Time

	cmd *exec.Cmd

	// adopted is non-nil exactly for records rebuilt from a persisted row by
	// rehydrate.go, and carries the identity token pid must still match.
	//
	// Its nil-ness is load-bearing, because it marks the one difference that
	// matters to Signal. A record this process forked holds an *exec.Cmd whose
	// child has not been reaped while the record is live, and an unreaped child
	// keeps its pid allocated as a zombie — so a forked record's pid provably
	// still names its own workload and can be signalled without a check. An
	// adopted record has no such claim on the number: its process was reaped by
	// init the moment it exited, and the pid became free for anyone. See
	// rehydrate.go's header.
	adopted *procIdentity

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
//
// SupportsWorkspaceProvisioning is false for a different reason, and it is an
// answer rather than a gap: this driver forks in the operator's own working
// directory, so the tree is already there. See Start.
func (e *Executor) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation:              executor.IsolationNone,
		SupportsStream:         true,
		SupportsSignal:         true,
		SupportsResourceLimits: false,
		SharesHostFilesystem:   true,
		NetworkEgress:          true,
		// Stated explicitly rather than left to the zero value: a driver that
		// runs in the host's filesystem has already answered the workspace
		// question, and a reader should not have to infer that from an absence.
		SupportsWorkspaceProvisioning: false,
		Platform:                      runtime.GOOS,
		Arch:                          runtime.GOARCH,
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
	// Bind semantics are this driver's answer to the workspace question, not a
	// missing feature.
	//
	// The child is forked with cmd.Dir = spec.WorkDir on the machine that holds
	// it, so the tree is present before the process exists — which is why
	// WorkspaceBind, WorkspaceNone and the unspecified zero value all pass
	// through untouched; none of them asks this driver for anything.
	//
	// WorkspaceGit is the one that cannot be honoured, and honouring it would be
	// worse than refusing: the clone target is the operator's own checkout, on
	// the machine they are sitting at, and `git init` plus a detached checkout
	// over it would discard uncommitted work that nothing in cloop can restore.
	if spec.Workspace.Kind == executor.WorkspaceGit {
		return executor.Handle{}, fmt.Errorf(
			"%w: the %s executor runs in the host's own filesystem, so the source tree is already "+
				"at %s and cloning into it would overwrite the operator's checkout; "+
				"use a bind workspace here, or dispatch a git workspace to a Kubernetes or remote "+
				"executor, which provision into a directory of their own",
			executor.ErrUnsupported, executor.KindLocalProcess, spec.WorkDir)
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
	store := e.store
	e.mu.Unlock()

	// Capture the pid's identity *before* the pump goroutine exists, and this
	// ordering is the correctness argument for the whole rehydration path.
	//
	// The pump is what calls cmd.Wait(), and reaping is what releases the pid
	// back to the kernel's allocator. Until then the child is at worst a zombie
	// whose /proc entry — including the starttime we are reading — is fully
	// present and provably belongs to *this* workload. Reading it after the
	// pump had started would introduce a window in which a fast-exiting child
	// is reaped, its pid handed to something else, and this driver persists a
	// stranger's start time as the token that authorises signalling it.
	//
	// A failure here is not a failed start. It costs this handle the ability to
	// survive a restart, which is exactly the behaviour that existed before the
	// row did, and reporting a running workload as failed over an unreadable
	// procfs would be a far larger regression than the one it guards.
	ident, _, identErr := probeProcess(rec.pid)
	if identErr != nil {
		warnNoIdentityOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "localprocess: workloads on this host will not survive a "+
				"control-plane restart, because their process identity cannot be read (first seen on "+
				"handle %s, pid %d): %v\n", rec.id, rec.pid, identErr)
		})
	}

	// Persist identity after the map insert, never before. The two orders differ
	// only in what a crash between them leaves behind, and the asymmetry is
	// decisive: this one can lose a row for a process that is running, which
	// degrades to the pre-Task-20191 behaviour. The other would leave a row for a
	// process that was never forked, whose pid the next boot would adopt, verify
	// against a stranger's start time, and — because the identity would not
	// match — report to a caller as a failed run that never ran.
	//
	// It happens here rather than in the pump because the caller holds a Handle
	// the moment Start returns and is entitled to assume that handle outlives
	// this process. RecordHandle never fails the start: see its doc for why a
	// locked database must not become a spurious task failure.
	// Armed before the row is written so the persisted deadline is the one
	// actually in force, and as an absolute instant so a restart resumes the
	// remaining time rather than restarting the clock.
	var deadline time.Time
	if d := spec.Timeout(); d > 0 {
		deadline = rec.startedAt.Add(d)
		e.armKillTimer(rec, d, fmt.Sprintf("timeout after %s", d))
	}

	executor.RecordHandle(store, executor.HandleRecord{
		HandleID:   rec.id,
		ExecutorID: e.id,
		Driver:     executor.KindLocalProcess,
		// The pid as decimal. It is the only handle the operating system will
		// answer for a process, and everything reattachment does is built on it —
		// which is also why it is never trusted on its own; see Meta.
		ExternalID:  strconv.Itoa(rec.pid),
		ProjectPath: spec.WorkDir,
		TaskID:      taskIDFromLabels(spec.Labels),
		PID:         rec.pid,
		StartedAt:   rec.startedAt,
		Deadline:    deadline,
		// The boot id and start time that turn the pid above from a recycled
		// integer into an identity. Nil when they could not be read, in which
		// case the row is still written — a sweep can still see that a workload
		// exists — but adoption will decline it rather than guess.
		Meta: ident.meta(),
	})

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
			e.finish(rec, executor.StateFailed, -1, fmt.Sprintf("output pump panic: %v", r))
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
	e.finish(rec, state, exitCode, errMsg)
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
	adopted := rec.adopted
	rec.mu.Unlock()
	if !running {
		return nil
	}
	// Re-prove the pid before delivering anything to an adopted handle.
	//
	// Verifying once at adoption is not enough, and the gap is not theoretical:
	// an adopted process can exit at any moment, its pid can be reused
	// immediately, and the watcher only notices at its next poll. A Stop pressed
	// inside that window would deliver SIGKILL to whatever inherited the number
	// — a database, an ssh session, the operator's own shell. Checking here
	// narrows the exposure to the microseconds between this read and the
	// os.FindProcess below, and on Linux 5.3+ even that half is covered by the
	// kernel: os.FindProcess opens a pidfd, so the signal lands on the process
	// that held the pid when the descriptor was opened rather than on whoever
	// holds it when the signal is sent. Closing the remaining sliver entirely
	// needs a pidfd held from verification time, which needs a dependency this
	// module does not have — see rehydrate.go's adoptPollInterval.
	//
	// A failure is not reported as a signal error. The caller asked for the
	// workload to stop, and the workload is not running: that request is
	// satisfied. What it does mean is that the handle is finished and its row
	// dropped, so the next Status says why instead of claiming it is still up.
	if adopted != nil {
		if err := adopted.verify(pid); err != nil {
			msg := watchFailureMessage(pid, err)
			rec.emit("[cloop] " + msg + "\n")
			e.finish(rec, executor.StateFailed, -1, msg)
			return nil
		}
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

// armKillTimer schedules a SIGKILL after d and records reason as the cause.
//
// Shared by Start and by adoption (see rehydrate.go) so a timeout resumed
// across a restart is enforced by exactly the same mechanism as the one it
// interrupted. A non-positive d fires immediately, which is what an adopted
// workload whose deadline passed while the control plane was down deserves:
// the timeout expired, and nobody having been there to enforce it is not a
// reprieve.
//
// It signals rec.pid rather than the *exec.Cmd because an adopted record has
// no Cmd. For an adopted record that pid is safe only because adopt verified
// the process's identity before arming this — see rehydrate.go, where the same
// reasoning keeps Signal from reaching a stranger that inherited the number.
func (e *Executor) armKillTimer(rec *record, d time.Duration, reason string) {
	if d < 0 {
		d = 0
	}
	timer := time.AfterFunc(d, func() {
		rec.markKilled(reason)
		_ = signalProcess(rec.pid, executor.SignalKill)
	})
	// Under rec.mu because finish reads the field to stop the timer, and it
	// can run concurrently once the pump or the adoption watcher is up.
	rec.mu.Lock()
	rec.killTimer = timer
	rec.mu.Unlock()
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

// finished reports whether the record has already reached its terminal state.
// Used by the adopted-process watcher to stop polling a handle that Signal has
// already retired.
func (r *record) finished() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// finish records the terminal state, drops the handle's durable row, and
// releases every subscriber. Called at most once per record — from the output
// pump for a forked workload, from the watcher or Signal for an adopted one.
//
// It hangs off the Executor rather than the record so it can reach the handle
// store, matching the container and Kubernetes drivers, where e.finish exists
// for the same reason.
func (e *Executor) finish(rec *record, state executor.State, exitCode int, errMsg string) {
	rec.mu.Lock()
	if rec.closed {
		rec.mu.Unlock()
		return
	}
	rec.closed = true
	// A kill we requested wins over the exit status the kernel reports,
	// which would otherwise look like an ordinary signal death.
	if rec.state == executor.StateKilled && state == executor.StateExited {
		state = executor.StateKilled
	}
	if rec.state == executor.StateKilled && errMsg == "" {
		errMsg = rec.errMsg
	}
	rec.state = state
	rec.exitCode = exitCode
	rec.finishedAt = time.Now()
	if errMsg != "" {
		rec.errMsg = errMsg
	}
	final := rec.state
	// Stopping the timeout timer belongs here rather than in the output pump,
	// and for an adopted record it is a safety requirement rather than tidiness.
	// An adopted record finishes through the watcher, which never touches the
	// pump — so a timer left armed would fire after the process had exited and
	// deliver SIGKILL to rec.pid, a number the kernel may by then have handed
	// to something else entirely. That is the recycled-pid kill that adopt's
	// whole identity check exists to make impossible, arriving by the back door.
	timer := rec.killTimer
	rec.killTimer = nil
	subs := make([]*subscriber, 0, len(rec.subscribers))
	for sub := range rec.subscribers {
		subs = append(subs, sub)
	}
	rec.subscribers = make(map[*subscriber]struct{})
	rec.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}

	// The workload is over, so its durable identity has nobody left to serve —
	// nothing can reattach to a process that has exited. Dropping the row here
	// is also what stops a handle whose pid turned out to be recycled from
	// being re-adopted and re-failed on every subsequent boot.
	//
	// Gated on a terminal state, and the gate is the point rather than a
	// formality. Every call today passes a terminal state, but the moment this
	// driver grows a Close() that retires live handles as StateUnknown while
	// deliberately leaving their processes running — which is what a graceful
	// control-plane shutdown is — an ungated delete would erase the identity of
	// every workload in flight at precisely the moment rehydration exists to
	// serve, and the next boot would come up with an empty map and a host full
	// of orphaned children. The Kubernetes driver hit exactly that; the gate is
	// how it stopped hitting it.
	//
	// It sits after the rec.closed guard so a double finish writes once, and
	// outside rec.mu because handleStore() takes e.mu and the lock order in this
	// driver is e.mu before rec.mu (see pruneLocked).
	if final.Terminal() {
		executor.ForgetHandle(e.handleStore(), rec.id)
	}

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
