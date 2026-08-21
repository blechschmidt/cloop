// Package executor defines cloop's pluggable execution backend abstraction.
//
// Historically the Web UI spawned harness processes directly on the host with
// raw exec.Command. That hard-wired three assumptions that no longer hold as
// cloop moves toward a hostable, multi-tenant product:
//
//  1. the machine running the control plane is also the machine running the
//     agent (no remote or edge executors),
//  2. an agent run has the same privileges, filesystem, and network as the UI
//     server itself (no isolation boundary), and
//  3. process lifecycle is expressible only as an *os.Process (no container,
//     no sandbox, no RPC to a remote agent).
//
// This package replaces those assumptions with a driver interface. A driver
// ("executor") knows how to start a process-shaped workload somewhere, stream
// its output back, signal it, and report its status. Where "somewhere" is —
// this host, a container on this host, a sandbox on a remote edge device — is
// the driver's business, not the caller's.
//
// Drivers live in sub-packages (pkg/executor/localprocess is the first) and
// register themselves into a Registry. Callers never construct a driver
// directly; they call Resolve(projectPath) and get whichever executor that
// project is bound to.
//
// Security model: Resolve deliberately fails closed. When a project is bound
// to an executor that is not currently registered, Resolve returns
// ErrExecutorNotFound rather than silently falling back to the local host.
// A project pinned to an isolated executor must never be downgraded to
// host execution because the isolated backend happened to be unreachable.
package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Well-known executor kinds. Kind identifies the *driver implementation*;
// ID identifies a particular configured instance of that driver.
const (
	// KindLocalProcess runs workloads as child processes of the cloop
	// control plane, on the same host, with the same privileges. This is
	// the legacy behavior and offers no isolation.
	KindLocalProcess = "localprocess"

	// KindContainer runs workloads in a container runtime (Docker/Podman)
	// on the control-plane host.
	KindContainer = "container"

	// KindRemoteAgent runs workloads on a remote cloop executor agent that
	// enrolled itself with this control plane over an outbound connection.
	KindRemoteAgent = "remote"
)

// Isolation describes how strongly a driver separates a workload from the
// control-plane host. It is advisory metadata used by the UI and by policy
// checks such as strict no-host-execution mode.
type Isolation string

const (
	// IsolationNone: the workload shares the host's filesystem, network,
	// and user with the control plane.
	IsolationNone Isolation = "none"
	// IsolationContainer: the workload runs in a container with its own
	// filesystem and (optionally) network namespace.
	IsolationContainer Isolation = "container"
	// IsolationVM: the workload runs in a virtual machine or microVM.
	IsolationVM Isolation = "vm"
	// IsolationRemote: the workload runs on a different machine entirely.
	IsolationRemote Isolation = "remote"
)

// Capabilities advertises what a driver can and cannot do. Callers use it to
// degrade gracefully (e.g. hide a "Stop" button for a driver that cannot
// signal) rather than to attempt an operation and handle the error.
type Capabilities struct {
	// Isolation is the strength of the boundary between workload and host.
	Isolation Isolation `json:"isolation"`
	// SupportsStream reports whether Stream returns live output. Drivers
	// that only persist output post-hoc set this false.
	SupportsStream bool `json:"supports_stream"`
	// SupportsSignal reports whether Signal can deliver signals to a
	// running handle.
	SupportsSignal bool `json:"supports_signal"`
	// SupportsResourceLimits reports whether Spec.ResourceLimits is
	// enforced. When false, limits in a Spec are ignored, not an error.
	SupportsResourceLimits bool `json:"supports_resource_limits"`
	// SharesHostFilesystem reports whether Spec.WorkDir refers to a path on
	// the control-plane host. False for remote and for containers with a
	// copied (rather than bind-mounted) workspace.
	SharesHostFilesystem bool `json:"shares_host_filesystem"`
	// NetworkEgress reports whether workloads can reach the network.
	NetworkEgress bool `json:"network_egress"`
	// MaxConcurrent is the advertised ceiling on simultaneously running
	// handles; 0 means unbounded/unknown.
	MaxConcurrent int `json:"max_concurrent,omitempty"`
	// Platform and Arch describe the execution target (GOOS/GOARCH style).
	Platform string `json:"platform,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

// ResourceLimits bounds a single workload. Zero means "no limit requested".
// Drivers that do not advertise SupportsResourceLimits ignore this struct
// entirely rather than failing the Start.
type ResourceLimits struct {
	// CPUMillis is the CPU allowance in thousandths of a core (1000 = 1 CPU).
	CPUMillis int `json:"cpu_millis,omitempty"`
	// MemoryMB is the resident memory ceiling in megabytes.
	MemoryMB int `json:"memory_mb,omitempty"`
	// DiskMB is the writable-layer / scratch-space ceiling in megabytes.
	DiskMB int `json:"disk_mb,omitempty"`
	// PIDs is the maximum number of processes/threads.
	PIDs int `json:"pids,omitempty"`
}

// IsZero reports whether no limit at all was requested.
func (rl ResourceLimits) IsZero() bool {
	return rl.CPUMillis == 0 && rl.MemoryMB == 0 && rl.DiskMB == 0 && rl.PIDs == 0
}

// Validate rejects negative limits. Zero (unset) is always valid.
func (rl ResourceLimits) Validate() error {
	switch {
	case rl.CPUMillis < 0:
		return fmt.Errorf("%w: cpu_millis must be >= 0, got %d", ErrInvalidSpec, rl.CPUMillis)
	case rl.MemoryMB < 0:
		return fmt.Errorf("%w: memory_mb must be >= 0, got %d", ErrInvalidSpec, rl.MemoryMB)
	case rl.DiskMB < 0:
		return fmt.Errorf("%w: disk_mb must be >= 0, got %d", ErrInvalidSpec, rl.DiskMB)
	case rl.PIDs < 0:
		return fmt.Errorf("%w: pids must be >= 0, got %d", ErrInvalidSpec, rl.PIDs)
	}
	return nil
}

// Spec fully describes one workload to start. It is intentionally
// serializable: a remote driver marshals it and ships it to an agent.
type Spec struct {
	// WorkDir is the directory the workload runs in. For host-local drivers
	// this is a real path; for remote drivers it is the path *on the
	// executor*, which the driver is responsible for provisioning.
	WorkDir string `json:"work_dir"`
	// Argv is the command and its arguments. Argv[0] is the program. It is
	// never passed through a shell — no quoting or injection surface.
	Argv []string `json:"argv"`
	// Env is the environment in "K=V" form. A nil Env means "inherit the
	// control plane's environment", matching os/exec semantics; an empty
	// non-nil slice means "start with an empty environment".
	Env []string `json:"env,omitempty"`
	// Labels carry routing and bookkeeping metadata (project path, task ID,
	// requesting user). Drivers may surface them for observability; they
	// never affect execution.
	Labels map[string]string `json:"labels,omitempty"`
	// ResourceLimits bounds the workload where the driver supports it.
	ResourceLimits ResourceLimits `json:"resource_limits,omitempty"`
	// TimeoutMinutes kills the workload after this long. 0 means no
	// timeout — cloop runs are long-lived by design (Task 20148 removed the
	// implicit task timeout), so this must stay opt-in.
	TimeoutMinutes int `json:"timeout_minutes,omitempty"`
}

// Timeout returns the spec's wall-clock ceiling as a duration, or 0 when
// unbounded.
func (s Spec) Timeout() time.Duration {
	if s.TimeoutMinutes <= 0 {
		return 0
	}
	return time.Duration(s.TimeoutMinutes) * time.Minute
}

// Validate checks the driver-independent invariants of a Spec. Drivers add
// their own checks on top (e.g. localprocess requires an existing WorkDir).
func (s Spec) Validate() error {
	if len(s.Argv) == 0 {
		return fmt.Errorf("%w: argv is empty", ErrInvalidSpec)
	}
	if strings.TrimSpace(s.Argv[0]) == "" {
		return fmt.Errorf("%w: argv[0] is blank", ErrInvalidSpec)
	}
	if s.TimeoutMinutes < 0 {
		return fmt.Errorf("%w: timeout_minutes must be >= 0, got %d", ErrInvalidSpec, s.TimeoutMinutes)
	}
	for i, kv := range s.Env {
		if !strings.Contains(kv, "=") {
			return fmt.Errorf("%w: env[%d] %q is not in K=V form", ErrInvalidSpec, i, kv)
		}
	}
	return s.ResourceLimits.Validate()
}

// Handle identifies one started workload. It is the token every subsequent
// operation (Signal, Status, Stream) is keyed by.
type Handle struct {
	// ID is unique within the executor that produced it.
	ID string `json:"id"`
	// ExecutorID is the ID of the executor that owns this handle, so a
	// caller holding only a Handle can find its way back to the driver.
	ExecutorID string `json:"executor_id"`
	// PID is the operating-system process ID *on the executor*. It is 0
	// for drivers where a PID is meaningless or not reported. Host-local
	// tooling (the /proc scan in pkg/multiui that powers the Stop button)
	// relies on this being the real PID for KindLocalProcess.
	PID int `json:"pid,omitempty"`
	// StartedAt is when the workload began, in the control plane's clock.
	StartedAt time.Time `json:"started_at"`
}

// State is the lifecycle phase of a handle.
type State string

const (
	// StatePending: accepted by the driver but not yet running (queued,
	// image pulling, remote agent dispatch in flight).
	StatePending State = "pending"
	// StateRunning: the workload is executing.
	StateRunning State = "running"
	// StateExited: the workload finished on its own; ExitCode is valid.
	StateExited State = "exited"
	// StateFailed: the workload could not be run, or the driver lost track
	// of it; Error explains why.
	StateFailed State = "failed"
	// StateKilled: the workload was terminated by a signal or by its
	// timeout rather than exiting on its own.
	StateKilled State = "killed"
	// StateUnknown: the driver cannot determine the state (e.g. a remote
	// executor is currently unreachable).
	StateUnknown State = "unknown"
)

// Terminal reports whether no further transitions are expected.
func (s State) Terminal() bool {
	return s == StateExited || s == StateFailed || s == StateKilled
}

// Status is a point-in-time snapshot of a handle.
type Status struct {
	HandleID   string    `json:"handle_id"`
	ExecutorID string    `json:"executor_id"`
	State      State     `json:"state"`
	PID        int       `json:"pid,omitempty"`
	ExitCode   int       `json:"exit_code"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// Error carries the driver-side failure detail for StateFailed. It is
	// a string rather than an error so Status stays serializable across
	// the remote-executor boundary.
	Error string `json:"error,omitempty"`
}

// StreamName identifies which output stream a LogLine came from.
type StreamName string

const (
	StreamStdout   StreamName = "stdout"
	StreamStderr   StreamName = "stderr"
	StreamCombined StreamName = "combined"
)

// LogLine is one chunk of workload output.
//
// Despite the name, Text is *not* guaranteed to be exactly one line: drivers
// forward output as it arrives, so a chunk may span several lines or stop
// mid-line. This is deliberate — a harness that prints a progress line
// without a trailing newline must still reach the live log panel promptly,
// which line-buffering would prevent. Consumers needing whole lines should
// buffer on '\n' themselves.
type LogLine struct {
	HandleID string     `json:"handle_id"`
	Stream   StreamName `json:"stream"`
	Text     string     `json:"text"`
	Time     time.Time  `json:"time"`
	// Seq numbers chunks per handle starting at 1. Because drivers must
	// never block a workload's writes waiting for a slow consumer, a
	// subscriber that falls too far behind has chunks dropped. A gap in
	// Seq is how a consumer detects that; see Run, which reports it.
	Seq uint64 `json:"seq"`
}

// Signal is a driver-independent termination request. Concrete OS signal
// numbers are a host-execution detail that a container or remote driver may
// not be able to express, so the interface speaks in intent.
type Signal string

const (
	// SignalInterrupt asks the workload to stop gracefully (SIGINT).
	// cloop runs trap this and checkpoint before exiting.
	SignalInterrupt Signal = "interrupt"
	// SignalTerminate asks the workload to stop (SIGTERM).
	SignalTerminate Signal = "terminate"
	// SignalKill stops the workload immediately and unconditionally.
	SignalKill Signal = "kill"
)

// Valid reports whether sig is one of the known signals.
func (sig Signal) Valid() bool {
	switch sig {
	case SignalInterrupt, SignalTerminate, SignalKill:
		return true
	}
	return false
}

// Executor is a pluggable execution backend.
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Context handling: the ctx passed to each method governs *that call*, not
// the lifetime of the workload. Cancelling the ctx passed to Start does not
// kill the started workload — it only aborts the act of starting it. This
// matters because the Web UI starts long-lived runs from short-lived HTTP
// request handlers; tying workload lifetime to the request context would
// kill every run the moment its originating request returned. Callers that
// *do* want ctx-bound lifetime should use Run.
type Executor interface {
	// ID returns the stable, unique identifier of this executor instance.
	ID() string
	// Kind returns the driver implementation name (one of the Kind* consts).
	Kind() string
	// Capabilities describes what this executor supports.
	Capabilities() Capabilities
	// Start launches a workload and returns its handle. The workload
	// outlives ctx.
	Start(ctx context.Context, spec Spec) (Handle, error)
	// Signal delivers sig to a running handle. Signalling an
	// already-finished handle returns nil (the desired end state already
	// holds); an unknown handle returns ErrHandleNotFound.
	Signal(ctx context.Context, handleID string, sig Signal) error
	// Status reports the current state of a handle.
	Status(ctx context.Context, handleID string) (Status, error)
	// Stream returns a channel of output chunks for a handle. The channel
	// is closed when the workload finishes and all output has been
	// delivered. Output produced between Start and Stream is replayed
	// (bounded) so callers do not race the workload's first writes.
	// Cancelling ctx unsubscribes the caller without affecting the
	// workload or other subscribers.
	Stream(ctx context.Context, handleID string) (<-chan LogLine, error)
	// HealthCheck reports whether this executor is able to accept work.
	HealthCheck(ctx context.Context) error
}

// Sentinel errors. Callers use errors.Is against these; drivers wrap them
// with %w and add detail.
var (
	// ErrHandleNotFound: the handle ID is unknown to this executor.
	ErrHandleNotFound = errors.New("executor: handle not found")
	// ErrExecutorNotFound: no executor with the requested ID is registered.
	ErrExecutorNotFound = errors.New("executor: executor not registered")
	// ErrAlreadyRegistered: an executor with this ID is already registered.
	ErrAlreadyRegistered = errors.New("executor: executor already registered")
	// ErrNoDefault: the registry has no default executor to fall back to.
	ErrNoDefault = errors.New("executor: no default executor configured")
	// ErrInvalidSpec: the Spec failed validation.
	ErrInvalidSpec = errors.New("executor: invalid spec")
	// ErrInvalidSignal: the requested signal is not one of the known kinds.
	ErrInvalidSignal = errors.New("executor: invalid signal")
	// ErrUnsupported: the driver does not implement this operation; check
	// Capabilities first.
	ErrUnsupported = errors.New("executor: operation not supported by this executor")
	// ErrHostExecutionDenied: policy forbids running this workload on the
	// control-plane host. Reserved for strict no-host-execution mode.
	ErrHostExecutionDenied = errors.New("executor: host execution denied by policy")
)

// RunResult is the outcome of a synchronous Run.
type RunResult struct {
	Handle Handle
	Status Status
	// Output is the workload's combined stdout+stderr.
	Output []byte
	// Dropped is true when the consumer fell behind and chunks were
	// discarded, so Output is incomplete. Detected via LogLine.Seq gaps.
	Dropped bool
}

// runOutputCap bounds how much output Run buffers in memory. A misbehaving
// workload that prints unboundedly must not OOM the control plane; callers
// of Run only ever want an error message or a short report, so 4 MiB is
// generous. Excess is discarded from the *front* so the tail — where the
// error message lives — survives.
const runOutputCap = 4 << 20

// Run starts spec on ex, collects its combined output, and blocks until the
// workload finishes.
//
// Unlike Start, Run *does* tie the workload to ctx: if ctx is cancelled or
// its deadline expires before the workload exits, the handle is killed and
// the ctx error is returned alongside whatever output was collected. This
// gives callers the familiar exec.CommandContext semantics on top of the
// lifetime-independent primitives.
//
// The returned error is non-nil when the workload could not be started, when
// ctx fired, or when the workload exited non-zero; RunResult is still
// populated in the latter two cases so callers can show the output.
func Run(ctx context.Context, ex Executor, spec Spec) (RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ex == nil {
		return RunResult{}, fmt.Errorf("%w: nil executor", ErrExecutorNotFound)
	}

	// Start is deliberately given a context that cannot be cancelled by the
	// caller's ctx: we want to own the handle for cleanup. If ctx is
	// already dead, bail before spawning anything.
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}

	handle, err := ex.Start(context.WithoutCancel(ctx), spec)
	if err != nil {
		return RunResult{}, err
	}
	result := RunResult{Handle: handle}

	// Subscribe with a context we control so we can unsubscribe on return
	// without killing the workload's other subscribers.
	streamCtx, unsubscribe := context.WithCancel(context.WithoutCancel(ctx))
	defer unsubscribe()

	lines, err := ex.Stream(streamCtx, handle.ID)
	if err != nil && !errors.Is(err, ErrUnsupported) {
		// We started something we can no longer observe — kill it rather
		// than leaking an unsupervised workload.
		_ = ex.Signal(context.WithoutCancel(ctx), handle.ID, SignalKill)
		return result, fmt.Errorf("executor: stream %s: %w", handle.ID, err)
	}

	var (
		buf     []byte
		nextSeq uint64 = 1
		ctxErr  error
	)

collect:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break collect
			}
			if line.Seq != 0 {
				if line.Seq != nextSeq {
					result.Dropped = true
				}
				nextSeq = line.Seq + 1
			}
			buf = append(buf, line.Text...)
			if len(buf) > runOutputCap {
				// Keep the tail: errors surface at the end of output.
				buf = buf[len(buf)-runOutputCap:]
				result.Dropped = true
			}
		case <-ctx.Done():
			ctxErr = ctx.Err()
			_ = ex.Signal(context.WithoutCancel(ctx), handle.ID, SignalKill)
			// Keep draining until the driver closes the channel so we
			// return the output produced before the kill.
			for line := range lines {
				buf = append(buf, line.Text...)
				if len(buf) > runOutputCap {
					buf = buf[len(buf)-runOutputCap:]
					result.Dropped = true
				}
			}
			break collect
		}
	}
	result.Output = buf

	// Status is read with a detached context: the caller's ctx may already
	// be dead, and we still want the exit code.
	statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if st, statusErr := ex.Status(statusCtx, handle.ID); statusErr == nil {
		result.Status = st
	}

	switch {
	case ctxErr != nil:
		return result, ctxErr
	case result.Status.State == StateFailed && result.Status.Error != "":
		return result, fmt.Errorf("executor: workload failed: %s", result.Status.Error)
	case result.Status.State == StateKilled:
		return result, fmt.Errorf("executor: workload was killed")
	case result.Status.ExitCode != 0:
		return result, fmt.Errorf("executor: exit status %d", result.Status.ExitCode)
	}
	return result, nil
}
