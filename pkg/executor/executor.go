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

	// KindKubernetes runs each workload as an ephemeral Pod in a Kubernetes
	// cluster, using a kubeconfig brokered as a short-lived lease rather than
	// a file on the control-plane host.
	KindKubernetes = "kubernetes"
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
	// Virtualized reports whether the workload runs behind a hypervisor — a
	// VM or microVM with a kernel of its own — rather than sharing the
	// executing machine's kernel.
	//
	// It is a separate field rather than a reading of Isolation because the
	// two answer different questions and a driver can need both. A Kata pod
	// on a remote cluster is IsolationRemote (the machine is not ours) *and*
	// virtualized (the kernel is not the node's); collapsing that into one
	// enum value would force every such driver to drop one of the two facts,
	// and Isolation is explicitly not a total order (see placement.go).
	//
	// It stays false unless the driver is certain. A requirement to run
	// virtualized is checked against this field, so a false positive places a
	// workload that must be behind a hypervisor onto one that is not.
	Virtualized bool `json:"virtualized,omitempty"`
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
	// FilteredEgress reports whether that reach is bounded at the IP layer
	// by a policy cloop installs — an nftables ruleset on the sandbox
	// bridge, an --internal runtime network, or a Kubernetes NetworkPolicy.
	//
	// It is separate from NetworkEgress because the two answer different
	// questions, and conflating them loses both. NetworkEgress says whether
	// the workload has an interface at all, which is what placement needs;
	// this says whether what it reaches through that interface is
	// constrained, which is what an operator auditing the fleet needs.
	//
	// False does not mean "nothing filters this" — a cluster may run its own
	// NetworkPolicy, an operator may firewall the host — it means cloop is
	// not the thing doing it and will not claim credit for it.
	FilteredEgress bool `json:"filtered_egress"`
	// SupportsImageOverride reports whether Spec.Image is honoured. It is
	// false for drivers with no image concept at all (localprocess) and for
	// drivers whose image is fixed by the operator, and it is what lets a
	// project carrying a .cloop/sandbox.yaml be refused *before* it runs
	// with the wrong toolchain rather than after.
	SupportsImageOverride bool `json:"supports_image_override"`
	// SupportsSandboxBuild reports whether Spec.SetupCommands can be baked
	// into a derived image. Building needs a builder on the executor, which
	// a driver that only schedules pre-built images does not have.
	SupportsSandboxBuild bool `json:"supports_sandbox_build"`
	// SupportsWorkspaceProvisioning reports whether this driver can
	// materialise a source tree itself (Spec.Workspace.Kind == "git").
	//
	// It is what makes a non-local executor honest. A driver that ignored the
	// field would start the harness in an empty directory, and the run would
	// look like a working run producing inexplicable output — which is the
	// exact failure this capability exists to turn into a refusal at
	// placement time. Drivers that share the host filesystem report false and
	// are given Kind "bind" instead, because their tree is already there.
	SupportsWorkspaceProvisioning bool `json:"supports_workspace_provisioning"`
	// SupportsWriteBack reports whether this driver can return the files a
	// workload changed (Spec.WriteBack).
	//
	// Separate from SupportsWorkspaceProvisioning even though the same drivers
	// implement both, because they are two different halves of the run and a
	// driver can genuinely have one without the other — an executor that
	// shares the host filesystem needs neither, and one whose transport cannot
	// carry bytes back can fetch but not return. Every field a driver can
	// quietly drop needs a flag that says so, and this is the one whose
	// omission costs work rather than confusion.
	SupportsWriteBack bool `json:"supports_write_back"`
	// SupportsSandboxMounts reports whether Spec.Mounts is honoured.
	//
	// It is tracked separately from SupportsImageOverride even though the same
	// two drivers implement both, because the failure mode of getting it wrong
	// is silent: a driver that ignores Mounts produces a sandbox that starts,
	// runs, and cannot find the cache directory the project told it to expect.
	// Every field a driver can quietly drop needs a flag that says so.
	SupportsSandboxMounts bool `json:"supports_sandbox_mounts"`
	// SupportsHostMounts reports whether Spec.HostMounts is honoured — i.e.
	// whether this driver can bind a path from the control-plane host into
	// the sandbox.
	//
	// It is not implied by SharesHostFilesystem, and the two are genuinely
	// different answers. localprocess shares the filesystem and cannot bind
	// anything: a granted repository is simply already visible at its own
	// path there. A remote agent can bind, but not paths from *this* host,
	// which it has never seen. Only a driver that both runs here and has a
	// mount namespace to bind into can honour the field, and a driver that
	// ignored it would start a harness whose /repos is empty.
	SupportsHostMounts bool `json:"supports_host_mounts"`
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

	// --- per-project sandbox (Task 20173) --------------------------------
	//
	// These fields carry a project's .cloop/sandbox.yaml down to a driver.
	// They are primitives rather than a nested spec type on purpose: pkg/config
	// already imports the container and Kubernetes drivers, so the package that
	// parses the YAML (pkg/sandbox, which needs config's clamping bounds) can
	// never be imported *by* a driver without an import cycle. Keeping the wire
	// shape primitive means the drivers depend on the contract, not the parser —
	// which is also what lets a remote agent receive one over JSON.

	// Image overrides the executor's configured sandbox image for this run.
	// Empty means "use the executor's image". A driver that does not
	// advertise SupportsImageOverride must reject a non-empty value rather
	// than run the wrong toolchain silently.
	Image string `json:"image,omitempty"`
	// SetupCommands are shell commands baked into a derived image once per
	// unique (base image, command list) pair — not re-run per workload.
	// Requires SupportsSandboxBuild.
	SetupCommands []string `json:"setup_commands,omitempty"`
	// Mounts re-expose sub-paths of WorkDir elsewhere in the sandbox. See
	// SpecMount: sources are workspace-relative and cannot escape it.
	Mounts []SpecMount `json:"mounts,omitempty"`
	// HostMounts bind absolute paths on the executor's host into the
	// sandbox. Unlike Mounts they may point anywhere, which is why nothing
	// that parses a repo-committed file is allowed to set them: the only
	// writer is a secret lease (secretbroker.KindLocalRepo), where a human
	// named the path and the broker recorded who. See HostMount.
	HostMounts []HostMount `json:"host_mounts,omitempty"`
	// DisableNetwork forces this workload off the network regardless of how
	// the executor is configured.
	//
	// It is deliberately one-directional. A sandbox spec is repo-committed
	// input, so it may *narrow* what the operator granted and may never widen
	// it; there is no corresponding EnableNetwork field, and a spec that wants
	// egress gets it only by the executor already having it (see
	// Requirements.RequireNetworkEgress, which refuses placement instead of
	// quietly turning the network on).
	DisableNetwork bool `json:"disable_network,omitempty"`
	// SandboxHash identifies the sandbox spec this workload was built from,
	// for the audit trail. Drivers surface it as a label; it never affects
	// execution.
	SandboxHash string `json:"sandbox_hash,omitempty"`

	// Secrets attributes parts of Env and the filesystem to the secret
	// leases that produced them, so a driver can take an individual
	// credential back mid-run. See SecretBinding.
	Secrets []SecretBinding `json:"secrets,omitempty"`

	// Workspace says how the source tree gets into WorkDir. It carries no
	// credential — only the name of a grant — for the reasons set out in
	// workspace.go. The zero value is "unspecified", which leaves a driver's
	// pre-existing behaviour alone.
	Workspace Workspace `json:"workspace,omitempty"`

	// WriteBack says how the file changes the workload produces get back to
	// the hub. It carries no credential either — a push reuses the grant
	// Workspace named — for the reasons set out in writeback.go. The zero
	// value means nothing is returned, which is correct for a driver that
	// shares the hub's filesystem and wrong for every other one; the caller
	// that builds the Spec is responsible for saying so.
	WriteBack WriteBack `json:"write_back,omitempty"`
}

// SecretBinding says which parts of a Spec came from one secret lease.
//
// It carries no credential material — only the *names* of the environment
// variables and the *paths* of the files a lease contributed. The material
// itself is already in Env and on disk; duplicating it here would put
// plaintext into a struct that gets persisted (executorstore records the
// dispatched spec) and logged.
//
// The binding exists because revocation needs attribution. Without it an
// executor holding GITHUB_TOKEN has no way to know that variable came from
// lease_abc rather than from the operator's own environment, so "revoke
// lease_abc" could only be honoured by killing the whole workload or by
// doing nothing. With it, a driver scrubs exactly what that lease delivered
// and leaves everything else alone.
type SecretBinding struct {
	// LeaseID is the broker lease this material was issued under.
	LeaseID string `json:"lease_id"`
	// GrantID is the specific grant within the lease, when the binding
	// describes one grant rather than every material in the lease.
	GrantID string `json:"grant_id,omitempty"`
	// SecretName is the operator-facing name, for diagnostics.
	SecretName string `json:"secret_name,omitempty"`
	// Kind is the credential kind ("github_pat", "kubeconfig", "egress", …).
	Kind string `json:"kind,omitempty"`
	// EnvKeys names the environment variables this lease contributed. Keys
	// only, never "K=V" — a value here would defeat the whole point.
	EnvKeys []string `json:"env_keys,omitempty"`
	// Files are the credential file paths as the *executor* sees them.
	Files []string `json:"files,omitempty"`
	// Dir is the lease directory holding Files.
	Dir string `json:"dir,omitempty"`
	// Egress marks a binding that also opened a network path (an egress
	// proxy session), so revoking it must drop the allowlist entry and not
	// only the credential.
	Egress bool `json:"egress,omitempty"`
	// ExpiresAt is the lease TTL, so a driver can expire material locally
	// even while it cannot reach the control plane.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Revocable reports whether this binding describes material that can
// meaningfully be taken back mid-run: it must name a lease and something
// that lease actually delivered.
func (b SecretBinding) Revocable() bool {
	return strings.TrimSpace(b.LeaseID) != "" &&
		(len(b.EnvKeys) > 0 || len(b.Files) > 0 || b.Egress)
}

// RevocableSecrets returns the bindings in this spec that carry revocable
// material. A driver that cannot honour revocation must refuse such a spec
// rather than run it and silently drop the guarantee.
func (s Spec) RevocableSecrets() []SecretBinding {
	var out []SecretBinding
	for _, b := range s.Secrets {
		if b.Revocable() {
			out = append(out, b)
		}
	}
	return out
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
	for i, cmd := range s.SetupCommands {
		// A newline would end the RUN instruction the command is rendered
		// into and start an attacker-chosen one.
		if strings.ContainsAny(cmd, "\n\r") {
			return fmt.Errorf("%w: setup_commands[%d] spans multiple lines", ErrInvalidSpec, i)
		}
		if strings.TrimSpace(cmd) == "" {
			return fmt.Errorf("%w: setup_commands[%d] is blank", ErrInvalidSpec, i)
		}
	}
	if err := ValidateSpecMounts(s.Mounts); err != nil {
		return err
	}
	// Host mounts are checked here too, not only by the driver that honours
	// them. A Spec is persisted and re-hydrated (executorstore records the
	// dispatched spec), and the next driver to grow SupportsHostMounts would
	// otherwise inherit no enforcement at all.
	if err := ValidateHostMounts(s.HostMounts); err != nil {
		return err
	}
	if err := s.Workspace.Validate(); err != nil {
		return err
	}
	// A tree that must be fetched and a workload forbidden from reaching the
	// network is a contradiction, and the failure it produces otherwise —
	// "could not resolve host" from a step nobody knew ran — points nowhere
	// near the two settings that caused it.
	if s.Workspace.NeedsProvisioning() && s.DisableNetwork {
		return fmt.Errorf("%w: workspace kind git needs to fetch %s, but this workload has "+
			"network egress disabled; either pre-populate the tree or grant egress "+
			"(.cloop/sandbox.yaml capabilities.network)", ErrInvalidSpec, s.Workspace.Host())
	}
	if err := s.WriteBack.Validate(); err != nil {
		return err
	}
	// The same contradiction as above, in the other direction, and it has to be
	// caught here because it is silent otherwise: a push that cannot reach the
	// network fails *after* the harness has run, so the work is already done
	// and about to be discarded. Mode bundle is the answer for an egress-less
	// sandbox and exists precisely so this is a choice rather than a loss.
	if s.WriteBack.Mode == WriteBackPush && s.DisableNetwork {
		return fmt.Errorf("%w: write_back mode push has to reach the origin, but this workload "+
			"has network egress disabled; use mode bundle for a sandbox with no egress",
			ErrInvalidSpec)
	}
	// A push has nowhere to go unless the tree came from somewhere. Bind
	// workspaces are exempt: they share the hub's filesystem, so their changes
	// are already where the hub can see them and a write-back is redundant
	// rather than impossible — but that redundancy is also a bug worth naming.
	if s.WriteBack.Enabled() {
		switch s.Workspace.Kind {
		case WorkspaceGit:
			// The tree has to be pinned to an exact commit, not to a branch.
			//
			// Everything downstream is measured against the commit the sandbox
			// started from: the range it bundles, the ancestry check, the set
			// of paths the hub inspects. A branch name does not identify one —
			// the remote tip can move between the hub deciding to dispatch and
			// the sandbox fetching — and a base the hub guessed wrong is not a
			// slightly-off range, it is a range the hub does not hold the other
			// end of. Pinning makes "what did this task change" answerable by
			// construction rather than by assumption.
			if err := ValidateCommitSHA(s.Workspace.Ref); err != nil {
				return fmt.Errorf("%w: write_back needs the workspace pinned to an exact "+
					"commit so the returned changes can be measured against it, but the ref is "+
					"%q: %v", ErrInvalidSpec, s.Workspace.Ref, err)
			}
		case WorkspaceBind:
			return fmt.Errorf("%w: write_back is set on a bind workspace, whose changes are "+
				"already on the control plane's filesystem", ErrInvalidSpec)
		default:
			return fmt.Errorf("%w: write_back mode %q needs a git workspace to have a branch "+
				"and an origin, but the workspace kind is %q", ErrInvalidSpec, s.WriteBack.Mode,
				s.Workspace.Kind)
		}
	}
	return s.ResourceLimits.Validate()
}

// SandboxRequirements returns the placement constraints implied by the
// sandbox-shaped fields of this Spec.
//
// It exists so the one mapping from "what the spec asks for" to "what an
// executor must therefore support" lives beside the fields themselves, instead
// of being re-derived (and eventually re-derived differently) at each of the
// several call sites that place work.
func (s Spec) SandboxRequirements() Requirements {
	return Requirements{
		RequireImageOverride:           strings.TrimSpace(s.Image) != "",
		RequireSandboxBuild:            len(s.SetupCommands) > 0,
		RequireSandboxMounts:           len(s.Mounts) > 0,
		RequireHostMounts:              len(s.HostMounts) > 0,
		RequireResourceLimits:          !s.ResourceLimits.IsZero(),
		RequireWorkspaceProvisioning:   s.Workspace.NeedsProvisioning(),
		RequireHostFilesystemWorkspace: s.Workspace.Kind == WorkspaceBind,
		RequireWriteBack:               s.WriteBack.Enabled(),
	}
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
	// Image is the fully-resolved image reference the workload actually ran
	// from — digest-pinned where the driver could resolve one, so the run
	// stays reproducible after the tag moves. Empty for drivers with no image.
	//
	// It is reported here rather than echoed from Spec.Image because the two
	// differ in exactly the case that matters: the spec asks for `python:3.12`
	// and the handle records `python@sha256:…`, which is the only one of the
	// two that will still mean the same thing next month.
	Image string `json:"image,omitempty"`
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
	// WriteBack reports what the driver recovered of the workload's file
	// changes, once the workload is terminal. Nil means the driver returned
	// nothing — either the Spec asked for no write-back, or the workload is
	// still running. It is metadata only; the bundle bytes, when there are
	// any, are collected through WriteBackFetcher.
	WriteBack *WriteBackResult `json:"write_back,omitempty"`
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

// Lister is an optional interface for drivers that can enumerate the handles
// they currently know about.
//
// It is separate from Executor because not every driver can answer cheaply —
// a remote agent would have to round-trip to a device that may be offline — and
// a UI panel refreshing a load column must never be the reason a page hangs.
// Callers use LiveHandles, which degrades to "unknown" rather than to an error.
type Lister interface {
	// HandleStatuses returns a status snapshot per handle the driver
	// retains, including recently-finished ones. Ordering is unspecified.
	//
	// It is not called Handles because the drivers already expose a
	// diagnostic Handles() []string, and one method name meaning two
	// different things across the same types is how a caller ends up
	// counting strings and believing it counted running workloads.
	HandleStatuses(ctx context.Context) ([]Status, error)
}

// LiveHandles returns the currently-running handles on ex and whether ex could
// report at all. A false second return means "this driver does not enumerate",
// which a UI should render as "—", not as zero: showing an idle executor when
// it is actually saturated is worse than admitting ignorance.
func LiveHandles(ctx context.Context, ex Executor) ([]Status, bool) {
	lister, ok := ex.(Lister)
	if !ok {
		return nil, false
	}
	all, err := lister.HandleStatuses(ctx)
	if err != nil {
		return nil, false
	}
	out := make([]Status, 0, len(all))
	for _, st := range all {
		if !st.State.Terminal() {
			out = append(out, st)
		}
	}
	return out, true
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
	// ErrNoPlacement: no registered executor satisfies the task's
	// requirements. Always carried by a *PlacementError, which names the
	// unsatisfied constraint; match the sentinel, read the typed error.
	ErrNoPlacement = errors.New("executor: no executor satisfies placement requirements")
	// ErrSessionClaimLost: a session was requeued by someone else first.
	// This is the exactly-once latch reporting that it worked, not a
	// failure — a supervisor that sees it must do nothing further.
	ErrSessionClaimLost = errors.New("executor: session claim lost to another requeue")
	// ErrDrainTimeout: a drain did not reach zero in-flight sessions before
	// its deadline.
	ErrDrainTimeout = errors.New("executor: drain timed out with sessions still in flight")
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
	// WriteBack is what the driver recovered of the workload's file changes,
	// copied from the terminal Status. Nil when the Spec asked for none.
	WriteBack *WriteBackResult
	// Bundle is the git bundle the driver received, for a bundle-mode
	// write-back. Empty for every other mode — a push leaves the objects at
	// the origin, so there is nothing for the hub to carry.
	Bundle []byte
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
		result.WriteBack = st.WriteBack
	}

	// The bundle is collected only when the driver says one arrived, so a
	// driver that implements the interface is not asked for bytes on every
	// run. A fetch failure is recorded on the result rather than returned:
	// the workload's own outcome is what the caller asked for, and losing the
	// work product is a separate, additive failure that must not mask a
	// successful — or an already-failing — run.
	if result.WriteBack != nil && result.WriteBack.Mode == WriteBackBundle && result.WriteBack.Delivered() {
		if fetcher, ok := ex.(WriteBackFetcher); ok {
			bundle, fetchErr := fetcher.WriteBackBundle(handle.ID)
			if fetchErr != nil {
				wb := *result.WriteBack
				wb.Err = fmt.Sprintf("bundle was reported but could not be collected: %v", fetchErr)
				result.WriteBack = &wb
			} else {
				result.Bundle = bundle
			}
		}
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
