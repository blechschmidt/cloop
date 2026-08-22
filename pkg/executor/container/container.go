// Package container implements the executor.Executor interface on top of the
// Docker/Podman command line, running each workload in a resource- and
// network-isolated sandbox.
//
// It exists because pkg/executor/localprocess — the driver cloop ships with
// by default — offers no isolation at all: a task runs as the control-plane
// user, sees the whole host filesystem, and can reach anything on the
// network. That is defensible on a laptop and indefensible for a hosted
// deployment where the agent executes model-authored code on someone else's
// behalf.
//
// # What the sandbox actually guarantees
//
// Every container is started with:
//
//   - only the project directory bind-mounted, at a fixed path
//     (ContainerWorkspace). Nothing else of the host is visible.
//   - a non-root UID derived from the project directory's owner, so files the
//     workload creates are owned correctly on the host and a container escape
//     lands on an unprivileged user. (Under rootless podman the same is
//     achieved with --userns=keep-id.)
//   - --network=none by default. Egress is opt-in per executor.
//   - all Linux capabilities dropped and no-new-privileges set, so a setuid
//     binary inside the image cannot undo the UID choice.
//   - --cpus / --memory / --pids-limit from the Spec's ResourceLimits, with
//     swap pinned to the memory ceiling so paging cannot evade it.
//
// The exact command line is built by buildRunArgs in argv.go, which is pure
// and exhaustively unit-tested. That file is the security boundary; this one
// is lifecycle plumbing around it.
//
// # What it deliberately does not do
//
// It does not filter egress. When an operator opts into a network, cloop
// attaches the container to it and says so in preflight; per-destination
// policy belongs to the network (a --internal podman network, an egress
// proxy, a CNI plugin), not to a flag we could pretend to enforce.
//
// It does not pull images. Start passes --pull=never so a cold image cache
// fails immediately with an actionable error instead of turning a UI click
// into a multi-minute hang. Preflight tells the operator what to pull.
//
// # Secrets
//
// Provider API keys and brokered secrets arrive in Spec.Env and are forwarded
// with the bare `--env NAME` form, so the runtime reads each value from its
// own environment and no secret ever appears in the host process table.
// Nothing is baked into an image and nothing is written to the mounted
// workdir.
//
// One divergence from localprocess is deliberate: a nil Spec.Env means "no
// host environment at all" here, where os/exec semantics would mean "inherit
// everything". Forwarding the control plane's entire environment into a
// sandbox would hand the workload every credential the server holds, which
// is precisely what this driver exists to prevent. Callers pass what the
// workload needs, explicitly.
package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// DefaultID is the executor ID used when none is configured.
const DefaultID = "container"

const (
	// readChunkSize matches the localprocess driver's pump buffer.
	readChunkSize = 4096

	// maxRetainedHandles caps how many finished handles stay queryable via
	// Status, so a long-lived control plane does not accumulate one record
	// per run forever.
	maxRetainedHandles = 256

	// shortCmdTimeout bounds the control-plane-side runtime calls (kill,
	// inspect, rm). These are local IPC; anything slower than this means the
	// runtime is wedged and waiting longer will not help.
	shortCmdTimeout = 30 * time.Second

	// defaultPIDsLimit bounds process creation when neither the Spec nor the
	// operator asked for a specific value. A fork bomb inside the sandbox
	// should exhaust its own PID budget, not the host's. 1024 is far above
	// what a build or test run needs.
	defaultPIDsLimit = 1024
)

// Options configures a container executor instance.
//
// The zero value is usable: it auto-detects a runtime, uses DefaultImage,
// disables networking, and applies defaultPIDsLimit. Every field maps to an
// executors.container.* config key.
type Options struct {
	// ID is the executor's registry identifier. Empty means DefaultID.
	ID string
	// Runtime pins the container runtime ("podman" or "docker"). Empty
	// auto-detects, preferring rootless podman.
	Runtime string
	// Image is the sandbox image reference. Empty means DefaultImage.
	Image string
	// CPUs is the default core allowance when a Spec requests none.
	CPUs float64
	// MemoryMB is the default memory ceiling when a Spec requests none.
	MemoryMB int
	// PIDsLimit is the default process cap. Zero means defaultPIDsLimit;
	// negative means explicitly unlimited.
	PIDsLimit int
	// Network is "none" (default), "bridge", or an operator-defined network.
	Network string
	// AllowHosts pins name resolution as "host:address" entries. Only
	// meaningful when Network is not "none".
	AllowHosts []string
	// ExtraArgs are additional runtime flags. Validated by ValidateExtraArgs.
	ExtraArgs []string
	// SELinuxLabel is "", "z", or "Z" — the relabel option applied to bind
	// mounts on SELinux hosts.
	SELinuxLabel string
	// AllowRootUser permits the workload to run as uid 0 inside the
	// container. Default false, and it should stay false.
	//
	// The UID is normally derived from the project directory's owner, so a
	// control plane running as root over a root-owned project silently
	// produces a root sandbox — capabilities dropped, but still uid 0 against
	// a bind mount from the host and the full kernel surface. That is a
	// decision an operator should make on purpose, which is what this flag
	// makes it: without it, such a configuration is refused with an error
	// that says how to fix it.
	AllowRootUser bool

	// ImagePolicy constrains the images a *project* may name in its
	// .cloop/sandbox.yaml (Task 20177). The zero value constrains nothing.
	//
	// It deliberately does not apply to Image above. That reference is the
	// operator's own choice, made in the same file as the policy; running it
	// through an allowlist the same person wrote would be a lint, not a
	// control, and with a safe chart default of "digests only" it would refuse
	// the hub's own tagged image at boot.
	ImagePolicy imagepolicy.Policy
}

// Normalize fills in defaults and validates. It returns a copy so a caller's
// struct is never mutated behind its back, and is exported so pkg/config can
// validate an operator's YAML against exactly the rules New will apply.
func (o Options) Normalize() (Options, error) {
	if strings.TrimSpace(o.ID) == "" {
		o.ID = DefaultID
	}
	if strings.TrimSpace(o.Image) == "" {
		o.Image = DefaultImage
	}
	if strings.TrimSpace(o.Network) == "" {
		o.Network = NetworkNone
	}
	if o.PIDsLimit == 0 {
		o.PIDsLimit = defaultPIDsLimit
	}
	if err := ValidateImageRef(o.Image); err != nil {
		return o, err
	}
	if err := ValidateNetwork(o.Network); err != nil {
		return o, err
	}
	if o.CPUs < 0 {
		return o, fmt.Errorf("container: cpus must be >= 0, got %v", o.CPUs)
	}
	if o.MemoryMB < 0 {
		return o, fmt.Errorf("container: memory_mb must be >= 0, got %d", o.MemoryMB)
	}
	switch o.SELinuxLabel {
	case "", "z", "Z":
	default:
		return o, fmt.Errorf("container: selinux_label must be empty, \"z\", or \"Z\", got %q", o.SELinuxLabel)
	}
	if o.Network == NetworkNone && len(o.AllowHosts) > 0 {
		return o, fmt.Errorf("container: allow_hosts is set but network is \"none\" — " +
			"the workload has no interfaces to resolve names on")
	}
	for _, h := range o.AllowHosts {
		if err := validateAddHost(h); err != nil {
			return o, err
		}
	}
	if err := ValidateExtraArgs(o.ExtraArgs); err != nil {
		return o, err
	}
	// A policy that cannot be applied must be refused where it was written,
	// not silently reduced to one that allows everything.
	if err := o.ImagePolicy.Validate(); err != nil {
		return o, fmt.Errorf("container: image policy: %w", err)
	}
	o.ImagePolicy = o.ImagePolicy.Normalize()
	return o, nil
}

// Executor runs workloads in containers. Safe for concurrent use.
type Executor struct {
	id   string
	opts Options
	rt   Runtime
	// verifier checks image signatures when opts.ImagePolicy requires them.
	// Never nil for an executor built by New; a nil one fails closed, which
	// is what a struct-literal Executor in a test should do.
	verifier imagepolicy.Verifier

	mu      sync.Mutex
	handles map[string]*record
}

// record is the driver's bookkeeping for one container.
type record struct {
	id        string
	name      string
	startedAt time.Time

	bus *logbus.Bus

	// cancelPump stops the `logs -f` follower when the workload is reaped.
	cancelPump context.CancelFunc
	// killTimer enforces Spec.TimeoutMinutes; nil when unbounded.
	killTimer *time.Timer

	mu         sync.Mutex
	state      executor.State
	exitCode   int
	finishedAt time.Time
	errMsg     string
	done       bool
}

// New returns a container executor, detecting the runtime described by opts.
// It performs no network or filesystem I/O beyond resolving the runtime
// binary on PATH, so constructing an executor on a host without a runtime
// fails fast and legibly rather than at the first run.
func New(opts Options) (*Executor, error) {
	norm, err := opts.Normalize()
	if err != nil {
		return nil, err
	}
	rt, err := DetectRuntime(norm.Runtime)
	if err != nil {
		return nil, err
	}
	return &Executor{
		id:   norm.ID,
		opts: norm,
		rt:   rt,
		// One verifier for the executor's lifetime, so its per-digest cache
		// actually caches: a fresh one per workload start would re-spawn
		// cosign — and re-contact the transparency log — for every task in a
		// project that runs the same image all day.
		verifier: imagepolicy.NewCosignVerifier(),
		handles:  make(map[string]*record),
	}, nil
}

// Ensure registers a container executor built from opts into reg (nil means
// executor.DefaultRegistry), unless one with the same ID is already present.
//
// It returns the executor so callers can preflight it. A missing runtime is
// reported as an error rather than swallowed: an operator who configured a
// container executor and silently got host execution would believe they had
// an isolation boundary they do not have.
func Ensure(reg *executor.Registry, opts Options) (*Executor, error) {
	if reg == nil {
		reg = executor.DefaultRegistry
	}
	ex, err := New(opts)
	if err != nil {
		return nil, err
	}
	if err := reg.Ensure(ex); err != nil {
		return nil, err
	}
	return ex, nil
}

// ID implements executor.Executor.
func (e *Executor) ID() string { return e.id }

// Kind implements executor.Executor.
func (e *Executor) Kind() string { return executor.KindContainer }

// Runtime reports the resolved container runtime, for diagnostics.
func (e *Executor) Runtime() Runtime { return e.rt }

// Image reports the sandbox image this executor runs.
func (e *Executor) Image() string { return e.opts.Image }

// Capabilities implements executor.Executor.
//
// SharesHostFilesystem is true because the project directory really is a bind
// mount of a host path — host-side tooling can read what the workload wrote.
// NetworkEgress reflects the configured network honestly: claiming isolation
// the configuration does not provide is the failure mode that matters.
//
// SupportsWorkspaceProvisioning is false, and that is the answer rather than a
// gap. See buildRequest: this driver's whole model is that WorkDir is the
// operator's own checkout, mounted in. There is no tree for it to fetch.
func (e *Executor) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation:              executor.IsolationContainer,
		SupportsStream:         true,
		SupportsSignal:         true,
		SupportsResourceLimits: true,
		SharesHostFilesystem:   true,
		NetworkEgress:          e.opts.Network != NetworkNone,
		// Stated explicitly rather than left to the zero value: a driver that
		// bind-mounts the host path has already answered the workspace
		// question, and a reader of this struct should not have to infer that
		// from an absence.
		SupportsWorkspaceProvisioning: false,
		// A per-project sandbox spec can pick its own image and bake its own
		// setup: this driver has both a local image store to resolve against
		// and a builder to derive from.
		SupportsImageOverride: true,
		SupportsSandboxBuild:  true,
		SupportsSandboxMounts: true,
		Platform:              runtime.GOOS,
		Arch:                  runtime.GOARCH,
	}
}

// HealthCheck implements executor.Executor. It verifies the runtime binary
// still responds; a full environment audit is Preflight's job.
func (e *Executor) HealthCheck(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "version", "--format", "{{.Client.Version}}")
	if err != nil {
		return fmt.Errorf("container: %s is not usable: %w", e.rt.Name, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("container: %s version exited %d: %s", e.rt.Name, res.ExitCode, firstLine(res.Stderr))
	}
	return nil
}

// Start implements executor.Executor: it launches a detached container and
// returns its handle. The container outlives ctx, which bounds only the act
// of starting.
func (e *Executor) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return executor.Handle{}, err
	}
	return e.start(ctx, spec, nil)
}

// start is Start with driver-internal extra mounts, used by SmokeTest.
func (e *Executor) start(ctx context.Context, spec executor.Spec, extraMounts []mount) (executor.Handle, error) {
	if err := spec.Validate(); err != nil {
		return executor.Handle{}, err
	}
	workDir, err := e.resolveWorkDir(spec.WorkDir)
	if err != nil {
		return executor.Handle{}, err
	}

	req, err := e.buildRequest(spec, workDir, extraMounts)
	if err != nil {
		return executor.Handle{}, err
	}

	// Resolve the image last, because it is the only step that can be slow:
	// on a cache miss with setup commands this builds a derived image. Doing
	// it after the cheap validation means a malformed spec fails immediately
	// instead of after a multi-minute `pip install`.
	image, err := e.sandboxImage(ctx, spec)
	if err != nil {
		return executor.Handle{}, err
	}
	// The digest-pinned form, not the tag: between resolving and running, a
	// concurrent `podman pull` could repoint the tag, and the whole point of
	// pinning is that the artifact names what actually executed.
	req.Image = image.Pinned()

	built, err := buildRunArgs(req)
	if err != nil {
		return executor.Handle{}, err
	}

	// The run itself is bounded: `run -d` returns as soon as the container
	// is created, so a call that takes longer than this means the runtime is
	// wedged, and a wedged Start would hold an HTTP handler open.
	startCtx, cancel := context.WithTimeout(ctx, shortCmdTimeout)
	defer cancel()

	res, err := runCLI(startCtx, e.rt, built.Env, built.Args...)
	if err != nil {
		// The CLI could not be invoked, or the start timed out. Either way a
		// container may already have been created under our name; the name
		// embeds a fresh random run ID, so it can only be ours.
		e.removeContainer(context.WithoutCancel(ctx), req.Name)
		return executor.Handle{}, fmt.Errorf("container: start %s: %w", req.Name, err)
	}
	if res.ExitCode != 0 {
		// A failed `run -d` can still leave a created-but-not-started
		// container holding the name, which would make the next run fail for
		// an unrelated reason — so clean it up.
		//
		// Except when the failure *is* a name collision: then the container
		// wearing that name is by definition not the one we just tried to
		// create, and removing it would kill an unrelated workload. Refusing
		// to touch it also preserves the evidence, since a collision on a
		// randomly-derived name means something is genuinely wrong.
		if !isNameCollision(res.Stderr) {
			e.removeContainer(context.WithoutCancel(ctx), req.Name)
		}
		return executor.Handle{}, explainRunFailure(e.rt, req.Image, res)
	}

	// Deliberately not retaining spec: Spec.Env holds the caller's secret
	// values, and a finished handle stays queryable for a long time. Nothing
	// after Start needs them, so they are dropped as soon as the container
	// has them.
	rec := &record{
		id:        req.Labels[LabelHandle],
		name:      req.Name,
		startedAt: time.Now(),
		state:     executor.StateRunning,
	}
	rec.bus = logbus.New(rec.id, executor.StreamCombined, logbus.Options{})

	e.mu.Lock()
	e.handles[rec.id] = rec
	e.pruneLocked()
	e.mu.Unlock()

	if d := spec.Timeout(); d > 0 {
		rec.killTimer = time.AfterFunc(d, func() {
			rec.markKilled(fmt.Sprintf("timeout after %s", d))
			killCtx, killCancel := context.WithTimeout(context.Background(), shortCmdTimeout)
			defer killCancel()
			_, _ = runCLI(killCtx, e.rt, nil, "kill", "--signal", "SIGKILL", rec.name)
		})
	}

	// The pump is detached from ctx on purpose: it must outlive the request
	// that started the workload, and is stopped by cancelPump when the
	// container is reaped.
	pumpCtx, cancelPump := context.WithCancel(context.WithoutCancel(ctx))
	rec.cancelPump = cancelPump
	go e.pump(pumpCtx, rec)

	return executor.Handle{
		ID:         rec.id,
		ExecutorID: e.id,
		// PID is deliberately 0. The container's main process does have a
		// host PID, but it lives in another namespace, and host-side tooling
		// that signals PIDs directly (the /proc scan behind the UI's Stop
		// button) must go through Signal instead so the runtime stays the
		// single point of control.
		StartedAt: rec.startedAt,
		Image:     req.Image,
	}, nil
}

// resolveWorkDir validates and canonicalises the project directory. Unlike
// localprocess, an empty WorkDir is an error: a container must bind-mount
// something, and silently mounting the control plane's cwd would expose
// whatever happens to be there.
func (e *Executor) resolveWorkDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("%w: the %s executor requires work_dir — it is the only host path the sandbox can see",
			executor.ErrInvalidSpec, executor.KindContainer)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("%w: work_dir %q: %w", executor.ErrInvalidSpec, dir, err)
	}
	// Resolve symlinks so the bind mount source is the real directory. A
	// symlinked project would otherwise mount the link's target without the
	// operator's path appearing anywhere in the audit trail.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("%w: work_dir %q: %w", executor.ErrInvalidSpec, dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: work_dir %q is not a directory", executor.ErrInvalidSpec, dir)
	}
	return abs, nil
}

// sandboxMounts converts a Spec's workspace-relative mounts into binds.
//
// The source is resolved against the already-canonicalised workDir and then
// re-checked for containment. executor.SpecMount.Validate has already refused
// "..", but re-deriving the containment here is not redundant: workDir has been
// through EvalSymlinks and the join has not, so a symlink *inside* the project
// tree pointing at /etc is a path this check catches and the syntactic one
// cannot.
func sandboxMounts(spec executor.Spec, workDir, selinuxLabel string) ([]mount, error) {
	if len(spec.Mounts) == 0 {
		return nil, nil
	}
	out := make([]mount, 0, len(spec.Mounts))
	for i, m := range spec.Mounts {
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("container: mount[%d]: %w", i, err)
		}
		host := filepath.Join(workDir, filepath.FromSlash(m.Source))
		if resolved, err := filepath.EvalSymlinks(host); err == nil {
			host = resolved
		}
		// filepath.Rel is the containment test rather than a string prefix
		// check, which would accept "/workspace-evil" as being inside
		// "/workspace".
		rel, err := filepath.Rel(workDir, host)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf(
				"%w: mount source %q resolves to %s, which is outside the project workspace",
				executor.ErrInvalidSpec, m.Source, host)
		}
		out = append(out, mount{
			HostPath:     host,
			TargetPath:   m.Target,
			ReadOnly:     m.ReadOnly,
			SELinuxLabel: selinuxLabel,
		})
	}
	return out, nil
}

// buildRequest turns a Spec plus this executor's options into a runRequest.
func (e *Executor) buildRequest(spec executor.Spec, workDir string, extraMounts []mount) (runRequest, error) {
	// Bind is this driver's answer to the workspace question, and it is a
	// deliberate one rather than a missing feature.
	//
	// The container's /workspace *is* the host's project directory: the same
	// inodes, mounted through. The tree is therefore already present before the
	// container exists, which is why Capabilities reports SharesHostFilesystem
	// and why WorkspaceBind, WorkspaceNone and the unspecified zero value all
	// pass through untouched — none of them asks this driver to do anything.
	//
	// WorkspaceGit is the one that cannot be honoured, and honouring it would be
	// worse than refusing. A clone into that path is a clone into the operator's
	// own checkout: `git init` over their .git, a fetch over their objects, and
	// a detached checkout over their uncommitted work, on the machine they are
	// sitting at. The tree they would lose is not reconstructible from anything
	// cloop holds.
	if spec.Workspace.Kind == executor.WorkspaceGit {
		return runRequest{}, fmt.Errorf(
			"%w: the %s executor bind-mounts the project directory, so the source tree is already "+
				"at %s and cloning into it would overwrite the operator's own checkout; "+
				"use a bind workspace here, or dispatch a git workspace to a Kubernetes or remote "+
				"executor, which provision into a volume of their own",
			executor.ErrUnsupported, executor.KindContainer, workDir)
	}
	if spec.ResourceLimits.DiskMB > 0 {
		// --storage-opt size= only works on a minority of storage-driver
		// configurations (overlay2 on xfs with pquota). Accepting the limit
		// and not enforcing it would be worse than refusing it.
		return runRequest{}, fmt.Errorf(
			"%w: writable-layer disk quotas need a storage driver that supports them; "+
				"bound disk usage on the host filesystem instead", executor.ErrUnsupported)
	}

	handleID := newHandleID()
	name := ContainerName(workDir, handleID)

	req := runRequest{
		Runtime: e.rt,
		Image:   e.opts.Image,
		Name:    name,
		Workspace: mount{
			HostPath:     workDir,
			TargetPath:   ContainerWorkspace,
			SELinuxLabel: e.opts.SELinuxLabel,
		},
		Network:   e.opts.Network,
		AddHosts:  e.opts.AllowHosts,
		ExtraArgs: e.opts.ExtraArgs,
		AllowRoot: e.opts.AllowRootUser,
		Argv:      spec.Argv,
		Detach:    true,
		Labels: map[string]string{
			LabelManaged:  "true",
			LabelExecutor: e.id,
			LabelHandle:   handleID,
			LabelProject:  workDir,
		},
	}
	for _, m := range extraMounts {
		if e.opts.SELinuxLabel != "" && m.SELinuxLabel == "" {
			m.SELinuxLabel = e.opts.SELinuxLabel
		}
		req.ExtraMounts = append(req.ExtraMounts, m)
	}
	specMounts, err := sandboxMounts(spec, workDir, e.opts.SELinuxLabel)
	if err != nil {
		return runRequest{}, err
	}
	req.ExtraMounts = append(req.ExtraMounts, specMounts...)

	// A sandbox spec may take the network away and may never add one, so this
	// is an assignment in one direction only. See executor.Spec.DisableNetwork.
	if spec.DisableNetwork {
		req.Network = NetworkNone
		// --add-host entries are name pins for a network that no longer
		// exists; both runtimes reject them alongside --network=none.
		req.AddHosts = nil
	}
	if spec.SandboxHash != "" {
		req.Labels[LabelSandboxHash] = spec.SandboxHash
	}

	// Spec limits override the executor's configured defaults: the per-run
	// request is more specific than the per-executor policy.
	req.CPUs = e.opts.CPUs
	if spec.ResourceLimits.CPUMillis > 0 {
		req.CPUs = float64(spec.ResourceLimits.CPUMillis) / 1000.0
	}
	req.MemoryMB = e.opts.MemoryMB
	if spec.ResourceLimits.MemoryMB > 0 {
		req.MemoryMB = spec.ResourceLimits.MemoryMB
	}
	req.PIDsLimit = e.opts.PIDsLimit
	if spec.ResourceLimits.PIDs > 0 {
		req.PIDsLimit = spec.ResourceLimits.PIDs
	}

	// User mapping. Rootless podman maps the invoking user with keep-id, so
	// bind-mounted files keep their ownership without a --user flag. Rootful
	// runtimes get an explicit UID taken from the project directory's owner,
	// which is both the least privilege available and the only choice that
	// leaves files readable on the host afterwards.
	if e.rt.Rootless {
		req.KeepID = true
	} else if info, err := os.Stat(workDir); err == nil {
		if owner, ok := fileOwner(info); ok {
			req.User = strconv.Itoa(owner.uid) + ":" + strconv.Itoa(owner.gid)
		}
	}

	// Environment: names into argv, values into the runtime CLI's own
	// environment. A nil Spec.Env forwards nothing (see the package doc).
	for _, kv := range spec.Env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			return runRequest{}, fmt.Errorf("%w: env %q is not in K=V form", executor.ErrInvalidSpec, kv)
		}
		req.EnvNames = append(req.EnvNames, kv[:i])
	}
	req.Env = runtimeCLIEnv(spec.Env)

	// Spec labels are observability metadata; namespace them so they cannot
	// collide with the driver's own reaping labels.
	for k, v := range spec.Labels {
		key := "cloop.spec." + sanitizeLabelKeySegment(k)
		if _, taken := req.Labels[key]; !taken {
			req.Labels[key] = v
		}
	}

	return req, nil
}

// runtimeCLIEnv builds the environment for the runtime CLI process.
//
// The CLI itself needs the host environment to work at all — PATH to find
// its helpers, HOME and XDG_RUNTIME_DIR for podman's storage, DOCKER_HOST to
// find the daemon. The workload's own variables are layered on top; only
// those named in EnvNames are forwarded into the container, so the rest of
// the host environment stays on the host side of the boundary.
func runtimeCLIEnv(specEnv []string) []string {
	if len(specEnv) == 0 {
		return nil
	}
	env := os.Environ()
	return append(env, specEnv...)
}

// pump follows the container's log stream, reaps it, and records the terminal
// status.
//
// Ordering matters: the bus is closed only after the status is final, because
// a consumer that sees its stream close is entitled to read a terminal Status
// immediately — executor.Run depends on it.
func (e *Executor) pump(ctx context.Context, rec *record) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "container: log pump panic recovered (handle %s): %v\n", rec.id, r)
			e.finish(rec, executor.StateFailed, -1, fmt.Sprintf("log pump panic: %v", r))
		}
	}()

	if err := e.followLogs(ctx, rec); err != nil {
		// Losing the log stream is not fatal to the workload — the container
		// keeps running — but it does mean the UI goes quiet. Surface it in
		// the stream itself so the gap is visible rather than mysterious.
		rec.bus.Emit(fmt.Sprintf("\n[cloop] log stream ended early: %v\n", err))
	}

	state, exitCode, errMsg := e.reap(ctx, rec)
	e.finish(rec, state, exitCode, errMsg)
}

// followLogs runs `<runtime> logs -f` and forwards every chunk to the bus.
// It returns when the container exits (the follower exits with it) or when
// ctx is cancelled.
func (e *Executor) followLogs(ctx context.Context, rec *record) error {
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create log pipe: %w", err)
	}

	cmd := commandContext(ctx, e.rt.Path, "logs", "--follow", rec.name)
	// Merge the runtime's stdout and stderr: the container's own streams are
	// already interleaved by the log driver, and the UI renders one stream.
	cmd.Stdout = pipeW
	cmd.Stderr = pipeW
	if err := cmd.Start(); err != nil {
		_ = pipeR.Close()
		_ = pipeW.Close()
		return fmt.Errorf("start log follower: %w", err)
	}
	// The parent never writes; closing its end is what turns the child's
	// exit into an EOF for the reader.
	_ = pipeW.Close()

	buf := make([]byte, readChunkSize)
	for {
		n, readErr := pipeR.Read(buf)
		if n > 0 {
			rec.bus.Emit(string(buf[:n]))
		}
		if readErr != nil {
			break
		}
	}
	_ = pipeR.Close()
	_ = cmd.Wait()
	return nil
}

// reap waits for the container to exit and maps the outcome onto executor
// state. It is called after the log follower returns, at which point the
// container has normally already exited and `wait` returns immediately.
func (e *Executor) reap(ctx context.Context, rec *record) (executor.State, int, string) {
	// No timeout on `wait`: the container may legitimately still be running
	// if the log follower died early, and inventing a deadline here would
	// mark a live workload as failed.
	waitRes, err := runCLI(ctx, e.rt, nil, "wait", rec.name)
	if err != nil {
		if ctx.Err() != nil {
			return executor.StateUnknown, -1, "control plane stopped following this container"
		}
		return executor.StateFailed, -1, fmt.Sprintf("could not wait for container: %v", err)
	}
	if waitRes.ExitCode != 0 {
		// `wait` itself failing usually means the container vanished — it
		// was removed out from under us, which we cannot distinguish from a
		// clean exit we missed.
		return executor.StateFailed, -1, fmt.Sprintf("container %s could not be waited on: %s",
			rec.name, firstLine(waitRes.Stderr))
	}

	code, parseErr := strconv.Atoi(strings.TrimSpace(waitRes.Stdout))
	if parseErr != nil {
		return executor.StateFailed, -1, fmt.Sprintf("unparsable exit status %q from %s wait",
			strings.TrimSpace(waitRes.Stdout), e.rt.Name)
	}

	state, msg := classifyExit(code, e.inspectState(ctx, rec.name))
	e.removeContainer(ctx, rec.name)
	return state, code, msg
}

// inspectDetail is the subset of `inspect` output the driver interprets.
type inspectDetail struct {
	OOMKilled bool
	ExitCode  int
	Found     bool
}

// inspectState reads the container's final state. Failure is non-fatal: the
// exit code alone already classifies the outcome, and inspect is only needed
// to tell "killed" from "killed by the memory cap".
func (e *Executor) inspectState(ctx context.Context, name string) inspectDetail {
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "inspect", "--format", "{{json .State}}", name)
	if err != nil || res.ExitCode != 0 {
		return inspectDetail{}
	}
	var st struct {
		OOMKilled bool `json:"OOMKilled"`
		ExitCode  int  `json:"ExitCode"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &st); err != nil {
		return inspectDetail{}
	}
	return inspectDetail{OOMKilled: st.OOMKilled, ExitCode: st.ExitCode, Found: true}
}

// classifyExit maps a container exit code onto an executor state plus a
// human explanation.
//
// The 125/126/127 trio is the runtimes' shared convention for "the container
// never really ran", and conflating those with a workload that exited
// non-zero sends operators hunting for a bug in their task instead of a
// broken image. 128+N is death by signal N.
func classifyExit(code int, detail inspectDetail) (executor.State, string) {
	switch {
	case detail.OOMKilled:
		return executor.StateKilled, "the workload exceeded its memory limit and was killed by the kernel OOM killer"
	case code == 0:
		return executor.StateExited, ""
	case code == 125:
		return executor.StateFailed, "the container runtime itself failed to run the container (exit 125)"
	case code == 126:
		return executor.StateFailed, "the command could not be invoked — check that it is executable in the image (exit 126)"
	case code == 127:
		return executor.StateFailed, "the command was not found in the image (exit 127) — is the sandbox image missing the harness?"
	case code == 137:
		return executor.StateKilled, "the workload was killed (SIGKILL) — a timeout, a manual stop, or the memory cap"
	case code == 143:
		return executor.StateKilled, "the workload was terminated (SIGTERM)"
	case code > 128 && code < 165:
		return executor.StateKilled, fmt.Sprintf("the workload was killed by signal %d", code-128)
	default:
		return executor.StateExited, ""
	}
}

// isNameCollision reports whether a failed `run` was rejected because the
// container name is already taken. Both runtimes phrase this as some form of
// "name ... is already in use".
func isNameCollision(stderr string) bool {
	return strings.Contains(strings.ToLower(stderr), "already in use")
}

// explainRunFailure turns a failed `run` into an actionable error. The
// runtimes report these as plain stderr text, so matching on it is the only
// option — but the fallback always includes the raw message, so an
// unrecognised failure is still legible.
func explainRunFailure(rt Runtime, image string, res cliResult) error {
	stderr := firstLine(res.Stderr)
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "no such image"),
		strings.Contains(lower, "image not known"),
		strings.Contains(lower, "unable to find image"),
		strings.Contains(lower, "manifest unknown"):
		return fmt.Errorf("container: image %s is not present locally and this driver never pulls implicitly — "+
			"run `%s pull %s` (runtime said: %s)", image, rt.Name, image, stderr)
	case strings.Contains(lower, "permission denied"), strings.Contains(lower, "connect: permission denied"):
		return fmt.Errorf("container: %s refused the request: %s — "+
			"the control-plane user may lack access to the runtime socket", rt.Name, stderr)
	case strings.Contains(lower, "cannot connect"), strings.Contains(lower, "is the docker daemon running"):
		return fmt.Errorf("container: cannot reach the %s daemon: %s — start it and retry", rt.Name, stderr)
	case strings.Contains(lower, "already in use"):
		return fmt.Errorf("container: name collision starting the sandbox: %s — "+
			"run `%s rm` on the stale container or `cloop executor reap`", stderr, rt.Name)
	case strings.Contains(lower, "invalid argument") && strings.Contains(lower, "cgroup"):
		return fmt.Errorf("container: the runtime could not apply resource limits: %s — "+
			"rootless podman needs cgroup v2 delegation for --cpus/--memory", stderr)
	default:
		if stderr == "" {
			stderr = firstLine(res.Stdout)
		}
		return fmt.Errorf("container: %s run failed (exit %d): %s", rt.Name, res.ExitCode, stderr)
	}
}

// Signal implements executor.Executor by asking the runtime to deliver the
// signal, rather than signalling a host PID: the container's PID namespace
// means the host PID and the in-container PID 1 are different numbers, and
// only the runtime knows the mapping.
func (e *Executor) Signal(ctx context.Context, handleID string, sig executor.Signal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
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
	name := rec.name
	rec.mu.Unlock()
	if !running {
		// The caller wanted it stopped and it is stopped.
		return nil
	}
	if sig == executor.SignalKill {
		// Record intent before delivering, so a Status read racing the
		// reaper reports "killed" rather than a bare non-zero exit.
		rec.markKilled("killed by signal request")
	}

	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "kill", "--signal", osSignalName(sig), name)
	if err != nil {
		return fmt.Errorf("container: signal %s to %s: %w", sig, name, err)
	}
	if res.ExitCode != 0 {
		lower := strings.ToLower(res.Stderr)
		// Losing the race with a container that just exited is success:
		// the requested end state holds.
		if strings.Contains(lower, "not running") || strings.Contains(lower, "no such container") ||
			strings.Contains(lower, "is not running") {
			return nil
		}
		return fmt.Errorf("container: signal %s to %s failed: %s", sig, name, firstLine(res.Stderr))
	}
	return nil
}

// osSignalName maps the driver-independent signal onto the name both
// runtimes' `kill --signal` accepts.
func osSignalName(sig executor.Signal) string {
	switch sig {
	case executor.SignalInterrupt:
		return "SIGINT"
	case executor.SignalTerminate:
		return "SIGTERM"
	default:
		return "SIGKILL"
	}
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
		ExitCode:   rec.exitCode,
		StartedAt:  rec.startedAt,
		FinishedAt: rec.finishedAt,
		Error:      rec.errMsg,
	}, nil
}

// HandleStatuses implements executor.Lister from the driver's own bookkeeping. It
// deliberately does not shell out to `podman ps`: the Executors panel reads
// this for every card it renders, and a wedged runtime socket would turn a
// status column into a page-load stall. Containers this process did not start
// are not ours to report on anyway.
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

	// Per-record locks are taken outside e.mu, matching the lock order the
	// log pump uses.
	out := make([]executor.Status, 0, len(recs))
	for _, rec := range recs {
		rec.mu.Lock()
		out = append(out, executor.Status{
			HandleID:   rec.id,
			ExecutorID: e.id,
			State:      rec.state,
			ExitCode:   rec.exitCode,
			StartedAt:  rec.startedAt,
			FinishedAt: rec.finishedAt,
			Error:      rec.errMsg,
		})
		rec.mu.Unlock()
	}
	return out, nil
}

// Stream implements executor.Executor.
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
	return rec.bus.Subscribe(ctx), nil
}

// ContainerName derives the deterministic container name for a run:
// cloop-<projectSlug>-<runID>.
//
// Deterministic naming is what makes orphans reapable. A control plane killed
// mid-run leaves containers behind with no in-memory record; `cloop executor
// reap` finds them by the cloop.managed label, and an operator reading
// `podman ps` can tell at a glance which project a container belongs to.
func ContainerName(workDir, runID string) string {
	slug := projectSlug(workDir)
	id := strings.TrimPrefix(runID, "c-")
	name := "cloop-" + slug + "-" + id
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

// projectSlug reduces a project path to a name-safe fragment.
func projectSlug(workDir string) string {
	base := filepath.Base(strings.TrimSpace(workDir))
	if base == "." || base == string(os.PathSeparator) || base == "" {
		base = "project"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= 32 {
			break
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "project"
	}
	return slug
}

// Handles returns the IDs of every handle this executor still knows about,
// newest first.
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

// ReapOrphans removes exited containers this control plane created but no
// longer tracks — the residue of a control plane that was killed mid-run.
// Running containers are never touched: they may belong to another live
// control plane sharing the same runtime.
//
// It returns the names of the containers removed.
func (e *Executor) ReapOrphans(ctx context.Context) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout,
		"ps", "--all", "--filter", "label="+LabelManaged+"=true",
		"--filter", "status=exited", "--format", "{{.Names}}")
	if err != nil {
		return nil, fmt.Errorf("container: list orphans: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("container: list orphans failed: %s", firstLine(res.Stderr))
	}

	live := e.liveContainerNames()
	var removed []string
	for _, name := range strings.Fields(res.Stdout) {
		if _, tracked := live[name]; tracked {
			continue
		}
		if e.removeContainer(ctx, name) {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	return removed, nil
}

// liveContainerNames is the set of container names this executor is actively
// tracking, so reaping never removes a container a live run still needs.
func (e *Executor) liveContainerNames() map[string]struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	names := make(map[string]struct{}, len(e.handles))
	for _, rec := range e.handles {
		rec.mu.Lock()
		if !rec.done {
			names[rec.name] = struct{}{}
		}
		rec.mu.Unlock()
	}
	return names
}

// removeContainer deletes a container, reporting whether it is now gone.
// Failure is logged rather than propagated: a leaked container is a cleanup
// problem, not a reason to fail the run whose output we already collected.
func (e *Executor) removeContainer(ctx context.Context, name string) bool {
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "rm", "--force", name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "container: could not remove %s: %v\n", name, err)
		return false
	}
	if res.ExitCode != 0 {
		if strings.Contains(strings.ToLower(res.Stderr), "no such container") {
			return true
		}
		fmt.Fprintf(os.Stderr, "container: could not remove %s: %s\n", name, firstLine(res.Stderr))
		return false
	}
	return true
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

// finish records the terminal state and releases every stream subscriber.
func (e *Executor) finish(rec *record, state executor.State, exitCode int, errMsg string) {
	rec.mu.Lock()
	if rec.done {
		rec.mu.Unlock()
		return
	}
	rec.done = true
	// A kill we requested wins over the exit status the runtime reports,
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
	timer := rec.killTimer
	cancel := rec.cancelPump
	rec.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	// Close the bus only after the status is final; see pump's doc comment.
	rec.bus.Close()
	if cancel != nil {
		cancel()
	}
}

// markKilled records that termination was requested. It does not deliver a
// signal.
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

// sanitizeLabelKeySegment makes an arbitrary Spec label key safe to append to
// the driver's "cloop.spec." prefix.
func sanitizeLabelKeySegment(k string) string {
	if len(k) > 64 {
		k = k[:64]
	}
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == '-':
			return r
		default:
			return '_'
		}
	}, k)
	if out == "" {
		return "unnamed"
	}
	return out
}

// newHandleID returns a collision-resistant handle ID. It doubles as the run
// ID embedded in the container name, so a container can always be traced back
// to its handle.
func newHandleID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is essentially impossible; fall back to a
		// time-derived ID rather than panicking a control plane.
		return fmt.Sprintf("c-%x", time.Now().UnixNano())
	}
	return "c-" + hex.EncodeToString(b[:])
}
