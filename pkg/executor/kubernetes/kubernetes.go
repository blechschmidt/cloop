// Package kubernetes implements the executor.Executor interface by running
// each workload as an ephemeral Pod in a Kubernetes cluster.
//
// It is the fourth backend, alongside localprocess (no isolation),
// container (a sandbox on the control-plane host) and remote (an enrolled
// edge device). Kubernetes is the one that scales: the control plane holds no
// compute, the cluster schedules the work, and a hosted deployment can run
// tenants' agents on nodes that share nothing with the server answering their
// HTTP requests.
//
// # Lifecycle
//
// Start creates a Pod with generateName, restartPolicy Never and no
// long-lived identity, then returns. A watcher goroutine follows the Pod's
// phase; when the container reaches Running it also opens the Pod log API
// with follow=true and pipes every chunk into the same
// pkg/executor/internal/logbus every other driver uses, so the UI's event
// stream is byte-for-byte the same shape it was for a local process.
//
// Signal deletes the Pod: Kubernetes has no signal API, and deletion is what
// makes the kubelet send SIGTERM (or SIGKILL at grace period zero).
// SignalInterrupt is therefore delivered as SIGTERM — the closest thing the
// platform offers — and that difference is documented rather than hidden,
// because a cloop run traps SIGINT to checkpoint and will instead see a TERM.
//
// # Credentials
//
// The kubeconfig comes from a pkg/secretbroker lease and is consumed in
// memory; it never becomes a file on the control-plane host. The lease is
// held for the handle's lifetime (the driver needs it to watch, to read logs
// and above all to delete the Pod), renewed while the run continues, and
// released when the handle reaches a terminal state — on the failure paths as
// well as the success one. See credentials.go.
//
// # What the confinement is, and is not
//
// Every Pod is built by buildPod with runAsNonRoot, a read-only root
// filesystem, all capabilities dropped, seccomp RuntimeDefault, and
// automountServiceAccountToken false so no in-cluster API credential is
// handed to model-authored code. Those are not configurable.
//
// What this driver does not do is filter egress. A Pod gets the cluster's
// pod network, which by default can reach every other Pod and the internet.
// Restricting that is a NetworkPolicy — an object the cluster owns and cloop
// would be lying about if it claimed to enforce. Capabilities().NetworkEgress
// reports true accordingly.
//
// Nor does it hide the workload's environment. Spec.Env lands in the Pod
// object, readable by anyone with `get pods` in the namespace. That is why a
// nil Spec.Env forwards *nothing* here (unlike os/exec, which would inherit
// the control plane's whole environment) and why the namespace should be one
// only the control plane can read.
package kubernetes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

// DefaultID is the executor ID used when none is configured.
const DefaultID = "kubernetes"

// DefaultImage is the sandbox image used when the operator names none.
//
// Unlike the container driver there is no bind-mounted host binary to fall
// back on, so the image must actually contain the harness. This default is a
// placeholder that an operator is expected to replace; preflight and
// `cloop executor test` say so.
const DefaultImage = "ghcr.io/blechschmidt/cloop-harness:latest"

const (
	// DefaultNamespace is where Pods land when the config names no namespace.
	DefaultNamespace = "cloop"

	// requestTimeout bounds a unary API call. Generous enough for a busy
	// API server, short enough that a wedged endpoint does not pin a Start.
	requestTimeout = 30 * time.Second

	// cleanupTimeout bounds the deletes issued after a workload ends. These
	// run on a context detached from the caller's, so they need their own
	// ceiling.
	cleanupTimeout = 20 * time.Second

	// DefaultKillGracePeriod is how long a Pod gets between SIGTERM and
	// SIGKILL when Signal(SignalKill) is called. Short by design: a kill is
	// a demand, not a request, and the caller has usually already tried
	// SignalTerminate.
	DefaultKillGracePeriod = 5 * time.Second

	// DefaultTerminationGracePeriod is the Pod's own grace period, used for
	// SignalTerminate and SignalInterrupt. Matches Kubernetes' default so a
	// harness that traps SIGTERM has the time it expects.
	DefaultTerminationGracePeriod = 30 * time.Second

	// DefaultOrphanGracePeriod protects a Pod young enough that it might
	// belong to a start still in flight. Only non-terminal Pods older than
	// this are garbage-collected; terminal ones are reaped immediately.
	DefaultOrphanGracePeriod = 10 * time.Minute

	// logDrainTimeout bounds how long finishing waits for the log follower
	// to deliver the tail after the Pod terminated.
	logDrainTimeout = 15 * time.Second

	// readChunkSize matches the other drivers' pump buffer.
	readChunkSize = 4096

	// maxRetainedHandles caps how many finished handles stay queryable.
	maxRetainedHandles = 256

	// watchBackoff bounds re-establishing a dropped watch. A cluster
	// upgrading its API servers drops every watch at once; retrying
	// instantly would turn that into a thundering herd.
	watchBackoffMin = 500 * time.Millisecond
	watchBackoffMax = 15 * time.Second
	// maxWatchFailures gives up after this many *consecutive* failures, so a
	// deleted namespace surfaces as a failed handle instead of an infinite
	// retry loop.
	maxWatchFailures = 8

	// Log-follow retry bounds. The kubelet reports Running slightly before
	// the log endpoint is ready, so the first attempt is often rejected and
	// must be retried — but with a much tighter budget than a watch, because
	// the pump is waiting on this and a run whose logs never open should
	// reach its terminal status in seconds, not in a minute.
	maxLogStartAttempts = 6
	maxLogStartBackoff  = 2 * time.Second

	// Renewal bounds. A lease's TTL is halved to pick the interval, then
	// clamped: too often is wasted round-trips, too rarely lets a revoked
	// grant keep a Pod alive longer than the broker's contract allows.
	minRenewInterval = 30 * time.Second
	maxRenewInterval = 5 * time.Minute
)

// errPodDeleted reports that the Pod object went away while being watched —
// either because this driver deleted it, or because something else did.
var errPodDeleted = errors.New("kubernetes: pod was deleted")

// errWatchInterrupted reports that the driver itself broke the watch
// connection to force an immediate re-list. See record.interruptWatch.
var errWatchInterrupted = errors.New("kubernetes: watch interrupted deliberately")

// Options configures a Kubernetes executor instance. Every field maps to an
// executors.kubernetes.* config key.
//
// The zero value is deliberately *not* usable: Credentials has no default,
// because the alternative to a brokered kubeconfig is reading one off the
// control-plane host, and a driver that silently did that would defeat the
// isolation the operator chose it for.
type Options struct {
	// ID is the executor's registry identifier. Empty means DefaultID.
	ID string
	// Namespace is where Pods are created. Empty means the grant's pinned
	// namespace, then the kubeconfig context's, then DefaultNamespace.
	Namespace string
	// Image is the harness image. Empty means DefaultImage.
	Image string
	// ImagePullPolicy is "", "Always", "IfNotPresent" or "Never".
	ImagePullPolicy string
	// ImagePullSecrets names Secrets in Namespace holding registry auth.
	ImagePullSecrets []string
	// ServiceAccountName runs the Pod under a named ServiceAccount. Its
	// token is still not mounted (automountServiceAccountToken is forced
	// false); the name is for image-pull secrets and Pod Security admission.
	ServiceAccountName string

	// CPURequest/CPULimit/MemoryRequest/MemoryLimit are Kubernetes quantity
	// strings ("500m", "2", "512Mi", "4Gi"). Empty means unset.
	CPURequest    string
	CPULimit      string
	MemoryRequest string
	MemoryLimit   string
	// EphemeralStorageLimit bounds writable scratch ("10Gi").
	EphemeralStorageLimit string
	// WorkspaceSizeLimit bounds the workspace emptyDir specifically.
	WorkspaceSizeLimit string

	// NodeSelector pins scheduling to labelled nodes.
	NodeSelector map[string]string
	// Tolerations lets Pods schedule onto tainted nodes.
	Tolerations []Toleration

	// ActiveDeadlineSeconds is the server-side wall-clock ceiling applied
	// when a Spec requests no timeout. Zero means unbounded, matching the
	// project-wide decision (Task 20148) that runs are long-lived.
	ActiveDeadlineSeconds int64
	// TerminationGracePeriod is the Pod's grace period. Zero means
	// DefaultTerminationGracePeriod.
	TerminationGracePeriod time.Duration
	// KillGracePeriod is used for Signal(SignalKill). Zero means
	// DefaultKillGracePeriod; negative means "no grace at all".
	KillGracePeriod time.Duration

	// RunAsUser/RunAsGroup override the non-root UID/GID. Zero means the
	// distroless "nonroot" defaults. Zero *values* are rejected: this
	// executor always sets runAsNonRoot.
	RunAsUser  int64
	RunAsGroup int64

	// KeepCompletedPods leaves finished Pods in the cluster instead of
	// deleting them once their final status and logs have been captured.
	// Off by default, because a namespace that accumulates one Terminated
	// Pod per task hits its ResourceQuota's pod count long before anyone
	// looks at them. Turn it on to debug a failing image; ReconcileOrphans
	// then collects them on the next control-plane start.
	KeepCompletedPods bool

	// OrphanGracePeriod protects young Pods from the reconcile sweep. Zero
	// means DefaultOrphanGracePeriod.
	OrphanGracePeriod time.Duration

	// MaxConcurrent caps simultaneously-running Pods. Zero means unbounded
	// (the cluster's ResourceQuota is the real ceiling).
	MaxConcurrent int

	// Credentials supplies the kubeconfig lease. Required.
	Credentials CredentialSource

	// now overrides the clock for tests.
	now func() time.Time
}

// Normalize fills defaults and validates. It returns a copy so a caller's
// struct is never mutated, and is exported so pkg/config can validate an
// operator's YAML against exactly the rules New will apply.
//
// It deliberately does not require Credentials: pkg/config validates a
// config section long before a broker exists. New does require it.
func (o Options) Normalize() (Options, error) {
	if strings.TrimSpace(o.ID) == "" {
		o.ID = DefaultID
	}
	if strings.TrimSpace(o.Image) == "" {
		o.Image = DefaultImage
	}
	o.ID = strings.TrimSpace(o.ID)
	o.Image = strings.TrimSpace(o.Image)
	o.Namespace = strings.TrimSpace(o.Namespace)
	o.ServiceAccountName = strings.TrimSpace(o.ServiceAccountName)

	if o.Namespace != "" {
		if err := ValidateNamespace(o.Namespace); err != nil {
			return o, err
		}
	}
	if o.ServiceAccountName != "" {
		if err := validateDNSSubdomain(o.ServiceAccountName, "service_account"); err != nil {
			return o, err
		}
	}
	for _, s := range o.ImagePullSecrets {
		if err := validateDNSSubdomain(strings.TrimSpace(s), "image_pull_secrets entry"); err != nil {
			return o, err
		}
	}
	switch o.ImagePullPolicy {
	case "", "Always", "IfNotPresent", "Never":
	default:
		return o, fmt.Errorf("kubernetes: image_pull_policy must be \"Always\", \"IfNotPresent\" or \"Never\" (got %q)",
			o.ImagePullPolicy)
	}
	if err := ValidateImageRef(o.Image); err != nil {
		return o, err
	}
	for field, q := range map[string]string{
		"cpu_request":             o.CPURequest,
		"cpu_limit":               o.CPULimit,
		"memory_request":          o.MemoryRequest,
		"memory_limit":            o.MemoryLimit,
		"ephemeral_storage_limit": o.EphemeralStorageLimit,
		"workspace_size_limit":    o.WorkspaceSizeLimit,
	} {
		if err := ValidateQuantity(q); err != nil {
			return o, fmt.Errorf("kubernetes: %s: %w", field, err)
		}
	}
	for k, v := range o.NodeSelector {
		if strings.TrimSpace(k) == "" {
			return o, fmt.Errorf("kubernetes: node_selector has an empty key")
		}
		if len(v) > maxLabelValue {
			return o, fmt.Errorf("kubernetes: node_selector[%q] value exceeds %d characters", k, maxLabelValue)
		}
	}
	for i, t := range o.Tolerations {
		if err := t.Validate(); err != nil {
			return o, fmt.Errorf("kubernetes: tolerations[%d]: %w", i, err)
		}
	}
	if o.ActiveDeadlineSeconds < 0 {
		return o, fmt.Errorf("kubernetes: active_deadline_seconds must be >= 0 (got %d)", o.ActiveDeadlineSeconds)
	}
	if o.RunAsUser < 0 || o.RunAsGroup < 0 {
		return o, fmt.Errorf("kubernetes: run_as_user and run_as_group must be >= 0")
	}
	if o.MaxConcurrent < 0 {
		return o, fmt.Errorf("kubernetes: max_concurrent must be >= 0 (got %d)", o.MaxConcurrent)
	}

	if o.TerminationGracePeriod == 0 {
		o.TerminationGracePeriod = DefaultTerminationGracePeriod
	}
	if o.KillGracePeriod == 0 {
		o.KillGracePeriod = DefaultKillGracePeriod
	}
	if o.KillGracePeriod < 0 {
		o.KillGracePeriod = 0
	}
	if o.OrphanGracePeriod <= 0 {
		o.OrphanGracePeriod = DefaultOrphanGracePeriod
	}
	if o.now == nil {
		o.now = time.Now
	}
	return o, nil
}

// Executor runs workloads as ephemeral Pods. Safe for concurrent use.
type Executor struct {
	id   string
	opts Options

	mu      sync.Mutex
	handles map[string]*record
	closed  bool
}

// record is the driver's bookkeeping for one Pod.
type record struct {
	id        string
	startedAt time.Time
	bus       *logbus.Bus

	// namespace and podName are fixed once the Pod is created.
	namespace string
	podName   string

	// cancelPump stops the watcher, the log follower and the lease renewer.
	cancelPump context.CancelFunc

	mu sync.Mutex
	// cancelWatch breaks the watch connection currently in flight, without
	// stopping the pump. See interruptWatch.
	cancelWatch context.CancelFunc
	cli         *client
	leaseID     string
	leaseExp    time.Time
	state       executor.State
	exitCode    int
	finishedAt  time.Time
	errMsg      string
	done        bool
	// killRequested records that termination was asked for, so a Pod that
	// exits mid-delete is reported as killed rather than as a plain exit.
	killRequested bool
}

// New returns a Kubernetes executor. It performs no I/O: an unreachable
// cluster surfaces at HealthCheck or Start, not at construction, so a control
// plane still boots when the cluster is briefly down.
func New(opts Options) (*Executor, error) {
	norm, err := opts.Normalize()
	if err != nil {
		return nil, err
	}
	if norm.Credentials == nil {
		return nil, fmt.Errorf("kubernetes: executor %q has no credential source. "+
			"This driver only authenticates with a brokered kubeconfig lease; "+
			"mint one with `cloop secret mint --kind kubeconfig` and grant it to executor:%s",
			norm.ID, norm.ID)
	}
	return &Executor{
		id:      norm.ID,
		opts:    norm,
		handles: make(map[string]*record),
	}, nil
}

// Ensure registers a Kubernetes executor built from opts into reg (nil means
// executor.DefaultRegistry) unless one with the same ID is already present.
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
func (e *Executor) Kind() string { return executor.KindKubernetes }

// Image reports the harness image this executor runs.
func (e *Executor) Image() string { return e.opts.Image }

// Namespace reports the configured namespace, which may be empty when the
// grant or kubeconfig supplies it per-run.
func (e *Executor) Namespace() string { return e.opts.Namespace }

// Capabilities implements executor.Executor.
//
// Isolation is IsolationRemote rather than IsolationContainer: kube-scheduler
// places the Pod on a cluster node, which in any deployment that is not
// deliberately co-located is a different machine from the control plane. Even
// when it is co-located the boundary is still a container, so the claim is
// never weaker than IsolationContainer would have been.
//
// SharesHostFilesystem is false, and that is the substantive difference from
// the container driver: there is no bind mount, so Spec.WorkDir names a path
// *inside* the Pod and the control plane cannot read what the workload wrote.
//
// NetworkEgress is true because a Pod joins the cluster network. Constraining
// that is a NetworkPolicy the cluster owns; reporting false would be claiming
// an isolation cloop does not enforce.
func (e *Executor) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation:              executor.IsolationRemote,
		SupportsStream:         true,
		SupportsSignal:         true,
		SupportsResourceLimits: true,
		SharesHostFilesystem:   false,
		NetworkEgress:          true,
		// A per-project image is just the Pod's image field. Building one is
		// not: there is no builder here, so a spec with setup: is refused at
		// placement rather than silently degraded (see buildPodFor).
		SupportsImageOverride: true,
		SupportsSandboxBuild:  false,
		SupportsSandboxMounts: true,
		MaxConcurrent:         e.opts.MaxConcurrent,
		Platform:              "linux",
		Arch:                  e.opts.NodeSelector["kubernetes.io/arch"],
	}
}

// HealthCheck implements executor.Executor: acquire a lease, reach /version,
// release. It exercises the whole credential path rather than just pinging an
// endpoint, because "the cluster is up but the grant was revoked" is the
// failure an operator actually hits.
func (e *Executor) HealthCheck(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	creds, cli, err := e.connect(ctx, "")
	if err != nil {
		return err
	}
	defer func() {
		cli.close()
		e.opts.Credentials.Release(creds.LeaseID)
	}()

	probeCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if _, err := cli.serverVersion(probeCtx); err != nil {
		return fmt.Errorf("kubernetes: executor %q cannot reach %s: %w", e.id, creds.Rest.Server, err)
	}
	return nil
}

// ServerVersion reports the cluster's version, for diagnostics. It acquires
// and releases its own lease.
func (e *Executor) ServerVersion(ctx context.Context) (string, error) {
	creds, cli, err := e.connect(ctx, "")
	if err != nil {
		return "", err
	}
	defer func() {
		cli.close()
		e.opts.Credentials.Release(creds.LeaseID)
	}()
	return cli.serverVersion(ctx)
}

// connect acquires a lease and builds a client from it. The caller owns both:
// it must close the client and release the lease.
func (e *Executor) connect(ctx context.Context, projectID string) (*Credentials, *client, error) {
	if e.opts.Credentials == nil {
		return nil, nil, fmt.Errorf("kubernetes: executor %q has no credential source", e.id)
	}
	creds, err := e.opts.Credentials.Acquire(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}
	if creds == nil || creds.Rest == nil {
		e.opts.Credentials.Release("")
		return nil, nil, fmt.Errorf("%w: the credential source returned no kubeconfig", ErrNoKubeconfigGrant)
	}
	cli, err := newClient(creds.Rest, requestTimeout)
	if err != nil {
		e.opts.Credentials.Release(creds.LeaseID)
		return nil, nil, err
	}
	return creds, cli, nil
}

// namespaceFor resolves where a Pod goes: the operator's configured
// namespace wins, then the grant's pinned namespace, then the kubeconfig
// context's, then DefaultNamespace.
//
// The configured value comes first because it is the one an operator can see
// in their config file; silently honouring a namespace embedded in a
// credential would make the config a lie.
func (e *Executor) namespaceFor(creds *Credentials) string {
	if ns := strings.TrimSpace(e.opts.Namespace); ns != "" {
		return ns
	}
	if creds != nil {
		if ns := strings.TrimSpace(creds.Namespace); ns != "" {
			return ns
		}
		if creds.Rest != nil {
			if ns := strings.TrimSpace(creds.Rest.Namespace); ns != "" {
				return ns
			}
		}
	}
	return DefaultNamespace
}

// Start implements executor.Executor: create a Pod and return its handle. The
// Pod outlives ctx, which bounds only the act of starting.
func (e *Executor) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return executor.Handle{}, err
	}
	if err := spec.Validate(); err != nil {
		return executor.Handle{}, err
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return executor.Handle{}, fmt.Errorf("kubernetes: executor %q is closed", e.id)
	}
	running := e.runningLocked()
	e.mu.Unlock()
	if max := e.opts.MaxConcurrent; max > 0 && running >= max {
		return executor.Handle{}, fmt.Errorf("kubernetes: executor %q already has %d running Pods (max_concurrent=%d)",
			e.id, running, max)
	}

	projectID := strings.TrimSpace(spec.Labels["project"])
	if projectID == "" {
		projectID = strings.TrimSpace(spec.WorkDir)
	}

	// The lease is acquired with a context detached from the caller's: the
	// credential must outlive the request that started the workload, because
	// the driver needs it to delete the Pod later.
	leaseCtx, cancelLease := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
	defer cancelLease()
	creds, cli, err := e.connect(leaseCtx, projectID)
	if err != nil {
		return executor.Handle{}, err
	}

	// From here every failure path must release the lease and close the
	// client, or a refused Start leaks a credential the broker still thinks
	// is held.
	release := func() {
		cli.close()
		e.opts.Credentials.Release(creds.LeaseID)
	}

	handleID := newHandleID()
	namespace := e.namespaceFor(creds)
	desired, err := e.buildPodFor(spec, handleID, namespace)
	if err != nil {
		release()
		return executor.Handle{}, err
	}

	createCtx, cancelCreate := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
	defer cancelCreate()
	created, err := cli.createPod(createCtx, namespace, desired)
	if err != nil {
		release()
		return executor.Handle{}, explainCreateFailure(e.opts, namespace, err)
	}

	rec := &record{
		id:        handleID,
		startedAt: e.opts.now(),
		namespace: namespace,
		podName:   created.Metadata.Name,
		state:     executor.StatePending,
		cli:       cli,
		leaseID:   creds.LeaseID,
		leaseExp:  creds.ExpiresAt,
	}
	rec.bus = logbus.New(rec.id, executor.StreamCombined, logbus.Options{})

	e.mu.Lock()
	if e.closed {
		// Raced with Close: undo rather than leave an untracked Pod running.
		e.mu.Unlock()
		delCtx, delCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		_ = cli.deletePod(delCtx, namespace, created.Metadata.Name, 0)
		delCancel()
		release()
		return executor.Handle{}, fmt.Errorf("kubernetes: executor %q is closed", e.id)
	}
	e.handles[rec.id] = rec
	e.pruneLocked()
	e.mu.Unlock()

	rec.bus.Emit(fmt.Sprintf("[cloop] pod %s/%s created on %s\n",
		namespace, rec.podName, creds.Rest.Server))

	// The pump is detached from ctx: it must outlive the request that
	// started the workload, and is stopped by cancelPump at finish.
	pumpCtx, cancelPump := context.WithCancel(context.WithoutCancel(ctx))
	rec.cancelPump = cancelPump
	go e.pump(pumpCtx, rec)
	go e.renewLoop(pumpCtx, rec)

	return executor.Handle{
		ID:         rec.id,
		ExecutorID: e.id,
		// PID is 0 and stays 0: the container's PID lives in a namespace on
		// a node this process cannot see, and host-side tooling that
		// signals PIDs directly must go through Signal instead.
		StartedAt: rec.startedAt,
		// The reference as scheduled. Unlike the container driver there is no
		// local store to resolve a tag against, so this is digest-pinned only
		// when the spec pinned it; ImageWarnings() is what nudges an author
		// toward doing so.
		Image: podImage(created, desired),
	}, nil
}

// podImage reports the image the API server accepted, falling back to the one
// that was requested. They differ only if an admission webhook rewrote it —
// which is exactly the case where echoing the request would be a lie.
func podImage(created, desired *pod) string {
	for _, p := range []*pod{created, desired} {
		if p == nil {
			continue
		}
		for _, c := range p.Spec.Containers {
			if c.Name == ContainerName && strings.TrimSpace(c.Image) != "" {
				return c.Image
			}
		}
	}
	return ""
}

// buildPodFor turns a Spec plus this executor's options into a Pod object.
func (e *Executor) buildPodFor(spec executor.Spec, handleID, namespace string) (*pod, error) {
	if spec.ResourceLimits.PIDs > 0 {
		// A Pod cannot express a PID cap: podPidsLimit is a kubelet flag,
		// set per node by the cluster operator. Accepting the number and not
		// enforcing it would be worse than saying so.
		return nil, fmt.Errorf("%w: a Pod cannot carry a PID limit — it is the kubelet's "+
			"podPidsLimit, configured per node by the cluster operator", executor.ErrUnsupported)
	}
	if len(spec.SetupCommands) > 0 {
		// There is no builder in a cluster the way there is a local image
		// store beside a container runtime. Running the commands as a Pod
		// prelude would look equivalent and would not be: they would re-run on
		// every task instead of once per sandbox, and their result would be
		// discarded with the Pod. Refusing names the alternative.
		return nil, fmt.Errorf("%w: the Kubernetes executor cannot build a sandbox image; "+
			"build the setup: steps into an image, publish it, and reference it as "+
			"image: in .cloop/sandbox.yaml", executor.ErrUnsupported)
	}

	// A per-project image replaces the executor's configured one. It has
	// already been through container.ValidateImageRef in the parser, and goes
	// through this package's ValidateImageRef below on the way into the Pod.
	image := e.opts.Image
	if override := strings.TrimSpace(spec.Image); override != "" {
		if err := ValidateImageRef(override); err != nil {
			return nil, fmt.Errorf("%w: sandbox image: %w", executor.ErrInvalidSpec, err)
		}
		image = override
	}

	req := podRequest{
		ExecutorID:            e.id,
		HandleID:              handleID,
		Namespace:             namespace,
		Image:                 image,
		ImagePullPolicy:       e.opts.ImagePullPolicy,
		ServiceAccountName:    e.opts.ServiceAccountName,
		ImagePullSecrets:      e.opts.ImagePullSecrets,
		NodeSelector:          e.opts.NodeSelector,
		Tolerations:           e.opts.Tolerations,
		Argv:                  spec.Argv,
		Env:                   spec.Env,
		WorkDir:               podWorkDir(spec.WorkDir),
		Labels:                spec.Labels,
		CPURequest:            e.opts.CPURequest,
		CPULimit:              e.opts.CPULimit,
		MemoryRequest:         e.opts.MemoryRequest,
		MemoryLimit:           e.opts.MemoryLimit,
		EphemeralStorageLimit: e.opts.EphemeralStorageLimit,
		WorkspaceSizeLimit:    e.opts.WorkspaceSizeLimit,
		RunAsUser:             e.opts.RunAsUser,
		RunAsGroup:            e.opts.RunAsGroup,
		SandboxMounts:         spec.Mounts,
		SandboxHash:           spec.SandboxHash,
		DisableNetwork:        spec.DisableNetwork,

		ActiveDeadlineSeconds:         e.opts.ActiveDeadlineSeconds,
		TerminationGracePeriodSeconds: int64(e.opts.TerminationGracePeriod / time.Second),
	}

	// Spec limits are more specific than the executor's configured defaults,
	// so they win — the same precedence the container driver uses.
	if q := quantityFromMillis(spec.ResourceLimits.CPUMillis); q != "" {
		req.CPULimit = q
	}
	if q := quantityFromMB(spec.ResourceLimits.MemoryMB); q != "" {
		req.MemoryLimit = q
	}
	if q := quantityFromMB(spec.ResourceLimits.DiskMB); q != "" {
		req.EphemeralStorageLimit = q
	}
	// A per-Spec timeout becomes activeDeadlineSeconds, which the API server
	// enforces. That is strictly better than a client-side timer: it survives
	// a control-plane restart, where a timer would not.
	if d := spec.Timeout(); d > 0 {
		req.ActiveDeadlineSeconds = int64(d / time.Second)
	}

	return buildPod(req)
}

// podWorkDir maps a Spec's WorkDir onto a path inside the Pod.
//
// Callers set WorkDir to a control-plane path (that is what it means for
// host-local drivers), and there is no such path here. Anything that is not
// already inside the writable workspace is replaced by the workspace root
// rather than rejected, so binding a project to a Kubernetes executor does
// not fail on a field that has no meaning for it.
func podWorkDir(specWorkDir string) string {
	w := strings.TrimSpace(specWorkDir)
	if w == PodWorkspace || strings.HasPrefix(w, PodWorkspace+"/") {
		return w
	}
	return PodWorkspace
}

// explainCreateFailure turns a rejected Pod create into an actionable error.
func explainCreateFailure(opts Options, namespace string, err error) error {
	ae, ok := asAPIError(err)
	if !ok {
		return fmt.Errorf("kubernetes: create pod in %s: %w", namespace, err)
	}
	switch {
	case ae.Code == 404:
		return fmt.Errorf("kubernetes: namespace %q does not exist (or the kubeconfig cannot see it): %w",
			namespace, err)
	case ae.Code == 403:
		return fmt.Errorf("kubernetes: not allowed to create Pods in %q: %w", namespace, err)
	case ae.Code == 422 || strings.Contains(strings.ToLower(ae.Message), "violates podsecurity"):
		return fmt.Errorf("kubernetes: the API server rejected the Pod: %w — "+
			"cloop always sets runAsNonRoot, readOnlyRootFilesystem and drops all capabilities, so a "+
			"restricted Pod Security policy should accept it; a rejection usually means the namespace "+
			"enforces an additional policy (image provenance, required labels)", err)
	case ae.Code == 507 || strings.Contains(strings.ToLower(ae.Message), "exceeded quota"):
		return fmt.Errorf("kubernetes: the namespace's ResourceQuota refused the Pod: %w — "+
			"lower executors.kubernetes.cpu_request/memory_request or raise the quota", err)
	default:
		_ = opts
		return fmt.Errorf("kubernetes: create pod in %s: %w", namespace, err)
	}
}

// pump watches the Pod to a terminal state, streams its logs, records the
// outcome and releases everything the handle held.
//
// Ordering matters and mirrors the other drivers: the terminal status is
// recorded before the bus is closed, because a consumer that sees its stream
// close is entitled to read a terminal Status immediately — executor.Run
// depends on it.
func (e *Executor) pump(ctx context.Context, rec *record) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "kubernetes: pod pump panic recovered (handle %s): %v\n", rec.id, r)
			e.finish(rec, executor.StateFailed, -1, fmt.Sprintf("pod pump panic: %v", r))
		}
	}()

	var (
		logsStarted bool
		logsDone    = make(chan struct{})
	)
	// The log follower gets a context of its own so the pump can stop it
	// without stopping itself.
	logsCtx, cancelLogs := context.WithCancel(ctx)
	defer cancelLogs()

	// startLogs is only ever called from this goroutine, so the flag needs
	// no synchronisation.
	startLogs := func() {
		if logsStarted {
			return
		}
		logsStarted = true
		go func() {
			defer close(logsDone)
			e.streamLogs(logsCtx, rec)
		}()
	}

	final, watchErr := e.watchToTerminal(ctx, rec, startLogs)

	if !logsStarted {
		close(logsDone)
	}
	// A Pod that died before its container started — an image that will not
	// pull, a config error, a failed mount — has no logs and never will.
	// Waiting out the drain timeout for it would add fifteen silent seconds
	// to the most common misconfiguration there is.
	if containerNeverStarted(final) {
		cancelLogs()
	}
	// Wait for the tail of the log stream, but not forever: a Pod whose logs
	// the API server will not close must not pin the handle in "running".
	select {
	case <-logsDone:
	case <-time.After(logDrainTimeout):
		rec.bus.Emit("\n[cloop] log stream did not close within " + logDrainTimeout.String() + "\n")
	case <-ctx.Done():
	}

	state, exitCode, msg := e.classifyOutcome(rec, final, watchErr)

	// Delete before finishing so the Pod is gone by the time the caller sees
	// a terminal status — otherwise a UI that immediately re-runs would race
	// a completed Pod still holding its ResourceQuota slot.
	if !e.opts.KeepCompletedPods {
		e.deletePodDetached(rec, e.opts.KillGracePeriod)
	}
	e.finish(rec, state, exitCode, msg)
}

// watchToTerminal runs a list-then-watch loop until the Pod reaches a
// terminal phase, is deleted, or ctx ends.
//
// The initial list is not an optimisation: a Pod can complete between create
// and watch, and a watch established afterwards would deliver no further
// events, leaving the handle running forever.
func (e *Executor) watchToTerminal(ctx context.Context, rec *record, onPhase func()) (*pod, error) {
	var (
		last     *pod
		failures int
		backoff  = watchBackoffMin
		observe  = func(p *pod) {
			last = p
			e.observePhase(rec, p)
			switch p.Status.Phase {
			case phaseRunning, phaseSucceeded, phaseFailed:
				onPhase()
			}
		}
	)

	for {
		if err := ctx.Err(); err != nil {
			return last, err
		}

		cur, err := e.getPodWithClient(ctx, rec)
		if err != nil {
			if ae, ok := asAPIError(err); ok && ae.NotFound() {
				return last, errPodDeleted
			}
			if ctx.Err() != nil {
				return last, ctx.Err()
			}
			failures++
			if failures >= maxWatchFailures {
				return last, fmt.Errorf("kubernetes: lost track of pod %s/%s after %d attempts: %w",
					rec.namespace, rec.podName, failures, err)
			}
			if !sleepCtx(ctx, backoff) {
				return last, ctx.Err()
			}
			backoff = nextBackoff(backoff)
			continue
		}
		failures, backoff = 0, watchBackoffMin
		observe(cur)
		if terminalPhase(cur.Status.Phase) {
			return cur, nil
		}

		terminal, err := e.watchOnce(ctx, rec, cur.Metadata.ResourceVersion, observe)
		if terminal != nil {
			return terminal, nil
		}
		if err != nil {
			if errors.Is(err, errPodDeleted) {
				return last, errPodDeleted
			}
			if ctx.Err() != nil {
				return last, ctx.Err()
			}
			if errors.Is(err, errWatchInterrupted) {
				// We broke the connection on purpose; re-list immediately
				// rather than treating our own action as a fault and
				// sleeping through the backoff.
				continue
			}
			failures++
			if failures >= maxWatchFailures {
				return last, fmt.Errorf("kubernetes: watch on pod %s/%s failed %d times: %w",
					rec.namespace, rec.podName, failures, err)
			}
			if !sleepCtx(ctx, backoff) {
				return last, ctx.Err()
			}
			backoff = nextBackoff(backoff)
		}
		// A watch that ends without error is the API server's own
		// timeoutSeconds firing; loop around and re-list.
	}
}

// watchOnce consumes one watch connection. It returns the terminal Pod when
// it sees one, or an error describing why the stream ended.
func (e *Executor) watchOnce(ctx context.Context, rec *record, resourceVersion string, observe func(*pod)) (*pod, error) {
	// The watch runs on a context of its own so a stop request can break the
	// connection without stopping the pump. Without that, deleting a Pod is
	// invisible until either the API server delivers the event or the watch's
	// own timeout expires, and the UI shows a stopped task as "running" for
	// up to five minutes.
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	rec.mu.Lock()
	rec.cancelWatch = cancelWatch
	rec.mu.Unlock()
	defer func() {
		rec.mu.Lock()
		rec.cancelWatch = nil
		rec.mu.Unlock()
	}()

	body, err := rec.client().watchPod(watchCtx, rec.namespace, rec.podName, resourceVersion)
	if err != nil {
		if ae, ok := asAPIError(err); ok && ae.NotFound() {
			return nil, errPodDeleted
		}
		if watchCtx.Err() != nil && ctx.Err() == nil {
			return nil, errWatchInterrupted
		}
		return nil, err
	}
	// Closed, never drained. A watch body is an open-ended stream the API
	// server holds until it decides otherwise, so reading it to completion
	// on the way out — which is what connection-reuse draining does — waits
	// for an event that is not coming. Abandoning the connection costs one
	// socket; draining it costs the handle.
	defer func() { _ = body.Close() }()

	dec := json.NewDecoder(body)
	for {
		var ev watchEvent
		if err := dec.Decode(&ev); err != nil {
			switch {
			case ctx.Err() != nil:
				return nil, ctx.Err()
			case watchCtx.Err() != nil:
				return nil, errWatchInterrupted
			case errors.Is(err, io.EOF):
				// The API server closed the watch on its own timeoutSeconds;
				// the caller re-lists and re-watches.
				return nil, nil
			}
			return nil, fmt.Errorf("kubernetes: decode watch event: %w", err)
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			var p pod
			if err := json.Unmarshal(ev.Object, &p); err != nil {
				// A frame we cannot parse is not a reason to abandon the
				// watch; the next one probably parses, and the outer loop
				// re-lists if it does not.
				continue
			}
			observe(&p)
			if terminalPhase(p.Status.Phase) {
				return &p, nil
			}
		case "DELETED":
			return nil, errPodDeleted
		case "ERROR":
			// The API server signals an expired resourceVersion this way.
			// Returning ends this connection; the outer loop re-lists, which
			// is exactly the recovery the protocol asks for.
			var st status
			if json.Unmarshal(ev.Object, &st) == nil && st.Message != "" {
				return nil, fmt.Errorf("kubernetes: watch error: %s", st.Message)
			}
			return nil, fmt.Errorf("kubernetes: watch returned an error frame")
		}
	}
}

// getPodWithClient reads the Pod under a bounded timeout.
func (e *Executor) getPodWithClient(ctx context.Context, rec *record) (*pod, error) {
	getCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return rec.client().getPod(getCtx, rec.namespace, rec.podName)
}

// observePhase records a non-terminal phase transition and narrates it into
// the log stream.
//
// The narration matters more than it looks: a Pod pulling a large image sits
// Pending for minutes with no container output, and a UI panel showing an
// empty log for a "running" task is indistinguishable from a hang.
func (e *Executor) observePhase(rec *record, p *pod) {
	if p == nil {
		return
	}
	// A terminal phase is classified by the pump, which has the container's
	// exit code and the Pod's reason to work from. Mapping it here would
	// have to guess, and the only guess available ("not Running, so
	// pending") would walk a finished handle *backwards* from running to
	// pending in the UI moments before it settles.
	if terminalPhase(p.Status.Phase) {
		return
	}
	state := executor.StatePending
	if p.Status.Phase == phaseRunning {
		state = executor.StateRunning
	}

	rec.mu.Lock()
	changed := !rec.done && rec.state != state && !rec.state.Terminal()
	if changed {
		rec.state = state
	}
	rec.mu.Unlock()

	if !changed {
		return
	}
	detail := podWaitingDetail(p)
	line := fmt.Sprintf("[cloop] pod %s/%s: %s", rec.namespace, rec.podName, p.Status.Phase)
	if detail != "" {
		line += " — " + detail
	}
	rec.bus.Emit(line + "\n")
}

// containerNeverStarted reports whether a terminal Pod's harness container
// never got as far as running, which means there are no logs to collect.
func containerNeverStarted(p *pod) bool {
	if p == nil || !terminalPhase(p.Status.Phase) {
		return false
	}
	cs := p.harnessStatus()
	return cs == nil || (cs.State.Running == nil && cs.State.Terminated == nil)
}

// podWaitingDetail summarises why a Pod has not started yet.
func podWaitingDetail(p *pod) string {
	if cs := p.harnessStatus(); cs != nil && cs.State.Waiting != nil {
		w := cs.State.Waiting
		if w.Message != "" {
			return w.Reason + ": " + firstLine(w.Message)
		}
		return w.Reason
	}
	for _, c := range p.Status.Conditions {
		if c.Type == "PodScheduled" && c.Status == "False" && c.Reason != "" {
			if c.Message != "" {
				return c.Reason + ": " + firstLine(c.Message)
			}
			return c.Reason
		}
	}
	if p.Status.Reason != "" {
		return p.Status.Reason
	}
	return ""
}

// streamLogs follows the Pod log API and forwards every chunk to the bus.
//
// It retries the "container is waiting to start" rejection a few times: the
// kubelet reports Running slightly before the log endpoint is ready, and
// giving up on that first 400 would silently drop the whole run's output.
func (e *Executor) streamLogs(ctx context.Context, rec *record) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "kubernetes: log follower panic recovered (handle %s): %v\n", rec.id, r)
		}
	}()

	backoff := watchBackoffMin
	for attempt := 0; attempt < maxLogStartAttempts; attempt++ {
		if ctx.Err() != nil || rec.finished() {
			return
		}
		body, err := rec.client().followLogs(ctx, rec.namespace, rec.podName, ContainerName, true)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			ae, ok := asAPIError(err)
			switch {
			case ok && ae.NotFound():
				// The Pod is gone; its logs went with it. The terminal
				// status carries the explanation.
				return
			case ok && (ae.Code == 400 || ae.Retryable()):
				if !sleepCtx(ctx, backoff) {
					return
				}
				if backoff *= 2; backoff > maxLogStartBackoff {
					backoff = maxLogStartBackoff
				}
				continue
			default:
				rec.bus.Emit(fmt.Sprintf("\n[cloop] could not read pod logs: %v\n", err))
				return
			}
		}

		buf := make([]byte, readChunkSize)
		for {
			n, readErr := body.Read(buf)
			if n > 0 {
				rec.bus.Emit(string(buf[:n]))
			}
			if readErr != nil {
				break
			}
		}
		_ = body.Close()
		return
	}
}

// classifyOutcome maps the final Pod (and any watch error) onto the
// executor's terminal state, exit code and explanation.
func (e *Executor) classifyOutcome(rec *record, final *pod, watchErr error) (executor.State, int, string) {
	rec.mu.Lock()
	killed := rec.killRequested
	killMsg := rec.errMsg
	rec.mu.Unlock()

	switch {
	case errors.Is(watchErr, errPodDeleted):
		if killed {
			if killMsg == "" {
				killMsg = "the workload was stopped"
			}
			return executor.StateKilled, -1, killMsg
		}
		return executor.StateKilled, -1, fmt.Sprintf(
			"pod %s/%s was deleted out from under this run — an eviction, a node drain, or a `kubectl delete`",
			rec.namespace, rec.podName)

	case watchErr != nil && (errors.Is(watchErr, context.Canceled) || errors.Is(watchErr, context.DeadlineExceeded)):
		return executor.StateUnknown, -1, "the control plane stopped following this Pod; it may still be running"

	case watchErr != nil:
		return executor.StateFailed, -1, watchErr.Error()

	case final == nil:
		return executor.StateFailed, -1, "the Pod produced no observable status"
	}

	state, code, msg := classifyPod(final)
	// A kill we asked for wins over the exit status the cluster reports,
	// which would otherwise read as an ordinary signal death.
	if killed && state == executor.StateExited {
		state = executor.StateKilled
		if killMsg != "" {
			msg = killMsg
		}
	}
	return state, code, msg
}

// classifyPod maps a terminal Pod onto an executor state.
//
// Kubernetes spreads the reason across three places — the Pod's phase, the
// Pod's reason, and the container's terminated state — and which one carries
// the truth depends on how it died. Deciding here, from all three, is what
// lets the UI say "OOMKilled" instead of "exit 137".
func classifyPod(p *pod) (executor.State, int, string) {
	cs := p.harnessStatus()

	// activeDeadlineSeconds and eviction are Pod-level, and the container
	// may carry no terminated state at all when they fire.
	switch p.Status.Reason {
	case "DeadlineExceeded":
		return executor.StateKilled, -1,
			"the Pod exceeded its activeDeadlineSeconds and was terminated by the cluster"
	case "Evicted":
		msg := firstLine(p.Status.Message)
		if msg == "" {
			msg = "the node evicted the Pod (resource pressure)"
		}
		return executor.StateKilled, -1, "evicted: " + msg
	case "Shutdown", "NodeShutdown", "TerminationByKubelet":
		return executor.StateKilled, -1, "the node shut down while the workload was running"
	}

	if cs != nil && cs.State.Terminated != nil {
		t := cs.State.Terminated
		switch {
		case t.Reason == "OOMKilled":
			return executor.StateKilled, t.ExitCode,
				"the workload exceeded its memory limit and was killed by the kernel OOM killer"
		case t.Signal != 0:
			return executor.StateKilled, t.ExitCode, fmt.Sprintf("the workload was killed by signal %d", t.Signal)
		case t.ExitCode == 0:
			return executor.StateExited, 0, ""
		case t.ExitCode == 126:
			return executor.StateFailed, t.ExitCode,
				"the command could not be invoked — check that it is executable in the image (exit 126)"
		case t.ExitCode == 127:
			return executor.StateFailed, t.ExitCode,
				"the command was not found in the image (exit 127) — does the harness image ship cloop?"
		case t.ExitCode == 137:
			return executor.StateKilled, t.ExitCode,
				"the workload was killed (SIGKILL) — a stop request, the grace period expiring, or the memory cap"
		case t.ExitCode == 143:
			return executor.StateKilled, t.ExitCode, "the workload was terminated (SIGTERM)"
		default:
			msg := firstLine(t.Message)
			if t.Reason != "" && msg == "" {
				msg = t.Reason
			}
			return executor.StateExited, t.ExitCode, msg
		}
	}

	// No terminated container: the Pod failed before the harness ran.
	if cs != nil && cs.State.Waiting != nil {
		w := cs.State.Waiting
		msg := w.Reason
		if w.Message != "" {
			msg = w.Reason + ": " + firstLine(w.Message)
		}
		return executor.StateFailed, -1, "the container never started — " + msg
	}
	if p.Status.Phase == phaseSucceeded {
		return executor.StateExited, 0, ""
	}
	msg := firstLine(p.Status.Message)
	if msg == "" {
		msg = p.Status.Reason
	}
	if msg == "" {
		msg = "the Pod failed before the container reported a status"
	}
	return executor.StateFailed, -1, msg
}

// renewLoop keeps the credential lease alive for as long as the workload
// runs, and terminates the workload if the authority behind it is withdrawn.
//
// That second half is the point. Broker.Renew re-evaluates every grant from
// the store, so a kubeconfig grant revoked mid-run stops renewing here, and a
// Pod that is running on a credential the operator just took away is killed
// rather than left to finish.
func (e *Executor) renewLoop(ctx context.Context, rec *record) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "kubernetes: lease renewer panic recovered (handle %s): %v\n", rec.id, r)
		}
	}()

	timer := time.NewTimer(rec.renewInterval(e.opts.now()))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if rec.finished() {
			return
		}

		renewCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		creds, err := e.opts.Credentials.Renew(renewCtx, rec.leaseIDValue())
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			rec.bus.Emit(fmt.Sprintf(
				"\n[cloop] the kubeconfig lease could not be renewed (%v); stopping the workload\n", err))
			e.terminate(rec, "the kubeconfig grant behind this run was revoked or expired", e.opts.KillGracePeriod)
			return
		}
		rec.adoptCredentials(creds)
		timer.Reset(rec.renewInterval(e.opts.now()))
	}
}

// Signal implements executor.Executor.
//
// Kubernetes has no signal API. Deletion is the only lever, and it is what
// makes the kubelet send SIGTERM followed by SIGKILL at the grace period. So:
//
//	SignalKill                    → delete with a short grace period
//	SignalTerminate/SignalInterrupt → delete with the Pod's grace period
//
// SignalInterrupt is therefore *not* SIGINT. A cloop run traps SIGINT to
// checkpoint; under this driver it will see SIGTERM instead. Pretending
// otherwise would be worse than saying it.
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
	if rec.done || rec.state.Terminal() {
		rec.mu.Unlock()
		// The caller wanted it stopped and it is stopped.
		return nil
	}
	rec.killRequested = true
	if rec.errMsg == "" {
		rec.errMsg = "the workload was stopped by a " + string(sig) + " request"
	}
	cli := rec.cli
	rec.mu.Unlock()

	grace := e.opts.TerminationGracePeriod
	if sig == executor.SignalKill {
		grace = e.opts.KillGracePeriod
	}

	delCtx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	if err := cli.deletePod(delCtx, rec.namespace, rec.podName, grace); err != nil {
		return fmt.Errorf("kubernetes: stop pod %s/%s: %w", rec.namespace, rec.podName, err)
	}
	// Force the watcher to re-list now. The DELETED event usually arrives on
	// its own, but "usually" is not good enough for a Stop button: a watch
	// that misses it would leave the task showing "running" until the watch's
	// own five-minute timeout expired.
	rec.interruptWatch()
	return nil
}

// terminate records intent and deletes the Pod, on a context detached from
// any caller. Used by the lease renewer, which has no caller to borrow one
// from.
func (e *Executor) terminate(rec *record, reason string, grace time.Duration) {
	rec.mu.Lock()
	if rec.done {
		rec.mu.Unlock()
		return
	}
	rec.killRequested = true
	if reason != "" {
		rec.errMsg = reason
	}
	rec.mu.Unlock()
	e.deletePodDetached(rec, grace)
}

// deletePodDetached removes the Pod with its own bounded context. Failure is
// logged rather than propagated: a leaked Pod is a cleanup problem for the
// reconcile sweep, not a reason to lose the result we already collected.
func (e *Executor) deletePodDetached(rec *record, grace time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := rec.client().deletePod(ctx, rec.namespace, rec.podName, grace); err != nil {
		fmt.Fprintf(os.Stderr, "kubernetes: could not delete pod %s/%s: %v\n",
			rec.namespace, rec.podName, err)
		return
	}
	rec.interruptWatch()
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
	return rec.snapshot(e.id), nil
}

// HandleStatuses implements executor.Lister from the driver's own
// bookkeeping. It deliberately does not call the API server: the Executors
// panel reads this for every card it renders, and a slow cluster must not
// turn a status column into a page-load stall.
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

	out := make([]executor.Status, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.snapshot(e.id))
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

// ReconcileOrphans deletes Pods this executor owns but no longer tracks.
//
// It is the answer to the failure mode that has no other answer: a control
// plane killed mid-run loses its in-memory handles, and the Pods it created
// keep running — burning a node's CPU, holding a ResourceQuota slot, and
// producing output nobody reads. Nothing else notices, because from the
// cluster's point of view they are perfectly healthy Pods.
//
// Terminal Pods are removed immediately. Non-terminal ones are removed only
// once they are older than OrphanGracePeriod, so a Pod belonging to a Start
// still in flight — or to another control plane that has just booted with the
// same executor ID — is not killed out from under it.
//
// It returns the namespaced names of the Pods removed.
func (e *Executor) ReconcileOrphans(ctx context.Context) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	creds, cli, err := e.connect(ctx, "")
	if err != nil {
		return nil, err
	}
	defer func() {
		cli.close()
		e.opts.Credentials.Release(creds.LeaseID)
	}()

	namespace := e.namespaceFor(creds)
	listCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	list, err := cli.listPods(listCtx, namespace, executorLabelSelector(e.id))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("kubernetes: list pods for reconciliation in %s: %w", namespace, err)
	}

	tracked := e.trackedPodNames()
	cutoff := e.opts.now().Add(-e.opts.OrphanGracePeriod)

	var removed []string
	for i := range list.Items {
		p := &list.Items[i]
		if _, ours := tracked[p.Metadata.Name]; ours {
			continue
		}
		if p.Metadata.DeletionTimestamp != "" {
			// Already terminating; deleting again just adds a request.
			continue
		}
		if !terminalPhase(p.Status.Phase) {
			created, perr := time.Parse(time.RFC3339, p.Metadata.CreationTimestamp)
			if perr != nil || created.After(cutoff) {
				continue
			}
		}
		delCtx, delCancel := context.WithTimeout(ctx, cleanupTimeout)
		derr := cli.deletePod(delCtx, namespace, p.Metadata.Name, e.opts.KillGracePeriod)
		delCancel()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "kubernetes: could not reap orphan pod %s/%s: %v\n",
				namespace, p.Metadata.Name, derr)
			continue
		}
		removed = append(removed, namespace+"/"+p.Metadata.Name)
	}
	sort.Strings(removed)
	return removed, nil
}

// trackedPodNames is the set of Pod names this executor is actively running,
// so reconciliation never deletes a Pod a live handle still needs.
func (e *Executor) trackedPodNames() map[string]struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	names := make(map[string]struct{}, len(e.handles))
	for _, rec := range e.handles {
		rec.mu.Lock()
		if !rec.done {
			names[rec.podName] = struct{}{}
		}
		rec.mu.Unlock()
	}
	return names
}

// Close stops every watcher, releases every lease and closes every client.
//
// It deliberately does not delete running Pods. A control plane restarting
// for an upgrade should not destroy work in flight; the Pods carry their own
// activeDeadlineSeconds where one is configured, and ReconcileOrphans
// collects whatever is left on the way back up.
func (e *Executor) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	recs := make([]*record, 0, len(e.handles))
	for _, rec := range e.handles {
		recs = append(recs, rec)
	}
	e.mu.Unlock()

	for _, rec := range recs {
		e.finish(rec, executor.StateUnknown, -1,
			"the control plane stopped following this Pod; it may still be running")
	}
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

// runningLocked counts handles that have not finished. Caller holds e.mu.
func (e *Executor) runningLocked() int {
	n := 0
	for _, rec := range e.handles {
		rec.mu.Lock()
		if !rec.done {
			n++
		}
		rec.mu.Unlock()
	}
	return n
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
		done, at := rec.done, rec.finishedAt
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

// finish records the terminal state, releases the lease and the client, and
// then releases every stream subscriber.
//
// Lease release lives here, and only here, so that every path out of a
// handle's life — a clean exit, a failed start's watcher, a kill, a panic in
// the pump, a Close — drops the credential exactly once.
func (e *Executor) finish(rec *record, state executor.State, exitCode int, errMsg string) {
	rec.mu.Lock()
	if rec.done {
		rec.mu.Unlock()
		return
	}
	rec.done = true
	if rec.killRequested && state == executor.StateExited {
		state = executor.StateKilled
	}
	if rec.killRequested && errMsg == "" {
		errMsg = rec.errMsg
	}
	rec.state = state
	rec.exitCode = exitCode
	rec.finishedAt = e.opts.now()
	if errMsg != "" {
		rec.errMsg = errMsg
	}
	cancel := rec.cancelPump
	cli := rec.cli
	leaseID := rec.leaseID
	rec.leaseID = ""
	rec.mu.Unlock()

	if leaseID != "" && e.opts.Credentials != nil {
		e.opts.Credentials.Release(leaseID)
	}
	// Close the bus only after the status is final; see pump's doc comment.
	rec.bus.Close()
	if cancel != nil {
		cancel()
	}
	if cli != nil {
		cli.close()
	}
}

// --- record helpers ---------------------------------------------------

func (r *record) client() *client {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cli
}

func (r *record) finished() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done
}

// interruptWatch breaks the watch connection in flight so the watcher
// re-lists immediately. It is a nudge, not a stop: the pump keeps running and
// re-establishes the watch if the Pod turns out to still exist.
func (r *record) interruptWatch() {
	r.mu.Lock()
	cancel := r.cancelWatch
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *record) leaseIDValue() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leaseID
}

func (r *record) snapshot(executorID string) executor.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return executor.Status{
		HandleID:   r.id,
		ExecutorID: executorID,
		State:      r.state,
		ExitCode:   r.exitCode,
		StartedAt:  r.startedAt,
		FinishedAt: r.finishedAt,
		Error:      r.errMsg,
	}
}

// renewInterval is half the remaining lease TTL, clamped. Halving leaves room
// for one failed attempt before the lease actually lapses.
func (r *record) renewInterval(now time.Time) time.Duration {
	r.mu.Lock()
	exp := r.leaseExp
	r.mu.Unlock()
	if exp.IsZero() {
		return maxRenewInterval
	}
	d := exp.Sub(now) / 2
	if d < minRenewInterval {
		return minRenewInterval
	}
	if d > maxRenewInterval {
		return maxRenewInterval
	}
	return d
}

// adoptCredentials swaps in a renewed lease, rebuilding the HTTP client when
// the credential itself changed (a rotated ServiceAccount token).
func (r *record) adoptCredentials(creds *Credentials) {
	if creds == nil || creds.Rest == nil {
		return
	}
	newCli, err := newClient(creds.Rest, requestTimeout)
	if err != nil {
		// Keep running on the old client: it still works until the
		// credential behind it expires, and dropping the handle because a
		// renewal produced an unusable config would be worse.
		fmt.Fprintf(os.Stderr, "kubernetes: renewed kubeconfig is unusable, keeping the previous one: %v\n", err)
		r.mu.Lock()
		r.leaseID, r.leaseExp = creds.LeaseID, creds.ExpiresAt
		r.mu.Unlock()
		return
	}
	r.mu.Lock()
	old := r.cli
	r.cli = newCli
	r.leaseID = creds.LeaseID
	r.leaseExp = creds.ExpiresAt
	r.mu.Unlock()

	// In-flight watch and log streams keep using the connections they
	// already opened; closing idle ones only reclaims sockets.
	if old != nil && old != newCli {
		old.close()
	}
}

// --- small helpers ----------------------------------------------------

// sleepCtx waits for d, returning false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > watchBackoffMax {
		return watchBackoffMax
	}
	return d
}

// newHandleID returns a collision-resistant handle ID.
func newHandleID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is essentially impossible; fall back to a
		// time-derived ID rather than panicking a control plane.
		return fmt.Sprintf("k-%x", time.Now().UnixNano())
	}
	return "k-" + hex.EncodeToString(b[:])
}
