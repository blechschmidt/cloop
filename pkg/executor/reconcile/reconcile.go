// Package reconcile turns the executors section of a config file into
// registered, preflighted executors — once, in one place, for every entry
// point that hosts a control plane (Task 20170).
//
// # Why this package exists
//
// Before it, three bootstraps disagreed. `cloop ui` and `cloop serve`
// registered only the localprocess driver from their own package-local
// bootstrap; the container and Kubernetes drivers were registered from
// cmd/root.go's PersistentPreRunE, keyed off os.Getwd() rather than the
// directory the server was actually given, and their failures were printed to
// stderr and dropped. A hub started from the Helm chart or the docker-compose
// stack with executors.allow_host_process: false could therefore come up with
// the host driver refused (correctly) and no isolating driver registered
// (silently) — zero usable executors, /readyz green, and every run failing at
// dispatch with a 409. A Kubernetes rollout would report success.
//
// So this package does three things the old split could not:
//
//  1. One reconciliation for all entry points, taking the directory
//     explicitly instead of inferring it from the process's cwd;
//  2. A per-driver preflight whose result is *recorded* — a structured
//     Diagnostic with an id, kind, status and remediation string — rather
//     than a warning on stderr that nothing can read back; and
//  3. A readiness verdict (see ready.go) that the /readyz probes consult, so
//     a hub with nothing to dispatch to fails its readiness gate loudly
//     instead of accepting traffic it cannot serve.
//
// # Why it is not in pkg/executor
//
// The natural home would be executor.ReconcileFromConfig. It cannot live
// there: pkg/config imports pkg/executor/container and
// pkg/executor/kubernetes for their Options types, and both import
// pkg/executor. A pkg/executor that imported pkg/config would close that
// loop. Keeping reconciliation one level down leaves pkg/executor free of
// driver and config dependencies, which is what lets any package import it.
//
// # Degraded is not failed
//
// A driver whose preflight finds a fatal problem stays registered and is
// marked degraded. Preflight is a point-in-time probe of a remote system: a
// cluster that is briefly unreachable while the hub boots would otherwise
// lose its executor until someone restarted the process, which is a worse
// outcome than a hub that reports the problem and lets the next dispatch
// retry. Only a driver that could not be *constructed* — no container
// runtime on PATH, no credential source for the cluster — is failed, because
// there is nothing to register.
package reconcile

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Status is the outcome of reconciling one configured driver.
type Status string

const (
	// StatusOK: registered, and preflight found nothing fatal.
	StatusOK Status = "ok"
	// StatusDegraded: registered, but preflight found a fatal problem.
	// Workloads placed here will probably fail until it is fixed.
	StatusDegraded Status = "degraded"
	// StatusFailed: not registered. The driver could not be built at all.
	StatusFailed Status = "failed"
)

// Finding is one preflight observation, normalised across drivers. The
// container and Kubernetes drivers each define their own identically-shaped
// Finding; flattening them here means the API and the panel render one type.
type Finding struct {
	Name string `json:"name"`
	// Level is "ok", "warn" or "fail", matching both drivers' vocabulary.
	Level   string `json:"level"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// Diagnostic is the per-driver record this package exists to produce: what
// was configured, whether it came up, and what to do when it did not.
type Diagnostic struct {
	// ID is the executor ID, which is also the registry key.
	ID string `json:"id"`
	// Kind is the executor.Kind* the driver reports.
	Kind string `json:"kind"`
	// Status is the reconciliation outcome.
	Status Status `json:"status"`
	// Registered reports whether the executor ended up in the registry.
	// Degraded executors are registered; failed ones are not.
	Registered bool `json:"registered"`
	// Isolating reports whether this driver puts a boundary between the
	// workload and the control-plane host. It is what strict mode counts.
	Isolating bool `json:"isolating"`
	// Message is the one-line summary an operator reads first.
	Message string `json:"message"`
	// Remediation is the concrete next action. Empty only when Status is OK.
	Remediation string `json:"remediation,omitempty"`
	// Findings is the preflight checklist, when one was run.
	Findings []Finding `json:"findings,omitempty"`
	// CheckedAt is when this diagnostic was produced.
	CheckedAt time.Time `json:"checked_at"`
}

// OK reports whether this driver is usable.
func (d Diagnostic) OK() bool { return d.Status == StatusOK }

// Report is the result of one reconciliation pass.
type Report struct {
	// Dir is the directory whose config was reconciled.
	Dir string `json:"dir"`
	// Diagnostics is one entry per configured driver, ordered by ID.
	Diagnostics []Diagnostic `json:"diagnostics"`
	// StrictMode is the host-execution policy in force when the pass ran.
	StrictMode bool `json:"strict_mode"`
	// ReconciledAt is when the pass completed.
	ReconciledAt time.Time `json:"reconciled_at"`
}

// IsolatingRegistered reports whether at least one isolating executor came up
// during this pass. It is deliberately *not* what readiness is computed from
// — see Ready — because a remote agent can enroll after startup.
func (r Report) IsolatingRegistered() bool {
	for _, d := range r.Diagnostics {
		if d.Registered && d.Isolating {
			return true
		}
	}
	return false
}

// Problems returns the diagnostics that are not OK, for logging and for the
// readiness message.
func (r Report) Problems() []Diagnostic {
	var out []Diagnostic
	for _, d := range r.Diagnostics {
		if d.Status == StatusFailed || d.Status == StatusDegraded {
			out = append(out, d)
		}
	}
	return out
}

// Options tunes a reconciliation pass. The zero value is what the hub entry
// points want: the default registry, preflight on, no orphan sweep.
type Options struct {
	// Registry receives the executors. nil means executor.DefaultRegistry.
	Registry *executor.Registry

	// SkipPreflight registers without probing. Preflight costs container
	// runtime calls and Kubernetes API round-trips, which is the right price
	// for a long-running hub and the wrong one for a short CLI command that
	// will never dispatch a workload.
	SkipPreflight bool

	// PreflightTimeout bounds each driver's probe. Zero uses
	// DefaultPreflightTimeout. A cluster that cannot answer in this long is
	// one the operator needs told about, not one worth waiting for.
	PreflightTimeout time.Duration

	// ReconcileOrphans asks the Kubernetes driver to sweep Pods left behind
	// by a control plane that died mid-run. It costs API calls, so only the
	// entry points a control plane actually restarts as should ask for it.
	ReconcileOrphans bool

	// KubernetesCredentials overrides how the Kubernetes driver's identity is
	// obtained. nil uses BrokerCredentials, which reads the secret broker out
	// of dir's state database. Tests and embedders that already hold a
	// credential source inject it here.
	KubernetesCredentials CredentialsFunc

	// Logf receives one line per diagnostic. nil logs to stderr; supply a
	// no-op to silence a pass entirely.
	Logf func(format string, args ...any)

	// QuietWhenHealthy logs only problems. A CLI invocation wants this — a
	// line reading "executor container: ready" on every `cloop status` is
	// noise, and a caller that prefixes its output with "warning:" would
	// otherwise emit "warning: ... ready". A long-running server wants the
	// healthy lines, because "which executors did this hub come up with" is
	// the first question asked of a startup log.
	QuietWhenHealthy bool

	// Publish records the report where LastReport and Ready can see it.
	// Defaults to true; tests reconciling into a private registry set it
	// false so they do not disturb process-global state.
	//
	// It is a pointer so the zero value can mean "yes" while still letting a
	// caller say "no" explicitly.
	Publish *bool
}

// Identity is everything the Kubernetes driver authenticates with: one
// credential for the cluster it schedules into, and one for the repositories it
// fetches project source from.
//
// They travel together, and are built together, because both are backed by the
// same secret broker and therefore the same open state database. Building them
// through two independent hooks would open two SQLite handles for one executor
// and hold both for the process's lifetime — see the comment on
// ensureKubernetes for why that lifetime makes a second handle a leak rather
// than an inefficiency.
type Identity struct {
	// Cluster authenticates to the Kubernetes API server. Required.
	Cluster kubernetes.CredentialSource
	// Workspace leases the credential a private-repository fetch needs. nil is
	// legitimate and means "public repositories only": an in-cluster hub with
	// no sealing key can still schedule Pods, and the driver's preflight says
	// so rather than failing a deployment that never needed it.
	Workspace executor.WorkspaceCredentialSource
}

// CredentialsFunc builds the identity the Kubernetes driver authenticates
// with, returning a cleanup to release whatever backs it.
//
// The cleanup exists because the broker source owns an open state database
// that the executor keeps for the process's lifetime. On the success path it
// is deliberately never called; on the path where the source was built but
// registration then failed, it is the only way to avoid leaking a SQLite
// handle and its WAL lock on every reconciliation pass. It may be nil.
type CredentialsFunc func(dir string, cfg *config.Config, execID string) (Identity, func(), error)

// DefaultPreflightTimeout bounds one driver's preflight. Generous enough for
// a cold container runtime and a cross-region API server, short enough that a
// hub with an unreachable cluster still finishes booting promptly.
const DefaultPreflightTimeout = 45 * time.Second

func (o Options) registry() *executor.Registry {
	if o.Registry != nil {
		return o.Registry
	}
	return executor.DefaultRegistry
}

func (o Options) preflightTimeout() time.Duration {
	if o.PreflightTimeout > 0 {
		return o.PreflightTimeout
	}
	return DefaultPreflightTimeout
}

func (o Options) publish() bool { return o.Publish == nil || *o.Publish }

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// lastMu guards the published report. The report is process-global for the
// same reason the host-execution policy is: /readyz and GET /api/executors
// need to read it from handlers that know nothing about how the process was
// bootstrapped, and threading it through every constructor would mean an
// embedder that forgot one gets a probe that silently reports nothing.
// publishSeq orders publications. A pass takes a ticket before it starts and
// may only publish if no later pass has published since — see publishAt.
var (
	lastMu      sync.RWMutex
	lastReport  *Report
	publishSeq  uint64
	publishedAt uint64
)

// nextPublishTicket reserves this pass's place in publication order.
func nextPublishTicket() uint64 {
	lastMu.Lock()
	defer lastMu.Unlock()
	publishSeq++
	return publishSeq
}

// LastReport returns a deep copy of the most recent published reconciliation,
// and whether one has happened. The copy is deliberate: callers marshal it
// into HTTP responses from other goroutines while a later pass may be running,
// and some hand the Findings slice on to a view struct.
func LastReport() (Report, bool) {
	lastMu.RLock()
	defer lastMu.RUnlock()
	if lastReport == nil {
		return Report{}, false
	}
	return cloneReport(*lastReport), true
}

// cloneReport copies a report and everything reachable from it, so no two
// holders ever share a backing array.
func cloneReport(r Report) Report {
	if r.Diagnostics == nil {
		return r
	}
	diags := make([]Diagnostic, len(r.Diagnostics))
	copy(diags, r.Diagnostics)
	for i := range diags {
		if diags[i].Findings != nil {
			f := make([]Finding, len(diags[i].Findings))
			copy(f, diags[i].Findings)
			diags[i].Findings = f
		}
	}
	r.Diagnostics = diags
	return r
}

// resetForTest clears the published report and retires every in-flight
// ticket, so a background preflight pass still running from an earlier test
// cannot republish over the next test's fixture.
func resetForTest() {
	lastMu.Lock()
	lastReport = nil
	publishSeq++
	publishedAt = publishSeq
	lastMu.Unlock()
}

// ResetForTest clears the published report, for tests in other packages.
//
// Exported because the report is process-global: pkg/ui asserts that a failed
// driver reaches GET /api/executors, and without a way to clear the report
// afterwards that fixture would leak into every later test's readiness
// verdict. Only tests should call it.
func ResetForTest() { resetForTest() }

// PublishForTest installs a report without running a reconciliation, for
// tests in other packages that need a specific diagnostic to be visible.
//
// It exists because the interesting case to render — a driver that failed to
// build — otherwise requires a broken container runtime on PATH. What those
// tests check is the plumbing from report to HTTP response; that a missing
// runtime produces this diagnostic is pinned down in this package's own
// tests. Only tests should call it.
func PublishForTest(r Report) { publishAt(nextPublishTicket(), r) }

// Bootstrap is what a long-running control plane calls: it registers
// synchronously and preflights in the background, returning the registration
// pass's report.
//
// The split exists because the two halves have opposite latency budgets.
// Registration is cheap — a PATH lookup for the container runtime, a struct
// for the cluster — and must complete before the server accepts its first
// request, or /readyz would report a hub with no executors as ready purely
// because bootstrap had not got there yet. Preflight is a container runtime
// round-trip and a Kubernetes API call, up to PreflightTimeout each; paying
// that before the listener opens would make `cloop ui` look hung on a host
// whose docker daemon is wedged.
//
// Running both is safe precisely because FromConfig is idempotent: the second
// pass finds every executor already registered, reuses it, and only adds the
// probe results. The published report is upgraded in place, so /readyz and
// GET /api/executors go from "registered, not yet probed" to the full
// checklist without either endpoint knowing a second pass happened.
func Bootstrap(dir string, cfg *config.Config, opts Options) Report {
	fast := opts
	fast.SkipPreflight = true
	// The fast pass reports only problems. A driver that failed to *build*
	// must be on stderr immediately, but announcing one as "ready" before it
	// has been probed would be a claim this pass has not earned — and the
	// preflight pass below repeats the line a second later anyway.
	fast.QuietWhenHealthy = opts.QuietWhenHealthy || !opts.SkipPreflight
	report := FromConfig(context.Background(), dir, cfg, fast)

	if opts.SkipPreflight || len(report.Diagnostics) == 0 {
		return report
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				opts.logf("executor: panic during background preflight: %v", r)
			}
		}()
		// No orphan sweep here: the registration pass above already owns
		// that decision, and ensureKubernetes reports this pass as a reuse.
		FromConfig(context.Background(), dir, cfg, opts)
	}()
	return report
}

// FromConfig registers every executor the config enables, preflights each
// one, and records a diagnostic for it.
//
// It is idempotent. A driver already present in the registry is reused rather
// than rebuilt — which matters beyond tidiness for the Kubernetes driver,
// whose construction opens a state database that is intentionally never
// closed. Rebuilding it on every pass would leak a handle per call.
//
// It never returns an error and never aborts on one driver's account: a hub
// with a broken container runtime and a working cluster must come up with the
// cluster. What the failure buys the operator is the diagnostic, and — when
// strict mode leaves nothing to dispatch to — a red /readyz.
func FromConfig(ctx context.Context, dir string, cfg *config.Config, opts Options) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	// Reserved before any work: a pass that started earlier must not
	// overwrite one that started later, however long its preflight took.
	ticket := nextPublishTicket()
	report := Report{
		Dir:          dir,
		StrictMode:   !executor.HostExecutionAllowed(),
		ReconciledAt: time.Now(),
	}
	if cfg == nil {
		if opts.publish() {
			publishAt(ticket, report)
		}
		return report
	}

	if d, ok := reconcileContainer(ctx, cfg, opts); ok {
		report.Diagnostics = append(report.Diagnostics, d)
	}
	if d, ok := reconcileKubernetes(ctx, dir, cfg, opts); ok {
		report.Diagnostics = append(report.Diagnostics, d)
	}

	sort.Slice(report.Diagnostics, func(i, j int) bool {
		return report.Diagnostics[i].ID < report.Diagnostics[j].ID
	})
	report.ReconciledAt = time.Now()

	logReport(report, opts)
	if opts.publish() {
		publishAt(ticket, report)
	}
	return report
}

// publishAt installs r as the current report unless a pass that started later
// has already published.
//
// Bootstrap deliberately runs two overlapping passes, tests construct many
// servers in one process, and a preflight against a wedged runtime can take
// the better part of a minute. Without this ordering check the *slowest* pass
// wins rather than the newest, so /readyz and the Executors panel could end up
// explaining a live hub with a dead one's diagnostics.
func publishAt(ticket uint64, r Report) {
	cp := cloneReport(r)
	lastMu.Lock()
	defer lastMu.Unlock()
	if ticket < publishedAt {
		return
	}
	publishedAt = ticket
	lastReport = &cp
}

// logReport emits one line per driver at startup. A silent bootstrap is how
// the original bug stayed invisible: the operator's only signal that a
// configured executor never came up was that runs failed later.
func logReport(r Report, opts Options) {
	for _, d := range r.Diagnostics {
		if opts.QuietWhenHealthy && d.Status == StatusOK {
			continue
		}
		if d.Status == StatusOK {
			opts.logf("executor %s (%s): ready", d.ID, d.Kind)
			continue
		}
		opts.logf("executor %s (%s): %s — %s", d.ID, d.Kind, d.Status, d.Message)
		if d.Remediation != "" {
			opts.logf("         fix: %s", d.Remediation)
		}
		// State the consequence, not just the cause. Without it an operator
		// reasonably assumes cloop degrades to running on the host, as it does
		// for many optional features — it does not: Resolve fails closed for
		// any project bound to this ID rather than downgrading it.
		if d.Status == StatusFailed {
			opts.logf("         projects bound to %s will be refused rather than run on this host.", d.ID)
		}
	}
	if r.StrictMode && !r.IsolatingRegistered() {
		opts.logf("executor: strict mode is on and no isolating executor is registered — " +
			"every run will be refused until one is configured or a remote agent enrolls")
	}
}

// reconcileContainer brings up the container sandbox driver. The bool reports
// whether a diagnostic applies at all: a config with no container section
// gets no card, because an executor nobody asked for is not a problem.
func reconcileContainer(ctx context.Context, cfg *config.Config, opts Options) (Diagnostic, bool) {
	if !cfg.Executors.Container.Enabled {
		return Diagnostic{}, false
	}
	reg := opts.registry()
	d := Diagnostic{
		Kind:      executor.KindContainer,
		Isolating: true,
		CheckedAt: time.Now(),
	}

	driverOpts, err := cfg.Executors.Container.DriverOptions()
	if err != nil {
		d.ID = fallbackID(cfg.Executors.Container.ID, "container")
		d.Status = StatusFailed
		d.Message = fmt.Sprintf("executors.container is enabled but invalid: %v", err)
		d.Remediation = "correct the executors.container section in .cloop/config.yaml, " +
			"then verify with `cloop config validate`"
		return d, true
	}
	// The image trust policy lives in its own top-level section because it
	// governs every backend identically, so it is attached here rather than in
	// DriverOptions, which only sees executors.container.
	driverOpts.ImagePolicy = cfg.Sandbox.ImagePolicy.Policy()
	d.ID = driverOpts.ID

	ex, err := ensureContainer(reg, driverOpts)
	if err != nil {
		d.Status = StatusFailed
		d.Message = fmt.Sprintf("could not be registered: %v", err)
		d.Remediation = containerRemediation(driverOpts, err)
		return d, true
	}

	if opts.SkipPreflight {
		d.Status = StatusOK
		d.Registered = true
		d.Message = "registered (preflight skipped)"
		return d, true
	}

	pctx, cancel := context.WithTimeout(ctx, opts.preflightTimeout())
	defer cancel()
	// Empty workDir: at control-plane startup there is no project to check,
	// and the driver documents that as "probe the runtime and image only".
	// Per-project bind-mount checks belong to `cloop executor test --workdir`.
	pre := ex.Preflight(pctx, "")
	d.Findings = convertContainerFindings(pre.Findings)
	d.Registered = true
	if err := pre.Err(); err != nil {
		d.Status = StatusDegraded
		d.Message = err.Error()
		d.Remediation = firstFix(d.Findings)
		if d.Remediation == "" {
			d.Remediation = containerRemediation(driverOpts, err)
		}
		return d, true
	}
	d.Status = StatusOK
	d.Message = fmt.Sprintf("registered: %s running %s", pre.Runtime, driverOpts.Image)
	return d, true
}

// ensureContainer returns the registered container executor, reusing one that
// is already present so repeated passes neither rebuild nor duplicate it.
func ensureContainer(reg *executor.Registry, opts container.Options) (*container.Executor, error) {
	if existing, err := reg.Get(opts.ID); err == nil {
		if ex, ok := existing.(*container.Executor); ok {
			return ex, nil
		}
		// Something else already owns this ID — a remote agent enrolled
		// under it, most likely. Refusing is the honest answer: silently
		// preflighting a different executor than the config describes would
		// report health for a backend the operator never configured.
		return nil, fmt.Errorf("executor ID %q is already taken by a %s executor",
			opts.ID, existing.Kind())
	}
	return container.Ensure(reg, opts)
}

// containerRemediation turns a registration or preflight failure into the
// command that fixes it. The runtime case is by far the most common — a hub
// image with no docker binary, or a socket the hub user cannot reach.
func containerRemediation(opts container.Options, err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found in $path"), strings.Contains(msg, "executable file not found"),
		strings.Contains(msg, "no container runtime"):
		return "install a container runtime (podman or docker) on the hub host and make it " +
			"reachable by the hub's user, or set executors.container.enabled: false and bind " +
			"projects to a Kubernetes or remote-agent executor instead"
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "cannot connect"),
		strings.Contains(msg, "daemon"):
		return "the container runtime is installed but not reachable by the hub's user — " +
			"add that user to the runtime's group (or run podman rootless) and restart the hub"
	case strings.Contains(msg, "image"):
		return fmt.Sprintf("pull the sandbox image first: `%s pull %s`",
			orDefault(opts.Runtime, "podman"), opts.Image)
	default:
		return fmt.Sprintf("run `cloop executor test %s` on the hub host to see the full checklist", opts.ID)
	}
}

// reconcileKubernetes brings up the ephemeral-Pod driver.
func reconcileKubernetes(ctx context.Context, dir string, cfg *config.Config, opts Options) (Diagnostic, bool) {
	if !cfg.Executors.Kubernetes.Enabled {
		return Diagnostic{}, false
	}
	reg := opts.registry()
	d := Diagnostic{
		Kind:      executor.KindKubernetes,
		Isolating: true,
		CheckedAt: time.Now(),
	}

	driverOpts, err := cfg.Executors.Kubernetes.DriverOptions()
	if err != nil {
		d.ID = fallbackID(cfg.Executors.Kubernetes.ID, "kubernetes")
		d.Status = StatusFailed
		d.Message = fmt.Sprintf("executors.kubernetes is enabled but invalid: %v", err)
		d.Remediation = "correct the executors.kubernetes section in .cloop/config.yaml, " +
			"then verify with `cloop config validate`"
		return d, true
	}
	// Same policy, same section, both backends — see reconcileContainer.
	driverOpts.ImagePolicy = cfg.Sandbox.ImagePolicy.Policy()
	d.ID = driverOpts.ID

	ex, created, err := ensureKubernetes(reg, dir, cfg, driverOpts, opts)
	if err != nil {
		d.Status = StatusFailed
		d.Message = fmt.Sprintf("could not be registered: %v", err)
		d.Remediation = kubernetesRemediation(cfg, driverOpts.ID)
		return d, true
	}

	// Only on the pass that actually registered it. Bootstrap reconciles
	// twice by design, and a sweep is API traffic plus a window in which two
	// concurrent sweeps could both decide to delete the same Pod.
	if created && opts.ReconcileOrphans {
		go sweepOrphans(ex, opts)
	}

	if opts.SkipPreflight {
		d.Status = StatusOK
		d.Registered = true
		d.Message = "registered (preflight skipped)"
		return d, true
	}

	pctx, cancel := context.WithTimeout(ctx, opts.preflightTimeout())
	defer cancel()
	pre := ex.Preflight(pctx)
	d.Findings = convertKubernetesFindings(pre.Findings)
	d.Registered = true
	if err := pre.Err(); err != nil {
		d.Status = StatusDegraded
		d.Message = err.Error()
		d.Remediation = firstFix(d.Findings)
		if d.Remediation == "" {
			d.Remediation = kubernetesRemediation(cfg, driverOpts.ID)
		}
		return d, true
	}
	d.Status = StatusOK
	d.Message = fmt.Sprintf("registered: namespace %s on %s",
		orDefault(pre.Namespace, "(from grant)"), orDefault(pre.Server, "(unknown server)"))
	return d, true
}

// ensureKubernetes returns the registered Kubernetes executor and whether
// this call is the one that registered it, building the credential source
// only when one must actually be constructed.
//
// The early registry lookup is what makes repeated reconciliation free: the
// broker credential source opens a state database that the executor holds for
// the process's lifetime and therefore never closes, so constructing one per
// pass would leak a handle every time.
func ensureKubernetes(
	reg *executor.Registry,
	dir string,
	cfg *config.Config,
	driverOpts kubernetes.Options,
	opts Options,
) (*kubernetes.Executor, bool, error) {
	if existing, err := reg.Get(driverOpts.ID); err == nil {
		if ex, ok := existing.(*kubernetes.Executor); ok {
			return ex, false, nil
		}
		return nil, false, fmt.Errorf("executor ID %q is already taken by a %s executor",
			driverOpts.ID, existing.Kind())
	}

	source := opts.KubernetesCredentials
	if source == nil {
		source = BrokerCredentials
	}
	identity, cleanup, err := source(dir, cfg, driverOpts.ID)
	if err != nil {
		return nil, false, err
	}
	driverOpts.Credentials = identity.Cluster
	driverOpts.Workspace = identity.Workspace
	ex, err := kubernetes.Ensure(reg, driverOpts)
	if err != nil {
		// The source is live and owns an open state database, but nothing
		// will ever read it: the executor it was built for is not registered.
		// Releasing it here is what keeps a hub that reconciles repeatedly
		// against a rejected config from leaking a SQLite handle per pass.
		if cleanup != nil {
			cleanup()
		}
		return nil, false, err
	}
	return ex, true, nil
}

// sweepOrphans garbage-collects Pods a previous control plane left running.
//
// Detached and bounded: a cluster slow to answer must not delay the hub's
// startup, and a sweep that cannot finish in a minute is one the next restart
// can finish instead.
func sweepOrphans(ex *kubernetes.Executor, opts Options) {
	defer func() {
		if r := recover(); r != nil {
			opts.logf("executor: panic during orphaned-Pod sweep: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	removed, err := ex.ReconcileOrphans(ctx)
	if err != nil {
		opts.logf("executor %s: could not reconcile orphaned Pods: %v", ex.ID(), err)
		return
	}
	if len(removed) > 0 {
		opts.logf("executor %s: garbage-collected %d orphaned Pod(s) from a previous run: %s",
			ex.ID(), len(removed), strings.Join(removed, ", "))
	}
}

// kubernetesRemediation names the identity the operator has to fix, which
// differs entirely between the two credential modes.
func kubernetesRemediation(cfg *config.Config, execID string) string {
	if cfg.Executors.Kubernetes.InCluster {
		return "the hub Pod's ServiceAccount cannot reach the cluster — check that the chart's " +
			"Role and RoleBinding are installed in the workload namespace and that " +
			"automountServiceAccountToken is not disabled on the hub Pod"
	}
	return fmt.Sprintf("set CLOOP_SECRET_KEY and grant a kubeconfig to this executor: "+
		"`cloop secret mint %s-kubeconfig --kind kubeconfig --file ~/.kube/config && "+
		"cloop secret grant %s-kubeconfig --to executor:%s`, or set "+
		"executors.kubernetes.in_cluster when the hub runs inside the target cluster",
		execID, execID, execID)
}

// BrokerCredentials is the default Kubernetes identity source: the hub Pod's
// own ServiceAccount when in_cluster is set, otherwise a kubeconfig leased
// from the secret broker in dir's state database.
//
// There is no fallback between the two. An executor that quietly authenticated
// as something other than what config named would make the audit trail lie
// about who did what in the cluster.
//
// On the success path the returned cleanup is deliberately NOT called by the
// caller that registers the executor: the driver holds the broker for as long
// as the process runs and needs it on every Start. Process exit closes it,
// which for both a CLI invocation and a long-running hub is exactly the
// intended lifetime. The cleanup exists for the one path where the source was
// built and registration then failed.
func BrokerCredentials(dir string, cfg *config.Config, execID string) (Identity, func(), error) {
	k := cfg.Executors.Kubernetes
	if k.InCluster {
		src, err := kubernetes.NewInClusterSource(k.Namespace)
		if err != nil {
			return Identity{}, nil, fmt.Errorf("in_cluster is set but the ServiceAccount is unusable: %w", err)
		}
		// Backed by the Pod's projected token on disk, so the cluster
		// credential has nothing to release. The workspace credential is a
		// separate question: it needs the broker, and an in-cluster hub is
		// specifically the deployment that may not have a sealing key
		// configured yet. Attempting it and accepting nil keeps that hub
		// schedulable — public repositories still clone, and the driver's
		// preflight reports the gap rather than the chart failing to come up.
		ws, closeWS := optionalWorkspaceSource(dir, execID)
		return Identity{Cluster: src, Workspace: ws}, closeWS, nil
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return Identity{}, nil, fmt.Errorf("needs a secret broker for its kubeconfig, but the state "+
			"database at %s could not be opened: %w", state.DBPath(dir), err)
	}
	closeDB := func() { _ = db.Close() }
	store, err := secretstore.New(db)
	if err != nil {
		closeDB()
		return Identity{}, nil, fmt.Errorf("needs a secret broker for its kubeconfig: %w", err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		closeDB()
		return Identity{}, nil, fmt.Errorf("needs a secret broker for its kubeconfig: %w", err)
	}
	src, err := kubernetes.NewBrokerSource(broker, execID, k.KubeconfigSecret, k.Context)
	if err != nil {
		closeDB()
		return Identity{}, nil, err
	}
	// The same broker, so a private-repository fetch and the cluster
	// credential are governed by one grant store and one audit trail.
	ws, err := gitcreds.New(broker, execID, "reconcile")
	if err != nil {
		closeDB()
		return Identity{}, nil, err
	}
	return Identity{Cluster: src, Workspace: ws}, closeDB, nil
}

// optionalWorkspaceSource builds a workspace credential source from dir's
// state database, or returns nil when it cannot.
//
// Nil is a supported outcome, not a swallowed error: an executor with no
// workspace source fetches public repositories anonymously and refuses private
// ones by name (see *executor.WorkspaceGrantError), which is a far better
// deployment story than an in-cluster hub that will not start because nobody
// has minted a GitHub secret yet. Preflight reports it as a warning.
func optionalWorkspaceSource(dir, execID string) (executor.WorkspaceCredentialSource, func()) {
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil, nil
	}
	closeDB := func() { _ = db.Close() }
	store, err := secretstore.New(db)
	if err != nil {
		closeDB()
		return nil, nil
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		// Almost always a missing CLOOP_SECRET_KEY, which is exactly the
		// in-cluster case this function exists for.
		closeDB()
		return nil, nil
	}
	src, err := gitcreds.New(broker, execID, "reconcile")
	if err != nil {
		closeDB()
		return nil, nil
	}
	return src, closeDB
}

func convertContainerFindings(in []container.Finding) []Finding {
	if len(in) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		out = append(out, Finding{Name: f.Name, Level: f.Level, Message: f.Message, Fix: f.Fix})
	}
	return out
}

func convertKubernetesFindings(in []kubernetes.Finding) []Finding {
	if len(in) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		out = append(out, Finding{Name: f.Name, Level: f.Level, Message: f.Message, Fix: f.Fix})
	}
	return out
}

// firstFix returns the remedy attached to the first fatal finding. Preflight
// checks run in dependency order, so the earliest failure is the one to fix
// first — later ones are usually its consequences.
func firstFix(findings []Finding) string {
	for _, f := range findings {
		if f.Level == "fail" && f.Fix != "" {
			return f.Fix
		}
	}
	return ""
}

// fallbackID names a driver whose options could not be parsed, so the
// diagnostic still has something to key on. The driver's own default ID is
// what Normalize would have produced.
func fallbackID(configured, def string) string {
	if id := strings.TrimSpace(configured); id != "" {
		return id
	}
	return def
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
