// Executor plumbing for the Web UI (Task 20156).
//
// The UI used to fork harness processes itself with raw exec.Command. It no
// longer does — every workload the UI starts goes through
// executor.Resolve(projectPath).Start(...), so where that workload actually
// runs (this host, a container, a remote edge device) becomes a deployment
// decision instead of a hard-coded assumption. no_direct_exec_test.go
// enforces that no exec.Command creeps back into this package.
//
// This file holds the three things the UI needs from that abstraction:
//
//   - bootstrap: registering the built-in host driver and wiring the
//     persistent project→executor binding lookup to statedb;
//   - startWorkload / runWorkload: the two call shapes the handlers use
//     (detached-with-streaming, and synchronous-collect-output);
//   - drainToStderr: the "echo the child's output to the server log"
//     behavior the pre-abstraction handlers got for free by assigning
//     cmd.Stdout = os.Stderr.

package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/executor/reconcile"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var builtinExecutorsOnce sync.Once

// controlPlaneDirMu guards controlPlaneDirValue, which bootstrapExecutors
// records so the package-level workload helpers can find the control plane's
// database. startWorkload and runWorkload have no Server receiver — they are
// called from handlers that only know a project path — and the alternative,
// re-deriving the control plane directory from each project, is exactly the
// confusion between "the tenant's database" and "the operator's database"
// that secret grants must not have.
var (
	controlPlaneDirMu    sync.RWMutex
	controlPlaneDirValue string
)

// controlPlaneDir returns the directory holding the control plane's own
// state database, or "" before bootstrap.
func controlPlaneDir() string {
	controlPlaneDirMu.RLock()
	defer controlPlaneDirMu.RUnlock()
	return controlPlaneDirValue
}

// registerBuiltinExecutors registers the drivers that ship in-process. It is
// idempotent and is called from both Server construction and every workload
// entry point, so a Server built as a struct literal (as several tests do)
// still has a usable registry.
//
// The host driver is registered unconditionally so a fresh single-machine
// install works with no configuration. Deployments that must never execute
// on the control-plane host unbind it and pin every project to an isolated
// executor; Resolve then fails closed rather than falling back here.
func registerBuiltinExecutors() {
	builtinExecutorsOnce.Do(func() {
		err := localprocess.Ensure(executor.DefaultRegistry)
		// Under strict mode this refusal is the designed outcome, not a
		// problem: the policy exists to keep the host driver out. Logging it
		// printed an alarming line on every hardened start — and, because the
		// isolating drivers are reconciled a moment later, one whose
		// "no isolated executor is configured" advice was usually false.
		if err == nil || errors.Is(err, executor.ErrHostExecutionDenied) {
			return
		}
		fmt.Fprintf(os.Stderr, "ui: register local executor: %v\n", err)
	})
}

// bootstrapExecutors registers the built-in drivers, reconciles the
// configured isolating ones, applies the host-execution policy, points the
// registry at this control plane's persisted project→executor bindings, and
// records a row for every backend that can run work.
func bootstrapExecutors(dir string) {
	// Policy first. Registration of a non-isolating driver is refused under
	// strict mode, so reading the config after registering would let the host
	// driver in through the door the policy exists to close. (The eviction
	// sweep in ApplyHostExecutionPolicy covers the reverse order too, since
	// other entry points also register; doing it in the right order here
	// means the refusal is the normal path rather than the repair.)
	applyHostExecutionPolicy(dir)
	// Host driver before the configured ones so it keeps being the registry
	// default on a permissive single-machine install — Register makes the
	// first executor the default, and an operator who enabled a container
	// sandbox without binding any project to it should not silently have
	// every project move into it. Under strict mode this registration is
	// refused and the first isolating driver below becomes the default,
	// which is exactly what that mode is asking for.
	registerBuiltinExecutors()
	reconcileConfiguredExecutors(dir)
	controlPlaneDirMu.Lock()
	controlPlaneDirValue = dir
	controlPlaneDirMu.Unlock()
	executor.SetBindingLookup(func(projectPath string) (string, bool) {
		return lookupProjectExecutor(dir, projectPath)
	})
	// Workspace provisioning is audited by whoever dispatched it. pkg/executor
	// is a leaf package the edge agent also imports, so it cannot write to the
	// hub's journal itself; it exposes a process-wide sink instead and the
	// control plane installs it here. Anywhere else — a CLI command, an agent
	// — the events are dropped, which is correct: an agent's local provisioning
	// belongs in the trail of the hub that asked for it, not in a journal on
	// the device. Best-effort, like every other emitter.
	executor.SetWorkspaceAuditor(workspaceAuditSink(dir))
	syncRegistryToStore(dir)
	// Before the supervisor, which can dispatch and therefore mint new leases.
	// The sweep skips directories held by a live lease, so the order is not
	// load-bearing for correctness — but a sweep that runs while work is
	// starting has to reason about a moving set, and there is no reason to make
	// it. At this point every recorded directory is unambiguously an orphan of
	// a previous run.
	sweepOrphanedLeaseDirs(dir)
	startExecutorSupervisor(dir)
}

// applyHostExecutionPolicy reads executors.allow_host_process and installs it
// on the process-wide switch that executor.Resolve and the localprocess driver
// both consult (Task 20160).
//
// The `cloop ui` command reaches here through cmd/root.go's PersistentPreRunE,
// which has already applied the same setting. Doing it again is deliberate:
// pkg/ui is also constructed directly by tests and by embedders, and a
// hardened deployment must not depend on which entry point happened to build
// the Server.
//
// It goes through ApplyHostExecutionPolicy rather than the raw switch so the
// policy can only tighten. That matters most here: a Server is constructed per
// dashboard instance and the dir it reads is a *project* directory in
// single-project mode, so a symmetric apply would let a managed project's own
// config.yaml re-enable host execution for the whole control plane.
//
// A config that cannot be read leaves the switch untouched — the setting lives
// in that file, so an unreadable one means "no policy stated here", not
// "policy withdrawn".
func applyHostExecutionPolicy(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	cfg, err := config.Load(dir)
	if err != nil || cfg == nil {
		return
	}
	executor.ApplyHostExecutionPolicy(cfg.Executors.HostProcessAllowed())
}

// reconcileConfiguredExecutors brings up the container and Kubernetes drivers
// this control plane's config enables (Task 20170).
//
// Before it, only the localprocess driver was registered here and the
// isolating drivers came up from cmd/root.go's PersistentPreRunE — keyed off
// os.Getwd() rather than the directory this server was handed, and with any
// failure printed to stderr and forgotten. A hub deployed from the Helm chart
// with allow_host_process: false therefore had the host driver correctly
// refused and no isolating driver registered, and nothing anywhere said so.
//
// A config that cannot be read is not an error: single-project `cloop ui`
// runs in directories that have no executors section at all, and the host
// driver registered above is the whole configuration those deployments need.
func reconcileConfiguredExecutors(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	cfg, err := config.Load(dir)
	if err != nil || cfg == nil {
		return
	}
	reconcile.Bootstrap(dir, cfg, reconcile.Options{
		// This is a process a control plane restarts as, so it is worth
		// paying for the sweep that cleans up Pods a previous instance left
		// running when it died mid-run.
		ReconcileOrphans: true,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "ui: "+format+"\n", args...)
		},
	})
}

// restoreEnrolledExecutors registers an offline executor for every agent that
// previously enrolled, before the listener opens.
//
// The agent hub is otherwise built lazily on the first request that touches
// it, and under strict mode that is a deadlock (Task 20170). A hub whose only
// isolating backends are edge devices starts with an empty registry, so
// /readyz reports not-ready, so Kubernetes drops it from the Service
// Endpoints, so no agent can reach /api/executors/connect to be restored — and
// the hub never becomes ready again. Since edge devices are a first-class
// fleet for cloop, not an edge case, the restore has to happen before anything
// can observe readiness.
//
// It runs from Run rather than from bootstrapExecutors because the hub
// captures ExternalURL and AllowedOrigins, which cmd/ui_cmd.go sets on the
// Server *after* New returns. Building it during New would freeze empty origin
// rules into a sync.Once for the process's lifetime.
//
// A failure is logged, not fatal: a control plane that cannot read its agent
// table should still serve the dashboard that lets someone fix it.
func (s *Server) restoreEnrolledExecutors() {
	if _, err := s.remoteHub(); err != nil {
		fmt.Fprintf(os.Stderr, "ui: restore enrolled executors: %v\n", err)
	}
}

// denyHostSideEffect refuses a handler that must run a program on the
// control-plane host itself, when policy forbids host execution.
//
// A handful of endpoints are not workload dispatch and so cannot be routed
// through an executor: `claude auth login` writes credentials into the control
// plane's own home directory, and inline task replay reads the project's git
// history in-process. They are host execution all the same — an HTTP request
// causes a program to run next to the control plane — so strict mode has to
// refuse them, or "the UI never executes on the host" is true only of the
// paths someone remembered to convert.
//
// projectPath may be empty, and is for endpoints whose side effect belongs to
// the control plane rather than to any one project — `claude auth login`
// writes credentials for the server's own identity, not a tenant's.
//
// It returns true when the request was refused and a response already written.
// The typed error carries the remediation, so the operator sees what to change
// rather than a bare 409. tests/security enumerates every handler that reaches
// this gate and asserts each one still refuses.
func denyHostSideEffect(w http.ResponseWriter, projectPath, what string) bool {
	if executor.HostExecutionAllowed() {
		return false
	}
	err := &executor.HostExecutionDeniedError{
		ExecutorID:   what,
		ProjectPath:  projectPath,
		Alternatives: executor.IsolatedIDs(),
	}
	jsonErr(w, err.Error(), http.StatusConflict)
	return true
}

// lookupProjectExecutor reads the persisted project→executor binding from
// the control plane's state database.
//
// Bindings live in the control plane's own DB rather than each project's,
// because a project pinned to a remote executor may not have a readable
// local .cloop directory at all. A missing database, an unmigrated one, or
// any read error yields "no binding" — the registry then falls back to its
// default, which is the same behavior as before bindings existed.
func lookupProjectExecutor(controlPlaneDir, projectPath string) (string, bool) {
	if controlPlaneDir == "" || projectPath == "" {
		return "", false
	}
	dbPath := state.DBPath(controlPlaneDir)
	if _, err := os.Stat(dbPath); err != nil {
		return "", false
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return "", false
	}
	defer db.Close()

	id, ok, err := db.ProjectExecutor(projectPath)
	if err != nil || !ok {
		return "", false
	}
	return id, true
}

// uiSpec builds an executor.Spec for a cloop subcommand run in workDir.
// Labels carry provenance so an executor (especially a remote one) can
// attribute a workload back to the project and handler that requested it.
func uiSpec(workDir string, argv []string, labels map[string]string) executor.Spec {
	spec := executor.Spec{
		WorkDir: workDir,
		Argv:    argv,
		Labels:  map[string]string{"component": "web-ui"},
	}
	if workDir != "" {
		spec.Labels["project"] = workDir
	}
	for k, v := range labels {
		spec.Labels[k] = v
	}
	return spec
}

// startWorkload resolves the executor bound to workDir and starts argv on
// it, detached: the workload outlives the HTTP request that started it.
//
// It returns the executor alongside the handle because the caller needs the
// same instance to Stream and Status the handle — re-resolving later could
// pick a different executor if bindings changed mid-run.
func startWorkload(workDir string, argv []string, labels map[string]string) (executor.Executor, executor.Handle, error) {
	registerBuiltinExecutors()
	ex, err := executor.Resolve(workDir)
	if err != nil {
		return nil, executor.Handle{}, fmt.Errorf("no executor available for %s: %w", workDir, err)
	}

	// The lease outlives this call because the workload does. Wiping it here
	// would pull the credential files out from under a process that has not
	// read them yet, so cleanup is deferred to a watcher that waits for the
	// handle to reach a terminal state.
	lease := acquireSecretLease(controlPlaneDir(), workDir, ex)
	spec, err := applyLease(uiSpec(workDir, argv, labels), ex, lease)
	if err != nil {
		lease.Close()
		return nil, executor.Handle{}, err
	}

	// Repositories the lease opened from the hub's own filesystem. Before the
	// sandbox check, so that a project whose executor cannot receive them is
	// refused for that reason — which names both the grant and the binding —
	// rather than for whatever the next check would have complained about.
	spec, err = applyRepoGrants(spec, ex, lease)
	if err != nil {
		lease.Close()
		return nil, executor.Handle{}, err
	}

	// The project's .cloop/sandbox.yaml, if it has one. It is applied after
	// the lease so its env allowlist can narrow the leased secrets, and it is
	// refused rather than partially honoured when the bound executor cannot
	// provide what it asks for.
	spec, sandboxSpec, err := applySandbox(spec, ex, workDir)
	if err != nil {
		lease.Close()
		auditImageDenial(workDir, err)
		return nil, executor.Handle{}, err
	}

	// Then the source tree — after the sandbox, never before. The sandbox is
	// what sets Workspace.SizeLimitMB (from resources.disk) and what refuses a
	// spec the executor cannot honour; applyWorkspace fills in the rest and
	// carries that limit across. The reverse order would let the sandbox
	// overwrite a workspace decision that was made against the executor it had
	// already been checked on. Its own capability gate runs last, inside
	// applyWorkspace, because the requirement it checks does not exist until
	// the workspace is on the spec.
	//
	// It is before Start because a tree that cannot be materialised is a run
	// that must not begin: a workload starting cleanly on an empty directory is
	// the exact failure this subsystem exists to remove.
	spec, err = applyWorkspace(spec, ex, workDir)
	if err != nil {
		lease.Close()
		return nil, executor.Handle{}, err
	}

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		lease.Close()
		// The executor enforces the image policy too, and it is the layer that
		// verifies signatures — so a denial can surface here and not above.
		auditImageDenial(workDir, err)
		return nil, executor.Handle{}, err
	}
	go wipeLeaseOnExit(ex, handle.ID, lease)
	recordSandboxProvenance(workDir, sandboxSpec, ex, handle)

	// Record the dispatch so the supervisor can fail it over if this executor
	// dies holding it. Best-effort: a session that cannot be recorded yields
	// an empty ID and the run proceeds untracked rather than not at all.
	if sessionID := openSessionFor(controlPlaneDir(), ex, handle, spec); sessionID != "" {
		go watchSessionExit(controlPlaneDir(), ex, handle.ID, sessionID)
	}
	return ex, handle, nil
}

// wipeLeaseOnExit closes a lease once its workload reaches a terminal state.
//
// Streaming is the signal rather than polling Status: the driver closes the
// output channel when the workload is finished and its output drained, which
// is precisely the moment the credentials stop being needed. A driver that
// cannot stream falls back to polling, and either way the wipe is bounded by
// maxLeaseWatch so a lost workload cannot strand a credential directory for
// the lifetime of the server.
func wipeLeaseOnExit(ex executor.Executor, handleID string, lease *secretLease) {
	defer recoverGoroutine("secret lease wipe: " + handleID)
	if lease == nil {
		return
	}
	defer lease.Close()

	const maxLeaseWatch = 24 * time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), maxLeaseWatch)
	defer cancel()

	if lines, err := ex.Stream(ctx, handleID); err == nil {
		for range lines {
			// Drain without buffering: another subscriber (drainToStderr,
			// the live log panel) is the one that cares about the content.
		}
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st, err := ex.Status(ctx, handleID)
			if err != nil || st.State.Terminal() {
				return
			}
		}
	}
}

// runWorkload resolves the executor bound to workDir and runs argv to
// completion, returning combined output. ctx bounds the workload: when it is
// cancelled or times out the workload is killed, matching the
// exec.CommandContext semantics the UI relied on before.
func runWorkload(ctx context.Context, workDir string, argv []string, labels map[string]string) ([]byte, error) {
	return runWorkloadEnv(ctx, workDir, argv, nil, labels)
}

// runWorkloadEnv is runWorkload with extra environment variables for the
// workload. It exists so a caller can hand a credential to a subcommand
// without putting it on the argv, where /proc/<pid>/cmdline exposes it to
// every local user for the lifetime of the process (Task 20188).
//
// extraEnv entries are "K=V" and are appended to the inherited environment,
// not substituted for it: applyLease reads a nil Spec.Env as "inherit
// os.Environ()", so assigning a bare one-element slice would silently strip
// PATH and HOME from the child.
func runWorkloadEnv(ctx context.Context, workDir string, argv, extraEnv []string, labels map[string]string) ([]byte, error) {
	registerBuiltinExecutors()
	ex, err := executor.Resolve(workDir)
	if err != nil {
		return nil, fmt.Errorf("no executor available for %s: %w", workDir, err)
	}
	// Run is synchronous, so the lease's lifetime is exactly this call's.
	lease := acquireSecretLease(controlPlaneDir(), workDir, ex)
	defer lease.Close()

	base := uiSpec(workDir, argv, labels)
	if len(extraEnv) > 0 {
		base.Env = append(os.Environ(), extraEnv...)
	}
	spec, err := applyLease(base, ex, lease)
	if err != nil {
		return nil, err
	}
	spec, err = applyRepoGrants(spec, ex, lease)
	if err != nil {
		return nil, err
	}
	spec, _, err = applySandbox(spec, ex, workDir)
	if err != nil {
		auditImageDenial(workDir, err)
		return nil, err
	}
	// Same order and the same reasons as startWorkload, and deliberately not
	// exempted for being a "short helper subcommand". Every caller of this
	// function reads or writes the project: `cloop do`, `cloop suggest`,
	// `cloop reset` and `cloop listen` come through runCloopSubcommand, and all
	// but the last operate on .cloop/ inside the tree. Running them against an
	// empty directory is the same bug as running a harness against one, only
	// quieter — `cloop suggest` would return suggestions for no code.
	//
	// The one caller that genuinely needs no tree is /api/projects/new's
	// `cloop init`, which creates a project from nothing. On an executor that
	// does not share this filesystem that call could never have worked: init
	// writes .cloop/ into a filesystem the hub will never read, while the hub
	// registers the local path it just created. It now fails with a named
	// error instead of appearing to succeed, which is the honest outcome.
	spec, err = applyWorkspace(spec, ex, workDir)
	if err != nil {
		return nil, err
	}
	res, runErr := executor.Run(ctx, ex, spec)
	if runErr != nil {
		auditImageDenial(workDir, runErr)
	}
	return res.Output, runErr
}

// drainToStderr copies a workload's output stream to the UI server's stderr,
// reproducing what `cmd.Stdout = os.Stderr` did before. Runs until the
// workload finishes and the driver closes the channel.
func drainToStderr(lines <-chan executor.LogLine, prefix string) {
	defer recoverGoroutine("executor stderr drain: " + prefix)
	for line := range lines {
		if line.Text == "" {
			continue
		}
		_, _ = io.WriteString(os.Stderr, line.Text)
	}
}
