package hubdoctor

// The dispatch smoke test: the one check that proves the circuit instead of
// describing it.
//
// # Why the rest of this package is not enough
//
// Everything else here reads configuration and probes endpoints. That catches a
// great deal, and it cannot catch the failure an operator actually has after
// enrolling a device: the issuer resolves, the certificate is valid, RBAC has an
// admin, the image policy is deny-by-default, the executor answers a liveness
// probe — and the first real task still fails, because the harness image has no
// shell, or the agent cannot write its workspace, or the driver silently drops
// the credential files it advertised support for. Every one of those is invisible
// to a check that never dispatches anything.
//
// tests/flagship proves the whole circuit, but it proves it in CI, on one
// machine, against a container executor built for the purpose. The operator who
// has just run `cloop executor enroll` for a device in another building cannot
// run it, and so still finds out whether their fleet works by starting a real
// task and reading logs.
//
// # What it does
//
// It dispatches a trivial workload through the same primitives a real task
// takes — placement, workspace, a secret file lease, executor.Run's
// stream/signal/teardown, and write-back where the backend advertises it — and
// reports each stage separately. Per stage matters: "the executor is broken" is
// not actionable, "the workload ran but the lease file never arrived" names a
// driver capability and a grant.
//
// # Hermetic, and what that costs
//
// The workload touches no network, clones no repository and calls no model. That
// is what makes it safe to run against production and fast enough for a
// readiness gate, and it is also the honest boundary of what it proves: a green
// smoke says the circuit carries work, not that a model is reachable or a
// repository is grantable. Stages it cannot prove report skip, never pass —
// "we did not look" and "we looked and it was fine" are different answers, and
// this package's contract is that only one of them is allowed to read as green.
//
// # Leaving nothing behind
//
// A diagnostic that leaks is worse than none: it turns "is my fleet healthy"
// into a command that accumulates containers, Pods, policies and credential
// material every time it is run, on the machines least likely to be watched.
// Every resource is registered on a LIFO cleanup stack the moment it exists,
// and the stack runs on every exit path — success, stage failure, panic, and
// ctrl-C — under a context that cancellation cannot reach. What it could not
// remove is reported as a leak with its own exit code, because the one thing
// worse than leaking is leaking quietly.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// SmokeStage names one leg of the circuit. The values are stable: they appear
// in --json and are what a pipeline greps for.
type SmokeStage string

const (
	// StagePlacement: would the scheduler actually choose this executor for
	// this workload? Run first because a failure here means nothing was
	// dispatched, which is a different problem from a dispatch that broke.
	StagePlacement SmokeStage = "placement"
	// StageWorkspace: did the workload get a usable working directory.
	StageWorkspace SmokeStage = "workspace"
	// StageLease: was a throwaway credential file minted, granted and
	// delivered to the sandbox.
	StageLease SmokeStage = "lease"
	// StageDispatch: did the workload start and exit zero.
	StageDispatch SmokeStage = "dispatch"
	// StageLogs: did its output come back over the stream.
	StageLogs SmokeStage = "logs"
	// StageWriteBack: did file changes return, for a backend that advertises
	// the capability.
	StageWriteBack SmokeStage = "write_back"
	// StageRevocation: is the credential material gone, verified rather than
	// assumed.
	StageRevocation SmokeStage = "revocation"
	// StageCleanup: did everything this run created get removed.
	StageCleanup SmokeStage = "cleanup"
)

// smokeStageOrder is the order stages are reported in, which is also the order
// they run in. Kept explicit so a reordering is a visible edit rather than an
// accident of control flow.
var smokeStageOrder = []SmokeStage{
	StagePlacement, StageWorkspace, StageLease, StageDispatch,
	StageLogs, StageWriteBack, StageRevocation, StageCleanup,
}

// StageOutcome is what happened to one stage.
type StageOutcome string

const (
	// StagePass: verified.
	StagePass StageOutcome = "pass"
	// StageSkip: not applicable to this backend, or not provable hermetically.
	// Deliberately not a pass — see the package comment.
	StageSkip StageOutcome = "skip"
	// StageFail: this leg of the circuit is broken.
	StageFail StageOutcome = "fail"
)

// StageResult is one stage's verdict.
type StageResult struct {
	Stage   SmokeStage   `json:"stage"`
	Outcome StageOutcome `json:"outcome"`
	Message string       `json:"message"`
	// Remediation names the fix. Required for anything that is not a pass,
	// for the same reason Finding.Remediation is.
	Remediation string         `json:"remediation,omitempty"`
	DurationMS  int64          `json:"duration_ms,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// SmokeResult is one executor's whole run.
type SmokeResult struct {
	ExecutorID string `json:"executor_id"`
	Kind       string `json:"kind,omitempty"`
	Isolation  string `json:"isolation,omitempty"`
	// Stages in smokeStageOrder.
	Stages []StageResult `json:"stages"`
	// FirstFailure is the stage that broke, or "" when none did. It is the
	// single most useful field in the report: the stages after a failure are
	// consequences, and an operator reading a wall of red needs to know which
	// line to act on.
	FirstFailure SmokeStage `json:"first_failure,omitempty"`
	// Leaked names resources cleanup could not remove. Non-empty is an
	// operator action item, not a warning.
	Leaked     []string `json:"leaked,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

// OK reports whether every stage that ran either passed or was skipped.
func (r SmokeResult) OK() bool { return r.FirstFailure == "" && len(r.Leaked) == 0 }

// Smoke exit codes. Distinct so the command is usable both as a Kubernetes
// readiness gate (which only cares about zero) and as a post-deploy CI step
// (which wants to tell a broken executor from a misconfigured hub from a
// diagnostic that left rubbish behind).
//
// 2 is deliberately unused: Cobra and `cloop executor test` already spend it.
const (
	// SmokeExitOK: every target smoked clean.
	SmokeExitOK = 0
	// SmokeExitConfig: a non-smoke check failed, so the hub is misconfigured
	// independently of whether it can dispatch. Matches Report.ExitCode.
	SmokeExitConfig = 1
	// SmokeExitNoTargets: there was nothing to smoke. Not the same as healthy:
	// a hub with no executor cannot run anything.
	SmokeExitNoTargets = 3
	// SmokeExitFailed: at least one executor failed a stage.
	SmokeExitFailed = 4
	// SmokeExitLeaked: the run could not clean up after itself. Highest
	// precedence — it is the only outcome that needs a human on a machine.
	SmokeExitLeaked = 5
)

// DefaultSmokeTimeout bounds one executor's smoke run.
//
// Ninety seconds is generous against the observed cost of starting a container
// from a warm image and stingy against a cold image pull, which is the right
// trade: a smoke test that waits five minutes for a registry is being used as a
// deployment tool, and the pull belongs in `cloop executor test` or in the
// image pre-staging reconciliation already does at startup.
const DefaultSmokeTimeout = 90 * time.Second

// smokeCleanupBudget bounds the cleanup stack after the run. Separate from the
// run's own budget and never derived from it: cleanup most needs to work in
// exactly the cases where the run's deadline already expired.
const smokeCleanupBudget = 30 * time.Second

// smokeLeaseTTL is how long the throwaway credential lives.
//
// Seconds, not minutes, and that is a requirement rather than a tuning choice.
// This command mints a real credential in the operator's real broker; the
// window in which that material exists is the window in which a diagnostic
// could become an incident. The run needs it only for as long as one `sh`
// takes to read a file.
const smokeLeaseTTL = 60 * time.Second

// smokeWorkload is the hermetic workload: POSIX sh, no network, no repository,
// no model call.
//
// It reports on itself in key=value lines rather than exiting non-zero on the
// first problem, because "the workload ran and the lease file was missing" and
// "the workload never ran" are different failures with different fixes, and an
// exit code cannot tell them apart. Every value it prints is derived — it
// greps the credential file for a marker and reports yes or no. It never
// prints the file, because this output goes to an operator's terminal and from
// there into CI logs.
const smokeWorkload = `
echo "smoke_nonce=${CLOOP_SMOKE_NONCE:-unset}"
echo "smoke_uid=$(id -u 2>/dev/null || echo unknown)"
if [ -f "./cloop-smoke-marker" ]; then
  echo "smoke_marker=$(cat ./cloop-smoke-marker 2>/dev/null)"
else
  echo "smoke_marker=absent"
fi
if : > ./cloop-smoke-write 2>/dev/null; then
  echo "smoke_writable=yes"
  rm -f ./cloop-smoke-write 2>/dev/null
else
  echo "smoke_writable=no"
fi
if [ -n "${KUBECONFIG:-}" ] && [ -f "${KUBECONFIG}" ]; then
  if grep -q "cloop-smoke-${CLOOP_SMOKE_NONCE}" "${KUBECONFIG}" 2>/dev/null; then
    echo "smoke_lease=delivered"
  else
    echo "smoke_lease=wrong-content"
  fi
elif [ -n "${KUBECONFIG:-}" ]; then
  echo "smoke_lease=env-without-file"
else
  echo "smoke_lease=absent"
fi
echo "smoke_done=ok"
`

// checkSmoke runs the dispatch smoke test and records what it found.
//
// It runs after checkExecutors and depends on it: reconciliation is what puts
// drivers in this process's registry, and there is nothing to dispatch to
// before that has happened.
func checkSmoke(ctx context.Context, dir string, cfg *config.Config, opts Options, rep *Report, add addFn) {
	if cfg == nil || !opts.Smoke {
		return
	}
	if opts.Offline {
		add(Finding{
			Check: "smoke.dispatch", Title: "Dispatch smoke test", Severity: SeverityWarn,
			Message: "--smoke was requested alongside --offline, so nothing was dispatched",
			Remediation: "Drop --offline: the smoke test has to start a workload, which is the " +
				"only way to tell a configured executor from a working one",
		})
		return
	}

	targets, skipped := smokeTargets(dir, strings.TrimSpace(opts.ProbeExecutorID))
	if len(targets) == 0 {
		msg := "no executor is available to smoke"
		remedy := "Enable executors.container or executors.kubernetes, or enroll a remote agent " +
			"with `cloop executor enroll --name <device>`"
		if id := strings.TrimSpace(opts.ProbeExecutorID); id != "" {
			msg = fmt.Sprintf("no executor named %q is registered", id)
			remedy = "Check the name against `cloop executor list`; a remote agent appears only " +
				"once it has connected at least once"
		} else if len(skipped) > 0 {
			// The distinction an operator needs: nothing to smoke because
			// nothing exists, versus nothing to smoke because they cordoned
			// everything. The second is a deliberate state, not a defect.
			msg = fmt.Sprintf("every executor is cordoned or draining (%s)", strings.Join(skipped, ", "))
			remedy = "Uncordon one with `cloop hub executor uncordon <id>`, or name it explicitly " +
				"with --executor to smoke it anyway"
		}
		add(Finding{
			Check: "smoke.dispatch", Title: "Dispatch smoke test", Severity: SeverityWarn,
			Message: msg, Remediation: remedy,
		})
		rep.SmokeRan = true
		return
	}
	if len(skipped) > 0 {
		// Never silently narrow the fleet: an operator who runs this to find
		// which of ten devices is broken must be told that three were not
		// looked at.
		add(Finding{
			Check: "smoke.skipped", Title: "Executors not smoked", Severity: SeverityWarn,
			Message: fmt.Sprintf("%d executor(s) were skipped because they are cordoned or draining: %s",
				len(skipped), strings.Join(skipped, ", ")),
			Remediation: "Name one with --executor to smoke it anyway, or uncordon it",
		})
	}

	rep.SmokeRan = true
	for _, ex := range targets {
		res := smokeOne(ctx, dir, ex, opts)
		rep.Smoke = append(rep.Smoke, res)
		for _, f := range smokeFindings(res) {
			add(f)
		}
	}
}

// smokeTargets returns the executors to smoke and the ids deliberately left
// out.
//
// Naming an executor explicitly overrides the cordon filter. That is the point
// of the flag: "this device is cordoned because it was misbehaving, is it fixed
// yet" is precisely the question an operator has, and refusing to answer it
// would send them to uncordon a node they are not yet ready to schedule on.
func smokeTargets(dir, only string) (targets []executor.Executor, skipped []string) {
	registered := executor.DefaultRegistry.List()
	sort.Slice(registered, func(i, j int) bool { return registered[i].ID() < registered[j].ID() })

	if only != "" {
		for _, ex := range registered {
			if ex.ID() == only {
				return []executor.Executor{ex}, nil
			}
		}
		return nil, nil
	}

	held := adminHeldExecutors(dir)
	for _, ex := range registered {
		if reason, ok := held[ex.ID()]; ok {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", ex.ID(), reason))
			continue
		}
		targets = append(targets, ex)
	}
	return targets, skipped
}

// adminHeldExecutors returns the executors an administrator has cordoned or
// drained, by id.
//
// Best-effort: a database that will not open is checkStorage's finding to
// report, and a smoke run that could not read health should smoke everything
// rather than silently skip the fleet. Erring toward *more* dispatch is right
// here because the failure mode of the other choice is a command that reports
// nothing and looks healthy.
func adminHeldExecutors(dir string) map[string]string {
	held := make(map[string]string)
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return held
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return held
	}
	defer func() { _ = db.Close() }()

	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		return held
	}
	all, err := sched.ListHealth()
	if err != nil {
		return held
	}
	for _, h := range all {
		if h.State.AdminHeld() {
			held[h.ExecutorID] = string(h.State)
		}
	}
	return held
}

// smokeOne runs the whole circuit against one executor.
//
// The stage list is built even when an early stage fails, so the report always
// has the same shape: a reader comparing two executors should not have to
// account for one of them having fewer rows.
// The return value is named because the deferred cleanup below writes to it —
// the leak list, the cleanup stage and the final stage ordering are all
// produced after the last `return res`. With an unnamed return those writes
// would land on a local the caller never sees, and the command would report a
// clean cleanup stage it had not actually performed.
func smokeOne(ctx context.Context, dir string, ex executor.Executor, opts Options) (res SmokeResult) {
	started := time.Now()
	caps := ex.Capabilities()
	res = SmokeResult{
		ExecutorID: ex.ID(),
		Kind:       ex.Kind(),
		Isolation:  string(caps.Isolation),
	}

	// Cleanup is registered as resources come into existence and runs on every
	// exit path below, including a panic and a cancelled ctx. Its context is
	// explicitly detached: after ctrl-C the caller's ctx is already dead, and
	// that is the moment cleanup matters most.
	cl := &cleanupStack{}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), smokeCleanupBudget)
		defer cancel()
		leaked := cl.run(cleanupCtx)
		res.Leaked = leaked
		res.Stages = append(res.Stages, cleanupStage(leaked))
		res.DurationMS = time.Since(started).Milliseconds()
		sortStages(&res)
	}()

	timeout := opts.SmokeTimeout
	if timeout <= 0 {
		timeout = DefaultSmokeTimeout
	}
	runCtx, cancelRun := context.WithTimeout(ctx, timeout)
	defer cancelRun()

	nonce := smokeNonce()
	opts.probeLogf("%s: smoking with run id %s", ex.ID(), nonce)

	// --- placement ----------------------------------------------------
	//
	// Asked first, and asked through executor.Select rather than by
	// inspecting capabilities inline, because the question is not "can this
	// driver run things" but "would the scheduler pick it" — and those differ
	// for exactly the reasons that make a fleet confusing: host-execution
	// policy, an agent build floor, an isolation requirement.
	placement, placementOK := smokePlacement(dir, ex)
	res.Stages = append(res.Stages, placement)
	if !placementOK {
		res.FirstFailure = StagePlacement
		return res
	}

	// --- workspace ----------------------------------------------------
	workDir, wsStage, wsOK := smokeWorkspace(dir, ex, caps, nonce, cl)
	res.Stages = append(res.Stages, wsStage)
	if !wsOK {
		res.FirstFailure = StageWorkspace
		return res
	}

	// --- lease --------------------------------------------------------
	lease, leaseStage := smokeLease(runCtx, dir, ex, caps, nonce, cl)
	res.Stages = append(res.Stages, leaseStage)
	if leaseStage.Outcome == StageFail {
		res.FirstFailure = StageLease
		return res
	}

	// --- dispatch, logs, write-back -----------------------------------
	spec := smokeSpec(ex, caps, workDir, nonce, lease)
	runRes, runErr := executor.Run(runCtx, ex, spec)
	if h := runRes.Handle.ID; h != "" {
		// Registered even though Run already waits for a terminal state:
		// Run returns early on ctx cancellation, and a handle whose kill
		// signal was the thing that got cancelled is the leak this guards.
		cl.push("workload "+h, func(c context.Context) error {
			return reapHandle(c, ex, h)
		})
	}

	dispatchStage := smokeDispatch(ex, runRes, runErr, timeout)
	res.Stages = append(res.Stages, dispatchStage)

	// The stages below read what the workload *reported about itself*, so they
	// are only meaningful if it ran. Grading them against an empty evidence
	// map would turn one failure into five, and — worse — would blame the
	// workspace and the credential for a workload that never started. That is
	// precisely the misattribution this command exists to remove, so an
	// undispatched run reports them as unobserved rather than broken.
	//
	// "Ran" is judged by whether any output came back, not by the dispatch
	// verdict. A workload that started and exited non-zero has failed the
	// dispatch stage and still told us everything it saw — and on a hub where
	// the harness image is the problem, that self-report is the only evidence
	// there is.
	if dispatchStage.Outcome != StagePass && len(runRes.Output) == 0 {
		res.Stages = append(res.Stages, unobservedStage(StageLogs,
			"the workload did not run, so there was no output to stream"))
		res.Stages = append(res.Stages, smokeWriteBackStage(caps, runRes))
		res.Stages = append(res.Stages, smokeRevocation(context.WithoutCancel(ctx), lease))
		res.FirstFailure = firstFailedStage(res.Stages)
		return res
	}

	evidence := parseSmokeEvidence(string(runRes.Output))
	res.Stages = append(res.Stages, smokeLogsStage(runRes, evidence, nonce))
	res.Stages = append(res.Stages, smokeWorkspaceEvidence(caps, evidence))
	res.Stages = append(res.Stages, smokeLeaseEvidence(lease, evidence))
	res.Stages = append(res.Stages, smokeWriteBackStage(caps, runRes))

	// --- revocation ---------------------------------------------------
	//
	// Runs after the workload has exited and before cleanup reports, because
	// proving the material is gone is the point of minting it. It is a stage
	// rather than part of cleanup so that a failure to destroy a credential
	// is reported as a failed assertion, not as a leak of an unrelated
	// resource.
	res.Stages = append(res.Stages, smokeRevocation(context.WithoutCancel(ctx), lease))

	res.FirstFailure = firstFailedStage(res.Stages)
	return res
}

// unobservedStage records a stage that could not be judged because an earlier
// one failed. Skip rather than fail, for the reason stated throughout this
// package: "we did not look" is a different answer from "we looked and it was
// broken", and only the second one is worth an operator's attention.
func unobservedStage(stage SmokeStage, why string) StageResult {
	return StageResult{
		Stage: stage, Outcome: StageSkip, Message: why,
		Remediation: "Fix the failure reported above and re-run; this stage was never reached",
	}
}

// smokePlacement asks the scheduler whether it would choose this executor.
func smokePlacement(dir string, ex executor.Executor) (StageResult, bool) {
	started := time.Now()
	health := executor.Health{State: executor.NodeReady}
	if h, ok := loadExecutorHealth(dir, ex.ID()); ok {
		health = h
	}

	// The requirements a hermetic workload genuinely has, and no more. Asking
	// for isolation here would be wrong: whether host execution is permitted
	// is the operator's policy, already reported by checkExecutionPolicy, and
	// a smoke run must diagnose the hub they have rather than the one this
	// package would prefer.
	chosen, err := executor.Select(
		[]executor.Candidate{{Executor: ex, Health: health}},
		executor.Requirements{ExecutorID: ex.ID()},
	)
	stage := StageResult{
		Stage: StagePlacement, DurationMS: time.Since(started).Milliseconds(),
		Details: map[string]any{"health": string(health.State)},
	}
	if err != nil {
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("the scheduler would not place a task here: %v", err)
		stage.Remediation = placementRemediation(err, ex)
		return stage, false
	}
	stage.Outcome = StagePass
	stage.Message = fmt.Sprintf("the scheduler would place a task on %s", chosen.ID())
	return stage, true
}

// placementRemediation turns a refusal into the action that lifts it.
//
// Placement errors are the ones most likely to be read as a bug in cloop
// rather than a statement about configuration — "it says my executor cannot
// run anything, but it is right there" — so each one names the setting.
func placementRemediation(err error, ex executor.Executor) string {
	var perr *executor.PlacementError
	if errors.As(err, &perr) {
		switch perr.Constraint {
		case executor.ConstraintHostPolicy:
			return "This executor runs on the control-plane host and executors.allow_host_process " +
				"is false. That is the correct setting for a hosted hub: enable a container, " +
				"Kubernetes or remote executor to have somewhere to dispatch to"
		case executor.ConstraintHealth:
			return "The executor is cordoned, draining or unreachable. `cloop hub executor uncordon " +
				ex.ID() + "` returns it to rotation; `cloop executor test " + ex.ID() + "` diagnoses " +
				"an unreachable one"
		case executor.ConstraintAgentBuild:
			return "The agent on this device is older than executors.min_agent_build. Upgrade it " +
				"with `cloop executor upgrade " + ex.ID() + "`, or lower the floor"
		}
	}
	return "Run `cloop executor test " + ex.ID() + "` for the driver's own diagnosis"
}

// loadExecutorHealth reads one executor's persisted health. Best-effort for the
// same reason adminHeldExecutors is.
func loadExecutorHealth(dir, id string) (executor.Health, bool) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return executor.Health{}, false
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return executor.Health{}, false
	}
	defer func() { _ = db.Close() }()
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		return executor.Health{}, false
	}
	h, err := sched.LoadHealth(id)
	if err != nil {
		return executor.Health{}, false
	}
	if strings.TrimSpace(string(h.State)) == "" {
		// An executor with no persisted record has never been probed, which is
		// not the same as unhealthy. Placement normalises the zero value to
		// ready; saying so explicitly keeps the reported detail honest instead
		// of printing an empty health field.
		h.State = executor.NodeReady
	}
	return h, true
}

// smokeWorkspace stages a throwaway working directory and registers its
// removal.
//
// The directory is created under the control plane's own tree rather than
// os.TempDir() so that a container driver bind-mounting it does not have to
// reach outside a path the operator already trusts cloop with, and so a leak —
// if one ever happened — lands somewhere an operator looks.
func smokeWorkspace(dir string, ex executor.Executor, caps executor.Capabilities, nonce string, cl *cleanupStack) (string, StageResult, bool) {
	started := time.Now()
	stage := StageResult{Stage: StageWorkspace, DurationMS: time.Since(started).Milliseconds()}

	base := filepath.Join(dir, ".cloop", "smoke")
	if err := os.MkdirAll(base, 0o700); err != nil {
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("could not create the smoke workspace root: %v", err)
		stage.Remediation = "Check that " + base + " is writable by the user running the hub"
		return "", stage, false
	}
	workDir, err := os.MkdirTemp(base, "run-"+nonce+"-")
	if err != nil {
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("could not create the smoke workspace: %v", err)
		stage.Remediation = "Check that " + base + " is writable by the user running the hub"
		return "", stage, false
	}
	cl.push("workspace "+workDir, func(context.Context) error { return os.RemoveAll(workDir) })

	// The marker proves the hub→sandbox direction for a driver that shares the
	// filesystem. For one that does not, the workload's own write test is the
	// assertion instead; see smokeWorkspaceEvidence.
	marker := filepath.Join(workDir, "cloop-smoke-marker")
	if err := os.WriteFile(marker, []byte(nonce), 0o600); err != nil {
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("could not write the workspace marker: %v", err)
		stage.Remediation = "Check that " + workDir + " is writable by the user running the hub"
		return "", stage, false
	}

	stage.Outcome = StagePass
	stage.Message = "staged a throwaway workspace"
	stage.Details = map[string]any{
		"dir": workDir, "shares_host_filesystem": caps.SharesHostFilesystem,
	}
	stage.DurationMS = time.Since(started).Milliseconds()
	return workDir, stage, true
}

// smokeLeaseState carries what the lease stage produced into the stages that
// assert on it.
type smokeLeaseState struct {
	broker   *secretbroker.Broker
	lease    *secretbroker.Lease
	delivery *secretbroker.Delivery
	mount    *secretbroker.Mount
	// attempted records that a lease was supposed to happen, so a later stage
	// can tell "no lease was asked for" from "a lease was asked for and is
	// missing".
	attempted bool
	dir       string
}

// smokeLease mints a throwaway credential, grants it to this executor, takes a
// lease and renders it for the driver.
//
// Every object it creates is registered for removal as soon as it exists, in
// reverse order of creation, so a failure halfway through leaves the broker as
// it found it. That ordering is load-bearing: releasing the lease before
// revoking the grant, and revoking the grant before deleting the secret, is
// the only sequence in which each step's precondition still holds.
func smokeLease(ctx context.Context, dir string, ex executor.Executor, caps executor.Capabilities, nonce string, cl *cleanupStack) (*smokeLeaseState, StageResult) {
	started := time.Now()
	st := &smokeLeaseState{}
	stage := StageResult{Stage: StageLease}
	finish := func(outcome StageOutcome, msg, remedy string) (*smokeLeaseState, StageResult) {
		stage.Outcome, stage.Message, stage.Remediation = outcome, msg, remedy
		stage.DurationMS = time.Since(started).Milliseconds()
		return st, stage
	}

	// Asked before anything is minted, because the hub itself refuses to place
	// a credential-carrying workload on a driver that cannot give the
	// credential back (executor.RequireRevocable). Minting first and letting
	// the dispatch be refused would produce a report blaming the dispatch
	// stage for a property of the executor's driver — the exact
	// misattribution this command exists to prevent — and would briefly mint
	// a credential for a workload that was never going to receive it.
	if !executor.SupportsRevocation(ex) {
		return finish(StageSkip,
			"this driver cannot take a credential back mid-run, so the hub would refuse to "+
				"place any credential-carrying task here and none was minted",
			"Nothing to fix if this executor's projects need no secrets. If they do, bind them "+
				"to a driver that implements revocation — `cloop executor list` shows which do")
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return finish(StageSkip,
			"the state database could not be opened, so no credential was brokered",
			"checkStorage above reports the database problem; fix that and re-run")
	}
	cl.push("state db handle", func(context.Context) error { return db.Close() })

	store, err := secretstore.New(db)
	if err != nil {
		return finish(StageSkip, fmt.Sprintf("the secret store is unavailable: %v", err),
			"Run `cloop hub doctor` without --smoke; the secrets section reports the cause")
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		// Overwhelmingly a missing or malformed CLOOP_SECRET_KEY, which
		// checkSecretKey already reports in detail. Skip rather than fail:
		// a hub with no sealing key can still dispatch work that needs no
		// credential, and duplicating that failure here would make one
		// problem look like two.
		return finish(StageSkip, fmt.Sprintf("no secret broker is available: %v", err),
			"Set CLOOP_SECRET_KEY (see the SECRETS section above); without it no credential "+
				"can be brokered to any executor")
	}
	st.broker = broker
	st.attempted = true

	name := "cloop-smoke-" + nonce
	secret, err := broker.Mint(ctx, secretbroker.MintRequest{
		Name:    name,
		Kind:    secretbroker.KindKubeconfig,
		Payload: smokeKubeconfig(nonce),
		Actor:   "hub-doctor-smoke",
		Metadata: map[string]string{
			"purpose": "cloop hub doctor --smoke; throwaway, points at 127.0.0.1:1",
		},
	})
	if err != nil {
		return finish(StageFail, fmt.Sprintf("could not mint a throwaway credential: %v", err),
			"The broker refused a mint. `cloop hub doctor` without --smoke reports the state of "+
				"the secret store and the sealing key")
	}
	cl.push("secret "+secret.ID, func(c context.Context) error {
		return broker.DeleteSecret(c, secret.ID, "hub-doctor-smoke")
	})

	grant, err := broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: secret.ID,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: ex.ID()},
		// The constraints are what make the kubeconfig renderable at all —
		// minimization drops every context the grant does not name — and
		// they double as proof that constraint evaluation runs on this path.
		Constraints: secretbroker.Constraints{
			Contexts:   []string{smokeContext},
			Namespaces: []string{smokeContext},
		},
		TTL:   smokeLeaseTTL,
		Actor: "hub-doctor-smoke",
	})
	if err != nil {
		return finish(StageFail, fmt.Sprintf("could not grant the throwaway credential: %v", err),
			"The broker refused a grant to executor "+ex.ID()+"; check the Secrets panel for a "+
				"policy that blocks it")
	}
	cl.push("grant "+grant.ID, func(c context.Context) error {
		return broker.Revoke(c, grant.ID, "hub-doctor-smoke")
	})

	lease, err := broker.Lease(ctx, ex.ID(), "")
	if err != nil {
		return finish(StageFail, fmt.Sprintf("could not take a lease: %v", err),
			"The broker minted and granted a credential but would not lease it; this is the "+
				"code path every real task takes, so no task can obtain credentials either")
	}
	if lease.Empty() {
		return finish(StageFail,
			"the lease came back with no material, so nothing would reach the sandbox",
			"A grant exists for this executor but produced no material — check its constraints "+
				"with `cloop secret grants`")
	}
	st.lease = lease
	cl.push("lease "+lease.ID, func(context.Context) error { broker.Release(lease.ID); return nil })

	// Which rendering is correct is a property of the driver, exactly as it is
	// for a real dispatch: a driver whose workload can read the hub's
	// filesystem gets files written there, and one whose cannot gets the bytes
	// to place itself.
	if caps.SecretFilesFromHostPath {
		leaseDir, derr := secretbroker.NewLeaseDirPath("")
		if derr != nil {
			return finish(StageFail, fmt.Sprintf("could not choose a lease directory: %v", derr),
				"The hub could not create a staging directory for credential files; check that "+
					"/dev/shm or $TMPDIR is writable")
		}
		mount, merr := lease.MaterializeAt(leaseDir)
		if merr != nil {
			return finish(StageFail, fmt.Sprintf("could not materialise the credential: %v", merr),
				"The hub could not write the credential file it would hand a real task")
		}
		st.mount = mount
		st.dir = mount.Dir
		cl.push("lease dir "+mount.Dir, func(context.Context) error { return mount.Close() })
	} else {
		if !caps.SupportsSecretFiles {
			// Honest skip rather than a contrived pass: this backend has told
			// us it cannot carry credential files, and that refusal is exactly
			// what placement would enforce for a real task too.
			return finish(StageSkip,
				"this backend does not advertise secret-file delivery, so no credential was sent",
				"Nothing to fix if this executor's projects need no credentials; if they do, "+
					"bind them to a backend that advertises SupportsSecretFiles")
		}
		delivery, derr := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
		if derr != nil {
			return finish(StageFail, fmt.Sprintf("could not render the credential for delivery: %v", derr),
				"The hub could not prepare the credential bytes this driver has to place itself")
		}
		st.delivery = delivery
		st.dir = delivery.Dir
		cl.push("lease delivery "+lease.ID, func(context.Context) error { return delivery.Close() })
	}

	return finish(StagePass,
		fmt.Sprintf("minted, granted and leased a throwaway credential (TTL %s)", smokeLeaseTTL),
		"")
}

// smokeContext is the single context name the throwaway kubeconfig carries.
const smokeContext = "cloop-smoke"

// smokeKubeconfig renders the throwaway credential.
//
// A kubeconfig because it is the credential kind the broker delivers as a
// *file*, which is the delivery mechanism worth proving: environment variables
// reach a sandbox through a dozen paths, a file has to be written by whichever
// side the driver's capabilities say owns it.
//
// The server is 127.0.0.1:1 — a port nothing listens on, inside the sandbox's
// own loopback. There is no host this can reach even if something tried, which
// is what makes minting it safe on a production hub.
func smokeKubeconfig(nonce string) []byte {
	return []byte(`apiVersion: v1
kind: Config
current-context: ` + smokeContext + `
clusters:
- name: ` + smokeContext + `
  cluster:
    server: https://127.0.0.1:1
contexts:
- name: ` + smokeContext + `
  context:
    cluster: ` + smokeContext + `
    user: ` + smokeContext + `
users:
- name: ` + smokeContext + `
  user:
    token: cloop-smoke-` + nonce + `
`)
}

// smokeSpec builds the workload's Spec the way a real dispatch builds one.
func smokeSpec(ex executor.Executor, caps executor.Capabilities, workDir, nonce string, lease *smokeLeaseState) executor.Spec {
	env := []string{
		"CLOOP_SMOKE_NONCE=" + nonce,
		// A minimal PATH, because Env is explicit for an isolating driver and
		// `id`/`grep` have to resolve.
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + workDir,
	}
	spec := executor.Spec{
		WorkDir: workDir,
		Argv:    []string{"/bin/sh", "-c", smokeWorkload},
		Labels: map[string]string{
			"component": "hub-doctor-smoke",
			"task_id":   "smoke-" + nonce,
		},
		// Hermetic in the strongest sense the driver can honour: a workload
		// that cannot reach the network cannot be the reason a smoke test
		// passed or failed for a network reason.
		DisableNetwork: true,
	}
	if lease != nil && lease.lease != nil {
		var bindings []executor.SecretBinding
		switch {
		case lease.mount != nil:
			bindings = secretbroker.ExecutorBindings(lease.lease.ID, lease.lease.ExpiresAt, lease.mount.Bindings())
			env = append(env, lease.mount.Env()...)
		case lease.delivery != nil:
			bindings = secretbroker.ExecutorBindings(lease.lease.ID, lease.lease.ExpiresAt, lease.delivery.Bindings())
			env = append(env, lease.delivery.Env()...)
			spec.SecretFiles = secretbroker.ExecutorSecretFiles(lease.lease.ID, lease.delivery.Files())
		}
		spec.Secrets = bindings
	}
	spec.Env = env

	// Ask for write-back only where the driver says it can do it. Setting the
	// field on a driver that cannot would be refused at placement, which would
	// report a write-back problem as a placement one.
	if caps.SupportsWriteBack {
		spec.WriteBack = executor.WriteBack{
			Mode:    executor.WriteBackBundle,
			Branch:  "cloop/smoke-" + nonce,
			Message: "cloop hub doctor --smoke",
		}
	}
	return spec
}

// smokeDispatch judges whether the workload started and exited cleanly.
func smokeDispatch(ex executor.Executor, res executor.RunResult, runErr error, budget time.Duration) StageResult {
	stage := StageResult{Stage: StageDispatch, Details: map[string]any{}}
	if res.Handle.ID != "" {
		stage.Details["handle"] = res.Handle.ID
	}
	if res.Handle.Image != "" {
		stage.Details["image"] = res.Handle.Image
	}
	stage.Details["exit_code"] = res.Status.ExitCode

	switch {
	case runErr == nil:
		stage.Outcome = StagePass
		stage.Message = "the workload ran in the sandbox and exited 0"
		return stage
	case errors.Is(runErr, context.DeadlineExceeded):
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("the workload did not finish within %s", budget)
		stage.Remediation = "Raise --smoke-timeout, or check whether the image is being pulled on " +
			"demand; `cloop executor test " + ex.ID() + "` times a cold start"
		return stage
	case errors.Is(runErr, context.Canceled):
		stage.Outcome = StageFail
		stage.Message = "the smoke run was interrupted before the workload finished"
		stage.Remediation = "Re-run without interrupting it; everything this run created has been " +
			"cleaned up"
		return stage
	}

	stage.Outcome = StageFail
	stage.Message = fmt.Sprintf("the workload did not run: %v", runErr)
	stage.Remediation = dispatchRemediation(runErr, ex, res)
	// Output that carries none of the workload's own markers means the image's
	// ENTRYPOINT consumed the argv and ran something else entirely. Detected
	// by the absence of the markers rather than by matching an error string,
	// so it holds for any entrypoint rather than the one that happened to be
	// in front of me — and it is worth its own sentence because the container
	// driver deliberately refuses to override an entrypoint, so the fix is
	// necessarily the image.
	if out := strings.TrimSpace(string(res.Output)); out != "" && !strings.Contains(out, "smoke_") {
		stage.Message = "the sandbox started but ran something other than the workload it was given"
		stage.Remediation = "This image declares an ENTRYPOINT, which the container driver will " +
			"not override (doing so would change what argv means), so the arguments were appended " +
			"to it instead of executed. A harness image must leave ENTRYPOINT empty and let cloop " +
			"supply argv — the output below is what ran instead"
	}
	// Carry the workload's own output. Without it the operator is told the
	// sandbox exited non-zero and given no way to see why — and for a
	// non-zero exit the reason is almost always in the last few lines, which
	// is the one place a hub's own logs do not have it either.
	if out := strings.TrimSpace(string(res.Output)); out != "" {
		stage.Details["output"] = lastLines(out, smokeOutputLines)
	}
	return stage
}

// smokeOutputLines bounds how much of a failing workload's output is carried
// into the report. Enough for a shell's error and the line before it; not so
// much that a --json report becomes a log file.
const smokeOutputLines = 12

// lastLines returns the final n lines of s. The tail, because that is where a
// shell puts the error that killed it.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// dispatchRemediation names the fix for the ways a dispatch fails.
//
// The shell case is first because it is the one this command exists to catch:
// an operator builds a harness image from a distroless base, every check in
// this package passes, and the first real task dies with an exec error that
// names a path rather than a cause.
func dispatchRemediation(err error, ex executor.Executor, res executor.RunResult) string {
	// An enrolled device's failures are asked about first, and by sentinel
	// rather than by string. A revoked credential, an expired token and a
	// replayed one are the ways a remote executor actually stops working, and
	// until this they reached the operator as a bare Go error — the precise
	// gap this command was written to close.
	if remedy := remote.EnrollmentRemediation(err); remedy != "" {
		return remedy
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "as uid 0") || strings.Contains(msg, "refusing to run the workload as root"):
		// The most likely refusal on a hub someone is trying out, because the
		// natural way to try one out is as root. The driver's own message is
		// already good; what it cannot say is that this is a *deployment*
		// decision rather than a bug in the smoke test.
		return "The hub is running as root, and the container driver refuses to run a workload " +
			"as uid 0 because that would defeat --cap-drop=ALL. Run the control plane as an " +
			"unprivileged user that owns the project directories — a hosted hub should not be " +
			"root in any case — or run it rootless so podman's keep-id mapping applies"
	case strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "exec format error"):
		return "The sandbox image has no POSIX shell at /bin/sh. cloop's own harness images are " +
			"Alpine-based and do; a distroless or scratch image cannot run a shell-based harness " +
			"at all. Set executors.*.image to an image with a shell"
	case strings.Contains(msg, "permission denied"):
		return "The executor refused to start the workload. For a container runtime, check that " +
			"the hub's user may talk to the socket (`podman info`); for Kubernetes, check the " +
			"service account's RBAC on pods/create"
	case strings.Contains(msg, "unsupported") || errors.Is(err, executor.ErrUnsupported):
		return "This driver refused part of the spec. Run `cloop executor test " + ex.ID() +
			"` for its own diagnosis"
	case res.Status.ExitCode != 0:
		return "The workload started and exited " + fmt.Sprint(res.Status.ExitCode) +
			". The output above is its combined stdout and stderr"
	}
	return "Run `cloop executor test " + ex.ID() + "` for the driver's own diagnosis, and check " +
		"the hub log for the dispatch it refused"
}

// smokeLogsStage asserts the workload's output actually came back.
//
// It is a separate stage from dispatch because the two fail independently and
// an operator needs to tell them apart: a driver whose Stream is broken
// produces a task that runs invisibly, which looks like a hung task rather
// than a logging fault.
func smokeLogsStage(res executor.RunResult, evidence map[string]string, nonce string) StageResult {
	stage := StageResult{Stage: StageLogs, Details: map[string]any{
		"bytes": len(res.Output),
	}}
	switch {
	case len(res.Output) == 0:
		stage.Outcome = StageFail
		stage.Message = "no output came back over the log stream"
		stage.Remediation = "The workload ran but nothing was streamed. A task on this executor " +
			"would appear to hang with an empty step log; check the driver's log plumbing"
		return stage
	case evidence["smoke_nonce"] != nonce:
		// Output arrived, but not this run's. Worth distinguishing: it means
		// the stream is crossed with another workload's, which on a
		// multi-tenant hub is a confidentiality problem and not merely a bug.
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("the output did not carry this run's id (got %q, want %q)",
			evidence["smoke_nonce"], nonce)
		stage.Remediation = "The log stream returned output that is not this workload's. Check " +
			"whether handles are being confused between concurrent runs before dispatching real work"
		return stage
	case evidence["smoke_done"] != "ok":
		stage.Outcome = StageFail
		stage.Message = "the workload's output was truncated before it finished"
		stage.Remediation = "Output started and stopped mid-run; a task's step log would be " +
			"silently incomplete. Check the driver's stream for a premature close"
		return stage
	case res.Dropped:
		stage.Outcome = StageFail
		stage.Message = "log chunks were dropped between the sandbox and the hub"
		stage.Remediation = "The stream reported a sequence gap, so a real task's log would be " +
			"missing lines. Check for backpressure in the driver's log path"
		return stage
	}
	stage.Outcome = StagePass
	stage.Message = fmt.Sprintf("streamed %d bytes, complete and correctly attributed", len(res.Output))
	if uid := evidence["smoke_uid"]; uid != "" {
		stage.Details["sandbox_uid"] = uid
	}
	return stage
}

// smokeWorkspaceEvidence upgrades the workspace verdict with what the workload
// saw from inside.
//
// Two different assertions, because the two topologies genuinely differ. A
// driver that shares the hub's filesystem must show the workload the marker the
// hub wrote — that is the whole mechanism. One that does not cannot see it, and
// forcing a marker there would need a repository, which a hermetic run has no
// way to supply; so what is asserted instead is that the workspace it *did*
// provision is real and writable.
func smokeWorkspaceEvidence(caps executor.Capabilities, evidence map[string]string) StageResult {
	stage := StageResult{Stage: StageWorkspace, Details: map[string]any{
		"shares_host_filesystem": caps.SharesHostFilesystem,
	}}
	if evidence["smoke_writable"] != "yes" {
		stage.Outcome = StageFail
		stage.Message = "the workload's working directory was not writable"
		stage.Remediation = "A harness cannot check out code or write output here. Check the " +
			"sandbox uid against the workspace's owner — a container running as a uid that does " +
			"not own the bind-mounted directory produces exactly this"
		return stage
	}
	if caps.SharesHostFilesystem {
		if evidence["smoke_marker"] == "absent" || evidence["smoke_marker"] == "" {
			stage.Outcome = StageFail
			stage.Message = "the workload could not see a file the hub wrote into its workspace"
			stage.Remediation = "This driver shares the control plane's filesystem, so the project " +
				"directory should be visible in the sandbox. Check the bind mount and any SELinux " +
				"labelling on the workspace path"
			return stage
		}
		stage.Outcome = StagePass
		stage.Message = "the workload read a file the hub wrote and could write its own"
		return stage
	}
	stage.Outcome = StagePass
	stage.Message = "the driver provisioned a writable workspace on the executor"
	return stage
}

// smokeLeaseEvidence upgrades the lease verdict with whether the credential
// file actually arrived where the workload could open it.
//
// This is the assertion the whole lease stage exists for. A driver reporting
// SupportsSecretFiles and then not placing them is the failure mode that costs
// the most time to diagnose from a task log, because the harness's error is
// about a missing file and says nothing about grants.
func smokeLeaseEvidence(lease *smokeLeaseState, evidence map[string]string) StageResult {
	stage := StageResult{Stage: StageLease}
	if lease == nil || !lease.attempted || lease.lease == nil {
		stage.Outcome = StageSkip
		stage.Message = "no credential was brokered, so none was expected in the sandbox"
		stage.Remediation = "See the lease stage above for why"
		return stage
	}
	switch evidence["smoke_lease"] {
	case "delivered":
		stage.Outcome = StagePass
		stage.Message = "the sandbox opened the leased credential file and it held this run's material"
		stage.Details = map[string]any{"lease_id": lease.lease.ID, "dir": lease.dir}
	case "wrong-content":
		stage.Outcome = StageFail
		stage.Message = "a credential file arrived but did not hold this lease's material"
		stage.Remediation = "The sandbox found a file at the leased path whose contents belong to " +
			"something else. Check for a stale lease directory left by an earlier run before " +
			"granting real credentials here"
	case "env-without-file":
		stage.Outcome = StageFail
		stage.Message = "the environment pointed at a credential file that does not exist"
		stage.Remediation = "The driver forwarded the lease's environment but never placed the " +
			"file. A real task would fail with a missing-kubeconfig error that says nothing about " +
			"grants; this is a driver defect, not a grant problem"
	default:
		stage.Outcome = StageFail
		stage.Message = "the leased credential never reached the sandbox"
		stage.Remediation = "The hub brokered a credential this executor advertised it could " +
			"carry, and the workload saw neither the file nor the environment. Until this is " +
			"fixed, any project bound here that needs a credential will fail"
	}
	return stage
}

// smokeWriteBackStage judges the return path, where the backend has one.
func smokeWriteBackStage(caps executor.Capabilities, res executor.RunResult) StageResult {
	stage := StageResult{Stage: StageWriteBack}
	if !caps.SupportsWriteBack {
		// Not a gap. A driver whose /workspace *is* the hub's directory has
		// nothing to ship anywhere, and saying "skipped" rather than "passed"
		// keeps the report honest about what was proved.
		stage.Outcome = StageSkip
		stage.Message = "this backend shares its workspace with the hub, so there is nothing to write back"
		stage.Remediation = "Nothing to fix: the workload's file changes are already on the hub's filesystem"
		return stage
	}
	wb := res.WriteBack
	switch {
	case wb == nil:
		stage.Outcome = StageFail
		stage.Message = "the driver advertises write-back but reported no result"
		stage.Remediation = "A task's commits would be produced in the sandbox and silently lost. " +
			"Check the driver's write-back implementation before running real work here"
	case wb.Err != "":
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("write-back failed: %s", wb.Err)
		stage.Remediation = "The sandbox ran but its file changes could not be returned. If the " +
			"message names git, the harness image needs git installed"
	case wb.Skipped:
		// The hermetic workload deletes its own scratch file, so a clean tree
		// is the expected outcome rather than a fault: the driver ran the
		// write-back path and correctly found nothing to send.
		stage.Outcome = StagePass
		stage.Message = "the write-back path ran and correctly found no changes to return"
		stage.Details = map[string]any{"skip_reason": wb.SkipReason}
	default:
		stage.Outcome = StagePass
		stage.Message = fmt.Sprintf("the driver returned the workload's changes (%s)", wb.Describe())
		stage.Details = map[string]any{"branch": wb.Branch, "commit": wb.CommitSHA}
	}
	return stage
}

// smokeRevocation proves the credential is gone rather than assuming it.
//
// The lease is released here — not left to the cleanup stack — precisely so
// that the proof is a reported assertion. Cleanup would destroy the same
// material, but a cleanup that quietly worked proves nothing to the operator
// reading the report, and requirement five of this command is that revocation
// is demonstrated.
func smokeRevocation(ctx context.Context, lease *smokeLeaseState) StageResult {
	stage := StageResult{Stage: StageRevocation}
	if lease == nil || !lease.attempted || lease.lease == nil {
		stage.Outcome = StageSkip
		stage.Message = "no credential was minted, so there was nothing to revoke"
		stage.Remediation = "See the lease stage for why no credential was brokered"
		return stage
	}

	// Close the rendering first: this is what wipes the bytes, whether they
	// were written to a tmpfs directory or held in memory for the driver.
	var closeErr error
	paths := leasedFilePaths(lease)
	if lease.mount != nil {
		closeErr = lease.mount.Close()
	}
	if lease.delivery != nil {
		if err := lease.delivery.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	lease.broker.Release(lease.lease.ID)

	if closeErr != nil {
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("the credential could not be destroyed: %v", closeErr)
		stage.Remediation = "Credential material may remain on disk. Check " + lease.dir +
			" and remove it by hand; investigate before granting real credentials on this hub"
		return stage
	}

	// Verify rather than trust. The whole point of this stage is that
	// "Close returned nil" and "the bytes are gone" are different claims.
	var survivors []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			survivors = append(survivors, p)
		}
	}
	if len(survivors) > 0 {
		stage.Outcome = StageFail
		stage.Message = fmt.Sprintf("credential material survived revocation: %s", strings.Join(survivors, ", "))
		stage.Remediation = "Remove these files by hand. A lease that outlives its revocation " +
			"means a real credential would too — do not grant secrets on this hub until it is fixed"
		return stage
	}

	// And the broker must no longer honour the lease id.
	if _, err := lease.broker.Renew(ctx, lease.lease.ID); err == nil {
		stage.Outcome = StageFail
		stage.Message = "the broker still renews a released lease"
		stage.Remediation = "Revocation is not taking effect in the broker, so a withdrawn " +
			"credential would stay usable. Do not rely on grant revocation on this hub"
		return stage
	}

	stage.Outcome = StagePass
	stage.Message = "the credential was destroyed and the lease no longer renews"
	stage.Details = map[string]any{"files_wiped": len(paths)}
	return stage
}

// leasedFilePaths lists the credential files a lease put on disk, so
// revocation can be checked rather than asserted.
//
// Only a hub-materialised lease has files on *this* filesystem. A delivered
// lease's bytes went to the driver, and whether that driver wiped them is the
// driver's own contract — see the container suite's revocation tests.
func leasedFilePaths(lease *smokeLeaseState) []string {
	if lease == nil || lease.mount == nil {
		return nil
	}
	var paths []string
	for _, b := range lease.mount.Bindings() {
		paths = append(paths, b.Files...)
	}
	return paths
}

// reapHandle makes sure a workload is not left running.
//
// Kill rather than terminate: this is a cleanup path for a diagnostic whose
// workload is a shell script with nothing to flush, and a graceful signal that
// the workload ignores would turn cleanup into another thing that can hang.
func reapHandle(ctx context.Context, ex executor.Executor, handleID string) error {
	st, err := ex.Status(ctx, handleID)
	if err == nil && st.State.Terminal() {
		return nil
	}
	if err := ex.Signal(ctx, handleID, executor.SignalKill); err != nil {
		if errors.Is(err, executor.ErrHandleNotFound) || errors.Is(err, executor.ErrUnsupported) {
			return nil
		}
		return err
	}
	return nil
}

// cleanupStack runs removals in reverse order of registration.
type cleanupStack struct {
	entries []cleanupEntry
}

type cleanupEntry struct {
	what string
	fn   func(context.Context) error
}

func (c *cleanupStack) push(what string, fn func(context.Context) error) {
	c.entries = append(c.entries, cleanupEntry{what: what, fn: fn})
}

// run executes every registered cleanup, newest first, and returns what could
// not be removed.
//
// It never stops at the first error. A stack that aborted halfway would turn
// one stubborn resource into several leaked ones, which is the opposite of
// what a cleanup path is for. Each entry is also isolated from a panic, so a
// driver that panics on a double-close cannot take the rest of the stack with
// it.
func (c *cleanupStack) run(ctx context.Context) []string {
	var leaked []string
	for i := len(c.entries) - 1; i >= 0; i-- {
		e := c.entries[i]
		if err := runOneCleanup(ctx, e); err != nil {
			leaked = append(leaked, fmt.Sprintf("%s: %v", e.what, err))
		}
	}
	return leaked
}

func runOneCleanup(ctx context.Context, e cleanupEntry) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panicked during cleanup: %v", r)
		}
	}()
	return e.fn(ctx)
}

// cleanupStage reports what the stack could not remove.
func cleanupStage(leaked []string) StageResult {
	if len(leaked) == 0 {
		return StageResult{
			Stage: StageCleanup, Outcome: StagePass,
			Message: "every container, credential and directory this run created was removed",
		}
	}
	return StageResult{
		Stage: StageCleanup, Outcome: StageFail,
		Message: fmt.Sprintf("%d resource(s) could not be removed: %s",
			len(leaked), strings.Join(leaked, "; ")),
		Remediation: "Remove these by hand. `cloop executor reap <id>` collects orphaned sandboxes; " +
			"credential directories are under /dev/shm or $TMPDIR named cloop-lease-*",
		Details: map[string]any{"leaked": leaked},
	}
}

// sortStages puts the stages in smokeStageOrder and collapses the duplicates
// that arise when a later assertion refines an earlier provisional verdict.
//
// The refinement is the reason this exists: workspace and lease are each
// reported once when they are set up and again once the workload has said what
// it actually saw, and the second verdict is the one that counts. Keeping the
// worse of the two would report a driver as broken for a file it had not yet
// been asked to place; keeping the later one reports what was finally observed.
func sortStages(res *SmokeResult) {
	latest := make(map[SmokeStage]StageResult, len(res.Stages))
	for _, s := range res.Stages {
		prev, seen := latest[s.Stage]
		if seen && s.Outcome == StageSkip && prev.Outcome != StageSkip {
			// A later skip must not erase an earlier real verdict.
			continue
		}
		latest[s.Stage] = s
	}
	ordered := make([]StageResult, 0, len(latest))
	for _, name := range smokeStageOrder {
		if s, ok := latest[name]; ok {
			ordered = append(ordered, s)
		}
	}
	res.Stages = ordered
	res.FirstFailure = firstFailedStage(ordered)
}

// firstFailedStage returns the earliest failing stage in smokeStageOrder.
func firstFailedStage(stages []StageResult) SmokeStage {
	byStage := make(map[SmokeStage]StageOutcome, len(stages))
	for _, s := range stages {
		byStage[s.Stage] = s.Outcome
	}
	for _, name := range smokeStageOrder {
		if byStage[name] == StageFail {
			return name
		}
	}
	return ""
}

// parseSmokeEvidence reads the workload's key=value report.
func parseSmokeEvidence(out string) map[string]string {
	ev := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "smoke_") {
			continue
		}
		ev[key] = strings.TrimSpace(value)
	}
	return ev
}

// smokeNonce returns a short random run id.
//
// Random rather than a timestamp because it is used as an attribution check:
// two runs a second apart must not be able to accept each other's output, and
// a clock is exactly the source that can repeat under a container's frozen
// time or a reset VM.
func smokeNonce() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Only reachable if the kernel CSPRNG fails, at which point the hub
		// has larger problems; a fixed value still produces a usable report.
		return "fallback0"
	}
	return hex.EncodeToString(buf)
}

// smokeFindings projects a smoke result onto the report's finding list, so
// --json, the text renderer and the exit code all work on one representation.
//
// One finding per executor rather than one per stage: a fleet of ten devices
// producing eighty rows is a report nobody reads, and the stage detail is
// carried in Details and in the Smoke array for anyone who wants it.
func smokeFindings(res SmokeResult) []Finding {
	details := map[string]any{
		"executor": res.ExecutorID, "kind": res.Kind,
		"isolation": res.Isolation, "duration_ms": res.DurationMS,
	}
	for _, s := range res.Stages {
		details[string(s.Stage)] = string(s.Outcome)
	}

	title := "Smoke " + res.ExecutorID
	if len(res.Leaked) > 0 {
		return []Finding{{
			Check: "smoke.cleanup", Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("the smoke run could not clean up after itself: %s",
				strings.Join(res.Leaked, "; ")),
			Remediation: "Remove the named resources by hand; `cloop executor reap " +
				res.ExecutorID + "` collects orphaned sandboxes",
			Details: details,
		}}
	}
	if res.FirstFailure != "" {
		failed := stageByName(res.Stages, res.FirstFailure)
		return []Finding{{
			Check: "smoke.dispatch", Title: title, Severity: SeverityFail,
			Message:     fmt.Sprintf("first failure at stage %q: %s", res.FirstFailure, failed.Message),
			Remediation: failed.Remediation,
			Details:     details,
		}}
	}
	return []Finding{{
		Check: "smoke.dispatch", Title: title, Severity: SeverityPass,
		Message: fmt.Sprintf("the dispatch circuit works end to end (%s)", summariseStages(res.Stages)),
		Details: details,
	}}
}

func stageByName(stages []StageResult, name SmokeStage) StageResult {
	for _, s := range stages {
		if s.Stage == name {
			return s
		}
	}
	return StageResult{Stage: name}
}

// summariseStages renders "6 passed, 2 skipped" for the one-line verdict.
func summariseStages(stages []StageResult) string {
	var pass, skip int
	for _, s := range stages {
		switch s.Outcome {
		case StagePass:
			pass++
		case StageSkip:
			skip++
		}
	}
	if skip == 0 {
		return fmt.Sprintf("%d stages passed", pass)
	}
	return fmt.Sprintf("%d stages passed, %d not applicable to this backend", pass, skip)
}
