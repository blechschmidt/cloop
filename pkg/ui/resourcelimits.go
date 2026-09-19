package ui

// resourcelimits.go is where a workload's resource request stops being the
// project's decision.
//
// Everything upstream of here treats resource limits as a request: uiSpec
// leaves them zero, applySandbox fills them in from .cloop/sandbox.yaml, and
// the drivers resolve what is left against the operator's configured defaults —
// with the spec winning, because for a request written by the operator that is
// the right precedence. .cloop/sandbox.yaml is not written by the operator. It
// is committed to the repository, so under that rule a project set its own
// limits and the operator's numbers were advice.
//
// applyResourceCeiling is the step that makes them binding. It runs *after*
// applySandbox, because it has to bound what that function just installed, and
// it runs unconditionally, because the most effective way to defeat a ceiling
// that only bounds stated requests is to state nothing: applySandbox returns
// early for a project with no sandbox.yaml, and a project with no sandbox.yaml
// is a project asking for no limits at all.

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// applyResourceCeiling bounds spec's resource limits by the fleet ceiling, then
// by the ceiling on the executor it is about to run on, then by this project's,
// returning the clamps so they can be explained.
//
// ex is the executor the caller already resolved. It is passed rather than
// re-derived because the two must not be allowed to disagree: a ceiling applied
// against a different executor than the one that runs the workload is worse
// than no ceiling, since an operator would believe it held. A nil ex asks only
// the fleet and the project, which is the honest answer when the caller has not
// placed the workload yet.
//
// It never fails the dispatch. A ceiling is a bound, not an admission decision:
// the outcome of exceeding one is a smaller sandbox, not a refused run, and a
// project that asked for more than it may have should still get the work done
// inside what it may have. Refusal is the right answer for a capability the
// executor cannot provide — see applySandbox — and the wrong one for a number
// that can simply be lowered.
func applyResourceCeiling(spec executor.Spec, workDir string, ex executor.Executor) (executor.Spec, []executor.Clamp) {
	// The clamping itself lives in pkg/executor, because the REST API server
	// dispatches too and must get the identical answer. This wrapper exists for
	// the lookups' control-plane directory, which is a Web UI concept.
	installProjectCeilingLookup()
	var id string
	if ex != nil {
		id = ex.ID()
	}
	clamps := executor.BoundSpec(&spec, workDir, id)
	return spec, clamps
}

// installProjectCeilingLookup wires the control-plane database into
// pkg/executor's ceiling resolvers, both the per-project one and the
// per-executor one.
//
// Idempotent and cheap, and called from the dispatch path rather than only from
// bootstrapExecutors because several tests build a Server as a struct literal
// and never run bootstrap — the same reason registerBuiltinExecutors is called
// from every workload entry point. A ceiling that applied only on the
// fully-bootstrapped path would be a ceiling that a test could not observe and
// an unusual startup order could lose.
func installProjectCeilingLookup() {
	executor.SetProjectCeilingLookup(func(projectPath string) (executor.ResourceCeiling, bool) {
		return lookupProjectResourceCeiling(controlPlaneDir(), projectPath)
	})
	executor.SetExecutorCeilingLookup(func(executorID string) (executor.ResourceCeiling, bool) {
		return lookupExecutorResourceCeiling(controlPlaneDir(), executorID)
	})
}

// logResourceClamps records what a ceiling did, on the project's own event
// log, where the developer whose run was capped will actually look.
//
// This is the whole reason Clamp carries a Source and a Requested value. A
// sandbox that quietly received 2 GB when its sandbox.yaml asked for 8 is
// indistinguishable from a machine that is simply slow, and the person debugging
// it has no reason to suspect a policy they cannot see. One line naming the
// resource, both numbers and the ceiling that bound it turns a mystery into an
// address to complain to.
func logResourceClamps(workDir string, clamps []executor.Clamp) {
	if len(clamps) == 0 {
		return
	}
	for _, line := range executor.ClampWarnings(clamps) {
		state.LogEvent(workDir, state.EventRow{
			Type:    state.EventResourceCeiling,
			Step:    state.NoStep,
			Message: line,
		})
	}
}

// logUnenforceableCeiling records that a ceiling bound this spec and the chosen
// executor will not hold the workload to it.
//
// Remote agents advertise SupportsResourceLimits false: they report a device's
// capacity so placement can rank it, and then run the workload without confining
// it to a share. A ceiling still lowers the numbers on the spec, and nothing
// applies them. Silence here would be the failure mode `min_agent_build`'s
// banner exists to prevent — an operator believing a policy is in force
// everywhere because they set it once.
func logUnenforceableCeiling(ex executor.Executor, workDir string, clamps []executor.Clamp) {
	if !executor.CeilingUnenforceable(ex, clamps) {
		return
	}
	state.LogEvent(workDir, state.EventRow{
		Type: state.EventResourceCeiling,
		Step: state.NoStep,
		Message: fmt.Sprintf(
			"executor %q (%s) does not enforce resource limits, so the ceiling was applied to "+
				"the spec but will not bound this run; bind the project to a container or "+
				"Kubernetes executor for an enforced cap",
			ex.ID(), ex.Kind()),
	})
}

// lookupProjectResourceCeiling reads the per-project ceiling from the control
// plane's state database.
//
// It mirrors lookupProjectExecutor, including its failure posture: a missing
// database, an unmigrated one, or any read error yields "no project ceiling".
//
// That is fail-open for this lookup alone, and it is bounded rather than
// unbounded — the fleet ceiling is process state and has already been applied,
// so a control-plane blip degrades a project from its own tighter cap to the
// hub-wide one rather than to no cap. Refusing the run instead would convert a
// transient storage fault into an outage for every project on the hub, which is
// a worse trade for a control whose job is to bound a number that is already
// bounded.
func lookupProjectResourceCeiling(controlPlaneDir, projectPath string) (executor.ResourceCeiling, bool) {
	if controlPlaneDir == "" || projectPath == "" {
		return executor.ResourceCeiling{}, false
	}
	dbPath := state.DBPath(controlPlaneDir)
	// Stat first: statedb.Open creates and migrates, and a dispatch is not the
	// place to bring a control-plane database into existence.
	if _, err := os.Stat(dbPath); err != nil {
		return executor.ResourceCeiling{}, false
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return executor.ResourceCeiling{}, false
	}
	defer db.Close()

	c, ok, err := db.ProjectResourceCeiling(projectPath)
	if err != nil || !ok || c.IsZero() {
		return executor.ResourceCeiling{}, false
	}
	return c, true
}

// lookupExecutorResourceCeiling reads the per-executor ceiling from the control
// plane's state database.
//
// The same shape and the same failure posture as the per-project lookup above,
// and bounded the same way: a control-plane fault degrades this executor from
// its own cap to the fleet's, never to no cap. The asymmetry worth noting is
// that the drivers call CeilingFor for themselves at build-request time, so a
// blip here that the driver's own later read does not see still ends with the
// limit applied — this lookup decides what the *spec* records, not solely what
// the container gets.
func lookupExecutorResourceCeiling(controlPlaneDir, executorID string) (executor.ResourceCeiling, bool) {
	if controlPlaneDir == "" || executorID == "" {
		return executor.ResourceCeiling{}, false
	}
	dbPath := state.DBPath(controlPlaneDir)
	if _, err := os.Stat(dbPath); err != nil {
		return executor.ResourceCeiling{}, false
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return executor.ResourceCeiling{}, false
	}
	defer db.Close()

	c, ok, err := db.ExecutorResourceCeiling(executorID)
	if err != nil || !ok || c.IsZero() {
		return executor.ResourceCeiling{}, false
	}
	return c, true
}
