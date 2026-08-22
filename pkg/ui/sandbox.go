package ui

// sandbox.go applies a project's .cloop/sandbox.yaml to the workloads the
// control plane starts for it.
//
// The order here is the security-relevant part and it does not vary:
//
//  1. resolve the spec (parse, schema-check, clamp),
//  2. ask the *bound* executor whether it can honour what the spec requires,
//     via the same matcher the scheduler uses,
//  3. apply it — including verifying any egress grant it names against the
//     grants the project actually holds,
//  4. narrow the environment to the spec's allowlist.
//
// Step 2 before step 3 matters. Applying first and checking after would mean a
// spec that names a toolchain the executor cannot provide gets *partially*
// honoured — the resource limits land, the image silently does not — and the
// task then fails inside an environment nobody described. Refusing up front,
// with the constraint named, is the only outcome that points at the deployment
// rather than at the code being worked on.

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// applySandbox resolves the project's sandbox spec and folds it into spec.
//
// A project with no spec is the common case and costs one failed stat; the
// returned Resolved reports Present() false and nothing is changed.
//
// The returned error is already user-facing: it is either a
// *executor.HostExecutionDeniedError, a *executor.PlacementError or a
// *sandbox.GrantDeniedError, each of which carries its own remediation for the
// UI to render.
func applySandbox(spec executor.Spec, ex executor.Executor, workDir string) (executor.Spec, *sandbox.Resolved, error) {
	resolved, err := sandbox.Resolve(workDir)
	if err != nil {
		return spec, resolved, err
	}
	if !resolved.Present() {
		return spec, resolved, nil
	}

	// Capability gate, against the executor this project is bound to.
	if err := executor.CheckSandboxSupport(ex, resolved.Requirements(), workDir); err != nil {
		return spec, resolved, err
	}

	if err := resolved.ApplyTo(&spec, workDir, egressGrantChecker{}); err != nil {
		return spec, resolved, err
	}
	spec.Env = resolved.FilterEnv(spec.Env)
	return spec, resolved, nil
}

// recordSandboxProvenance writes the run's execution-environment record into
// the project directory, where the orchestrator running *inside* the sandbox
// picks it up and stamps it onto every task artifact it writes.
//
// Best-effort by design. A project directory that cannot be written is already
// a run that will fail on its first artifact, and failing the start here would
// replace that clear error with a confusing one about provenance.
func recordSandboxProvenance(workDir string, resolved *sandbox.Resolved, ex executor.Executor, h executor.Handle) {
	rec := artifact.SandboxRecord{
		PinnedImage: h.Image,
		StartedAt:   h.StartedAt,
	}
	if rec.StartedAt.IsZero() {
		rec.StartedAt = time.Now()
	}
	if ex != nil {
		rec.ExecutorID, rec.ExecutorKind = ex.ID(), ex.Kind()
	}
	if resolved.Present() {
		rec.SpecHash = resolved.Hash
		rec.RequestedImage = resolved.Spec.Image
		rec.SetupHash = resolved.Spec.SetupHash()
		rec.Warnings = resolved.Warnings
	}
	if rec.IsZero() {
		// Nothing to record: no sandbox spec and a driver with no image. Leave
		// any previous run's record in place rather than replacing it with an
		// empty one that would read as "this run had no environment".
		return
	}
	if _, err := artifact.WriteSandboxRun(workDir, rec); err != nil {
		fmt.Fprintf(os.Stderr, "[ui] sandbox: record run environment for %s: %v\n", workDir, err)
	}
}

// egressGrantChecker answers "does this project hold an active grant by this
// name" against the control plane's grant store.
//
// The store is opened lazily, inside HasEgressGrant, because the overwhelming
// majority of specs never name a grant — every workload start would otherwise
// open and close a SQLite handle to answer a question nobody asked.
type egressGrantChecker struct{}

// HasEgressGrant implements sandbox.GrantChecker.
//
// It fails closed on every error path. A hub whose grant store will not open
// must not become one that hands out network access it cannot audit; the run is
// refused with *sandbox.GrantDeniedError and its remediation instead of
// proceeding without the grant the spec asked for.
//
// Matching is on grant ID *and* subject. A grant issued to another project must
// not satisfy this project's spec merely because the names line up — that is
// the tenancy boundary, so the subject check stays even though IDs are already
// unique. A future ID scheme that is not, or a wildcard subject, has to fail
// closed here rather than at the call site.
func (egressGrantChecker) HasEgressGrant(projectPath, grantID string) bool {
	bs, err := openBrokersAt(controlPlaneDir())
	if err != nil || bs == nil {
		return false
	}
	if bs.close != nil {
		defer bs.close()
	}
	if bs.egress == nil {
		return false
	}

	grants, err := bs.egress.ListGrants(egressbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		return false
	}
	requester := secretbroker.Requester{ProjectID: projectPath}
	now := time.Now()
	for _, g := range grants {
		if g.ID != grantID {
			continue
		}
		if !g.Active(now) || !g.Subject.Matches(requester) {
			continue
		}
		return true
	}
	return false
}

// All sandbox failures reach the browser through jsonWorkloadErr
// (executors_api.go), which is the single place every workload-dispatch error
// is rendered. Adding a second renderer here would be how the run panel and the
// project panel start disagreeing about what a refusal means.
