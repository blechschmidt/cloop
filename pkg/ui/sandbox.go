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
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
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

	// Image trust, before anything else looks at the spec. The executors
	// enforce this too — they are the authority, because they are what runs the
	// image, and a device's executor is where its signature is verified (Task
	// 20424) — but a refusal here reaches the author as a config error on the
	// file they wrote, rather than as a container that failed to start.
	policy, err := hubImagePolicy()
	if err != nil && resolved.Spec.Image != "" {
		return spec, resolved, fmt.Errorf("%s: image: %w", sandbox.FileName, unreadableImagePolicy(resolved.Spec.Image, err))
	}
	if _, err := resolved.CheckImagePolicy(policy); err != nil {
		return spec, resolved, err
	}

	// Capability gate, against the executor this project is bound to.
	if err := executor.CheckSandboxSupport(ex, resolved.Requirements(), workDir); err != nil {
		return spec, resolved, err
	}
	// Admitted, but on a claim nothing has verified: say so on the run's
	// journal (Task 20439). A contradicted claim was refused above.
	journalUnverifiedIsolation(workDir, ex, resolved.Requirements())

	if err := resolved.ApplyTo(&spec, workDir, egressGrantChecker{ex: ex}); err != nil {
		return spec, resolved, err
	}
	spec.Env = resolved.FilterEnv(spec.Env)
	return spec, resolved, nil
}

// hubImagePolicy reads the control plane's image trust policy.
//
// Read per call rather than cached, so an operator who tightens the policy sees
// it apply to the next run instead of after a restart — the same expectation
// every other section of config.yaml sets. Read from the hub's effective
// configuration, so a policy written in the per-instance overlay is enforced
// here as well as in the drivers' bootstrap copy (Task 20364).
//
// A config that will not load is an error, never the zero policy, which admits
// every image (Task 20424). This read used to fail open on the argument that
// the executors hold their own copy — true of the container and Kubernetes
// drivers, built from the config that loaded at bootstrap, and of nothing on a
// device. A device's executor now reads the policy itself per dispatch and
// refuses when it cannot; this refuses too, earlier and naming the file.
//
// No control plane at all — a process that bootstrapped no hub — has stated no
// policy, and gets the zero one: there is no configuration to have failed.
func hubImagePolicy() (imagepolicy.Policy, error) {
	cfg, err := controlPlaneConfig()
	if errors.Is(err, errNoControlPlane) {
		return imagepolicy.Policy{}, nil
	}
	if err != nil {
		return imagepolicy.Policy{}, err
	}
	return cfg.Sandbox.ImagePolicy.Policy(), nil
}

// unreadableImagePolicy is the refusal of a project image the hub cannot check
// because its own configuration will not load: an image denial, so it is
// audited and rendered as one.
func unreadableImagePolicy(image string, cause error) error {
	return &imagepolicy.DenyError{
		Ref:  image,
		Rule: imagepolicy.RuleConfig,
		Reason: fmt.Sprintf("the hub could not read its image trust policy (%v), so it cannot say whether "+
			"this image is one it admits", cause),
		Remediation: "Fix the hub's configuration — `cloop config validate` in the hub's directory names what " +
			"is wrong — and start the run again.",
	}
}

// auditImageDenial records a container image refused by the trust policy, and
// does nothing for any other error.
//
// It is called from the workload entry points rather than from applySandbox,
// because a denial can come from either of two places: the early validation
// check here, or the executor itself — which is also where a signature
// verification failure is decided, and that is the denial an operator most
// wants a row for. Emitting at the entry point catches both without either
// layer having to know about the trail.
//
// The actor is "system": these functions are reached from handlers that know
// who is signed in, but also from the supervisor's failover path, which is
// nobody. Attributing a hub-side refusal to whichever human happened to trigger
// the dispatch would be the more misleading of the two records; the identity
// that started the run is already in the trail and correlates by project and
// timestamp.
func auditImageDenial(workDir string, err error) {
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) {
		return
	}
	dir := controlPlaneDir()
	if dir == "" {
		return
	}
	// state.DBPath, not dir: statedb.Open takes the path of the database file
	// and handing it a directory fails on every call — which is how this
	// emitter silently recorded nothing.
	db, dbErr := statedb.Open(state.DBPath(dir))
	if dbErr != nil {
		fmt.Fprintf(os.Stderr, "[ui] sandbox: audit image denial for %s: %v\n", workDir, dbErr)
		return
	}
	defer db.Close()
	// An image-policy denial is a placement decision the hub made, so it is
	// recorded in the hub's chain even though workDir names a project. Marking
	// the handle is what keeps that deliberate choice from reading like the
	// accident it resembles.
	db.AsControlPlane()

	in := statedb.ImagePolicyDenialInput{
		ProjectPath: workDir,
		Image:       denied.Ref,
		Rule:        denied.Rule,
		Reason:      denied.Reason,
	}
	// Re-parse for the structured components. A reference that does not parse
	// leaves them empty, which is correct: there was no registry to record.
	if ref, perr := imagepolicy.ParseReference(denied.Ref); perr == nil {
		in.Registry, in.Repository = ref.Registry, ref.Repository
	}
	statedb.AuditImagePolicyDenial(db, in)
}

// recordSandboxProvenance writes the run's execution-environment record into
// the project directory, where the orchestrator running *inside* the sandbox
// picks it up and stamps it onto every task artifact it writes.
//
// Best-effort by design. A project directory that cannot be written is already
// a run that will fail on its first artifact, and failing the start here would
// replace that clear error with a confusing one about provenance.
func recordSandboxProvenance(workDir string, resolved *sandbox.Resolved, ex executor.Executor, h executor.Handle, identity, runID string, leaseIDs []string) {
	rec := artifact.SandboxRecord{
		PinnedImage: h.Image,
		StartedAt:   h.StartedAt,
		Identity:    identity,
		RunID:       runID,
		LeaseIDs:    leaseIDs,
	}
	// The verdict on one of cloop's own images, and the digest verified (Task
	// 20453): onto every task artifact and task.dispatch row of the run.
	if p := h.ImageProvenance; p != nil {
		rec.ImageProvenance = string(p.Status)
		rec.VerifiedDigest = p.VerifiedDigest()
		if rec.PinnedImage == "" && p.Digest != "" {
			// A device pins an unverified tag in its own store, so its handle
			// names no image; the record says what the hub resolved instead.
			rec.PinnedImage = p.Ref
		}
	}
	if rec.StartedAt.IsZero() {
		rec.StartedAt = time.Now()
	}
	if ex != nil {
		rec.ExecutorID, rec.ExecutorKind = ex.ID(), ex.Kind()
		rec.Isolation = string(ex.Capabilities().Isolation)
	}
	if resolved.Present() {
		rec.SpecHash = resolved.Hash
		rec.RequestedImage = resolved.Spec.Image
		rec.SetupHash = resolved.Spec.SetupHash()
		rec.Warnings = resolved.Warnings
	}
	if rec.IsZero() && rec.Identity == "" {
		// Nothing to record: no sandbox spec and a driver with no image. Leave
		// any previous run's record in place rather than replacing it with an
		// empty one that would read as "this run had no environment".
		//
		// An identity alone is worth a record even when the environment is
		// not, and is in fact the common case on a host-executor hub: without
		// this the spend of every local run would be unattributable, and — the
		// worse half — a *previous* run's record would survive and attribute
		// this run's spend to whoever started that one.
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
//
// It asks as the executor the run is bound to, as the hub records it — the
// requester the session will be redeemed as (applyEgressSession) — so a grant
// issued to that executor, or to a label selector its labels match (Task
// 20432), satisfies the spec as it would at redemption. It used to ask as the
// project alone, which only a project or "any" grant could answer.
type egressGrantChecker struct {
	ex executor.Executor
}

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
func (c egressGrantChecker) HasEgressGrant(projectPath, grantID string) bool {
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
	rec, err := recordedExecutor(bs.db, c.ex)
	if err != nil {
		return false
	}
	requester := secretbroker.NewRequester(rec, secretbroker.RequestScope{ProjectID: policyProjectPath(projectPath)})
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

// provenanceWarned remembers which unverified images of cloop's own this hub
// process has journaled for each project, so a project of a hundred tasks
// carries one warning per image digest and verdict rather than a hundred.
var provenanceWarned = struct {
	sync.Mutex
	seen map[string]bool
}{seen: map[string]bool{}}

// journalImageProvenance writes the run's warning when one of cloop's own
// images ran without a signature verified against the workflow that publishes
// them (Task 20453): unsigned, or nothing could check it. A verified image and
// one that is not cloop's say nothing; a wrongly signed one never started.
func journalImageProvenance(workDir string, ex executor.Executor, h executor.Handle) {
	p := h.ImageProvenance
	if p == nil || p.Verified() || p.Warning == "" || workDir == "" {
		return
	}
	key := workDir + "\x00" + p.Image + "\x00" + p.Digest + "\x00" + string(p.Status)
	provenanceWarned.Lock()
	if provenanceWarned.seen[key] {
		provenanceWarned.Unlock()
		return
	}
	if len(provenanceWarned.seen) >= 4096 {
		provenanceWarned.seen = map[string]bool{}
	}
	provenanceWarned.seen[key] = true
	provenanceWarned.Unlock()

	details := map[string]any{
		"image":    p.Image,
		"ref":      p.Ref,
		"status":   string(p.Status),
		"identity": p.Identity,
		"issuer":   p.Issuer,
	}
	if p.Digest != "" {
		details["digest"] = p.Digest
	}
	if ex != nil {
		details["executor_id"] = ex.ID()
	}
	state.LogEventDetails(workDir, state.EventRow{
		Type:    state.EventImageProvenance,
		Step:    state.NoStep,
		Message: p.Warning,
	}, details)
}

// isolationWarned remembers which unverified placements this hub process has
// already journaled, so a project of a hundred tasks carries one warning per
// executor runtime and probe attempt rather than a hundred.
var isolationWarned = struct {
	sync.Mutex
	seen map[string]bool
}{seen: map[string]bool{}}

// journalUnverifiedIsolation writes the run's warning when ex was admitted for
// a project requiring isolation on a claim no probe has verified.
func journalUnverifiedIsolation(workDir string, ex executor.Executor, req executor.Requirements) {
	msg := executor.IsolationAdmissionWarning(ex, req)
	if msg == "" || workDir == "" {
		return
	}
	st := executor.JudgeIsolation(ex)
	attempt := ""
	if st.Record != nil {
		attempt = st.Record.AttemptedAt.String()
	}
	key := workDir + "\x00" + ex.ID() + "\x00" + st.Runtime + "\x00" + attempt
	isolationWarned.Lock()
	if isolationWarned.seen[key] {
		isolationWarned.Unlock()
		return
	}
	if len(isolationWarned.seen) >= 4096 {
		isolationWarned.seen = map[string]bool{}
	}
	isolationWarned.seen[key] = true
	isolationWarned.Unlock()

	state.LogEventDetails(workDir, state.EventRow{
		Type:    state.EventIsolationEvidence,
		Step:    state.NoStep,
		Message: msg,
	}, map[string]any{
		"executor_id": ex.ID(),
		"runtime":     st.Runtime,
		"claim":       string(st.Claim),
		"status":      string(st.Status),
	})
}
