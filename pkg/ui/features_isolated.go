package ui

// features_isolated.go runs a feature on an executor that isolates from the
// hub's filesystem (Task 20367) — a container, a remote device, a virtual
// executor on one — instead of refusing it.
//
// A feature is a linked git worktree of its project's repository, on the hub.
// Its .git names the parent repository by an absolute host path, so the
// worktree itself cannot go anywhere: mounted into a container it is a
// directory git does not recognise, and a device never sees it. Mounting the
// parent's .git in as well is not an option either — hooks and configuration
// written there would run on the hub at the next git command run in that
// repository. So the feature travels as a branch:
//
//   - dispatch (applyFeatureWorkspace): the hub bundles the feature's branch
//     (pkg/executor/featurehub.Ship) and the executor builds a standalone
//     checkout from it — on top of an upstream clone when the parent's https
//     upstream already holds the feature's base, from the bundle alone
//     otherwise — and the feature's own .cloop state travels as a seed, as
//     for any project on an isolating executor;
//   - return (landFeatureWork): the run's commits come back as a write-back
//     bundle onto cloop/feature/<slug>, are vetted in quarantine
//     (pkg/writeback), and the hub's worktree is fast-forwarded onto them only
//     when it is clean and the work builds on its HEAD. Anything else is a
//     conflict, reported on the feature, with the work kept on a branch of its
//     own; nothing is ever forced;
//   - management: creating, removing and publishing a feature of such a
//     project happen on the hub (featurehub), because the hub is the only
//     place the feature exists.
//
// Policy stays the parent's throughout: every executor, ceiling, grant and
// firewall lookup keyed by the feature's path is mapped to its parent by
// policyProjectPath, exactly as for a feature that runs on the hub.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/featurehub"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/featureops"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	// featureShipTimeout bounds bundling a feature's branch at dispatch. Local
	// work, but a shallow fallback clones the repository once more.
	featureShipTimeout = 5 * time.Minute
	// featureLandTimeout bounds landing a run's returned work.
	featureLandTimeout = 5 * time.Minute
)

// featureBundleCap is executors.feature_bundle_mb from the hub's effective
// configuration, installed at startup (installFeatureBundleCap). Zero means
// the default.
var featureBundleCap atomic.Int64

// installFeatureBundleCap installs the hub's cap on feature bundles.
func installFeatureBundleCap(cfg *config.Config) {
	if cfg == nil {
		return
	}
	featureBundleCap.Store(cfg.Executors.FeatureBundleBytes())
}

// featureBundleLimit is the cap on a feature's shipped and returned bundles.
func featureBundleLimit() int64 {
	if n := featureBundleCap.Load(); n > 0 {
		return n
	}
	return executor.DefaultBranchBundleBytes
}

// featureRunsIsolated reports whether workDir is a feature whose workloads, on
// ex, have to travel as a branch rather than run in the hub's worktree.
func featureRunsIsolated(workDir string, ex executor.Executor) bool {
	if ex == nil {
		return false
	}
	_, _, ok := feature.ParentOf(workDir)
	return ok && executor.IsolatesFromHost(ex)
}

// featureCapabilityGap names what ex lacks to run a feature, or "" when it
// has everything: receiving the branch, placing the feature's state, and
// returning both the commits and the state afterwards.
func featureCapabilityGap(ex executor.Executor) string {
	caps := ex.Capabilities()
	var missing []string
	if !caps.SupportsBranchBundle {
		missing = append(missing, "receive the feature's branch from the hub")
	}
	if !caps.SupportsProjectSeed {
		missing = append(missing, "receive the feature's task list")
	}
	if !caps.SupportsWriteBack {
		missing = append(missing, "return the commits the run makes")
	}
	if !caps.ReturnsProjectState {
		missing = append(missing, "return the run's task outcomes")
	}
	return strings.Join(missing, ", ")
}

// applyFeatureWorkspace shapes spec to run the feature at workDir on ex: a
// standalone checkout of its branch, built by the executor from a bundle the
// hub ships, seeded with the feature's own project state, and — for a run,
// when returnWork — returning its commits as a bundle onto the feature's
// branch.
//
// The bundle file is named in spec.BranchBundleFile; the caller removes it once
// Start has returned. On error nothing is left behind.
func applyFeatureWorkspace(spec executor.Spec, ex executor.Executor, workDir string, returnWork bool) (executor.Spec, error) {
	refuse := func(reason string) (executor.Spec, error) {
		return spec, &workspaceSourceError{
			ProjectPath:       workDir,
			ExecutorID:        ex.ID(),
			ExecutorKind:      ex.Kind(),
			Reason:            reason,
			SuppressRemoteFix: true,
		}
	}
	if gap := featureCapabilityGap(ex); gap != "" {
		return spec, &featureExecutorError{FeaturePath: workDir, ExecutorID: ex.ID(),
			ExecutorKind: string(ex.Kind()), Missing: gap}
	}
	parent, _, _ := feature.ParentOf(workDir)
	caps := ex.Capabilities()
	sizeLimit := spec.Workspace.SizeLimitMB
	limit := featureBundleLimit()

	// The commits alone, on top of an upstream clone, when the executor can
	// clone and the parent has an https upstream it may fetch: on a device
	// with a slow uplink that is the difference between shipping a feature's
	// three commits and shipping its project's whole history.
	var upstream, grant string
	if caps.SupportsWorkspaceProvisioning && !spec.DisableNetwork {
		if origin, err := readGitOrigin(parent); err == nil {
			if repo, err := normalizeRemoteToHTTPS(origin.Remote); err == nil {
				ws := executor.Workspace{Kind: executor.WorkspaceGit, Repo: repo}
				if g, err := workspaceGrantFor(ws, ex, workDir); err == nil {
					upstream, grant = repo, g
				}
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), featureShipTimeout)
	defer cancel()
	sh, err := featurehub.Ship(ctx, featurehub.ShipRequest{FeatureDir: workDir, Upstream: upstream, MaxBytes: limit})
	if err != nil {
		return refuse(err.Error())
	}
	keep := false
	defer func() {
		if !keep {
			sh.Remove()
		}
	}()

	seed, err := projectSeedFor(workDir)
	if err != nil {
		return spec, err
	}
	if len(seed) == 0 {
		return refuse("the feature has no project state on the hub to send with it")
	}

	if !caps.SharesHostFilesystem {
		spec.WorkDir = executor.DeviceWorkDir(spec.WorkDir)
	}
	if sh.Mode != featurehub.ShipOverlay {
		grant = ""
	}
	spec.Workspace = sh.Workspace(sizeLimit, grant)
	spec.BranchBundleFile = sh.File
	spec.ProjectSeed = seed
	if returnWork {
		spec.WriteBack = executor.WriteBack{
			Mode:           executor.WriteBackBundle,
			Branch:         sh.Branch,
			Message:        "cloop: work on feature " + sh.Branch + " from executor " + ex.ID(),
			MaxBundleBytes: limit,
		}
	}
	if err := spec.Workspace.Validate(); err != nil {
		return refuse(err.Error())
	}
	if err := executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), workDir); err != nil {
		return spec, err
	}
	state.LogEvent(workDir, state.EventRow{
		Type: state.EventProjectSeed, Step: state.NoStep,
		Message: fmt.Sprintf("Sent to executor %q as a standalone checkout of %s", ex.ID(), sh.Describe()),
	})
	keep = true
	return spec, nil
}

// --- the way back ------------------------------------------------------------

// featureReturn is what the hub needs, after a feature's run, to land its work:
// the branch it was sent and the commit it was sent at. It travels with the
// run's seeded-dispatch record, and in the cluster owner row so a member that
// adopts the run can land it too.
type featureReturn struct {
	Branch   string `json:"branch"`
	Head     string `json:"head"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
}

// featureReturnFor reads the return record off a dispatched spec, or nil when
// the run returns no feature work.
func featureReturnFor(spec executor.Spec) *featureReturn {
	b := spec.Workspace.Branch
	if b == nil || !spec.WriteBack.Enabled() {
		return nil
	}
	return &featureReturn{Branch: b.Branch, Head: b.Head, MaxBytes: spec.WriteBack.BundleCap()}
}

// rememberFeatureReturn attaches fr to the seeded dispatch of handleID on ex.
func rememberFeatureReturn(ex executor.Executor, handleID string, fr *featureReturn) {
	if ex == nil || fr == nil {
		return
	}
	key := seededKey(ex.ID(), handleID)
	seededMu.Lock()
	defer seededMu.Unlock()
	if d, ok := seeded[key]; ok {
		cp := *fr
		d.feature = &cp
		seeded[key] = d
	}
}

// landFeatureWork applies what a feature's run on ex returned to the hub's
// worktree, and records the outcome on the feature. Called once the run's
// stream has closed, from collectRunResult.
func (s *Server) landFeatureWork(workDir string, ex executor.Executor, handleID string, d seededDispatch) {
	defer recoverGoroutine("land feature work: " + workDir)
	fr := d.feature
	if fr == nil {
		return
	}
	// The executor may be keeping the run's output for us; tell it we are
	// done with it whatever happens below.
	defer func() {
		if r, ok := ex.(executor.ResultReleaser); ok {
			r.ReleaseResults(handleID)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), featureLandTimeout)
	defer cancel()

	ret := feature.Return{At: time.Now().UTC(), Executor: ex.ID()}
	details := map[string]any{"executor_id": ex.ID(), "branch": fr.Branch, "base": fr.Head}
	if d.prov.RunID != "" {
		details["run_id"] = d.prov.RunID
	}
	finish := func() {
		s.recordFeatureReturn(workDir, ret, details)
	}
	defer finish()

	st, err := ex.Status(ctx, handleID)
	if err != nil || st.WriteBack == nil {
		ret.Outcome = "failed"
		ret.Message = fmt.Sprintf("Executor %q reported no write-back for this run, so the commits it made did "+
			"not come back to the hub.", ex.ID())
		if err != nil {
			ret.Message += " " + err.Error()
		}
		return
	}
	wb := *st.WriteBack
	redact := func(s string) string { return s }
	var bundle []byte
	if wb.Err == "" && wb.Mode == executor.WriteBackBundle && wb.Delivered() {
		fetcher, ok := ex.(executor.WriteBackFetcher)
		if !ok {
			ret.Outcome, ret.Commit = "failed", wb.CommitSHA
			ret.Message = fmt.Sprintf("Executor %q produced the run's work but has no way to hand it to the hub.", ex.ID())
			return
		}
		if bundle, err = fetcher.WriteBackBundle(handleID); err != nil {
			ret.Outcome, ret.Commit = "failed", wb.CommitSHA
			ret.Message = fmt.Sprintf("The run's work could not be collected from executor %q: %v", ex.ID(), err)
			return
		}
	}

	res, err := featurehub.Land(ctx, featurehub.LandRequest{
		FeatureDir:  workDir,
		Reported:    wb,
		Bundle:      bundle,
		ShippedHead: fr.Head,
		Label:       d.prov.RunID,
		MaxBytes:    fr.MaxBytes,
	})
	details["commit"] = res.CommitSHA
	if res.Commits > 0 {
		details["commits"] = res.Commits
		details["files_changed"] = res.FilesChanged
	}
	if err != nil {
		ret.Outcome, ret.Commit = "failed", wb.CommitSHA
		if errors.Is(err, executor.ErrWriteBackRejected) {
			ret.Outcome = "rejected"
		}
		ret.Message = "The run's work was not applied to " + fr.Branch + ": " + redact(err.Error())
		if strings.Contains(wb.Err, "over this workload's limit") {
			// The sandbox enforced the cap; say where it comes from, since
			// nothing in the project's own files sets it.
			ret.Message += fmt.Sprintf(" (the limit is the hub's executors.feature_bundle_mb, %d MB)", fr.MaxBytes>>20)
		}
		details["error"] = err.Error()
		return
	}
	ret.Outcome, ret.Commit, ret.KeptOn = string(res.Outcome), res.CommitSHA, res.KeptOn
	ret.Message = res.Describe()
	if res.KeptOn != "" {
		details["kept_on"] = res.KeptOn
		details["reason"] = res.Reason
	}
}

// recordFeatureReturn writes a landing's outcome to the feature's record and
// journal, and tells the dashboard.
func (s *Server) recordFeatureReturn(workDir string, ret feature.Return, details map[string]any) {
	details["outcome"] = ret.Outcome
	state.LogEventDetails(workDir, state.EventRow{
		Type: state.EventWriteBack, Step: state.NoStep, Message: ret.Message,
	}, details)
	if ret.Outcome == string(featurehub.LandConflict) {
		// On the parent's journal too: the conflict needs a person, and the
		// parent's Activity is where the project's people look.
		if parent, slug, ok := feature.ParentOf(workDir); ok {
			state.LogEventDetails(parent, state.EventRow{
				Type: state.EventWriteBack, Step: state.NoStep,
				Message: fmt.Sprintf("Feature %s: %s", slug, ret.Message),
			}, details)
		}
	}
	if m, err := feature.LoadMeta(workDir); err == nil {
		r := ret
		m.Return = &r
		if err := feature.SaveMeta(workDir, m); err != nil {
			fmt.Fprintf(os.Stderr, "ui: record the returned work on feature %s: %v\n", workDir, err)
		}
	}
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
}

// --- managing a feature of an isolated project ---------------------------------

// featureOpsOnHub reports whether the hub itself must create, remove and
// publish the features of the project at parentPath, rather than dispatch
// `cloop feature` to the project's executor: true when that executor isolates
// from the hub's filesystem — or when none can be resolved, since then nothing
// could run the command anywhere else either.
func featureOpsOnHub(parentPath string) bool {
	registerBuiltinExecutors()
	ex, err := executor.ResolveBinding(parentPath)
	if err != nil || ex == nil {
		return true
	}
	return executor.IsolatesFromHost(ex)
}

// errNoProjectRepository refuses a feature of a project with no repository on
// the hub. Its message is the whole explanation, so it is shown as it stands.
type errNoProjectRepository struct{ path string }

func (e errNoProjectRepository) Error() string {
	return "this project has no git repository of its own on the hub — its working directory lives on its " +
		"executor, and its code is the repositories granted to it, which the harness clones there — so there " +
		"is no branch on the hub to develop a feature on. A feature is a branch of the project's own " +
		"repository: give the project one (git init, or clone its repository into " + e.path +
		") to develop features of it"
}

// checkFeatureRepository refuses a project the hub cannot make features of.
func checkFeatureRepository(parentPath string) error {
	if _, _, err := resolveGitDir(parentPath); errors.Is(err, errNoGitRepo) {
		return errNoProjectRepository{path: parentPath}
	}
	return nil
}

// featureOpsCode classifies a featureops failure the way `cloop feature --json`
// does, so the hub-side and dispatched paths answer with the same HTTP status.
func featureOpsCode(err error) string {
	var dirty *featureops.DirtyError
	switch {
	case errors.Is(err, featureops.ErrExists):
		return "exists"
	case errors.Is(err, featureops.ErrNested):
		return "nested"
	case errors.As(err, &dirty):
		return "dirty"
	case errors.Is(err, featureops.ErrNothingToPropose):
		return "nothing_to_propose"
	case errors.Is(err, featureops.ErrNoToken):
		return "no_token"
	}
	return "failed"
}

// hubFeatureToken finds the credential the hub pushes a feature's branch and
// opens its pull request with, when the hub does it itself: the project's own
// GitHub grant first — branch restrictions honoured here, since no proxy
// stands between the hub and the forge — and the hub's own token only where
// featureTokenEnv would hand it out too, a hub without sign-in.
//
// release must be called once the token is no longer needed; it is never nil.
func (s *Server) hubFeatureToken(ctx context.Context, dir, branch string) (token, source string, release func(), err error) {
	release = func() {}
	remote, err := featurehub.Origin(ctx, dir)
	if err != nil {
		return "", "", release, fmt.Errorf("%w: %v", featureops.ErrNoToken, err)
	}
	parent := policyProjectPath(dir)
	registerBuiltinExecutors()
	ex, rerr := executor.ResolveBinding(parent)
	if rerr == nil && ex != nil && remote.HTTPS {
		ws := executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://" + remote.Host + "/" + remote.Repo}
		if grantName, gerr := workspaceGrantFor(ws, ex, dir); gerr == nil && grantName != "" {
			ws.CredentialGrant = grantName
			broker, closeDB, berr := openUIBroker(controlPlaneDir())
			if berr == nil {
				src, serr := gitcreds.New(broker, ex.ID(), workspaceLeaseActor)
				if serr == nil {
					access, rel, lerr := src.ForProxiedWorkspace(ctx, parent, ws)
					if lerr == nil && !access.Credential.Empty() {
						release = func() {
							rel()
							if closeDB != nil {
								closeDB()
							}
						}
						if b := access.Credential.Branches; len(b) > 0 {
							pol := gitproxy.Policy{AllowedRefs: b}
							pol.Normalize()
							if !pol.AllowsRef("refs/heads/" + branch) {
								release()
								return "", "", func() {}, fmt.Errorf("%w: grant %s may push only to %s, not to the "+
									"feature's branch %s — add it (or cloop/*) to the grant's branches",
									featureops.ErrNoToken, access.Credential.SecretName, strings.Join(b, ", "), branch)
							}
						}
						return access.Credential.Password, "grant " + access.Credential.SecretName, release, nil
					}
					rel()
				}
				if closeDB != nil {
					closeDB()
				}
			}
		}
	}
	if !s.oidcEnabled() && strings.EqualFold(remote.Host, "github.com") {
		if cfg, cerr := s.loadHubConfig(); cerr == nil && cfg != nil {
			if t := strings.TrimSpace(cfg.GitHub.Token); t != "" {
				return t, "the hub's github.token", release, nil
			}
		}
	}
	return "", "", release, fmt.Errorf("%w for %s: grant the project its GitHub repository with write and "+
		"pull-request access", featureops.ErrNoToken, remote.Repo)
}

// openFeaturePROnHub opens a feature's pull request from the hub itself.
func (s *Server) openFeaturePROnHub(ctx context.Context, dir string, req featurePRRequest) *featurePROutcome {
	meta, err := feature.LoadMeta(dir)
	if err != nil {
		return &featurePROutcome{Error: err.Error(), Code: "not_found"}
	}
	token, _, release, err := s.hubFeatureToken(ctx, dir, meta.Branch)
	defer release()
	if err != nil {
		return &featurePROutcome{Error: err.Error(), Code: featureOpsCode(err)}
	}
	res, err := featurehub.OpenPR(ctx, featureops.PROptions{
		FeatureDir: dir, Title: req.Title, Body: req.Body, Draft: req.Draft, Token: token,
	})
	if err != nil {
		return &featurePROutcome{Error: err.Error(), Code: featureOpsCode(err), Partial: res}
	}
	return &featurePROutcome{OK: true, Result: res}
}

// refreshFeaturePROnHub re-reads a feature's pull request from the hub itself.
func (s *Server) refreshFeaturePROnHub(ctx context.Context, dir string) (*feature.PR, error) {
	meta, err := feature.LoadMeta(dir)
	if err != nil {
		return nil, err
	}
	token, _, release, err := s.hubFeatureToken(ctx, dir, meta.Branch)
	defer release()
	if err != nil {
		return nil, err
	}
	return featurehub.RefreshPR(ctx, dir, token, "")
}
