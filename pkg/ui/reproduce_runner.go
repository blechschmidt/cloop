package ui

// reproduce_runner.go places a hermetic reproduction on an isolating executor.
//
// It is the implementation of taskreplay.SandboxRunner, and it lives here
// rather than in pkg/taskreplay because everything it needs is already wired up
// here: the executor registry and the project's binding, the secret broker that
// leases a workspace credential, the sandbox spec resolver, and the egress
// filter. pkg/taskreplay owns what a reproduction *means*; this owns how a
// sandbox is started, and the seam between them is four methods wide.
//
// # The guarantees this file is responsible for
//
// taskreplay.SandboxRunner documents four promises to its callers. Three of
// them are enforced here and each has a test in reproduce_runner_test.go:
//
//   - isolation: a host-sharing executor is refused, never silently used.
//     This is the promise that matters most, because a reproduction that ran
//     on the host would be scoring the operator's working tree.
//   - freshness: the workspace is provisioned from git at the recorded base
//     commit, so the sandbox starts from the tree the original run saw rather
//     than from whatever is checked out now.
//   - non-destructive: write-back is bundle mode. A bundle comes home as bytes;
//     there is no push, so no ref anywhere can move.
//
// The fourth — egress denied except for brokered grants — is inherited rather
// than re-implemented: the spec goes through the same applyLease,
// applyRepoGrants and applySandbox path a real run does, so a reproduction gets
// exactly the egress policy the project's own runs get and no more.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/taskreplay"
)

// ErrNoIsolatingExecutor is returned when no executor can host a reproduction.
//
// Its message names the remediation because this is the error an operator hits
// on a hub that has never been configured for isolation, and "no isolating
// executor" alone does not tell them what to do about it.
var ErrNoIsolatingExecutor = errors.New(
	"reproduce needs an isolating executor (container, VM, or remote agent) and this project is bound to one that " +
		"shares the host filesystem — a reproduction there would run against the working tree instead of a clean " +
		"checkout, so it is refused; configure a container or Kubernetes executor, or enrol a remote agent")

// ReproduceResultMarker prefixes the machine-readable line the in-sandbox half
// prints so this side can recover the test outcome.
//
// A marker on stdout rather than a file in the workspace: the file would be
// committed by the write-back and show up as a spurious difference in the
// diff-of-diffs — the reproduction would change its own result. Stdout is
// already streamed home by every driver, including the remote one.
const ReproduceResultMarker = "CLOOP_REPRODUCE_RESULT "

// reproducePromptDir is where the reconstructed prompt is delivered inside the
// sandbox.
//
// It travels as a Spec.SecretFile, which is the only channel that puts
// hub-side bytes at a known absolute path inside an isolated sandbox — the
// workspace is cloned from git, so writing there on the hub would not reach it.
// Treating the prompt as secret material is also right on its own terms: it
// carries the project's goal and instructions, and the channel's 0600 mode and
// post-run wipe are the handling that deserves.
const reproducePromptDir = "/run/cloop-reproduce"

const reproducePromptFile = "prompt.txt"

// reproduceRunner implements taskreplay.SandboxRunner against the hub's
// executor fleet.
type reproduceRunner struct {
	// selfExe is the cloop binary the sandbox runs. Injected so tests do not
	// need a real binary on PATH.
	selfExe string
}

// NewReproduceRunner returns a taskreplay.SandboxRunner backed by the hub's
// executor fleet. exe is the cloop binary to invoke inside the sandbox.
func NewReproduceRunner(exe string) taskreplay.SandboxRunner {
	return &reproduceRunner{selfExe: exe}
}

// RunReproduction re-executes the task in a fresh isolating sandbox.
func (r *reproduceRunner) RunReproduction(ctx context.Context, req taskreplay.RunRequest) (*taskreplay.RunOutcome, error) {
	if req.Provenance == nil {
		return nil, errors.New("reproduce: no provenance to run from")
	}
	argv := []string{r.exe(), "task", "reproduce-exec",
		"--prompt-file", reproducePromptDir + "/" + reproducePromptFile,
	}
	argv = append(argv, modelArgs(req.Provenance)...)
	argv = append(argv, testArgs(req.TestCommand)...)

	return r.run(ctx, runSpec{
		ProjectDir:  req.ProjectDir,
		BaseSHA:     req.Provenance.BaseSHA,
		Branch:      req.Branch,
		Argv:        argv,
		Prompt:      req.Provenance.Prompt,
		Timeout:     req.Timeout,
		WantCommits: true,
	})
}

// VerifyCommit runs only the project's test command, at a given commit.
//
// No agent, no prompt, and no write-back: this measures the behaviour of a tree
// that already exists. It is what turns "the bytes differ" into EQUIVALENT or
// DIVERGENT, so it must run in the same kind of sandbox as the reproduction —
// a suite that passes on the host and fails in the container would otherwise
// be reported as a divergence in the agent's work.
func (r *reproduceRunner) VerifyCommit(ctx context.Context, req taskreplay.VerifyRequest) (*taskreplay.TestOutcome, error) {
	if len(req.TestCommand) == 0 {
		return nil, nil
	}
	argv := append([]string{r.exe(), "task", "reproduce-exec", "--tests-only"},
		testArgs(req.TestCommand)...)

	out, err := r.run(ctx, runSpec{
		ProjectDir: req.ProjectDir,
		BaseSHA:    req.CommitSHA,
		Argv:       argv,
		Timeout:    req.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return out.Test, nil
}

func (r *reproduceRunner) exe() string {
	if strings.TrimSpace(r.selfExe) != "" {
		return r.selfExe
	}
	return "cloop"
}

// runSpec is the internal shape of one sandbox dispatch.
type runSpec struct {
	ProjectDir string
	// BaseSHA is the commit to provision the workspace at.
	BaseSHA string
	// Branch is the write-back branch; empty means no write-back at all.
	Branch string
	Argv   []string
	Prompt string
	// WantCommits asks for bundle-mode write-back.
	WantCommits bool
	Timeout     time.Duration
}

// run assembles the spec, dispatches it, and recovers the outcome.
func (r *reproduceRunner) run(ctx context.Context, rs runSpec) (*taskreplay.RunOutcome, error) {
	registerBuiltinExecutors()

	ex, err := resolveIsolatingExecutor(rs.ProjectDir)
	if err != nil {
		return nil, err
	}

	// A reproduction is its own execution and gets its own run id, deliberately
	// not the original's: it holds its own leases, and filing them under the run
	// being reproduced would put credentials the original never held into that
	// run's trail (Task 20282).
	lease := acquireSecretLease(controlPlaneDir(), rs.ProjectDir, ex, artifact.NewRunID())
	defer lease.Close()

	base := uiSpec(rs.ProjectDir, rs.Argv, map[string]string{
		"handler":   "reproduce",
		"ephemeral": "true",
	})
	// resolveIsolatingExecutor has already guaranteed this executor has a
	// filesystem of its own, so unlike the other dispatch sites this one has no
	// unisolated case at all: argv[0] here is the hub's path to the hub's
	// binary and is never resolvable on the far side. A reproduction sandbox
	// could therefore never run on a hub installed under any other name.
	executor.DeviceArgv(&base, ex)

	spec, err := applyLease(base, ex, lease)
	if err != nil {
		return nil, err
	}
	if spec, err = applyRepoGrants(spec, ex, lease); err != nil {
		return nil, err
	}
	if spec, err = applyDeviceGrants(spec, ex, lease); err != nil {
		return nil, err
	}
	if spec, err = applyInterfaceGrants(spec, ex, lease); err != nil {
		return nil, err
	}
	if spec, _, err = applySandbox(spec, ex, rs.ProjectDir); err != nil {
		return nil, err
	}
	if spec, err = applyWorkspace(spec, ex, rs.ProjectDir); err != nil {
		return nil, err
	}
	// A reproduction runs under the same ceilings as the run it reproduces.
	// Exempting it would make the verdict meaningless in the one direction that
	// matters: a commit that only builds in more memory than its project is
	// allowed would reproduce here and fail in production.
	spec, clamps := applyResourceCeiling(spec, rs.ProjectDir, ex)
	logResourceClamps(rs.ProjectDir, clamps)
	logUnenforceableCeiling(ex, rs.ProjectDir, clamps)

	if spec, err = pinWorkspaceTo(spec, rs.BaseSHA); err != nil {
		return nil, err
	}
	if rs.Prompt != "" {
		if spec, err = attachPrompt(spec, rs.Prompt); err != nil {
			return nil, err
		}
	}
	if rs.WantCommits {
		spec.WriteBack = executor.WriteBack{
			Mode:    executor.WriteBackBundle,
			Branch:  rs.Branch,
			Message: "cloop: reproduction of the recorded task",
		}
	} else {
		// Explicitly none rather than left zero: the zero value means the same
		// thing, but saying it makes the "a verification run never pushes"
		// decision greppable at the place it is made.
		spec.WriteBack = executor.WriteBack{Mode: executor.WriteBackNone}
	}
	if rs.Timeout > 0 {
		spec.TimeoutMinutes = int(rs.Timeout / time.Minute)
	}
	// Note: the hub's own dispatch path (startWorkload) additionally refuses an
	// executor that cannot take leased credentials back mid-run. That check is
	// not applied here because the helper it needs does not exist on this
	// branch yet; when it lands, this is the place for it — a reproduction
	// acquires the same lease a real run does and deserves the same guarantee.
	res, runErr := executor.Run(ctx, ex, spec)
	outcome := &taskreplay.RunOutcome{
		Branch:       rs.Branch,
		ExitCode:     res.Status.ExitCode,
		Output:       string(res.Output),
		ExecutorID:   ex.ID(),
		ExecutorKind: ex.Kind(),
		Isolation:    string(ex.Capabilities().Isolation),
		PinnedImage:  spec.Image,
	}
	outcome.Test = parseTestOutcome(outcome.Output)
	if runErr != nil {
		return outcome, fmt.Errorf("reproduction sandbox: %w", runErr)
	}

	if res.WriteBack != nil {
		outcome.Skipped = res.WriteBack.Skipped
		outcome.SkipReason = res.WriteBack.SkipReason
	}
	if rs.WantCommits && len(res.Bundle) > 0 {
		path, werr := writeBundle(res.Bundle)
		if werr != nil {
			return outcome, werr
		}
		outcome.BundlePath = path
	}
	return outcome, nil
}

// resolveIsolatingExecutor picks where a reproduction runs.
//
// The project's own binding first, because reproducing somewhere other than
// where the task ran is already a weaker claim and should not be done by
// default. When that binding shares the host filesystem, any other registered
// isolating executor is used instead — and when there is none, the run is
// refused rather than quietly downgraded to the host.
func resolveIsolatingExecutor(projectDir string) (executor.Executor, error) {
	bound, err := executor.Resolve(projectDir)
	if err == nil && bound != nil && isolates(bound) {
		return bound, nil
	}
	for _, id := range executor.DefaultRegistry.IsolatedIDs() {
		if candidate, getErr := executor.Get(id); getErr == nil && isolates(candidate) {
			return candidate, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w (resolving the project's executor also failed: %v)", ErrNoIsolatingExecutor, err)
	}
	return nil, ErrNoIsolatingExecutor
}

// isolates reports whether an executor can host a hermetic reproduction.
//
// Both halves are required and they are not the same question.
// Isolation says the workload is confined; SharesHostFilesystem says whether
// /workspace is the hub's own checkout. An executor could confine a process and
// still point it at the operator's working tree, and that is precisely the case
// this predicate exists to exclude.
func isolates(ex executor.Executor) bool {
	if ex == nil {
		return false
	}
	caps := ex.Capabilities()
	return caps.Isolation != executor.IsolationNone && !caps.SharesHostFilesystem
}

// pinWorkspaceTo rewrites the workspace to check out exactly base.
//
// Depth is cleared as well as Ref: a shallow fetch cannot resolve an arbitrary
// commit, so leaving a depth from the project's sandbox spec in place would
// turn every reproduction of anything but the branch tip into a fetch error.
func pinWorkspaceTo(spec executor.Spec, base string) (executor.Spec, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return spec, errors.New("reproduce: no base commit to provision the workspace at")
	}
	if spec.Workspace.Kind != executor.WorkspaceGit {
		// Reached only if applyWorkspace chose bind or none, which means the
		// executor shares our filesystem — resolveIsolatingExecutor should
		// already have refused. Fail closed rather than run against a tree
		// whose contents nobody chose.
		return spec, fmt.Errorf("%w: the resolved workspace is %q, not a fresh git checkout",
			ErrNoIsolatingExecutor, spec.Workspace.Kind)
	}
	spec.Workspace.Ref = base
	spec.Workspace.Depth = 0
	return spec, nil
}

// attachPrompt delivers the reconstructed prompt into the sandbox.
func attachPrompt(spec executor.Spec, prompt string) (executor.Spec, error) {
	file := executor.SecretFile{
		Dir:     reproducePromptDir,
		Name:    reproducePromptFile,
		Mode:    0o600,
		Content: []byte(prompt),
	}
	if err := file.Validate(); err != nil {
		return spec, fmt.Errorf("reproduce: the reconstructed prompt cannot be delivered (%d bytes): %w",
			len(prompt), err)
	}
	spec.SecretFiles = append(spec.SecretFiles, file)
	return spec, nil
}

// writeBundle spills the returned bundle to a temp file for compare.go.
//
// A file rather than bytes because git reads a bundle as a remote, and the
// caller (taskreplay.Reproduce) removes it.
func writeBundle(data []byte) (string, error) {
	f, err := os.CreateTemp("", "cloop-reproduce-*.bundle")
	if err != nil {
		return "", fmt.Errorf("create bundle file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write bundle file: %w", err)
	}
	return f.Name(), nil
}

// modelArgs reproduces the model settings the original run used.
func modelArgs(p *taskreplay.Provenance) []string {
	var args []string
	if v := strings.TrimSpace(p.Provider); v != "" {
		args = append(args, "--provider", v)
	}
	if v := strings.TrimSpace(p.Model); v != "" {
		args = append(args, "--model", v)
	}
	if v := strings.TrimSpace(p.Effort); v != "" {
		args = append(args, "--effort", v)
	}
	return args
}

// testArgs encodes the test command as one JSON argument.
//
// JSON rather than a trailing `-- cmd...`: the argv already ends in flags this
// side controls, and a command whose own arguments start with a dash would
// otherwise be parsed as reproduce-exec's.
func testArgs(cmd []string) []string {
	if len(cmd) == 0 {
		return nil
	}
	encoded, err := json.Marshal(cmd)
	if err != nil {
		return nil
	}
	return []string{"--test-command", string(encoded)}
}

// parseTestOutcome recovers the in-sandbox test result from the transcript.
//
// The last marker wins: a test command that printed the marker itself (a suite
// echoing its own logs, say) must not shadow the one this harness wrote at the
// end.
func parseTestOutcome(output string) *taskreplay.TestOutcome {
	idx := strings.LastIndex(output, ReproduceResultMarker)
	if idx < 0 {
		return nil
	}
	line := output[idx+len(ReproduceResultMarker):]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	var t taskreplay.TestOutcome
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &t); err != nil {
		return nil
	}
	return &t
}
