package container

// feature.go is this driver's feature mode (Task 20367): running a workload
// whose tree is a branch the control plane shipped (executor.WorkspaceBundle)
// rather than the project directory the driver ordinarily mounts.
//
// # Why not mount the feature
//
// A feature is a linked git worktree on the hub. Its .git is a pointer to the
// parent repository's .git/worktrees/<slug> by absolute path, so mounted at
// /workspace it names a directory the container does not have, and git does
// not work. Mounting the parent's .git as well would make it resolve, and would
// hand the sandbox the hub's own repository: hooks and configuration written
// there run on the host at the next git command anything on the hub runs in
// that repository. So the sandbox gets a standalone checkout of the feature's
// branch instead, staged by this driver in a directory of its own.
//
// # Nothing the sandbox wrote is interpreted on the host
//
// The staged tree, its .git included, is the sandbox's to write. Running git in
// it afterwards on the host — to commit what the harness left and bundle the
// result — would run that git with whatever the sandbox configured: a
// core.fsmonitor, a filter, a core.worktree aimed elsewhere on the hub. Reading
// the run's state database on the host would parse a file the sandbox wrote.
// So both happen inside the container, after the harness: the workload's argv
// is wrapped in `cloop workspace writeback`, which runs the harness, then
// commits and bundles in the sandbox, reads back the run's project state, and
// writes both into a second mounted directory. All the host does is read two
// files out of it as bytes — refusing anything that is not a regular file of
// bounded size — and hand them to the hub, which vets the bundle commit by
// commit and path by path (pkg/writeback) and merges the project state through
// the same validation a remote device's result gets.
//
// The seed is placed by the wrapper too, for the same reason in the other
// direction: the host writes the bytes the hub sent into the output directory
// and the sandbox unpacks them.
//
// # Lifetime
//
// The staged tree and the output directory outlive the container: the hub
// collects the bundle and the result after the workload's stream has closed.
// They are removed when the hub says it is done (ReleaseResults), when the
// handle is pruned, or featureRetention after the workload finished —
// whichever comes first — and immediately on a start that never ran.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

const (
	// featureOutMount is where the output directory appears in the sandbox.
	featureOutMount = "/cloop-out"
	// Names inside the output directory.
	featureBundleName = "writeback.bundle"
	featureSeedName   = "seed"
	featureResultName = "project-result"
	// featureRetention is how long a finished feature workload's tree and
	// output are kept for the hub to collect when it never says it is done.
	featureRetention = time.Hour
	// Persisted with the handle so a restarted hub can find them again.
	metaFeatureRoot   = "feature_root"
	metaFeatureBranch = "feature_branch"
	metaFeatureCap    = "feature_bundle_cap"
)

// featureRun is one feature workload's staged tree and output.
type featureRun struct {
	// root holds stage and out, and is what is removed.
	root  string
	stage string
	out   string
	// branch and bundleCap are what the write-back was asked for, kept to
	// synthesise an honest report when the sandbox produced none.
	branch    string
	bundleCap int64
	// redact scrubs the workload's leased credentials from anything read
	// back, for the hub's merge.
	redact func(string) string

	scanner executor.WriteBackScanner

	mu      sync.Mutex
	removed bool
	timer   *time.Timer
}

// isFeatureSpec reports whether spec asks for feature mode.
func isFeatureSpec(spec executor.Spec) bool {
	return spec.Workspace.Branch != nil || spec.Workspace.Kind == executor.WorkspaceBundle
}

// stageFeature builds the standalone tree a feature workload runs in, and the
// output directory its results come back through.
//
// user is the "uid:gid" the container will run as; the staged directories are
// handed to it so the sandbox can write them. "" leaves ownership alone, which
// is right under rootless podman's keep-id mapping.
func (e *Executor) stageFeature(ctx context.Context, spec executor.Spec, user string, emit func(string)) (*featureRun, error) {
	w := spec.Workspace
	b := w.Branch
	switch {
	case w.Kind != executor.WorkspaceBundle || b == nil:
		// A branch on top of a git workspace means cloning the upstream with a
		// brokered credential, which this driver never holds; the hub ships
		// the whole branch to an executor on its own host instead.
		return nil, fmt.Errorf("%w: the %s executor builds a feature's tree from a branch bundle the "+
			"control plane ships, not on top of a fetched repository (workspace kind %q)",
			executor.ErrUnsupported, executor.KindContainer, w.Kind)
	case len(spec.ProjectSeed) == 0:
		return nil, fmt.Errorf("%w: a feature workload needs the feature's project state, and this one "+
			"carries none", executor.ErrInvalidSpec)
	case spec.WriteBack.Mode != executor.WriteBackBundle:
		return nil, fmt.Errorf("%w: a feature workload on the %s executor returns its work as a bundle, "+
			"and this one asks for %q", executor.ErrInvalidSpec, executor.KindContainer, spec.WriteBack.Mode)
	}

	root, err := os.MkdirTemp("", "cloop-feature-")
	if err != nil {
		return nil, fmt.Errorf("container: create the feature's staging directory: %w", err)
	}
	f := &featureRun{
		root:      root,
		stage:     filepath.Join(root, "workspace"),
		out:       filepath.Join(root, "out"),
		branch:    b.Branch,
		bundleCap: spec.WriteBack.BundleCap(),
		redact:    spec.Redactor().String,
	}
	ok := false
	defer func() {
		if !ok {
			f.remove()
		}
	}()
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("container: secure the feature's staging directory: %w", err)
	}
	for _, dir := range []string{f.stage, f.out} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, fmt.Errorf("container: create %s: %w", dir, err)
		}
	}

	// The tree is built here, on the host, and that is safe in a way running
	// git in it afterwards would not be: the repository is brand new, made by
	// this call from bytes the hub produced, and nothing has had a chance to
	// write to it.
	if err := gitprovision.Provision(ctx, gitprovision.Request{
		Dir:              f.stage,
		Workspace:        w,
		BranchBundleFile: spec.BranchBundleFile,
		Emit:             emit,
		Host:             "the " + e.id + " container executor's host",
	}); err != nil {
		return nil, err
	}
	// Where the run is, so it attributes its tasks to this executor rather
	// than to "local, no isolation" — the claim the dashboard flags as host
	// execution.
	if _, err := artifact.WriteSandboxRun(f.stage, artifact.SandboxRecord{
		ExecutorID:   e.id,
		ExecutorKind: executor.KindContainer,
		Isolation:    string(e.Capabilities().Isolation),
		RunID:        strings.TrimSpace(spec.Labels[executor.LabelRunID]),
	}); err != nil {
		return nil, fmt.Errorf("container: record where the feature runs: %w", err)
	}
	if err := os.WriteFile(filepath.Join(f.out, featureSeedName), spec.ProjectSeed, 0o600); err != nil {
		return nil, fmt.Errorf("container: stage the feature's project state: %w", err)
	}
	if err := chownTree(root, user); err != nil {
		return nil, err
	}
	ok = true
	return f, nil
}

// wrap renders the argv that runs the harness inside `cloop workspace
// writeback`, which places the seed first and returns the work after.
func (f *featureRun) wrap(spec executor.Spec) []string {
	argv := []string{
		featureProgram(spec.Argv), "workspace", "writeback",
		"--dir", ContainerWorkspace,
		"--branch", f.branch,
		"--base", spec.WriteBackBase(),
		"--bundle", featureOutMount + "/" + featureBundleName,
		"--max-bundle-bytes", strconv.FormatInt(f.bundleCap, 10),
		"--seed", featureOutMount + "/" + featureSeedName,
		"--place-seed",
		"--project-result", featureOutMount + "/" + featureResultName,
	}
	if msg := strings.TrimSpace(spec.WriteBack.Message); msg != "" {
		argv = append(argv, "--message", msg)
	}
	// "--" so nothing in the harness's own command line is read as a flag of
	// the wrapper.
	argv = append(argv, "--")
	return append(argv, spec.Argv...)
}

// featureProgram is the cloop the wrapper runs as: the workload's own program
// when it is cloop — so a sandbox image that installs it under another path
// keeps working — and the bare name otherwise.
func featureProgram(argv []string) string {
	if len(argv) > 0 && strings.HasPrefix(filepath.Base(argv[0]), executor.HarnessProgram) {
		return argv[0]
	}
	return executor.HarnessProgram
}

// outMount is the bind that exposes the output directory to the sandbox.
func (f *featureRun) outMount(selinuxLabel string) mount {
	return mount{HostPath: f.out, TargetPath: featureOutMount, SELinuxLabel: selinuxLabel}
}

// handleMeta is the persisted metadata of a handle: the runtime, and for a
// feature workload what a restarted hub needs to find its output again.
func handleMeta(runtimeName string, f *featureRun) map[string]string {
	m := map[string]string{metaRuntime: runtimeName}
	if f != nil {
		for k, v := range f.meta() {
			m[k] = v
		}
	}
	return m
}

// meta is what a restarted hub needs to find this run's output again.
func (f *featureRun) meta() map[string]string {
	return map[string]string{
		metaFeatureRoot:   f.root,
		metaFeatureBranch: f.branch,
		metaFeatureCap:    strconv.FormatInt(f.bundleCap, 10),
	}
}

// restoreFeature rebuilds a featureRun from a persisted handle, or returns nil
// when the handle was not one.
func restoreFeature(meta map[string]string) *featureRun {
	root := strings.TrimSpace(meta[metaFeatureRoot])
	if root == "" || !filepath.IsAbs(root) {
		return nil
	}
	capBytes, _ := strconv.ParseInt(meta[metaFeatureCap], 10, 64)
	return &featureRun{
		root:      root,
		stage:     filepath.Join(root, "workspace"),
		out:       filepath.Join(root, "out"),
		branch:    meta[metaFeatureBranch],
		bundleCap: capBytes,
		redact:    func(s string) string { return s },
	}
}

// writeBack reports the sandbox's write-back for a finished workload: the
// report its wrapper printed, or an honest failure when it printed none.
func (f *featureRun) writeBack() *executor.WriteBackResult {
	if r := f.scanner.Snapshot(); r != nil {
		return r
	}
	return &executor.WriteBackResult{
		Mode:   executor.WriteBackBundle,
		Branch: f.branch,
		Err: "the sandbox produced no write-back report, so the feature's work could not be " +
			"returned; check that the sandbox image's cloop is recent enough to run a feature " +
			"(`cloop workspace writeback --place-seed`), and that the workload was not killed " +
			"before it finished",
	}
}

// bundle reads the returned bundle.
func (f *featureRun) bundle() ([]byte, error) {
	limit := f.bundleCap
	if limit <= 0 || limit > executor.MaxWriteBackBundleBytes {
		limit = executor.MaxWriteBackBundleBytes
	}
	data, err := f.readOut(featureBundleName, limit)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: the sandbox reported a bundle but left none", executor.ErrWriteBackUnavailable)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", executor.ErrWriteBackUnavailable, err)
	}
	return data, nil
}

// followRedaction scrubs the project state read back with bus's redaction as
// it stands then, not the Spec's: the state comes back after the run, and a
// token refreshed meanwhile (RefreshSecretFiles) joined the bus, not the Spec.
func (f *featureRun) followRedaction(bus *logbus.Bus) {
	if f == nil || bus == nil {
		return
	}
	f.redact = func(s string) string { return bus.Redactor().String(s) }
}

// projectResult reads the run's project state back.
func (f *featureRun) projectResult() (executor.ProjectResult, error) {
	res := executor.ProjectResult{Redact: f.redact}
	if res.Redact == nil {
		res.Redact = func(s string) string { return s }
	}
	data, err := f.readOut(featureResultName, executor.MaxProjectResultBytes)
	if err == nil {
		res.Data = data
		return res, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		res.Err = err.Error()
		return res, nil
	}
	reason, rerr := f.readOut(featureResultName+".err", 4096)
	if rerr != nil {
		return res, executor.ErrProjectResultUnavailable
	}
	res.Err = strings.TrimSpace(string(reason))
	return res, nil
}

// readOut reads one file the sandbox wrote into the output directory, as bytes.
//
// The directory is the sandbox's to write, so the file is opened without
// following a link and must be a regular file under limit bytes: a link left
// there would otherwise make this host read a file of the sandbox's choosing,
// with this host's authority, and hand it to the hub.
func (f *featureRun) readOut(name string, limit int64) ([]byte, error) {
	f.mu.Lock()
	removed := f.removed
	f.mu.Unlock()
	if removed {
		return nil, fmt.Errorf("the workload's output was already released")
	}
	path := filepath.Join(f.out, name)
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s in the sandbox's output is a link, not a file", name)
		}
		return nil, err
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s in the sandbox's output is not a regular file", name)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s in the sandbox's output is %d bytes, over the %d-byte limit",
			name, info.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(fh, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s in the sandbox's output grew past the %d-byte limit", name, limit)
	}
	return data, nil
}

// expireAfter schedules the removal of a finished workload's output.
func (f *featureRun) expireAfter(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removed || f.timer != nil {
		return
	}
	f.timer = time.AfterFunc(d, f.remove)
}

// remove deletes the staged tree and the output. Idempotent.
func (f *featureRun) remove() {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.removed {
		f.mu.Unlock()
		return
	}
	f.removed = true
	if f.timer != nil {
		f.timer.Stop()
	}
	f.mu.Unlock()
	if err := os.RemoveAll(f.root); err != nil {
		fmt.Fprintf(os.Stderr, "container: remove a feature workload's staging directory %s: %v\n", f.root, err)
	}
}

// chownTree hands everything under root to the sandbox user. Links are
// changed themselves, never followed.
func chownTree(root, user string) error {
	uid, gid, chown, err := parseContainerUser(user)
	if err != nil || !chown {
		return err
	}
	if uid == os.Getuid() && gid == os.Getgid() {
		return nil
	}
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			return fmt.Errorf("container: hand %s to the sandbox user %s: %w", path, user, err)
		}
		return nil
	})
}

// ReleaseResults implements executor.ResultReleaser: the hub has collected a
// feature workload's work, so its staged tree and output can go.
func (e *Executor) ReleaseResults(handleID string) {
	rec, err := e.lookup(handleID)
	if err != nil || rec.feature == nil {
		return
	}
	rec.feature.remove()
}

// WriteBackBundle implements executor.WriteBackFetcher for a feature workload.
func (e *Executor) WriteBackBundle(handleID string) ([]byte, error) {
	rec, err := e.lookup(handleID)
	if err != nil {
		return nil, err
	}
	if rec.feature == nil {
		return nil, fmt.Errorf("%w: handle %s was not a feature workload, so its changes are already "+
			"on the host", executor.ErrWriteBackUnavailable, handleID)
	}
	return rec.feature.bundle()
}

// ProjectResult implements executor.ProjectResultFetcher for a feature
// workload.
func (e *Executor) ProjectResult(handleID string) (executor.ProjectResult, error) {
	rec, err := e.lookup(handleID)
	if err != nil {
		return executor.ProjectResult{}, err
	}
	if rec.feature == nil {
		return executor.ProjectResult{}, executor.ErrProjectResultUnavailable
	}
	return rec.feature.projectResult()
}
