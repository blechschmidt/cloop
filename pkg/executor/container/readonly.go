package container

// readonly.go binds the other projects a run may read (Spec.ReadOnly, Task
// 20501) into its sandbox.
//
// Each project's directory is bound read-only at /readonly/<slug>, the same
// inodes as on the host, so the run reads the project as it is. Its hidden
// entries — the control directory, the git directory, the files credentials
// live in (executor.ReadOnlyHidden) — are each covered by a read-only bind of
// an empty directory or an empty file this driver stages, so what the run
// finds there is nothing.
//
// The project's root is bound, never its entries one by one. The root is a
// directory the project's own runs cannot replace — it is an entry of its
// parent, which no sandbox of the project may write — so what is bound is the
// directory that was checked. An entry inside it could be swapped for a link
// between the check and the runtime's mount, and a bind follows a link on the
// host: that would put whatever the link named on the hub's host into the
// sandbox. A link inside the bound tree is followed inside the sandbox, which
// reaches nothing the sandbox does not have.
//
// Read-only is the runtime's bind flag, which runc, crun, Kata and gVisor all
// honour: a write anywhere under /readonly fails with EROFS whatever user the
// workload runs as.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/projectconfine"
)

// readOnlyDirPrefix names the directories holding the empty directory and the
// empty file that cover a read-only project's hidden entries.
const readOnlyDirPrefix = "cloop-ro-"

// readOnlyMounts renders spec.ReadOnly: the binds of each project and of the
// covers for its hidden entries, parents before what they cover. It returns
// the directory it staged the covers in, which the caller removes when the
// container is terminal, or "" when nothing needed covering.
func (e *Executor) readOnlyMounts(spec executor.Spec) ([]mount, string, error) {
	if len(spec.ReadOnly) == 0 {
		return nil, "", nil
	}
	if err := executor.ValidateReadOnly(spec.ReadOnly); err != nil {
		return nil, "", fmt.Errorf("container: %w", err)
	}
	type planned struct {
		target string
		source string
		hidden []string
	}
	plans := make([]planned, 0, len(spec.ReadOnly))
	covers := 0
	for _, p := range spec.ReadOnly {
		if strings.TrimSpace(p.Source) == "" {
			return nil, "", fmt.Errorf("%w: read-only project %s has no directory on this executor's host",
				executor.ErrInvalidSpec, p.Project)
		}
		// Resolved once, here: what is bound is the directory checked below,
		// not whatever a link on the way to it names when the runtime looks.
		src, err := filepath.EvalSymlinks(p.Source)
		if err != nil {
			return nil, "", fmt.Errorf("%w: read-only project %s is not readable on this executor: %v",
				executor.ErrInvalidSpec, p.Project, err)
		}
		if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
			return nil, "", fmt.Errorf("%w: read-only project %s is not a directory on this executor",
				executor.ErrInvalidSpec, p.Project)
		}
		// Never the hub's own directory, nor one holding a control plane: its
		// .cloop is every project's state, and covering it would be the only
		// thing standing between the run and the hub's keys (Task 20418).
		if err := refuseControlPlaneTree(e.opts.ControlPlaneDir, src, e.id); err != nil {
			return nil, "", err
		}
		if err := projectconfine.Backstop(e.opts.ControlPlaneDir, src); err != nil {
			return nil, "", fmt.Errorf("%w: read-only project %s: %w", executor.ErrInvalidSpec, p.Project, err)
		}
		if strings.ContainsAny(src, ":,") {
			return nil, "", fmt.Errorf("%w: read-only project %s is at %q, which the runtime's mount flag "+
				"cannot carry", executor.ErrInvalidSpec, p.Project, src)
		}
		_, hidden, err := executor.ReadOnlyEntries(src)
		if err != nil {
			return nil, "", fmt.Errorf("%w: read-only project %s: %v", executor.ErrInvalidSpec, p.Project, err)
		}
		for _, h := range hidden {
			if !executor.ReadOnlyCoverable(filepath.Base(h)) {
				return nil, "", fmt.Errorf("%w: read-only project %s holds %q, which cannot be covered",
					executor.ErrInvalidSpec, p.Project, filepath.Base(h))
			}
		}
		covers += len(hidden)
		plans = append(plans, planned{target: p.Target(), source: src, hidden: hidden})
	}

	var stageDir, emptyDir, emptyFile string
	if covers > 0 {
		var err error
		stageDir, emptyDir, emptyFile, err = e.stageReadOnlyCovers()
		if err != nil {
			return nil, "", err
		}
	}
	out := make([]mount, 0, len(plans)+covers)
	for _, pl := range plans {
		// No SELinux label: a label would have the runtime relabel the
		// project's tree, which belongs to another project, not to this run.
		out = append(out, mount{HostPath: pl.source, TargetPath: pl.target, ReadOnly: true})
		for _, h := range pl.hidden {
			fi, err := os.Lstat(h)
			if err != nil {
				// Gone since it was listed: nothing left to cover, and a bind
				// onto a missing target inside a read-only tree would fail.
				continue
			}
			cover := emptyFile
			if fi.IsDir() {
				cover = emptyDir
			}
			out = append(out, mount{HostPath: cover, TargetPath: path.Join(pl.target, filepath.Base(h)),
				ReadOnly: true})
		}
	}
	return out, stageDir, nil
}

// stageReadOnlyCovers makes the directory holding the empty directory and the
// empty file hidden entries are covered with: under the stage base the engine
// sees at the same path, as the hub CA's (gitca.go), world-readable and
// nobody's to write.
func (e *Executor) stageReadOnlyCovers() (dir, emptyDir, emptyFile string, err error) {
	base := strings.TrimSpace(e.opts.StageDir)
	if base == "" {
		base = secretStageBase()
	}
	dir, err = os.MkdirTemp(base, readOnlyDirPrefix)
	if err != nil {
		return "", "", "", fmt.Errorf("container: stage the covers of a read-only project: %w", err)
	}
	fail := func(what string, err error) (string, string, string, error) {
		removeReadOnlyStage(dir)
		return "", "", "", fmt.Errorf("container: %s: %w", what, err)
	}
	emptyDir, emptyFile = filepath.Join(dir, "empty"), filepath.Join(dir, "empty-file")
	if err := os.Mkdir(emptyDir, 0o555); err != nil {
		return fail("make the empty directory a read-only project's hidden entries are covered with", err)
	}
	f, err := os.OpenFile(emptyFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return fail("make the empty file a read-only project's hidden files are covered with", err)
	}
	if err := f.Close(); err != nil {
		return fail("make the empty file a read-only project's hidden files are covered with", err)
	}
	// The modes past the umask, and the directory open to the sandbox's user.
	for p, mode := range map[string]os.FileMode{dir: 0o755, emptyDir: 0o555, emptyFile: 0o444} {
		if err := os.Chmod(p, mode); err != nil {
			return fail("open the covers of a read-only project to the sandbox", err)
		}
	}
	return dir, emptyDir, emptyFile, nil
}

// removeReadOnlyStage removes a directory stageReadOnlyCovers made.
func removeReadOnlyStage(dir string) {
	if dir == "" || !strings.HasPrefix(filepath.Base(dir), readOnlyDirPrefix) {
		return
	}
	// The empty directory is 0555; open it so RemoveAll can remove it.
	_ = os.Chmod(filepath.Join(dir, "empty"), 0o755)
	_ = os.RemoveAll(dir)
}
