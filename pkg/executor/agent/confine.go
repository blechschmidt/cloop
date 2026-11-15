package agent

// confine.go keeps the projects a device serves apart (Task 20500).
//
// A device enrolled with one hub can be handed any of that hub's projects, and
// every project's tree lands beneath the same root. A payload the device runs
// as a host process runs as the agent's own user, and before this file nothing
// but convention kept one project's run out of another's tree: a run could
// list the root, read every checkout beside its own, and write into them. A
// container payload never had that problem — it sees its bind mount — and a
// host payload of the only project a device serves has nobody to keep out.
//
// So the layout makes each project's directory its own, and the host sandbox
// enforces it when the hub says the device is shared:
//
//   - A project's directory is exactly one level beneath the trees root, a
//     real directory (never a link) of mode 0700, so it neither contains nor
//     sits inside another project's, and another local user cannot read it.
//   - A workload that names no directory gets a private one of its own under
//     the agent's scratch root, removed when it ends, instead of the root
//     holding every project's tree.
//   - The package-manager caches the agent points payloads at are per project:
//     a shared Go build cache is one project's way of planting objects into
//     another's builds.
//   - With Spec.ConfineToProject (protocol v30), a host payload runs in the
//     host sandbox (pkg/hostsandbox: Landlock, no_new_privs, and namespaces
//     when the agent runs as root): its directory, its home and its caches
//     writable, its lease files, its harness and the system's directories
//     readable, nothing else. A device that cannot give the sandbox refuses
//     the payload rather than run it unconfined.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// unscopedDirName is the directory under the agent's scratch root that holds
// the private directories of workloads that name no project directory.
const unscopedDirName = ".cloop-unscoped"

// projectDirMode is the mode of a project's directory beneath the trees root.
const projectDirMode os.FileMode = 0o700

// ensureProjectDir makes dir — a project's directory, one level beneath the
// trees root — a real directory of mode 0700, creating it if needed. It never
// follows a link: a directory one project's run could have replaced with a
// link to another's would hand the next run of the first the other's tree.
func ensureProjectDir(dir string) error {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(dir, projectDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("agent: create the project directory %s: %w", dir, err)
		}
		info, err = os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("agent: inspect the project directory %s: %w", dir, err)
		}
	case err != nil:
		return fmt.Errorf("agent: inspect the project directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a link; a project's directory on this device is a directory of its own, "+
			"never a link to somewhere else", remote.ErrPathOutsideRoot, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("agent: %s is not a directory, so it cannot hold the project's tree", dir)
	}
	if info.Mode().Perm() != projectDirMode {
		// MkdirAll and Mkdir leave an existing directory's mode alone, and
		// one an older agent, a clone or an operator loosened must not stay
		// readable to the device's other users.
		if err := os.Chmod(dir, projectDirMode); err != nil {
			return fmt.Errorf("agent: restrict the project directory %s to its owner: %w", dir, err)
		}
	}
	return nil
}

// projectMarkerSuffix names the file beside a project's directory that
// records whose it is: "<dir>" gets ".<dir>.project".
const projectMarkerSuffix = ".project"

// claimProjectDir checks that dir, which the hub named after a project's path
// (executor.DeviceWorkDir: its base name and 32 bits of a hash), is that
// project's and no other's (Task 20500). Thirty-two bits are few enough that
// someone able to choose a project's path could find one whose name is
// another project's, and be handed that project's tree; so the first run in a
// directory records the full path's digest beside it, and a run of any other
// project there is refused. project is the hub's path, as the spec's
// "project" label carries it; "" — a hub too old to send one — checks
// nothing. The record sits beside the directory, beneath the trees root,
// where no workload may write.
func claimProjectDir(dir, project string) error {
	project = strings.TrimSpace(project)
	if project == "" || strings.TrimSpace(dir) == "" {
		return nil
	}
	sum := sha256.Sum256([]byte("cloop.dev/device-project/v1\x00" + filepath.Clean(project)))
	want := hex.EncodeToString(sum[:])
	marker := filepath.Join(filepath.Dir(dir), "."+filepath.Base(dir)+projectMarkerSuffix)
	info, err := os.Lstat(marker)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return fmt.Errorf("agent: record which project %s belongs to: %w", dir, err)
		}
		_, werr := f.WriteString(want + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("agent: record which project %s belongs to: %w", dir, werr)
		}
		return nil
	case err != nil:
		return fmt.Errorf("agent: read which project %s belongs to: %w", dir, err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("%w: the record of which project %s belongs to (%s) is not a file",
			remote.ErrPathOutsideRoot, dir, marker)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		return fmt.Errorf("agent: read which project %s belongs to: %w", dir, err)
	}
	if strings.TrimSpace(string(got)) != want {
		return fmt.Errorf("%w: %s holds another project's tree: the hub named this project's directory as "+
			"another's, and this device keeps them apart; give one of the two projects another path on the hub",
			remote.ErrPathOutsideRoot, dir)
	}
	return nil
}

// scratchWorkDir makes the private directory a workload that names no project
// directory runs in: never the trees root, which holds every project's tree.
func (a *Agent) scratchWorkDir(handleID string) (string, error) {
	base := filepath.Join(a.root, unscopedDirName)
	if err := ensureProjectDir(base); err != nil {
		return "", err
	}
	prefix := "w-"
	if id := sanitizeHandle(handleID); id != "" {
		prefix = id + "-"
	}
	dir, err := os.MkdirTemp(base, prefix)
	if err != nil {
		return "", fmt.Errorf("agent: make a private directory for a workload with no project: %w", err)
	}
	return dir, nil
}

// removeScratchWorkDir removes a directory scratchWorkDir made, and nothing
// else, whatever the caller passes.
func (a *Agent) removeScratchWorkDir(dir string) {
	if dir == "" || filepath.Dir(dir) != filepath.Join(a.root, unscopedDirName) {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		a.cfg.logf("warning: could not remove the private directory %s of a workload with no project: %v", dir, err)
	}
}

// sanitizeHandle keeps the characters of a handle ID that are safe in a
// directory name.
func sanitizeHandle(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	return b.String()
}

// projectCacheKey is the per-project name the caches of the payload whose
// tree is workDir are kept under: the tree's own directory name, which the hub
// derives from the project's path and which is one level beneath the trees
// root.
func projectCacheKey(workDir string) string {
	return filepath.Base(filepath.Clean(workDir))
}

// projectCacheDir is where the package-manager caches of the payload whose
// tree is workDir live, "" when this agent keeps no caches.
func (a *Agent) projectCacheDir(workDir string) string {
	if a.cacheDir == "" || strings.TrimSpace(workDir) == "" {
		return ""
	}
	key := projectCacheKey(workDir)
	if key == "" || key == "." || key == string(os.PathSeparator) {
		return ""
	}
	return filepath.Join(a.cacheDir, key)
}

// projectSandbox is the host sandbox a payload runs in when the hub asked for
// it to be kept to its project: its tree (the driver grants the work
// directory itself), home and the caches of the project whose tree is
// cacheTree ("" for none) writable; the harnesses it may start readable and
// first on its PATH. The lease's files, the hub's CA, the program and the
// system's directories the host-process driver adds itself.
func (a *Agent) projectSandbox(cacheTree, home string, env []string) *executor.HostSandbox {
	sb := &executor.HostSandbox{Home: home}
	if cache := a.projectCacheDir(cacheTree); cache != "" {
		// A real directory of the project's own: a link an earlier run left
		// where it goes is replaced, never granted, or the grant would be
		// wherever the link points.
		if err := ensurePayloadHome(cache); err == nil {
			sb.ReadWrite = append(sb.ReadWrite, cache)
		}
	}
	path, ro := harnessGrants(env)
	sb.Path = path
	sb.ReadOnly = append(sb.ReadOnly, ro...)
	return sb
}

// harnessGrants finds the harnesses a confined payload may start — claude and
// copilot, on the payload's PATH or in the per-user directories their
// installers write to — and returns the directories to put first on its PATH
// (where each was found) and to let it read and execute (where each really
// is). A confined payload's HOME is its own, so a harness under the agent
// user's home is no longer on the way to it.
func harnessGrants(env []string) (path, readOnly []string) {
	dirs := NativeHarnessDirs()
	pathVar := os.Getenv("PATH")
	if env != nil {
		pathVar = ""
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, "PATH="); ok {
				pathVar = v
			}
		}
	}
	dirs = append(dirs, filepath.SplitList(pathVar)...)
	seen := map[string]bool{}
	for _, name := range []string{"claude", "copilot"} {
		for _, d := range dirs {
			if d == "" || !filepath.IsAbs(d) {
				continue
			}
			candidate := filepath.Join(d, name)
			fi, err := os.Stat(candidate)
			if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
				continue
			}
			if !seen["p:"+d] {
				seen["p:"+d] = true
				path = append(path, d)
			}
			if resolved, err := filepath.EvalSymlinks(candidate); err == nil {
				if dir := filepath.Dir(resolved); !seen["r:"+dir] {
					seen["r:"+dir] = true
					readOnly = append(readOnly, dir)
				}
			}
			break
		}
	}
	return path, readOnly
}
