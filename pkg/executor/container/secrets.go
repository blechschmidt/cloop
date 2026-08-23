package container

// secrets.go stages a secret lease's credential *files* for a sandbox.
//
// # Why the driver stages its own copy
//
// The hub used to write every lease into its own /dev/shm and put the path in
// the workload's environment. That is a delivery only for a process running on
// the hub's filesystem. This driver runs on the hub and still cannot use it,
// for two independent reasons:
//
//   - the container has a mount namespace of its own, so a path the hub wrote
//     is simply not present inside it; and
//   - the lease directory is 0700 owned by the control-plane user, while the
//     sandbox runs as an unprivileged UID taken from the project directory's
//     owner. Even bound in, it would be unreadable.
//
// So the bytes travel in Spec.SecretFiles and this file writes them into a
// directory of its own — one per run, on a tmpfs where the host has one — owned
// by the UID the workload will run as, and binds it read-only at exactly the
// path the environment already names. Nothing is rewritten, and the hub holds
// no plaintext on disk at all.
//
// # What the sandbox gets
//
//	/dev/shm/cloop-lease-XXXX (host, 0700, owned by the sandbox UID)
//	        └── mounted read-only at /run/cloop/cloop-lease-<lease> (container)
//
// Read-only is not decoration. A credential helper script the workload could
// rewrite is a credential helper that answers for every repository, which would
// undo the one enforcement point a repository-scoped GitHub PAT has.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// secretDirPrefix names the staging directories. It matches the prefix
// pkg/secretbroker uses, which is also what pkg/executor/agent recognises as
// lease-owned — one vocabulary for "this directory holds leased credentials",
// wherever it is on disk.
const secretDirPrefix = "cloop-lease-"

// secretTmpfsCandidates are checked in order for a memory-backed staging
// directory. Same reasoning as the broker's: on tmpfs the plaintext never
// reaches a block device, so it cannot survive into something a later reader
// of that block sees. os.TempDir() is the fallback, where the wipe on teardown
// is the only thing carrying the guarantee.
var secretTmpfsCandidates = []string{"/dev/shm"}

// secretStage is one run's staged credential files, and the means to remove
// them.
type secretStage struct {
	// mounts are the read-only binds to add to the run.
	mounts []mount
	// dirs are the host directories created, for teardown.
	dirs []string
}

// mountList returns the binds to add to the run, or nil for no stage.
func (s *secretStage) mountList() []mount {
	if s == nil {
		return nil
	}
	return s.mounts
}

// remove wipes and deletes everything the stage created. It is idempotent and
// safe on the zero value, so it can sit in a defer beside an explicit call.
func (s *secretStage) remove() {
	if s == nil {
		return
	}
	for _, dir := range s.dirs {
		wipeSecretDir(dir)
	}
	s.dirs = nil
}

// stageSecretFiles writes spec.SecretFiles into per-run host directories and
// returns the read-only binds that make them visible at the paths the
// workload's environment already points at.
//
// user is the "uid[:gid]" the container will run as, or "" when the runtime
// maps the invoking user itself (rootless podman with keep-id) and no
// ownership change is needed. A failure part-way through removes what was
// already written rather than leaving credentials on the host.
func stageSecretFiles(spec executor.Spec, user string) (*secretStage, error) {
	if len(spec.SecretFiles) == 0 {
		return nil, nil
	}
	// Re-validate rather than trusting the caller. Spec.Validate has already
	// run, but this is the function that turns a name into a filesystem write,
	// and a check at the point of the write is the one that cannot be skipped
	// by a future call path.
	if err := executor.ValidateSecretFiles(spec.SecretFiles); err != nil {
		return nil, fmt.Errorf("container: %w", err)
	}

	uid, gid, chown, err := parseContainerUser(user)
	if err != nil {
		return nil, err
	}

	stage := &secretStage{}
	// One host directory per distinct target directory. A lease produces one;
	// two leases on one workload would produce two, and they must not share a
	// staging directory or a revocation of either would take both.
	hostDirs := make(map[string]string)
	for _, target := range executor.SecretFileDirs(spec.SecretFiles) {
		dir, derr := os.MkdirTemp(secretStageBase(), secretDirPrefix)
		if derr != nil {
			stage.remove()
			return nil, fmt.Errorf("container: create secret staging dir: %w", derr)
		}
		stage.dirs = append(stage.dirs, dir)
		hostDirs[target] = dir

		// 0700 before anything is written into it: a window in which the
		// directory is traversable is a window in which a file created inside
		// it is reachable, whatever the file's own mode.
		if cerr := os.Chmod(dir, 0o700); cerr != nil {
			stage.remove()
			return nil, fmt.Errorf("container: secure secret staging dir: %w", cerr)
		}
		if chown {
			if cerr := os.Chown(dir, uid, gid); cerr != nil {
				stage.remove()
				return nil, fmt.Errorf(
					"container: hand secret staging dir to uid %d (the sandbox user): %w", uid, cerr)
			}
		}
		stage.mounts = append(stage.mounts, mount{
			HostPath:   dir,
			TargetPath: target,
			// The workload reads its credentials; it never writes them. A
			// writable credential helper is one the workload can rewrite to
			// answer for repositories the grant excluded.
			ReadOnly: true,
		})
	}

	for _, f := range spec.SecretFiles {
		path := filepath.Join(hostDirs[f.Dir], f.Name)
		if werr := os.WriteFile(path, f.Content, f.FileMode()); werr != nil {
			stage.remove()
			return nil, fmt.Errorf("container: write secret file %s: %w", f.Name, werr)
		}
		// WriteFile honours the mode only when it creates the file, and chown
		// clears the setuid/setgid bits on some systems — so the mode is
		// asserted after both, not before either.
		if chown {
			if cerr := os.Chown(path, uid, gid); cerr != nil {
				stage.remove()
				return nil, fmt.Errorf("container: hand secret file %s to uid %d: %w", f.Name, uid, cerr)
			}
		}
		if cerr := os.Chmod(path, f.FileMode()); cerr != nil {
			stage.remove()
			return nil, fmt.Errorf("container: set mode on secret file %s: %w", f.Name, cerr)
		}
	}
	return stage, nil
}

// secretStageBase picks the parent directory for staging, preferring a tmpfs.
func secretStageBase() string {
	for _, cand := range secretTmpfsCandidates {
		info, err := os.Stat(cand)
		if err != nil || !info.IsDir() {
			continue
		}
		// Confirm writability rather than assuming it: a hardened image may
		// mount /dev/shm read-only.
		probe, err := os.CreateTemp(cand, ".cloop-probe-")
		if err != nil {
			continue
		}
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
		return cand
	}
	return os.TempDir()
}

// parseContainerUser splits the "uid[:gid]" the container will run as.
//
// chown is false for an empty value, which means the runtime is mapping the
// invoking user itself (rootless podman's keep-id): the files are already
// owned by the user the workload runs as, and chowning to our own UID would be
// a no-op that fails on some setups rather than a safeguard.
func parseContainerUser(user string) (uid, gid int, chown bool, err error) {
	u := strings.TrimSpace(user)
	if u == "" {
		return 0, 0, false, nil
	}
	uidField, gidField, hasGID := strings.Cut(u, ":")
	uid, err = strconv.Atoi(strings.TrimSpace(uidField))
	if err != nil {
		return 0, 0, false, fmt.Errorf("container: sandbox user %q is not a numeric uid[:gid]", user)
	}
	gid = uid
	if hasGID {
		gid, err = strconv.Atoi(strings.TrimSpace(gidField))
		if err != nil {
			return 0, 0, false, fmt.Errorf("container: sandbox group in %q is not numeric", user)
		}
	}
	return uid, gid, true, nil
}

// wipeSecretDir zeroes every file in a staging directory and removes it.
//
// Zeroing matters on the os.TempDir() fallback, where the directory is on a
// real filesystem and an unlink leaves the plaintext in blocks that survive
// until they are reused. On tmpfs the pages are freed anyway. Neither is a
// guarantee against a copy-on-write or log-structured filesystem, which is why
// the tmpfs candidate is preferred rather than merely convenient.
//
// Errors go to stderr and are not returned: this runs on teardown paths where
// there is nobody left to hand a failure to, and the one thing worse than a
// noisy wipe failure is a silent one.
func wipeSecretDir(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	// Refuse anything that is not one of ours. The path comes from this
	// process's own state today, but a delete driven by a path is exactly the
	// primitive that should not widen quietly if a future caller starts
	// passing something else in.
	if !strings.HasPrefix(filepath.Base(dir), secretDirPrefix) {
		fmt.Fprintf(os.Stderr, "container: refusing to wipe %s: not a %s* directory\n", dir, secretDirPrefix)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "container: read secret staging dir %s: %v\n", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		zeroFile(filepath.Join(dir, entry.Name()))
	}
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "container: remove secret staging dir %s: %v\n", dir, err)
	}
}

// zeroFile overwrites a file's bytes in place. A missing file is not an error:
// something else having already cleaned up is the desired end state.
func zeroFile(path string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	size := info.Size()
	if size <= 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	zeros := make([]byte, size)
	_, _ = f.WriteAt(zeros, 0)
	_ = f.Sync()
	_ = f.Close()
}
