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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/securewipe"
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

// stagedFile is one credential file on the host, attributed to the lease that
// produced it.
//
// The attribution is what makes revocation possible at the right granularity.
// Without it a stage is an anonymous set of paths, and "revoke lease_abc" could
// only be honoured by wiping every credential the workload holds — taking away
// a kubeconfig because a GitHub PAT was withdrawn.
type stagedFile struct {
	// host is the path on this machine. It is inside a dir bind-mounted into
	// the container, so unlinking it here is what the workload sees.
	host string
	// leaseID and grantID attribute the file, copied from executor.SecretFile.
	leaseID string
	grantID string
}

// secretStage is one run's staged credential files, and the means to remove
// them — either all at once on teardown, or one lease at a time on revocation.
//
// It is mutex-guarded because those two callers race: a revocation arriving
// while the workload is exiting would otherwise have finish() walking the same
// slices the revocation is truncating.
type secretStage struct {
	mu sync.Mutex
	// mounts are the read-only binds to add to the run.
	mounts []mount
	// dirs are the host directories created, for teardown.
	dirs []string
	// files are the staged credentials, attributed to their leases.
	files []stagedFile
}

// mountList returns the binds to add to the run, or nil for no stage.
func (s *secretStage) mountList() []mount {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mounts
}

// remove wipes and deletes everything the stage created. It is idempotent and
// safe on the zero value, so it can sit in a defer beside an explicit call.
func (s *secretStage) remove() {
	if s == nil {
		return
	}
	s.mu.Lock()
	dirs, files := s.dirs, s.files
	s.dirs, s.files = nil, nil
	s.mu.Unlock()

	// Files first, then the directories. Wiping a file the dir sweep would
	// also have caught is harmless; the reverse — removing the directory and
	// then finding an unwiped file — is not expressible.
	for _, f := range files {
		if err := securewipe.File(f.host); err != nil {
			fmt.Fprintf(os.Stderr, "container: wipe secret file %s: %v\n", f.host, err)
		}
	}
	for _, dir := range dirs {
		wipeSecretDir(dir)
	}
}

// revoke wipes the staged files matching req and reports how many went.
//
// Only the matching files are touched: a directory shared by two leases loses
// one lease's credentials and keeps the other's, and the directory itself is
// removed only once nothing staged remains in it. The bind mount stays in
// place either way — the container's view of the directory is the same inode
// as the host's, so unlinking here is what makes the next read inside the
// sandbox fail. Removing the mount would need a remount of a running
// container's namespace, which no runtime exposes, and is not needed: an empty
// read-only directory delivers nothing.
//
// Errors are joined and returned rather than logged, because this one runs
// with an operator waiting for an answer. A wipe that failed must not be
// reported as a revocation that succeeded.
func (s *secretStage) revoke(req executor.RevokeRequest) (int, error) {
	if s == nil {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		errs    []error
		removed int
		kept    []stagedFile
	)
	for _, f := range s.files {
		if !req.Matches(executor.SecretBinding{LeaseID: f.leaseID, GrantID: f.grantID}) {
			kept = append(kept, f)
			continue
		}
		if err := securewipe.File(f.host); err != nil {
			errs = append(errs, fmt.Errorf("wipe %s: %w", f.host, err))
			// Kept deliberately: a file that would not wipe is still this
			// stage's responsibility, and dropping it from the list would
			// mean teardown never tried again.
			kept = append(kept, f)
			continue
		}
		removed++
	}
	s.files = kept

	// A directory with no staged file left in it is removed, so a revoked
	// lease leaves nothing behind — not even an empty directory naming it.
	inUse := make(map[string]struct{}, len(kept))
	for _, f := range kept {
		inUse[filepath.Dir(f.host)] = struct{}{}
	}
	var keptDirs []string
	for _, dir := range s.dirs {
		if _, still := inUse[dir]; still {
			keptDirs = append(keptDirs, dir)
			continue
		}
		if err := securewipe.Dir(dir); err != nil {
			errs = append(errs, fmt.Errorf("remove lease dir %s: %w", dir, err))
			keptDirs = append(keptDirs, dir)
		}
	}
	s.dirs = keptDirs
	return removed, errors.Join(errs...)
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
		// Attributed as soon as it exists, before the chown and chmod below
		// can fail: a file that was written and then failed to be secured is
		// still a credential on this host, and the teardown that runs on the
		// error path has to know about it.
		stage.files = append(stage.files, stagedFile{
			host:    path,
			leaseID: f.LeaseID,
			grantID: f.GrantID,
		})
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
