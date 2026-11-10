package agent

// storage.go: where an agent keeps what, when its workloads' trees live on a
// volume that outlives it (Task 20484).
//
// An executor pool's runner used to be one emptyDir: the agent's scratch, the
// project's checkout, the harness's home and the leased credential files all
// beneath --workdir-root, all gone with the Pod. A runner whose controller
// keeps a persistent volume per project wants the checkout and the caches to
// survive — and nothing else. So the agent's directories are split by what
// they hold:
//
//   - --workspace-root: the trees, on the volume. A project's next run finds
//     its checkout there and fetches instead of cloning; gitprovision resets it
//     to exactly the commit fetched before the harness starts.
//   - --workdir-root: the agent's own scratch — shipped branches, the device
//     ledger, the isolation probe's staging — on an emptyDir, emptied on exit.
//   - --home-root: payloads' home directories — a harness's login state, its
//     session transcripts — on a memory-backed emptyDir, emptied on exit.
//     Never on the volume: the next run on it may be another person's.
//   - --secret-dir: leased credential files, ahead of the usual tmpfs probes,
//     on a memory-backed emptyDir; each lease's files are wiped as before.
//   - --cache-dir and --git-cache-dir: package-manager caches and a git object
//     cache, on the volume beside the trees, so a run starts warm.
//
// The volume itself is the controller's: it decides whether one is reused for
// a project, and wipes it before a runner starts when it last served another.
// The agent's part is never to write a credential there, and to refuse a
// configuration that would — a home or a secret directory on the volume, or
// a scratch root that overlaps it and would be emptied with it.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/securewipe"
)

// resolveStorageRoots resolves Config's storage directories and refuses a
// layout that would put a credential on the persistent volume, or empty the
// volume with the agent's scratch.
func (a *Agent) resolveStorageRoots() error {
	a.workspaceRoot = a.root
	if strings.TrimSpace(a.cfg.WorkspaceRoot) != "" {
		ws, err := resolveRoot(a.cfg.WorkspaceRoot)
		if err != nil {
			return fmt.Errorf("agent: --workspace-root: %w", err)
		}
		if ws != a.root && (within(a.root, ws) || within(ws, a.root)) {
			// The scratch root is emptied by an ephemeral runner, and a
			// workspace inside it would go with it; a scratch root inside the
			// workspace would put the agent's scratch on the volume.
			return fmt.Errorf("agent: --workspace-root %s and --workdir-root %s must not contain one another", ws, a.root)
		}
		a.workspaceRoot = ws
	}
	separate := a.workspaceRoot != a.root
	for _, d := range []struct {
		flag, value string
		dst         *string
	}{
		{"--home-root", a.cfg.HomeRoot, &a.homeRoot},
		{"--secret-dir", a.cfg.SecretDir, &a.secretDir},
		{"--cache-dir", a.cfg.CacheDir, &a.cacheDir},
		{"--git-cache-dir", a.cfg.GitCacheDir, &a.gitCacheDir},
	} {
		if strings.TrimSpace(d.value) == "" {
			continue
		}
		dir, err := resolveRoot(d.value)
		if err != nil {
			return fmt.Errorf("agent: %s: %w", d.flag, err)
		}
		*d.dst = dir
	}
	for _, d := range []struct{ flag, dir string }{{"--home-root", a.homeRoot}, {"--secret-dir", a.secretDir}} {
		if d.dir != "" && separate && (within(a.workspaceRoot, d.dir) || within(d.dir, a.workspaceRoot)) {
			return fmt.Errorf("agent: %s %s must not share a directory with --workspace-root %s: what it holds "+
				"is a credential, and the workspace root is a volume the next run may read", d.flag, d.dir, a.workspaceRoot)
		}
	}
	if a.cfg.Ephemeral && separate && a.homeRoot == "" {
		// Without a home root a payload's home goes beside its tree — onto
		// the volume, with its login state and transcripts.
		return errors.New("agent: --ephemeral with a separate --workspace-root needs --home-root, so payloads' " +
			"homes are kept off the persistent volume")
	}
	if a.homeRoot != "" && a.cfg.Ephemeral {
		entries, err := os.ReadDir(a.homeRoot)
		if err != nil {
			return fmt.Errorf("agent: --ephemeral: read --home-root %s: %w", a.homeRoot, err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("agent: --ephemeral needs an empty --home-root of its own, which it empties again on "+
				"exit; %s holds %d entries", a.homeRoot, len(entries))
		}
	}
	return nil
}

// within reports whether path is root or lies beneath it.
func within(root, path string) bool { return containedIn(root, path) == nil }

// treesRoot is where workloads' trees live: the workspace root, or the work
// root for an agent with none of its own.
func (a *Agent) treesRoot() string {
	if a.workspaceRoot != "" {
		return a.workspaceRoot
	}
	return a.root
}

// persistentWorkspace reports whether workloads' trees live on a workspace
// root of their own, apart from the agent's scratch.
func (a *Agent) persistentWorkspace() bool { return a.workspaceRoot != "" && a.workspaceRoot != a.root }

// payloadHome is the home directory of a payload whose tree is workDir, and
// the root it must stay beneath; "" when workDir is the workspace root
// itself, which has no directory of its own to name a home after.
func (a *Agent) payloadHome(workDir string) (home, root string) {
	trees := a.treesRoot()
	if a.homeRoot == "" {
		return payloadHomeFor(trees, workDir), trees
	}
	workDir = filepath.Clean(workDir)
	if workDir == filepath.Clean(trees) {
		return "", a.homeRoot
	}
	rel, err := filepath.Rel(trees, workDir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", a.homeRoot
	}
	// One directory per tree, flat: a tree's path beneath the workspace root,
	// its separators replaced, so two trees never share a home.
	name := strings.ReplaceAll(rel, string(os.PathSeparator), "--") + payloadHomeSuffix
	return filepath.Join(a.homeRoot, name), a.homeRoot
}

// withCacheEnv adds the package-manager caches to an explicit environment
// that does not name them itself, creating their directories, and — where
// homes are in memory — the caches that would grow there, as this agent's
// own environment names them (its controller points them at disk scratch). A
// nil environment inherits the agent's.
func (a *Agent) withCacheEnv(env []string) ([]string, error) {
	if env == nil || (a.cacheDir == "" && a.homeRoot == "") {
		return env, nil
	}
	set := map[string]bool{}
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok {
			set[k] = true
		}
	}
	out := append([]string(nil), env...)
	if a.homeRoot != "" {
		for _, k := range executor.ScratchCacheVarNames() {
			if v := strings.TrimSpace(os.Getenv(k)); v != "" && !set[k] && filepath.IsAbs(v) {
				out = append(out, k+"="+v)
			}
		}
	}
	if a.cacheDir == "" {
		return out, nil
	}
	for _, kv := range executor.CacheEnv(a.cacheDir) {
		k, dir, _ := strings.Cut(kv, "=")
		if set[k] {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return env, fmt.Errorf("agent: create the cache directory %s: %w", dir, err)
		}
		out = append(out, kv)
	}
	return out, nil
}

// StorageUsage is how full a runner's workspace volume is, in its retirement
// report: what its controller records on the volume, and reads to tell one
// that is filling from one that is not.
type StorageUsage struct {
	Path          string `json:"path"`
	CapacityBytes int64  `json:"capacity_bytes"`
	FreeBytes     int64  `json:"free_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
}

// storageUsage measures the workspace root's filesystem, nil when the
// workspace is not on one of its own or cannot be measured.
func (a *Agent) storageUsage() *StorageUsage {
	if !a.persistentWorkspace() {
		return nil
	}
	u, err := MeasureFilesystem(a.workspaceRoot)
	if err != nil {
		return nil
	}
	return &u
}

// MeasureFilesystem reports the size and free space of the filesystem dir is
// on: free is what an unprivileged writer may still use.
func MeasureFilesystem(dir string) (StorageUsage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return StorageUsage{}, fmt.Errorf("measure %s: %w", dir, err)
	}
	bsize := int64(st.Bsize)
	capacity := int64(st.Blocks) * bsize
	free := int64(st.Bavail) * bsize
	used := capacity - int64(st.Bfree)*bsize
	if used < 0 {
		used = 0
	}
	return StorageUsage{Path: dir, CapacityBytes: capacity, FreeBytes: free, UsedBytes: used}, nil
}

// secretBase is where a workload's lease directories go: --secret-dir when
// it is set and writable, and otherwise the first tmpfs secretFileBase finds.
func (a *Agent) secretBase() string {
	if a.secretDir != "" {
		probe, err := os.CreateTemp(a.secretDir, ".cloop-probe-")
		if err == nil {
			name := probe.Name()
			_ = probe.Close()
			_ = os.Remove(name)
			return a.secretDir
		}
		a.cfg.logf("warning: --secret-dir %s is not writable (%v); falling back to the usual places", a.secretDir, err)
	}
	return secretFileBase()
}

// wipeEphemeralPrivate empties what an ephemeral runner kept in memory-backed
// directories of its own: every payload home beneath --home-root, and any
// lease directory a failed wipe left in --secret-dir. It returns what it
// could not remove.
func (a *Agent) wipeEphemeralPrivate() []string {
	var problems []string
	if a.homeRoot != "" {
		problems = append(problems, emptyDir(a.homeRoot, nil)...)
	}
	if a.secretDir != "" {
		// Only lease directories: --secret-dir may be a directory others use.
		problems = append(problems, emptyDir(a.secretDir, func(name string) bool {
			return strings.HasPrefix(name, securewipe.LeaseDirPrefix)
		})...)
	}
	return problems
}

// emptyDir removes the entries of dir that keep accepts (all, for nil),
// without following a link out of it.
func emptyDir(dir string, keep func(name string) bool) []string {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("read %s: %v", dir, err)}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if keep == nil || keep(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var problems []string
	for _, name := range names {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			problems = append(problems, fmt.Sprintf("remove %s: %v", filepath.Join(dir, name), err))
		}
	}
	return problems
}
