package kubecontroller

// storageprep.go: what a runner volume's init container does before the
// runner starts (Task 20484) — `cloop executor runner-storage`, run as the
// runner's own user, with the volume mounted and nothing else.
//
//  1. When the controller asked for it — the volume last held another
//     project's data, or whose it held is unknown — it empties the volume:
//     every entry at its root but lost+found, which the filesystem owns. A
//     removal that fails fails the step, and the runner never starts on a
//     volume that still holds what it was meant not to see.
//  2. It keeps the subdirectories the pool's mounts name — workspace, git,
//     tools — creating any missing and removing those no longer named.
//  3. It holds the volume to the free-space floor: under it, the caches are
//     cleared first, then the workspace; a volume still under the floor once
//     empty is reported full and the step fails, so the runner does not start
//     on a disk its run would fill.
//  4. It writes what it did and how full the volume is as one line of JSON to
//     the termination log, which the controller reads from the Pod's status.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// storageInitContainer is the name of the init container.
const storageInitContainer = "prepare-storage"

// lostFound is the directory a filesystem keeps at its root, owned by root:
// not the runner's to remove.
const lostFound = "lost+found"

// PrepareOptions are what the init container is given.
type PrepareOptions struct {
	// Root is where the volume is mounted.
	Root string
	// Dirs are the subdirectories to keep: workspace, git, tools.
	Dirs []string
	// Wipe empties the volume first.
	Wipe bool
	// MinFree is the free space, in bytes, the runner must start with.
	MinFree int64
	// Measure reports the filesystem's capacity and free bytes; nil is
	// statfs. A test seam.
	Measure func(dir string) (capacity, free int64, err error)
}

// PrepareReport is what the init container says, on its termination log.
type PrepareReport struct {
	// Wiped says the volume was emptied; WipeReason why — "asked" by the
	// controller, or "full".
	Wiped      bool   `json:"wiped"`
	WipeReason string `json:"wipe_reason,omitempty"`
	// Cleared lists what was cleared to get above the floor.
	Cleared []string `json:"cleared,omitempty"`
	// Full says the volume is under the floor even empty.
	Full          bool   `json:"full,omitempty"`
	CapacityBytes int64  `json:"capacity_bytes"`
	FreeBytes     int64  `json:"free_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	Error         string `json:"error,omitempty"`
}

// knownDirs are the subdirectories a runner volume may hold.
var knownDirs = map[string]bool{"workspace": true, "git": true, "tools": true}

// PrepareStorage readies a runner volume. The report is meaningful even with
// an error, which is the report's Error too.
func PrepareStorage(o PrepareOptions) (PrepareReport, error) {
	var rep PrepareReport
	fail := func(err error) (PrepareReport, error) {
		rep.Error = err.Error()
		return rep, err
	}
	measure := o.Measure
	if measure == nil {
		measure = statfs
	}
	root := filepath.Clean(strings.TrimSpace(o.Root))
	if root == "" || root == "." || !filepath.IsAbs(root) {
		return fail(fmt.Errorf("the volume's root %q is not an absolute path", o.Root))
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fail(fmt.Errorf("the volume's root: %w", err))
	}
	if !info.IsDir() {
		return fail(fmt.Errorf("the volume's root %s is not a directory", root))
	}
	keep := map[string]bool{}
	for _, d := range o.Dirs {
		if !knownDirs[d] {
			return fail(fmt.Errorf("%q is not a runner volume's directory (workspace, git, tools)", d))
		}
		keep[d] = true
	}
	if o.Wipe {
		if err := emptyVolume(root, true); err != nil {
			return fail(fmt.Errorf("could not empty the volume: %w", err))
		}
		rep.Wiped, rep.WipeReason = true, "asked"
	}
	// Directories no mount names any more go: the workspace with the git
	// cache it may have taken objects from never depends on it, so either
	// may go alone.
	for d := range knownDirs {
		if !keep[d] {
			if err := os.RemoveAll(filepath.Join(root, d)); err != nil {
				return fail(fmt.Errorf("could not remove %s, which no mount names: %w", d, err))
			}
		}
	}
	if err := makeDirs(root, keep); err != nil {
		return fail(err)
	}
	if keep["workspace"] {
		// What the last run left at the top of its own tree that would keep
		// the next run from starting on it — a link where a project's tree
		// was, a file or a pipe, a directory it made unreadable — is put
		// right here, where nothing has trusted it yet.
		if err := repairTrees(filepath.Join(root, "workspace")); err != nil {
			return fail(err)
		}
	}
	fill := func() error {
		capacity, free, err := measure(root)
		if err != nil {
			return err
		}
		rep.CapacityBytes, rep.FreeBytes, rep.UsedBytes = capacity, free, max(0, capacity-free)
		return nil
	}
	if err := fill(); err != nil {
		return fail(fmt.Errorf("could not measure the volume: %w", err))
	}
	if o.MinFree <= 0 || rep.FreeBytes >= o.MinFree {
		return rep, nil
	}
	// Under the floor: the caches go first, then everything.
	for _, d := range []string{"tools", "git"} {
		if !keep[d] {
			continue
		}
		if err := emptyVolume(filepath.Join(root, d), false); err != nil {
			return fail(fmt.Errorf("could not clear %s to make room: %w", d, err))
		}
		rep.Cleared = append(rep.Cleared, d)
	}
	if err := fill(); err != nil {
		return fail(fmt.Errorf("could not measure the volume: %w", err))
	}
	if rep.FreeBytes >= o.MinFree {
		return rep, nil
	}
	if !rep.Wiped {
		if err := emptyVolume(root, true); err != nil {
			return fail(fmt.Errorf("could not empty the volume to make room: %w", err))
		}
		rep.Wiped, rep.WipeReason = true, "full"
		if err := makeDirs(root, keep); err != nil {
			return fail(err)
		}
		if err := fill(); err != nil {
			return fail(fmt.Errorf("could not measure the volume: %w", err))
		}
		if rep.FreeBytes >= o.MinFree {
			return rep, nil
		}
	}
	rep.Full = true
	return fail(fmt.Errorf("the volume has %s free of %s with nothing on it, under the %s a runner starts with",
		humanBytes(rep.FreeBytes), humanBytes(rep.CapacityBytes), humanBytes(o.MinFree)))
}

// emptyVolume removes every entry of dir. At a volume's root (atRoot) the
// filesystem's lost+found stays, emptied: with fsGroup the runner may write
// there, so it is not a place anything survives a wipe in. RemoveAll removes
// a link it meets, never what the link points at.
func emptyVolume(dir string, atRoot bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	var errs []error
	for _, e := range entries {
		if atRoot && e.Name() == lostFound && e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			if err := emptyVolume(filepath.Join(dir, lostFound), false); err != nil {
				errs = append(errs, fmt.Errorf("empty %s: %w", lostFound, err))
			}
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		p := filepath.Join(dir, name)
		if err := os.RemoveAll(p); err != nil {
			// A directory the run made read-only is still the run's: make it
			// writable and try once more.
			_ = filepath.Walk(p, func(q string, fi os.FileInfo, err error) error {
				if err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
					_ = os.Chmod(q, 0o700)
				}
				return nil
			})
			if err := os.RemoveAll(p); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// makeDirs creates the kept subdirectories, 0700: one that is not a
// directory of its own — a link, a file — is replaced, and one a run made
// unusable is made usable again.
func makeDirs(root string, keep map[string]bool) error {
	for d := range keep {
		p := filepath.Join(root, d)
		if fi, err := os.Lstat(p); err == nil && !fi.IsDir() {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("%s is not a directory and cannot be replaced: %w", p, err)
			}
		}
		if err := os.MkdirAll(p, 0o700); err != nil {
			return fmt.Errorf("could not create %s: %w", p, err)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return fmt.Errorf("could not make %s usable: %w", p, err)
		}
	}
	return nil
}

// repairTrees puts right the top of each tree in a kept workspace: an entry
// that is not a directory — a link, a file, a pipe — goes, as does a tree's
// .cloop or .git that is a link; a directory is made the runner's to use.
func repairTrees(workspace string) error {
	entries, err := os.ReadDir(workspace)
	if err != nil {
		return fmt.Errorf("read the workspace: %w", err)
	}
	for _, e := range entries {
		p := filepath.Join(workspace, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if !fi.IsDir() {
			if err := os.RemoveAll(p); err != nil {
				return fmt.Errorf("remove %s, which is not a tree: %w", p, err)
			}
			continue
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return fmt.Errorf("make %s usable: %w", p, err)
		}
		for _, inner := range []string{".cloop", ".git"} {
			q := filepath.Join(p, inner)
			if ifi, err := os.Lstat(q); err == nil && ifi.Mode()&os.ModeSymlink != 0 {
				if err := os.Remove(q); err != nil {
					return fmt.Errorf("remove %s, a link: %w", q, err)
				}
			}
		}
	}
	return nil
}

// statfs reports the filesystem's capacity and what an unprivileged writer
// may still use.
func statfs(dir string) (int64, int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bs := int64(st.Bsize)
	return int64(st.Blocks) * bs, int64(st.Bavail) * bs, nil
}

// WriteReport writes rep to path as one line of JSON; "" writes nowhere.
func (rep PrepareReport) WriteReport(path string) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
