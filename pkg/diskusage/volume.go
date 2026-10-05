package diskusage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Volume is one filesystem that a set of paths lives on, and the space this
// process could still write there (Task 20381).
type Volume struct {
	// Mount names the volume the way an operator does: the directory it is
	// mounted on, as far as walking up from Path can tell — the highest
	// ancestor still on the same device. "/" on a single-disk host.
	Mount string `json:"mount"`
	// Path is the first of the probed paths that lives on this volume, as
	// given (before symlinks were resolved).
	Path string `json:"path"`
	// Device is the st_dev the volume was told apart by.
	Device uint64 `json:"device"`
	// FreeBytes is what this process could write there; see FreeBytes for
	// why that depends on whether it runs as root.
	FreeBytes int64 `json:"free_bytes"`
}

// Volumes resolves each path to the filesystem holding it and returns one
// Volume per distinct device, in the order the paths first name them.
//
// It exists because the question "is there room to run" is per filesystem,
// not per path: a project's .cloop and its working tree are normally one
// volume and measuring it twice would print the same warning twice, but .cloop
// can be a symlink onto another disk, and then both have to be watched.
// Symlinks are followed, so a path counts against the volume its data lands
// on.
//
// A path that does not exist yet is measured at its nearest existing ancestor
// — that is where it will be created. An empty path is skipped. An error comes
// back only when a path's volume cannot be determined at all.
func Volumes(paths ...string) ([]Volume, error) {
	var out []Volume
	seen := map[uint64]bool{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		at, fi, err := nearestExisting(p)
		if err != nil {
			return out, err
		}
		dev, ok := deviceOf(fi)
		if !ok {
			return out, fmt.Errorf("diskusage: %s: no device id", at)
		}
		if seen[dev] {
			continue
		}
		seen[dev] = true
		free, err := FreeBytes(at)
		if err != nil {
			return out, err
		}
		out = append(out, Volume{Mount: mountOf(at, dev), Path: p, Device: dev, FreeBytes: free})
	}
	return out, nil
}

// nearestExisting returns the closest existing ancestor of p (p itself when it
// exists), with symlinks resolved, and its FileInfo.
func nearestExisting(p string) (string, os.FileInfo, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", nil, fmt.Errorf("diskusage: %s: %w", p, err)
	}
	for cur := abs; ; {
		fi, err := os.Stat(cur)
		if err == nil {
			if real, rerr := filepath.EvalSymlinks(cur); rerr == nil {
				cur = real
			}
			return cur, fi, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", nil, fmt.Errorf("diskusage: stat %s: %w", cur, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", nil, fmt.Errorf("diskusage: no existing ancestor of %s", p)
		}
		cur = parent
	}
}

// mountOf walks up from dir while the device stays the same, and returns the
// highest directory on it. An ancestor that cannot be read ends the walk: the
// name is for people, and the deepest certain answer beats a guess.
func mountOf(dir string, dev uint64) string {
	cur := dir
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return cur
		}
		fi, err := os.Stat(parent)
		if err != nil {
			return cur
		}
		if pd, ok := deviceOf(fi); !ok || pd != dev {
			return cur
		}
		cur = parent
	}
}

// deviceOf returns the st_dev of a stat result.
func deviceOf(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	// Dev is uint64 on Linux and int32 on Darwin; as an identifier either
	// converts losslessly enough to compare.
	return uint64(st.Dev), true //nolint:gosec,unconvert // see comment
}
