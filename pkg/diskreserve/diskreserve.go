// Package diskreserve holds back a little of a project's disk for the writes
// that record what a run did (Task 20381).
//
// A run learns its disk is full when a write fails. The orchestrator checks
// free space before every task attempt (orchestrator.min_free_disk_mb), but a
// check is a prediction: a task's own build, a neighbour's test run filling
// /tmp, or another project on the same volume can take the last megabyte
// between the check and the moment the task's outcome is stored. The write
// that fails then is the worst one to lose — the verdict sidecar and the
// outcome row are what stale-task recovery reads, and with both gone it falls
// back to the agent's own TASK_DONE (pkg/taskrecover).
//
// So each project keeps .cloop/reserve: Size bytes of preallocated blocks
// that nothing reads. When one of those critical writes fails for want of
// space, the orchestrator deletes the reserve and tries the write again. The
// space it frees is on the volume that refused the write, because the reserve
// lives in the same .cloop directory as state.db and the verdicts. Then the
// run pauses until there is room again, and the next check that passes puts
// the reserve back.
//
// The file is blocks, not a sparse length: Ensure allocates it with
// fallocate(2) where the filesystem supports it and otherwise writes it out,
// with random bytes so that a compressing or deduplicating filesystem cannot
// store it as nothing. A reserve that held no blocks would free nothing.
//
// It is not data. Snapshots skip it and restores leave it alone, `cloop
// compact` and the janitor never touch it, and pkg/diskusage does not count
// it — 16 MiB of placeholder in every snapshot, or reported as part of what
// .cloop costs, would be noise in exactly the tools an operator reads when the
// disk is full.
//
// The package depends on the standard library alone, so every walker of
// .cloop can name the file without importing anything heavier.
package diskreserve

import (
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// Name is the reserve's file name inside a project's .cloop directory.
	Name = "reserve"

	// Size is how much the reserve holds back: 16 MiB. Enough for a verdict
	// sidecar (a few KiB), the state write of one task's outcome and a WAL
	// checkpoint of a busy state.db, with a wide margin; small enough that no
	// operator misses it on a volume worth running a hub on.
	Size int64 = 16 << 20

	// roomFactor is how much free space Ensure wants before it creates the
	// reserve: twice its size. Creating it on a volume with less would take
	// the space the reserve exists to keep for other writes.
	roomFactor = 2
)

// ErrNoRoom reports that the reserve could not be created because its volume
// does not have room for it. Not a fault: the next check that finds space
// creates it.
var ErrNoRoom = errors.New("diskreserve: not enough free space to create the reserve")

// Path returns the reserve's path for the project rooted at workDir.
func Path(workDir string) string {
	return filepath.Join(workDir, ".cloop", Name)
}

// IsName reports whether a top-level entry of a .cloop directory is the
// reserve. Walkers that enumerate .cloop use it to leave the file out.
func IsName(name string) bool {
	return name == Name
}

// freeBytes is the free space this process can write on the filesystem
// holding path. A variable so tests can simulate a full volume without
// filling one.
var freeBytes = func(path string) (int64, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return 0, err
	}
	// Bfree for root, Bavail otherwise: the same reading pkg/diskusage's
	// FreeBytes takes, for the same reason — root may write into the blocks
	// reserved for it, and a reading that ignored them would refuse a reserve
	// on a disk with gigabytes left.
	blocks := fs.Bavail
	if os.Geteuid() == 0 {
		blocks = fs.Bfree
	}
	return int64(blocks) * int64(uint64(fs.Bsize)), nil //nolint:gosec,unconvert // Bsize is int64 on Linux, uint32 on Darwin
}

// allocate gives f size bytes of real blocks. A variable so tests can make
// allocation fail the way a full disk does.
var allocate = allocateFile

// Held returns how many bytes the reserve currently holds on disk: its
// allocated blocks, which is what deleting it frees. Zero when it is absent.
func Held(workDir string) int64 {
	fi, err := os.Stat(Path(workDir))
	if err != nil || !fi.Mode().IsRegular() {
		return 0
	}
	return allocatedBytes(fi)
}

// Ensure makes sure the project's reserve exists and holds Size bytes of
// allocated blocks. It reports whether it created (or re-created) the file.
//
// An existing reserve of the right size is left alone, so calling this before
// every task attempt costs a stat. One that is short — a crash between create
// and rename cannot leave one, but a hand-made file can — is replaced.
//
// The file is built under a temporary name and renamed into place, so a disk
// that fills while it is written never leaves a half-sized reserve that
// claims to be whole; the temporary is removed. A volume with less than twice
// Size free is not asked for it: ErrNoRoom, and nothing is written.
func Ensure(workDir string) (created bool, err error) {
	dir := filepath.Join(workDir, ".cloop")
	path := Path(workDir)
	if fi, statErr := os.Stat(path); statErr == nil {
		if fi.Mode().IsRegular() && fi.Size() == Size && allocatedBytes(fi) >= Size {
			return false, nil
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("diskreserve: stat %s: %w", path, statErr)
	}

	free, err := freeBytes(dir)
	if err != nil {
		return false, fmt.Errorf("diskreserve: measure free space in %s: %w", dir, err)
	}
	if free < roomFactor*Size {
		return false, fmt.Errorf("%w: %s has %d bytes free, the reserve wants %d", ErrNoRoom, dir, free, roomFactor*Size)
	}

	f, err := os.CreateTemp(dir, "."+Name+".*.tmp")
	if err != nil {
		if IsDiskFull(err) {
			return false, fmt.Errorf("%w: %v", ErrNoRoom, err)
		}
		return false, fmt.Errorf("diskreserve: create in %s: %w", dir, err)
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := allocate(f, Size); err != nil {
		if IsDiskFull(err) {
			return false, fmt.Errorf("%w: %v", ErrNoRoom, err)
		}
		return false, fmt.Errorf("diskreserve: allocate %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return false, fmt.Errorf("diskreserve: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("diskreserve: close %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return false, fmt.Errorf("diskreserve: chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, fmt.Errorf("diskreserve: rename %s: %w", tmp, err)
	}
	keep = true
	return true, nil
}

// Release deletes the project's reserve and returns the bytes it held, so a
// write that just failed for want of space can be tried again. Releasing a
// reserve that is not there frees nothing and is not an error: two writes
// that fail in the same moment both release, and the second finds it gone.
func Release(workDir string) (freed int64, err error) {
	path := Path(workDir)
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("diskreserve: stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		// Somebody else's directory or device under our name. Removing it is
		// not ours to do, and it holds no space we could count on.
		return 0, fmt.Errorf("diskreserve: %s is not a regular file", path)
	}
	held := allocatedBytes(fi)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("diskreserve: remove %s: %w", path, err)
	}
	return held, nil
}

// IsDiskFull reports whether err says a write ran out of room: ENOSPC from the
// kernel, a disk quota, or SQLite's SQLITE_FULL ("database or disk is full"),
// which is how a state.db write reports the same condition.
//
// The message is checked as well as the error chain because several layers
// between a write and its caller wrap with %v, and losing the errno there must
// not turn a full disk into an unexplained write failure.
func IsDiskFull(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no space left on device") ||
		strings.Contains(msg, "database or disk is full") ||
		strings.Contains(msg, "disk quota exceeded")
}

// allocatedBytes is the space a file's blocks occupy, which can differ from
// its length both ways: a sparse file holds less, and a filesystem's block
// rounding a little more.
func allocatedBytes(fi os.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
		return int64(st.Blocks) * 512 //nolint:unconvert // Blocks is int64 on Linux and Darwin alike
	}
	return 0
}

// writeOut fills f with size bytes of pseudo-random data — the fallback where
// a filesystem cannot preallocate. Random rather than zeros because a
// compressing or deduplicating filesystem stores a run of zeros as nothing,
// and a reserve that holds nothing frees nothing. Not cryptographic: nothing
// reads it.
func writeOut(f *os.File, size int64) error {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(mrand.Uint32())
	}
	src := mrand.NewChaCha8(seed)
	buf := make([]byte, 1<<20)
	for written := int64(0); written < size; {
		n := int64(len(buf))
		if size-written < n {
			n = size - written
		}
		if _, err := src.Read(buf[:n]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		written += n
	}
	return nil
}
