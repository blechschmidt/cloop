// Package diskwatch measures a sandbox's workspace and holds a running
// workload to its disk limit by sampling it (Task 20405).
//
// The container driver's sandbox writes in a few places. The image's root
// filesystem is mounted read-only and /tmp is a size-capped tmpfs; the
// workspace — the project directory bind-mounted at /workspace, or a feature's
// staged checkout and its output directory — is the host's own disk, and is
// where the work goes. --storage-opt size= bounds the container's writable
// layer, which is not that, so the only way to bound the workspace on a host
// filesystem with no project quota is to measure it.
//
// That makes this enforcement by measurement, not a quota, and the difference
// is the overshoot: a workload writing fast enough fills the write rate times
// the sampling interval past the limit before the next sample sees it. The
// free-space floor (orchestrator.min_free_disk_mb, Task 20381) is what stands
// between that burst and a full volume.
//
// # What a measurement counts
//
// Allocated size, the way du(1) counts it: st_blocks for every entry, so a
// sparse file costs what it occupies rather than what it claims. A file with
// several hard links is counted once. Symlinks are counted as themselves and
// never followed. Mount points below a root are neither counted nor crossed —
// whatever is mounted there is not the workspace's to spend — and a mount
// point is what the mount table lists, not any directory with a device number
// of its own: a btrfs subvolume has one, and any user can make one. A root may
// name entries directly beneath it to leave out, and may carry an allowance: a
// project's own .cloop/ is measured as a root of its own whose size at the
// start is the hub's bookkeeping, so only what the run adds to it counts.
//
// On Linux the walk goes through directory descriptors, so no depth of nesting
// puts part of a tree out of its reach; see walk_linux.go.
//
// # What a measurement costs
//
// A walk is one goroutine per workload at a time — the Watchdog never overlaps
// two — run by LowPriority on a thread of its own at the lowest CPU priority
// and in the idle I/O class, and bounded by a deadline. A walk that misses its
// deadline is reported as unknown, never as under the limit: its count is a
// lower bound, which settles "over" when it is already over and nothing else.
package diskwatch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

// ErrDeadline reports a walk that did not finish within its deadline. The
// Usage returned beside it is a lower bound.
var ErrDeadline = errors.New("diskwatch: the walk did not finish within its deadline")

// ErrIncomplete reports a walk that could not list every directory under its
// roots — one the walker may not read. The Usage returned beside it is a
// lower bound.
var ErrIncomplete = errors.New("diskwatch: part of the tree could not be read")

// checkEvery is how many entries the walk visits between looks at its
// deadline and its context. Small enough that a slow filesystem cannot carry a
// walk far past its deadline, large enough that the clock is not read per file.
const checkEvery = 128

// readBatch bounds one getdents read, so a directory holding a million entries
// is listed in pieces the deadline can interrupt rather than in one allocation.
const readBatch = 1024

// maxUnreadable bounds how many unreadable directories a Usage names.
const maxUnreadable = 3

// Clock is the walker's source of time. Tests inject one that advances on
// every read, which is how a deadline is exercised without a slow filesystem.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Root is one tree to measure.
type Root struct {
	// Path is the directory measured. It is not resolved: a symlink here is a
	// symlink, and is measured as one.
	Path string
	// Exclude names entries directly under Path that are not counted, such as
	// ".cloop". Deeper entries with the same name are counted: a fixture
	// directory called .cloop inside the workload's tree is the workload's.
	Exclude []string
	// Allowance is how many bytes of this root go uncounted. A tree whose
	// size at the start is not the workload's — a project's own .cloop/ —
	// counts only what it grows by; math.MaxInt64 counts none of it. Its own
	// size is still reported, in Usage.RootBytes.
	Allowance int64
	// Optional makes a root that does not exist, or is not a directory,
	// measure as empty rather than fail the measurement.
	Optional bool
}

// Usage is one measurement.
type Usage struct {
	// Bytes is what counts against a limit: each root's allocated size beyond
	// its Allowance, summed.
	Bytes int64
	// RootBytes is each root's own allocated size, before any allowance, in
	// the order the roots were given. A walk that stopped early leaves the
	// roots it never reached at zero.
	RootBytes []int64
	// Entries is how many directory entries the walk visited.
	Entries int
	// Elapsed is how long the walk took, by the walker's clock.
	Elapsed time.Duration
	// MountsSkipped counts the mount points below a root that were left out.
	MountsSkipped int
	// Unreadable counts directories whose contents could not be listed, and
	// UnreadablePaths names the first few.
	Unreadable      int
	UnreadablePaths []string
}

// Walker measures trees. The zero value is usable: a real clock, no deadline,
// and the host's own mount table.
type Walker struct {
	// Clock reads the time for the deadline; nil means the real clock.
	Clock Clock
	// Deadline bounds one Measure call; 0 means none.
	Deadline time.Duration
	// MountPoints returns the mount points below the given roots, keyed by
	// cleaned absolute path, and whether the mount table could be read at
	// all. Nil reads the process's own table, /proc/self/mountinfo on Linux;
	// tests inject theirs, because creating a mount needs a privilege CI does
	// not have.
	//
	// A readable table is the whole answer: a directory is a mount point
	// when the table lists it, whatever its st_dev. A device check would
	// skip every btrfs subvolume — each has a device number of its own, and
	// any user may create one in a directory they can write — so a workload
	// could put its data where no walk counts it. Only when the table cannot
	// be read does a change of device stand in for it.
	MountPoints func(roots []string) (map[string]bool, bool)

	// maxOpen bounds the directory descriptors a walk holds at once; zero
	// derives it from the process's file limit. A field so tests can force
	// the walk to let go of ancestors and find them again.
	maxOpen int
}

// Measure walks every root and returns their combined allocated size. A hard
// link shared between two roots is still counted once.
//
// A non-nil error means the count is incomplete and therefore a lower bound:
// ErrDeadline, ErrIncomplete, ctx's error, or the reason a root could not be
// opened. The Usage is returned with every error, because a lower bound that is
// already over a limit settles the question it was taken to answer.
func (w Walker) Measure(ctx context.Context, roots ...Root) (Usage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	clock := w.Clock
	if clock == nil {
		clock = realClock{}
	}
	start := clock.Now()
	m := &walk{
		ctx:     ctx,
		clock:   clock,
		seen:    make(map[fileID]struct{}),
		maxOpen: w.maxOpen,
	}
	if w.Deadline > 0 {
		m.deadline = start.Add(w.Deadline)
	}
	paths := make([]string, 0, len(roots))
	for _, r := range roots {
		paths = append(paths, filepath.Clean(r.Path))
	}
	if w.MountPoints != nil {
		m.mounts, m.mountsKnown = w.MountPoints(paths)
	} else {
		m.mounts, m.mountsKnown = mountPointsUnder(paths)
	}

	m.usage.RootBytes = make([]int64, len(roots))
	var err error
	for i, r := range roots {
		before := m.raw
		err = m.root(r)
		own := m.raw - before
		m.usage.RootBytes[i] = own
		if counted := own - r.Allowance; r.Allowance >= 0 && counted > 0 {
			m.usage.Bytes += counted
		} else if r.Allowance < 0 {
			m.usage.Bytes += own
		}
		if err != nil {
			break
		}
	}
	m.usage.Elapsed = clock.Now().Sub(start)
	if err == nil && m.usage.Unreadable > 0 {
		err = fmt.Errorf("%w: %d director%s could not be listed (%s)", ErrIncomplete,
			m.usage.Unreadable, plural(m.usage.Unreadable, "y", "ies"), m.usage.UnreadablePaths[0])
	}
	return m.usage, err
}

// fileID identifies an inode, for counting a hard-linked file once.
type fileID struct {
	dev uint64
	ino uint64
}

// walk is one Measure call's state.
type walk struct {
	ctx         context.Context
	clock       Clock
	deadline    time.Time
	mounts      map[string]bool
	mountsKnown bool
	seen        map[fileID]struct{}
	maxOpen     int
	// raw is every byte counted so far, before allowances.
	raw   int64
	usage Usage
}

// tick counts one entry and, every checkEvery, checks the deadline and the
// context.
func (m *walk) tick() error {
	m.usage.Entries++
	if m.usage.Entries%checkEvery != 0 {
		return nil
	}
	return m.check()
}

func (m *walk) check() error {
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if !m.deadline.IsZero() && m.clock.Now().After(m.deadline) {
		return ErrDeadline
	}
	return nil
}

// isMount reports whether the directory at path, whose device is dev, is a
// mount point below a root on rootDev. See Walker.MountPoints for why the
// table, when there is one, decides alone.
func (m *walk) isMount(path string, dev, rootDev uint64) bool {
	if m.mountsKnown {
		return m.mounts[path]
	}
	return dev != rootDev
}

// file counts one non-directory entry, a hard-linked one once.
func (m *walk) file(bytes int64, dev, ino, nlink uint64) {
	if nlink > 1 {
		id := fileID{dev: dev, ino: ino}
		if _, dup := m.seen[id]; dup {
			return
		}
		m.seen[id] = struct{}{}
	}
	m.raw += bytes
}

// unlistable records a directory whose contents could not be read. A directory
// removed while the walk ran is not one: it no longer holds anything.
func (m *walk) unlistable(dir string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if errors.Is(err, fs.ErrPermission) {
		m.usage.Unreadable++
		if len(m.usage.UnreadablePaths) < maxUnreadable {
			m.usage.UnreadablePaths = append(m.usage.UnreadablePaths, dir)
		}
		return nil
	}
	return fmt.Errorf("diskwatch: %w", err)
}

// joinPath appends one entry name to a directory path. Names come from the
// directory itself, so they are single components and need no cleaning.
func joinPath(dir, name string) string {
	if dir == string(filepath.Separator) {
		return dir + name
	}
	return dir + string(filepath.Separator) + name
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
