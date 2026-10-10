//go:build linux

package diskwatch

// The Linux walk works through directory descriptors — openat(2) and
// fstatat(2) relative to the directory being listed — never through a full
// path. A path is bounded by PATH_MAX and a tree's depth is not: a workload
// that nests a few thousand directories makes every path below them fail with
// ENAMETOOLONG, and a walk by path then never measures what is down there.
// Relative to a descriptor, every name is one component.
//
// Holding a descriptor per level would trade that for EMFILE on a tree deep
// enough, so the walk holds at most maxOpen and lets go of the shallowest
// ancestors past that, finding each again through ".." when it climbs back —
// checked against the device and inode it had, so a directory renamed while
// the walk was below it is reported rather than measured in the wrong place.
// That is how fts(3) with FTS_CWDFD walks, and why du(1) has no depth limit.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// dirFlags opens a directory to list it: never through a symlink, and never
// leaked into a child process.
const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// maxOpenCeiling bounds the descriptors one walk holds even when the process
// may hold far more: several workloads can be measured at once.
const maxOpenCeiling = 4096

// errTreeMoved reports a directory that was renamed while the walk was below
// it, found when climbing back through "..".
var errTreeMoved = errors.New("diskwatch: the tree changed while it was measured")

// frame is one directory on the walk's path.
type frame struct {
	// f is nil while the walk has let go of the descriptor; see reopen.
	f        *os.File
	path     string
	dev, ino uint64
	// pending are the subdirectories still to visit.
	pending []string
}

// openLimit is how many directory descriptors this walk may hold.
func (m *walk) openLimit() int {
	if m.maxOpen > 0 {
		return m.maxOpen
	}
	n := maxOpenCeiling
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err == nil && lim.Cur > 0 {
		// An eighth of what the process may hold, leaving the rest to the
		// hub's sockets and databases.
		if share := int(lim.Cur / 8); share < n {
			n = share
		}
	}
	if n < 8 {
		n = 8
	}
	return n
}

// root measures one tree.
func (m *walk) root(r Root) error {
	root := filepath.Clean(r.Path)
	fd, err := unix.Open(root, dirFlags, 0)
	if err != nil {
		if r.Optional && (errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP)) {
			return nil
		}
		return fmt.Errorf("diskwatch: open %s: %w", root, err)
	}
	top := &frame{f: os.NewFile(uintptr(fd), root), path: root}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = top.f.Close()
		return fmt.Errorf("diskwatch: stat %s: %w", root, err)
	}
	top.dev, top.ino = uint64(st.Dev), uint64(st.Ino)
	rootDev := top.dev
	m.raw += int64(st.Blocks) * 512
	m.usage.Entries++

	exclude := make(map[string]bool, len(r.Exclude))
	for _, name := range r.Exclude {
		exclude[name] = true
	}

	stack := []*frame{top}
	defer func() {
		for _, fr := range stack {
			if fr.f != nil {
				_ = fr.f.Close()
			}
		}
	}()
	if err := m.list(top, rootDev, exclude); err != nil {
		return err
	}
	limit := m.openLimit()
	open := 1
	for len(stack) > 0 {
		if err := m.check(); err != nil {
			return err
		}
		cur := stack[len(stack)-1]
		if len(cur.pending) == 0 {
			// Climbing back: the parent has to be open before cur's
			// descriptor goes, because cur's is the way back to it.
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].f == nil {
				if err := reopen(stack[len(stack)-1], cur); err != nil {
					_ = cur.f.Close()
					return err
				}
				open++
			}
			_ = cur.f.Close()
			open--
			continue
		}
		name := cur.pending[len(cur.pending)-1]
		cur.pending = cur.pending[:len(cur.pending)-1]
		path := joinPath(cur.path, name)

		cfd, err := unix.Openat(int(cur.f.Fd()), name, dirFlags, 0)
		if errors.Is(err, unix.EMFILE) && releaseShallowest(stack, &open) {
			cfd, err = unix.Openat(int(cur.f.Fd()), name, dirFlags, 0)
		}
		if err != nil {
			switch {
			case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP):
				// Removed, or replaced by something that is not a
				// directory, since it was listed: nothing to descend into.
				continue
			case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
				_ = m.unlistable(path, err)
				continue
			default:
				return fmt.Errorf("diskwatch: open %s: %w", path, err)
			}
		}
		child := &frame{f: os.NewFile(uintptr(cfd), path), path: path}
		var cst unix.Stat_t
		if err := unix.Fstat(cfd, &cst); err != nil {
			_ = child.f.Close()
			return fmt.Errorf("diskwatch: stat %s: %w", path, err)
		}
		child.dev, child.ino = uint64(cst.Dev), uint64(cst.Ino)
		stack = append(stack, child)
		open++
		// Over the limit, let go of ancestors until it is met; they are
		// found again through ".." on the way back up.
		for open > limit {
			if !releaseShallowest(stack, &open) {
				break
			}
		}
		// The child's own blocks were counted when its parent listed it.
		if err := m.list(child, rootDev, nil); err != nil {
			return err
		}
	}
	return nil
}

// list counts one directory's entries and queues its subdirectories.
// exclude applies to the root's own entries only.
func (m *walk) list(fr *frame, rootDev uint64, exclude map[string]bool) error {
	dirfd := int(fr.f.Fd())
	for {
		names, readErr := fr.f.Readdirnames(readBatch)
		for _, name := range names {
			if err := m.tick(); err != nil {
				return err
			}
			if exclude[name] {
				continue
			}
			var st unix.Stat_t
			if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					// Removed between the listing and the stat: the tree is
					// being written, which is the expected case.
					continue
				}
				// Listable but not searchable: the names are readable and
				// the entries are not, so the rest of the directory is as
				// unmeasured as one that cannot be listed at all.
				return m.unlistable(fr.path, err)
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				if m.isMount(joinPath(fr.path, name), uint64(st.Dev), rootDev) {
					m.usage.MountsSkipped++
					continue
				}
				m.raw += int64(st.Blocks) * 512
				fr.pending = append(fr.pending, name)
				continue
			}
			m.file(int64(st.Blocks)*512, uint64(st.Dev), uint64(st.Ino), uint64(st.Nlink))
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return m.unlistable(fr.path, readErr)
		}
	}
}

// releaseShallowest lets go of the descriptor of the shallowest open frame
// other than the deepest, which the walk is using. It reports whether there
// was one.
func releaseShallowest(stack []*frame, open *int) bool {
	for i := 0; i < len(stack)-1; i++ {
		if stack[i].f != nil {
			_ = stack[i].f.Close()
			stack[i].f = nil
			*open--
			return true
		}
	}
	return false
}

// reopen finds parent again through child's "..", and refuses a directory
// that is not the one the walk left: something renamed it, or moved child,
// while the walk was below.
func reopen(parent, child *frame) error {
	fd, err := unix.Openat(int(child.f.Fd()), "..", dirFlags, 0)
	if err != nil {
		return fmt.Errorf("diskwatch: climb back to %s: %w", parent.path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("diskwatch: climb back to %s: %w", parent.path, err)
	}
	if uint64(st.Dev) != parent.dev || uint64(st.Ino) != parent.ino {
		_ = unix.Close(fd)
		return fmt.Errorf("%w: %s", errTreeMoved, parent.path)
	}
	parent.f = os.NewFile(uintptr(fd), parent.path)
	return nil
}
