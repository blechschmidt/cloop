//go:build linux

package diskwatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMeasureDoesNotCrossARealMount(t *testing.T) {
	// The injected table covers the boundary logic everywhere; this is the
	// same boundary against the kernel's own table, where mounting is
	// possible: a tmpfs, another filesystem, and a bind mount of the same one,
	// which shares its device and which only the table can name.
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "kept"), 64<<10)
	tmpfs := filepath.Join(root, "tmpfs")
	bind := filepath.Join(root, "bind")
	for _, d := range []string{tmpfs, bind} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	base := measure(t, Walker{}, Root{Path: root})
	// What the two mount points cost as plain directories, before anything
	// is mounted on them.
	mountDirs := allocated(t, tmpfs) + allocated(t, bind)

	if err := syscall.Mount("tmpfs", tmpfs, "tmpfs", 0, "size=4m"); err != nil {
		t.Skipf("cannot mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(tmpfs, syscall.MNT_DETACH) })
	writeFile(t, filepath.Join(tmpfs, "foreign"), 1<<20)

	src := t.TempDir()
	writeFile(t, filepath.Join(src, "foreign"), 1<<20)
	if err := syscall.Mount(src, bind, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("cannot bind-mount here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(bind, syscall.MNT_DETACH) })
	if statOf(mustLstat(t, bind)).dev != statOf(mustLstat(t, root)).dev {
		t.Skip("the bind mount reports another device, so it would not test the mount table")
	}

	u := measure(t, Walker{}, Root{Path: root})
	// Both mount points are left out whole — the directory the mount covers
	// as well as what is mounted on it.
	if want := base.Bytes - mountDirs; u.Bytes != want {
		t.Fatalf("Bytes = %d, want %d: a mount was crossed or counted", u.Bytes, want)
	}
	if u.MountsSkipped != 2 {
		t.Fatalf("MountsSkipped = %d, want 2, both from the mount table", u.MountsSkipped)
	}
}

func mustLstat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// mountTmpfs mounts a small tmpfs at dir for the test, or skips it.
func mountTmpfs(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=4m"); err != nil {
		t.Skipf("cannot mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(dir, syscall.MNT_DETACH) })
}

// TestMeasureCountsADirectoryOnAnotherDeviceThatIsNotAMount is the btrfs case:
// a subvolume has a device number of its own, any user may create one, and it
// is not a mount. A walk that skipped every change of device would leave what a
// workload put there uncounted. The tmpfs stands in for the subvolume — another
// device — and the injected table, readable and not listing it, says it is not
// mounted.
func TestMeasureCountsADirectoryOnAnotherDeviceThatIsNotAMount(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "subvol")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	mountTmpfs(t, sub)
	writeFile(t, filepath.Join(sub, "hidden"), 1<<20)

	readable := Walker{MountPoints: func([]string) (map[string]bool, bool) { return map[string]bool{}, true }}
	u := measure(t, readable, Root{Path: root})
	if u.MountsSkipped != 0 || u.Bytes < 1<<20 {
		t.Fatalf("Bytes = %d, MountsSkipped = %d: a directory with its own device number was skipped "+
			"though the mount table does not list it", u.Bytes, u.MountsSkipped)
	}

	// With no table to read, a change of device is the best evidence left.
	unreadable := Walker{MountPoints: func([]string) (map[string]bool, bool) { return nil, false }}
	u = measure(t, unreadable, Root{Path: root})
	if u.MountsSkipped != 1 || u.Bytes >= 1<<20 {
		t.Fatalf("Bytes = %d, MountsSkipped = %d: with no mount table the device change must stand in",
			u.Bytes, u.MountsSkipped)
	}
}

// deepChain nests depth directories called "a" below root — too deep to name
// by path — and writes size bytes in a file at the bottom. Built through
// descriptors, because the paths it makes cannot be passed to mkdir(2).
func deepChain(t *testing.T, root string, depth, size int) {
	t.Helper()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < depth; i++ {
		if err := unix.Mkdirat(fd, "a", 0o755); err != nil {
			unix.Close(fd)
			t.Fatalf("mkdirat at depth %d: %v", i, err)
		}
		next, err := unix.Openat(fd, "a", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			t.Fatalf("openat at depth %d: %v", i, err)
		}
		fd = next
	}
	defer unix.Close(fd)
	ffd, err := unix.Openat(fd, "bottom", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ffd)
	if _, err := unix.Write(ffd, []byte(strings.Repeat("z", size))); err != nil {
		t.Fatal(err)
	}
}

// TestMeasureReachesBelowPATH_MAX: nesting a few thousand directories puts
// everything below them out of reach of any path — open(2) fails with
// ENAMETOOLONG — and a walk by path would report every sample unknown, which
// never stops a workload. Through descriptors every name is one component.
func TestMeasureReachesBelowPATH_MAX(t *testing.T) {
	root := t.TempDir()
	const depth = 2100 // "a/" × 2100 is 4200 bytes, past PATH_MAX's 4096
	deepChain(t, root, depth, 1<<20)
	if _, err := os.Stat(filepath.Join(root, strings.Repeat("a/", depth)+"bottom")); !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Fatalf("the chain is not deeper than a path can name (stat: %v)", err)
	}

	u, err := Walker{}.Measure(context.Background(), Root{Path: root})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if u.Bytes < 1<<20 {
		t.Fatalf("Bytes = %d: the file below PATH_MAX was not counted", u.Bytes)
	}

	// And with the walk made to let go of its ancestors every few levels, it
	// finds them again through ".." and arrives at the same number.
	small, err := Walker{maxOpen: 8}.Measure(context.Background(), Root{Path: root})
	if err != nil || small.Bytes != u.Bytes {
		t.Fatalf("with 8 descriptors: %d, %v; want %d", small.Bytes, err, u.Bytes)
	}
}

func TestMeasureLetsGoOfAncestorsAndFindsThemAgain(t *testing.T) {
	root := t.TempDir()
	path := root
	for i := 0; i < 40; i++ {
		path = filepath.Join(path, "d")
		writeFile(t, filepath.Join(path, "f"), 4<<10)
		writeFile(t, filepath.Join(path, "side", "g"), 4<<10)
	}
	want := measure(t, Walker{}, Root{Path: root})
	got := measure(t, Walker{maxOpen: 3}, Root{Path: root})
	if got.Bytes != want.Bytes || got.Entries != want.Entries {
		t.Fatalf("with 3 descriptors: %d bytes / %d entries, want %d / %d",
			got.Bytes, got.Entries, want.Bytes, want.Entries)
	}
}

// TestReopenRefusesADirectoryThatMoved: climbing back through ".." must arrive
// at the directory the walk left, or the rest of the measurement would be of
// somewhere else.
func TestReopenRefusesADirectoryThatMoved(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"p/c", "q"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	open := func(p string) *frame {
		fd, err := unix.Open(p, dirFlags, 0)
		if err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		return &frame{f: os.NewFile(uintptr(fd), p), path: p, dev: uint64(st.Dev), ino: uint64(st.Ino)}
	}
	parent := open(filepath.Join(root, "p"))
	child := open(filepath.Join(root, "p", "c"))
	defer child.f.Close()
	_ = parent.f.Close()
	parent.f = nil

	if err := reopen(parent, child); err != nil {
		t.Fatalf("reopen of an unmoved parent: %v", err)
	}
	_ = parent.f.Close()
	parent.f = nil

	if err := os.Rename(filepath.Join(root, "p", "c"), filepath.Join(root, "q", "c")); err != nil {
		t.Fatal(err)
	}
	if err := reopen(parent, child); !errors.Is(err, errTreeMoved) {
		t.Fatalf("reopen after the child moved = %v, want errTreeMoved", err)
	}
}
