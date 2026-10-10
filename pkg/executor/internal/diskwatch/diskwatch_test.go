package diskwatch

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeFile writes n bytes of non-zero data, so the file is allocated rather
// than sparse.
func writeFile(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", n)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// allocated is what statOf charges for one path, for computing expectations
// that do not depend on the filesystem's block size.
func allocated(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return statOf(info).bytes
}

func measure(t *testing.T, w Walker, roots ...Root) Usage {
	t.Helper()
	u, err := w.Measure(context.Background(), roots...)
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	return u
}

func TestMeasureCountsAllocatedBlocksNotApparentSize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("allocation is a Unix measurement")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "data"), 256<<10)
	// A sparse file claims a gigabyte and occupies next to nothing: the disk
	// a workload fills is the blocks, not the claim.
	sparse := filepath.Join(root, "sparse")
	f, err := os.Create(sparse)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	f.Close()

	u := measure(t, Walker{}, Root{Path: root})
	want := allocated(t, root) + allocated(t, filepath.Join(root, "data")) + allocated(t, sparse)
	if u.Bytes != want {
		t.Fatalf("Bytes = %d, want %d", u.Bytes, want)
	}
	if u.Bytes >= 1<<30 {
		t.Fatalf("a sparse file was charged its apparent size: %d bytes", u.Bytes)
	}
	if u.Bytes < 256<<10 {
		t.Fatalf("Bytes = %d, below the data actually written", u.Bytes)
	}
}

func TestMeasureCountsAHardLinkedFileOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard-link identity is a Unix measurement")
	}
	root := t.TempDir()
	orig := filepath.Join(root, "a", "big")
	writeFile(t, orig, 512<<10)
	base := measure(t, Walker{}, Root{Path: root})

	// Three more names for the same inode, one in a directory of its own.
	if err := os.MkdirAll(filepath.Join(root, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(root, "a", "link1"), filepath.Join(root, "a", "link2"),
		filepath.Join(root, "b", "link3")} {
		if err := os.Link(orig, name); err != nil {
			t.Skipf("hard links unsupported here: %v", err)
		}
	}
	u := measure(t, Walker{}, Root{Path: root})
	if want := base.Bytes + allocated(t, filepath.Join(root, "b")); u.Bytes != want {
		t.Fatalf("Bytes = %d, want %d: the file was counted once per link", u.Bytes, want)
	}

	// Across two roots measured together, too: a feature's checkout and its
	// output directory share one budget.
	other := t.TempDir()
	if err := os.Link(orig, filepath.Join(other, "link4")); err != nil {
		t.Fatal(err)
	}
	both := measure(t, Walker{}, Root{Path: root}, Root{Path: other})
	if want := u.Bytes + allocated(t, other); both.Bytes != want {
		t.Fatalf("two roots: Bytes = %d, want %d", both.Bytes, want)
	}
}

func TestMeasureDoesNotFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "elsewhere"), 1<<20)
	writeFile(t, filepath.Join(root, "small"), 10)
	base := measure(t, Walker{}, Root{Path: root})

	// A link to a large directory and a link to the filesystem root: each is
	// one small entry, never what it points at.
	if err := os.Symlink(outside, filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(root, "rootlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "elsewhere"), filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}
	u := measure(t, Walker{}, Root{Path: root})
	links := allocated(t, filepath.Join(root, "dirlink")) + allocated(t, filepath.Join(root, "rootlink")) +
		allocated(t, filepath.Join(root, "filelink"))
	if want := base.Bytes + links; u.Bytes != want {
		t.Fatalf("Bytes = %d, want %d: a symlink was followed", u.Bytes, want)
	}
	if u.Entries > base.Entries+3 {
		t.Fatalf("visited %d entries, want %d: the walk descended through a link", u.Entries, base.Entries+3)
	}
}

func TestMeasureDoesNotCrossAMountPoint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "kept"), 64<<10)
	writeFile(t, filepath.Join(root, "mnt", "foreign"), 1<<20)
	writeFile(t, filepath.Join(root, "deep", "er", "mnt2", "foreign"), 1<<20)
	all := measure(t, Walker{}, Root{Path: root})

	// Creating a mount needs a privilege CI does not have, so the mount table
	// is injected — which is exactly the case st_dev cannot see: a bind mount
	// of the same filesystem shares its device.
	mounted := map[string]bool{
		filepath.Join(root, "mnt"):                true,
		filepath.Join(root, "deep", "er", "mnt2"): true,
	}
	var asked []string
	w := Walker{MountPoints: func(roots []string) (map[string]bool, bool) {
		asked = append(asked, roots...)
		return mounted, true
	}}
	u := measure(t, w, Root{Path: root})
	if u.MountsSkipped != 2 {
		t.Fatalf("MountsSkipped = %d, want 2", u.MountsSkipped)
	}
	skipped := allocated(t, filepath.Join(root, "mnt")) + allocated(t, filepath.Join(root, "mnt", "foreign")) +
		allocated(t, filepath.Join(root, "deep", "er", "mnt2")) +
		allocated(t, filepath.Join(root, "deep", "er", "mnt2", "foreign"))
	if want := all.Bytes - skipped; u.Bytes != want {
		t.Fatalf("Bytes = %d, want %d: a mount point was crossed or counted", u.Bytes, want)
	}
	if len(asked) != 1 || asked[0] != filepath.Clean(root) {
		t.Fatalf("mount table asked about %v, want [%s]", asked, root)
	}
}

func TestMeasureExcludesTheProjectStateDirectoryAtTheRootOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "main.go"), 4<<10)
	writeFile(t, filepath.Join(root, ".cloop", "state.db"), 2<<20)
	writeFile(t, filepath.Join(root, ".cloop", "artifacts", "1_output.txt"), 1<<20)
	// The workload's own directory of that name, deeper down, is the
	// workload's and is counted.
	writeFile(t, filepath.Join(root, "fixtures", ".cloop", "blob"), 128<<10)

	without := measure(t, Walker{}, Root{Path: root, Exclude: []string{".cloop"}})
	with := measure(t, Walker{}, Root{Path: root})
	stateDir := allocated(t, filepath.Join(root, ".cloop")) +
		allocated(t, filepath.Join(root, ".cloop", "state.db")) +
		allocated(t, filepath.Join(root, ".cloop", "artifacts")) +
		allocated(t, filepath.Join(root, ".cloop", "artifacts", "1_output.txt"))
	if want := with.Bytes - stateDir; without.Bytes != want {
		t.Fatalf("Bytes = %d, want %d: .cloop/ was counted, or the nested one was not", without.Bytes, want)
	}
	nested := allocated(t, filepath.Join(root, "fixtures", ".cloop", "blob"))
	if without.Bytes < nested {
		t.Fatalf("Bytes = %d, below the nested .cloop's own %d", without.Bytes, nested)
	}
}

// stepClock advances by step on every read, so a walk's own visits move time.
type stepClock struct {
	mu   sync.Mutex
	at   time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(c.step)
	return c.at
}

func TestMeasureMissesItsDeadlineAsALowerBoundNotAMeasurement(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 40; i++ {
		writeFile(t, filepath.Join(root, "d", strings.Repeat("n", i+1)), 4<<10)
	}
	for i := 0; i < 600; i++ {
		writeFile(t, filepath.Join(root, "many", "f"+strings.Repeat("0", i%7)+string(rune('a'+i%26))+
			time.Duration(i).String()), 1)
	}
	full := measure(t, Walker{}, Root{Path: root})

	// Every clock read is a second; the deadline is three. The walk reads the
	// clock once per directory and once per checkEvery entries — about ten
	// reads for this tree — so it cannot finish inside three.
	clock := &stepClock{at: time.Unix(1_700_000_000, 0), step: time.Second}
	u, err := Walker{Clock: clock, Deadline: 3 * time.Second}.Measure(context.Background(), Root{Path: root})
	if !errors.Is(err, ErrDeadline) {
		t.Fatalf("err = %v, want ErrDeadline", err)
	}
	if u.Bytes >= full.Bytes {
		t.Fatalf("a walk that missed its deadline reported %d bytes, the whole tree's %d", u.Bytes, full.Bytes)
	}
	if u.Elapsed < 3*time.Second {
		t.Fatalf("Elapsed = %s, want the time it spent (at least the deadline)", u.Elapsed)
	}

	// The same walk with room to finish completes and agrees with the real
	// clock's measurement.
	clock = &stepClock{at: time.Unix(1_700_000_000, 0), step: time.Millisecond}
	u, err = Walker{Clock: clock, Deadline: time.Hour}.Measure(context.Background(), Root{Path: root})
	if err != nil || u.Bytes != full.Bytes {
		t.Fatalf("Measure = %d, %v; want %d, nil", u.Bytes, err, full.Bytes)
	}
}

func TestMeasureHonoursItsContext(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a"), 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Walker{}).Measure(ctx, Root{Path: root}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestMeasureReportsAnUnreadableDirectoryAsIncomplete(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	if os.Geteuid() == 0 {
		// Root reads through any mode bits, which is also why a hub running
		// as root cannot be hidden from this way.
		t.Skip("root can read every directory")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "open", "f"), 4<<10)
	writeFile(t, filepath.Join(root, "closed", "hidden"), 1<<20)
	if err := os.Chmod(filepath.Join(root, "closed"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "closed"), 0o755) })

	u, err := Walker{}.Measure(context.Background(), Root{Path: root})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want ErrIncomplete", err)
	}
	if u.Unreadable != 1 || len(u.UnreadablePaths) != 1 || u.UnreadablePaths[0] != filepath.Join(root, "closed") {
		t.Fatalf("Unreadable = %d %v", u.Unreadable, u.UnreadablePaths)
	}
}

// TestMeasureCountsARootsGrowthBeyondItsAllowance is how a project's .cloop/
// is measured: its size at the start is the hub's bookkeeping, and only what
// the run adds to it counts — excluded outright, it would be a directory the
// sandbox can write and no walk ever counts.
func TestMeasureCountsARootsGrowthBeyondItsAllowance(t *testing.T) {
	work := t.TempDir()
	state := t.TempDir()
	writeFile(t, filepath.Join(work, "src"), 64<<10)
	writeFile(t, filepath.Join(state, "state.db"), 2<<20)

	start := measure(t, Walker{}, Root{Path: work}, Root{Path: state, Allowance: math.MaxInt64})
	if len(start.RootBytes) != 2 || start.Bytes != start.RootBytes[0] {
		t.Fatalf("start = %+v: a root under an unlimited allowance was counted", start)
	}
	baseline := start.RootBytes[1]
	if baseline < 2<<20 {
		t.Fatalf("the state root measured %d bytes, below what is in it", baseline)
	}

	writeFile(t, filepath.Join(state, "smuggled"), 1<<20)
	later := measure(t, Walker{}, Root{Path: work}, Root{Path: state, Allowance: baseline})
	grown := later.RootBytes[1] - baseline
	if grown < 1<<20 || later.Bytes != later.RootBytes[0]+grown {
		t.Fatalf("later = %+v: the state root's growth of %d bytes was not counted", later, grown)
	}

	// Shrinking below the allowance counts as nothing, not as a credit.
	if err := os.Remove(filepath.Join(state, "state.db")); err != nil {
		t.Fatal(err)
	}
	shrunk := measure(t, Walker{}, Root{Path: work}, Root{Path: state, Allowance: baseline})
	if shrunk.Bytes != shrunk.RootBytes[0] {
		t.Fatalf("shrunk = %+v: a root below its allowance reduced the total", shrunk)
	}
}

func TestMeasureAnOptionalRootThatIsMissingIsEmpty(t *testing.T) {
	work := t.TempDir()
	writeFile(t, filepath.Join(work, "f"), 4<<10)
	missing := filepath.Join(work, "no-such-dir")
	u, err := Walker{}.Measure(context.Background(), Root{Path: work}, Root{Path: missing, Optional: true})
	if err != nil || u.RootBytes[1] != 0 || u.Bytes != u.RootBytes[0] {
		t.Fatalf("Measure = %+v, %v; want the optional root empty", u, err)
	}
	if runtime.GOOS != "windows" {
		// A symlink where the optional directory should be is not followed.
		if err := os.Symlink(t.TempDir(), missing); err != nil {
			t.Fatal(err)
		}
		if u, err := (Walker{}).Measure(context.Background(), Root{Path: missing, Optional: true}); err != nil || u.Bytes != 0 {
			t.Fatalf("an optional root that is a symlink = %+v, %v; want it empty", u, err)
		}
	}
}

func TestMeasureRefusesAMissingRoot(t *testing.T) {
	_, err := Walker{}.Measure(context.Background(), Root{Path: filepath.Join(t.TempDir(), "gone")})
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want a not-exist error", err)
	}
}

func TestParseMountPoints(t *testing.T) {
	table := strings.Join([]string{
		`22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw`,
		`40 22 0:35 / /srv/proj/node_modules rw shared:20 - tmpfs tmpfs rw`,
		`41 22 8:1 /data /srv/proj/vendor\040cache rw shared:1 - ext4 /dev/sda1 rw`,
		`42 22 8:1 / /srv/proj rw shared:1 - ext4 /dev/sda1 rw`,
		`43 22 8:1 / /srv/project-two rw shared:1 - ext4 /dev/sda1 rw`,
		`44 22 0:50 / /srv/other/x rw - tmpfs tmpfs rw`,
		`garbage`,
		``,
	}, "\n")
	got := parseMountPoints(table, []string{"/srv/proj"})
	want := map[string]bool{"/srv/proj/node_modules": true, "/srv/proj/vendor cache": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("got %v, missing %q", got, k)
		}
	}
	// The root itself and a sibling sharing its prefix are not below it.
	if got["/srv/proj"] || got["/srv/project-two"] {
		t.Fatalf("got %v: the root or a prefix sibling was taken for a mount below it", got)
	}
	if all := parseMountPoints(table, []string{"/"}); !all["/srv/other/x"] || all["/"] {
		t.Fatalf("root /: got %v", all)
	}
}

func TestUnescapeMountField(t *testing.T) {
	for in, want := range map[string]string{
		`/plain`:            "/plain",
		`/with\040space`:    "/with space",
		`/tab\011and\012nl`: "/tab\tand\nnl",
		`/back\134slash`:    `/back\slash`,
		`/trailing\04`:      `/trailing\04`,
		`/notoctal\999`:     `/notoctal\999`,
	} {
		if got := unescapeMountField(in); got != want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLowPriorityRunsOnAThreadAtTheLowestPriority(t *testing.T) {
	ran := false
	var nice, class int
	err := LowPriority(func() {
		ran = true
		nice, class = threadPriority()
	})
	if err != nil || !ran {
		t.Fatalf("LowPriority = %v, ran %v", err, ran)
	}
	if runtime.GOOS != "linux" {
		return
	}
	if nice != 19 {
		t.Fatalf("the walk ran at nice %d, want 19", nice)
	}
	if class != ioprioClassIdle {
		t.Fatalf("the walk ran in I/O class %d, want %d (idle)", class, ioprioClassIdle)
	}
	// The caller's own thread is untouched.
	if n, _ := threadPriority(); n == 19 {
		t.Fatalf("the caller's thread was left at nice 19")
	}
}

func TestLowPriorityReturnsAPanicAsAnError(t *testing.T) {
	err := LowPriority(func() { panic("boom") })
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the panic", err)
	}
}
