package diskreserve

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func newProject(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	return work
}

// leftovers lists .cloop entries other than the reserve itself — the
// temporaries a failed Ensure must not leave behind.
func leftovers(t *testing.T, work string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(work, ".cloop"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != Name {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestEnsureCreatesAnAllocatedReserve(t *testing.T) {
	work := newProject(t)

	created, err := Ensure(work)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !created {
		t.Fatal("Ensure reported no reserve created on a project that had none")
	}
	fi, err := os.Stat(Path(work))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != Size {
		t.Errorf("reserve is %d bytes, want %d", fi.Size(), Size)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("reserve mode = %v, want 0600", fi.Mode().Perm())
	}
	// Blocks, not a sparse length: a reserve that holds nothing frees nothing.
	if held := Held(work); held < Size {
		t.Errorf("Held = %d, want at least %d — the reserve is sparse", held, Size)
	}
	if extra := leftovers(t, work); len(extra) > 0 {
		t.Errorf("Ensure left %v in .cloop", extra)
	}

	// A whole reserve is left alone: this runs before every task attempt.
	before := fi.ModTime()
	created, err = Ensure(work)
	if err != nil || created {
		t.Fatalf("second Ensure = (%v, %v), want (false, nil)", created, err)
	}
	if fi2, _ := os.Stat(Path(work)); !fi2.ModTime().Equal(before) {
		t.Error("a whole reserve was rewritten")
	}
}

func TestEnsureReplacesAShortReserve(t *testing.T) {
	work := newProject(t)
	if err := os.WriteFile(Path(work), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := Ensure(work)
	if err != nil || !created {
		t.Fatalf("Ensure = (%v, %v), want (true, nil)", created, err)
	}
	if fi, _ := os.Stat(Path(work)); fi.Size() != Size {
		t.Errorf("short reserve not replaced: %d bytes", fi.Size())
	}
}

// TestEnsureWantsRoomFirst: a volume with less than twice the reserve free is
// not asked for it — creating it there would take the very space it exists to
// keep for other writes.
func TestEnsureWantsRoomFirst(t *testing.T) {
	work := newProject(t)
	orig := freeBytes
	t.Cleanup(func() { freeBytes = orig })
	freeBytes = func(string) (int64, error) { return roomFactor*Size - 1, nil }

	created, err := Ensure(work)
	if !errors.Is(err, ErrNoRoom) || created {
		t.Fatalf("Ensure = (%v, %v), want (false, ErrNoRoom)", created, err)
	}
	if _, statErr := os.Stat(Path(work)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a reserve was created on a volume without room for it (%v)", statErr)
	}
	if extra := leftovers(t, work); len(extra) > 0 {
		t.Errorf("Ensure left %v in .cloop", extra)
	}
}

// TestEnsureLeavesNothingWhenTheDiskFillsMidway: the allocation itself runs
// out of space. The temporary goes, and no half-sized file claims to be the
// reserve.
func TestEnsureLeavesNothingWhenTheDiskFillsMidway(t *testing.T) {
	work := newProject(t)
	orig := allocate
	t.Cleanup(func() { allocate = orig })
	allocate = func(f *os.File, size int64) error {
		if _, err := f.Write(make([]byte, 4096)); err != nil {
			return err
		}
		return &os.PathError{Op: "fallocate", Path: f.Name(), Err: syscall.ENOSPC}
	}

	created, err := Ensure(work)
	if !errors.Is(err, ErrNoRoom) || created {
		t.Fatalf("Ensure = (%v, %v), want (false, ErrNoRoom)", created, err)
	}
	if extra := leftovers(t, work); len(extra) > 0 {
		t.Errorf("a failed Ensure left %v in .cloop", extra)
	}
	if _, statErr := os.Stat(Path(work)); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("a half-allocated reserve was renamed into place")
	}
}

func TestReleaseFreesTheReserve(t *testing.T) {
	work := newProject(t)
	if _, err := Ensure(work); err != nil {
		t.Fatal(err)
	}
	freed, err := Release(work)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if freed < Size {
		t.Errorf("Release freed %d bytes, want at least %d", freed, Size)
	}
	if _, statErr := os.Stat(Path(work)); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("the reserve is still there after Release")
	}
	// Two writes that fail together both release; the second finds it gone.
	freed, err = Release(work)
	if err != nil || freed != 0 {
		t.Errorf("second Release = (%d, %v), want (0, nil)", freed, err)
	}
	if Held(work) != 0 {
		t.Error("Held reports bytes for an absent reserve")
	}
}

func TestReleaseLeavesSomethingElseAlone(t *testing.T) {
	work := newProject(t)
	if err := os.Mkdir(Path(work), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Release(work); err == nil {
		t.Fatal("Release removed a directory that happened to be called reserve")
	}
	if fi, err := os.Stat(Path(work)); err != nil || !fi.IsDir() {
		t.Error("the directory is gone")
	}
}

func TestIsDiskFull(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ENOSPC", syscall.ENOSPC, true},
		{"wrapped ENOSPC", fmt.Errorf("write verdict: %w", &os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC}), true},
		// A layer that wrapped with %v keeps only the message.
		{"ENOSPC flattened to text", fmt.Errorf("save: %v", syscall.ENOSPC), true},
		{"quota", fmt.Errorf("write: %w", syscall.EDQUOT), true},
		{"SQLITE_FULL", errors.New("statedb: save project: database or disk is full (13)"), true},
		{"busy", errors.New("database is locked (5) (SQLITE_BUSY)"), false},
		{"permission", fmt.Errorf("write: %w", syscall.EACCES), false},
	}
	for _, tc := range cases {
		if got := IsDiskFull(tc.err); got != tc.want {
			t.Errorf("%s: IsDiskFull(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// TestWriteOutIsNotZeros: the fallback for filesystems that cannot
// preallocate writes data a compressing filesystem cannot store as nothing.
func TestWriteOutIsNotZeros(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "r"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const size = 3<<20 + 17 // not a multiple of the buffer
	if err := writeOut(f, size); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != size {
		t.Fatalf("wrote %d bytes, want %d", len(data), size)
	}
	if bytes.Count(data[:1<<16], []byte{0}) > 1<<10 {
		t.Error("the fallback wrote mostly zeros, which a compressing filesystem stores as nothing")
	}
}

func TestIsName(t *testing.T) {
	if !IsName("reserve") || IsName("reserve.tmp") || IsName("state.db") {
		t.Error("IsName answers for the wrong entries")
	}
	if !strings.HasSuffix(Path("/p"), filepath.Join(".cloop", "reserve")) {
		t.Errorf("Path = %q", Path("/p"))
	}
}
