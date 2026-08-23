package securewipe

// These tests exist because the code they cover used to lie.
//
// Two copies of the wipe — the hub's and the edge agent's — opened the file
// with `if f, err := os.OpenFile(...); err == nil`, wrote with `_, _ =`, synced
// with `_ =`, and returned nil regardless. A caller was told the credential's
// bytes had been overwritten when, if any of those steps failed, only the name
// had been removed. On the os.TempDir() fallback path — macOS, a container
// with no /dev/shm — that is the difference between a destroyed secret and a
// recoverable one.
//
// So the interesting assertions here are the negative ones: that a wipe which
// cannot happen says so.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "ghp_thequickbrownfoxjumpsoverthelazydog"

// leaseDir returns a lease-named directory holding one credential file.
func leaseDir(t *testing.T) (dir, file string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), LeaseDirPrefix+"test")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir lease dir: %v", err)
	}
	file = filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	return dir, file
}

func TestFileZeroesAndRemoves(t *testing.T) {
	_, file := leaseDir(t)
	if err := File(file); err != nil {
		t.Fatalf("File: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("credential survived the wipe: %v", err)
	}
}

// TestFileOverwritesBeforeUnlinking is the property the function's name
// promises. Unlinking alone leaves the plaintext in blocks that survive until
// they are reused, so the zeroing has to happen through the same inode, before
// the name goes.
//
// Reading it back through a second open file descriptor is how the test sees
// it: the unlink drops the directory entry, but the inode stays alive while
// this handle holds it, so what the handle reads is what is genuinely left on
// the filesystem.
func TestFileOverwritesBeforeUnlinking(t *testing.T) {
	_, file := leaseDir(t)

	fd, err := os.Open(file)
	if err != nil {
		t.Fatalf("open witness: %v", err)
	}
	defer fd.Close()

	if err := File(file); err != nil {
		t.Fatalf("File: %v", err)
	}

	buf := make([]byte, len(secret))
	if _, err := fd.ReadAt(buf, 0); err != nil {
		t.Fatalf("read through witness handle: %v", err)
	}
	if strings.Contains(string(buf), "ghp_") {
		t.Errorf("the credential is still readable through a surviving handle: %q\n"+
			"the file was unlinked but never overwritten, which is exactly the "+
			"failure this package was extracted to fix", buf)
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d is %#x, want 0: the overwrite did not cover the whole file", i, b)
		}
	}
}

func TestFileOnMissingPathIsNotAnError(t *testing.T) {
	if err := File(filepath.Join(t.TempDir(), "never-existed")); err != nil {
		t.Errorf("a missing file is the end state we want, not an error: %v", err)
	}
}

// TestFileReportsAnOverwriteItCannotPerform is the regression test for the
// original defect.
//
// A file this process cannot open for writing cannot be zeroed. The old code
// swallowed the open error and returned nil, so the caller logged "credential
// wiped" over an unlinked-but-intact secret. The new contract: the unlink still
// happens (a weaker outcome beats none), and the error still comes back.
func TestFileReportsAnOverwriteItCannotPerform(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root bypasses the permission check, so the open would succeed and
		// there would be no failure to report. Skipping is honest; asserting a
		// failure that cannot occur would be a test that only passes by
		// accident of the CI user.
		t.Skip("running as root: file permissions cannot make an open fail")
	}
	_, file := leaseDir(t)
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := File(file)
	if err == nil {
		t.Fatal("File returned nil for a credential it could not overwrite; " +
			"the caller would report a secret as destroyed when only its name was removed")
	}
	if !strings.Contains(err.Error(), "overwrite") {
		t.Errorf("error should name the failed step, got: %v", err)
	}
	// The unlink is still attempted: an unlinked-but-unzeroed credential is a
	// worse outcome than a destroyed one and a better one than an untouched
	// file sitting in /dev/shm.
	if _, serr := os.Stat(file); !os.IsNotExist(serr) {
		t.Errorf("the file should still have been unlinked despite the failed overwrite: %v", serr)
	}
}

// TestFileRefusesNonRegularFiles is the root-safe half of the same contract: a
// wipe that cannot happen must be reported rather than assumed. It also closes
// a confinement hole — a device node in a lease directory is not something this
// package put there, and writing zeros into one is not a wipe.
func TestFileRefusesNonRegularFiles(t *testing.T) {
	dir, _ := leaseDir(t)
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := File(sub)
	if err == nil {
		t.Fatal("File returned nil for a directory; a caller would treat that as a successful wipe")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error should say why it refused, got: %v", err)
	}
}

// TestFileRemovesSymlinksWithoutFollowingThem guards the primitive against
// being turned into a write. The paths reaching an edge agent come from the
// control plane, which this system's threat model treats as potentially
// compromised; following a planted link would write zeros through it into
// whatever it names.
func TestFileRemovesSymlinksWithoutFollowingThem(t *testing.T) {
	dir, _ := leaseDir(t)
	victim := filepath.Join(t.TempDir(), "important")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := File(link); err != nil {
		t.Fatalf("File on a symlink: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("the link itself should be gone: %v", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("the link target was removed: %v", err)
	}
	if string(got) != "do not touch" {
		t.Errorf("the link target was overwritten: %q — the wipe followed the symlink", got)
	}
}

func TestDirWipesEveryCredentialAndRemovesItself(t *testing.T) {
	dir, file := leaseDir(t)
	extra := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(extra, []byte("apiVersion: v1"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := Dir(dir); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	for _, p := range []string{file, extra, dir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived: %v", p, err)
		}
	}
}

// TestDirRefusesDirectoriesItDoesNotOwn is the confinement rule. Without it,
// "clean up this lease" is a recursive-delete primitive pointed at any path the
// control plane names.
func TestDirRefusesDirectoriesItDoesNotOwn(t *testing.T) {
	for _, tc := range []struct{ name, dir string }{
		{"no lease prefix", filepath.Join(t.TempDir(), "etc")},
		{"bare prefix with no suffix", filepath.Join(t.TempDir(), LeaseDirPrefix)},
		{"relative path", "cloop-lease-relative"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Dir(tc.dir); err == nil {
				t.Errorf("Dir(%q) was accepted; only cloop-lease-* directories may be removed", tc.dir)
			}
		})
	}
}

// TestDirRefusesToRecurse keeps the blast radius of a bad path to one level. It
// also gives callers a deterministic way to observe a failed wipe, which is
// what the "callers surface it" tests in pkg/secretbroker rely on.
func TestDirRefusesToRecurse(t *testing.T) {
	dir, _ := leaseDir(t)
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	buried := filepath.Join(nested, "token")
	if err := os.WriteFile(buried, []byte(secret), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := Dir(dir)
	if err == nil {
		t.Fatal("Dir silently accepted a subdirectory; a caller would believe the lease was clean")
	}
	if !strings.Contains(err.Error(), "subdirectories") {
		t.Errorf("error should explain the refusal, got: %v", err)
	}
	if _, serr := os.Stat(buried); serr != nil {
		t.Errorf("the refused subtree should be left intact as evidence: %v", serr)
	}
}

func TestDirOnMissingDirectoryIsNotAnError(t *testing.T) {
	if err := Dir(filepath.Join(t.TempDir(), LeaseDirPrefix+"gone")); err != nil {
		t.Errorf("a missing lease directory is the end state we want: %v", err)
	}
}

// TestDirJoinsEveryFailure matters for the audit line: an operator deciding
// whether a credential is still on disk needs every reason it might be, not
// just the first one encountered.
func TestDirJoinsEveryFailure(t *testing.T) {
	dir, _ := leaseDir(t)
	for _, name := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	err := Dir(dir)
	if err == nil {
		t.Fatal("Dir returned nil with two unremovable entries")
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("expected a joined error, got %T", err)
	}
	// Two refusals plus the directory removal that consequently fails.
	if got := len(joined.Unwrap()); got < 2 {
		t.Errorf("joined %d errors, want at least the two refusals: %v", got, err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Error("a refusal must not be reported as a missing file")
	}
}

func TestIsLeaseDir(t *testing.T) {
	for _, tc := range []struct {
		dir  string
		want bool
	}{
		{"/dev/shm/cloop-lease-abc123", true},
		{"/run/cloop/cloop-lease-x", true},
		{"/dev/shm/cloop-lease-abc123/", true},
		{"/dev/shm/cloop-lease-", false},
		{"/dev/shm/cloop-leases-abc", false},
		{"/etc", false},
		{"", false},
	} {
		if got := IsLeaseDir(tc.dir); got != tc.want {
			t.Errorf("IsLeaseDir(%q) = %v, want %v", tc.dir, got, tc.want)
		}
	}
}
