package multiui

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// fakeCloopEnv is a sentinel: when set, TestMain pretends to be a "cloop"
// binary that sleeps until killed instead of running the test suite. Lets
// the live-/proc test re-exec the test binary as a fake cloop without
// shelling out to system tools that don't accept arbitrary argv.
const fakeCloopEnv = "CLOOP_MULTIUI_FAKE_CLOOP"

// TestMain enables the fake-cloop subprocess shim. When the env var is set
// the binary blocks on stdin (or sleeps for 60s, whichever comes first) so
// the parent can inspect its /proc entry. When unset it runs the normal
// test suite.
func TestMain(m *testing.M) {
	if os.Getenv(fakeCloopEnv) != "" {
		// Sleep up to 60s so parent can inspect /proc; parent always
		// kills us via Process.Kill in cleanup, so 60s is just a safety
		// upper bound to avoid leaking processes if a test panics.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestCloopRunMatch covers the pure decision predicate that decides whether
// a /proc entry represents a "cloop run" process whose cwd matches a given
// predicate. The /proc walk is non-deterministic per-host, so this test
// pins down the rules without involving the filesystem.
func TestCloopRunMatch(t *testing.T) {
	always := func(string) bool { return true }
	matchDir := func(want string) func(string) bool {
		return func(cwd string) bool { return cwd == want }
	}

	cases := []struct {
		name    string
		exePath string
		cmdline []string
		cwd     string
		match   func(string) bool
		want    bool
	}{
		{
			name:    "abs path cloop run matches always",
			exePath: "/usr/local/bin/cloop",
			cmdline: []string{"/usr/local/bin/cloop", "run"},
			cwd:     "/work/proj",
			match:   always,
			want:    true,
		},
		{
			name:    "bare basename cloop run matches always",
			exePath: "cloop",
			cmdline: []string{"cloop", "run"},
			cwd:     "/work/proj",
			match:   always,
			want:    true,
		},
		{
			name:    "cloop ui is not cloop run",
			exePath: "/usr/local/bin/cloop",
			cmdline: []string{"cloop", "ui"},
			cwd:     "/work/proj",
			match:   always,
			want:    false,
		},
		{
			name:    "non-cloop binary rejected even with run argv",
			exePath: "/usr/bin/grep",
			cmdline: []string{"grep", "run"},
			cwd:     "/work/proj",
			match:   always,
			want:    false,
		},
		{
			name:    "executable suffix collision rejected (notcloop)",
			exePath: "/usr/local/bin/notcloop",
			cmdline: []string{"notcloop", "run"},
			cwd:     "/work/proj",
			match:   always,
			want:    false,
		},
		{
			name:    "executable suffix collision rejected (xcloop)",
			exePath: "xcloop",
			cmdline: []string{"xcloop", "run"},
			cwd:     "/work/proj",
			match:   always,
			want:    false,
		},
		{
			name:    "matching cwd accepted",
			exePath: "/usr/local/bin/cloop",
			cmdline: []string{"cloop", "run", "--pm"},
			cwd:     "/work/proj-a",
			match:   matchDir("/work/proj-a"),
			want:    true,
		},
		{
			name:    "non-matching cwd rejected (multi-project scoping)",
			exePath: "/usr/local/bin/cloop",
			cmdline: []string{"cloop", "run", "--pm"},
			cwd:     "/work/proj-b",
			match:   matchDir("/work/proj-a"),
			want:    false,
		},
		{
			name:    "empty cmdline rejected",
			exePath: "/usr/local/bin/cloop",
			cmdline: nil,
			cwd:     "/work/proj",
			match:   always,
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cloopRunMatch(tc.exePath, tc.cmdline, tc.cwd, tc.match)
			if got != tc.want {
				t.Fatalf("cloopRunMatch(%q, %v, %q) = %v, want %v",
					tc.exePath, tc.cmdline, tc.cwd, got, tc.want)
			}
		})
	}
}

// TestSplitCmdline verifies the trailing-NUL element from /proc/PID/cmdline
// is dropped so callers see only real argv entries.
func TestSplitCmdline(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want []string
	}{
		{name: "single arg with trailing nul", raw: []byte("cloop\x00"), want: []string{"cloop"}},
		{name: "multi arg with trailing nul", raw: []byte("cloop\x00run\x00--pm\x00"), want: []string{"cloop", "run", "--pm"}},
		{name: "empty", raw: []byte{}, want: []string{}},
		{name: "no trailing nul", raw: []byte("cloop\x00run"), want: []string{"cloop", "run"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCmdline(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("splitCmdline(%q) len=%d, want %d (got %v)", tc.raw, len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("splitCmdline(%q)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestParseAllDigits verifies the /proc-entry digit filter rejects every
// non-numeric directory name (init, kthreads, "self", etc.) without paying
// for strconv.Atoi's broader surface (signs, whitespace, leading +).
func TestParseAllDigits(t *testing.T) {
	good := map[string]int{"0": 0, "1": 1, "12345": 12345}
	for s, want := range good {
		if n, ok := parseAllDigits(s); !ok || n != want {
			t.Fatalf("parseAllDigits(%q) = (%d,%v); want (%d,true)", s, n, ok, want)
		}
	}
	bad := []string{"", "self", "12a", "a12", "+1", "-1", " 1", "1 "}
	for _, s := range bad {
		if _, ok := parseAllDigits(s); ok {
			t.Fatalf("parseAllDigits(%q) accepted, want rejected", s)
		}
	}
}

// TestCloopRunPIDsInDir_LiveProc spawns a real child process whose argv
// looks like `cloop run --pm` (via a symlink), waits for /proc to publish
// it, then asserts that:
//   - CloopRunPIDsInDir(childCwd) finds exactly that PID.
//   - CloopRunPIDsInDir(otherDir) does not find it (project scoping works).
//   - AllCloopRunPIDs() includes that PID.
//
// This is the regression test for the multi-project pkill bug: the prior
// `pkill -f "cloop run"` implementation would have signalled this child
// regardless of what dir was passed to handleProjectStop.
func TestCloopRunPIDsInDir_LiveProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc (Linux only)")
	}
	if _, err := os.Stat("/proc/self/cwd"); err != nil {
		t.Skipf("/proc not accessible: %v", err)
	}

	// Copy the test binary itself into a file named "cloop" so
	// /proc/PID/exe shows .../bin/cloop. We re-exec with fakeCloopEnv set
	// so TestMain knows to act as the sleep shim instead of running the
	// suite. A symlink would not work — the kernel resolves symlinks in
	// /proc/PID/exe back to the real binary, defeating the basename check.
	selfBin, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	tmp := t.TempDir()
	cwdDir := filepath.Join(tmp, "project")
	otherDir := filepath.Join(tmp, "other")
	binDir := filepath.Join(tmp, "bin")
	for _, d := range []string{cwdDir, otherDir, binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	fakeCloop := filepath.Join(binDir, "cloop")
	if err := copyExecutable(selfBin, fakeCloop); err != nil {
		t.Skipf("cannot stage fake cloop binary (skipping live-proc test): %v", err)
	}

	// Spawn ./cloop run — argv contains "run" and the cwd is cwdDir.
	cmd := exec.Command(fakeCloop, "run")
	cmd.Dir = cwdDir
	cmd.Env = append(os.Environ(), fakeCloopEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake cloop: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	pid := cmd.Process.Pid

	// Poll until /proc publishes the symlinks (usually instant; bound to 2s).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/cwd"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	scoped := CloopRunPIDsInDir(cwdDir)
	if !containsPID(scoped, pid) {
		t.Fatalf("CloopRunPIDsInDir(%q) = %v; want to contain pid %d", cwdDir, scoped, pid)
	}

	other := CloopRunPIDsInDir(otherDir)
	if containsPID(other, pid) {
		t.Fatalf("CloopRunPIDsInDir(%q) returned pid %d that lives in %q — project scoping broken", otherDir, pid, cwdDir)
	}

	all := AllCloopRunPIDs()
	if !containsPID(all, pid) {
		t.Fatalf("AllCloopRunPIDs() = %v; want to contain pid %d", all, pid)
	}

	// IsCloopRunningInDir is a thin wrapper — check it stays in sync.
	if !IsCloopRunningInDir(cwdDir) {
		t.Fatalf("IsCloopRunningInDir(%q) = false; want true (pid %d)", cwdDir, pid)
	}
	if IsCloopRunningInDir(otherDir) {
		t.Fatalf("IsCloopRunningInDir(%q) = true; want false (pid %d lives in %q)", otherDir, pid, cwdDir)
	}
}

func containsPID(list []int, pid int) bool {
	for _, p := range list {
		if p == pid {
			return true
		}
	}
	return false
}

// copyExecutable performs a byte-for-byte copy of src to dst and chmods dst
// to 0o755 so the test child can exec it. Used in lieu of a symlink because
// /proc/PID/exe resolves symlinks back to the real binary, which would
// defeat the basename check the matcher relies on.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
