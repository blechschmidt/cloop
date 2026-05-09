package multiui

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"
)

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
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep binary not found: %v", err)
	}

	// Build a symlink named "cloop" pointing at /usr/bin/sleep so the
	// /proc/PID/exe basename check accepts the child. We then invoke it
	// via that symlink, which also makes argv[0] read "cloop".
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
	if err := os.Symlink(sleepBin, fakeCloop); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Spawn ./cloop run 30 — argv contains "run" and the cwd is cwdDir.
	cmd := exec.Command(fakeCloop, "run", "30")
	cmd.Dir = cwdDir
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
	i := sort.SearchInts(append([]int(nil), sortedCopy(list)...), pid)
	if i < len(list) && sortedCopy(list)[i] == pid {
		return true
	}
	for _, p := range list {
		if p == pid {
			return true
		}
	}
	return false
}

func sortedCopy(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	return out
}
