package multiui

// The batched liveness index replaced a per-project /proc walk on the hub's
// two-second sweep, so the property that matters is not that it is fast — the
// benchmark in pkg/ui covers that — but that it answers *the same question*.
// Two implementations of "is a run executing here?" that disagree would show up
// as a project stuck on the wrong Run/Stop button, or as stale-run recovery
// firing at a live run.
//
// So these tests assert equivalence against IsCloopRunningInDir rather than
// against hand-written expectations: whichever way the rules move, the two
// have to move together.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// startFakeRun spawns a process that looks like `cloop run` with its working
// directory set to cwd, and waits for /proc to publish its symlinks. It returns
// the PID.
func startFakeRun(t *testing.T, root, cwd string) int {
	t.Helper()
	selfBin, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", binDir, err)
	}
	fakeCloop := filepath.Join(binDir, "cloop")
	if _, err := os.Stat(fakeCloop); err != nil {
		if err := copyExecutable(selfBin, fakeCloop); err != nil {
			t.Skipf("cannot stage fake cloop binary: %v", err)
		}
	}

	cmd := exec.Command(fakeCloop, "run")
	cmd.Dir = cwd
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
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/cwd"); err == nil {
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("/proc never published cwd for pid %d", pid)
	return 0
}

// TestScanRunningDirsMatchesPerProjectWalk is the equivalence assertion, run
// over the shapes the hub actually registers: the project itself, an unrelated
// sibling, the parent that contains both, a nested worktree, and a project
// reached through a symlink.
func TestScanRunningDirsMatchesPerProjectWalk(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("liveness is read from /proc")
	}
	root := t.TempDir()
	project := filepath.Join(root, "project")
	sibling := filepath.Join(root, "sibling")
	worktree := filepath.Join(project, ".cloop", "worktrees", "task-42")
	for _, d := range []string{project, sibling, worktree} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	// A project registered through a symlink: /proc reports the resolved path,
	// so this is the case that needs Contains to resolve before giving up.
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(project, linked); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// A run in the worktree, not in the project root — the arrangement parallel
	// tasks produce, and the reason the index records ancestors at all.
	pid := startFakeRun(t, root, worktree)

	ix := ScanRunningDirs()
	if !ix.Any() {
		t.Fatalf("ScanRunningDirs found no runs while pid %d is running in %s", pid, worktree)
	}

	for _, dir := range []string{project, sibling, worktree, linked, root} {
		want := IsCloopRunningInDir(dir)
		if got := ix.Contains(dir); got != want {
			t.Errorf("Contains(%s) = %v, IsCloopRunningInDir = %v — the batched index "+
				"and the per-project walk disagree", dir, got, want)
		}
	}

	// Pin the expectations too, so a change that broke *both* in the same
	// direction could not pass the equivalence check above.
	if !ix.Contains(project) {
		t.Error("a run in a project's worktree must count as a run in the project")
	}
	if !ix.Contains(linked) {
		t.Error("a project registered through a symlink must resolve to the same run (Task 20153)")
	}
	if ix.Contains(sibling) {
		t.Error("a run in one project must not count as a run in its sibling")
	}
}

// TestScanRunningDirsEmptyWithoutRuns covers the case the hub spends almost all
// of its time in, and the one the fast path depends on: no runs anywhere means
// no project is running, decided without resolving a single path.
func TestScanRunningDirsEmptyWithoutRuns(t *testing.T) {
	var empty RunningDirs
	if empty.Any() {
		t.Error("the zero RunningDirs must report no runs")
	}
	if empty.Contains("/anything") {
		t.Error("the zero RunningDirs must report every project as not running")
	}
}
