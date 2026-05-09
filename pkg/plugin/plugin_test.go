package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeScript writes a shell script that's executable and returns its path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRunCtx_TimeoutKillsHungPlugin: without the CommandContext timeout in
// RunCtx, a plugin that blocks (sleep 5) would pin the orchestrator until the
// process exited on its own. The context deadline must propagate the kill.
func TestRunCtx_TimeoutKillsHungPlugin(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, ".cloop", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeScript(t, pluginsDir, "hang", "sleep 5")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := RunCtx(ctx, dir, "hang", nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected RunCtx to return error after timeout, got nil")
	}
	if elapsed > 4*time.Second {
		t.Errorf("plugin took %v to terminate, expected <4s", elapsed)
	}
}

// TestRunCtx_HappyPath ensures normal plugins still work with the new
// context-aware codepath.
func TestRunCtx_HappyPath(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, ".cloop", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeScript(t, pluginsDir, "ok", "exit 0")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := RunCtx(ctx, dir, "ok", nil, nil); err != nil {
		t.Fatalf("happy-path plugin returned error: %v", err)
	}
}

// TestDescribe_TimeoutKillsBackgroundedGrandchild: the describe codepath
// captures stdout into a bytes.Buffer, which exec implements via a pipe +
// copy goroutine. If the script backgrounds a child that inherits the pipe
// fd, killing only the script leaves the grandchild alive holding the pipe
// open — Wait then blocks reading from the pipe until WaitDelay (2s) force-
// closes it, AND the grandchild leaks as an orphan. The pgroup kill on
// timeout reaps the entire tree.
func TestDescribe_TimeoutKillsBackgroundedGrandchild(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	// The grandchild writes its pid then sleeps long. The script sleeps too
	// so the timeout fires while everything is still running.
	body := `#!/bin/sh
if [ "$1" = "describe" ]; then
  sh -c 'echo $$ > "` + pidFile + `"; exec sleep 30' &
  # Wait for grandchild to record its pid before we ourselves block.
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "` + pidFile + `" ] && break
    sleep 0.05
  done
  sleep 30
fi
`
	script := filepath.Join(dir, "hang.sh")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	prev := describeTimeout
	describeTimeout = 500 * time.Millisecond
	defer func() { describeTimeout = prev }()

	if _, err := describe(script); err == nil {
		t.Fatal("expected describe to error on hung script, got nil")
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("grandchild pid file missing — script never reached background fork: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("invalid pid in marker file %q: %v", string(data), err)
	}

	// Give the kernel a beat to deliver SIGKILL through the pgroup, then
	// confirm the grandchild is gone. signal 0 returns ESRCH on a dead pid.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return // ESRCH — grandchild reaped, fix is working.
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Last resort: clean up the leaked process so the test host doesn't
	// accumulate sleep zombies on failure.
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("grandchild pid %d still alive after timeout — pgroup kill did not propagate", pid)
}

// TestDescribe_TimeoutOnHungScript: a plugin's describe subcommand must not
// be allowed to block indefinitely — that would freeze plugin enumeration
// (Discover → describe per file).
func TestDescribe_TimeoutOnHungScript(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "hang.sh", `if [ "$1" = "describe" ]; then sleep 30; fi`)
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}

	// Tighten the package-level timeout for the duration of this test so we
	// don't block the suite for the full 10s production default.
	prev := describeTimeout
	describeTimeout = 200 * time.Millisecond
	defer func() { describeTimeout = prev }()

	start := time.Now()
	_, err := describe(script)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected describe to error on hung script, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got: %v", err)
	}
	if elapsed > 4*time.Second {
		t.Errorf("describe took %v to terminate, expected ~timeout+grace", elapsed)
	}
}
