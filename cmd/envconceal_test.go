package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// envConcealRole names the part a re-executed test binary plays in
// TestAWrappedHarnessCannotReadTheWorkspaceToken.
const envConcealRole = "CLOOP_TEST_ENV_CONCEAL_ROLE"

// envConcealCanary is the forge token the wrapper is started with.
const envConcealCanary = "ghs_EnvConcealCanary" + "0123456789abcdefghij"

// TestAWrappedHarnessCannotReadTheWorkspaceToken: on Kubernetes, a push
// write-back's forge token reaches `cloop workspace writeback` in its
// environment, and the harness it wraps is its child, running as the same
// user. Unsetting the variable changes Go's copy only; the kernel kept serving
// the block the wrapper was started with at /proc/<pid>/environ, where the
// harness could read the token (Task 20424). The wrapper hides that block
// before spawning anything. The control — the token unset and nothing more —
// shows the copy is there to be read, so the assertion cannot pass by reading
// nothing at all.
func TestAWrappedHarnessCannotReadTheWorkspaceToken(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/<pid>/environ is Linux's")
	}
	if role := os.Getenv(envConcealRole); role != "" {
		concealProbe(role)
		return
	}
	for _, tc := range []struct {
		role        string
		wantVisible bool
	}{
		{"unset-only", true},
		{"wrapper", false},
	} {
		out := runAsSameUnprivilegedUser(t, tc.role)
		visible := strings.Contains(out, "TOKEN-VISIBLE")
		if !visible && !strings.Contains(out, "TOKEN-HIDDEN") {
			t.Fatalf("%s: the probe reported nothing:\n%s", tc.role, out)
		}
		if visible != tc.wantVisible {
			t.Errorf("%s: a child of the process read the token from its environ = %v, want %v:\n%s",
				tc.role, visible, tc.wantVisible, out)
		}
	}
}

// concealProbe is the re-executed binary: it takes the credential as the
// wrapper does (or only unsets it, for the control), then has a child — the
// harness's position — read its environ.
func concealProbe(role string) {
	if role == "wrapper" {
		_ = takeWorkspaceCredential()
	} else {
		_ = os.Unsetenv(kubernetes.EnvWorkspaceToken)
	}
	out, _ := exec.Command("sh", "-c", fmt.Sprintf("cat /proc/%d/environ 2>&1", os.Getpid())).CombinedOutput()
	if strings.Contains(string(out), envConcealCanary) {
		fmt.Println("TOKEN-VISIBLE")
	} else {
		fmt.Println("TOKEN-HIDDEN")
	}
}

// runAsSameUnprivilegedUser runs this test binary in role, as a user without
// CAP_SYS_PTRACE — this one, or nobody's uid when the suite runs as root, which
// reads every process's environment — and returns what it printed.
func runAsSameUnprivilegedUser(t *testing.T, role string) string {
	t.Helper()
	bin := os.Args[0]
	var attr *syscall.SysProcAttr
	// Not t.TempDir, whose parent only its creator may enter.
	dir, err := os.MkdirTemp("", "cloop-envconceal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if os.Geteuid() == 0 {
		// The test binary sits in a directory only root can enter.
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		bin = filepath.Join(dir, "probe.test")
		copyExecutable(t, os.Args[0], bin)
		attr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	}
	cmd := exec.Command(bin, "-test.run", "^TestAWrappedHarnessCannotReadTheWorkspaceToken$", "-test.v")
	cmd.Dir = dir
	cmd.SysProcAttr = attr
	cmd.Env = append(os.Environ(), envConcealRole+"="+role,
		kubernetes.EnvWorkspaceToken+"="+envConcealCanary, "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s probe: %v\n%s", role, err, out)
	}
	return string(out)
}

func copyExecutable(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}
