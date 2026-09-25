package remote_test

// Loopback regression test for Task 20337: a project that holds a secret grant
// must find the harness a device installed for itself, exactly as a project
// without one does.
//
// The difference between the two is only the shape of Spec.Env. Without a
// grant it is nil and the payload inherits the agent's environment, whose PATH
// EnsureHarnessPath has already extended with ~/.local/bin. With a grant the
// hub composes the lease's variables over a nil base, so Env is explicit and
// names no PATH — and cmd.Env replaces rather than adds. On the sgx edge device
// that difference failed every run of a granted project with
// `exec: "claude": executable file not found in $PATH`, immediately after the
// device had installed claude for it.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestLoopbackAGrantedPayloadFindsAPerUserHarness runs the same probe with and
// without a lease-shaped environment and requires the same answer.
//
// The probe is `command -v claude`, not `claude`: this suite runs on
// development hosts that have a real claude installed system-wide, and a probe
// that executed the name would, on a regression, start a real harness. The
// resolved path is also the sharper assertion — it distinguishes "found the
// harness the device installed" from "found some claude".
func TestLoopbackAGrantedPayloadFindsAPerUserHarness(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	harness := filepath.Join(home, ".local", "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(harness), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte("#!/bin/sh\necho stub\n"), 0o755); err != nil { //nolint:gosec — must be executable
		t.Fatal(err)
	}

	// The agent's PATH: a directory holding the tools the probe needs and no
	// claude, which is what a systemd unit's PATH looks like on a device that
	// has only a per-user install.
	bin := t.TempDir()
	for _, tool := range []string{"sh"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("no %s on this host", tool)
		}
		if err := os.Symlink(real, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)

	lb := newLoopback(t)
	ex := lb.executor(t)

	probe := func(t *testing.T, env []string) string {
		t.Helper()
		// An absolute sh, so starting the probe does not itself depend on the
		// PATH under test; only the name the probe resolves does.
		shell, err := filepath.EvalSymlinks(filepath.Join(bin, "sh"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := executor.Run(context.Background(), ex, executor.Spec{
			WorkDir: "granted-project",
			Argv:    []string{shell, "-c", "command -v claude || echo NOT-FOUND"},
			Env:     env,
		})
		if err != nil {
			t.Fatalf("Run: %v (output=%q)", err, res.Output)
		}
		return strings.TrimSpace(string(res.Output))
	}

	t.Run("without a grant the payload inherits", func(t *testing.T) {
		if got := probe(t, nil); got != harness {
			t.Fatalf("resolved claude to %q, want %s", got, harness)
		}
	})

	t.Run("with a grant it resolves the same harness", func(t *testing.T) {
		// Shaped as pkg/ui's applyLease shapes it: the lease's own variables
		// and nothing else — in particular, no PATH.
		got := probe(t, []string{
			"CLOOP_LEASE_DIR=/dev/shm/cloop-lease-e2e",
			"CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-not-a-real-token",
		})
		if got != harness {
			t.Fatalf("with an explicit environment claude resolved to %q, want %s — the "+
				"harness the device installed is invisible to every project that holds a "+
				"secret grant", got, harness)
		}
	})
}
