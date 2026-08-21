package container

// smoke.go implements the end-to-end proof that a container executor works:
// run `cloop version` inside the sandbox and read the answer back.
//
// It is a real test of the whole path, not a probe of its parts. Preflight
// can report a present image, a responding runtime, and a writable workdir
// and the executor can still be broken — a cgroup delegation gap, an SELinux
// denial, a seccomp profile that blocks the harness's first syscall. All of
// those surface here and nowhere earlier.
//
// The binary under test is bind-mounted read-only from the control plane
// rather than assumed present in the image. That keeps the smoke test
// meaningful against any base image (alpine, debian, a half-built harness
// image) instead of only against one that already ships cloop — which is
// exactly the situation an operator is in while setting the executor up.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// SmokeTestResult is the outcome of a sandbox smoke test.
type SmokeTestResult struct {
	// Image is the sandbox image the test ran in.
	Image string `json:"image"`
	// Runtime describes the container runtime used.
	Runtime string `json:"runtime"`
	// ContainerName is the deterministic name that was used, so an operator
	// can correlate with runtime logs.
	ContainerName string `json:"container_name"`
	// Output is the workload's combined stdout+stderr, trimmed.
	Output string `json:"output"`
	// ExitCode is the workload's exit status.
	ExitCode int `json:"exit_code"`
	// Duration is the wall-clock time from start to reap.
	Duration time.Duration `json:"duration"`
	// MountedBinary is the host path bind-mounted at ContainerCloopPath,
	// empty when the image's own cloop was used.
	MountedBinary string `json:"mounted_binary,omitempty"`
}

// smokeTestTimeout bounds the whole smoke test. `cloop version` prints and
// exits; anything approaching this means the sandbox is wedged, and a CLI
// command that hangs forever is worse than one that reports a timeout.
const smokeTestTimeout = 2 * time.Minute

// SmokeTest runs `cloop version` inside the sandbox and returns what it
// printed.
//
// workDir is the project directory to bind-mount; empty uses a throwaway
// temporary directory, which is the right choice for testing the executor
// itself rather than a particular project.
//
// The control plane's own binary is mounted read-only at ContainerCloopPath
// so the test works against images that do not yet ship cloop. It is mounted
// read-only specifically so a compromised sandbox cannot rewrite the binary
// that the host will execute next.
func (e *Executor) SmokeTest(ctx context.Context, workDir string) (SmokeTestResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, smokeTestTimeout)
	defer cancel()

	result := SmokeTestResult{Image: e.opts.Image, Runtime: e.rt.String()}

	if workDir == "" {
		tmp, err := os.MkdirTemp("", "cloop-smoke-*")
		if err != nil {
			return result, fmt.Errorf("container: create smoke-test workdir: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		// The sandbox runs as a non-root UID; MkdirTemp is 0700 and owned by
		// the control-plane user, so widen it enough for that UID to write.
		if err := os.Chmod(tmp, 0o777); err != nil {
			return result, fmt.Errorf("container: prepare smoke-test workdir: %w", err)
		}
		workDir = tmp
	}

	var extra []mount
	if self, err := selfBinaryPath(); err == nil {
		extra = append(extra, mount{
			HostPath:   self,
			TargetPath: ContainerCloopPath,
			ReadOnly:   true,
		})
		result.MountedBinary = self
	}

	spec := executor.Spec{
		WorkDir: workDir,
		// Absolute path rather than bare "cloop": the mounted binary is at a
		// known location and may not be on the image's PATH.
		Argv: []string{ContainerCloopPath, "version"},
		Labels: map[string]string{
			"component": "smoke-test",
		},
		// Deliberately no Env: the smoke test must prove the sandbox runs a
		// binary, and doing it with an empty environment also proves no
		// host credentials are needed to get that far.
	}

	started := time.Now()
	handle, err := e.start(ctx, spec, extra)
	if err != nil {
		return result, err
	}
	result.ContainerName = ContainerName(mustAbs(workDir), handle.ID)

	lines, err := e.Stream(ctx, handle.ID)
	if err != nil {
		_ = e.Signal(context.WithoutCancel(ctx), handle.ID, executor.SignalKill)
		return result, fmt.Errorf("container: stream smoke test output: %w", err)
	}

	var sb strings.Builder
	var timedOut bool
collect:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break collect
			}
			sb.WriteString(line.Text)
		case <-ctx.Done():
			timedOut = true
			_ = e.Signal(context.WithoutCancel(ctx), handle.ID, executor.SignalKill)
			break collect
		}
	}
	result.Output = strings.TrimSpace(sb.String())
	result.Duration = time.Since(started)

	statusCtx, statusCancel := context.WithTimeout(context.WithoutCancel(ctx), shortCmdTimeout)
	defer statusCancel()
	status, statusErr := e.Status(statusCtx, handle.ID)
	if statusErr == nil {
		result.ExitCode = status.ExitCode
	}

	switch {
	case timedOut:
		return result, fmt.Errorf("container: smoke test timed out after %s — the sandbox started but never finished `cloop version`", smokeTestTimeout)
	case statusErr != nil:
		return result, fmt.Errorf("container: smoke test status: %w", statusErr)
	case status.State == executor.StateExited && status.ExitCode == 0:
		return result, nil
	case status.ExitCode == 127:
		return result, fmt.Errorf(
			"container: the sandbox could not execute %s (exit 127). The image %s is missing a "+
				"dynamic loader or libraries the cloop binary needs — use a glibc-based image, or "+
				"build a harness image from the documented contract. Output: %s",
			ContainerCloopPath, e.opts.Image, truncate(result.Output, 400))
	default:
		detail := status.Error
		if detail == "" {
			detail = truncate(result.Output, 400)
		}
		return result, fmt.Errorf("container: smoke test failed (state %s, exit %d): %s",
			status.State, status.ExitCode, detail)
	}
}

// selfBinaryPath returns the absolute, symlink-resolved path of the running
// executable so it can be bind-mounted into the sandbox.
func selfBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	info, err := os.Stat(exe)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("executable path is a directory")
	}
	return exe, nil
}

// mustAbs resolves p the same way start does, so a derived container name
// matches the one actually used.
func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// truncate bounds a message so a runaway workload's output cannot flood a
// terminal through an error string.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "… (truncated)"
}
