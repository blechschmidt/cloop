package container

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Supported container runtime names. Both speak a compatible enough CLI that
// one argv builder covers them; anything else is rejected rather than
// hopefully attempted, because the argv *is* the security boundary and we
// cannot reason about flags a third runtime may interpret differently.
const (
	RuntimePodman = "podman"
	RuntimeDocker = "docker"
)

// supportedRuntimes is the allowlist, in auto-detection preference order.
//
// Podman is preferred over Docker because a rootless podman run is confined
// by a user namespace as well as by the flags we pass: even a container
// escape lands on an unprivileged host user. Docker's default socket grants
// its clients root-equivalent access to the host, so it is the fallback, not
// the first choice.
var supportedRuntimes = []string{RuntimePodman, RuntimeDocker}

// Runtime is a resolved container runtime binary.
type Runtime struct {
	// Name is one of the Runtime* constants.
	Name string
	// Path is the absolute path to the binary, resolved once at detection
	// so a later PATH change cannot swap the binary out from under a run.
	Path string
	// Rootless reports whether workloads will run in a user namespace owned
	// by an unprivileged host user. It changes the UID mapping strategy:
	// see buildRunArgs.
	Rootless bool
}

// String renders the runtime for logs and error messages.
func (r Runtime) String() string {
	if r.Name == "" {
		return "<none>"
	}
	if r.Rootless {
		return r.Name + " (rootless)"
	}
	return r.Name
}

// ErrNoRuntime is returned when no supported container runtime is installed.
// Tests use errors.Is against it to skip cleanly.
var ErrNoRuntime = errors.New("container: no container runtime found")

// DetectRuntime resolves the container runtime to use.
//
// preferred may be a bare name ("podman", "docker") or an absolute path to
// one of those binaries. An empty preferred auto-detects in
// supportedRuntimes order. A name outside the allowlist is an error: config
// must not be able to point cloop at an arbitrary executable, since that
// executable is invoked with the workload's environment (which holds the
// caller's secrets).
func DetectRuntime(preferred string) (Runtime, error) {
	preferred = strings.TrimSpace(preferred)

	if preferred != "" {
		name := preferred
		if filepath.IsAbs(preferred) || strings.ContainsRune(preferred, os.PathSeparator) {
			name = filepath.Base(preferred)
		}
		if !isSupportedRuntime(name) {
			return Runtime{}, fmt.Errorf(
				"container: unsupported runtime %q — set executors.container.runtime to one of: %s",
				preferred, strings.Join(supportedRuntimes, ", "))
		}
		path, err := exec.LookPath(preferred)
		if err != nil {
			return Runtime{}, fmt.Errorf(
				"%w: configured runtime %q is not installed or not on PATH (%v) — install it or change executors.container.runtime",
				ErrNoRuntime, preferred, err)
		}
		return Runtime{Name: name, Path: path, Rootless: isRootless(name)}, nil
	}

	var tried []string
	for _, name := range supportedRuntimes {
		path, err := exec.LookPath(name)
		if err != nil {
			tried = append(tried, name)
			continue
		}
		return Runtime{Name: name, Path: path, Rootless: isRootless(name)}, nil
	}
	return Runtime{}, fmt.Errorf(
		"%w: none of %s are installed — install podman (preferred, rootless) or docker, "+
			"or bind this project to a different executor",
		ErrNoRuntime, strings.Join(tried, ", "))
}

// isSupportedRuntime reports whether name is on the allowlist.
func isSupportedRuntime(name string) bool {
	for _, s := range supportedRuntimes {
		if s == name {
			return true
		}
	}
	return false
}

// isRootless reports whether runs will be rootless.
//
// Podman is rootless exactly when invoked by a non-root user — it has no
// daemon, so the caller's identity is the container's identity. Docker
// delegates to a daemon that is normally root-owned, so a non-root client
// says nothing about the privileges the workload gets; we deliberately do
// not claim rootlessness there even when rootless dockerd is in use, because
// over-claiming isolation is the dangerous direction to be wrong in.
func isRootless(name string) bool {
	return name == RuntimePodman && os.Geteuid() != 0
}

// cliResult is the outcome of one runtime CLI invocation.
type cliResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runCLI invokes the runtime binary and collects its output.
//
// env, when non-nil, replaces the child environment entirely — that is how
// secret values reach a `--env NAME` passthrough without ever appearing in
// argv (and therefore without appearing in the host's process table).
//
// A non-zero exit is not an error: callers frequently need to distinguish
// "the runtime said no" (parse stderr, produce an actionable message) from
// "we could not invoke the runtime at all".
func runCLI(ctx context.Context, rt Runtime, env []string, args ...string) (cliResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, rt.Path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if env != nil {
		cmd.Env = env
	}

	err := cmd.Run()
	res := cliResult{Stdout: stdout.String(), Stderr: stderr.String()}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("container: invoke %s %s: %w", rt.Name, args[0], err)
	}
	return res, nil
}

// runCLIStdin is runCLI with stdin fed from a string, for `build --file -`.
//
// Piping the Dockerfile rather than writing it into the build context is the
// point: a Dockerfile on disk inside the context directory is itself part of
// the context, and a build that ships a file the operator never reviewed to a
// daemon is exactly the shape this driver exists to avoid.
//
// The environment is deliberately not overridable. Unlike `run`, a build has no
// `--env NAME` passthrough to satisfy, so there is nothing legitimate to give
// it — and a build that inherited the control plane's environment would put
// every provider API key one `RUN env` away from a repo-supplied command.
func runCLIStdin(ctx context.Context, rt Runtime, stdin string, args ...string) (cliResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, rt.Path, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	// Rootless podman resolves its storage and runtime dirs from these; without
	// them a build under a systemd unit fails with an unrelated-looking
	// "cannot find UID/GID" rather than building.
	for _, k := range []string{"XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "CONTAINERS_STORAGE_CONF", "DOCKER_HOST"} {
		if v, ok := os.LookupEnv(k); ok {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := cliResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("container: invoke %s %s: %w", rt.Name, args[0], err)
	}
	return res, nil
}

// shortHash returns a 16-hex-character digest of s, used to content-address
// derived sandbox images. Truncated deliberately: it is a cache key, and a
// 64-character image tag is unreadable in `podman images` output.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// commandContext builds a runtime CLI command whose lifetime is bound to
// ctx. Used for the long-lived `logs --follow` follower, where the caller
// needs the *os.Cmd itself to wire up pipes rather than buffered output.
func commandContext(ctx context.Context, path string, args ...string) *exec.Cmd {
	if ctx == nil {
		ctx = context.Background()
	}
	return exec.CommandContext(ctx, path, args...)
}

// runCLITimeout is runCLI with a bounded deadline, for the short control
// commands (version, inspect, kill, rm) where hanging forever is never the
// right answer. It deliberately does not apply to `logs -f` or `wait`, which
// are long-lived by design.
func runCLITimeout(ctx context.Context, rt Runtime, d time.Duration, args ...string) (cliResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	tctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	res, err := runCLI(tctx, rt, nil, args...)
	if err != nil && tctx.Err() != nil && ctx.Err() == nil {
		return res, fmt.Errorf("container: %s %s timed out after %s: %w", rt.Name, args[0], d, tctx.Err())
	}
	return res, err
}

// firstLine returns s trimmed to its first non-empty line, for turning a
// multi-line runtime error into a one-line message.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
