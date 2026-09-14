package container

// attach.go satisfies executor.Attacher for the container driver: an operator's
// shell inside a sandbox that is already running (Task 20265).
//
// # Why the CLI and not the runtime socket
//
// Everything else in this driver drives `docker`/`podman` as a subprocess, and
// attach follows. The alternative — speaking the Engine API over its unix
// socket to hijack /exec/{id}/start — would be a second, privileged way into
// the same daemon, with its own authentication story, its own rootless-podman
// quirks, and its own reason to hold a socket handle open in the hub. The
// subprocess path inherits the credential and the connection the driver already
// proved it has in HealthCheck.
//
// # The four shapes of a session
//
// Read-only and writable are genuinely different invocations, not one
// invocation with an output discarded:
//
//	read-only + tty   `exec -t`        pty inside the sandbox, no input fd
//	read-only + pipe  `exec`           no tty, no input fd
//	writable  + tty   `exec -i -t`     needs a real pty *here* — see ptyshell
//	writable  + pipe  `exec -i`        stdin is a pipe
//
// The middle column is the point. A read-only session does not get an input
// channel that the hub then declines to use; the exec'd process has no stdin at
// all, so read-only is enforced by the runtime rather than by this file
// remembering to check a flag.

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/ptyshell"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// attachProcessEnv is the environment for the runtime CLI subprocess itself —
// not for the command inside the sandbox.
//
// Deliberately a short allowlist rather than os.Environ(). The hub's own
// environment holds provider API keys and, on a hub that granted itself a
// lease, credential paths; handing all of it to a subprocess an operator can
// name the argv of is a way to read the control plane's secrets through a
// sandbox shell. What is left is what docker and rootless podman genuinely need
// to find their daemon and storage.
func attachProcessEnv() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	for _, k := range []string{"XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
		"CONTAINERS_STORAGE_CONF", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// Attach implements executor.Attacher.
func (e *Executor) Attach(ctx context.Context, req executor.AttachRequest) (executor.AttachConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec, err := e.lookup(req.HandleID)
	if err != nil {
		return nil, err
	}

	rec.mu.Lock()
	running := rec.state == executor.StateRunning || rec.state == executor.StatePending
	name := rec.name
	rec.mu.Unlock()
	if !running {
		return nil, fmt.Errorf("%w: container %s is not running", executor.ErrAttachClosed, name)
	}

	// The same set the log bus scrubs with. Taking it from the bus rather than
	// rebuilding it from a Spec is deliberate: a rehydrated handle has no Spec
	// any more, and a credential that is filtered out of the log stream must
	// not reappear the moment someone opens a terminal on the same workload.
	redactor := rec.bus.Redactor()

	args := []string{"exec"}
	if req.Stdin {
		args = append(args, "-i")
	}
	if req.TTY {
		args = append(args, "-t")
	}
	for _, kv := range attachEnv(req) {
		args = append(args, "--env", kv)
	}
	args = append(args, name)
	args = append(args, req.Argv()...)

	// A detached context, so closing the operator's browser tab does not have
	// to be the thing that ends the session — Close does, explicitly. Binding
	// the exec to the request context would kill a session the instant an HTTP
	// handler returned, which for a WebSocket upgrade is immediately.
	execCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	cmd := commandContext(execCtx, e.rt.Path, args...)
	cmd.Env = attachProcessEnv()

	conn, err := startAttach(cmd, req, redactor, cancel)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("container: attach to %s: %w", name, err)
	}
	return conn, nil
}

// startAttach wires the runtime subprocess to the caller, choosing a pty only
// when one is both wanted and usable.
func startAttach(cmd *exec.Cmd, req executor.AttachRequest, redactor *redact.Set, cancel context.CancelFunc) (executor.AttachConn, error) {
	// A pty is only needed when the operator can type. Without -i the runtime
	// is content with a pipe on its own stdin and still allocates a terminal
	// inside the sandbox, so a read-only TTY session costs nothing here.
	if req.TTY && req.Stdin && ptyshell.Supported() {
		sess, err := ptyshell.Start(cmd, req.Rows, req.Cols)
		if err != nil {
			return nil, err
		}
		out := executor.RedactAttachOutput(sess.Master, redactor)
		return executor.NewAttachConn(out, sess.Master, sess.Resize, func() error {
			cancel()
			return sess.Close()
		}), nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	// One reader for both: an operator debugging a sandbox wants the error
	// interleaved with the output that preceded it, and a terminal has one
	// screen.
	merged := mergeReaders(stdout, stderr)

	var stdin io.WriteCloser
	if req.Stdin {
		if stdin, err = cmd.StdinPipe(); err != nil {
			return nil, err
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	out := executor.RedactAttachOutput(merged, redactor)
	return executor.NewAttachConn(out, stdin,
		// No pty means no window size to report. Not an error: a caller that
		// always sends geometry should not have to know which kind it opened.
		nil,
		func() error {
			cancel()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			go func() { _ = cmd.Wait() }()
			return nil
		}), nil
}

// attachEnv is the environment handed to the command *inside* the sandbox.
//
// Only TERM, and only when a terminal was asked for. This is not the place to
// propagate the operator's environment: the sandbox's own variables are the
// workload's, including its leased credentials, and merging a second set in
// would be a way to smuggle values across the boundary in the one direction
// this driver does not otherwise allow.
func attachEnv(req executor.AttachRequest) []string {
	var out []string
	seen := false
	for _, kv := range req.Env {
		if k, _, ok := strings.Cut(kv, "="); ok && k == "TERM" {
			out = append(out, kv)
			seen = true
		}
	}
	if req.TTY && !seen {
		out = append(out, "TERM=xterm-256color")
	}
	return out
}

// mergeReaders concatenates two live streams into one.
//
// io.MultiReader would serialise them — nothing from stderr until stdout hits
// EOF — which for a live session means every error arrives after the command
// has already exited. A pipe fed by two copies interleaves at write granularity,
// which is what a terminal shows anyway.
func mergeReaders(a, b io.Reader) io.Reader {
	pr, pw := io.Pipe()
	done := make(chan struct{}, 2)
	copyOne := func(r io.Reader) {
		defer func() { done <- struct{}{} }()
		_, _ = io.Copy(pw, r)
	}
	go copyOne(a)
	go copyOne(b)
	go func() {
		<-done
		<-done
		_ = pw.Close()
	}()
	return pr
}
