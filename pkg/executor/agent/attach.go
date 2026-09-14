package agent

// attach.go is the device half of interactive attach (Task 20265): the agent
// runs the operator's command beside the workload and streams it back over the
// session the device already holds open.
//
// # What "inside the sandbox" means here
//
// For the container and Kubernetes drivers the sandbox is a namespace and
// attach enters it. For a remote agent the sandbox *is the device* — that is
// what IsolationRemote means, and it is why the hub is willing to call this
// isolating at all. So a session here is a process on the device, started in
// the workload's own directory and with nothing else inherited. It is not a
// shell on the control plane, which is the property that matters.
//
// # Read-only is enforced here, not at the hub
//
// A session opened without Stdin gets no input descriptor: the command's stdin
// is /dev/null, and any attach_data frame that arrives for it is dropped. The
// hub also refuses to send one. Two independent refusals, because the one that
// counts is the one on the machine where the command runs — a hub that was
// compromised or simply buggy must not be able to talk its way into a writable
// terminal.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/ptyshell"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// maxAgentAttachSessions bounds concurrent terminals on one device.
//
// Lower than the hub's per-executor ceiling on purpose. The hub's limit is a
// policy an operator can widen; this is the device protecting itself, and an
// edge device is the machine least able to absorb a mistake — it is frequently
// a small board whose whole job is the one workload it is running.
const maxAgentAttachSessions = 8

// attachProc is one live terminal on this device.
type attachProc struct {
	id       string
	handleID string

	cmd   *exec.Cmd
	pty   *ptyshell.Session // nil when running on pipes
	stdin io.WriteCloser    // nil for a read-only session

	closeOnce sync.Once
	done      chan struct{}
}

// attachTable is the agent's registry of live terminals.
type attachTable struct {
	mu    sync.Mutex
	procs map[string]*attachProc
}

func (t *attachTable) add(p *attachProc) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.procs == nil {
		t.procs = make(map[string]*attachProc)
	}
	if len(t.procs) >= maxAgentAttachSessions {
		return false
	}
	t.procs[p.id] = p
	return true
}

func (t *attachTable) get(id string) *attachProc {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.procs[id]
}

func (t *attachTable) remove(id string) *attachProc {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.procs[id]
	delete(t.procs, id)
	return p
}

func (t *attachTable) drain() []*attachProc {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*attachProc, 0, len(t.procs))
	for _, p := range t.procs {
		out = append(out, p)
	}
	t.procs = nil
	return out
}

// stop ends the terminal and reaps the process.
func (p *attachProc) stop() {
	p.closeOnce.Do(func() {
		close(p.done)
		if p.stdin != nil {
			_ = p.stdin.Close()
		}
		if p.pty != nil {
			_ = p.pty.Close()
			return
		}
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
			go func(c *exec.Cmd) { _ = c.Wait() }(p.cmd)
		}
	})
}

// handleAttachOpen starts an interactive command beside a running workload.
func (a *Agent) handleAttachOpen(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	payload, err := remote.DecodeAttachOpen(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	wl, ok := a.workload(frame.Handle)
	if !ok {
		a.replyError(ctx, sess, frame.ID, remote.CodeUnknownHandle,
			fmt.Sprintf("no workload %s on this agent", frame.Handle))
		return
	}
	if wl.snapshot().State.Terminal() {
		a.replyError(ctx, sess, frame.ID, remote.CodeUnknownHandle,
			fmt.Sprintf("workload %s has finished", frame.Handle))
		return
	}

	workDir := wl.attachDir()
	if workDir == "" {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol,
			fmt.Sprintf("workload %s has no working directory yet", frame.Handle))
		return
	}

	argv := payload.Command
	if len(argv) == 0 {
		argv = defaultAgentShell()
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = workDir
	cmd.Env = attachEnv(workDir, payload)

	proc := &attachProc{id: payload.SessionID, handleID: frame.Handle, cmd: cmd, done: make(chan struct{})}

	gotTTY := false
	if payload.TTY && payload.Stdin && ptyshell.Supported() {
		// A pty only earns its complexity when the operator can type. A
		// read-only session on pipes reads identically.
		ps, perr := ptyshell.Start(cmd, payload.Rows, payload.Cols)
		if perr != nil {
			a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, perr.Error())
			return
		}
		proc.pty, proc.stdin, gotTTY = ps, nopWriteCloser{ps.Master}, true
		a.pumpAttach(sess, proc, ps.Master, wl.redactor())
	} else {
		out, perr := a.startPipeAttach(proc, payload)
		if perr != nil {
			a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, perr.Error())
			return
		}
		a.pumpAttach(sess, proc, out, wl.redactor())
	}

	if !a.attaches.add(proc) {
		proc.stop()
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol,
			fmt.Sprintf("this device already has %d interactive sessions open", maxAgentAttachSessions))
		return
	}
	a.reply(ctx, sess, remote.TypeAttachOpened, frame.ID, frame.Handle, remote.AttachOpenedPayload{
		SessionID: payload.SessionID,
		TTY:       gotTTY,
	})
}

// startPipeAttach wires a non-pty session and starts it.
func (a *Agent) startPipeAttach(proc *attachProc, payload remote.AttachOpenPayload) (io.Reader, error) {
	cmd := proc.cmd
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if payload.Stdin {
		if proc.stdin, err = cmd.StdinPipe(); err != nil {
			return nil, err
		}
	} else {
		// Explicitly /dev/null rather than left nil: an exec.Cmd with a nil
		// Stdin already gets the null device, but saying so is what makes the
		// read-only guarantee legible at the place it is enforced.
		devNull, oerr := os.Open(os.DevNull)
		if oerr != nil {
			return nil, oerr
		}
		cmd.Stdin = devNull
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return io.MultiReader(stdout, stderr), nil
}

// pumpAttach streams the command's output back to the control plane until it
// ends, then reports the close.
func (a *Agent) pumpAttach(sess *deviceSession, proc *attachProc, out io.Reader, red *redact.Set) {
	// Scrubbed on the device, before the bytes leave it. The hub scrubs again
	// with the same set, but this is the half that matters: a credential that
	// never crosses the wire cannot be read off it.
	src := executor.RedactAttachOutput(out, red)

	go func() {
		defer func() {
			// A panic in one terminal must not take the agent down; it is
			// running somebody's whole edge device.
			if r := recover(); r != nil {
				a.cfg.logf("attach session %s: panic: %v", proc.id, r)
			}
		}()
		buf := make([]byte, remote.MaxAttachChunk)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				a.sendAttach(sess, proc.handleID, remote.TypeAttachData,
					remote.AttachDataPayload{SessionID: proc.id, Data: chunk})
			}
			if err != nil {
				break
			}
			select {
			case <-proc.done:
				return
			default:
			}
		}
		exitCode := -1
		if proc.cmd != nil {
			if werr := proc.cmd.Wait(); werr != nil {
				var ee *exec.ExitError
				if errors.As(werr, &ee) {
					exitCode = ee.ExitCode()
				}
			} else {
				exitCode = 0
			}
		}
		a.attaches.remove(proc.id)
		proc.stop()
		a.sendAttach(sess, proc.handleID, remote.TypeAttachClose, remote.AttachClosePayload{
			SessionID: proc.id,
			Reason:    "command exited",
			ExitCode:  exitCode,
		})
	}()
}

// handleAttachData delivers keystrokes, or drops them for a read-only session.
func (a *Agent) handleAttachData(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	payload, err := remote.DecodeAttachData(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	proc := a.attaches.get(payload.SessionID)
	if proc == nil {
		return
	}
	if proc.stdin == nil {
		// The refusal that counts. A hub that sent input to a read-only
		// session is either buggy or lying, and either way the device is the
		// last place able to say no.
		a.cfg.logf("attach session %s: dropped %d bytes of input on a read-only session",
			payload.SessionID, len(payload.Data))
		return
	}
	if _, werr := proc.stdin.Write(payload.Data); werr != nil {
		proc.stop()
	}
}

// handleAttachResize reports new geometry to the terminal.
func (a *Agent) handleAttachResize(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	payload, err := remote.DecodeAttachResize(frame)
	if err != nil {
		return
	}
	if proc := a.attaches.get(payload.SessionID); proc != nil && proc.pty != nil {
		_ = proc.pty.Resize(payload.Rows, payload.Cols)
	}
}

// handleAttachClose ends a terminal at the operator's request.
func (a *Agent) handleAttachClose(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	payload, err := remote.DecodeAttachClose(frame)
	if err != nil {
		return
	}
	if proc := a.attaches.remove(payload.SessionID); proc != nil {
		proc.stop()
	}
}

// closeAttachSessions ends every terminal on this device. Called when the
// session to the control plane drops: nobody is left to read the output, and a
// shell left running would hold the workload's credentials unattended.
func (a *Agent) closeAttachSessions() {
	for _, p := range a.attaches.drain() {
		p.stop()
	}
}

// sendAttach writes one attach frame, dropping it if the link is gone.
func (a *Agent) sendAttach(sess *deviceSession, handle string, t remote.FrameType, payload any) {
	frame, err := remote.NewFrame(t, "", handle, payload)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), attachSendTimeout)
	defer cancel()
	_ = sess.conn.WriteFrame(ctx, frame)
}

// attachEnv is the environment for a session command on the device.
//
// Deliberately minimal, and deliberately *not* the workload's environment. The
// workload holds the project's leased credentials; a terminal that inherited
// them would turn "look at what the task is doing" into "read the task's
// secrets", and the operator who may attach is not always the one who may hold
// the credential.
func attachEnv(workDir string, payload remote.AttachOpenPayload) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"PWD=" + workDir,
	}
	term := ""
	for _, kv := range payload.Env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "TERM" {
			term = v
		}
	}
	if payload.TTY {
		if term == "" {
			term = "xterm-256color"
		}
		env = append(env, "TERM="+term)
	}
	return env
}

// defaultAgentShell is what a session runs when the hub named no command.
func defaultAgentShell() []string {
	if sh := strings.TrimSpace(os.Getenv("SHELL")); sh != "" {
		return []string{sh}
	}
	return []string{"/bin/sh"}
}

// nopWriteCloser lets the pty master serve as stdin without Close racing the
// pty teardown — attachProc.stop closes the pty itself.
type nopWriteCloser struct{ w io.Writer }

func (n nopWriteCloser) Write(p []byte) (int, error) { return n.w.Write(p) }
func (n nopWriteCloser) Close() error                { return nil }

// attachSendTimeout bounds one outbound attach frame from the device.
//
// Shorter than the hub's, because the failure it guards against is different:
// a device whose uplink has stalled should stop trying and let the session die,
// rather than accumulating goroutines each holding a chunk of a terminal nobody
// is reading.
const attachSendTimeout = 10 * time.Second

// recordAttachContext remembers what an interactive session needs: where to
// start, and what to scrub. Called once the Spec has been resolved and confined.
func (w *workload) recordAttachContext(workDir string, red *redact.Set) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.workDir = workDir
	w.redactSet = red
}

// attachDir returns the confined working directory, or "" before the start
// path has resolved one.
func (w *workload) attachDir() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.workDir
}

// redactor returns this workload's credential set.
func (w *workload) redactor() *redact.Set {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.redactSet
}
