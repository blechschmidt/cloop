package executor

// attach.go is the optional interactive-session capability: getting a shell
// inside a workload that is already running (Task 20265).
//
// # Why this is not just another Spec field
//
// Start/Signal/Status/Stream are the lifecycle of a workload the hub dispatched.
// Attach is the opposite direction: a human, mid-run, asking to be let into a
// boundary the rest of this package exists to keep closed. So it is an optional
// interface rather than a method on Executor — a driver that cannot safely offer
// it must be able to *not offer it*, and `_, ok := ex.(Attacher)` is the only
// form where "cannot" is expressible. The alternative, a method returning
// ErrNotSupported on three of four drivers, makes the unsafe case the default
// and the refusal a runtime detail.
//
// # The gate is here, not at the call site
//
// AttachTarget is the single funnel: it decides whether *this* executor may be
// entered at all, before any driver code runs. Putting that in the hub route
// would mean the CLI, a future MCP tool and any test helper each re-derive it,
// and the one that forgets grants a shell on the control-plane host. The rule it
// encodes is narrow and worth stating plainly: only an isolating driver can be
// attached to, because on a non-isolating one there is no sandbox to enter and
// the "sandbox shell" would be a shell on the hub.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// Attach errors. Callers distinguish them with errors.Is: the hub maps the
// refusals to 403 and the absences to 501/404, and the CLI prints the
// remediation that fits.
var (
	// ErrAttachUnsupported means the driver has no interactive session
	// capability — it does not implement Attacher.
	ErrAttachUnsupported = errors.New("executor: attach not supported by this executor")

	// ErrAttachNoSandbox means the workload has no boundary to enter: it runs
	// as a process on the hub's own machine. Attaching would be a shell on the
	// control plane, which is the one thing this package promises never
	// happens.
	ErrAttachNoSandbox = errors.New("executor: attach refused: workload runs on the host, not in a sandbox")

	// ErrAttachReadOnly means the session was opened without write authority
	// and something tried to send stdin anyway.
	ErrAttachReadOnly = errors.New("executor: attach session is read-only")

	// ErrAttachHandleUnknown means the handle is not running on this executor.
	ErrAttachHandleUnknown = errors.New("executor: attach: unknown handle")

	// ErrAttachBusy means the per-executor concurrent-session ceiling is
	// reached. It is a capacity refusal, not an authorization one.
	ErrAttachBusy = errors.New("executor: attach: too many concurrent sessions on this executor")

	// ErrAttachClosed means the session ended — the workload exited, the
	// sandbox was removed, or the transport dropped.
	ErrAttachClosed = errors.New("executor: attach session closed")
)

// DefaultMaxAttachSessionsPerExecutor bounds simultaneous interactive sessions
// against one executor.
//
// The ceiling is small on purpose. Each session is a live exec process inside
// the sandbox holding a pty and a transport, so the resource being protected is
// the *workload's* machine, not the hub's; a debugging tool that can be pointed
// at a struggling sandbox forty times over is a denial-of-service primitive
// against the thing it is meant to diagnose. Four is enough for an operator plus
// a colleague plus a stale session that has not timed out yet.
const DefaultMaxAttachSessionsPerExecutor = 4

// AttachRequest asks a driver to open an interactive session inside a running
// workload.
type AttachRequest struct {
	// HandleID identifies the running workload, as returned by Start.
	HandleID string

	// Command is the argv to run inside the sandbox. Empty means the driver's
	// default interactive shell.
	Command []string

	// TTY requests a pseudo-terminal. Without one the session is a pipe: fine
	// for `tail -f`, useless for anything that draws.
	TTY bool

	// Stdin reports that the caller holds write authority and that the driver
	// should wire an input channel.
	//
	// It is a field of the request rather than a property of the returned
	// session because it must reach the sandbox: `docker exec` without -i and
	// a Kubernetes exec without stdin=true give the remote process no input fd
	// at all. A read-only session is therefore read-only *in the sandbox*, not
	// merely at the hub — there is no open channel to smuggle bytes down.
	Stdin bool

	// Rows and Cols are the initial terminal geometry; ignored when !TTY.
	Rows, Cols uint16

	// Env carries extra environment for the exec'd command (TERM, mainly).
	// Entries are "K=V"; a driver that cannot set environment ignores them.
	Env []string
}

// DefaultAttachCommand is what a session runs when the caller named no command.
//
// `sh` rather than `bash`: the sandbox images cloop ships are minimal, and a
// session that fails with "bash: not found" on an alpine-based image is a worse
// default than a plainer shell that is always there.
var DefaultAttachCommand = []string{"/bin/sh"}

// Argv returns the command to run, substituting the default when empty.
func (r AttachRequest) Argv() []string {
	if len(r.Command) == 0 {
		return append([]string(nil), DefaultAttachCommand...)
	}
	return append([]string(nil), r.Command...)
}

// CommandLine renders Argv for an audit record and an operator's eyes. It is
// not shell-quoted for re-execution — it exists to answer "what did they run",
// and a naive quote would imply a round-trip that is not offered.
func (r AttachRequest) CommandLine() string {
	return strings.Join(r.Argv(), " ")
}

// AttachConn is one live interactive session.
//
// Read yields the sandbox's combined output, already scrubbed of the workload's
// own leased credentials. Write forwards stdin, or fails with ErrAttachReadOnly.
// Close is idempotent and must terminate the remote process, not merely detach
// from it: a session that left a shell running inside the sandbox after the
// operator closed the tab would be an unattributed process holding the project's
// credentials.
type AttachConn interface {
	io.ReadWriteCloser

	// Resize reports new terminal geometry. It is a no-op — not an error —
	// for a session without a TTY, so a caller that always sends the window
	// size does not need to know which kind it opened.
	Resize(rows, cols uint16) error
}

// Attacher is the optional capability: a driver that can open a session inside
// a workload it is already running.
//
// Implemented by the three isolating drivers (container, kubernetes, remote) and
// deliberately not by localprocess — see AttachTarget.
type Attacher interface {
	Attach(ctx context.Context, req AttachRequest) (AttachConn, error)
}

// AsAttacher reports whether ex can open interactive sessions, mirroring
// AsRevoker. It does no policy checking; callers want AttachTarget.
func AsAttacher(ex Executor) (Attacher, bool) {
	at, ok := ex.(Attacher)
	return at, ok
}

// AttachTarget is the one place that decides whether an executor may be entered.
//
// Order matters, and it is the opposite of the cheap one. The sandbox question
// is asked *before* the capability question so that a localprocess workload is
// refused with "this runs on the host" rather than the milder "not supported":
// the two have the same effect today and very different meanings if someone
// later teaches localprocess to exec. A refusal that would silently become a
// grant is not a refusal.
func AttachTarget(ex Executor) (Attacher, error) {
	if ex == nil {
		return nil, ErrAttachHandleUnknown
	}
	if !IsolatesFromHost(ex) {
		// Two ways to arrive here, and they need different remediation. On a
		// strict-mode hub the workload should never have run at all, so name
		// the policy; on a permissive one the operator chose host execution and
		// needs to know that the choice is what costs them the shell.
		if !HostExecutionAllowed() {
			return nil, fmt.Errorf("%w (executor %q, kind %q; executors.allow_host_process is false)",
				ErrAttachNoSandbox, ex.ID(), ex.Kind())
		}
		return nil, fmt.Errorf("%w (executor %q, kind %q; bind this project to a container, "+
			"Kubernetes or remote executor to get an attachable sandbox)",
			ErrAttachNoSandbox, ex.ID(), ex.Kind())
	}
	at, ok := AsAttacher(ex)
	if !ok {
		return nil, fmt.Errorf("%w (executor %q, kind %q)", ErrAttachUnsupported, ex.ID(), ex.Kind())
	}
	return at, nil
}

// AttachSupported reports whether ex could be attached to right now, for a UI
// that wants to disable a button rather than explain a failure after the click.
func AttachSupported(ex Executor) bool {
	_, err := AttachTarget(ex)
	return err == nil
}

// ── Concurrency ceiling ───────────────────────────────────────────────────

// AttachLimiter bounds simultaneous sessions per executor.
//
// Per executor rather than per hub, per project or per user, because the
// resource at risk is the sandboxed machine: one operator opening four sessions
// on four different executors costs each of them one, while four operators
// converging on the one pod that is misbehaving is exactly the pile-on worth
// stopping. The limiter is also where the hub learns who is attached to what, so
// it doubles as the live-session inventory the UI and the CLI read.
type AttachLimiter struct {
	mu    sync.Mutex
	max   int
	live  map[string]map[string]AttachSessionInfo // executorID -> sessionID -> info
	nextN uint64
}

// AttachSessionInfo describes one live session, for the inventory.
type AttachSessionInfo struct {
	SessionID  string `json:"session_id"`
	ExecutorID string `json:"executor_id"`
	HandleID   string `json:"handle_id"`
	Actor      string `json:"actor"`
	Command    string `json:"command"`
	Writable   bool   `json:"writable"`
}

// NewAttachLimiter returns a limiter admitting at most max sessions per
// executor. A max below 1 falls back to the default rather than admitting
// nothing or everything — a misconfigured ceiling should not decide the policy.
func NewAttachLimiter(max int) *AttachLimiter {
	if max < 1 {
		max = DefaultMaxAttachSessionsPerExecutor
	}
	return &AttachLimiter{max: max, live: make(map[string]map[string]AttachSessionInfo)}
}

// Max returns the configured per-executor ceiling.
func (l *AttachLimiter) Max() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.max
}

// Acquire reserves a slot on info.ExecutorID and returns the session ID plus a
// release function. The release is idempotent, so a caller may defer it and also
// call it on an early error path.
//
// A nil limiter admits everything: the ceiling is a hub concern, and a driver
// test or an embedded use with no limiter configured should not be silently
// capped at zero.
func (l *AttachLimiter) Acquire(info AttachSessionInfo) (string, func(), error) {
	if l == nil {
		return "", func() {}, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	sessions := l.live[info.ExecutorID]
	if len(sessions) >= l.max {
		return "", nil, fmt.Errorf("%w (%d of %d in use on %q)",
			ErrAttachBusy, len(sessions), l.max, info.ExecutorID)
	}
	l.nextN++
	id := fmt.Sprintf("att-%d", l.nextN)
	info.SessionID = id
	if sessions == nil {
		sessions = make(map[string]AttachSessionInfo)
		l.live[info.ExecutorID] = sessions
	}
	sessions[id] = info

	var once sync.Once
	release := func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if m := l.live[info.ExecutorID]; m != nil {
				delete(m, id)
				if len(m) == 0 {
					delete(l.live, info.ExecutorID)
				}
			}
		})
	}
	return id, release, nil
}

// Live returns every open session, ordered by session ID, for the inventory.
func (l *AttachLimiter) Live() []AttachSessionInfo {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []AttachSessionInfo
	for _, sessions := range l.live {
		for _, info := range sessions {
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out
}

// Count returns the number of live sessions on one executor.
func (l *AttachLimiter) Count(executorID string) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.live[executorID])
}

// ── Redaction ─────────────────────────────────────────────────────────────

// RedactAttachOutput wraps r so the workload's own leased credentials never
// reach the operator's terminal.
//
// It reuses redact.Writer rather than scrubbing each read, because a credential
// does not respect read boundaries: a 40-character token split across two reads
// matches neither half, and a per-chunk scrub would pass it through in two
// pieces that a terminal reassembles perfectly. redact.Writer already holds back
// a partial tail for exactly this, and routing attach output through it is what
// makes "the same redaction path as the log stream" true rather than aspirational.
//
// A nil set returns r unchanged, so a driver can call this unconditionally.
func RedactAttachOutput(r io.Reader, set *redact.Set) io.Reader {
	if set == nil || set.Len() == 0 || r == nil {
		return r
	}
	pr, pw := io.Pipe()
	go func() {
		rw := redact.NewWriter(pw, set)
		_, err := io.Copy(rw, r)
		// Flush before closing: the holdback buffer may still be sitting on the
		// tail of a transcript that ended mid-token, and dropping it would eat
		// the last line of every session that ends without a trailing newline.
		if ferr := rw.Flush(); err == nil {
			err = ferr
		}
		_ = pw.CloseWithError(err)
	}()
	return pr
}

// attachConn adapts the three halves a driver has — an output reader, an input
// writer, a teardown — into an AttachConn, and enforces the read-only rule in
// one place so no driver can forget it.
type attachConn struct {
	out     io.Reader
	in      io.WriteCloser
	resize  func(rows, cols uint16) error
	closeFn func() error

	closeOnce sync.Once
	closeErr  error
}

// NewAttachConn assembles an AttachConn from a driver's pieces.
//
// in may be nil, which is how a read-only session is expressed: Write then
// fails with ErrAttachReadOnly rather than blocking or silently discarding.
func NewAttachConn(out io.Reader, in io.WriteCloser, resize func(rows, cols uint16) error, closeFn func() error) AttachConn {
	return &attachConn{out: out, in: in, resize: resize, closeFn: closeFn}
}

func (c *attachConn) Read(p []byte) (int, error) {
	if c.out == nil {
		return 0, ErrAttachClosed
	}
	return c.out.Read(p)
}

func (c *attachConn) Write(p []byte) (int, error) {
	if c.in == nil {
		return 0, ErrAttachReadOnly
	}
	return c.in.Write(p)
}

func (c *attachConn) Resize(rows, cols uint16) error {
	if c.resize == nil {
		return nil
	}
	return c.resize(rows, cols)
}

func (c *attachConn) Close() error {
	c.closeOnce.Do(func() {
		if c.in != nil {
			_ = c.in.Close()
		}
		if c.closeFn != nil {
			c.closeErr = c.closeFn()
		}
	})
	return c.closeErr
}
