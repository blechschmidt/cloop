package remote

// attachmux.go is the session-level registry that routes attach frames to the
// right terminal (Task 20265).
//
// It lives beside Session rather than on Executor because an attach session
// cannot outlive the connection it was opened on: the command runs on the
// device, and when the device drops, the shell is gone. Keying the registry to
// the Session makes that lifetime the compiler's problem — closing a session
// ends every terminal on it, by construction, and there is no map left behind
// on the executor holding pipes nobody will ever write to again.

import (
	"context"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// attachWriteTimeout bounds one outbound attach frame.
//
// Generous for a keystroke and short for a stall. An edge device on a bad link
// should make a terminal feel slow; it should not make one hang with no way to
// tell whether the far end is thinking or gone.
const attachWriteTimeout = 15 * time.Second

// maxAttachSessionsPerConnection bounds how many terminals one agent session
// may carry.
//
// The hub's own RBAC ceiling (executor.AttachLimiter) is the policy limit and
// is the one an operator sees. This is the structural backstop: it is enforced
// where the frames are routed, so a bug that let the policy be bypassed — a new
// call site that forgot the limiter — still cannot turn one connection into an
// unbounded fan-out of pipes.
const maxAttachSessionsPerConnection = 16

// attachRegistry is the per-session map of live terminals.
type attachRegistry struct {
	mu       sync.Mutex
	sessions map[string]*attachSession
}

func (r *attachRegistry) add(as *attachSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]*attachSession)
	}
	if len(r.sessions) >= maxAttachSessionsPerConnection {
		return false
	}
	r.sessions[as.id] = as
	return true
}

func (r *attachRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
}

func (r *attachRegistry) get(id string) *attachSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

// drain returns every live session and empties the registry, for teardown.
func (r *attachRegistry) drain() []*attachSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*attachSession, 0, len(r.sessions))
	for _, as := range r.sessions {
		out = append(out, as)
	}
	r.sessions = nil
	return out
}

// registerAttach adds a terminal to this session's registry.
func (s *Session) registerAttach(as *attachSession) bool { return s.attaches.add(as) }

// unregisterAttach drops one.
func (s *Session) unregisterAttach(id string) { s.attaches.remove(id) }

// closeAttachSessions ends every terminal on this connection. Called when the
// session itself ends, for any reason.
func (s *Session) closeAttachSessions(reason string) {
	for _, as := range s.attaches.drain() {
		as.finish(reason)
	}
}

// handleAttachFrame routes one inbound attach frame, reporting whether it
// consumed it.
//
// An unknown session ID is dropped rather than answered. It is the expected
// shape of a race — the operator closed the terminal while the device was
// mid-chunk — and replying would tell a device that guessed an ID whether that
// guess was right.
func (s *Session) handleAttachFrame(ctx context.Context, f Frame) bool {
	switch f.Type {
	case TypeAttachData:
		p, err := DecodeAttachData(f)
		if err != nil {
			writeError(ctx, s.conn, f.ID, CodeProtocol, err.Error())
			return true
		}
		if as := s.attaches.get(p.SessionID); as != nil {
			as.deliver(p.Data)
		}
		return true

	case TypeAttachClose:
		p, err := DecodeAttachClose(f)
		if err != nil {
			writeError(ctx, s.conn, f.ID, CodeProtocol, err.Error())
			return true
		}
		if as := s.attaches.get(p.SessionID); as != nil {
			as.finish(closeReasonText(p))
		}
		return true

	case TypeAttachOpened:
		// The answer to an open request; the waiter in Attach owns it.
		s.deliver(f)
		return true
	}
	return false
}

// closeReasonText renders a device-reported close for the operator's screen.
func closeReasonText(p AttachClosePayload) string {
	switch {
	case p.Reason != "":
		return p.Reason
	case p.ExitCode > 0:
		return "session ended with exit code " + itoa(p.ExitCode)
	default:
		return "session ended"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// redactor returns the credential set installed on this handle's log bus, so an
// attach session scrubs with exactly what the log stream scrubs with.
func (h *handleState) redactor() *redact.Set {
	if h == nil {
		return nil
	}
	return h.bus.Redactor()
}

// attachInboxDepth is how many chunks one terminal may buffer before the hub
// gives up on it.
//
// Each chunk is at most MaxAttachChunk (32 KiB), so this is a 1 MiB ceiling per
// terminal — 4 MiB at the hub's default per-executor session limit, and 16 MiB
// at the structural per-connection cap. Bounded on purpose in both directions:
// large enough that an ordinary browser hiccup does not drop a session, small
// enough that a reader who has stopped reading entirely cannot turn a debugging
// tool into a memory-exhaustion primitive against the control plane.
const attachInboxDepth = 32
