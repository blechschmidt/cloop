// Package ptyshell runs a command attached to a pseudo-terminal.
//
// It exists for one reason: an interactive session needs the *hub* (or the edge
// agent) to hold a real terminal, not merely to ask for one. `docker exec -t`
// allocates a pty inside the container and is happy with a pipe on its own
// stdin — but only while nothing is being typed. Add `-i` and the Docker CLI
// refuses outright with "the input device is not a TTY", because it is about to
// put the terminal into raw mode and there is no terminal. Kubernetes and the
// edge agent have the same shape from the other side: they will happily deliver
// keystrokes, and a shell reading from a pipe echoes nothing, draws no prompt,
// and runs no line editor.
//
// So a writable session needs a pty on this side of the transport. That is all
// this package does — open one, start a command on its slave, hand back the
// master — and it deliberately does not know what a sandbox is.
//
// # Portability
//
// The implementation is Linux-only, which is where cloop's container and
// Kubernetes executors run and where its agent is installed. Other platforms
// get Supported() == false and Start returns ErrUnsupported, which callers turn
// into a pipe-backed session rather than a failure: a terminal without line
// editing still runs commands and still reads back output, and degrading is
// better than refusing to let an operator into a sandbox at all.
package ptyshell

import (
	"errors"
	"os"
	"os/exec"
)

// ErrUnsupported means this platform has no pty implementation here. Callers
// should fall back to pipes rather than fail.
var ErrUnsupported = errors.New("ptyshell: pseudo-terminal not supported on this platform")

// Session is a command running on a pty. Master is both ends of the terminal:
// reading it yields the command's output, writing it delivers keystrokes.
type Session struct {
	// Master is the pty master. Close it to hang up the terminal.
	Master *os.File
	// Cmd is the running command, for Wait and Process.Kill.
	Cmd *exec.Cmd
}

// Resize reports new terminal geometry to the command.
//
// A zero row or column count is ignored rather than applied: a browser tab that
// has not laid out yet reports 0x0, and a shell told its terminal is zero-by-zero
// wraps every line at column one.
func (s *Session) Resize(rows, cols uint16) error {
	if s == nil || s.Master == nil {
		return nil
	}
	if rows == 0 || cols == 0 {
		return nil
	}
	return resize(s.Master, rows, cols)
}

// Close hangs up the terminal and kills the command if it is still running.
//
// Both, in that order, and neither alone is enough. Closing the master sends
// SIGHUP to the foreground process group, which a shell honours and `sleep`
// does not; killing without closing leaves the master fd open in this process
// for as long as the caller holds the Session. A session that outlived its
// operator would be an unattributed process inside the sandbox still holding
// the project's credentials, which is the whole reason attach is audited.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.Master != nil {
		err = s.Master.Close()
	}
	if s.Cmd != nil && s.Cmd.Process != nil {
		_ = s.Cmd.Process.Kill()
		// Reap, so the child does not linger as a zombie for the life of the
		// hub. The exit status is uninteresting — the caller asked for the
		// session to end and it has.
		go func(c *exec.Cmd) { _ = c.Wait() }(s.Cmd)
	}
	return err
}

// Start runs cmd attached to a new pty of the given size.
//
// On success cmd is running, its standard streams are the pty slave, and the
// slave has been closed in this process so that reading Master returns EOF when
// the command exits rather than blocking forever on an fd nobody will write.
func Start(cmd *exec.Cmd, rows, cols uint16) (*Session, error) {
	return start(cmd, rows, cols)
}

// Supported reports whether this platform can allocate a pty here.
func Supported() bool { return supported }
