//go:build linux

package e2e_test

// cloop does not query the terminal as it starts (Task 20374).
//
// bubbletea's package init asked the terminal for its background colour on
// every command whose stdout was a terminal, and waited up to five seconds for
// the reply. Under a pseudo-terminal nobody answers — a script driving cloop
// through expect, `docker exec -t`, a CI job with a tty — `cloop status` took
// 5.05 s instead of 0.03 s and its output began with the query. These tests
// run the built binary the way such a script does.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY returns both ends of a new pseudo-terminal sized like a terminal
// window. Nothing ever answers on the master side: it is only read.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals here: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetUint32(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Fatalf("pty number: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		m.Close()
		t.Fatalf("open pty slave: %v", err)
	}
	if err := unix.IoctlSetWinsize(int(s.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}); err != nil {
		m.Close()
		s.Close()
		t.Fatalf("size pty: %v", err)
	}
	return m, s
}

// runUnderPTY runs the binary as the session leader of a new session whose
// controlling terminal is a pty, as `script` or `docker exec -t` would: that is
// the condition under which the terminal was queried, since the query is only
// made by a process in the terminal's foreground. It returns everything the
// process wrote and how long it ran.
func runUnderPTY(t *testing.T, dir string, args ...string) ([]byte, time.Duration) {
	t.Helper()
	master, slave := openPTY(t)
	defer master.Close()

	cmd := exec.Command(binaryPath(t), args...)
	cmd.Dir = dir
	// A terminal termenv queries: it skips dumb, screen and tmux.
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		slave.Close()
		t.Fatalf("start: %v", err)
	}
	slave.Close() // the child holds its own copies; EOF reaches us when it exits

	var out bytes.Buffer
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(&out, master) // ends with EIO once the last slave fd closes
	}()

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
		t.Fatalf("cloop %s did not exit within 20 s under a pty", strings.Join(args, " "))
	}
	took := time.Since(start)
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("the pty's output did not drain after the process exited")
	}
	return out.Bytes(), took
}

func TestStartupDoesNotQueryTheTerminal(t *testing.T) {
	dir := newWorkDir(t)
	out, took := runUnderPTY(t, dir, "status")

	for _, q := range []struct{ seq, name string }{
		{"\x1b]11;", "an OSC 11 background-colour query"},
		{"\x1b[6n", "a cursor-position request"},
	} {
		if bytes.Contains(out, []byte(q.seq)) {
			t.Errorf("cloop status wrote %s to the terminal: %q", q.name, out)
		}
	}
	// A query that nobody answers costs termenv's five-second timeout; without
	// one the command finishes in tens of milliseconds.
	if took >= time.Second {
		t.Errorf("cloop status took %s under a pty that never answers; want well under 1 s", took)
	}
	if !bytes.Contains(out, []byte("no cloop project found")) {
		t.Errorf("unexpected output under the pty (did the command run at all?): %q", out)
	}
}

// The fix is an init that has to run before bubbletea's, and Go decides that
// order. GODEBUG=inittrace=1 prints every package init as it runs.
func TestTermqueryInitRunsBeforeBubbletea(t *testing.T) {
	cmd := exec.Command(binaryPath(t), "version")
	cmd.Dir = newWorkDir(t)
	cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1", "NO_COLOR=1", "TERM=dumb")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatalf("cloop version: %v\n%s", err, stderr.String())
	}

	ours, theirs := -1, -1
	for i, line := range strings.Split(stderr.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "init github.com/blechschmidt/cloop/internal/termquery "):
			ours = i
		case strings.HasPrefix(line, "init github.com/charmbracelet/bubbletea "):
			theirs = i
		}
	}
	if ours < 0 {
		t.Fatal("internal/termquery's init did not run: main no longer imports it")
	}
	if theirs < 0 {
		t.Skip("bubbletea has no init any more; internal/termquery may be removable")
	}
	if ours > theirs {
		t.Fatalf("bubbletea's init (line %d) ran before internal/termquery's (line %d), so it still queries the terminal",
			theirs, ours)
	}
}
