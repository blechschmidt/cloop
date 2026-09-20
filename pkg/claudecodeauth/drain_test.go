package claudecodeauth

// drain_test.go pins the ordering between reaping the login subprocess and
// draining its pipes (Task 20290).
//
// os/exec is explicit about it: Wait closes the parent's ends of the pipes
// StdoutPipe and StderrPipe returned as soon as it sees the child exit, so "it
// is incorrect to call Wait before all reads from the pipe have completed". The
// session machinery held both — two reader goroutines and a third calling Wait
// — with nothing ordering them, and the loser was whatever the CLI printed
// last. On a per-user Claude login that tail is the entire diagnostic: a failed
// login reported nothing actionable because the reason had been thrown away.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClaudeLoginWithLateTail is a stand-in `claude` whose last line is written
// by a grandchild, *after* the process cmd.Wait is watching has already exited.
//
// That is what makes this deterministic rather than a stress test. A child that
// merely writes a lot and exits leaves the tail somewhere in a kernel pipe
// buffer and asks which goroutine gets there first — a race that can be lost in
// either direction, which is exactly why the shipped defect only showed up
// about twice in three hundred runs. Here the tail does not exist yet when the
// child exits, so a Wait that does not first drain cannot capture it, and one
// that does always will.
//
// The handshake is a fifo the child holds the only write end of: the grandchild
// blocks reading it and is released precisely when the child exits. No sleeps,
// no polling, no ordering left to the scheduler.
func fakeClaudeLoginWithLateTail(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	gate := filepath.Join(dir, "gate")
	if out, err := exec.Command("mkfifo", gate).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable: %v: %s", err, out)
	}
	script := "#!/bin/sh\n" +
		"echo \"Visit: https://claude.com/cai/oauth/authorize?dir=${CLAUDE_CONFIG_DIR:-none}\"\n" +
		"read code\n" +
		// The grandchild inherits stdout and stderr and outlives us. It writes
		// the tail through one more exec so that "after the child exits" is
		// unambiguous at wall-clock scale too, and a Wait goroutine delayed by
		// a busy machine still cannot beat it.
		"( cat " + gate + " >/dev/null; " +
		"/bin/sh -c 'echo \"received:$1\"; echo \"stderr-tail:$1\" >&2' _ \"$code\" ) &\n" +
		// The only write end of the gate. Closed by exit, and by nothing else.
		"exec 9>" + gate + "\n" +
		"exit 0\n"
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestSubmitCodeCapturesOutputWrittenAfterTheChildExits is the regression test.
// Before the fix the Wait goroutine snapshotted the buffer the instant the child
// exited — closing both pipes on the way — and the tail never reached it.
func TestSubmitCodeCapturesOutputWrittenAfterTheChildExits(t *testing.T) {
	fakeClaudeLoginWithLateTail(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start alice: %v", err)
	}

	st, err := m.SubmitCode("alice@example.com", "alice-code")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !st.Done {
		t.Fatalf("session did not finish: %+v", st)
	}
	if !strings.Contains(st.Output, "received:alice-code") {
		t.Errorf("stdout tail missing from the captured session output: %q\n"+
			"cmd.Wait closed the pipe and snapshotted before the reader had drained it", st.Output)
	}
	if !strings.Contains(st.Output, "stderr-tail:alice-code") {
		t.Errorf("stderr tail missing from the captured session output: %q\n"+
			"a login that fails reports its reason on stderr; losing it is why a "+
			"failed login showed nothing actionable", st.Output)
	}
}

// TestSnapshotAfterDoneIsTheCompleteOutput: the UI reads Snapshot after
// SubmitCode returns, so the same guarantee has to hold through the field the
// UI actually renders, not only through SubmitCode's return value.
func TestSnapshotAfterDoneIsTheCompleteOutput(t *testing.T) {
	fakeClaudeLoginWithLateTail(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	sess, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := m.SubmitCode("alice@example.com", "alice-code"); err != nil {
		t.Fatalf("submit: %v", err)
	}

	st := sess.Snapshot()
	if !st.Done {
		t.Fatalf("session is not done: %+v", st)
	}
	if !strings.Contains(st.Output, "received:alice-code") ||
		!strings.Contains(st.Output, "stderr-tail:alice-code") {
		t.Errorf("Snapshot output is truncated: %q", st.Output)
	}
}

// TestCancelReturnsWhenAGrandchildHoldsThePipes is the liveness half of the
// fix. Draining before reaping means the readers decide when a session
// finishes, and a process that inherited stdout but is not the child cloop
// waits on can keep them from ever reaching EOF — so Cancel, Shutdown and
// SubmitCode's timeout would all block on s.done forever, which on a hub is an
// HTTP handler that never returns. pkg/executor/gitprovision.BoundChild exists
// because git spawns exactly this shape of grandchild.
func TestCancelReturnsWhenAGrandchildHoldsThePipes(t *testing.T) {
	prev := pipeDrainGrace
	pipeDrainGrace = 200 * time.Millisecond
	t.Cleanup(func() { pipeDrainGrace = prev })

	dir := t.TempDir()
	gate := filepath.Join(dir, "gate")
	if out, err := exec.Command("mkfifo", gate).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable: %v: %s", err, out)
	}
	script := "#!/bin/sh\n" +
		// Inherits stdout and stderr and never exits on its own: nothing ever
		// opens the gate for writing, so this read blocks indefinitely.
		"( cat " + gate + " >/dev/null ) &\n" +
		"echo \"Visit: https://claude.com/cai/oauth/authorize?dir=${CLAUDE_CONFIG_DIR:-none}\"\n" +
		"read code\n"
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	m := NewManager()
	t.Cleanup(m.Shutdown)
	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start: %v", err)
	}

	returned := make(chan struct{})
	go func() { m.Cancel("alice@example.com"); close(returned) }()
	select {
	case <-returned:
	case <-time.After(15 * time.Second):
		t.Fatal("Cancel never returned: a grandchild holding stdout kept the " +
			"readers from EOF, so nothing ever reaped the session")
	}
	if m.Snapshot("alice@example.com").Active {
		t.Error("the cancelled session is still active")
	}

	// Release the grandchild rather than leaving a blocked process behind:
	// opening the gate for writing gives its read an EOF.
	if f, err := os.OpenFile(gate, os.O_WRONLY, 0); err == nil {
		_ = f.Close()
	}
}

// fakeClaudeFailingLogin exits non-zero with its explanation on stderr and no
// OAuth URL anywhere — the shape of a real misconfigured login.
func fakeClaudeFailingLogin(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	gate := filepath.Join(dir, "gate")
	if out, err := exec.Command("mkfifo", gate).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable: %v: %s", err, out)
	}
	script := "#!/bin/sh\n" +
		"( cat " + gate + " >/dev/null; " +
		"/bin/sh -c 'echo \"error: no such organization\" >&2' ) &\n" +
		"exec 9>" + gate + "\n" +
		"exit 1\n"
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestStartReportsWhyTheCLIFailed covers the other exit from Start: the child
// dies before emitting a URL, and the error returned to the operator is the only
// account of why. Snapshotting beside a live reader reported half of it.
func TestStartReportsWhyTheCLIFailed(t *testing.T) {
	fakeClaudeFailingLogin(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	_, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{})
	if err == nil {
		t.Fatal("a login whose CLI exited 1 without a URL was reported as started")
	}
	if !strings.Contains(err.Error(), "no such organization") {
		t.Errorf("error does not carry the CLI's explanation: %v", err)
	}
	if m.Snapshot("alice@example.com").Active {
		t.Error("a failed Start left a session registered")
	}
}
