package container

// Integration tests for the interactive attach path (Task 20265).
//
// These drive a real runtime, because the two things most likely to be wrong
// here cannot be asserted against a fake: whether `exec -i -t` is actually
// satisfied by the pty this process allocates, and whether a read-only session
// genuinely has no input fd inside the sandbox. Both are properties of docker
// and podman, not of this package's control flow.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// startSleeper runs a long-lived workload and returns its handle, so a test has
// something to attach to.
func startSleeper(t *testing.T, ex *Executor, spec executor.Spec) executor.Handle {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if len(spec.Argv) == 0 {
		spec.Argv = []string{"sleep", "120"}
	}
	if spec.WorkDir == "" {
		spec.WorkDir = t.TempDir()
	}
	h, err := ex.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer scancel()
		_ = ex.Signal(sctx, h.ID, executor.SignalKill)
	})
	return h
}

// readUntil reads from conn until want appears or the deadline passes. It
// returns everything it saw, so a failure message can show the transcript.
func readUntil(t *testing.T, conn executor.AttachConn, want string, within time.Duration) (string, bool) {
	t.Helper()
	type chunk struct {
		b   []byte
		err error
	}
	ch := make(chan chunk, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				ch <- chunk{b: append([]byte(nil), buf[:n]...)}
			}
			if err != nil {
				ch <- chunk{err: err}
				return
			}
		}
	}()

	var sb strings.Builder
	deadline := time.After(within)
	for {
		select {
		case c := <-ch:
			sb.Write(c.b)
			if strings.Contains(sb.String(), want) {
				return sb.String(), true
			}
			if c.err != nil {
				return sb.String(), strings.Contains(sb.String(), want)
			}
		case <-deadline:
			return sb.String(), false
		}
	}
}

// TestAttach_ReadOnlySessionHasNoStdinInTheSandbox is the security property the
// read-only default rests on. It is not enough that the hub declines to forward
// keystrokes: the exec'd process must have no input fd at all, so that a bug in
// the forwarding layer cannot become a write.
func TestAttach_ReadOnlySessionHasNoStdinInTheSandbox(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	h := startSleeper(t, ex, executor.Spec{})

	conn, err := ex.Attach(context.Background(), executor.AttachRequest{
		HandleID: h.ID,
		// `read` fails immediately when fd 0 is closed, and blocks when it is a
		// pipe nobody writes. The distinction is the whole test.
		Command: []string{"sh", "-c", "read x </dev/stdin 2>/dev/null && echo GOT_INPUT || echo NO_STDIN"},
		Stdin:   false,
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer conn.Close()

	out, ok := readUntil(t, conn, "NO_STDIN", 30*time.Second)
	if !ok {
		t.Fatalf("read-only session must have no readable stdin in the sandbox; transcript: %q", out)
	}
	if strings.Contains(out, "GOT_INPUT") {
		t.Errorf("read-only session delivered input to the sandbox; transcript: %q", out)
	}

	// The hub side refuses too, so the two halves agree.
	if _, err := conn.Write([]byte("whoami\n")); !errors.Is(err, executor.ErrAttachReadOnly) {
		t.Errorf("Write on a read-only session = %v, want ErrAttachReadOnly", err)
	}
}

// TestAttach_WritableSessionRunsCommands proves the writable path end to end:
// a pty is allocated here, `exec -i -t` accepts it, and what is typed reaches
// the shell inside the sandbox.
func TestAttach_WritableSessionRunsCommands(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	h := startSleeper(t, ex, executor.Spec{})

	conn, err := ex.Attach(context.Background(), executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"sh"},
		TTY:      true,
		Stdin:    true,
		Rows:     40, Cols: 100,
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("echo MARKER_$((6*7))\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, ok := readUntil(t, conn, "MARKER_42", 30*time.Second)
	if !ok {
		t.Fatalf("typed command produced no output; transcript: %q", out)
	}
}

// TestAttach_TTYSessionGetsARealTerminal distinguishes a session that asked for
// a terminal from one that got one. A shell whose stdout is a pipe draws no
// prompt and runs no line editor, which is the difference between a terminal
// and a log tail.
func TestAttach_TTYSessionGetsARealTerminal(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	h := startSleeper(t, ex, executor.Spec{})

	conn, err := ex.Attach(context.Background(), executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"sh", "-c", "test -t 1 && echo IS_TTY || echo NOT_TTY"},
		TTY:      true,
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer conn.Close()

	out, ok := readUntil(t, conn, "IS_TTY", 30*time.Second)
	if !ok {
		t.Fatalf("TTY session did not get a terminal; transcript: %q", out)
	}
}

// TestAttach_WindowSizeReachesTheSandbox proves Resize is wired, not merely
// accepted. A terminal that reports the wrong width wraps every line.
func TestAttach_WindowSizeReachesTheSandbox(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	h := startSleeper(t, ex, executor.Spec{})

	conn, err := ex.Attach(context.Background(), executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"sh"},
		TTY:      true, Stdin: true,
		Rows: 24, Cols: 80,
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer conn.Close()

	if err := conn.Resize(50, 132); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	// Give the shell a moment to see SIGWINCH before asking.
	time.Sleep(300 * time.Millisecond)
	if _, err := conn.Write([]byte("stty size\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, ok := readUntil(t, conn, "50 132", 30*time.Second)
	if !ok {
		t.Fatalf("resize did not reach the sandbox; want \"50 132\", transcript: %q", out)
	}
}

// TestAttach_RedactsLeasedCredentials is the property the task turns on: a
// credential echoed into the terminal must be scrubbed on the way out, through
// the same set the log stream uses.
//
// The secret is planted via the Spec's redaction declaration, which is exactly
// how a real lease travels, and then printed by a command the operator typed —
// the path a `cat ~/.git-credentials` takes.
func TestAttach_RedactsLeasedCredentials(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)

	const secret = "ghp_AttachMustNeverEchoThisToken00"
	h := startSleeper(t, ex, executor.Spec{
		Env: []string{
			"CLOOP_TEST_TOKEN=" + secret,
			redact.EnvKey + "=CLOOP_TEST_TOKEN",
		},
	})

	conn, err := ex.Attach(context.Background(), executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"sh", "-c", "echo TOKEN_IS:$CLOOP_TEST_TOKEN:END"},
	})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer conn.Close()

	out, ok := readUntil(t, conn, ":END", 30*time.Second)
	if !ok {
		t.Fatalf("command produced no output; transcript: %q", out)
	}
	if strings.Contains(out, secret) {
		t.Errorf("attach transcript leaked a leased credential: %q", out)
	}
	if !strings.Contains(out, "TOKEN_IS:") {
		t.Errorf("redaction ate the surrounding output; transcript: %q", out)
	}
}

// TestAttach_RejectsUnknownHandle keeps the driver from opening a session
// against a workload it is not running.
func TestAttach_RejectsUnknownHandle(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	_, err := ex.Attach(context.Background(), executor.AttachRequest{HandleID: "no-such-handle"})
	if err == nil {
		t.Fatal("Attach to an unknown handle must fail")
	}
}

// TestAttach_RefusesFinishedWorkload: a container that has exited has nothing
// to enter, and `docker exec` against it produces a confusing runtime error.
func TestAttach_RefusesFinishedWorkload(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	h, err := ex.Start(ctx, executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wait for the reaper to mark it terminal.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, err := ex.Status(ctx, h.ID)
		if err == nil && st.State.Terminal() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	_, err = ex.Attach(ctx, executor.AttachRequest{HandleID: h.ID})
	if !errors.Is(err, executor.ErrAttachClosed) {
		t.Errorf("Attach to a finished workload = %v, want ErrAttachClosed", err)
	}
}

// TestAttach_SatisfiesTheOptionalInterface is the compile-and-policy check: the
// container driver must be reachable through executor.AttachTarget, which is the
// only funnel the hub uses.
func TestAttach_SatisfiesTheOptionalInterface(t *testing.T) {
	rt := requireRuntime(t)
	ex, err := New(Options{ID: "iface-check", Image: defaultTestImage, AllowRootUser: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = rt
	if _, ok := executor.AsAttacher(ex); !ok {
		t.Fatal("container executor must implement executor.Attacher")
	}
	if _, err := executor.AttachTarget(ex); err != nil {
		t.Errorf("AttachTarget(container) = %v, want nil: the driver isolates and implements Attacher", err)
	}
}

// TestMergeReaders_InterleavesRatherThanSerialising guards the choice not to use
// io.MultiReader: with it, nothing from the second stream appears until the
// first reaches EOF, so every error in a live session would arrive only after
// the command exited.
func TestMergeReaders_InterleavesRatherThanSerialising(t *testing.T) {
	aR, aW := io.Pipe()
	bR, bW := io.Pipe()
	merged := mergeReaders(aR, bR)

	go func() {
		_, _ = bW.Write([]byte("from-b\n"))
		time.Sleep(50 * time.Millisecond)
		_, _ = aW.Write([]byte("from-a\n"))
		_ = aW.Close()
		_ = bW.Close()
	}()

	br := bufio.NewReader(merged)
	first, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(first) != "from-b" {
		t.Errorf("first line = %q, want the stream that wrote first (%q): "+
			"a serialising merge would block it behind the other stream's EOF", first, "from-b")
	}
}
