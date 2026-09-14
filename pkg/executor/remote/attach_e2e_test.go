package remote_test

// End-to-end tests for interactive attach over the agent transport
// (Task 20265).
//
// These run a real hub and a real agent over a real WebSocket, because the
// thing most likely to be wrong is the multiplexing: attach shares one
// connection with heartbeats, log chunks and signals, and a session ID that
// routed to the wrong terminal — or a frame the agent silently dropped as
// unexpected — would look exactly like "the sandbox produced no output".

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// startLongRunning gives a test something to attach to.
func startLongRunning(t *testing.T, lb *loopback, spec executor.Spec) (executor.Handle, *remoteExec) {
	t.Helper()
	ex := lb.executor(t)
	if spec.WorkDir == "" {
		spec.WorkDir = "attach-target"
	}
	if len(spec.Argv) == 0 {
		spec.Argv = []string{"/bin/sh", "-c", "sleep 120"}
	}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = ex.Signal(context.Background(), h.ID, executor.SignalKill)
	})
	return h, &remoteExec{ex}
}

// remoteExec is a tiny alias so the tests read as "the executor under test"
// without importing the concrete type into every signature.
type remoteExec struct{ ex executor.Executor }

func (r *remoteExec) attach(t *testing.T, req executor.AttachRequest) executor.AttachConn {
	t.Helper()
	at, err := executor.AttachTarget(r.ex)
	if err != nil {
		t.Fatalf("AttachTarget: %v", err)
	}
	conn, err := at.Attach(context.Background(), req)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readUntilE2E drains conn until want appears or the deadline passes.
func readUntilE2E(t *testing.T, conn executor.AttachConn, want string, within time.Duration) (string, bool) {
	t.Helper()
	type chunk struct {
		b   []byte
		err error
	}
	ch := make(chan chunk, 32)
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

// TestLoopbackAttachRunsCommandOnTheDevice is the headline assertion: a
// command opened by the hub actually executes on the agent, and its output
// comes back down the same session the workload's logs use.
func TestLoopbackAttachRunsCommandOnTheDevice(t *testing.T) {
	lb := newLoopback(t)
	h, ex := startLongRunning(t, lb, executor.Spec{})

	conn := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh", "-c", "echo REMOTE_MARKER_$((6*7))"},
	})
	out, ok := readUntilE2E(t, conn, "REMOTE_MARKER_42", 30*time.Second)
	if !ok {
		t.Fatalf("attach produced no output from the device; transcript: %q", out)
	}
}

// TestLoopbackAttachRunsInTheWorkloadsDirectory: a session that opened
// somewhere else would show an operator the wrong tree, which is worse than
// showing them nothing.
func TestLoopbackAttachRunsInTheWorkloadsDirectory(t *testing.T) {
	lb := newLoopback(t)
	h, ex := startLongRunning(t, lb, executor.Spec{WorkDir: "attach-cwd-probe"})

	conn := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh", "-c", "pwd"},
	})
	out, ok := readUntilE2E(t, conn, "attach-cwd-probe", 30*time.Second)
	if !ok {
		t.Fatalf("session did not start in the workload's directory; transcript: %q", out)
	}
}

// TestLoopbackAttachReadOnlyHasNoStdinOnTheDevice is the security property.
// The refusal that counts is the one on the machine where the command runs.
func TestLoopbackAttachReadOnlyHasNoStdinOnTheDevice(t *testing.T) {
	lb := newLoopback(t)
	h, ex := startLongRunning(t, lb, executor.Spec{})

	conn := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh", "-c", "read x </dev/stdin 2>/dev/null && echo GOT_INPUT || echo NO_STDIN"},
		Stdin:    false,
	})
	out, ok := readUntilE2E(t, conn, "NO_STDIN", 30*time.Second)
	if !ok {
		t.Fatalf("read-only session must give the device's command no stdin; transcript: %q", out)
	}
	if strings.Contains(out, "GOT_INPUT") {
		t.Errorf("read-only session delivered input to the device; transcript: %q", out)
	}
	if _, err := conn.Write([]byte("whoami\n")); !errors.Is(err, executor.ErrAttachReadOnly) {
		t.Errorf("Write on a read-only session = %v, want ErrAttachReadOnly", err)
	}
}

// TestLoopbackAttachWritableDeliversInput proves the other direction of the
// multiplex: bytes typed at the hub reach a process on the device.
func TestLoopbackAttachWritableDeliversInput(t *testing.T) {
	lb := newLoopback(t)
	h, ex := startLongRunning(t, lb, executor.Spec{})

	conn := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh"},
		Stdin:    true,
		TTY:      true,
		Rows:     24, Cols: 80,
	})
	if _, err := conn.Write([]byte("echo TYPED_$((3*5))\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, ok := readUntilE2E(t, conn, "TYPED_15", 30*time.Second)
	if !ok {
		t.Fatalf("typed input never reached the device; transcript: %q", out)
	}
}

// TestLoopbackAttachRedactsLeasedCredentials: the scrub happens on the device,
// before the bytes cross the wire, so a credential echoed into a terminal never
// leaves the machine holding it.
func TestLoopbackAttachRedactsLeasedCredentials(t *testing.T) {
	lb := newLoopback(t)
	const secret = "ghp_remoteAttachMustNeverEchoThis1"
	h, ex := startLongRunning(t, lb, executor.Spec{
		Env: []string{
			"CLOOP_TEST_TOKEN=" + secret,
			redact.EnvKey + "=CLOOP_TEST_TOKEN",
		},
	})

	conn := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh", "-c", "echo TOKEN_IS:$CLOOP_TEST_TOKEN:END"},
	})
	out, ok := readUntilE2E(t, conn, ":END", 30*time.Second)
	if !ok {
		t.Fatalf("command produced no output; transcript: %q", out)
	}
	if strings.Contains(out, secret) {
		t.Errorf("remote attach transcript leaked a leased credential: %q", out)
	}
}

// TestLoopbackAttachTwoSessionsDoNotCrossTalk is the multiplexing assertion.
// Two terminals on one handle share a connection and are told apart only by
// their session ID; a routing bug would deliver both transcripts to both.
func TestLoopbackAttachTwoSessionsDoNotCrossTalk(t *testing.T) {
	lb := newLoopback(t)
	h, ex := startLongRunning(t, lb, executor.Spec{})

	connA := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh", "-c", "echo AAA_ONLY; sleep 5"},
	})
	connB := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh", "-c", "echo BBB_ONLY; sleep 5"},
	})

	outA, okA := readUntilE2E(t, connA, "AAA_ONLY", 30*time.Second)
	if !okA {
		t.Fatalf("session A produced no output; transcript: %q", outA)
	}
	outB, okB := readUntilE2E(t, connB, "BBB_ONLY", 30*time.Second)
	if !okB {
		t.Fatalf("session B produced no output; transcript: %q", outB)
	}
	if strings.Contains(outA, "BBB_ONLY") {
		t.Errorf("session A received session B's output: %q", outA)
	}
	if strings.Contains(outB, "AAA_ONLY") {
		t.Errorf("session B received session A's output: %q", outB)
	}
}

// TestLoopbackAttachEndsWhenTheCommandExits: the device reports the close, and
// the hub turns it into EOF rather than leaving a reader blocked forever.
func TestLoopbackAttachEndsWhenTheCommandExits(t *testing.T) {
	lb := newLoopback(t)
	h, ex := startLongRunning(t, lb, executor.Spec{})

	conn := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command:  []string{"/bin/sh", "-c", "echo BYE"},
	})

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, conn)
		done <- err
	}()
	select {
	case <-done:
		// Either EOF or a close error is fine; what matters is that it returned.
	case <-time.After(30 * time.Second):
		t.Fatal("attach reader never saw the session end after the command exited")
	}
}

// TestLoopbackAttachRefusesAnUnknownHandle keeps a session from being opened
// against a workload the device is not running.
func TestLoopbackAttachRefusesAnUnknownHandle(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	at, err := executor.AttachTarget(ex)
	if err != nil {
		t.Fatalf("AttachTarget: %v", err)
	}
	if _, err := at.Attach(context.Background(), executor.AttachRequest{HandleID: "no-such-handle"}); err == nil {
		t.Fatal("attach to an unknown handle must fail")
	}
}

// TestRemoteExecutorIsAttachable pins the capability: the remote driver
// isolates (the machine is not ours) and implements Attacher, so the hub's one
// funnel must accept it.
func TestRemoteExecutorIsAttachable(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	if _, ok := executor.AsAttacher(ex); !ok {
		t.Fatal("the remote executor must implement executor.Attacher")
	}
	if _, err := executor.AttachTarget(ex); err != nil {
		t.Errorf("AttachTarget(remote) = %v, want nil", err)
	}
}
