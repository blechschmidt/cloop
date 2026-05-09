package ui

// Regression tests for runCloopSubcommand.
//
// The Web UI shells out to the cloop binary for several handler-driven
// operations (chat, voice, reset, suggest). Without bounds on these
// invocations a wedged sub-binary — slow STT provider, unresponsive LLM,
// hung file lock — would pin both the handler goroutine and the OS process
// it forked for the lifetime of the UI server. The async suggest path is
// especially vulnerable: a single hung run leaves suggestRunning=true
// forever, blocking every future suggest request with "suggest already
// running" until the daemon is restarted.
//
// runCloopSubcommand enforces both a caller-supplied ctx (for client-disconnect
// cancellation) and a hard timeout (so background goroutines whose only
// parent ctx is context.Background can still recover from a wedged child).
// These tests pin that contract using /bin/sleep as a stand-in for any
// long-running cloop sub-binary.

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

// sleepBin returns the path to /bin/sleep (or the equivalent on the host).
// The tests intentionally use a real OS binary rather than a recompiled
// helper because runCloopSubcommand's whole job is to bound external
// processes — using a fake in-process command would defeat the test.
func sleepBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep not available on this platform: %v", err)
	}
	return p
}

// TestRunCloopSubcommand_HappyPath verifies that a fast-completing command
// returns its output and a nil error within the timeout window.
func TestRunCloopSubcommand_HappyPath(t *testing.T) {
	echo, err := exec.LookPath("echo")
	if err != nil {
		t.Skipf("echo not available: %v", err)
	}
	out, err := runCloopSubcommand(context.Background(), echo, "", 5*time.Second, "hello")
	if err != nil {
		t.Fatalf("expected nil err, got: %v", err)
	}
	if got := string(out); got != "hello\n" {
		t.Fatalf("expected output %q, got %q", "hello\n", got)
	}
}

// TestRunCloopSubcommand_HardTimeoutKillsChild verifies that a command which
// would otherwise run for 60s is killed by the per-call timeout, returning
// context.DeadlineExceeded promptly. This is the property that protects
// the async suggest goroutine — without it, a wedged child would never
// release suggestRunning.
func TestRunCloopSubcommand_HardTimeoutKillsChild(t *testing.T) {
	sleep := sleepBin(t)
	start := time.Now()
	_, err := runCloopSubcommand(context.Background(), sleep, "", 200*time.Millisecond, "60")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	// Generous upper bound — we expect well under a second; anything
	// approaching the original 60s sleep would mean the kill failed.
	if elapsed > 5*time.Second {
		t.Fatalf("subprocess was not killed promptly; elapsed=%s", elapsed)
	}
}

// TestRunCloopSubcommand_CtxCancelKillsChild verifies that cancelling the
// caller's ctx (e.g. browser tab close on the chat handler) terminates the
// child process well before the hard timeout expires. Without this, a
// disconnected client would leave the LLM provider call running to completion
// and burn quota.
func TestRunCloopSubcommand_CtxCancelKillsChild(t *testing.T) {
	sleep := sleepBin(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay so the child has a chance to start.
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	// Hard timeout intentionally far longer than the cancel delay so we
	// can be sure cancellation (not the timeout) is what unblocks us.
	_, err := runCloopSubcommand(ctx, sleep, "", 30*time.Second, "60")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected ctx-cancel error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("subprocess was not killed promptly on ctx cancel; elapsed=%s", elapsed)
	}
}

// TestRunCloopSubcommand_NilCtxAccepted verifies that callers passing a nil
// ctx (rare but the helper must not panic) get the same hard-timeout
// guarantee from a context.Background fallback.
func TestRunCloopSubcommand_NilCtxAccepted(t *testing.T) {
	sleep := sleepBin(t)
	start := time.Now()
	//nolint:staticcheck // nil ctx is the contract under test
	_, err := runCloopSubcommand(nil, sleep, "", 200*time.Millisecond, "30")
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded with nil ctx, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("nil-ctx path did not honour timeout; elapsed=%s", elapsed)
	}
}
