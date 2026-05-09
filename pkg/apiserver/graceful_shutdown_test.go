package apiserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestServer_Run_GracefulShutdown_OnContextCancel verifies the API server
// returns nil from Run when its context is cancelled, instead of blocking on
// ListenAndServe forever. This is the load-bearing invariant for systemd's
// SIGTERM → graceful drain → clean exit, and prevents `cloop serve` from
// being SIGKILLed (with the in-flight `cloop run` subprocess orphaned to
// init) when an operator stops the daemon.
func TestServer_Run_GracefulShutdown_OnContextCancel(t *testing.T) {
	t.Parallel()

	port := pickFreePort(t)
	srv := New(t.TempDir(), port, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	waitForServerReady(t, port, 2*time.Second)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error after ctx cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of ctx cancel — graceful shutdown is hung")
	}
}

// TestServer_Shutdown_StopsRun — same invariant but via the explicit Shutdown
// method (the lever for callers that don't own the Run context).
func TestServer_Shutdown_StopsRun(t *testing.T) {
	t.Parallel()

	port := pickFreePort(t)
	srv := New(t.TempDir(), port, "")

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(context.Background()) }()

	waitForServerReady(t, port, 2*time.Second)

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Run returned unexpected error after Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of Shutdown")
	}
}

// TestServer_Shutdown_BeforeRun_NoOp — Shutdown on a never-started server is
// safe so deferred-Shutdown patterns in cobra commands don't crash on
// early-exit code paths.
func TestServer_Shutdown_BeforeRun_NoOp(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before Run should be a no-op, got: %v", err)
	}
}

// pickFreePort asks the kernel for an unused TCP port by binding to :0 and
// reading back the assigned port. The bind is closed immediately; the test
// then re-binds via Run. There's a tiny race window but it's vanishingly
// unlikely on a developer machine, and avoids hard-coding a port.
func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitForServerReady polls TCP-connect until the server is accepting or
// timeout fires. Without this barrier a fast cancel races ListenAndServe and
// we'd be testing the early-exit path instead of the shutdown path.
func waitForServerReady(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server on port %d did not become ready within %v", port, timeout)
}
