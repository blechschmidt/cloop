package ui

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestServer_Run_GracefulShutdown_OnContextCancel verifies that cancelling the
// context passed to Run causes the UI server to drain in-flight work and
// return nil rather than blocking indefinitely. This is the load-bearing
// invariant for systemd's `systemctl stop cloop-ui`: SIGTERM → cancel ctx →
// Run returns → process exits cleanly. A regression here surfaces as systemd
// having to SIGKILL the daemon after the stop timeout, dropping in-flight
// WebSocket frames and (potentially) corrupting any state mid-write.
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

// TestServer_Shutdown_StopsRun verifies the explicit Shutdown method also
// brings Run down. Some callers cannot easily plumb a context (e.g. an
// integration harness that already owns one); Shutdown gives them an
// out-of-band lever. After Shutdown returns, Run must return nil within a
// short window — not block forever waiting for a signal it will never see.
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
		t.Fatal("Run did not return within 5s of Shutdown — graceful shutdown is hung")
	}
}

// TestServer_Shutdown_BeforeRun_NoOp documents that calling Shutdown on a
// server that has never been started is safe. This matters because the cobra
// command path may construct a Server and then bail out before Run for an
// unrelated reason (config error, etc.), and a deferred Shutdown should not
// crash the process.
func TestServer_Shutdown_BeforeRun_NoOp(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before Run should be a no-op, got: %v", err)
	}
}

// TestServer_Shutdown_TwiceSafe verifies Shutdown is idempotent. The second
// call must not double-close the http.Server (which would panic) or leave
// the field in an inconsistent state.
func TestServer_Shutdown_TwiceSafe(t *testing.T) {
	t.Parallel()

	port := pickFreePort(t)
	srv := New(t.TempDir(), port, "")

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(context.Background()) }()

	waitForServerReady(t, port, 2*time.Second)

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown should be a no-op, got: %v", err)
	}

	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

// TestWatchState_StopsOnContextCancel verifies the polling goroutine respects
// ctx cancellation instead of leaking for the lifetime of the process. We use
// a synchronisation pattern: spawn watchState in a goroutine, cancel ctx,
// and confirm the goroutine returns within a short window.
//
// Without ctx awareness, this goroutine would tick on its 1-second timer
// forever — leaking a goroutine plus an os.Stat call per second per UI
// instance restart in long-lived test processes.
func TestWatchState_StopsOnContextCancel(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.watchState(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchState did not return within 2s of ctx cancel")
	}
}

// TestWatchProjects_StopsOnContextCancel — same invariant for the multi-
// project watcher.
func TestWatchProjects_StopsOnContextCancel(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.watchProjects(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("watchProjects did not return within 3s of ctx cancel")
	}
}

// pickFreePort asks the kernel for an unused TCP port by binding to :0,
// reading back the assigned port, and immediately closing. There's a tiny
// race window between Close and the test re-binding, but it's vanishingly
// unlikely to collide on a developer machine and avoids hard-coding a port
// that's already in use.
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

// waitForServerReady polls TCP-connect to the given port until success or the
// timeout. The test goroutine starts Run asynchronously; without this barrier
// a fast cancel would race ListenAndServe and we'd be testing nothing.
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

