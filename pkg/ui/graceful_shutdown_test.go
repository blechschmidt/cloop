package ui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"nhooyr.io/websocket"
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

// TestServer_GracefulShutdown_FullIntegration is the contract test for Task
// 20083: it starts the server, opens a WebSocket connection, fires an HTTP
// request, triggers shutdown via ctx cancel, and asserts the three required
// invariants:
//
//	(a) the in-flight HTTP request completes successfully (not severed mid-
//	    response by Shutdown);
//	(b) Run returns within the 10s shutdown budget plus a small safety
//	    margin (no goroutine leak holding ListenAndServe open);
//	(c) the WebSocket client receives a close frame with code 1001
//	    (websocket.StatusGoingAway) — not a bare TCP teardown — so browsers
//	    can distinguish "server going away" from a network blip and act
//	    accordingly (e.g. stop hammering reconnect attempts).
//
// Without this contract, `systemctl stop cloop-ui` would either drop active
// websockets without notification (browsers retry immediately, hammering the
// next process) or hang past the systemd stop timeout and get SIGKILLed,
// risking partial state writes.
func TestServer_GracefulShutdown_FullIntegration(t *testing.T) {
	t.Parallel()

	dir := setupProjectDir(t, cloopGoal, nil)
	port := pickFreePort(t)
	srv := New(dir, port, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- srv.Run(ctx) }()

	waitForServerReady(t, port, 2*time.Second)

	// (c-prep) Open a WebSocket client and wait until the server has
	// registered it in hubClients so the shutdown path actually has a
	// peer to send the 1001 close frame to.
	wsURL := fmt.Sprintf("ws://127.0.0.1:%d/api/ws", port)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	conn, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	// Defer CloseNow so the test cleans up even if assertions fail
	// before the client finishes its read loop.
	defer conn.CloseNow() //nolint:errcheck

	if got := waitForHubClients(srv, 1, 2*time.Second); got != 1 {
		t.Fatalf("server never registered the WebSocket client (got %d)", got)
	}

	// (a) Fire a real HTTP request — /api/state is light and exists on
	// the UI mux. We synchronously check it completes with 200 so a
	// future regression that races Shutdown ahead of the response gets
	// caught here.
	statusURL := fmt.Sprintf("http://127.0.0.1:%d/api/state", port)
	httpClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := httpClient.Get(statusURL)
	if err != nil {
		t.Fatalf("GET /api/state: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/state: want 200, got %d", resp.StatusCode)
	}

	// Trigger graceful shutdown. Time the latency so a regression
	// where Run blocks past the configured 10s budget surfaces clearly.
	shutdownStart := time.Now()
	cancel()

	// (c) The client's next Read call should return a CloseError with
	// code 1001. We give it a 5s budget — Close handshakes are quick on
	// a localhost loopback. Without the shutdown path's explicit
	// conn.Close(StatusGoingAway, ...) call, the client would observe
	// io.EOF or a generic connection-reset error instead.
	readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readCancel()
	for {
		_, _, readErr := conn.Read(readCtx)
		if readErr == nil {
			// Server may push initial state frames before the
			// close frame — keep reading until the connection
			// terminates one way or another.
			continue
		}
		status := websocket.CloseStatus(readErr)
		if status == -1 {
			t.Fatalf("ws Read returned non-CloseError after shutdown: %v (want CloseStatus=GoingAway)", readErr)
		}
		if status != websocket.StatusGoingAway {
			t.Fatalf("ws close status: got %d (%v), want %d (GoingAway)", status, readErr, websocket.StatusGoingAway)
		}
		break
	}

	// (b) Run must return within the 10s shutdown budget plus a
	// margin for the ListenAndServe drain. 12s is generous enough to
	// avoid CI flakes but tight enough that a wedged shutdown trips
	// the test.
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error after shutdown: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatalf("Run did not return within 12s of shutdown — graceful shutdown is hung (started %v ago)", time.Since(shutdownStart))
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

