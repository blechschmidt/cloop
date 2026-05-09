package ui

// Goroutine-leak regression tests for the long-lived push paths.
//
// `handleWS` spawns two goroutines per connection (the request-handler
// frame writer plus a drain goroutine reading inbound frames). `handleEvents`
// runs a single per-connection writer goroutine. A regression in the cleanup
// path — a missed cancel(), a forgotten defer, a writer that exits without
// nudging the drain — would leave one or more goroutines pinned past the
// connection's lifetime, scaling linearly with abandoned reconnects until
// the process exhausts its goroutine table or saturates scheduler overhead.
//
// These tests are deliberately *macroscopic*: they open N short-lived
// connections, close them, and assert that runtime.NumGoroutine returns
// to within a small slack of the pre-test baseline. They don't try to pin
// the exact count (the Go runtime, the test framework, and nhooyr's
// internals all spawn ambient goroutines that flap by 1–2 between calls)
// — they assert the difference does not scale with N. With N=20, a leak
// of one goroutine per connection produces a delta of ~20–40, far above
// the slack threshold; the noise floor is ~5.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// goroutineLeakSlack is the maximum acceptable goroutine-count delta after
// N connections have been opened and closed. The number is large enough to
// absorb runtime/scheduler/nhooyr ambient flapping but small enough that a
// real per-connection leak (which scales with N) would clearly fail the
// assertion. Tuned empirically: ambient delta on a single iteration is
// typically 0–3.
const goroutineLeakSlack = 10

// settleGoroutineCount triggers GC and sleeps briefly to give transient
// goroutines a chance to exit, then returns the current count. Used both
// for the baseline reading and the post-test reading. The sleep is required
// because conn.Close returns once the close-frame is queued; the server's
// drain goroutine sees the resulting Read error and exits asynchronously,
// and the writer loop only exits after the deferred cancel() propagates
// through the select.
func settleGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// TestWSConnectionLifecycle_NoGoroutineLeak opens N WebSocket connections,
// closes them, waits for the hub-client count to return to zero, then
// verifies runtime.NumGoroutine has returned to within goroutineLeakSlack
// of the pre-test baseline. A regression in handleWS's cleanup chain
// (drain goroutine that doesn't exit, writer that doesn't honour ctx
// cancel, deferred hubClient cleanup that doesn't run) would scale the
// leaked goroutines linearly with N.
func TestWSConnectionLifecycle_NoGoroutineLeak(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	// Warm up: dial once and disconnect so any one-time package init
	// (e.g., nhooyr lazy-allocated buffers) doesn't pollute the baseline.
	{
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, _, err := websocket.Dial(dialCtx, wsURL, nil)
		dialCancel()
		if err != nil {
			t.Fatalf("warmup dial: %v", err)
		}
		conn.SetReadLimit(-1)
		if got := waitForHubClients(srv, 1, 2*time.Second); got != 1 {
			t.Fatalf("warmup: server did not register client (got %d)", got)
		}
		_ = conn.Close(websocket.StatusNormalClosure, "")
		if got := waitForHubClients(srv, 0, 3*time.Second); got != 0 {
			t.Fatalf("warmup: hubClient still registered after close (got %d)", got)
		}
	}

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, _, err := websocket.Dial(dialCtx, wsURL, nil)
		dialCancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.SetReadLimit(-1)
		if got := waitForHubClients(srv, 1, 2*time.Second); got != 1 {
			t.Fatalf("iter %d: server did not register client (got %d)", i, got)
		}
		// Use CloseNow on alternating iterations to exercise both the
		// graceful-close path (writer sees ctx.Done after handshake) and
		// the abrupt-close path (drain Read returns net.ErrClosed). Both
		// must trigger the deferred cleanup.
		if i%2 == 0 {
			_ = conn.Close(websocket.StatusNormalClosure, "")
		} else {
			_ = conn.CloseNow()
		}
		if got := waitForHubClients(srv, 0, 3*time.Second); got != 0 {
			t.Fatalf("iter %d: hubClient still registered after close (got %d)", i, got)
		}
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in WebSocket connection lifecycle: baseline=%d post=%d delta=%d (>%d) after %d open/close cycles",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// TestSSEConnectionLifecycle_NoGoroutineLeak is the SSE analogue of the
// WebSocket test. Each connection runs a single per-connection writer
// goroutine in handleEvents. The test opens N raw TCP connections to
// /api/events, completes the HTTP request, reads enough of the response
// to confirm the handler is live, then closes the TCP socket. The
// writer's next writeSSE call (or the http.Server's request-ctx
// cancellation) tears it down. The post-test goroutine count must
// return to within goroutineLeakSlack of the pre-test baseline.
func TestSSEConnectionLifecycle_NoGoroutineLeak(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	addr := ts.Listener.Addr().String()

	// Shrink the keepalive interval so the writer detects the closed peer
	// quickly via its next writeSSE attempt. Without this, a quiet stream
	// would only emit on the default 30s tick, and the test's
	// waitForSSEClients would have to wait that long for cleanup.
	prev := sseKeepaliveInterval
	sseKeepaliveInterval = 100 * time.Millisecond
	t.Cleanup(func() { sseKeepaliveInterval = prev })

	// Warm up.
	if err := openAndCloseSSE(addr); err != nil {
		t.Fatalf("warmup: %v", err)
	}
	if got := waitForSSEClients(srv, 0, 3*time.Second); got != 0 {
		t.Fatalf("warmup: SSE client still registered after close (got %d)", got)
	}

	baseline := settleGoroutineCount()

	const N = 20
	for i := 0; i < N; i++ {
		if err := openAndCloseSSE(addr); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if got := waitForSSEClients(srv, 0, 3*time.Second); got != 0 {
			t.Fatalf("iter %d: SSE client still registered after close (got %d)", i, got)
		}
	}

	post := settleGoroutineCount()
	delta := post - baseline
	if delta > goroutineLeakSlack {
		t.Fatalf("goroutine leak in SSE connection lifecycle: baseline=%d post=%d delta=%d (>%d) after %d open/close cycles",
			baseline, post, delta, goroutineLeakSlack, N)
	}
}

// openAndCloseSSE dials a raw TCP socket to addr, writes a GET /api/events
// HTTP request, drains the response headers (so we know the SSE handler
// has been entered), then closes the socket. The server's writer detects
// the closed peer on its next write attempt — either the periodic
// keepalive tick or http.Server's request-ctx cancellation, whichever
// fires first.
func openAndCloseSSE(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET /api/events HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	br := bufio.NewReader(conn)
	if err := drainHTTPHeaders(br, conn); err != nil {
		return fmt.Errorf("drain headers: %w", err)
	}

	// Read a tiny prefix of the SSE body so the handler has definitely
	// proceeded past handshake into the writer-loop select. Best-effort:
	// the initial state-snapshot frame may or may not be ready before our
	// short deadline; either is fine — we only care that the handler
	// goroutine is live, which it is by the time we reach this point.
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = br.ReadString('\n')
	return nil
}

// waitForSSEClients blocks until the SSE client count reaches want or the
// deadline expires. Returns the last observed count.
func waitForSSEClients(srv *Server, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		srv.mu.Lock()
		got := len(srv.clients)
		srv.mu.Unlock()
		if got == want {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}
