package ui

// Regression test: server-initiated WebSocket ping (wsPingInterval, wsPingTimeout).
//
// Without server-initiated keepalive, a TCP-connected but unresponsive peer
// (laptop suspended, network partition, peer process crashed without RST)
// holds the per-connection goroutine pair alive until the OS-level TCP
// keepalive fires — typically ~2 hours on Linux. The ping ticker in the
// writer loop probes every wsPingInterval and treats no-pong-within-
// wsPingTimeout as a dead connection, exiting the writer goroutine and
// triggering the deferred hubClient cleanup.
//
// This test simulates an unresponsive peer by dialling but never calling
// Read on the client side: nhooyr's pong dispatch only happens during a
// Read call, so the server's Ping never receives a pong and times out.

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// TestWSPing_UnresponsivePeerDroppedViaPingTimeout verifies that a peer
// that keeps the TCP connection open but never processes inbound frames
// (so it never sends pongs) is dropped within roughly wsPingInterval +
// wsPingTimeout. We shrink both for speed.
func TestWSPing_UnresponsivePeerDroppedViaPingTimeout(t *testing.T) {
	prevInterval := wsPingInterval
	prevTimeout := wsPingTimeout
	wsPingInterval = 100 * time.Millisecond
	wsPingTimeout = 200 * time.Millisecond
	t.Cleanup(func() {
		wsPingInterval = prevInterval
		wsPingTimeout = prevTimeout
	})

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	conn, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Defer CloseNow so the test cleans up even if assertions fail before the
	// server detects the timeout. Deliberately do NOT call conn.Read — that
	// is what makes the peer unresponsive at the WebSocket protocol layer
	// (nhooyr dispatches pong frames inside Read; with no Read, no pong).
	defer conn.CloseNow() //nolint:errcheck

	if got := waitForHubClients(srv, 1, 2*time.Second); got != 1 {
		t.Fatalf("server never registered the WebSocket client (got %d)", got)
	}

	// Allow up to ~20x (wsPingInterval+wsPingTimeout) for the ping to fire,
	// the timeout to expire, the writer to exit, and the deferred cleanup
	// path to deregister the hubClient.
	budget := 20 * (wsPingInterval + wsPingTimeout)
	if got := waitForHubClients(srv, 0, budget); got != 0 {
		t.Fatalf("unresponsive peer was not dropped via ping timeout within %v (interval=%v, timeout=%v); %d hubClient(s) still registered",
			budget, wsPingInterval, wsPingTimeout, got)
	}
}

// TestWSPing_ResponsivePeerStaysConnected is the negative companion: a
// peer that does call Read sends pong replies automatically, so the ping
// path must NOT trigger a disconnect even when the interval and timeout
// are tiny. Catches regressions where the writer loop misinterprets a
// ping success as an error or where ctx propagation is broken.
func TestWSPing_ResponsivePeerStaysConnected(t *testing.T) {
	prevInterval := wsPingInterval
	prevTimeout := wsPingTimeout
	wsPingInterval = 50 * time.Millisecond
	wsPingTimeout = 500 * time.Millisecond
	t.Cleanup(func() {
		wsPingInterval = prevInterval
		wsPingTimeout = prevTimeout
	})

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	conn, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "") //nolint:errcheck
	conn.SetReadLimit(-1)

	if got := waitForHubClients(srv, 1, 2*time.Second); got != 1 {
		t.Fatalf("server never registered the WebSocket client (got %d)", got)
	}

	// Run a continuous reader so nhooyr's pong dispatch can run. Stop on
	// any error (test-end Close is the expected cause).
	readDone := make(chan struct{})
	readCtx, readCancel := context.WithCancel(context.Background())
	defer readCancel()
	go func() {
		defer close(readDone)
		for {
			if _, _, err := conn.Read(readCtx); err != nil {
				return
			}
		}
	}()

	// Run for several ping intervals; the client must remain connected.
	time.Sleep(10 * (wsPingInterval + wsPingTimeout))

	if got := activeHubClientCount(srv); got != 1 {
		t.Fatalf("responsive peer was disconnected by ping path; want 1 hubClient, got %d", got)
	}

	readCancel()
	<-readDone
}
