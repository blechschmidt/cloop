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

// setWSPingTiming shrinks the ping cadence for one test and restores it after.
//
// The restore is the reason this exists as a helper rather than an inline
// t.Cleanup: these cells are package-wide, every pkg/ui test that starts a
// server leaves a writer loop reading them, and the test binary runs cleanups
// while other tests are still serving. Writing them directly was a genuine data
// race — see wsPingIntervalNS — so the mutation goes through the atomics in one
// place instead of being spelled out at each call site.
func setWSPingTiming(t *testing.T, interval, timeout time.Duration) {
	t.Helper()
	prevInterval := wsPingIntervalNS.Swap(int64(interval))
	prevTimeout := wsPingTimeoutNS.Swap(int64(timeout))
	t.Cleanup(func() {
		wsPingIntervalNS.Store(prevInterval)
		wsPingTimeoutNS.Store(prevTimeout)
	})
}

// TestWSPing_UnresponsivePeerDroppedViaPingTimeout verifies that a peer
// that keeps the TCP connection open but never processes inbound frames
// (so it never sends pongs) is dropped within roughly wsPingInterval +
// wsPingTimeout. We shrink both for speed.
func TestWSPing_UnresponsivePeerDroppedViaPingTimeout(t *testing.T) {
	setWSPingTiming(t, 100*time.Millisecond, 200*time.Millisecond)

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
	budget := 20 * (wsPingInterval() + wsPingTimeout())
	if got := waitForHubClients(srv, 0, budget); got != 0 {
		t.Fatalf("unresponsive peer was not dropped via ping timeout within %v (interval=%v, timeout=%v); %d hubClient(s) still registered",
			budget, wsPingInterval(), wsPingTimeout(), got)
	}
}

// TestWSPing_ResponsivePeerStaysConnected is the negative companion: a
// peer that does call Read sends pong replies automatically, so the ping
// path must NOT trigger a disconnect even when the interval and timeout
// are tiny. Catches regressions where the writer loop misinterprets a
// ping success as an error or where ctx propagation is broken.
func TestWSPing_ResponsivePeerStaysConnected(t *testing.T) {
	// A short interval so many pings fire, but a timeout long enough that
	// losing the CPU cannot be mistaken for an unresponsive peer. At 500ms
	// this test was asserting that the client goroutine gets scheduled
	// promptly, which under a full -race suite it does not: a single stall
	// longer than the timeout drops the connection and the test reports a
	// ping-path regression that is not there. The pong deadline is not what
	// this test is about — see the companion above for that.
	setWSPingTiming(t, 50*time.Millisecond, 5*time.Second)

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

	// Started before the registration wait, and that ordering is the fix.
	// nhooyr only dispatches pong frames from inside Read, so until this
	// goroutine is running the peer is unresponsive at the protocol layer —
	// exactly what the companion test above simulates deliberately. The
	// server begins pinging the moment the client registers, so starting the
	// reader after waiting for that left a window in which the peer this test
	// calls "responsive" was not, and a slow enough runner turned the window
	// into a disconnect.
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

	if got := waitForHubClients(srv, 1, 10*time.Second); got != 1 {
		t.Fatalf("server never registered the WebSocket client (got %d)", got)
	}

	// Long enough for many pings to fire and be answered. Scaled off the
	// interval alone: tying it to the timeout as well would make the run
	// time grow with a deadline that is now deliberately generous.
	time.Sleep(20 * wsPingInterval())

	if got := activeHubClientCount(srv); got != 1 {
		t.Fatalf("responsive peer was disconnected by ping path; want 1 hubClient, got %d", got)
	}

	readCancel()
	<-readDone
}
