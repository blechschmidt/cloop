package ui

// Regression tests: WebSocket inbound bounds (wsReadFrameLimit and
// wsMaxInboundMsgsPerSecond).
//
// The handleWS drain goroutine accepts inbound frames so the ws stream is
// bidirectional for future use. Two defensive bounds protect that goroutine
// from abuse:
//
//   - wsReadFrameLimit caps a single frame size. Without it, a relied-on
//     nhooyr default could change upstream and let oversized frames slip
//     through. On overshoot, nhooyr closes with StatusMessageTooBig.
//   - wsMaxInboundMsgsPerSecond caps the *rate* of inbound frames. Without
//     it, a client streaming many tiny frames keeps the drain goroutine
//     hot forever (each Read returns immediately, the loop never yields).
//     On overshoot, the server closes with StatusPolicyViolation.
//
// These tests assert that breaching either bound causes the server to drop
// the connection — i.e. the hubClient registration is removed.

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// activeHubClientCount counts every registered hub client across every
// project. Used to confirm cleanup after the server drops a connection.
func activeHubClientCount(srv *Server) int {
	srv.hubMu.Lock()
	defer srv.hubMu.Unlock()
	n := 0
	for _, m := range srv.hubClients {
		n += len(m)
	}
	return n
}

// waitForHubClients blocks until activeHubClientCount(srv) == want or the
// deadline expires. Returns the last observed count.
func waitForHubClients(srv *Server, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		got := activeHubClientCount(srv)
		if got == want {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestWSDrain_OversizedFrameDropsClient verifies that a client sending a
// single frame larger than wsReadFrameLimit causes the server's drain
// goroutine to abort and the hubClient to be cleaned up. We shrink the
// limit so the test payload stays small.
func TestWSDrain_OversizedFrameDropsClient(t *testing.T) {
	prev := wsReadFrameLimit
	wsReadFrameLimit = 256
	t.Cleanup(func() { wsReadFrameLimit = prev })

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
	// Allow the test client to receive the server's initial state push,
	// which (under wsReadFrameLimit=256 if set client-side) would itself
	// trip the limit.
	conn.SetReadLimit(-1)

	if got := waitForHubClients(srv, 1, 2*time.Second); got != 1 {
		t.Fatalf("server never registered the WebSocket client (got %d)", got)
	}

	// Send a single oversized frame (4x the limit). The server's drain
	// goroutine must reject it and tear down the connection.
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer writeCancel()
	payload := []byte(strings.Repeat("x", int(wsReadFrameLimit)*4))
	if err := conn.Write(writeCtx, websocket.MessageText, payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	if got := waitForHubClients(srv, 0, 3*time.Second); got != 0 {
		t.Fatalf("oversized inbound frame did not drop the client; %d hubClient(s) still registered", got)
	}
}

// TestWSDrain_FloodedFramesDropsClient verifies that a client streaming
// inbound frames faster than wsMaxInboundMsgsPerSecond causes the server's
// drain goroutine to close the connection with StatusPolicyViolation. We
// shrink the rate cap so the test sends a manageable number of frames.
func TestWSDrain_FloodedFramesDropsClient(t *testing.T) {
	prev := wsMaxInboundMsgsPerSecond
	wsMaxInboundMsgsPerSecond = 5
	t.Cleanup(func() { wsMaxInboundMsgsPerSecond = prev })

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

	// Burst a lot more than the cap. They must all land within the same
	// 1s window for the rate check to trip; sending without sleeps between
	// frames over loopback easily satisfies that.
	burst := wsMaxInboundMsgsPerSecond * 20
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer writeCancel()
	for i := 0; i < burst; i++ {
		if err := conn.Write(writeCtx, websocket.MessageText, []byte("ping")); err != nil {
			// Once the server closes the connection, subsequent writes will
			// fail. That's the expected outcome — break and proceed to the
			// hubClient assertion.
			break
		}
	}

	if got := waitForHubClients(srv, 0, 3*time.Second); got != 0 {
		t.Fatalf("flood of inbound frames did not drop the client; %d hubClient(s) still registered", got)
	}
}
