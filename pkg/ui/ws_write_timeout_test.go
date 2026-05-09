package ui

// Regression test: per-write WebSocket deadline (wsWriteTimeout).
//
// Before the fix, conn.Write(ctx, ...) used the long-lived request context
// inside handleWS. A wedged client (TCP buffers full, network stalled,
// half-open NAT) would pin the per-connection writer goroutine until the
// OS-level TCP timeout — minutes — letting an attacker exhaust goroutines
// by opening many stalled connections.
//
// The fix wraps each conn.Write in a context.WithTimeout(ctx, wsWriteTimeout).
// On timeout, nhooyr's timeoutLoop closes the underlying conn, the writer
// loop exits, and handleWS's deferred cleanup removes the hubClient.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// TestWSWrite_StalledClientDisconnectsWithinDeadline verifies that a client
// that connects and never reads is forcibly disconnected within roughly
// wsWriteTimeout, instead of pinning the server's writer goroutine until TCP
// gives up. We shrink wsWriteTimeout for speed and assert the server-side
// hubClient registration is cleaned up within ~5x the deadline.
func TestWSWrite_StalledClientDisconnectsWithinDeadline(t *testing.T) {
	prev := wsWriteTimeout
	wsWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { wsWriteTimeout = prev })

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
	// Deliberately never call conn.Read. Defer Close so the test cleans up
	// even if the assertion fails before the server detects the timeout.
	defer conn.Close(websocket.StatusNormalClosure, "") //nolint:errcheck

	// Wait for the server to register the client.
	registered := false
	for d := time.Now().Add(2 * time.Second); time.Now().Before(d); {
		srv.hubMu.Lock()
		n := 0
		for _, m := range srv.hubClients {
			n += len(m)
		}
		srv.hubMu.Unlock()
		if n >= 1 {
			registered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !registered {
		t.Fatal("server never registered the WebSocket client")
	}

	// Send a single very large message. The client never reads, so the
	// kernel TCP receive buffer fills, then send-side flow control kicks
	// in and the server's conn.Write blocks mid-payload. With the per-write
	// deadline in place, that blocked Write must abort in ~wsWriteTimeout.
	// Without the fix, it would block until the OS-level TCP timeout.
	//
	// 16 MiB comfortably exceeds default Linux loopback sndbuf+rcvbuf
	// (~4 MiB each) so a single Write reliably stalls. Spawn a background
	// pump in case the kernel happens to be configured with very large
	// buffers on this host — additional frames keep the writer goroutine
	// busy until the deadline fires.
	bigPayload := strings.Repeat("x", 16*1024*1024)
	raw, _ := json.Marshal(map[string]interface{}{"id": 1, "title": bigPayload})
	msg := wsMessage{Type: "task_update", Data: raw}
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		for i := 0; i < 8; i++ {
			srv.broadcastToProject(dir, msg)
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer func() { <-pumpDone }()

	// The deadline must fire and disconnect the stalled client. Allow up to
	// ~20x wsWriteTimeout to absorb GC pauses, scheduling jitter, and the
	// presence-broadcast cleanup path.
	disconnectDeadline := time.Now().Add(20 * wsWriteTimeout)
	for time.Now().Before(disconnectDeadline) {
		srv.hubMu.Lock()
		n := 0
		for _, m := range srv.hubClients {
			n += len(m)
		}
		srv.hubMu.Unlock()
		if n == 0 {
			return // success: server cleaned up the stalled client
		}
		time.Sleep(20 * time.Millisecond)
	}

	srv.hubMu.Lock()
	remaining := 0
	for _, m := range srv.hubClients {
		remaining += len(m)
	}
	srv.hubMu.Unlock()
	t.Fatalf("stalled WebSocket client was not disconnected within %v (wsWriteTimeout=%v); %d hubClient(s) still registered",
		20*wsWriteTimeout, wsWriteTimeout, remaining)
}

// TestWSWrite_AppliesDeadline is a direct unit test for the wsWrite helper:
// given a parent ctx with a far-future deadline, wsWrite must time out
// according to wsWriteTimeout — not wait for the parent. We construct a
// dedicated WebSocket where the peer never reads, then pump large frames
// until one wsWrite blocks, and assert the eventual error appears within
// ~10x wsWriteTimeout (the parent ctx is 30s away).
func TestWSWrite_AppliesDeadline(t *testing.T) {
	prev := wsWriteTimeout
	wsWriteTimeout = 100 * time.Millisecond
	t.Cleanup(func() { wsWriteTimeout = prev })

	type acceptResult struct {
		conn *websocket.Conn
		err  error
	}
	gotConn := make(chan acceptResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		gotConn <- acceptResult{conn: c, err: err}
		if err != nil {
			return
		}
		// Hold the connection open until the request context is canceled
		// (i.e. the client closes or the test server shuts down).
		<-r.Context().Done()
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/"
	clientConn, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close(websocket.StatusNormalClosure, "") //nolint:errcheck

	srvSide := <-gotConn
	if srvSide.err != nil {
		t.Fatalf("server accept: %v", srvSide.err)
	}
	defer srvSide.conn.CloseNow() //nolint:errcheck

	parentCtx, parentCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer parentCancel()

	payload := []byte(strings.Repeat("y", 65536))
	start := time.Now()
	for i := 0; i < 1024; i++ {
		if err := wsWrite(parentCtx, srvSide.conn, payload); err != nil {
			elapsed := time.Since(start)
			if elapsed > 10*wsWriteTimeout {
				t.Fatalf("wsWrite returned after %v; expected ≤ ~%v (wsWriteTimeout=%v)",
					elapsed, 10*wsWriteTimeout, wsWriteTimeout)
			}
			return
		}
	}
	t.Fatalf("wsWrite never blocked even after 1024 large frames; the test cannot exercise the deadline path on this platform")
}
