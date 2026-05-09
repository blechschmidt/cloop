package ui

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestNewUIHTTPServer_TimeoutsSet asserts that the UI's http.Server is
// constructed with slowloris/idle-keepalive defenses but NO ReadTimeout or
// WriteTimeout, since those would cut off SSE streams and WebSocket frames
// mid-flight. This is a load-bearing invariant: the UI's /api/events (SSE)
// and /api/ws (WebSocket) endpoints intentionally hold connections open for
// the lifetime of a session.
func TestNewUIHTTPServer_TimeoutsSet(t *testing.T) {
	srv := newUIHTTPServer(":0", http.NewServeMux())

	if srv.ReadHeaderTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout must be set (>0); got %v", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout must be set (>0); got %v", srv.IdleTimeout)
	}
	if srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout must be 0 to allow long-lived SSE/WS reads; got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must be 0 to allow long-lived SSE/WS writes; got %v", srv.WriteTimeout)
	}
}

// TestNewUIHTTPServer_ReadHeaderTimeoutFires verifies the slowloris defense
// actually trips. We open a TCP socket to the server, write a partial HTTP
// request line without the terminating CRLF, and confirm the server closes
// the connection within the timeout window. Without ReadHeaderTimeout, this
// connection would be held open indefinitely and could exhaust file
// descriptors under attack.
func TestNewUIHTTPServer_ReadHeaderTimeoutFires(t *testing.T) {
	srv := newUIHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Override to a small value so the test runs fast.
	srv.ReadHeaderTimeout = 200 * time.Millisecond

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a partial header — no final CRLF, so the server is still reading.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n")); err != nil {
		t.Fatalf("write partial: %v", err)
	}

	// Set a generous deadline; a working ReadHeaderTimeout closes the
	// connection within ~ReadHeaderTimeout. Without the timeout, this
	// Read would block until the client gives up.
	deadline := time.Now().Add(2 * time.Second)
	conn.SetReadDeadline(deadline)

	buf := make([]byte, 1)
	start := time.Now()
	_, err = conn.Read(buf)
	elapsed := time.Since(start)

	// Either EOF (server closed) or a network error indicates the timeout
	// fired. A nil error means the server somehow served the partial
	// request, which would be a regression.
	if err == nil {
		t.Fatalf("expected server to close partial-header connection, but Read returned nil error after %v", elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("ReadHeaderTimeout did not fire within expected window; elapsed=%v", elapsed)
	}
}
