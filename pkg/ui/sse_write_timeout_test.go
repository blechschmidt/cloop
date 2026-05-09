package ui

// Regression test: per-write SSE deadline (sseWriteTimeout) and Write-error
// propagation in handleEvents / handleProjectsEvents / handlePlanChat.
//
// Before the fix, fmt.Fprintf(w, ...) + flusher.Flush() inside the SSE
// writer loop discarded write errors and had no per-write deadline. A
// wedged client (TCP buffers full, network stalled, half-open NAT entry)
// would pin the per-connection writer goroutine until the OS-level send
// timeout — typically minutes — letting an attacker exhaust goroutines by
// opening many stalled SSE connections and never draining.
//
// The fix wraps each write in writeSSE, which arms a SetWriteDeadline on
// the underlying conn via http.ResponseController and returns the first
// Write error so the caller can exit the loop.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// errorFlushWriter is a minimal http.ResponseWriter+Flusher whose Write
// returns a configurable error and whose Flush is a no-op. Used to verify
// writeSSE propagates Write errors.
type errorFlushWriter struct {
	header http.Header
	err    error
}

func (e *errorFlushWriter) Header() http.Header {
	if e.header == nil {
		e.header = http.Header{}
	}
	return e.header
}
func (e *errorFlushWriter) Write(p []byte) (int, error) { return 0, e.err }
func (e *errorFlushWriter) WriteHeader(int)             {}
func (e *errorFlushWriter) Flush()                      {}

// TestWriteSSE_PropagatesWriteError verifies that when the underlying
// ResponseWriter's Write returns an error, writeSSE returns that error so
// the SSE handler loop can exit instead of looping on a dead connection.
func TestWriteSSE_PropagatesWriteError(t *testing.T) {
	want := errors.New("simulated TCP write failure")
	w := &errorFlushWriter{err: want}
	got := writeSSE(w, w, "data: %s\n\n", "payload")
	if got == nil {
		t.Fatal("writeSSE returned nil; expected the underlying Write error to propagate")
	}
	if !errors.Is(got, want) {
		t.Fatalf("writeSSE returned %v; want %v", got, want)
	}
}

// TestWriteSSE_NoErrorOnSuccess verifies that writeSSE returns nil when the
// underlying Write succeeds, regardless of whether the response writer
// supports SetWriteDeadline (httptest.ResponseRecorder doesn't, so this
// also covers the best-effort SetWriteDeadline arming).
func TestWriteSSE_NoErrorOnSuccess(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := writeSSE(rec, rec, "data: %s\n\n", "ok"); err != nil {
		t.Fatalf("writeSSE returned %v; want nil", err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data: ok") {
		t.Errorf("writeSSE body = %q; want it to contain 'data: ok'", body)
	}
}

// TestSSE_StalledClientDisconnectsWithinDeadline opens a raw TCP connection
// to /api/events, completes the HTTP/SSE handshake, then stops draining and
// triggers many large broadcasts. With the per-write deadline in place, the
// server's writer goroutine must abort the wedged Write within roughly
// sseWriteTimeout and the SSE client must be removed from the hub. Without
// the fix, the goroutine would block until the OS-level TCP timeout
// (minutes) and the s.clients map would stay populated.
func TestSSE_StalledClientDisconnectsWithinDeadline(t *testing.T) {
	prev := sseWriteTimeout
	sseWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { sseWriteTimeout = prev })

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	addr := ts.Listener.Addr().String()

	// Open a raw TCP conn so we can read just the headers and then stall.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET /api/events HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", addr); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read response headers to confirm SSE stream started, then stop.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read headers: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "text/event-stream") {
		t.Fatalf("response missing SSE content-type; got: %s", string(buf[:n]))
	}

	// Wait for the server to register the SSE client.
	registered := false
	for d := time.Now().Add(2 * time.Second); time.Now().Before(d); {
		srv.mu.Lock()
		nClients := len(srv.clients)
		srv.mu.Unlock()
		if nClients >= 1 {
			registered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !registered {
		t.Fatal("server never registered the SSE client")
	}

	// Trigger many large broadcasts. The client never reads, so the kernel
	// TCP send buffer fills, then send-side flow control kicks in and the
	// server's Write blocks. With the per-write deadline, that blocked
	// Write must abort in ~sseWriteTimeout. 64 KiB × 200 frames easily
	// exceeds default Linux loopback sndbuf+rcvbuf (~4 MiB combined).
	bigPayload := strings.Repeat("z", 64*1024)
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		for i := 0; i < 200; i++ {
			srv.broadcast(bigPayload)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	defer func() { <-pumpDone }()

	// The deadline must fire and clean up the stalled client. Allow up to
	// 30x sseWriteTimeout to absorb scheduling jitter.
	disconnectDeadline := time.Now().Add(30 * sseWriteTimeout)
	for time.Now().Before(disconnectDeadline) {
		srv.mu.Lock()
		nClients := len(srv.clients)
		srv.mu.Unlock()
		if nClients == 0 {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	srv.mu.Lock()
	remaining := len(srv.clients)
	srv.mu.Unlock()
	t.Fatalf("stalled SSE client was not cleaned up within %v (sseWriteTimeout=%v); %d sseClient(s) still registered",
		30*sseWriteTimeout, sseWriteTimeout, remaining)
}
