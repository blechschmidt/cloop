package ui

// Regression test: periodic SSE keep-alive comment frames (": keepalive\n\n")
// on the long-lived /api/events and /api/projects/events streams.
//
// Without keep-alives, a quiet SSE stream emits no bytes at all between
// state updates. A dead peer (laptop suspended, network partition, peer
// crashed without RST) holds the per-connection writer goroutine and the
// underlying TCP socket alive until the OS-level kernel TCP keepalive
// fires (default ~2 hours on Linux). Combined with sseWriteTimeout, a
// periodic keep-alive frame forces a TCP write so the server detects the
// dead peer within roughly sseKeepaliveInterval+sseWriteTimeout.
//
// SSE comment frames (lines beginning with `:`) are silently ignored by
// EventSource clients per the WHATWG spec, so the keep-alive is invisible
// to the application layer.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// readUntilKeepalive reads from r until it sees a line starting with ":"
// (an SSE comment frame) or until deadline. Returns the line if found, or
// an error otherwise.
func readUntilKeepalive(r *bufio.Reader, deadline time.Time, conn net.Conn) (string, error) {
	for time.Now().Before(deadline) {
		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return "", err
		}
		line, err := r.ReadString('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, io.EOF) {
				return "", err
			}
			return "", err
		}
		if strings.HasPrefix(line, ":") {
			return line, nil
		}
	}
	return "", fmt.Errorf("deadline exceeded without seeing keep-alive frame")
}

// drainHTTPHeaders consumes the HTTP response status line and headers from
// r, leaving the reader positioned at the start of the SSE body.
func drainHTTPHeaders(r *bufio.Reader, conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

// TestSSE_HandleEvents_KeepaliveOnQuietStream opens a raw TCP connection
// to /api/events, completes the HTTP/SSE handshake, then waits on a quiet
// stream (no broadcasts) until a `: keepalive\n\n` comment frame arrives.
// Without the keepalive ticker, the read would time out; with it, the
// frame must arrive within roughly sseKeepaliveInterval+jitter.
func TestSSE_HandleEvents_KeepaliveOnQuietStream(t *testing.T) {
	prev := sseKeepaliveInterval
	sseKeepaliveInterval = 100 * time.Millisecond
	t.Cleanup(func() { sseKeepaliveInterval = prev })

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	addr := ts.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET /api/events HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", addr); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	if err := drainHTTPHeaders(br, conn); err != nil {
		t.Fatalf("drain headers: %v", err)
	}

	// Generous deadline (20x the test interval) to absorb scheduling jitter
	// and to skip past the initial state snapshot frame the handler sends
	// on connect.
	deadline := time.Now().Add(20 * sseKeepaliveInterval)
	line, err := readUntilKeepalive(br, deadline, conn)
	if err != nil {
		t.Fatalf("waiting for SSE keep-alive frame (sseKeepaliveInterval=%v): %v",
			sseKeepaliveInterval, err)
	}
	if !strings.HasPrefix(line, ": keepalive") {
		t.Fatalf("expected keep-alive comment frame; got %q", line)
	}
}

// TestSSE_HandleProjectsEvents_KeepaliveOnQuietStream is the multi-project
// SSE analogue of the test above. Same contract: a quiet stream must emit
// the periodic comment frame.
func TestSSE_HandleProjectsEvents_KeepaliveOnQuietStream(t *testing.T) {
	prev := sseKeepaliveInterval
	sseKeepaliveInterval = 100 * time.Millisecond
	t.Cleanup(func() { sseKeepaliveInterval = prev })

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	addr := ts.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET /api/projects/events HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", addr); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	if err := drainHTTPHeaders(br, conn); err != nil {
		t.Fatalf("drain headers: %v", err)
	}

	deadline := time.Now().Add(20 * sseKeepaliveInterval)
	line, err := readUntilKeepalive(br, deadline, conn)
	if err != nil {
		t.Fatalf("waiting for SSE keep-alive frame (sseKeepaliveInterval=%v): %v",
			sseKeepaliveInterval, err)
	}
	if !strings.HasPrefix(line, ": keepalive") {
		t.Fatalf("expected keep-alive comment frame; got %q", line)
	}
}
