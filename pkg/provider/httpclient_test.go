package provider

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewHTTPClient_TransportTimeoutsSet verifies that the shared HTTP client
// has all the transport-level timeouts configured. The bare zero-value
// http.Client used previously had none of these, so a hung peer could block
// a Complete() call indefinitely.
func TestNewHTTPClient_TransportTimeoutsSet(t *testing.T) {
	c := NewHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout is zero — TLS handshake can hang forever")
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("ResponseHeaderTimeout is zero — server stalls before headers can hang forever")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout is zero — idle conns are never reaped")
	}
	if tr.ExpectContinueTimeout == 0 {
		t.Error("ExpectContinueTimeout is zero")
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil — TCP connect uses default dialer with no keepalive")
	}
	// Client.Timeout MUST remain unset so streaming response bodies are not cut
	// off mid-stream. This is intentional and load-bearing — guard the invariant.
	if c.Timeout != 0 {
		t.Errorf("Client.Timeout = %v, want 0 (must not cap streaming reads)", c.Timeout)
	}
}

// TestNewHTTPClient_ResponseHeaderTimeoutFires verifies that a server which
// accepts the connection but never sends response headers does not hang the
// client forever. Without ResponseHeaderTimeout this would block until the OS
// keepalive killed the socket (~2 hours on Linux).
func TestNewHTTPClient_ResponseHeaderTimeoutFires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	// Listen on a TCP socket but never write a response. http.NewRequest will
	// connect successfully, then the client will wait for headers.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	var connsAccepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connsAccepted.Add(1)
			// Hold the connection open without writing anything. Close on test exit
			// via the listener close.
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	// Override ResponseHeaderTimeout to something short so the test runs fast.
	c := NewHTTPClient()
	tr := c.Transport.(*http.Transport)
	tr.ResponseHeaderTimeout = 200 * time.Millisecond

	url := "http://" + ln.Addr().String() + "/"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	start := time.Now()
	_, err = c.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Should fail well before 5s — guards against the timeout being effectively disabled.
	if elapsed > 5*time.Second {
		t.Errorf("request took %v, expected ResponseHeaderTimeout to fire much sooner", elapsed)
	}
}

// TestNewHTTPClient_HappyPath confirms the client still works for a normal
// short request — i.e. our transport tweaks don't break the common case.
func TestNewHTTPClient_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewHTTPClient()
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}
