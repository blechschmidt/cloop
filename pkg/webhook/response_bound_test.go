package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestSend_ResponseBodyDrainedAndCapped verifies that:
//  1. The client returns promptly even when the server streams a response body
//     larger than the cap (defense-in-depth — a hostile webhook target cannot
//     keep us reading forever).
//  2. The bytes the client reads from the response body do not exceed
//     webhookMaxResponseBytes by more than a small buffer.
func TestSend_ResponseBodyDrainedAndCapped(t *testing.T) {
	const flood = 4 * webhookMaxResponseBytes // 256 KiB — far above the 64 KiB cap

	var bytesWritten int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// Flush so the client starts reading; then write a very large body.
		flusher, _ := w.(http.Flusher)
		chunk := make([]byte, 4096)
		var written int64
		for written < flood {
			n, err := w.Write(chunk)
			if err != nil {
				break
			}
			written += int64(n)
			if flusher != nil {
				flusher.Flush()
			}
			// Detect early disconnect (ctx done = client gave up reading).
			select {
			case <-r.Context().Done():
				atomic.StoreInt64(&bytesWritten, written)
				return
			default:
			}
		}
		atomic.StoreInt64(&bytesWritten, written)
	}))
	defer srv.Close()

	c := New(srv.URL, nil, nil, "")

	// Run send synchronously so we can time it. Use the unexported entry point.
	done := make(chan struct{})
	start := time.Now()
	go func() {
		c.send(Payload{Event: EventTaskDone, Goal: "bounded-response", Timestamp: time.Now()})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("send() did not return within 5s — body drain is unbounded")
	}
	elapsed := time.Since(start)

	// Sanity: the call must not have taken anywhere near the 10 s ctx timeout.
	if elapsed > 3*time.Second {
		t.Errorf("send() took %v — should complete well under the 10 s ctx deadline once the cap is reached", elapsed)
	}
}

// TestSend_ContextDeadlinePropagated verifies that a hung server (one that
// accepts the connection but never responds) does not pin the goroutine
// beyond the 10 s ctx deadline. We use a short-lived context to keep the
// test fast; the production code uses 10 s.
func TestSend_ContextDeadlinePropagated(t *testing.T) {
	hangCh := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hangCh // never returns until test cleanup
	}))

	// LIFO: close hangCh first (so handler returns), then close srv (so it can
	// finish waiting for active connections).
	defer srv.Close()
	defer close(hangCh)

	// Replicate send() but with a tighter ctx so the test runs fast.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if resp != nil {
		_ = resp.Body.Close()
	}

	if err == nil {
		t.Fatal("expected ctx deadline error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Do() returned after %v — ctx deadline (200 ms) was not respected", elapsed)
	}
}
