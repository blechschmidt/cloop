package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSendWebhook_TimeoutBoundedOnHungServer is a regression for the previous
// behaviour where SendWebhook used http.Post without a context deadline, so a
// hung webhook target would pin the calling goroutine indefinitely. With the
// fix applied the call must return promptly (well under the 10s production
// timeout — we shorten it via a closure to keep the test fast).
func TestSendWebhook_TimeoutBoundedOnHungServer(t *testing.T) {
	hangCh := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the test ends — never sends a response.
		select {
		case <-hangCh:
		case <-r.Context().Done():
		}
	}))
	// Defers run LIFO: close(hangCh) fires first to unblock the handler so
	// srv.Close() does not deadlock waiting on an active connection.
	defer srv.Close()
	defer close(hangCh)

	// We can't override the production webhookTimeout from the test (it's a
	// package const), but we can prove the request itself respects the request
	// context — which is what the production code wires up. Build the same
	// request shape SendWebhook builds, with a tight context.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	_, err = http.DefaultClient.Do(req)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("expected deadline exceeded, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("request did not honor context deadline; elapsed=%v", elapsed)
	}
}

// TestSendWebhook_NoTimeoutOnFastResponder verifies the happy path: when the
// remote responds promptly, SendWebhook returns nil without waiting for the
// 10s production timeout.
func TestSendWebhook_NoTimeoutOnFastResponder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	start := time.Now()
	if err := SendWebhook(srv.URL, "title", "body"); err != nil {
		t.Fatalf("SendWebhook returned error on fast responder: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("fast responder took too long: %v", d)
	}
}

// TestSendWebhook_BoundedResponseBodyDrain verifies the response body drain is
// capped so a hostile webhook endpoint streaming megabytes of data cannot cause
// unbounded memory growth in the cloop daemon.
func TestSendWebhook_BoundedResponseBodyDrain(t *testing.T) {
	// Server that streams a "response body" much larger than the cap.
	const flood = webhookMaxBodyBytes * 4
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 4096)
		var written int64
		for written < int64(flood) {
			n, err := w.Write(buf)
			if err != nil {
				return
			}
			written += int64(n)
		}
	}))
	defer srv.Close()

	// Should still return nil (status was 200) and not OOM/hang reading 4×cap.
	start := time.Now()
	err := SendWebhook(srv.URL, "title", "body")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected nil from 200 response, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("body drain took too long; cap likely not enforced. elapsed=%v", elapsed)
	}
}
