package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer creates a Server with the given RPS and Burst for testing.
// It wires up only the rate-limit middleware so no state files are needed.
func newTestServer(rps float64, burst int) *Server {
	s := &Server{
		RPS:       rps,
		Burst:     burst,
		rlBuckets: make(map[string]*ipBucket),
	}
	return s
}

// handler returns a simple 200 OK handler for testing.
func handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// TestRateLimiter_AllowsWithinBurst verifies that requests within the burst
// limit are served with 200 OK.
func TestRateLimiter_AllowsWithinBurst(t *testing.T) {
	s := newTestServer(10, 5)
	h := s.rateLimitMiddleware(handler())

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rr.Code)
		}
	}
}

// TestRateLimiter_ReturnsRetryAfterHeader verifies that 429 responses include
// a Retry-After header.
func TestRateLimiter_ReturnsRetryAfterHeader(t *testing.T) {
	s := newTestServer(10, 2)
	h := s.rateLimitMiddleware(handler())

	// Exhaust the burst bucket.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:9999"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	// Next request must be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header to be set on 429 response")
	}
}

// TestRateLimiter_ExceedsBurstReturns429 verifies that rapid requests beyond
// the burst limit receive 429 responses.
func TestRateLimiter_ExceedsBurstReturns429(t *testing.T) {
	// Small burst of 3 so we can exhaust it quickly.
	s := newTestServer(1, 3)
	h := s.rateLimitMiddleware(handler())

	const total = 10
	got200 := 0
	got429 := 0

	for i := 0; i < total; i++ {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		// Same IP for all requests so they share a bucket.
		req.RemoteAddr = "172.16.0.5:4321"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		switch rr.Code {
		case http.StatusOK:
			got200++
		case http.StatusTooManyRequests:
			got429++
		default:
			t.Fatalf("unexpected status %d", rr.Code)
		}
	}

	if got200 != 3 {
		t.Errorf("expected exactly 3 allowed requests (burst=3), got %d", got200)
	}
	if got429 != total-3 {
		t.Errorf("expected %d rate-limited requests, got %d", total-3, got429)
	}
}

// TestRateLimiter_IndependentPerIP verifies that two different IPs each get
// their own independent bucket.
func TestRateLimiter_IndependentPerIP(t *testing.T) {
	s := newTestServer(1, 2)
	h := s.rateLimitMiddleware(handler())

	ips := []string{"1.1.1.1:100", "2.2.2.2:200"}

	// Each IP should be allowed up to burst=2 requests.
	for _, ip := range ips {
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = ip
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("ip %s request %d: expected 200, got %d", ip, i+1, rr.Code)
			}
		}
		// Third request from each IP must be 429.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("ip %s: expected 429 on 3rd request, got %d", ip, rr.Code)
		}
	}
}

// TestRateLimiter_DefaultsApplied verifies that zero-value RPS/Burst fall back
// to the package defaults without panicking.
func TestRateLimiter_DefaultsApplied(t *testing.T) {
	s := newTestServer(0, 0) // should use defaultRPS=20, defaultBurst=50
	h := s.rateLimitMiddleware(handler())

	// 50 requests should all succeed with the default burst of 50.
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.10.10.10:5555"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 with default burst, got %d", i+1, rr.Code)
		}
	}

	// 51st request should be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.10.10.10:5555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on request beyond default burst, got %d", rr.Code)
	}
}
