package ui

// Tests for Task 20090: per-IP and total WebSocket connection caps.
//
// The cloop ui server bounds the number of concurrent WebSocket peers it
// accepts so an accidental browser-tab storm or deliberate connection flood
// cannot exhaust the per-process goroutine budget. The cap has two
// dimensions:
//
//   - MaxWebSocketConns          — total across every remote IP (default 256)
//   - MaxWebSocketConnsPerIP     — max from any single remote IP (default 8)
//
// On a breach the upgrade handler returns HTTP 429 with a Retry-After
// header *before* websocket.Accept hijacks the response, so a rejected
// client sees a normal HTTP response instead of a half-completed upgrade.
// On disconnect both counters are decremented via a deferred releaseWebSocket
// in the handler — the per-IP map entry is dropped when its count hits zero
// to keep the map size bounded by the number of currently-connected IPs.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/config"
)

// dialWS opens a single WebSocket connection to the test server. Returns the
// connection, the HTTP response (when present — populated even on rejection
// so callers can assert on the status / Retry-After header), and any dial
// error. Caller closes the connection when non-nil.
func dialWS(t *testing.T, wsURL string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return websocket.Dial(dialCtx, wsURL, nil)
}

// waitForWSConnTotal polls the server's wsConnTotal counter until it equals
// want or the deadline expires. Used to wait for the deferred
// releaseWebSocket to actually run after a client closes its end.
func waitForWSConnTotal(srv *Server, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		srv.wsConnMu.Lock()
		got := srv.wsConnTotal
		srv.wsConnMu.Unlock()
		if got == want {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitForWSConnPerIP polls the per-IP counter for the loopback IP that
// httptest connections use ("127.0.0.1"). Returns the last observation.
func waitForWSConnPerIP(srv *Server, ip string, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		srv.wsConnMu.Lock()
		got := srv.wsConnPerIP[ip]
		srv.wsConnMu.Unlock()
		if got == want {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestWSConn_DefaultsAppliedWhenUnset verifies that an unconfigured Server
// substitutes the package defaults. This is the load-bearing guarantee
// that newly started servers are protected without operator action.
func TestWSConn_DefaultsAppliedWhenUnset(t *testing.T) {
	srv := New(t.TempDir(), 0, "")
	if got, want := srv.effectiveMaxWebSocketConns(), config.WebSocketConnsDefault; got != want {
		t.Errorf("effectiveMaxWebSocketConns = %d, want %d", got, want)
	}
	if got, want := srv.effectiveMaxWebSocketConnsPerIP(), config.WebSocketConnsPerIPDefault; got != want {
		t.Errorf("effectiveMaxWebSocketConnsPerIP = %d, want %d", got, want)
	}
}

// TestWSConn_PerIPLimitRejectsWith429 floods the server with more
// connections from a single IP than MaxWebSocketConnsPerIP and verifies
// that:
//   - the first N attempts succeed (where N == per-IP cap)
//   - subsequent attempts receive HTTP 429 with a Retry-After header
//   - the wsConnPerIP counter exactly equals N while the floods are open
//
// httptest.NewServer always reports 127.0.0.1 as the remote, so every
// connection in this test counts against the same per-IP bucket.
func TestWSConn_PerIPLimitRejectsWith429(t *testing.T) {
	const perIPLimit = 3

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	srv.MaxWebSocketConnsPerIP = perIPLimit
	srv.MaxWebSocketConns = 100 // total cap well above per-IP cap

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	// Hold open exactly perIPLimit connections.
	conns := make([]*websocket.Conn, 0, perIPLimit)
	for i := 0; i < perIPLimit; i++ {
		c, _, err := dialWS(t, wsURL)
		if err != nil {
			t.Fatalf("dial #%d should have succeeded: %v", i, err)
		}
		conns = append(conns, c)
	}
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close(websocket.StatusNormalClosure, "")
		}
	})

	if got := waitForWSConnPerIP(srv, "127.0.0.1", perIPLimit, 2*time.Second); got != perIPLimit {
		t.Fatalf("per-IP counter = %d, want %d", got, perIPLimit)
	}

	// The next attempt must be rejected with HTTP 429 + Retry-After.
	httpURL := ts.URL + "/api/ws"
	req, err := http.NewRequest(http.MethodGet, httpURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// We use a plain GET (not a WebSocket upgrade) because admission
	// happens before websocket.Accept reads the upgrade headers, and
	// we want to read the rejection body directly. The server treats
	// the request as a normal HTTP request from the same IP, so the
	// per-IP limit still applies.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rejection request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 429; body=%s", resp.StatusCode, body)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Errorf("missing Retry-After header on 429 rejection")
	} else if n, err := strconv.Atoi(ra); err != nil || n <= 0 {
		t.Errorf("Retry-After = %q, want positive integer seconds", ra)
	}

	// Confirm the rejection did NOT bump wsConnTotal — admission is
	// transactional, so a rejected request must leave both counters
	// unchanged.
	srv.wsConnMu.Lock()
	if got := srv.wsConnTotal; got != perIPLimit {
		srv.wsConnMu.Unlock()
		t.Fatalf("rejected request bumped wsConnTotal: got %d, want %d", got, perIPLimit)
	}
	srv.wsConnMu.Unlock()
}

// TestWSConn_TotalLimitRejectsWith429 saturates the total cap (with the
// per-IP cap raised so the per-IP path doesn't shadow the total path) and
// verifies the next upgrade is rejected with 429 + Retry-After.
func TestWSConn_TotalLimitRejectsWith429(t *testing.T) {
	const totalLimit = 4

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	srv.MaxWebSocketConns = totalLimit
	srv.MaxWebSocketConnsPerIP = totalLimit + 10 // raise per-IP so total is the binding cap

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	conns := make([]*websocket.Conn, 0, totalLimit)
	for i := 0; i < totalLimit; i++ {
		c, _, err := dialWS(t, wsURL)
		if err != nil {
			t.Fatalf("dial #%d should have succeeded: %v", i, err)
		}
		conns = append(conns, c)
	}
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close(websocket.StatusNormalClosure, "")
		}
	})

	if got := waitForWSConnTotal(srv, totalLimit, 2*time.Second); got != totalLimit {
		t.Fatalf("wsConnTotal = %d, want %d", got, totalLimit)
	}

	// Verify the next dial fails fast at the HTTP layer.
	httpResp, err := http.Get(ts.URL + "/api/ws")
	if err != nil {
		t.Fatalf("rejection request: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", httpResp.StatusCode)
	}
	if ra := httpResp.Header.Get("Retry-After"); ra == "" {
		t.Errorf("missing Retry-After header on 429 rejection")
	}
}

// TestWSConn_DecrementOnDisconnect verifies that closing a WebSocket
// connection releases its slot in both counters within a bounded window.
// Without this, a long-running server's counter would monotonically grow
// and eventually wedge new connections out permanently.
func TestWSConn_DecrementOnDisconnect(t *testing.T) {
	const totalLimit = 3
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	srv.MaxWebSocketConns = totalLimit
	srv.MaxWebSocketConnsPerIP = totalLimit

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	// Saturate.
	conns := make([]*websocket.Conn, 0, totalLimit)
	for i := 0; i < totalLimit; i++ {
		c, _, err := dialWS(t, wsURL)
		if err != nil {
			t.Fatalf("dial #%d: %v", i, err)
		}
		conns = append(conns, c)
	}
	if got := waitForWSConnTotal(srv, totalLimit, 2*time.Second); got != totalLimit {
		t.Fatalf("wsConnTotal = %d, want %d", got, totalLimit)
	}

	// Close every connection. The per-conn cleanup runs in the handler's
	// deferred releaseWebSocket; we wait until the counter falls back
	// to zero. Use CloseNow to skip the close-handshake roundtrip — the
	// server's deferred conn.CloseNow() unwinds the handler regardless.
	for _, c := range conns {
		_ = c.CloseNow()
	}

	if got := waitForWSConnTotal(srv, 0, 3*time.Second); got != 0 {
		t.Fatalf("wsConnTotal did not decrement to 0 after disconnect; got %d", got)
	}
	if got := waitForWSConnPerIP(srv, "127.0.0.1", 0, 3*time.Second); got != 0 {
		t.Fatalf("per-IP counter did not decrement; got %d", got)
	}

	// Per-IP map entry must be removed when its counter hits zero so
	// the map size stays bounded by currently-connected IPs.
	srv.wsConnMu.Lock()
	_, present := srv.wsConnPerIP["127.0.0.1"]
	mapLen := len(srv.wsConnPerIP)
	srv.wsConnMu.Unlock()
	if present {
		t.Errorf("wsConnPerIP entry for 127.0.0.1 not deleted after release")
	}
	if mapLen != 0 {
		t.Errorf("wsConnPerIP map non-empty after all releases: %d entries", mapLen)
	}

	// And — importantly — a fresh dial must now succeed: the slots
	// have been freed for re-use.
	c, _, err := dialWS(t, wsURL)
	if err != nil {
		t.Fatalf("dial after release should have succeeded: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
}

// TestWSConn_DifferentIPsBypassPerIPLimit verifies that the per-IP cap
// is keyed on remote IP — a flood from one IP must not consume the
// quota for a different IP. We forge X-Forwarded-For headers (which
// clientIP() prefers) to simulate distinct origins behind a reverse
// proxy.
func TestWSConn_DifferentIPsBypassPerIPLimit(t *testing.T) {
	const perIPLimit = 2

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	srv.MaxWebSocketConnsPerIP = perIPLimit
	srv.MaxWebSocketConns = 100

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	// Saturate IP "10.0.0.1".
	conns := make([]*websocket.Conn, 0, perIPLimit*2)
	for i := 0; i < perIPLimit; i++ {
		dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"X-Forwarded-For": []string{"10.0.0.1"}},
		})
		cancel()
		if err != nil {
			t.Fatalf("dial 10.0.0.1 #%d: %v", i, err)
		}
		conns = append(conns, c)
	}
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close(websocket.StatusNormalClosure, "")
		}
	})

	if got := waitForWSConnPerIP(srv, "10.0.0.1", perIPLimit, 2*time.Second); got != perIPLimit {
		t.Fatalf("10.0.0.1 counter = %d, want %d", got, perIPLimit)
	}

	// Connections from a different IP must still succeed.
	for i := 0; i < perIPLimit; i++ {
		dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"X-Forwarded-For": []string{"10.0.0.2"}},
		})
		cancel()
		if err != nil {
			t.Fatalf("dial 10.0.0.2 #%d should have succeeded (different IP): %v", i, err)
		}
		conns = append(conns, c)
	}

	if got := waitForWSConnPerIP(srv, "10.0.0.2", perIPLimit, 2*time.Second); got != perIPLimit {
		t.Fatalf("10.0.0.2 counter = %d, want %d", got, perIPLimit)
	}

	// And a third dial from 10.0.0.1 must STILL be rejected because
	// its bucket is unchanged.
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/ws", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rejection request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
}

// TestWSConn_AdmissionIsRaceFree spawns parallel admission attempts and
// confirms the wsConnTotal counter never exceeds the configured cap.
// Without atomic admission (check + increment under the same lock), a
// burst of simultaneous upgrades could each see "below the cap" and all
// succeed, blowing past the limit.
func TestWSConn_AdmissionIsRaceFree(t *testing.T) {
	const totalLimit = 5
	srv := New(t.TempDir(), 0, "")
	srv.MaxWebSocketConns = totalLimit
	srv.MaxWebSocketConnsPerIP = totalLimit

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	admitted := make([]bool, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", idx%3) // mix of 3 IPs
			ok, _ := srv.admitWebSocket(ip)
			admitted[idx] = ok
		}(i)
	}
	wg.Wait()

	// Count successes — must not exceed totalLimit.
	successes := 0
	for _, ok := range admitted {
		if ok {
			successes++
		}
	}
	if successes > totalLimit {
		t.Fatalf("admitted %d concurrent connections, cap is %d", successes, totalLimit)
	}
	srv.wsConnMu.Lock()
	if srv.wsConnTotal != successes {
		srv.wsConnMu.Unlock()
		t.Fatalf("wsConnTotal = %d, want %d (number of successful admits)", srv.wsConnTotal, successes)
	}
	srv.wsConnMu.Unlock()
}

// TestWSConn_ConfigValidation exercises the pkg/config validators for the
// new UI WebSocket fields. validateAndClamp must reset out-of-range values
// to zero (so EffectiveMax* substitutes the default), and ValidateNumeric
// must reject the same inputs with a non-nil error.
func TestWSConn_ConfigValidation(t *testing.T) {
	cases := []struct {
		name              string
		total             int
		perIP             int
		wantTotalAfter    int
		wantPerIPAfter    int
		wantValidateError bool
	}{
		{"zero is fine", 0, 0, 0, 0, false},
		{"in-range is fine", 100, 4, 100, 4, false},
		{"negative total clamped", -1, 4, 0, 4, true},
		{"too-large total clamped", config.WebSocketConnsUpper + 1, 4, 0, 4, true},
		{"negative per-IP clamped", 100, -1, 100, 0, true},
		{"too-large per-IP clamped", 100, config.WebSocketConnsPerIPUpper + 1, 100, 0, true},
		{"per-IP > total reset", 10, 50, 10, 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.UI.MaxWebSocketConns = tc.total
			cfg.UI.MaxWebSocketConnsPerIP = tc.perIP

			gotErr := cfg.ValidateNumeric() != nil
			if gotErr != tc.wantValidateError {
				t.Errorf("ValidateNumeric error=%v, want=%v", gotErr, tc.wantValidateError)
			}

			// validateAndClamp is unexported; trigger it via Save→Load.
			tmp := t.TempDir()
			// Reset and re-set so each subtest starts from a clean slate.
			cfg2 := config.Default()
			cfg2.UI.MaxWebSocketConns = tc.total
			cfg2.UI.MaxWebSocketConnsPerIP = tc.perIP
			if err := config.Save(tmp, cfg2); err != nil {
				t.Fatalf("Save: %v", err)
			}
			loaded, err := config.Load(tmp)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if loaded.UI.MaxWebSocketConns != tc.wantTotalAfter {
				t.Errorf("after clamp: MaxWebSocketConns = %d, want %d", loaded.UI.MaxWebSocketConns, tc.wantTotalAfter)
			}
			if loaded.UI.MaxWebSocketConnsPerIP != tc.wantPerIPAfter {
				t.Errorf("after clamp: MaxWebSocketConnsPerIP = %d, want %d", loaded.UI.MaxWebSocketConnsPerIP, tc.wantPerIPAfter)
			}
		})
	}
}
