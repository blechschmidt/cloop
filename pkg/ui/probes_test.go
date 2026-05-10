package ui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestHealthz_AlwaysOK is table-driven and verifies that /healthz returns
// 200 regardless of the state of the underlying SQLite store. Liveness
// probes must NOT depend on downstream services — that is the entire
// reason load balancers distinguish liveness from readiness.
func TestHealthz_AlwaysOK(t *testing.T) {
	cases := []struct {
		name        string
		setupServer func(t *testing.T) *Server
	}{
		{
			name: "healthy server with initialized state",
			setupServer: func(t *testing.T) *Server {
				dir := setupProjectDir(t, cloopGoal, nil)
				return New(dir, 0, "")
			},
		},
		{
			name: "no state directory at all",
			setupServer: func(t *testing.T) *Server {
				dir, err := os.MkdirTemp("", "cloop-healthz-empty-*")
				if err != nil {
					t.Fatalf("mkdirtemp: %v", err)
				}
				t.Cleanup(func() { os.RemoveAll(dir) })
				return New(dir, 0, "")
			},
		},
		{
			name: "ReadyCheck override that always fails (must not affect /healthz)",
			setupServer: func(t *testing.T) *Server {
				dir := setupProjectDir(t, cloopGoal, nil)
				srv := New(dir, 0, "")
				srv.ReadyCheck = func(ctx context.Context) error {
					return errors.New("simulated DB outage")
				}
				return srv
			},
		},
		{
			name: "auth token set — /healthz must still bypass auth",
			setupServer: func(t *testing.T) *Server {
				dir := setupProjectDir(t, cloopGoal, nil)
				return New(dir, 0, "secret-token")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.setupServer(t)
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()

			resp, err := http.Get(ts.URL + "/healthz")
			if err != nil {
				t.Fatalf("GET /healthz: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: got %d want 200; body=%s", resp.StatusCode, body)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("content-type: got %q want json", ct)
			}
			var got map[string]string
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("body not valid JSON: %v (raw=%s)", err, body)
			}
			if got["status"] != "ok" {
				t.Errorf("body status: got %q want %q", got["status"], "ok")
			}
		})
	}
}

// TestReadyz is table-driven over healthy, uninitialized, ping-failure, and
// "closed db handle" scenarios. The latter is simulated via the ReadyCheck
// override — it returns an error analogous to what database/sql would
// surface against a closed *sql.DB. The point of the test is the wiring:
// readiness failures must produce 503 with a JSON body that names the
// failing check; readiness success must produce 200.
func TestReadyz(t *testing.T) {
	cases := []struct {
		name           string
		setupServer    func(t *testing.T) *Server
		wantStatus     int
		wantBodyStatus string  // value of the "status" JSON field
		wantErrMatch   string  // substring expected in the "error" field on failure
	}{
		{
			name: "healthy — initialized state.db, SELECT 1 succeeds",
			setupServer: func(t *testing.T) *Server {
				dir := setupProjectDir(t, cloopGoal, nil)
				return New(dir, 0, "")
			},
			wantStatus:     http.StatusOK,
			wantBodyStatus: "ready",
		},
		{
			name: "degraded — state store not initialized (no state.db)",
			setupServer: func(t *testing.T) *Server {
				dir, err := os.MkdirTemp("", "cloop-readyz-uninit-*")
				if err != nil {
					t.Fatalf("mkdirtemp: %v", err)
				}
				t.Cleanup(func() { os.RemoveAll(dir) })
				return New(dir, 0, "")
			},
			wantStatus:     http.StatusServiceUnavailable,
			wantBodyStatus: "not_ready",
			wantErrMatch:   "state store not initialized",
		},
		{
			name: "degraded — closed db handle (simulated via ReadyCheck override)",
			setupServer: func(t *testing.T) *Server {
				dir := setupProjectDir(t, cloopGoal, nil)
				srv := New(dir, 0, "")
				srv.ReadyCheck = func(ctx context.Context) error {
					return errors.New("sql: database is closed")
				}
				return srv
			},
			wantStatus:     http.StatusServiceUnavailable,
			wantBodyStatus: "not_ready",
			wantErrMatch:   "database is closed",
		},
		{
			name: "degraded — readyCheck returns context-deadline error (slow DB)",
			setupServer: func(t *testing.T) *Server {
				dir := setupProjectDir(t, cloopGoal, nil)
				srv := New(dir, 0, "")
				srv.ReadyCheck = func(ctx context.Context) error {
					return context.DeadlineExceeded
				}
				return srv
			},
			wantStatus:     http.StatusServiceUnavailable,
			wantBodyStatus: "not_ready",
			wantErrMatch:   "context deadline exceeded",
		},
		{
			name: "auth token set — /readyz must still bypass auth and succeed",
			setupServer: func(t *testing.T) *Server {
				dir := setupProjectDir(t, cloopGoal, nil)
				return New(dir, 0, "secret-token")
			},
			wantStatus:     http.StatusOK,
			wantBodyStatus: "ready",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.setupServer(t)
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()

			resp, err := http.Get(ts.URL + "/readyz")
			if err != nil {
				t.Fatalf("GET /readyz: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status: got %d want %d; body=%s",
					resp.StatusCode, tc.wantStatus, body)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("content-type: got %q want json", ct)
			}
			var got map[string]any
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("body not valid JSON: %v (raw=%s)", err, body)
			}
			if s, _ := got["status"].(string); s != tc.wantBodyStatus {
				t.Errorf("body status: got %q want %q (raw=%s)",
					s, tc.wantBodyStatus, body)
			}
			if tc.wantErrMatch != "" {
				errStr, _ := got["error"].(string)
				if !strings.Contains(errStr, tc.wantErrMatch) {
					t.Errorf("error field: got %q want substring %q",
						errStr, tc.wantErrMatch)
				}
			}
		})
	}
}

// TestProbes_BypassAuth verifies that /healthz and /readyz are reachable
// WITHOUT a bearer token even when one is configured — the whole point of
// the bypass is that load balancers and Kubernetes probes don't carry
// credentials. By contrast, an authenticated route (/api/state) returns
// 401 from the same server, proving the auth middleware is in fact
// installed and only the probe paths are exempt.
func TestProbes_BypassAuth(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "secret-token")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// /healthz: no token → 200
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("/healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz without token: got %d want 200", resp.StatusCode)
	}

	// /readyz: no token → 200
	resp, err = http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("/readyz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/readyz without token: got %d want 200", resp.StatusCode)
	}

	// Sanity: /api/state without token → 401, proving auth IS active.
	resp, err = http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatalf("/api/state: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/state without token: got %d want 401 (auth must still apply to non-probe routes)",
			resp.StatusCode)
	}
}

// TestProbes_BypassRateLimit verifies that bursting probe requests does NOT
// exhaust the per-IP token bucket. We configure an absurdly tight limiter
// (1 req/s, burst 1), then fire 50 /healthz requests in a row. Without the
// bypass the very first one would consume the burst token and the rest
// would 429; with the bypass all 50 succeed.
func TestProbes_BypassRateLimit(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	srv.RPS = 1
	srv.Burst = 1
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for i := 0; i < 50; i++ {
		resp, err := http.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("iter %d: /healthz returned %d (rate limiter must not apply)",
				i, resp.StatusCode)
		}
	}
	for i := 0; i < 50; i++ {
		resp, err := http.Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("iter %d: /readyz returned %d (rate limiter must not apply)",
				i, resp.StatusCode)
		}
	}
}

// TestDefaultReadyCheck_RealDB exercises the default check end-to-end
// against a real SQLite database — the SELECT 1 path that production
// uses, not the override. This is what catches regressions in the
// statedb.PingContext wiring (e.g., if the schema applied during Open
// silently breaks PingContext, or the modernc driver changes behavior).
func TestDefaultReadyCheck_RealDB(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	// Healthy path: stat OK, open OK, SELECT 1 OK.
	if err := srv.defaultReadyCheck(context.Background()); err != nil {
		t.Fatalf("default check on healthy state: %v", err)
	}

	// Sanity that the Open path actually completed against the file we
	// expected — a plain stat must succeed and PingContext on a
	// freshly-opened handle must succeed too.
	dbPath := state.StateDBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("state.db missing after setupProjectDir: %v", err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("PingContext on open handle: %v", err)
	}

	// Closing the handle and pinging it MUST fail. This is the literal
	// "closed db handle" case from the task spec.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := db.PingContext(context.Background()); err == nil {
		t.Fatal("PingContext on closed handle: want error, got nil")
	}
}

// TestDefaultReadyCheck_MissingDB asserts the uninitialized-state case is
// reported with a specific, actionable error string. Operators reading
// readiness probe logs need to be able to distinguish "not initialized
// yet" (run cloop init) from "DB is broken" (file corruption / disk full).
func TestDefaultReadyCheck_MissingDB(t *testing.T) {
	dir, err := os.MkdirTemp("", "cloop-readyz-missing-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	srv := New(dir, 0, "")
	err = srv.defaultReadyCheck(context.Background())
	if err == nil {
		t.Fatal("default check with no state.db: want error, got nil")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("error: got %q, want substring %q", err.Error(), "not initialized")
	}
}

// TestDefaultReadyCheck_CorruptDB asserts that a non-SQLite file at the
// expected path produces a 503-worthy error rather than a panic. This is
// what happens if disk corruption truncates the WAL or someone accidentally
// `echo > state.db`.
func TestDefaultReadyCheck_CorruptDB(t *testing.T) {
	dir, err := os.MkdirTemp("", "cloop-readyz-corrupt-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	dbPath := state.StateDBPath(dir)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("this is not a sqlite file"), 0o644); err != nil {
		t.Fatalf("write corrupt db: %v", err)
	}

	srv := New(dir, 0, "")
	if err := srv.defaultReadyCheck(context.Background()); err == nil {
		t.Fatal("default check on corrupt db: want error, got nil")
	}
}
