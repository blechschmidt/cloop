package apiserver

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

// initProject creates a fresh project workdir with a populated state.db.
// Returns the absolute workdir path.
func initProject(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-apiserver-probes-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if _, err := state.Init(dir, "test goal", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return dir
}

// emptyDir creates a temp dir without running cloop init — used to simulate
// an uninitialized state store on /readyz.
func emptyDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-apiserver-empty-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// newProbeServer wraps the apiserver Server in an httptest.Server using the
// production handler chain (rate-limit + auth + probe-bypass).
func newProbeServer(t *testing.T, srv *Server) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// Register only one real route so we can verify auth works against
	// non-probe paths.
	mux.HandleFunc("GET /status", srv.handleStatus)
	ts := httptest.NewServer(srv.buildHandler(mux))
	t.Cleanup(ts.Close)
	return ts
}

// TestAPIServer_Healthz_AlwaysOK is table-driven and verifies the liveness
// probe returns 200 in every server configuration we care about. Liveness
// MUST NOT depend on downstream services.
func TestAPIServer_Healthz_AlwaysOK(t *testing.T) {
	cases := []struct {
		name        string
		setupServer func(t *testing.T) *Server
	}{
		{
			name: "healthy initialized state",
			setupServer: func(t *testing.T) *Server {
				return New(initProject(t), 0, "")
			},
		},
		{
			name: "uninitialized workdir (state.db missing)",
			setupServer: func(t *testing.T) *Server {
				return New(emptyDir(t), 0, "")
			},
		},
		{
			name: "ReadyCheck override that always fails (must not affect /healthz)",
			setupServer: func(t *testing.T) *Server {
				s := New(initProject(t), 0, "")
				s.ReadyCheck = func(ctx context.Context) error {
					return errors.New("simulated outage")
				}
				return s
			},
		},
		{
			name: "auth token set — /healthz must still bypass auth",
			setupServer: func(t *testing.T) *Server {
				return New(initProject(t), 0, "secret-token")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.setupServer(t)
			ts := newProbeServer(t, srv)

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
				t.Fatalf("invalid JSON body: %v (raw=%s)", err, body)
			}
			if got["status"] != "ok" {
				t.Errorf("status field: got %q want %q", got["status"], "ok")
			}
		})
	}
}

// TestAPIServer_Readyz is table-driven over healthy, uninitialized,
// closed-handle, and timeout scenarios. The closed-handle case is the
// literal example called out in Task 20092: "closed db handle returns
// 503 from /readyz but 200 from /healthz."
func TestAPIServer_Readyz(t *testing.T) {
	cases := []struct {
		name           string
		setupServer    func(t *testing.T) *Server
		wantStatus     int
		wantBodyStatus string
		wantErrMatch   string
	}{
		{
			name: "healthy — initialized state.db, SELECT 1 succeeds",
			setupServer: func(t *testing.T) *Server {
				return New(initProject(t), 0, "")
			},
			wantStatus:     http.StatusOK,
			wantBodyStatus: "ready",
		},
		{
			name: "degraded — state store not initialized (no state.db)",
			setupServer: func(t *testing.T) *Server {
				return New(emptyDir(t), 0, "")
			},
			wantStatus:     http.StatusServiceUnavailable,
			wantBodyStatus: "not_ready",
			wantErrMatch:   "state store not initialized",
		},
		{
			name: "degraded — closed db handle (simulated via ReadyCheck override)",
			setupServer: func(t *testing.T) *Server {
				s := New(initProject(t), 0, "")
				s.ReadyCheck = func(ctx context.Context) error {
					return errors.New("sql: database is closed")
				}
				return s
			},
			wantStatus:     http.StatusServiceUnavailable,
			wantBodyStatus: "not_ready",
			wantErrMatch:   "database is closed",
		},
		{
			name: "degraded — context deadline exceeded (slow DB)",
			setupServer: func(t *testing.T) *Server {
				s := New(initProject(t), 0, "")
				s.ReadyCheck = func(ctx context.Context) error {
					return context.DeadlineExceeded
				}
				return s
			},
			wantStatus:     http.StatusServiceUnavailable,
			wantBodyStatus: "not_ready",
			wantErrMatch:   "context deadline exceeded",
		},
		{
			name: "auth token set — /readyz must still bypass auth and succeed",
			setupServer: func(t *testing.T) *Server {
				return New(initProject(t), 0, "secret-token")
			},
			wantStatus:     http.StatusOK,
			wantBodyStatus: "ready",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.setupServer(t)
			ts := newProbeServer(t, srv)

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
				t.Fatalf("invalid JSON body: %v (raw=%s)", err, body)
			}
			if s, _ := got["status"].(string); s != tc.wantBodyStatus {
				t.Errorf("status field: got %q want %q (raw=%s)",
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

// TestAPIServer_Probes_BypassAuth verifies that /healthz and /readyz are
// reachable without a bearer token, while protected routes still 401. This
// is the auth-bypass invariant for load-balancer probes.
func TestAPIServer_Probes_BypassAuth(t *testing.T) {
	srv := New(initProject(t), 0, "secret-token")
	ts := newProbeServer(t, srv)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("/healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz without token: got %d want 200", resp.StatusCode)
	}

	resp, err = http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("/readyz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/readyz without token: got %d want 200", resp.StatusCode)
	}

	// Sanity: a non-probe route still requires auth.
	resp, err = http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatalf("/status: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/status without token: got %d want 401 (auth must still apply to non-probe routes)",
			resp.StatusCode)
	}
}

// TestAPIServer_Probes_BypassRateLimit confirms the per-IP token-bucket
// rate limiter does not gate probe traffic. We set RPS=1 burst=1 and fire
// 50 probe requests; without the bypass only the first would succeed.
func TestAPIServer_Probes_BypassRateLimit(t *testing.T) {
	srv := New(initProject(t), 0, "")
	srv.RPS = 1
	srv.Burst = 1
	ts := newProbeServer(t, srv)

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

// TestAPIServer_DefaultReadyCheck_RealDB exercises the default check
// end-to-end against a real SQLite database — the production path with
// no override.
func TestAPIServer_DefaultReadyCheck_RealDB(t *testing.T) {
	dir := initProject(t)
	srv := New(dir, 0, "")

	if err := srv.defaultReadyCheck(context.Background()); err != nil {
		t.Fatalf("default check on healthy state: %v", err)
	}

	// Closing a freshly-opened handle and re-pinging it must error —
	// the literal "closed db handle" scenario from the task spec.
	dbPath := state.StateDBPath(dir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("PingContext on open handle: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := db.PingContext(context.Background()); err == nil {
		t.Fatal("PingContext on closed handle: want error, got nil")
	}
}

// TestAPIServer_DefaultReadyCheck_MissingDB asserts the uninitialized
// case is reported with an actionable error string.
func TestAPIServer_DefaultReadyCheck_MissingDB(t *testing.T) {
	srv := New(emptyDir(t), 0, "")
	err := srv.defaultReadyCheck(context.Background())
	if err == nil {
		t.Fatal("default check with no state.db: want error, got nil")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("error: got %q, want substring %q", err.Error(), "not initialized")
	}
}

// TestAPIServer_DefaultReadyCheck_CorruptDB asserts a non-SQLite file at
// the expected path fails gracefully (no panic, no hang).
func TestAPIServer_DefaultReadyCheck_CorruptDB(t *testing.T) {
	dir := emptyDir(t)
	dbPath := state.StateDBPath(dir)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("not a sqlite file"), 0o644); err != nil {
		t.Fatalf("write corrupt db: %v", err)
	}

	srv := New(dir, 0, "")
	if err := srv.defaultReadyCheck(context.Background()); err == nil {
		t.Fatal("default check on corrupt db: want error, got nil")
	}
}
