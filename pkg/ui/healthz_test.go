package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// initStateDB creates a minimal but valid .cloop/state.db at workDir so the
// readiness check can stat + open + ping it. The DB is closed before returning
// so the test owns no live handles; the file remains on disk in WAL mode.
func initStateDB(t *testing.T, workDir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workDir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	dbPath := state.StateDBPath(workDir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("statedb.Close: %v", err)
	}
	return dbPath
}

// TestHealthz_AlwaysOK_TableCases verifies /healthz is a pure liveness probe:
// it always returns 200 regardless of state-store presence, auth configuration,
// or request method. This is the load-bearing invariant for K8s liveness probes
// — a transient DB outage MUST NOT cause the orchestrator to kill the pod.
//
// Sister test: TestHealthz_AlwaysOK in probes_test.go covers a smaller subset
// of the same invariant; this file's table-driven version exercises the
// auth-configured and ReadyCheck-override cases that one omits.
func TestHealthz_AlwaysOK_TableCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		setup func(t *testing.T) *Server
	}{
		{
			name: "no state directory",
			setup: func(t *testing.T) *Server {
				return New(t.TempDir(), 0, "")
			},
		},
		{
			name: "with healthy state.db",
			setup: func(t *testing.T) *Server {
				wd := t.TempDir()
				initStateDB(t, wd)
				return New(wd, 0, "")
			},
		},
		{
			name: "auth token configured (probe still public)",
			setup: func(t *testing.T) *Server {
				return New(t.TempDir(), 0, "secret-token")
			},
		},
		{
			name: "ReadyCheck override returning error (must not affect healthz)",
			setup: func(t *testing.T) *Server {
				s := New(t.TempDir(), 0, "")
				s.ReadyCheck = func(ctx context.Context) error {
					return errors.New("simulated db failure")
				}
				return s
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := tc.setup(t)
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("/healthz: want 200, got %d (body=%s)", rr.Code, rr.Body.String())
			}
			if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("/healthz: want application/json Content-Type, got %q", ct)
			}
			var body map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("/healthz: invalid JSON: %v (body=%s)", err, rr.Body.String())
			}
			if body["status"] != "ok" {
				t.Errorf("/healthz: want status=ok, got %v", body["status"])
			}
		})
	}
}

// TestReadyz_TableCases verifies /readyz reflects the SQLite store's actual
// reachability: 200 when state.db is present and pings successfully, 503
// (with a JSON body explaining the failed check) otherwise. The probe MUST
// bypass auth and rate-limiting so a load balancer can reach it without
// credentials.
//
// Sister test: TestReadyz in probes_test.go covers a smaller subset; this
// file's table-driven version adds the corrupted-DB and ReadyCheck-override
// cases.
func TestReadyz_TableCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		setup            func(t *testing.T) *Server
		wantStatus       int
		wantStatusField  string // "ready" or "not_ready"
		wantErrSubstring string // partial match on error message when degraded
	}{
		{
			name: "healthy: state.db present and reachable",
			setup: func(t *testing.T) *Server {
				wd := t.TempDir()
				initStateDB(t, wd)
				return New(wd, 0, "")
			},
			wantStatus:      http.StatusOK,
			wantStatusField: "ready",
		},
		{
			name: "degraded: state store not initialized",
			setup: func(t *testing.T) *Server {
				return New(t.TempDir(), 0, "")
			},
			wantStatus:       http.StatusServiceUnavailable,
			wantStatusField:  "not_ready",
			wantErrSubstring: "not initialized",
		},
		{
			name: "degraded: corrupted state.db",
			setup: func(t *testing.T) *Server {
				wd := t.TempDir()
				if err := os.MkdirAll(filepath.Join(wd, ".cloop"), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(state.StateDBPath(wd), []byte("not a sqlite file"), 0o644); err != nil {
					t.Fatalf("write garbage: %v", err)
				}
				return New(wd, 0, "")
			},
			wantStatus:      http.StatusServiceUnavailable,
			wantStatusField: "not_ready",
		},
		{
			name: "degraded: ReadyCheck override returns error (simulates closed db handle)",
			setup: func(t *testing.T) *Server {
				s := New(t.TempDir(), 0, "")
				s.ReadyCheck = func(ctx context.Context) error {
					return errors.New("sql: database is closed")
				}
				return s
			},
			wantStatus:       http.StatusServiceUnavailable,
			wantStatusField:  "not_ready",
			wantErrSubstring: "database is closed",
		},
		{
			name: "degraded: ReadyCheck override returns context deadline exceeded",
			setup: func(t *testing.T) *Server {
				s := New(t.TempDir(), 0, "")
				s.ReadyCheck = func(ctx context.Context) error {
					return context.DeadlineExceeded
				}
				return s
			},
			wantStatus:       http.StatusServiceUnavailable,
			wantStatusField:  "not_ready",
			wantErrSubstring: "deadline",
		},
		{
			name: "auth configured: probe still public (no token in request)",
			setup: func(t *testing.T) *Server {
				wd := t.TempDir()
				initStateDB(t, wd)
				return New(wd, 0, "secret-token")
			},
			wantStatus:      http.StatusOK,
			wantStatusField: "ready",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := tc.setup(t)
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("/readyz: want status %d, got %d (body=%s)",
					tc.wantStatus, rr.Code, rr.Body.String())
			}
			if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("/readyz: want application/json Content-Type, got %q", ct)
			}
			var body map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("/readyz: invalid JSON: %v (body=%s)", err, rr.Body.String())
			}
			if got, _ := body["status"].(string); got != tc.wantStatusField {
				t.Errorf("/readyz: want status=%q, got %q", tc.wantStatusField, got)
			}
			if tc.wantErrSubstring != "" {
				gotErr, _ := body["error"].(string)
				if !strings.Contains(strings.ToLower(gotErr), strings.ToLower(tc.wantErrSubstring)) {
					t.Errorf("/readyz: want error containing %q, got %q",
						tc.wantErrSubstring, gotErr)
				}
			}
		})
	}
}

// TestHealthz_BypassesRateLimit ensures probe endpoints stay reachable even
// when the per-IP rate-limit bucket is fully drained. Without this, a noisy
// neighbor (or a flood from a single LB IP) would cause the orchestrator to
// flap pods — which in turn amplifies traffic and worsens the outage.
func TestHealthz_BypassesRateLimit(t *testing.T) {
	t.Parallel()

	s := New(t.TempDir(), 0, "")
	// Tiny burst so the very first non-probe request would be 429.
	s.RPS = 1
	s.Burst = 1
	h := s.Handler()

	// Drain the per-IP bucket via a non-probe path that would otherwise be
	// rate-limited.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	// The probe must still return 200 from the same IP.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz under exhausted rate limit: want 200, got %d (body=%s)",
			rr.Code, rr.Body.String())
	}
}

// TestReadyz_BypassesRateLimit mirrors the healthz check for the readiness
// probe — same load-balancer rationale.
func TestReadyz_BypassesRateLimit(t *testing.T) {
	t.Parallel()

	wd := t.TempDir()
	initStateDB(t, wd)
	s := New(wd, 0, "")
	s.RPS = 1
	s.Burst = 1
	h := s.Handler()

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
		req.RemoteAddr = "10.0.0.2:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/readyz under exhausted rate limit: want 200, got %d (body=%s)",
			rr.Code, rr.Body.String())
	}
}

// TestReadyz_HonoursRequestTimeout verifies the readiness probe's 1s ctx
// timeout is enforced: a check that blocks longer than the timeout should
// observe ctx.Done() and return an error (degrading to 503), not run to
// completion. Without this bound a hung SQLite file would pin the probe
// goroutine and the LB would never receive a response.
func TestReadyz_HonoursRequestTimeout(t *testing.T) {
	t.Parallel()

	s := New(t.TempDir(), 0, "")
	// Block until ctx fires, then surface that as the readiness error.
	s.ReadyCheck = func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return nil
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()

	start := time.Now()
	s.Handler().ServeHTTP(rr, req)
	elapsed := time.Since(start)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz: want 503 on timeout, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	// Allow generous slack above the 1s readyCheckTimeout for slow CI.
	if elapsed > 5*time.Second {
		t.Errorf("/readyz: timeout not honoured — took %v, expected ≤ ~%v",
			elapsed, readyCheckTimeout)
	}
}
