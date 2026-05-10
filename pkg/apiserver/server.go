// Package apiserver implements a standalone REST API server that exposes all
// cloop functionality over HTTP with an OpenAPI 3.0 spec at /openapi.json.
// It is designed for CI/CD integration, external dashboards, and scripting.
package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	defaultRPS   = 20.0 // requests per second per IP
	defaultBurst = 50   // bucket capacity per IP

	// rlMaxBuckets caps the per-IP rate-limit map so a flood of unique IPs
	// cannot grow it without bound. When the map exceeds this size, stale
	// buckets are swept (and if still over, the least-recently-seen bucket
	// is evicted) on each new IP insert.
	rlMaxBuckets = 10000

	// rlBucketIdleTTL is how long a bucket is kept after the last request
	// from that IP. Anything older is eligible for sweep.
	rlBucketIdleTTL = 1 * time.Hour

	// HTTP server timeouts. ReadHeaderTimeout protects against slowloris;
	// IdleTimeout closes idle keep-alive connections.
	httpReadHeaderTimeout = 10 * time.Second
	httpReadTimeout       = 60 * time.Second
	httpWriteTimeout      = 120 * time.Second
	httpIdleTimeout       = 120 * time.Second

	// maxJSONBodyBytes caps JSON request bodies to prevent memory-DoS via
	// slow-stream or oversized POST payloads on the long-running daemon.
	// Used as the default when Server.MaxRequestBodyBytes is unset; the
	// runtime cap is reported in the OpenAPI spec (Task 20102). Aligned
	// with config.MaxRequestBodyBytesDefault so both servers behave the
	// same out of the box.
	maxJSONBodyBytes int64 = 10 << 20 // 10 MiB

	// maxMetricsFileBytes caps the size of .cloop/metrics.json the API server
	// will load and serve. A corrupted or runaway metrics file would otherwise
	// be loaded fully into memory before the response is written, doubling
	// allocation when re-encoded as a JSON-escaped string.
	maxMetricsFileBytes int64 = 4 << 20 // 4 MiB

	// maxArtifactFileBytes caps the size of a single task artifact .md file
	// served via GET /artifacts/{taskId}. AI-generated artifacts are typically
	// tens of KB; a 4 MiB cap covers very chatty runs while preventing a
	// runaway artifact (or one tampered with on disk) from OOM-ing the server.
	maxArtifactFileBytes int64 = 4 << 20 // 4 MiB
)

// ipBucket is a token-bucket state for one remote IP.
type ipBucket struct {
	tokens   float64
	lastSeen time.Time
}

// Server is the cloop REST API HTTP server.
type Server struct {
	WorkDir string
	Port    int
	Token   string // optional bearer token; empty = no auth

	// RPS and Burst control the per-IP token-bucket rate limiter.
	// Zero values use defaultRPS / defaultBurst.
	RPS   float64
	Burst int

	// MaxRequestBodyBytes caps any incoming POST/PUT/PATCH request body
	// the server will accept. Zero substitutes maxJSONBodyBytes (10 MiB).
	// Oversize requests are rejected with HTTP 413. Set via
	// config.UIConfig.MaxRequestBodyBytes when wired through cmd/serve.go.
	// Task 20102.
	MaxRequestBodyBytes int64

	mu        sync.Mutex
	runCmd    *exec.Cmd // currently-running `cloop run` subprocess, if any
	runActive bool      // mutex-guarded liveness flag; avoids racing on cmd.ProcessState
	runLog    strings.Builder

	// Per-IP rate-limit buckets.
	rlMu      sync.Mutex
	rlBuckets map[string]*ipBucket

	// Graceful shutdown plumbing. httpServer is set in Run after the
	// http.Server is constructed so Shutdown can call its Shutdown method.
	// shutdownMu serialises Shutdown vs Run-failure cleanup.
	shutdownMu sync.Mutex
	httpServer *http.Server

	// ReadyCheck overrides the readiness check used by /readyz. nil means
	// use defaultReadyCheck (stat state.db, open it, run SELECT 1 bounded
	// by ctx). Tests override this field to simulate degraded states like
	// "closed db handle" or "state store not initialized".
	ReadyCheck func(ctx context.Context) error

	// Log is the structured logger used for lifecycle / error messages
	// emitted by the API server itself (startup, shutdown, panics in
	// background goroutines). Nil means the package picks a sensible
	// default at first-use (text output to stdout, project bound).
	Log logger.Logger
}

// New creates a new API server.
func New(workdir string, port int, token string) *Server {
	return &Server{
		WorkDir:   workdir,
		Port:      port,
		Token:     token,
		rlBuckets: make(map[string]*ipBucket),
		Log:       logger.New(false).With("project", workdir).With("component", "apiserver"),
	}
}

// log returns s.Log, falling back to a default logger if the field was
// left zero by an external constructor.
func (s *Server) log() logger.Logger {
	if s.Log != nil {
		return s.Log
	}
	s.Log = logger.New(false).With("project", s.WorkDir).With("component", "apiserver")
	return s.Log
}

// effectiveMaxBodyBytes returns the configured request-body cap for this
// server, falling back to maxJSONBodyBytes when MaxRequestBodyBytes is
// unset or non-positive. Task 20102.
func (s *Server) effectiveMaxBodyBytes() int64 {
	if s != nil && s.MaxRequestBodyBytes > 0 {
		return s.MaxRequestBodyBytes
	}
	return maxJSONBodyBytes
}

// limitJSONBody wraps r.Body with http.MaxBytesReader so a subsequent
// json.NewDecoder().Decode() stops reading after maxBytes and returns
// *http.MaxBytesError instead of streaming attacker-controlled data into
// memory. Task 20102.
func limitJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	if r != nil && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
}

// respondToBodyError translates a JSON decode failure into the right HTTP
// response: HTTP 413 (PAYLOAD_TOO_LARGE) if MaxBytesReader fired, HTTP 400
// (INVALID_INPUT) otherwise. The helper centralises detection of
// *http.MaxBytesError so each handler's decode-error path stays consistent.
// Task 20102 / 20103.
func respondToBodyError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		apierror.Write(w, apierror.CodePayloadTooLarge, "request body too large")
		return
	}
	apierror.Write(w, apierror.CodeInvalidInput, "invalid JSON body")
}

// remoteIP extracts the client IP from the request, honouring X-Forwarded-For
// when the connection comes from localhost (reverse-proxy pattern).
func remoteIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if idx := strings.Index(fwd, ","); idx != -1 {
			return strings.TrimSpace(fwd[:idx])
		}
		return strings.TrimSpace(fwd)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// allow reports whether the request from ip is within the rate limit. It
// refills the bucket based on elapsed time and consumes one token.
func (s *Server) allow(ip string) bool {
	rps := s.RPS
	if rps <= 0 {
		rps = defaultRPS
	}
	burst := s.Burst
	if burst <= 0 {
		burst = defaultBurst
	}

	now := time.Now()
	s.rlMu.Lock()
	defer s.rlMu.Unlock()

	b, ok := s.rlBuckets[ip]
	if !ok {
		// New IP. If we're at the cap, sweep stale buckets first; if still
		// at the cap, evict the least-recently-seen one. Both branches keep
		// the map size bounded by rlMaxBuckets.
		if len(s.rlBuckets) >= rlMaxBuckets {
			s.evictRLBucketsLocked(now)
		}
		b = &ipBucket{tokens: float64(burst), lastSeen: now}
		s.rlBuckets[ip] = b
	}

	// Refill based on elapsed time.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rps
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictRLBucketsLocked removes stale rate-limit buckets to keep the map
// bounded. The caller must hold s.rlMu. It first sweeps anything older than
// rlBucketIdleTTL; if the map is still at the cap, it evicts the single
// least-recently-seen bucket so the caller can safely insert a new entry.
func (s *Server) evictRLBucketsLocked(now time.Time) {
	for ip, b := range s.rlBuckets {
		if now.Sub(b.lastSeen) > rlBucketIdleTTL {
			delete(s.rlBuckets, ip)
		}
	}
	if len(s.rlBuckets) < rlMaxBuckets {
		return
	}
	// Still full of recent entries — evict the oldest one.
	var oldestIP string
	var oldestSeen time.Time
	for ip, b := range s.rlBuckets {
		if oldestIP == "" || b.lastSeen.Before(oldestSeen) {
			oldestIP = ip
			oldestSeen = b.lastSeen
		}
	}
	if oldestIP != "" {
		delete(s.rlBuckets, oldestIP)
	}
}

// rateLimitMiddleware wraps next with per-IP token-bucket rate limiting.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allow(remoteIP(r)) {
			rps := s.RPS
			if rps <= 0 {
				rps = defaultRPS
			}
			retryAfter := int(1.0/rps) + 1
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			apierror.WriteError(w, apierror.New(apierror.CodeRateLimited, "rate limit exceeded").
				WithDetails(map[string]any{"retry_after_seconds": retryAfter}))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Start begins listening on the configured port. It installs SIGINT/SIGTERM
// handlers so the daemon shuts down gracefully when supervised by systemd or
// interrupted from a TTY: in-flight requests drain (bounded to 10s) before
// Start returns nil. Production callers use this; tests should call Run with
// their own context for fine-grained lifecycle control.
func (s *Server) Start() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return s.Run(ctx)
}

// Run is the lifecycle entrypoint without signal handling: it blocks until
// ctx is cancelled or the underlying http.Server fails. On ctx cancellation
// it triggers a bounded graceful shutdown (10s) and returns nil.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	// OpenAPI spec — no auth required so tooling can discover it.
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)

	// Plan
	mux.HandleFunc("GET /plan", s.handleGetPlan)

	// Tasks
	mux.HandleFunc("PATCH /tasks/{id}", s.handlePatchTask)

	// Run control
	mux.HandleFunc("POST /run/start", s.handleRunStart)
	mux.HandleFunc("POST /run/stop", s.handleRunStop)

	// Status & metrics
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Artifacts
	mux.HandleFunc("GET /artifacts/{taskId}", s.handleArtifact)

	addr := ":" + strconv.Itoa(s.Port)
	if s.Token != "" {
		fmt.Printf("cloop API server running at http://localhost%s (token auth enabled)\n", addr)
	} else {
		fmt.Printf("cloop API server running at http://localhost%s\n", addr)
	}
	fmt.Printf("OpenAPI spec: http://localhost%s/openapi.json\n", addr)
	s.log().Info(logger.EventSessionStart, 0, "cloop API server listening", map[string]interface{}{
		"port":      s.Port,
		"auth":      s.Token != "",
		"workdir":   s.WorkDir,
	})

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           s.buildHandler(mux),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}

	s.shutdownMu.Lock()
	s.httpServer = httpSrv
	s.shutdownMu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		s.log().Info(logger.EventSessionDone, 0, "cloop serve: shutting down", map[string]interface{}{
			"port": s.Port,
		})
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("api server shutdown: %w", err)
		}
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Shutdown initiates a graceful shutdown of a server started via Run. Safe to
// call from any goroutine; if the server has not started or has already been
// shut down it is a no-op. ctx bounds how long Shutdown will wait for
// in-flight requests to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownMu.Lock()
	srv := s.httpServer
	s.httpServer = nil
	s.shutdownMu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// buildHandler assembles the final HTTP handler chain. Probe endpoints
// (/healthz, /readyz) are routed BEFORE rate-limit and auth middleware so
// load balancers and Kubernetes-style probes can reach them without
// credentials and without competing with user traffic for token-bucket
// capacity.
func (s *Server) buildHandler(mux *http.ServeMux) http.Handler {
	return s.probeBypass(s.rateLimitMiddleware(s.authMiddleware(mux)))
}

// probeBypass routes /healthz and /readyz directly to their handlers,
// skipping auth and rate-limit middleware. Every other request flows
// through the supplied next handler unchanged.
func (s *Server) probeBypass(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			s.handleHealthz(w, r)
			return
		case "/readyz":
			s.handleReadyz(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// readyCheckTimeout caps the readiness probe's view of the SQLite store.
// Per Task 20092: "run a SELECT 1 with a 1s timeout."
const readyCheckTimeout = 1 * time.Second

// handleHealthz is the liveness probe. It returns 200 unconditionally as
// long as the request goroutine is alive — i.e., the process is up and
// the HTTP server is accepting connections. Liveness MUST NOT depend on
// downstream services (DB, network), or a transient outage would cause
// the orchestrator to kill an otherwise-recoverable process.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleReadyz is the readiness probe. It returns 200 only when the
// SQLite-backed state store is reachable AND has been initialized for
// this work directory; any failure yields 503 with a JSON body that
// names the failing check. The check is bounded by a 1s timeout so a
// hung database cannot block the probe response.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	check := s.ReadyCheck
	if check == nil {
		check = s.defaultReadyCheck
	}
	ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
	defer cancel()

	w.Header().Set("Content-Type", "application/json")
	if err := check(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "not_ready",
			"check":  "sqlite",
			"error":  err.Error(),
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready","check":"sqlite"}`))
}

// defaultReadyCheck verifies the state store is initialized at the server's
// configured workdir and reachable. ctx bounds the entire check (file stat,
// DB open, SELECT 1 ping) so a hung disk or wedged SQLite file cannot pin
// the probe goroutine.
func (s *Server) defaultReadyCheck(ctx context.Context) error {
	dbPath := state.StateDBPath(s.WorkDir)
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("state store not initialized at %s", dbPath)
		}
		return fmt.Errorf("state store stat: %w", err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("statedb open: %w", err)
	}
	defer db.Close()
	return db.PingContext(ctx)
}

// authMiddleware enforces Bearer-token authentication on all routes when
// s.Token is set. The /openapi.json endpoint is always public.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS pre-flight
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// OpenAPI spec is always public.
		if r.URL.Path == "/openapi.json" {
			next.ServeHTTP(w, r)
			return
		}

		if s.Token == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Authorization: Bearer <token>
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			if strings.TrimPrefix(auth, "Bearer ") == s.Token {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Fallback: ?token=<token>
		if r.URL.Query().Get("token") == s.Token {
			next.ServeHTTP(w, r)
			return
		}

		apierror.Write(w, apierror.CodeUnauthorized, "unauthorized")
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// jsonErr is a thin shim that forwards to apierror.WriteStatus, mapping
// the legacy `(message, status)` call shape to the structured wire
// format. Kept for backwards compatibility with the many existing call
// sites in this file; new code should call apierror.Write/WriteError
// directly so the chosen Code is visible at the call site. Task 20103.
func jsonErr(w http.ResponseWriter, msg string, code int) {
	apierror.WriteStatus(w, msg, code)
}

func loadState(w http.ResponseWriter, workDir string) (*state.ProjectState, bool) {
	ps, err := state.Load(workDir)
	if err != nil {
		// apierror.FromError maps statedb sentinels:
		//   ErrProjectNotFound / ErrTaskNotFound → NOT_FOUND (404)
		//   ErrStaleVersion                      → CONFLICT (409)
		//   ErrDBLocked                          → UNAVAILABLE (503)
		//   ErrSchemaMismatch                    → INTERNAL (500)
		// Anything else falls through to INTERNAL (500). The flat-404
		// behaviour from before Task 20103 was retired because a locked
		// or corrupt database should not be reported as "no project
		// found".
		if errors.Is(err, statedb.ErrProjectNotFound) {
			apierror.Write(w, apierror.CodeNotFound, "no cloop project found (run 'cloop init' first)")
		} else {
			apierror.WriteFromError(w, err)
		}
		return nil, false
	}
	return ps, true
}

// ── handlers ──────────────────────────────────────────────────────────────────

// GET /plan — return the current plan (goal + tasks).
func (s *Server) handleGetPlan(w http.ResponseWriter, r *http.Request) {
	ps, ok := loadState(w, s.WorkDir)
	if !ok {
		return
	}
	type planResponse struct {
		Goal   string     `json:"goal"`
		Status string     `json:"status"`
		PMMode bool       `json:"pm_mode"`
		Tasks  []*pm.Task `json:"tasks,omitempty"`
	}
	resp := planResponse{
		Goal:   ps.Goal,
		Status: ps.Status,
		PMMode: ps.PMMode,
	}
	if ps.Plan != nil {
		resp.Tasks = pm.SortPinnedFirst(ps.Plan.Tasks)
	}
	jsonOK(w, resp)
}

// PATCH /tasks/{id} — update a task's fields (status, title, priority, tags).
func (s *Server) handlePatchTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 1 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "invalid task id").
			WithDetails(map[string]any{"id": idStr}))
		return
	}

	var body struct {
		Status   string   `json:"status"`
		Title    string   `json:"title"`
		Priority int      `json:"priority"`
		Tags     []string `json:"tags"`
	}
	limitJSONBody(w, r, s.effectiveMaxBodyBytes())
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondToBodyError(w, err)
		return
	}

	ps, ok := loadState(w, s.WorkDir)
	if !ok {
		return
	}
	if !ps.PMMode || ps.Plan == nil {
		apierror.Write(w, apierror.CodeConflict, "PM mode not active")
		return
	}

	task, err := ps.RequireTask(id)
	if err != nil {
		apierror.WriteFromError(w, err)
		return
	}

	validStatuses := map[string]bool{
		"pending": true, "in_progress": true, "done": true,
		"skipped": true, "failed": true,
	}
	if body.Status != "" {
		if !validStatuses[body.Status] {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
				"invalid status; must be one of: pending, in_progress, done, skipped, failed").
				WithDetails(map[string]any{"field": "status", "value": body.Status}))
			return
		}
		task.Status = pm.TaskStatus(body.Status)
		if body.Status == "done" || body.Status == "failed" || body.Status == "skipped" {
			now := time.Now()
			task.CompletedAt = &now
		}
	}
	if body.Title != "" {
		task.Title = body.Title
	}
	if body.Priority != 0 {
		task.Priority = body.Priority
	}
	if body.Tags != nil {
		task.Tags = body.Tags
	}

	if err := ps.Save(); err != nil {
		apierror.WriteFromError(w, fmt.Errorf("save state: %w", err))
		return
	}
	jsonOK(w, task)
}

// POST /run/start — start `cloop run` as a subprocess.
func (s *Server) handleRunStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PM          bool   `json:"pm"`
		AutoEvolve  bool   `json:"auto_evolve"`
		PlanOnly    bool   `json:"plan_only"`
		RetryFailed bool   `json:"retry_failed"`
		Provider    string `json:"provider"`
		Model       string `json:"model"`
	}
	limitJSONBody(w, r, s.effectiveMaxBodyBytes())
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		respondToBodyError(w, err)
		return
	}

	s.mu.Lock()
	if s.runActive {
		s.mu.Unlock()
		apierror.Write(w, apierror.CodeConflict, "a run is already in progress")
		return
	}
	s.runLog.Reset()
	s.mu.Unlock()

	args := []string{"run"}
	if req.PM {
		args = append(args, "--pm")
	}
	if req.AutoEvolve {
		args = append(args, "--auto-evolve")
	}
	if req.PlanOnly {
		args = append(args, "--plan-only")
	}
	if req.RetryFailed {
		args = append(args, "--retry-failed")
	}
	if req.Provider != "" {
		args = append(args, "--provider", req.Provider)
	}
	if req.Model != "" {
		args = append(args, "--model", req.Model)
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = s.WorkDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "failed to start run").
			WithCause(err).
			WithDetails(map[string]any{"reason": err.Error()}))
		return
	}

	s.mu.Lock()
	s.runCmd = cmd
	s.runActive = true
	s.mu.Unlock()

	// Reap the process in a goroutine. Recover from panics so a bug in the
	// reaper cannot kill the API server, and always clear runActive so the
	// caller can start another run after this one exits.
	go func() {
		startedAt := time.Now()
		defer func() {
			if r := recover(); r != nil {
				s.log().Error(logger.EventTaskFailed, 0, "panic in run reaper", map[string]interface{}{
					"panic":       fmt.Sprintf("%v", r),
					"duration_ms": time.Since(startedAt).Milliseconds(),
				})
			}
			s.mu.Lock()
			s.runActive = false
			s.mu.Unlock()
		}()
		_ = cmd.Wait()
		s.log().Info(logger.EventSessionDone, 0, "run subprocess exited", map[string]interface{}{
			"pid":         cmd.Process.Pid,
			"duration_ms": time.Since(startedAt).Milliseconds(),
		})
	}()

	jsonOK(w, map[string]any{
		"started": true,
		"pid":     cmd.Process.Pid,
		"args":    args,
	})
}

// POST /run/stop — send SIGTERM to the running subprocess.
func (s *Server) handleRunStop(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cmd := s.runCmd
	active := s.runActive
	s.mu.Unlock()

	if cmd == nil || !active {
		jsonErr(w, "no run currently in progress", http.StatusConflict)
		return
	}
	if err := cmd.Process.Kill(); err != nil {
		jsonErr(w, "failed to stop run: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"stopped": true})
}

// GET /status — lightweight status summary (no full step history).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ps, ok := loadState(w, s.WorkDir)
	if !ok {
		return
	}

	type taskSummary struct {
		ID     int    `json:"id"`
		Title  string `json:"title"`
		Status string `json:"status"`
	}
	type statusResponse struct {
		Goal        string        `json:"goal"`
		Status      string        `json:"status"`
		Provider    string        `json:"provider,omitempty"`
		CurrentStep int           `json:"current_step"`
		MaxSteps    int           `json:"max_steps,omitempty"`
		PMMode      bool          `json:"pm_mode"`
		Tasks       []taskSummary `json:"tasks,omitempty"`
		UpdatedAt   time.Time     `json:"updated_at"`

		// Derived counters for PM mode
		TasksDone    int `json:"tasks_done,omitempty"`
		TasksPending int `json:"tasks_pending,omitempty"`
		TasksFailed  int `json:"tasks_failed,omitempty"`

		// Token usage
		TotalInputTokens  int `json:"total_input_tokens,omitempty"`
		TotalOutputTokens int `json:"total_output_tokens,omitempty"`

		// Is there a subprocess currently running?
		RunActive bool `json:"run_active"`
	}

	resp := statusResponse{
		Goal:              ps.Goal,
		Status:            ps.Status,
		Provider:          ps.Provider,
		CurrentStep:       ps.CurrentStep,
		MaxSteps:          ps.MaxSteps,
		PMMode:            ps.PMMode,
		UpdatedAt:         ps.UpdatedAt,
		TotalInputTokens:  ps.TotalInputTokens,
		TotalOutputTokens: ps.TotalOutputTokens,
	}

	s.mu.Lock()
	resp.RunActive = s.runActive
	s.mu.Unlock()

	if ps.PMMode && ps.Plan != nil {
		for _, t := range ps.Plan.Tasks {
			resp.Tasks = append(resp.Tasks, taskSummary{ID: t.ID, Title: t.Title, Status: string(t.Status)})
			switch t.Status {
			case "done", "skipped":
				resp.TasksDone++
			case "pending", "in_progress":
				resp.TasksPending++
			case "failed":
				resp.TasksFailed++
			}
		}
	}

	jsonOK(w, resp)
}

// GET /metrics — return metrics as Prometheus text or JSON.
// Use Accept: application/json to get JSON; default is Prometheus text format.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metricsPath := filepath.Join(s.WorkDir, ".cloop", "metrics.json")
	data, err := boundedread.ReadFile(metricsPath, maxMetricsFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No metrics file yet — return empty metrics.
			jsonOK(w, map[string]any{"error": "no metrics data yet"})
			return
		}
		if errors.Is(err, boundedread.ErrTooLarge) {
			jsonErr(w, "metrics file exceeds size limit", http.StatusRequestEntityTooLarge)
			return
		}
		jsonErr(w, "failed to read metrics: "+err.Error(), http.StatusInternalServerError)
		return
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		// Return raw JSON metrics.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
		return
	}

	// Otherwise try to present as Prometheus text. If the file is already
	// Prometheus-format we serve it as-is; if it's JSON we serve the JSON with
	// the right content type.
	if len(data) > 0 && data[0] == '{' {
		// It's JSON — serve it as JSON regardless of Accept.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	} else {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write(data)
	}
}

// GET /artifacts/{taskId} — return the artifact Markdown for a task.
func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("taskId")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 1 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	dir := filepath.Join(s.WorkDir, ".cloop", "tasks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			jsonErr(w, "no artifacts found", http.StatusNotFound)
			return
		}
		jsonErr(w, "failed to read artifacts dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	prefix := fmt.Sprintf("%d-", id)
	for _, e := range entries {
		name := e.Name()
		// Match <id>-<slug>.md but not the -verify.md variant.
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".md") && !strings.HasSuffix(name, "-verify.md") {
			data, err := boundedread.ReadFile(filepath.Join(dir, name), maxArtifactFileBytes)
			if err != nil {
				if errors.Is(err, boundedread.ErrTooLarge) {
					jsonErr(w, "artifact exceeds size limit", http.StatusRequestEntityTooLarge)
					return
				}
				jsonErr(w, "failed to read artifact: "+err.Error(), http.StatusInternalServerError)
				return
			}
			accept := r.Header.Get("Accept")
			if strings.Contains(accept, "application/json") {
				jsonOK(w, map[string]string{
					"task_id":  idStr,
					"filename": name,
					"content":  string(data),
				})
			} else {
				w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
				_, _ = w.Write(data)
			}
			return
		}
	}

	jsonErr(w, fmt.Sprintf("artifact for task %d not found", id), http.StatusNotFound)
}

// GET /openapi.json — return the OpenAPI 3.0 specification.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	spec := buildOpenAPISpec(s.Port, s.Token != "")
	jsonOK(w, spec)
}

// buildOpenAPISpec constructs the OpenAPI 3.0 document as a Go map so we
// don't need a template or external dependency.
func buildOpenAPISpec(port int, hasAuth bool) map[string]any {
	securitySchemes := map[string]any{}
	var security []any
	if hasAuth {
		securitySchemes["bearerAuth"] = map[string]any{
			"type":         "http",
			"scheme":       "bearer",
			"bearerFormat": "token",
		}
		security = []any{map[string]any{"bearerAuth": []any{}}}
	}

	taskSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id":          map[string]any{"type": "integer"},
			"title":       map[string]any{"type": "string"},
			"description": map[string]any{"type": "string"},
			"status": map[string]any{
				"type": "string",
				"enum": []any{"pending", "in_progress", "done", "skipped", "failed"},
			},
			"priority":          map[string]any{"type": "integer"},
			"role":              map[string]any{"type": "string"},
			"tags":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"depends_on":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
			"estimated_minutes": map[string]any{"type": "integer"},
			"actual_minutes":    map[string]any{"type": "integer"},
			"artifact_path":     map[string]any{"type": "string"},
		},
	}

	errorSchema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"error": map[string]any{"type": "string"}},
	}

	paths := map[string]any{
		"/openapi.json": map[string]any{
			"get": map[string]any{
				"summary":     "OpenAPI specification",
				"operationId": "getOpenAPI",
				"security":    []any{},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "OpenAPI 3.0 document",
						"content":     map[string]any{"application/json": map[string]any{}},
					},
				},
			},
		},
		"/plan": map[string]any{
			"get": map[string]any{
				"summary":     "Get the current plan",
				"operationId": "getPlan",
				"responses": map[string]any{
					"200": map[string]any{
						"description": "Plan with goal and task list",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"goal":    map[string]any{"type": "string"},
										"status":  map[string]any{"type": "string"},
										"pm_mode": map[string]any{"type": "boolean"},
										"tasks":   map[string]any{"type": "array", "items": taskSchema},
									},
								},
							},
						},
					},
					"404": map[string]any{"description": "No cloop project found"},
				},
			},
		},
		"/tasks/{id}": map[string]any{
			"patch": map[string]any{
				"summary":     "Update a task",
				"operationId": "patchTask",
				"parameters": []any{
					map[string]any{
						"name": "id", "in": "path", "required": true,
						"schema": map[string]any{"type": "integer"},
					},
				},
				"requestBody": map[string]any{
					"required": true,
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"status": map[string]any{
										"type": "string",
										"enum": []any{"pending", "in_progress", "done", "skipped", "failed"},
									},
									"title":    map[string]any{"type": "string"},
									"priority": map[string]any{"type": "integer"},
									"tags":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
								},
							},
						},
					},
				},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "Updated task",
						"content":     map[string]any{"application/json": map[string]any{"schema": taskSchema}},
					},
					"400": map[string]any{"description": "Bad request"},
					"404": map[string]any{"description": "Task not found"},
					"409": map[string]any{"description": "PM mode not active"},
				},
			},
		},
		"/run/start": map[string]any{
			"post": map[string]any{
				"summary":     "Start a cloop run",
				"operationId": "runStart",
				"requestBody": map[string]any{
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"pm":           map[string]any{"type": "boolean"},
									"auto_evolve":  map[string]any{"type": "boolean"},
									"plan_only":    map[string]any{"type": "boolean"},
									"retry_failed": map[string]any{"type": "boolean"},
									"provider":     map[string]any{"type": "string"},
									"model":        map[string]any{"type": "string"},
								},
							},
						},
					},
				},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "Run started",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"started": map[string]any{"type": "boolean"},
										"pid":     map[string]any{"type": "integer"},
										"args":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
									},
								},
							},
						},
					},
					"409": map[string]any{"description": "A run is already in progress"},
					"500": map[string]any{"description": "Failed to start run"},
				},
			},
		},
		"/run/stop": map[string]any{
			"post": map[string]any{
				"summary":     "Stop the current run",
				"operationId": "runStop",
				"responses": map[string]any{
					"200": map[string]any{
						"description": "Run stopped",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type":       "object",
									"properties": map[string]any{"stopped": map[string]any{"type": "boolean"}},
								},
							},
						},
					},
					"409": map[string]any{"description": "No run in progress"},
				},
			},
		},
		"/status": map[string]any{
			"get": map[string]any{
				"summary":     "Get lightweight status summary",
				"operationId": "getStatus",
				"responses": map[string]any{
					"200": map[string]any{
						"description": "Status summary",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"goal":                map[string]any{"type": "string"},
										"status":              map[string]any{"type": "string"},
										"provider":            map[string]any{"type": "string"},
										"current_step":        map[string]any{"type": "integer"},
										"max_steps":           map[string]any{"type": "integer"},
										"pm_mode":             map[string]any{"type": "boolean"},
										"run_active":          map[string]any{"type": "boolean"},
										"tasks_done":          map[string]any{"type": "integer"},
										"tasks_pending":       map[string]any{"type": "integer"},
										"tasks_failed":        map[string]any{"type": "integer"},
										"total_input_tokens":  map[string]any{"type": "integer"},
										"total_output_tokens": map[string]any{"type": "integer"},
										"updated_at":          map[string]any{"type": "string", "format": "date-time"},
									},
								},
							},
						},
					},
					"404": map[string]any{"description": "No cloop project found"},
				},
			},
		},
		"/metrics": map[string]any{
			"get": map[string]any{
				"summary":     "Get run metrics",
				"operationId": "getMetrics",
				"parameters": []any{
					map[string]any{
						"name": "Accept", "in": "header",
						"description": "Use application/json for JSON; default is Prometheus text format",
						"schema":      map[string]any{"type": "string"},
					},
				},
				"responses": map[string]any{
					"200": map[string]any{"description": "Metrics in Prometheus text or JSON format"},
					"404": map[string]any{"description": "No metrics data yet"},
				},
			},
		},
		"/artifacts/{taskId}": map[string]any{
			"get": map[string]any{
				"summary":     "Get the artifact for a task",
				"operationId": "getArtifact",
				"parameters": []any{
					map[string]any{
						"name": "taskId", "in": "path", "required": true,
						"schema": map[string]any{"type": "integer"},
					},
				},
				"responses": map[string]any{
					"200": map[string]any{"description": "Artifact Markdown (or JSON if Accept: application/json)"},
					"404": map[string]any{"description": "Artifact not found"},
				},
			},
		},
	}

	spec := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "cloop REST API",
			"description": "REST API for cloop — the AI product manager. Enables CI/CD integration, external dashboards, and scripting without the TUI or Web UI.",
			"version":     "1.0.0",
			"contact": map[string]any{
				"name": "cloop",
				"url":  "https://github.com/blechschmidt/cloop",
			},
		},
		"servers": []any{
			map[string]any{
				"url":         fmt.Sprintf("http://localhost:%d", port),
				"description": "Local cloop API server",
			},
		},
		"paths": paths,
		"components": map[string]any{
			"schemas": map[string]any{
				"Task":  taskSchema,
				"Error": errorSchema,
			},
			"securitySchemes": securitySchemes,
		},
	}
	if hasAuth {
		spec["security"] = security
	}
	return spec
}
