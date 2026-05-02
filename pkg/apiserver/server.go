// Package apiserver implements a standalone REST API server that exposes all
// cloop functionality over HTTP with an OpenAPI 3.0 spec at /openapi.json.
// It is designed for CI/CD integration, external dashboards, and scripting.
package apiserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	defaultRPS   = 20.0 // requests per second per IP
	defaultBurst = 50   // bucket capacity per IP
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

	mu      sync.Mutex
	runCmd  *exec.Cmd // currently-running `cloop run` subprocess, if any
	runLog  strings.Builder

	// Per-IP rate-limit buckets.
	rlMu     sync.Mutex
	rlBuckets map[string]*ipBucket
}

// New creates a new API server.
func New(workdir string, port int, token string) *Server {
	return &Server{
		WorkDir:   workdir,
		Port:      port,
		Token:     token,
		rlBuckets: make(map[string]*ipBucket),
	}
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
			jsonErr(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Start begins listening on the configured port.
func (s *Server) Start() error {
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
	return http.ListenAndServe(addr, s.rateLimitMiddleware(s.authMiddleware(mux)))
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

		jsonErr(w, "unauthorized", http.StatusUnauthorized)
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func loadState(w http.ResponseWriter, workDir string) (*state.ProjectState, bool) {
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, "no cloop project found (run 'cloop init' first)", http.StatusNotFound)
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
		resp.Tasks = ps.Plan.Tasks
	}
	jsonOK(w, resp)
}

// PATCH /tasks/{id} — update a task's fields (status, title, priority, tags).
func (s *Server) handlePatchTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 1 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	var body struct {
		Status   string   `json:"status"`
		Title    string   `json:"title"`
		Priority int      `json:"priority"`
		Tags     []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	ps, ok := loadState(w, s.WorkDir)
	if !ok {
		return
	}
	if !ps.PMMode || ps.Plan == nil {
		jsonErr(w, "PM mode not active", http.StatusConflict)
		return
	}

	var task *pm.Task
	for _, t := range ps.Plan.Tasks {
		if t.ID == id {
			task = t
			break
		}
	}
	if task == nil {
		jsonErr(w, fmt.Sprintf("task %d not found", id), http.StatusNotFound)
		return
	}

	validStatuses := map[string]bool{
		"pending": true, "in_progress": true, "done": true,
		"skipped": true, "failed": true,
	}
	if body.Status != "" {
		if !validStatuses[body.Status] {
			jsonErr(w, "invalid status; must be one of: pending, in_progress, done, skipped, failed", http.StatusBadRequest)
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
		jsonErr(w, "failed to save state: "+err.Error(), http.StatusInternalServerError)
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
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	if s.runCmd != nil && s.runCmd.ProcessState == nil {
		s.mu.Unlock()
		jsonErr(w, "a run is already in progress", http.StatusConflict)
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
		jsonErr(w, "failed to start run: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.runCmd = cmd
	s.mu.Unlock()

	// Reap the process in a goroutine.
	go func() { _ = cmd.Wait() }()

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
	s.mu.Unlock()

	if cmd == nil || cmd.ProcessState != nil {
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
	resp.RunActive = s.runCmd != nil && s.runCmd.ProcessState == nil
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
	data, err := os.ReadFile(metricsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No metrics file yet — return empty metrics.
			jsonOK(w, map[string]any{"error": "no metrics data yet"})
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
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
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
