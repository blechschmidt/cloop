// Package ui implements a local web dashboard for monitoring and controlling cloop.
package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// sseEvent is a typed SSE message. If Event is empty the browser receives a
// default "message" event; otherwise the named event type is sent.
type sseEvent struct {
	Event string // e.g. "" or "log"
	Data  string
}

// ChatMessage is a single turn in the chat conversation history.
type ChatMessage struct {
	Role      string    `json:"role"`            // "user" or "assistant"
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action,omitempty"` // resolved cloop command, if any
}

const liveLogMaxLines = 500

// authFailEntry tracks failed authentication attempts for rate-limiting.
type authFailEntry struct {
	count     int
	lockedUntil time.Time
}

const (
	authMaxFailures    = 5               // failures before lockout
	authLockoutSeconds = 60              // lockout duration in seconds
)

// Server is the cloop web dashboard HTTP server.
type Server struct {
	WorkDir  string
	Port     int
	Token    string   // optional auth token; empty = no auth
	Projects []string // extra project directories for multi-project dashboard

	mu      sync.Mutex
	clients map[chan sseEvent]struct{}
	lastMod time.Time

	// Rate limiting: tracks per-IP auth failure counts.
	authMu   sync.Mutex
	authFails map[string]*authFailEntry

	// Live log ring-buffer (last liveLogMaxLines lines of subprocess output).
	liveLogMu      sync.Mutex
	liveLogLines   []string
	liveLogRunning bool

	// Suggest background job state
	suggestMu      sync.Mutex
	suggestRunning bool
	suggestLog     bytes.Buffer
	suggestErr     string
	suggestDone    bool

	// Multi-project state cache
	projMu       sync.RWMutex
	projStatuses []multiui.ProjectStatus
	projLastMod  map[string]time.Time // path -> last mod time

	// Chat conversation history
	chatMu      sync.Mutex
	chatHistory []ChatMessage
}

// New creates a new UI server for the given working directory and port.
// token is optional; if non-empty every API request must supply it via
// "Authorization: Bearer <token>" header or "?token=<token>" query param.
func New(workdir string, port int, token string) *Server {
	return &Server{
		WorkDir:   workdir,
		Port:      port,
		Token:     token,
		clients:   make(map[chan sseEvent]struct{}),
		authFails: make(map[string]*authFailEntry),
	}
}

// Start begins listening on the configured port and broadcasting state updates.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Dashboard SPA
	mux.HandleFunc("/", s.handleDashboard)

	// Read-only state & SSE
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/events", s.handleEvents)

	// Run controls
	mux.HandleFunc("/api/run", s.handleRun)
	mux.HandleFunc("/api/stop", s.handleStop)

	// Task management (legacy endpoints)
	mux.HandleFunc("/api/task/add", s.handleTaskAdd)
	mux.HandleFunc("/api/task/status", s.handleTaskStatus)
	mux.HandleFunc("/api/task/move", s.handleTaskMove)
	mux.HandleFunc("/api/task/edit", s.handleTaskEdit)
	mux.HandleFunc("/api/task/remove", s.handleTaskRemove)

	// RESTful task endpoints (Go 1.22+ method+path routing)
	mux.HandleFunc("POST /api/tasks", s.handlePostTasks)
	mux.HandleFunc("POST /api/tasks/reorder", s.handleReorderTasks)
	mux.HandleFunc("PUT /api/tasks/{id}", s.handlePutTask)
	mux.HandleFunc("DELETE /api/tasks/{id}", s.handleDeleteTask)

	// Config
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/set", s.handleConfigSet)

	// Suggest
	mux.HandleFunc("/api/suggest/run", s.handleSuggestRun)
	mux.HandleFunc("/api/suggest/status", s.handleSuggestStatus)

	// Live log
	mux.HandleFunc("/api/livelog", s.handleLiveLog)

	// Voice / STT
	mux.HandleFunc("/api/voice", s.handleVoice)

	// Chat
	mux.HandleFunc("/api/chat", s.handleChat)
	mux.HandleFunc("/api/chat/history", s.handleChatHistory)

	// Init & reset
	mux.HandleFunc("/api/init", s.handleInit)
	mux.HandleFunc("/api/reset", s.handleReset)

	// Multi-project dashboard
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/projects/events", s.handleProjectsEvents)
	mux.HandleFunc("POST /api/projects/{idx}/run", s.handleProjectRun)
	mux.HandleFunc("POST /api/projects/{idx}/stop", s.handleProjectStop)

	go s.watchState()
	go s.watchProjects()

	addr := ":" + strconv.Itoa(s.Port)
	if s.Token != "" {
		fmt.Printf("cloop dashboard running at http://localhost%s (token auth enabled)\n", addr)
	} else {
		fmt.Printf("cloop dashboard running at http://localhost%s\n", addr)
	}
	return http.ListenAndServe(addr, securityHeaders(s.authMiddleware(mux)))
}

// securityHeaders adds hardening HTTP response headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME-type sniffing.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Deny framing to prevent clickjacking.
		w.Header().Set("X-Frame-Options", "DENY")
		// Strict CSP: only allow same-origin resources plus inline styles/scripts
		// needed by the SPA. No external connections permitted.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		// Disable the Referrer header for privacy.
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Restrict CORS to localhost only (not wildcard).
		origin := r.Header.Get("Origin")
		if origin != "" {
			if strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the real client IP, preferring X-Forwarded-For when running
// behind a reverse proxy on localhost.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// Take first address only.
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

// authMiddleware enforces Bearer-token authentication on all /api/* routes when
// s.Token is set. The root path "/" is always served without auth so the login
// page can be loaded in the browser. Failed attempts are rate-limited per IP.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Token == "" || r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientIP(r)

		// Check rate limit before evaluating the token.
		if s.Token != "" {
			s.authMu.Lock()
			entry, ok := s.authFails[ip]
			if !ok {
				entry = &authFailEntry{}
				s.authFails[ip] = entry
			}
			if entry.count >= authMaxFailures && time.Now().Before(entry.lockedUntil) {
				s.authMu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(authLockoutSeconds))
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{"error": "too many failed attempts, try again later"}) //nolint:errcheck
				return
			}
			// Reset counter if lockout has expired.
			if entry.count >= authMaxFailures && time.Now().After(entry.lockedUntil) {
				entry.count = 0
			}
			s.authMu.Unlock()
		}

		// Check Authorization: Bearer <token> header.
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			if strings.TrimPrefix(auth, "Bearer ") == s.Token {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Fallback: ?token=<token> query param (needed for EventSource which
		// cannot send custom headers).
		if r.URL.Query().Get("token") == s.Token {
			next.ServeHTTP(w, r)
			return
		}

		// Auth failed — increment failure counter.
		s.authMu.Lock()
		entry := s.authFails[ip]
		entry.count++
		if entry.count >= authMaxFailures {
			entry.lockedUntil = time.Now().Add(authLockoutSeconds * time.Second)
		}
		s.authMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}) //nolint:errcheck
	})
}

// watchState polls the state file every second and notifies SSE clients on change.
func (s *Server) watchState() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		statePath := state.StatePath(s.WorkDir)
		fi, err := os.Stat(statePath)
		if err != nil {
			continue
		}
		if fi.ModTime().Equal(s.lastMod) {
			continue
		}
		s.lastMod = fi.ModTime()

		data, err := os.ReadFile(statePath)
		if err != nil {
			continue
		}
		s.broadcast(string(data))
	}
}

// broadcast sends a state JSON payload to all connected SSE clients as a
// default ("message") SSE event.
func (s *Server) broadcast(data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- sseEvent{Data: data}:
		default:
		}
	}
}

// broadcastLog sends a log chunk to all connected SSE clients as a "log"
// SSE event, and stores it in the ring buffer.
func (s *Server) broadcastLog(chunk string) {
	// Update ring buffer: split chunk into lines and append.
	s.liveLogMu.Lock()
	for _, line := range strings.SplitAfter(chunk, "\n") {
		if line == "" {
			continue
		}
		s.liveLogLines = append(s.liveLogLines, line)
		if len(s.liveLogLines) > liveLogMaxLines {
			s.liveLogLines = s.liveLogLines[len(s.liveLogLines)-liveLogMaxLines:]
		}
	}
	s.liveLogMu.Unlock()

	data, _ := json.Marshal(map[string]string{"chunk": chunk})
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- sseEvent{Event: "log", Data: string(data)}:
		default:
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// ── handlers ─────────────────────────────────────────────────────────────────

// handleDashboard serves the single-page HTML dashboard.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, dashboardHTML) //nolint:errcheck
}

// handleState returns the current project state as JSON.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no cloop project found", http.StatusNotFound)
		return
	}
	jsonOK(w, ps)
}

// handleEvents is an SSE endpoint that streams state updates to the browser.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan sseEvent, 8)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	// Send current state immediately on connect.
	if ps, err := state.Load(s.WorkDir); err == nil {
		if data, err := json.Marshal(ps); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}

	// Send current live log buffer so reconnecting clients see recent output.
	s.liveLogMu.Lock()
	if len(s.liveLogLines) > 0 {
		buf := strings.Join(s.liveLogLines, "")
		s.liveLogMu.Unlock()
		if d, err := json.Marshal(map[string]string{"chunk": buf}); err == nil {
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", d)
			flusher.Flush()
		}
	} else {
		s.liveLogMu.Unlock()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			if ev.Event != "" {
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Event, ev.Data)
			} else {
				fmt.Fprintf(w, "data: %s\n\n", ev.Data)
			}
			flusher.Flush()
		}
	}
}

// handleRun starts `cloop run` with optional flags from a JSON body.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		PM          bool   `json:"pm"`
		AutoEvolve  bool   `json:"autoEvolve"`
		PlanOnly    bool   `json:"planOnly"`
		RetryFailed bool   `json:"retryFailed"`
		Innovate    bool   `json:"innovate"`
		DryRun      bool   `json:"dryRun"`
		Provider    string `json:"provider"`
		Model       string `json:"model"`
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&req)
	} else {
		// Legacy query-param compat
		req.PM = r.URL.Query().Get("pm") == "1"
	}

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
	if req.Innovate {
		args = append(args, "--innovate")
	}
	if req.DryRun {
		args = append(args, "--dry-run")
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

	// Pipe combined output so we can stream it to the live log panel.
	pipeR, pipeW, pipeErr := os.Pipe()
	if pipeErr != nil {
		// Fall back to inheriting stderr if pipe creation fails.
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = pipeW
		cmd.Stderr = pipeW
	}

	if err := cmd.Start(); err != nil {
		if pipeR != nil {
			pipeR.Close()
			pipeW.Close()
		}
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if pipeErr == nil {
		// Clear old log and mark running.
		s.liveLogMu.Lock()
		s.liveLogLines = nil
		s.liveLogRunning = true
		s.liveLogMu.Unlock()

		pipeW.Close() // parent doesn't write; close its end so reader gets EOF when child exits.

		go func() {
			buf := make([]byte, 4096)
			for {
				n, readErr := pipeR.Read(buf)
				if n > 0 {
					chunk := string(buf[:n])
					os.Stderr.WriteString(chunk) // also echo to server's stderr
					s.broadcastLog(chunk)
				}
				if readErr != nil {
					break
				}
			}
			pipeR.Close()
			_ = cmd.Wait()
			s.liveLogMu.Lock()
			s.liveLogRunning = false
			s.liveLogMu.Unlock()
			// Broadcast updated state after run completes.
			if ps, loadErr := state.Load(s.WorkDir); loadErr == nil {
				if data, marshalErr := json.Marshal(ps); marshalErr == nil {
					s.broadcast(string(data))
				}
			}
		}()
	} else {
		go func() { _ = cmd.Wait() }()
	}

	jsonOK(w, map[string]interface{}{"ok": true, "command": "cloop " + strings.Join(args, " ")})
}

// handleStop sends SIGINT to any running `cloop run` processes.
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	out, err := exec.Command("pkill", "-SIGINT", "-f", "cloop run").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "no running cloop process found"
		}
		jsonOK(w, map[string]interface{}{"ok": false, "message": msg})
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "message": "pause signal sent"})
}

// handleConfig returns the current configuration with secrets masked.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := config.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	type provInfo struct {
		HasKey  bool   `json:"has_key"`
		Model   string `json:"model"`
		BaseURL string `json:"base_url"`
	}
	jsonOK(w, map[string]interface{}{
		"provider": cfg.Provider,
		"anthropic": provInfo{
			HasKey:  cfg.Anthropic.APIKey != "",
			Model:   cfg.Anthropic.Model,
			BaseURL: cfg.Anthropic.BaseURL,
		},
		"openai": provInfo{
			HasKey:  cfg.OpenAI.APIKey != "",
			Model:   cfg.OpenAI.Model,
			BaseURL: cfg.OpenAI.BaseURL,
		},
		"ollama": map[string]string{
			"base_url": cfg.Ollama.BaseURL,
			"model":    cfg.Ollama.Model,
		},
		"claudecode": map[string]string{
			"model": cfg.ClaudeCode.Model,
		},
	})
}

// handleConfigSet sets a single configuration key.
func (s *Server) handleConfigSet(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	cfg, err := config.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	if err := applyUIConfigKey(cfg, req.Key, req.Value); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.Save(s.WorkDir, cfg); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// applyUIConfigKey applies a key/value pair to a Config struct.
func applyUIConfigKey(cfg *config.Config, key, value string) error {
	switch strings.ToLower(key) {
	case "provider":
		valid := map[string]bool{"anthropic": true, "openai": true, "ollama": true, "claudecode": true}
		if !valid[value] {
			return fmt.Errorf("unknown provider %q — valid: anthropic, openai, ollama, claudecode", value)
		}
		cfg.Provider = value
	case "anthropic.api_key":
		cfg.Anthropic.APIKey = value
	case "anthropic.model":
		cfg.Anthropic.Model = value
	case "anthropic.base_url":
		cfg.Anthropic.BaseURL = value
	case "openai.api_key":
		cfg.OpenAI.APIKey = value
	case "openai.model":
		cfg.OpenAI.Model = value
	case "openai.base_url":
		cfg.OpenAI.BaseURL = value
	case "ollama.base_url":
		cfg.Ollama.BaseURL = value
	case "ollama.model":
		cfg.Ollama.Model = value
	case "claudecode.model":
		cfg.ClaudeCode.Model = value
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

// handleTaskAdd adds a new task to the plan.
func (s *Server) handleTaskAdd(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
		DependsOn   []int  `json:"depends_on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		jsonErr(w, "title is required", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found — run cloop init first", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		ps.Plan = pm.NewPlan(ps.Goal)
		ps.PMMode = true
	}

	maxID, maxPri := 0, 0
	for _, t := range ps.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
		if t.Priority > maxPri {
			maxPri = t.Priority
		}
	}
	priority := req.Priority
	if priority <= 0 {
		priority = maxPri + 1
	}

	task := &pm.Task{
		ID:          maxID + 1,
		Title:       req.Title,
		Description: req.Description,
		Priority:    priority,
		DependsOn:   req.DependsOn,
		Status:      pm.TaskPending,
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, task)

	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "task": task})
}

// handleTaskStatus changes a task's status.
func (s *Server) handleTaskStatus(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	validStatuses := map[string]pm.TaskStatus{
		"pending":     pm.TaskPending,
		"in_progress": pm.TaskInProgress,
		"done":        pm.TaskDone,
		"skipped":     pm.TaskSkipped,
		"failed":      pm.TaskFailed,
	}
	newStatus, ok := validStatuses[req.Status]
	if !ok {
		jsonErr(w, fmt.Sprintf("invalid status %q", req.Status), http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan", http.StatusNotFound)
		return
	}

	var task *pm.Task
	for _, t := range ps.Plan.Tasks {
		if t.ID == req.ID {
			task = t
			break
		}
	}
	if task == nil {
		jsonErr(w, fmt.Sprintf("task %d not found", req.ID), http.StatusNotFound)
		return
	}

	task.Status = newStatus
	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "id": req.ID, "status": req.Status})
}

// handleTaskMove reorders a task up or down by swapping priorities.
func (s *Server) handleTaskMove(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID        int    `json:"id"`
		Direction string `json:"direction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Direction != "up" && req.Direction != "down" {
		jsonErr(w, "direction must be 'up' or 'down'", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil || len(ps.Plan.Tasks) == 0 {
		jsonErr(w, "no task plan", http.StatusNotFound)
		return
	}

	sorted := make([]*pm.Task, len(ps.Plan.Tasks))
	copy(sorted, ps.Plan.Tasks)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Priority < sorted[j].Priority })

	idx := -1
	for i, t := range sorted {
		if t.ID == req.ID {
			idx = i
			break
		}
	}
	if idx == -1 {
		jsonErr(w, fmt.Sprintf("task %d not found", req.ID), http.StatusNotFound)
		return
	}

	var other *pm.Task
	if req.Direction == "up" {
		if idx == 0 {
			jsonErr(w, "already at top", http.StatusBadRequest)
			return
		}
		other = sorted[idx-1]
	} else {
		if idx == len(sorted)-1 {
			jsonErr(w, "already at bottom", http.StatusBadRequest)
			return
		}
		other = sorted[idx+1]
	}
	sorted[idx].Priority, other.Priority = other.Priority, sorted[idx].Priority

	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "id": req.ID})
}

// handleTaskEdit edits a task's title, description, priority, and/or depends_on.
func (s *Server) handleTaskEdit(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID          int    `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
		DependsOn   *[]int `json:"depends_on"` // nil = don't change; []int{} = clear; [1,2] = set
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan", http.StatusNotFound)
		return
	}

	var task *pm.Task
	for _, t := range ps.Plan.Tasks {
		if t.ID == req.ID {
			task = t
			break
		}
	}
	if task == nil {
		jsonErr(w, fmt.Sprintf("task %d not found", req.ID), http.StatusNotFound)
		return
	}

	if t := strings.TrimSpace(req.Title); t != "" {
		task.Title = t
	}
	if req.Description != "" {
		task.Description = req.Description
	}
	if req.Priority > 0 {
		task.Priority = req.Priority
	}
	if req.DependsOn != nil {
		task.DependsOn = *req.DependsOn
	}

	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "task": task})
}

// handleTaskRemove removes a task from the plan.
func (s *Server) handleTaskRemove(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan", http.StatusNotFound)
		return
	}

	idx := -1
	for i, t := range ps.Plan.Tasks {
		if t.ID == req.ID {
			idx = i
			break
		}
	}
	if idx == -1 {
		jsonErr(w, fmt.Sprintf("task %d not found", req.ID), http.StatusNotFound)
		return
	}

	ps.Plan.Tasks = append(ps.Plan.Tasks[:idx], ps.Plan.Tasks[idx+1:]...)
	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handlePostTasks is a RESTful alias for handleTaskAdd (POST /api/tasks).
func (s *Server) handlePostTasks(w http.ResponseWriter, r *http.Request) {
	s.handleTaskAdd(w, r)
}

// handlePutTask updates a task by ID (PUT /api/tasks/{id}).
func (s *Server) handlePutTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
		Status      string `json:"status"`
		DependsOn   *[]int `json:"depends_on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan", http.StatusNotFound)
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

	if t := strings.TrimSpace(req.Title); t != "" {
		task.Title = t
	}
	if req.Description != "" {
		task.Description = req.Description
	}
	if req.Priority > 0 {
		task.Priority = req.Priority
	}
	if req.DependsOn != nil {
		task.DependsOn = *req.DependsOn
	}
	if req.Status != "" {
		validStatuses := map[string]pm.TaskStatus{
			"pending":     pm.TaskPending,
			"in_progress": pm.TaskInProgress,
			"done":        pm.TaskDone,
			"skipped":     pm.TaskSkipped,
			"failed":      pm.TaskFailed,
		}
		if ns, ok := validStatuses[req.Status]; ok {
			task.Status = ns
		}
	}

	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "task": task})
}

// handleDeleteTask removes a task by ID (DELETE /api/tasks/{id}).
func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan", http.StatusNotFound)
		return
	}

	idx := -1
	for i, t := range ps.Plan.Tasks {
		if t.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		jsonErr(w, fmt.Sprintf("task %d not found", id), http.StatusNotFound)
		return
	}

	ps.Plan.Tasks = append(ps.Plan.Tasks[:idx], ps.Plan.Tasks[idx+1:]...)
	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleReorderTasks reassigns priorities from the given task ID order (POST /api/tasks/reorder).
func (s *Server) handleReorderTasks(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		IDs []int `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 {
		jsonErr(w, "ids is required", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan", http.StatusNotFound)
		return
	}

	taskMap := make(map[int]*pm.Task, len(ps.Plan.Tasks))
	for _, t := range ps.Plan.Tasks {
		taskMap[t.ID] = t
	}
	for i, id := range req.IDs {
		if t, ok := taskMap[id]; ok {
			t.Priority = i + 1
		}
	}

	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleLiveLog returns the current live log ring buffer and running status.
func (s *Server) handleLiveLog(w http.ResponseWriter, r *http.Request) {
	s.liveLogMu.Lock()
	lines := make([]string, len(s.liveLogLines))
	copy(lines, s.liveLogLines)
	running := s.liveLogRunning
	s.liveLogMu.Unlock()

	jsonOK(w, map[string]interface{}{
		"running": running,
		"lines":   lines,
	})
}

// handleSuggestRun triggers background suggest generation via `cloop suggest --yes`.
func (s *Server) handleSuggestRun(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Count <= 0 {
		req.Count = 5
	}
	if req.Count > 20 {
		req.Count = 20
	}

	s.suggestMu.Lock()
	if s.suggestRunning {
		s.suggestMu.Unlock()
		jsonErr(w, "suggest already running", http.StatusConflict)
		return
	}
	s.suggestRunning = true
	s.suggestDone = false
	s.suggestErr = ""
	s.suggestLog.Reset()
	s.suggestMu.Unlock()

	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}

	go func() {
		cmd := exec.Command(exe, "suggest", "--yes", "--count", strconv.Itoa(req.Count))
		cmd.Dir = s.WorkDir
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		runErr := cmd.Run()

		s.suggestMu.Lock()
		s.suggestRunning = false
		s.suggestDone = true
		_, _ = s.suggestLog.Write(buf.Bytes())
		if runErr != nil {
			s.suggestErr = runErr.Error()
		}
		s.suggestMu.Unlock()

		// Force SSE broadcast of updated state (new tasks were added).
		if ps, loadErr := state.Load(s.WorkDir); loadErr == nil {
			if data, marshalErr := json.Marshal(ps); marshalErr == nil {
				s.broadcast(string(data))
			}
		}
	}()

	jsonOK(w, map[string]interface{}{"ok": true, "count": req.Count})
}

// handleSuggestStatus returns the current suggest job status and output log.
func (s *Server) handleSuggestStatus(w http.ResponseWriter, r *http.Request) {
	s.suggestMu.Lock()
	running := s.suggestRunning
	done := s.suggestDone
	errMsg := s.suggestErr
	log := s.suggestLog.String()
	s.suggestMu.Unlock()

	jsonOK(w, map[string]interface{}{
		"running": running,
		"done":    done,
		"error":   errMsg,
		"log":     log,
	})
}

// handleInit initializes a new cloop project.
func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Goal         string `json:"goal"`
		Provider     string `json:"provider"`
		Model        string `json:"model"`
		Instructions string `json:"instructions"`
		MaxSteps     int    `json:"maxSteps"`
		PMMode       bool   `json:"pmMode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Goal = strings.TrimSpace(req.Goal)
	if req.Goal == "" {
		jsonErr(w, "goal is required", http.StatusBadRequest)
		return
	}

	ps, err := state.Init(s.WorkDir, req.Goal, req.MaxSteps)
	if err != nil {
		jsonErr(w, "init failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Instructions != "" {
		ps.Instructions = req.Instructions
	}
	if req.Model != "" {
		ps.Model = req.Model
	}
	if req.Provider != "" {
		ps.Provider = req.Provider
	}
	if req.PMMode {
		ps.PMMode = true
	}
	if err := ps.Save(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "goal": ps.Goal})
}

// handleVoice accepts a multipart audio upload, transcribes it with the local
// cloop listen command, and returns the transcription + resolved action.
// POST /api/voice   multipart field: "audio" (binary audio file)
// Optional query params: stt_provider, whisper_model, groq_api_key, dry_run=true
func (s *Server) handleVoice(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}

	// 32 MB max upload.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonErr(w, "parse multipart: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, fh, err := r.FormFile("audio")
	if err != nil {
		jsonErr(w, "audio field required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Write to a temp file.
	tmp, err := os.CreateTemp("", "cloop-voice-*-"+fh.Filename)
	if err != nil {
		jsonErr(w, "tmpfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		jsonErr(w, "write tmpfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmp.Close()

	// Build cloop listen args.
	// dry_run=false (or execute=true) means the resolved command is actually
	// executed; otherwise we default to --dry-run to just show the intent.
	dryRun := r.FormValue("execute") != "true" && r.FormValue("dry_run") != "false"
	listenArgs := []string{"listen", "--file", tmp.Name()}
	if dryRun {
		listenArgs = append(listenArgs, "--dry-run")
	}

	if v := r.FormValue("stt_provider"); v != "" {
		listenArgs = append(listenArgs, "--stt-provider", v)
	}
	if v := r.FormValue("whisper_model"); v != "" {
		listenArgs = append(listenArgs, "--whisper-model", v)
	}
	if v := r.FormValue("groq_api_key"); v != "" {
		listenArgs = append(listenArgs, "--groq-api-key", v)
	}

	// Run cloop listen via the installed binary. We capture stdout.
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	out, cmdErr := exec.Command(exe, listenArgs...).CombinedOutput()
	output := strings.TrimSpace(string(out))

	if cmdErr != nil {
		// Return a partial result with the output so the browser can display it.
		jsonOK(w, map[string]interface{}{
			"ok":     false,
			"output": output,
			"error":  cmdErr.Error(),
		})
		return
	}

	jsonOK(w, map[string]interface{}{
		"ok":     true,
		"output": output,
	})
}

// handleChatHistory returns the full chat conversation history as JSON.
// GET /api/chat/history
func (s *Server) handleChatHistory(w http.ResponseWriter, r *http.Request) {
	s.chatMu.Lock()
	h := make([]ChatMessage, len(s.chatHistory))
	copy(h, s.chatHistory)
	s.chatMu.Unlock()
	jsonOK(w, h)
}

// handleChat receives a natural-language message, attempts to execute it as a
// cloop command (via `cloop do`), and returns the result.
// POST /api/chat  {"message":"..."}
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Message) == "" {
		jsonErr(w, "message required", http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(req.Message)

	// Store user message.
	s.chatMu.Lock()
	s.chatHistory = append(s.chatHistory, ChatMessage{
		Role:      "user",
		Content:   msg,
		Timestamp: time.Now(),
	})
	s.chatMu.Unlock()

	// Run cloop do <message> to parse and execute the intent.
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	out, cmdErr := exec.Command(exe, "do", msg).CombinedOutput()
	output := strings.TrimSpace(string(out))

	ok := cmdErr == nil
	response := output
	if response == "" {
		if ok {
			response = "Command executed successfully."
		} else {
			response = "Failed: " + cmdErr.Error()
		}
	}

	// Store assistant message.
	s.chatMu.Lock()
	s.chatHistory = append(s.chatHistory, ChatMessage{
		Role:      "assistant",
		Content:   response,
		Timestamp: time.Now(),
	})
	s.chatMu.Unlock()

	jsonOK(w, map[string]interface{}{
		"ok":       ok,
		"response": response,
	})
}

// handleReset resets the project state by running `cloop reset`.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	out, err := exec.Command(exe, "reset").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		jsonErr(w, msg, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// ── multi-project handlers ────────────────────────────────────────────────────

// allProjectEntries returns the union of Projects flag paths + registry.
func (s *Server) allProjectEntries() []multiui.ProjectEntry {
	seen := make(map[string]bool)
	var entries []multiui.ProjectEntry

	// Always include current WorkDir as the "primary" project.
	if s.WorkDir != "" {
		abs, _ := filepath.Abs(s.WorkDir)
		if !seen[abs] {
			seen[abs] = true
			entries = append(entries, multiui.ProjectEntry{
				Name: filepath.Base(abs),
				Path: abs,
			})
		}
	}

	// Paths from --projects / --scan flags.
	for _, p := range s.Projects {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		entries = append(entries, multiui.ProjectEntry{
			Name: filepath.Base(abs),
			Path: abs,
		})
	}

	// Paths from persistent registry (~/.cloop/projects.json).
	registered, _ := multiui.Load()
	for _, e := range registered {
		abs, err := filepath.Abs(e.Path)
		if err != nil {
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		name := e.Name
		if name == "" {
			name = filepath.Base(abs)
		}
		entries = append(entries, multiui.ProjectEntry{Name: name, Path: abs})
	}

	return entries
}

// refreshProjectStatuses rebuilds the projStatuses cache from disk.
func (s *Server) refreshProjectStatuses() {
	entries := s.allProjectEntries()
	statuses := make([]multiui.ProjectStatus, 0, len(entries))
	for _, e := range entries {
		statuses = append(statuses, multiui.GetStatus(e))
	}
	s.projMu.Lock()
	s.projStatuses = statuses
	s.projMu.Unlock()
}

// watchProjects polls state files for all registered projects and broadcasts
// updates to SSE clients on change.
func (s *Server) watchProjects() {
	s.projLastMod = make(map[string]time.Time)
	s.refreshProjectStatuses()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		changed := false
		for _, e := range s.allProjectEntries() {
			statePath := filepath.Join(e.Path, ".cloop", "state.json")
			fi, err := os.Stat(statePath)
			if err != nil {
				// Also try state.db.
				statePath = filepath.Join(e.Path, ".cloop", "state.db")
				fi, err = os.Stat(statePath)
			}
			if err != nil {
				continue
			}
			prev := s.projLastMod[e.Path]
			if !fi.ModTime().Equal(prev) {
				s.projLastMod[e.Path] = fi.ModTime()
				changed = true
			}
		}
		if changed {
			s.refreshProjectStatuses()
			s.broadcastProjectsUpdate()
		}
	}
}

// broadcastProjectsUpdate sends the updated project statuses to SSE clients.
func (s *Server) broadcastProjectsUpdate() {
	s.projMu.RLock()
	statuses := s.projStatuses
	stats := multiui.Aggregate(statuses)
	s.projMu.RUnlock()

	payload, err := json.Marshal(map[string]interface{}{
		"projects": statuses,
		"stats":    stats,
	})
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- sseEvent{Event: "projects", Data: string(payload)}:
		default:
		}
	}
}

// handleProjects returns all project statuses and aggregate stats.
func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	s.refreshProjectStatuses()
	s.projMu.RLock()
	statuses := s.projStatuses
	stats := multiui.Aggregate(statuses)
	s.projMu.RUnlock()
	jsonOK(w, map[string]interface{}{
		"projects": statuses,
		"stats":    stats,
	})
}

// handleProjectsEvents is an SSE endpoint for multi-project updates.
func (s *Server) handleProjectsEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan sseEvent, 8)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	// Send current snapshot immediately.
	s.projMu.RLock()
	statuses := s.projStatuses
	stats := multiui.Aggregate(statuses)
	s.projMu.RUnlock()
	if payload, err := json.Marshal(map[string]interface{}{"projects": statuses, "stats": stats}); err == nil {
		fmt.Fprintf(w, "event: projects\ndata: %s\n\n", payload)
		flusher.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			if ev.Event == "projects" {
				fmt.Fprintf(w, "event: projects\ndata: %s\n\n", ev.Data)
				flusher.Flush()
			}
		}
	}
}

// handleProjectRun starts a `cloop run` in the specified project directory.
func (s *Server) handleProjectRun(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		jsonErr(w, "invalid project index", http.StatusBadRequest)
		return
	}
	entries := s.allProjectEntries()
	if idx < 0 || idx >= len(entries) {
		jsonErr(w, "project index out of range", http.StatusBadRequest)
		return
	}
	entry := entries[idx]

	var req struct {
		PM bool `json:"pm"`
	}
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	args := []string{"run"}
	if req.PM {
		args = append(args, "--pm")
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = entry.Path
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	go func() { _ = cmd.Wait() }()
	jsonOK(w, map[string]interface{}{"ok": true, "project": entry.Name, "command": strings.Join(args, " ")})
}

// handleProjectStop sends SIGINT to `cloop run` processes in the given project directory.
func (s *Server) handleProjectStop(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		jsonErr(w, "invalid project index", http.StatusBadRequest)
		return
	}
	entries := s.allProjectEntries()
	if idx < 0 || idx >= len(entries) {
		jsonErr(w, "project index out of range", http.StatusBadRequest)
		return
	}
	entry := entries[idx]
	// pkill processes running in that directory.
	out, err := exec.Command("pkill", "-SIGINT", "-f", "cloop run").CombinedOutput()
	_ = out
	if err != nil {
		jsonOK(w, map[string]interface{}{"ok": false, "project": entry.Name, "message": "no running process found"})
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "project": entry.Name})
}

// ── dashboard HTML ────────────────────────────────────────────────────────────

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cloop dashboard</title>
<style>
  :root {
    --bg:      #0d1117;
    --surface: #161b22;
    --border:  #30363d;
    --text:    #e6edf3;
    --muted:   #8b949e;
    --accent:  #58a6ff;
    --green:   #3fb950;
    --yellow:  #d29922;
    --red:     #f85149;
    --cyan:    #39c5cf;
    --purple:  #bc8cff;
    --radius:  8px;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }

  /* ── Layout ── */
  .layout { display: flex; flex-direction: column; min-height: 100vh; }
  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 10px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
    position: sticky;
    top: 0;
    z-index: 20;
    flex-wrap: wrap;
  }
  header h1 { font-size: 16px; font-weight: 700; color: var(--accent); white-space: nowrap; }
  header h1 span { color: var(--muted); font-weight: 400; }
  .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); flex-shrink: 0; transition: background .3s; }
  .live-dot.connected { background: var(--green); animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .spacer { flex: 1; min-width: 8px; }
  .updated-at { font-size: 11px; color: var(--muted); white-space: nowrap; }

  /* ── Tabs ── */
  .tab-nav { display: flex; gap: 2px; }
  .tab-btn {
    padding: 6px 14px;
    background: none;
    border: 1px solid transparent;
    border-radius: 6px;
    color: var(--muted);
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
  }
  .tab-btn:hover { color: var(--text); border-color: var(--border); }
  .tab-btn.active { color: var(--text); background: var(--bg); border-color: var(--border); }

  /* ── Main ── */
  main { flex: 1; padding: 24px; max-width: 1100px; margin: 0 auto; width: 100%; }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  /* ── Section ── */
  .section { margin-bottom: 24px; }
  .section-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); margin-bottom: 10px; }

  /* ── Card ── */
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 20px; }
  .goal-card { display: flex; align-items: flex-start; gap: 16px; }
  .goal-text { flex: 1; font-size: 15px; font-weight: 500; line-height: 1.4; }
  .goal-text.empty { color: var(--muted); font-style: italic; }

  /* ── Badge ── */
  .badge { display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; flex-shrink: 0; }
  .badge.running    { background:rgba(57,197,207,.15);  color:var(--cyan);   border:1px solid rgba(57,197,207,.3); }
  .badge.complete   { background:rgba(63,185,80,.15);   color:var(--green);  border:1px solid rgba(63,185,80,.3);  }
  .badge.failed     { background:rgba(248,81,73,.15);   color:var(--red);    border:1px solid rgba(248,81,73,.3);  }
  .badge.paused,
  .badge.initialized{ background:rgba(210,153,34,.15);  color:var(--yellow); border:1px solid rgba(210,153,34,.3); }
  .badge.evolving   { background:rgba(188,140,255,.15); color:var(--purple); border:1px solid rgba(188,140,255,.3);}
  .badge.unknown    { background:rgba(139,148,158,.15); color:var(--muted);  border:1px solid rgba(139,148,158,.3);}
  .badge-dot { width:5px; height:5px; border-radius:50%; background:currentColor; }
  .badge.running .badge-dot { animation: pulse 1.5s infinite; }
  .task-tags { display:inline-flex; flex-wrap:wrap; gap:3px; margin-left:4px; }
  .task-tag  { display:inline-block; padding:1px 6px; border-radius:10px; font-size:10px; font-weight:600; background:rgba(139,148,158,.15); color:var(--muted); border:1px solid rgba(139,148,158,.3); }

  /* ── Stats grid ── */
  .stats-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(140px,1fr)); gap:10px; }
  .stat-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:12px 14px; }
  .stat-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; margin-bottom:2px; }
  .stat-value { font-size:20px; font-weight:700; }
  .stat-value.accent { color:var(--accent); }
  .stat-sub { font-size:11px; color:var(--muted); margin-top:1px; }
  .token-bar { margin-top:6px; }
  .token-bar-track { height:3px; background:var(--border); border-radius:2px; overflow:hidden; }
  .token-bar-fill { height:100%; background:var(--accent); border-radius:2px; transition:width .5s; }

  /* ── Controls ── */
  .controls { display:flex; gap:8px; flex-wrap:wrap; align-items:flex-start; }
  .btn {
    display:inline-flex; align-items:center; gap:6px;
    padding:7px 13px; border-radius:var(--radius);
    border:1px solid var(--border); background:var(--surface);
    color:var(--text); font-size:13px; font-weight:500;
    cursor:pointer; transition:all .15s; text-decoration:none; white-space:nowrap;
  }
  .btn:hover { background:#21262d; border-color:#8b949e; }
  .btn.primary { background:var(--accent); color:#0d1117; border-color:var(--accent); }
  .btn.primary:hover { background:#79bcff; }
  .btn.danger  { color:var(--red);   border-color:rgba(248,81,73,.4); }
  .btn.danger:hover  { background:rgba(248,81,73,.1); border-color:var(--red); }
  .btn.success { color:var(--green); border-color:rgba(63,185,80,.4); }
  .btn.success:hover { background:rgba(63,185,80,.1); border-color:var(--green); }
  .btn.warn    { color:var(--yellow); border-color:rgba(210,153,34,.4); }
  .btn.warn:hover    { background:rgba(210,153,34,.1); border-color:var(--yellow); }
  .btn svg { width:13px; height:13px; }
  .btn:disabled { opacity:.4; cursor:not-allowed; }
  .btn.mic { color:var(--purple); border-color:rgba(188,140,255,.4); }
  .btn.mic:hover { background:rgba(188,140,255,.1); border-color:var(--purple); }
  .btn.mic.recording { color:var(--red); border-color:rgba(248,81,73,.4); animation: pulse 1s infinite; }

  /* ── Voice modal ── */
  .voice-modal-backdrop { position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:100; display:flex; align-items:center; justify-content:center; }
  .voice-modal { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:24px; width:480px; max-width:95vw; }
  .voice-modal h3 { margin-bottom:16px; font-size:15px; color:var(--accent); }
  .voice-modal .voice-status { font-size:13px; color:var(--muted); margin-bottom:12px; min-height:20px; }
  .voice-modal .voice-transcript { background:var(--bg); border:1px solid var(--border); border-radius:var(--radius); padding:10px; font-size:13px; min-height:40px; margin-bottom:12px; white-space:pre-wrap; }
  .voice-modal .voice-output { background:var(--bg); border:1px solid var(--border); border-radius:var(--radius); padding:10px; font-size:12px; font-family:monospace; min-height:60px; max-height:200px; overflow-y:auto; margin-bottom:12px; white-space:pre-wrap; }
  .voice-modal-btns { display:flex; gap:8px; justify-content:flex-end; }

  /* ── Advanced options (details) ── */
  details.advanced { margin-top:8px; }
  details.advanced summary {
    cursor:pointer; font-size:12px; color:var(--muted);
    user-select:none; list-style:none; display:flex; align-items:center; gap:5px;
  }
  details.advanced summary::-webkit-details-marker { display:none; }
  details.advanced summary::before { content:'▶'; font-size:9px; transition:transform .15s; }
  details.advanced[open] summary::before { transform:rotate(90deg); }
  .adv-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:8px; margin-top:10px; }
  .adv-label { font-size:12px; color:var(--muted); display:flex; align-items:center; gap:6px; cursor:pointer; }
  .adv-label input[type=checkbox] { accent-color:var(--accent); }
  .adv-row { display:flex; gap:8px; margin-top:8px; }

  /* ── Task list ── */
  .task-list { display:flex; flex-direction:column; gap:6px; }
  .task-item {
    display:flex; align-items:flex-start; gap:10px;
    padding:10px 14px; border:1px solid var(--border);
    border-radius:var(--radius); background:var(--surface);
  }
  .task-item.in_progress { border-color:var(--cyan); background:rgba(57,197,207,.05); }
  .task-item.done        { border-color:rgba(63,185,80,.3); }
  .task-item.failed      { border-color:rgba(248,81,73,.3); }
  .task-item.skipped     { opacity:.5; }
  .task-icon { font-size:15px; flex-shrink:0; margin-top:1px; }
  .task-body { flex:1; min-width:0; }
  .task-title { font-weight:500; font-size:13px; }
  .task-desc { font-size:12px; color:var(--muted); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .task-meta { font-size:11px; color:var(--muted); margin-top:3px; display:flex; gap:10px; }
  .task-priority { padding:1px 5px; border-radius:3px; font-size:11px; font-weight:600; }
  .task-priority.p1 { background:rgba(248,81,73,.15);   color:var(--red); }
  .task-priority.p2 { background:rgba(210,153,34,.15);  color:var(--yellow); }
  .task-priority.p3 { background:rgba(57,197,207,.15);  color:var(--cyan); }
  .task-actions { display:flex; gap:3px; flex-shrink:0; flex-wrap:wrap; justify-content:flex-end; align-items:center; max-width:220px; }
  .act { font-size:11px; padding:2px 6px; border-radius:3px; border:1px solid var(--border); background:none; color:var(--muted); cursor:pointer; white-space:nowrap; }
  .act:hover { background:#21262d; color:var(--text); }
  .act.done:hover   { color:var(--green);  border-color:var(--green); }
  .act.skip:hover   { color:var(--yellow); border-color:var(--yellow); }
  .act.fail:hover   { color:var(--red);    border-color:var(--red); }
  .act.reset:hover  { color:var(--accent); border-color:var(--accent); }
  .act.remove:hover { color:var(--red);    border-color:var(--red); }
  .act.edit:hover   { color:var(--accent); border-color:var(--accent); }

  /* ── Drag-and-drop ── */
  .task-item[draggable] { cursor: grab; }
  .task-item[draggable]:active { cursor: grabbing; }
  .task-item.dragging { opacity: .4; pointer-events: none; }
  .task-item.drag-over {
    border-color: var(--accent);
    background: rgba(88,166,255,.08);
    box-shadow: 0 0 0 1px rgba(88,166,255,.2);
  }
  .drag-handle {
    display: flex; align-items: center; padding: 0 4px 0 0;
    color: var(--muted); font-size: 14px; cursor: grab; flex-shrink: 0;
    opacity: 0.5; user-select: none;
  }
  .task-item:hover .drag-handle { opacity: 1; }

  /* ── Add task form ── */
  .add-task-bar { display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap; }
  .add-task-bar input { flex:1; min-width:160px; }

  /* ── Form elements ── */
  .form-input, .form-select, .form-textarea {
    background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
    color:var(--text); padding:7px 10px; font-size:13px; font-family:inherit;
  }
  .form-input:focus, .form-select:focus, .form-textarea:focus { outline:none; border-color:var(--accent); }
  .form-input  { width:100%; }
  .form-select { width:100%; appearance:none; background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%238b949e'/%3E%3C/svg%3E"); background-repeat:no-repeat; background-position:right 10px center; padding-right:28px; }
  .form-textarea { width:100%; resize:vertical; min-height:60px; }
  .form-group { margin-bottom:12px; }
  .form-label { font-size:12px; color:var(--muted); margin-bottom:4px; display:block; }
  .form-row { display:flex; gap:8px; }
  .form-row > * { flex:1; }

  /* ── Settings section ── */
  .settings-section { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px 20px; margin-bottom:12px; }
  .settings-section h3 { font-size:13px; font-weight:600; margin-bottom:12px; color:var(--text); display:flex; align-items:center; gap:8px; }
  .settings-section h3 .badge { font-size:10px; }
  .settings-save { margin-top:10px; }

  /* ── Step history ── */
  .step-list { display:flex; flex-direction:column; gap:5px; }
  .step-item { border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }
  .step-header { display:flex; align-items:center; gap:8px; padding:9px 12px; background:var(--surface); cursor:pointer; user-select:none; }
  .step-header:hover { background:#21262d; }
  .step-num { font-size:11px; color:var(--muted); font-weight:600; min-width:24px; flex-shrink:0; }
  .step-task { flex:1; font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .step-meta { font-size:11px; color:var(--muted); flex-shrink:0; display:flex; gap:8px; align-items:center; }
  .step-ok  { color:var(--green); }
  .step-bad { color:var(--red); }
  .step-chevron { color:var(--muted); transition:transform .2s; flex-shrink:0; font-size:9px; }
  .step-item.expanded .step-chevron { transform:rotate(90deg); }
  .step-output { display:none; background:#0d1117; border-top:1px solid var(--border); padding:10px 12px; font-family:monospace; font-size:11px; white-space:pre-wrap; word-break:break-all; max-height:360px; overflow-y:auto; color:#adbac7; }
  .step-item.expanded .step-output { display:block; }

  /* ── Live output panel ── */
  .live-output-wrap { margin-bottom: 24px; }
  .live-output-header { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
  .live-output-header .section-title { margin:0; }
  .live-output-clear { font-size:11px; color:var(--muted); background:none; border:none; cursor:pointer; padding:2px 6px; }
  .live-output-clear:hover { color:var(--text); }
  .live-output-box {
    background:#090d14;
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:12px 14px;
    font-family:'SF Mono','Consolas','Menlo',monospace;
    font-size:12px;
    line-height:1.6;
    white-space:pre-wrap;
    word-break:break-all;
    color:#cdd9e5;
    max-height:380px;
    overflow-y:auto;
    min-height:80px;
    position:relative;
  }
  .live-output-box:empty::before {
    content: 'No output yet. Start a run to see live output here.';
    color: var(--muted);
    font-style: italic;
    font-family: inherit;
  }
  .live-output-running .live-output-box {
    border-color: rgba(57,197,207,.35);
    box-shadow: 0 0 0 1px rgba(57,197,207,.1);
  }
  .live-cursor { display:inline-block; width:7px; height:13px; background:var(--cyan); vertical-align:text-bottom; animation:blink 1s step-end infinite; }
  @keyframes blink { 50%{opacity:0} }

  /* ── Suggest ── */
  .suggest-controls { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:12px; }
  .suggest-log { background:#0d1117; border:1px solid var(--border); border-radius:var(--radius); padding:12px; font-family:monospace; font-size:12px; white-space:pre-wrap; color:#adbac7; max-height:320px; overflow-y:auto; margin-top:10px; }
  .suggest-status { font-size:13px; color:var(--muted); display:flex; align-items:center; gap:8px; }
  .spinner { display:inline-block; width:12px; height:12px; border:2px solid var(--border); border-top-color:var(--accent); border-radius:50%; animation:spin .8s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }

  /* ── Empty state ── */
  .empty-state { text-align:center; padding:40px 20px; color:var(--muted); }
  .empty-state h3 { font-size:15px; margin-bottom:6px; }
  .empty-state p  { font-size:12px; }

  /* ── Init panel ── */
  .init-panel { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:24px; max-width:520px; margin:0 auto; }
  .init-panel h2 { font-size:16px; font-weight:600; margin-bottom:4px; }
  .init-panel p  { font-size:13px; color:var(--muted); margin-bottom:20px; }

  /* ── Modal ── */
  #modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.7); z-index:50; align-items:center; justify-content:center; }
  #modal-overlay.open { display:flex; }
  #modal { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:24px; width:440px; max-width:92vw; }
  #modal h2 { font-size:15px; font-weight:600; margin-bottom:16px; }
  .modal-footer { display:flex; gap:8px; justify-content:flex-end; margin-top:16px; }

  /* ── Toast ── */
  #toast { position:fixed; bottom:20px; right:20px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:9px 14px; font-size:13px; opacity:0; transform:translateY(8px); transition:all .2s; pointer-events:none; z-index:100; max-width:300px; }
  #toast.show { opacity:1; transform:translateY(0); }
  #toast.ok  { border-color:rgba(63,185,80,.5);  color:var(--green); }
  #toast.err { border-color:rgba(248,81,73,.5);  color:var(--red); }
  #toast.info{ border-color:rgba(88,166,255,.5); color:var(--accent); }

  /* ── Danger zone ── */
  .danger-zone { border-color:rgba(248,81,73,.3); }
  .danger-zone h3 { color:var(--red); }

  @media(max-width:600px){ main{padding:12px;} header{padding:8px 12px;} .stats-grid{grid-template-columns:repeat(2,1fr);} }

  /* ── Login modal ── */
  #loginOverlay {
    display: none;
    position: fixed; inset: 0; z-index: 1000;
    background: rgba(13,17,23,.85);
    backdrop-filter: blur(4px);
    align-items: center; justify-content: center;
  }
  #loginOverlay.visible { display: flex; }
  .login-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px 36px;
    width: 100%; max-width: 380px;
    display: flex; flex-direction: column; gap: 16px;
  }
  .login-box h2 { font-size: 16px; font-weight: 700; color: var(--text); }
  .login-box p  { font-size: 13px; color: var(--muted); line-height: 1.5; }
  .login-box input {
    width: 100%; padding: 9px 12px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; color: var(--text); font-size: 14px;
    font-family: monospace;
  }
  .login-box input:focus { outline: none; border-color: var(--accent); }
  .login-box button {
    padding: 9px 0; border-radius: 6px; border: none; cursor: pointer;
    background: var(--accent); color: #000; font-size: 14px; font-weight: 600;
  }
  .login-box button:hover { opacity: .85; }
  .login-error { font-size: 12px; color: var(--red); display: none; }
  .login-error.visible { display: block; }

  /* ── Project cards (multi-project tab) ── */
  .proj-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 18px;
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
  }
  .proj-card:hover { border-color: var(--accent); }
  .proj-health-dot {
    width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
  }
  .proj-health-dot.running  { background: var(--cyan); animation: pulse 1.5s infinite; }
  .proj-health-dot.stalled  { background: var(--yellow); }
  .proj-health-dot.failed   { background: var(--red); }
  .proj-health-dot.complete { background: var(--green); }
  .proj-health-dot.idle     { background: var(--muted); }
  .proj-health-dot.unknown  { background: var(--border); }
  .proj-name   { font-weight: 600; font-size: 14px; min-width: 120px; }
  .proj-goal   { flex: 1; font-size: 12px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 320px; }
  .proj-meta   { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
  .proj-progress-wrap { display: flex; align-items: center; gap: 6px; }
  .proj-progress-bar  { width: 80px; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .proj-progress-fill { height: 100%; background: var(--green); border-radius: 2px; transition: width .4s; }
  .proj-actions { display: flex; gap: 6px; flex-shrink: 0; }
  .proj-actions .btn { padding: 4px 10px; font-size: 12px; }

  /* ── Chat panel ── */
  .chat-layout {
    display: flex;
    flex-direction: column;
    height: calc(100vh - 120px);
    min-height: 400px;
  }
  .chat-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0;
    flex-wrap: wrap;
  }
  .chat-hint { font-size: 12px; color: var(--muted); }
  .chat-hint kbd {
    display: inline-block;
    padding: 1px 5px;
    border: 1px solid var(--border);
    border-radius: 3px;
    font-size: 11px;
    background: var(--surface);
    color: var(--text);
    font-family: inherit;
  }
  .chat-tts-label {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: var(--muted);
    cursor: pointer;
  }
  .chat-tts-label input { accent-color: var(--accent); }
  .chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 16px 0;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .chat-welcome {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 40px 20px;
    color: var(--muted);
    text-align: center;
  }
  .chat-welcome-icon { font-size: 32px; }
  .chat-welcome-title { font-size: 15px; font-weight: 600; color: var(--text); }
  .chat-welcome-text { font-size: 13px; line-height: 1.6; }
  .chat-welcome-text em { color: var(--accent); font-style: normal; font-family: monospace; }
  .chat-bubble-row {
    display: flex;
    gap: 10px;
    align-items: flex-start;
  }
  .chat-bubble-row.user { flex-direction: row-reverse; }
  .chat-avatar {
    width: 28px; height: 28px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700;
    flex-shrink: 0;
  }
  .chat-avatar.user      { background: var(--accent); color: #000; }
  .chat-avatar.assistant { background: var(--purple);  color: #000; }
  .chat-bubble {
    max-width: 72%;
    padding: 10px 14px;
    border-radius: var(--radius);
    font-size: 13px;
    line-height: 1.6;
    word-break: break-word;
    white-space: pre-wrap;
  }
  .chat-bubble.user      { background: rgba(88,166,255,.15); border: 1px solid rgba(88,166,255,.25); color: var(--text); }
  .chat-bubble.assistant { background: var(--surface);       border: 1px solid var(--border);        color: var(--text); }
  .chat-bubble.error     { background: rgba(248,81,73,.1);   border: 1px solid rgba(248,81,73,.3);   color: var(--red); }
  .chat-bubble-time { font-size: 10px; color: var(--muted); margin-top: 4px; }
  .chat-bubble-action {
    display: inline-block;
    margin-top: 6px;
    padding: 2px 8px;
    background: rgba(63,185,80,.1);
    border: 1px solid rgba(63,185,80,.25);
    border-radius: 10px;
    font-size: 11px;
    color: var(--green);
    font-family: monospace;
  }
  .chat-thinking {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--muted);
    font-size: 12px;
    padding: 6px 0;
  }
  .chat-input-bar {
    display: flex;
    gap: 8px;
    align-items: center;
    padding-top: 10px;
    border-top: 1px solid var(--border);
  }
  .chat-input { flex: 1; }
  .chat-mic-btn { flex-shrink: 0; padding: 7px 10px; }
  .chat-mic-btn.recording { color: var(--red); border-color: rgba(248,81,73,.4); animation: pulse 1s infinite; }
  .chat-voice-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 0 0;
    font-size: 13px;
    color: var(--muted);
  }
  .chat-voice-indicator { display: flex; align-items: center; gap: 6px; }
  .chat-tts-btn {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 11px;
    padding: 2px 5px;
    border-radius: 3px;
  }
  .chat-tts-btn:hover { color: var(--accent); background: rgba(88,166,255,.1); }
</style>
</head>
<body>

<!-- ── Login overlay ── -->
<div id="loginOverlay">
  <div class="login-box">
    <h2>cloop dashboard</h2>
    <p>This dashboard is protected. Enter the access token to continue.</p>
    <input type="password" id="loginTokenInput" placeholder="Access token" autocomplete="off"
           onkeydown="if(event.key==='Enter')submitLogin()">
    <div class="login-error" id="loginError">Invalid token. Please try again.</div>
    <button onclick="submitLogin()">Unlock</button>
  </div>
</div>

<div class="layout">
  <header>
    <h1>cloop <span>dashboard</span></h1>
    <div class="live-dot" id="liveDot"></div>
    <div class="tab-nav">
      <button class="tab-btn active" onclick="switchTab('overview')"  id="tbtn-overview">Overview</button>
      <button class="tab-btn"        onclick="switchTab('tasks')"     id="tbtn-tasks">Tasks</button>
      <button class="tab-btn"        onclick="switchTab('chat')"      id="tbtn-chat">Chat</button>
      <button class="tab-btn"        onclick="switchTab('projects')"  id="tbtn-projects">Projects</button>
      <button class="tab-btn"        onclick="switchTab('suggest')"   id="tbtn-suggest">Suggest</button>
      <button class="tab-btn"        onclick="switchTab('settings')"  id="tbtn-settings">Settings</button>
    </div>
    <div class="spacer"></div>
    <div class="updated-at" id="updatedAt"></div>
  </header>

  <main>
    <!-- ═══════════════════════════════════════════════════════════ OVERVIEW -->
    <div id="tab-overview" class="tab-panel active">

      <!-- No-project init panel -->
      <div id="initPanel" style="display:none">
        <div class="init-panel">
          <h2>Initialize a project</h2>
          <p>No cloop project found in this directory. Create one to get started.</p>
          <div class="form-group">
            <label class="form-label">Project goal *</label>
            <input class="form-input" id="initGoal" placeholder="e.g. Build a REST API with auth and user CRUD">
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Provider</label>
              <select class="form-select" id="initProvider">
                <option value="claudecode">claudecode (default)</option>
                <option value="anthropic">anthropic</option>
                <option value="openai">openai</option>
                <option value="ollama">ollama</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Max steps (0=unlimited)</label>
              <input class="form-input" id="initMaxSteps" type="number" min="0" value="0">
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Instructions / constraints (optional)</label>
            <textarea class="form-textarea" id="initInstructions" placeholder="e.g. Use Go, no external dependencies..."></textarea>
          </div>
          <label class="adv-label" style="margin-bottom:12px">
            <input type="checkbox" id="initPMMode"> Start in PM mode (decompose goal into tasks)
          </label>
          <br>
          <button class="btn primary" onclick="submitInit()">Initialize Project</button>
        </div>
      </div>

      <!-- Project overview -->
      <div id="projectPanel" style="display:none">

        <!-- Goal + status -->
        <div class="section">
          <div class="section-title">Project Goal</div>
          <div class="card goal-card">
            <div class="goal-text empty" id="goalText">Loading...</div>
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
              <div id="statusBadge"></div>
              <div id="healthBadge" style="display:none"></div>
            </div>
          </div>
        </div>

        <!-- Stats -->
        <div class="section">
          <div class="section-title">Overview</div>
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-label">Steps</div>
              <div class="stat-value accent" id="statSteps">—</div>
              <div class="stat-sub" id="statStepsSub"></div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Provider</div>
              <div class="stat-value" id="statProvider" style="font-size:13px;margin-top:4px">—</div>
              <div class="stat-sub" id="statModel"></div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Mode</div>
              <div class="stat-value" id="statMode" style="font-size:13px;margin-top:4px">—</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Tokens</div>
              <div class="stat-value accent" id="statTokens">0</div>
              <div class="stat-sub" id="statTokensSub"></div>
              <div class="token-bar" id="tokenBarWrap" style="display:none">
                <div class="token-bar-track"><div class="token-bar-fill" id="tokenBarFill" style="width:0%"></div></div>
              </div>
            </div>
            <div class="stat-card" id="statCostCard" style="display:none">
              <div class="stat-label">Est. Cost</div>
              <div class="stat-value" id="statCost" style="font-size:16px;margin-top:4px">—</div>
              <div class="stat-sub" id="statCostSub"></div>
            </div>
            <div class="stat-card" id="statHealthCard" style="display:none">
              <div class="stat-label">Plan Health</div>
              <div class="stat-value" id="statHealth" style="font-size:22px;margin-top:4px">—</div>
              <div class="stat-sub" id="statHealthSub"></div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Created</div>
              <div class="stat-value" id="statCreated" style="font-size:12px;margin-top:4px">—</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Updated</div>
              <div class="stat-value" id="statUpdated" style="font-size:12px;margin-top:4px">—</div>
            </div>
          </div>
        </div>

        <!-- Run controls -->
        <div class="section">
          <div class="section-title">Controls</div>
          <div class="controls">
            <button class="btn success" onclick="apiRun({})">
              <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0zm3.5 7.5l-5-3a.5.5 0 0 0-.75.43v6a.5.5 0 0 0 .75.43l5-3a.5.5 0 0 0 0-.86z"/></svg>
              Run
            </button>
            <button class="btn primary" onclick="apiRun({pm:true})">
              <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0zm3.5 7.5l-5-3a.5.5 0 0 0-.75.43v6a.5.5 0 0 0 .75.43l5-3a.5.5 0 0 0 0-.86z"/></svg>
              Run PM
            </button>
            <button class="btn danger" onclick="apiStop()">
              <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0zM5.5 5.5h5v5h-5z"/></svg>
              Pause / Stop
            </button>
            <button class="btn" onclick="refreshState()">
              <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2v1z"/><path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466z"/></svg>
              Refresh
            </button>
            <button class="btn mic" id="micBtn" onclick="openVoiceModal()" title="Voice command (cloop listen)">
              <svg viewBox="0 0 16 16" fill="currentColor"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/><path d="M3.5 6.5A.5.5 0 0 1 4 7v1a4 4 0 0 0 8 0V7a.5.5 0 0 1 1 0v1a5 5 0 0 1-4.5 4.975V15h2.5a.5.5 0 0 1 0 1h-6a.5.5 0 0 1 0-1H7.5v-2.025A5 5 0 0 1 3 8V7a.5.5 0 0 1 .5-.5z"/></svg>
              Voice
            </button>
          </div>
          <!-- Voice modal -->
          <div id="voiceModalBackdrop" class="voice-modal-backdrop" style="display:none">
            <div class="voice-modal">
              <h3>Voice Command</h3>
              <div class="voice-status" id="voiceStatus">Click Record to start recording...</div>
              <div class="voice-transcript" id="voiceTranscript" style="color:var(--muted)">Transcription will appear here</div>
              <div class="voice-output" id="voiceOutput" style="display:none"></div>
              <div class="voice-modal-btns">
                <button class="btn mic" id="voiceRecordBtn" onclick="toggleVoiceRecording()">
                  <svg viewBox="0 0 16 16" fill="currentColor"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/></svg>
                  Record
                </button>
                <button class="btn primary" id="voiceSendBtn" onclick="sendVoiceAudio()" disabled>
                  <svg viewBox="0 0 16 16" fill="currentColor"><path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11z"/></svg>
                  Execute
                </button>
                <button class="btn" onclick="closeVoiceModal()">Cancel</button>
              </div>
            </div>
          </div>
          <details class="advanced">
            <summary>Advanced run options</summary>
            <div class="adv-grid">
              <label class="adv-label"><input type="checkbox" id="optAutoEvolve"> --auto-evolve</label>
              <label class="adv-label"><input type="checkbox" id="optPlanOnly"> --plan-only</label>
              <label class="adv-label"><input type="checkbox" id="optRetryFailed"> --retry-failed</label>
              <label class="adv-label"><input type="checkbox" id="optInnovate"> --innovate</label>
              <label class="adv-label"><input type="checkbox" id="optDryRun"> --dry-run</label>
            </div>
            <div class="adv-row">
              <select class="form-select" id="optProvider" style="flex:1">
                <option value="">Provider (from config)</option>
                <option value="claudecode">claudecode</option>
                <option value="anthropic">anthropic</option>
                <option value="openai">openai</option>
                <option value="ollama">ollama</option>
              </select>
              <input class="form-input" id="optModel" placeholder="Model (optional)" style="flex:1">
            </div>
            <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
              <button class="btn success" onclick="apiRunAdv(false)">Run with options</button>
              <button class="btn primary" onclick="apiRunAdv(true)">Run PM with options</button>
            </div>
          </details>
        </div>

        <!-- Live Output panel -->
        <div class="live-output-wrap" id="liveOutputWrap">
          <div class="live-output-header">
            <div class="section-title">Live Output</div>
            <button class="live-output-clear" onclick="clearLiveLog()" title="Clear output">Clear</button>
          </div>
          <div class="live-output-box" id="liveOutputBox" role="log" aria-live="polite" aria-label="Live run output"></div>
        </div>

        <!-- Step history -->
        <div class="section">
          <div class="section-title">Step History</div>
          <div class="step-list" id="stepList">
            <div class="empty-state"><h3>No steps yet</h3><p>Start a run to see history here.</p></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ════════════════════════════════════════════════════════════ TASKS -->
    <div id="tab-tasks" class="tab-panel">
      <div class="section">
        <div class="section-title">Add Task</div>
        <div class="add-task-bar">
          <input class="form-input" id="newTaskTitle" placeholder="Task title..." style="flex:2;min-width:200px" onkeydown="if(event.key==='Enter')submitAddTask()">
          <input class="form-input" id="newTaskDesc"  placeholder="Description (optional)" style="flex:2;min-width:160px">
          <input class="form-input" id="newTaskPriority" placeholder="Priority (1=high)" type="number" min="1" style="flex:0 0 140px">
          <input class="form-input" id="newTaskDeps" placeholder="Depends on (IDs, e.g. 1,2)" style="flex:1;min-width:160px">
          <button class="btn primary" onclick="submitAddTask()">Add Task</button>
        </div>
      </div>
      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          Tasks <span id="taskCountBadge" style="color:var(--muted);font-weight:400;text-transform:none;letter-spacing:0"></span>
          <button id="toggleCompletedBtn" class="btn" style="margin-left:auto;padding:3px 10px;font-size:11px" onclick="toggleCompletedTasks()">Show completed</button>
        </div>
        <div class="task-list" id="taskListFull">
          <div class="empty-state"><h3>No tasks yet</h3><p>Add a task above, or run <code>cloop run --pm</code> to generate a task plan.</p></div>
        </div>
      </div>
    </div>

    <!-- ════════════════════════════════════════════════════════════ CHAT -->
    <div id="tab-chat" class="tab-panel">
      <div class="chat-layout">
        <div class="chat-header">
          <span class="section-title" style="margin:0">AI Chat</span>
          <span class="chat-hint">Type a command or question — or hold <kbd>Space</kbd> to talk</span>
          <div style="display:flex;gap:6px;align-items:center;margin-left:auto">
            <label class="chat-tts-label" title="Read responses aloud">
              <input type="checkbox" id="chatTtsToggle" onchange="toggleTTS(this.checked)"> TTS
            </label>
            <button class="btn" style="padding:4px 10px;font-size:12px" onclick="clearChatHistory()">Clear</button>
          </div>
        </div>
        <div class="chat-messages" id="chatMessages">
          <div class="chat-welcome">
            <div class="chat-welcome-icon">💬</div>
            <div class="chat-welcome-title">Chat with cloop</div>
            <div class="chat-welcome-text">Type a natural language command to control your project.<br>
            Examples: <em>"add a task to fix the login bug"</em>, <em>"start the run"</em>, <em>"show me task 3"</em>, <em>"pause"</em></div>
          </div>
        </div>
        <div class="chat-input-bar">
          <button class="btn mic chat-mic-btn" id="chatMicBtn" onclick="toggleChatVoice()" title="Hold Space or click to record voice command">
            <svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/><path d="M3.5 6.5A.5.5 0 0 1 4 7v1a4 4 0 0 0 8 0V7a.5.5 0 0 1 1 0v1a5 5 0 0 1-4.5 4.975V15h2.5a.5.5 0 0 1 0 1h-6a.5.5 0 0 1 0-1H7.5v-2.025A5 5 0 0 1 3 8V7a.5.5 0 0 1 .5-.5z"/></svg>
          </button>
          <input class="form-input chat-input" id="chatInput" placeholder="Ask anything or give a command..."
                 onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();submitChat();}">
          <button class="btn primary" onclick="submitChat()" style="flex-shrink:0">
            <svg viewBox="0 0 16 16" fill="currentColor" width="13" height="13"><path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11z"/></svg>
            Send
          </button>
        </div>
        <div class="chat-voice-bar" id="chatVoiceBar" style="display:none">
          <span class="chat-voice-indicator">
            <span class="live-dot connected" style="width:6px;height:6px"></span>
            Recording...
          </span>
          <button class="btn danger" style="padding:4px 10px;font-size:12px" onclick="stopChatVoice()">Stop &amp; Send</button>
          <button class="btn" style="padding:4px 10px;font-size:12px" onclick="cancelChatVoice()">Cancel</button>
        </div>
      </div>
    </div>

    <!-- ═══════════════════════════════════════════════════════════ SUGGEST -->
    <div id="tab-suggest" class="tab-panel">
      <div class="section">
        <div class="section-title">AI Feature Suggestions</div>
        <div class="card" style="margin-bottom:12px">
          <p style="font-size:13px;color:var(--muted);margin-bottom:12px">Generate AI-brainstormed feature ideas tailored to your project goal. Accepted suggestions are added as PM tasks automatically.</p>
          <div class="suggest-controls">
            <label class="form-label" style="margin:0;white-space:nowrap">Ideas to generate:</label>
            <input class="form-input" id="suggestCount" type="number" min="1" max="20" value="5" style="width:70px">
            <button class="btn primary" id="suggestBtn" onclick="runSuggest()">
              <svg viewBox="0 0 16 16" fill="currentColor" width="13" height="13"><path d="M8 1a.5.5 0 0 1 .5.5V6h4.5a.5.5 0 0 1 0 1H8.5v4.5a.5.5 0 0 1-1 0V7H3a.5.5 0 0 1 0-1h4.5V1.5A.5.5 0 0 1 8 1z"/></svg>
              Generate &amp; Add All
            </button>
          </div>
          <div id="suggestStatusLine" style="display:none" class="suggest-status">
            <span class="spinner" id="suggestSpinner"></span>
            <span id="suggestStatusText">Running...</span>
          </div>
        </div>
        <div id="suggestLogWrap" style="display:none">
          <div class="section-title">Output</div>
          <div class="suggest-log" id="suggestLogEl"></div>
        </div>
      </div>
    </div>

    <!-- ══════════════════════════════════════════════════════════ SETTINGS -->
    <div id="tab-settings" class="tab-panel">
      <div class="section">
        <div class="section-title">Configuration</div>

        <!-- Provider -->
        <div class="settings-section">
          <h3>Default Provider</h3>
          <div class="form-group">
            <label class="form-label">Active provider</label>
            <select class="form-select" id="cfgProvider">
              <option value="claudecode">claudecode</option>
              <option value="anthropic">anthropic</option>
              <option value="openai">openai</option>
              <option value="ollama">ollama</option>
            </select>
          </div>
          <button class="btn" onclick="saveConfigField('provider', document.getElementById('cfgProvider').value)">Save Provider</button>
        </div>

        <!-- ClaudeCode -->
        <div class="settings-section">
          <h3>ClaudeCode</h3>
          <div class="form-group">
            <label class="form-label">Model</label>
            <input class="form-input" id="cfgCCModel" placeholder="e.g. claude-opus-4-6">
          </div>
          <button class="btn settings-save" onclick="saveConfigField('claudecode.model', document.getElementById('cfgCCModel').value)">Save</button>
        </div>

        <!-- Anthropic -->
        <div class="settings-section">
          <h3>Anthropic <span id="anthropicKeyStatus"></span></h3>
          <div class="form-group">
            <label class="form-label">API Key (leave blank to keep existing)</label>
            <input class="form-input" id="cfgAnthropicKey" type="password" placeholder="sk-ant-...">
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Model</label>
              <input class="form-input" id="cfgAnthropicModel" placeholder="e.g. claude-opus-4-6">
            </div>
            <div class="form-group">
              <label class="form-label">Base URL (optional)</label>
              <input class="form-input" id="cfgAnthropicBase" placeholder="https://api.anthropic.com">
            </div>
          </div>
          <button class="btn settings-save" onclick="saveAnthropicCfg()">Save</button>
        </div>

        <!-- OpenAI -->
        <div class="settings-section">
          <h3>OpenAI <span id="openaiKeyStatus"></span></h3>
          <div class="form-group">
            <label class="form-label">API Key (leave blank to keep existing)</label>
            <input class="form-input" id="cfgOpenAIKey" type="password" placeholder="sk-...">
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Model</label>
              <input class="form-input" id="cfgOpenAIModel" placeholder="e.g. gpt-4o">
            </div>
            <div class="form-group">
              <label class="form-label">Base URL (optional)</label>
              <input class="form-input" id="cfgOpenAIBase" placeholder="https://api.openai.com/v1">
            </div>
          </div>
          <button class="btn settings-save" onclick="saveOpenAICfg()">Save</button>
        </div>

        <!-- Ollama -->
        <div class="settings-section">
          <h3>Ollama</h3>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Base URL</label>
              <input class="form-input" id="cfgOllamaBase" placeholder="http://localhost:11434">
            </div>
            <div class="form-group">
              <label class="form-label">Model</label>
              <input class="form-input" id="cfgOllamaModel" placeholder="e.g. llama3.2">
            </div>
          </div>
          <button class="btn settings-save" onclick="saveOllamaCfg()">Save</button>
        </div>

        <!-- Danger zone -->
        <div class="settings-section danger-zone">
          <h3>Danger Zone</h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Reset clears all step history and resets the project status. The goal and config are preserved.</p>
          <button class="btn danger" onclick="confirmReset()">Reset Project State</button>
        </div>
      </div>
    </div>

    <!-- ══════════════════════════════════════════════════════════ PROJECTS -->
    <div id="tab-projects" class="tab-panel">

      <!-- Aggregate stats bar -->
      <div class="section">
        <div class="section-title">All Projects</div>
        <div class="stats-grid" id="projAggStats">
          <div class="stat-card">
            <div class="stat-label">Projects</div>
            <div class="stat-value accent" id="paTotal">—</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Active Runs</div>
            <div class="stat-value" id="paActive" style="color:var(--cyan)">—</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Tasks</div>
            <div class="stat-value" id="paTasks">—</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Done Tasks</div>
            <div class="stat-value" id="paDone" style="color:var(--green)">—</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Failed Tasks</div>
            <div class="stat-value" id="paFailed" style="color:var(--red)">—</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Steps</div>
            <div class="stat-value" id="paSteps">—</div>
          </div>
        </div>
      </div>

      <!-- Project list -->
      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          Projects
          <button id="toggleCompletedProjectsBtn" class="btn" style="margin-left:auto;padding:3px 10px;font-size:11px" onclick="toggleCompletedProjects()">Show completed</button>
        </div>
        <div id="projListEmpty" style="display:none;color:var(--muted);font-size:13px;padding:12px 0">
          No projects loaded. Use <code>cloop ui --projects /path/a /path/b</code> or <code>--scan /root/Projects</code>.
        </div>
        <div id="projList" style="display:flex;flex-direction:column;gap:10px"></div>
      </div>

    </div>

  </main>
</div>

<!-- Delete confirmation modal -->
<div id="delete-modal-overlay" onclick="if(event.target===this)closeDeleteModal()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
  <div id="delete-modal" style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:400px;max-width:92vw">
    <h2 style="font-size:15px;font-weight:600;margin-bottom:10px;color:var(--red)">Delete Task</h2>
    <p id="deleteModalMsg" style="font-size:13px;color:var(--muted);margin-bottom:16px"></p>
    <div class="modal-footer">
      <button class="btn" onclick="closeDeleteModal()">Cancel</button>
      <button class="btn danger" onclick="executeDeleteTask()">Delete</button>
    </div>
  </div>
</div>

<!-- Edit task modal -->
<div id="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div id="modal">
    <h2 id="modalTitle">Edit Task</h2>
    <div class="form-group">
      <label class="form-label">Title *</label>
      <input class="form-input" id="modalTitle_" placeholder="Task title">
    </div>
    <div class="form-group">
      <label class="form-label">Description</label>
      <textarea class="form-textarea" id="modalDesc" placeholder="Optional description"></textarea>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Priority (1 = highest)</label>
        <input class="form-input" id="modalPriority" type="number" min="1">
      </div>
      <div class="form-group">
        <label class="form-label">Depends on (task IDs, e.g. 1,2)</label>
        <input class="form-input" id="modalDeps" placeholder="e.g. 1,2 or leave blank">
      </div>
    </div>
    <input type="hidden" id="modalTaskId">
    <div class="modal-footer">
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn primary" onclick="submitEditTask()">Save Changes</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
(function() {
'use strict';

let appState = null;
let evtSource = null;
let suggestPollTimer = null;
let activeTab = 'overview';
let showCompletedTasks    = false;
let showCompletedProjects = false;

// ── Auth token (stored in sessionStorage) ───────────────────────────────────
let authToken = sessionStorage.getItem('cloop_token') || '';

function authHeaders() {
  return authToken ? {'Authorization': 'Bearer ' + authToken} : {};
}

function showLoginModal() {
  document.getElementById('loginOverlay').classList.add('visible');
  setTimeout(() => document.getElementById('loginTokenInput').focus(), 50);
}

function hideLoginModal() {
  document.getElementById('loginOverlay').classList.remove('visible');
  document.getElementById('loginError').classList.remove('visible');
  document.getElementById('loginTokenInput').value = '';
}

window.submitLogin = function() {
  const input = document.getElementById('loginTokenInput');
  const token = input.value.trim();
  if (!token) return;
  // Test the token against the state endpoint.
  fetch('/api/state', {headers: {'Authorization': 'Bearer ' + token}}).then(r => {
    if (r.status === 401) {
      document.getElementById('loginError').classList.add('visible');
      input.select();
    } else {
      authToken = token;
      sessionStorage.setItem('cloop_token', token);
      hideLoginModal();
      connectSSE();
      refreshState();
    }
  }).catch(() => {
    document.getElementById('loginError').classList.add('visible');
  });
};

// ── Drag-and-drop state ──────────────────────────────────────────────────────
let dragSrcId = null;
let pendingDeleteId = null;

// ── Live output state ────────────────────────────────────────────────────────
let liveLogText = '';         // accumulated text for the panel
let liveLogAutoScroll = true; // whether to auto-scroll (user can disable by scrolling up)

// ── Tab switching ───────────────────────────────────────────────────────────

window.switchTab = function(name) {
  activeTab = name;
  document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  const panel = document.getElementById('tab-' + name);
  const btn   = document.getElementById('tbtn-' + name);
  if (panel) panel.classList.add('active');
  if (btn)   btn.classList.add('active');

  if (name === 'settings') loadConfig();
  if (name === 'tasks' && appState) renderTasks(appState);
  if (name === 'projects') loadProjects();
  if (name === 'chat') loadChatHistory();
};

// ── Helpers ─────────────────────────────────────────────────────────────────

// estimateCost returns estimated USD cost or null if the model is unknown.
// Returns 0 for local (ollama) providers. Prices are per 1M tokens.
function estimateCost(provider, model, inputTok, outputTok) {
  const p = (provider || '').toLowerCase();
  if (p === 'ollama') return 0;
  const m = (model || '').toLowerCase();
  // Pricing table: [inputPerM, outputPerM] in USD
  const prices = {
    'claude-opus-4-6':            [15.00, 75.00],
    'claude-opus-4-5':            [15.00, 75.00],
    'claude-sonnet-4-6':          [3.00,  15.00],
    'claude-sonnet-4-5':          [3.00,  15.00],
    'claude-haiku-4-5':           [0.80,  4.00],
    'claude-3-opus-20240229':     [15.00, 75.00],
    'claude-3-5-sonnet-20241022': [3.00,  15.00],
    'claude-3-5-haiku-20241022':  [0.80,  4.00],
    'claude-3-haiku-20240307':    [0.25,  1.25],
    'gpt-4o':                     [2.50,  10.00],
    'gpt-4o-mini':                [0.15,  0.60],
    'gpt-4-turbo':                [10.00, 30.00],
    'gpt-4':                      [30.00, 60.00],
    'gpt-3.5-turbo':              [0.50,  1.50],
    'o1':                         [15.00, 60.00],
    'o1-mini':                    [3.00,  12.00],
    'o3-mini':                    [1.10,  4.40],
    'gemini-1.5-pro':             [1.25,  5.00],
    'gemini-1.5-flash':           [0.075, 0.30],
    'llama3':                     [0,     0],
    'llama3.1':                   [0,     0],
    'llama3.2':                   [0,     0],
    'mistral':                    [0,     0],
    'mixtral':                    [0,     0],
  };
  // Exact match
  if (prices[m]) {
    const [inM, outM] = prices[m];
    return (inputTok / 1e6) * inM + (outputTok / 1e6) * outM;
  }
  // Prefix match (longest wins)
  let best = null, bestLen = 0;
  for (const key of Object.keys(prices)) {
    if (key.length > bestLen && m.startsWith(key)) {
      best = prices[key]; bestLen = key.length;
    }
  }
  if (best) {
    return (inputTok / 1e6) * best[0] + (outputTok / 1e6) * best[1];
  }
  // claudecode without explicit model: assume sonnet
  if (p === 'claudecode' || p === '') {
    const [inM, outM] = prices['claude-sonnet-4-6'];
    return (inputTok / 1e6) * inM + (outputTok / 1e6) * outM;
  }
  return null;
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString(undefined,{month:'short',day:'numeric'})+' '+
         d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});
}

function fmtNum(n) {
  if (!n) return '0';
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
  return String(n);
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'show ' + (type || '');
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = ''; }, 3000);
}

function api(url, body) {
  const ah = authHeaders();
  const opts = body !== undefined
    ? { method: 'POST', headers: Object.assign({'Content-Type':'application/json'}, ah), body: JSON.stringify(body) }
    : { method: 'GET',  headers: ah };
  return fetch(url, opts).then(r => {
    if (r.status === 401) { showLoginModal(); return Promise.reject(new Error('401')); }
    return r.json();
  });
}

function apiMethod(method, url, body) {
  const opts = { method, headers: authHeaders() };
  if (body !== null && body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(url, opts).then(r => {
    if (r.status === 401) { showLoginModal(); return Promise.reject(new Error('401')); }
    return r.json();
  });
}

function statusBadge(status) {
  const s = status || 'unknown';
  const labels = {running:'Running',complete:'Complete',failed:'Failed',
                  paused:'Paused',initialized:'Ready',evolving:'Evolving'};
  const label = labels[s] || s;
  return '<span class="badge '+esc(s)+'"><span class="badge-dot"></span>'+esc(label)+'</span>';
}

function taskIcon(status) {
  const icons = {pending:'◦',in_progress:'◎',done:'✓',failed:'✗',skipped:'⊘'};
  return icons[status] || '◦';
}

function priorityBadge(p) {
  const cls = p<=1?'p1':p<=3?'p2':'p3';
  return '<span class="task-priority '+cls+'">P'+p+'</span>';
}

// ── Render overview ─────────────────────────────────────────────────────────

function render(s) {
  appState = s;

  const hasProject = s && s.goal;
  document.getElementById('initPanel').style.display    = hasProject ? 'none' : '';
  document.getElementById('projectPanel').style.display = hasProject ? '' : 'none';
  if (!hasProject) return;

  // Goal
  const goalEl = document.getElementById('goalText');
  goalEl.textContent = s.goal;
  goalEl.classList.toggle('empty', !s.goal);

  // Status badge
  document.getElementById('statusBadge').innerHTML = statusBadge(s.status);

  // Stats
  const steps = (s.steps || []).length;
  document.getElementById('statSteps').textContent    = steps;
  document.getElementById('statStepsSub').textContent = s.max_steps > 0 ? 'of '+s.max_steps+' max' : 'unlimited';
  document.getElementById('statProvider').textContent = s.provider || 'claudecode';
  document.getElementById('statModel').textContent    = s.model || '';
  document.getElementById('statMode').textContent     = s.pm_mode ? 'Product Manager' : 'Feedback Loop';
  document.getElementById('statCreated').textContent  = fmtDate(s.created_at);
  document.getElementById('statUpdated').textContent  = fmtDate(s.updated_at);

  const ti = s.total_input_tokens || 0, to = s.total_output_tokens || 0;
  document.getElementById('statTokens').textContent    = fmtNum(ti + to);
  document.getElementById('statTokensSub').textContent = ti > 0 ? fmtNum(ti)+' in / '+fmtNum(to)+' out' : '';

  // Estimated cost
  const usd = estimateCost(s.provider || '', s.model || '', ti, to);
  const costCard = document.getElementById('statCostCard');
  if (usd !== null && (ti > 0 || to > 0)) {
    costCard.style.display = '';
    document.getElementById('statCost').textContent = usd === 0 ? '$0 (local)' : '$' + usd.toFixed(usd < 0.01 ? 4 : 2);
    document.getElementById('statCostSub').textContent = (s.provider || '') + (s.model ? ' / '+s.model : '');
  } else {
    costCard.style.display = 'none';
  }

  // Plan health score
  const hr = s.health_report;
  const healthCard = document.getElementById('statHealthCard');
  const healthBadge = document.getElementById('healthBadge');
  if (hr && typeof hr.score === 'number') {
    healthCard.style.display = '';
    const score = hr.score;
    const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
    const col = score >= 75 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';
    document.getElementById('statHealth').innerHTML =
      '<span style="color:'+col+'">' + score + '</span>' +
      '<span style="font-size:13px;color:var(--muted);margin-left:4px">/ 100</span>';
    document.getElementById('statHealthSub').innerHTML =
      '<span style="color:'+col+'">Grade: ' + grade + '</span>';
    // Header badge
    healthBadge.style.display = '';
    healthBadge.innerHTML =
      '<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:12px;' +
      'border:1px solid '+col+';font-size:12px;font-weight:600;color:'+col+'">'+
      '&#10003; Health ' + score + '/100</span>';
    if (hr.issues && hr.issues.length) {
      healthBadge.title = hr.issues.slice(0, 3).join('\n');
    }
  } else {
    healthCard.style.display = 'none';
    healthBadge.style.display = 'none';
  }

  // Steps
  const stepListEl = document.getElementById('stepList');
  const allSteps = s.steps || [];
  if (!allSteps.length) {
    stepListEl.innerHTML = '<div class="empty-state"><h3>No steps yet</h3><p>Start a run to see history here.</p></div>';
  } else {
    const expanded = {};
    stepListEl.querySelectorAll('.step-item.expanded').forEach(el => { expanded[el.dataset.idx] = true; });
    const reversed = [...allSteps].reverse();
    stepListEl.innerHTML = reversed.map((st, i) => {
      const idx = allSteps.length - 1 - i;
      const isExp = expanded[idx] ? ' expanded' : '';
      const exitCls = st.exit_code === 0 ? 'step-ok' : 'step-bad';
      return '<div class="step-item'+isExp+'" data-idx="'+idx+'" onclick="toggleStep(this)">'+
        '<div class="step-header">'+
          '<span class="step-num">#'+(st.step+1)+'</span>'+
          '<span class="step-task">'+esc(st.task||'(no description)')+'</span>'+
          '<div class="step-meta">'+
            (st.duration?'<span>'+esc(st.duration)+'</span>':'')+
            '<span class="'+exitCls+'">'+(st.exit_code===0?'OK':'exit '+st.exit_code)+'</span>'+
            (st.output_tokens?'<span>'+fmtNum(st.output_tokens)+' tok</span>':'')+
          '</div>'+
          '<span class="step-chevron">&#9654;</span>'+
        '</div>'+
        '<div class="step-output">'+esc(st.output||'')+'</div>'+
      '</div>';
    }).join('');
  }

  // Tasks tab
  if (activeTab === 'tasks') renderTasks(s);

  document.getElementById('updatedAt').textContent = s.updated_at ? fmtDate(s.updated_at) : '';

  // Update live output running indicator.
  renderLiveLog();
}

window.toggleStep = function(el) { el.classList.toggle('expanded'); };

// ── Render tasks tab ─────────────────────────────────────────────────────────

window.toggleCompletedTasks = function() {
  showCompletedTasks = !showCompletedTasks;
  const btn = document.getElementById('toggleCompletedBtn');
  if (btn) btn.textContent = showCompletedTasks ? 'Hide completed' : 'Show completed';
  if (appState) renderTasks(appState);
};

function renderTasks(s) {
  const container = document.getElementById('taskListFull');
  const badge     = document.getElementById('taskCountBadge');
  if (!s || !s.plan || !s.plan.tasks || !s.plan.tasks.length) {
    badge.textContent = '';
    container.innerHTML = '<div class="empty-state"><h3>No tasks yet</h3><p>Add a task above, or run <code>cloop run --pm</code> to generate a task plan.</p></div>';
    return;
  }
  const sorted = [...s.plan.tasks].sort((a,b) => a.priority - b.priority);
  const done    = sorted.filter(t => t.status==='done').length;
  const hidden  = ['done', 'skipped', 'failed', 'timed_out'];
  const visible = showCompletedTasks ? sorted : sorted.filter(t => !hidden.includes(t.status || 'pending'));
  const hiddenCount = sorted.length - visible.length;
  badge.textContent = '(' + done + '/' + sorted.length + ' done' + (hiddenCount > 0 && !showCompletedTasks ? ', ' + hiddenCount + ' hidden' : '') + ')';

  if (!visible.length) {
    container.innerHTML = '<div class="empty-state"><h3>All tasks completed</h3><p>Click <strong>Show completed</strong> to view all tasks.</p></div>';
    return;
  }

  container.innerHTML = visible.map(t => {
    const cls = t.status || 'pending';
    const statusActions = buildStatusActions(t);
    const tid = t.id;
    return '<div class="task-item '+esc(cls)+'" draggable="true" data-task-id="'+tid+'" '+
      'ondragstart="onDragStart(event,'+tid+')" '+
      'ondragover="onDragOver(event,'+tid+')" '+
      'ondragleave="onDragLeave(event)" '+
      'ondrop="onDrop(event,'+tid+')" '+
      'ondragend="onDragEnd(event)">'+
      '<div class="drag-handle" title="Drag to reorder">&#8597;</div>'+
      '<div class="task-icon">'+taskIcon(cls)+'</div>'+
      '<div class="task-body">'+
        '<div class="task-title">'+esc(t.title)+'</div>'+
        (t.description ? '<div class="task-desc">'+esc(t.description)+'</div>' : '')+
        '<div class="task-meta">'+
          '<span>'+esc(cls)+'</span>'+
          (t.role?'<span>'+esc(t.role)+'</span>':'')+
          (t.depends_on&&t.depends_on.length?'<span>deps: #'+t.depends_on.join(', #')+'</span>':'')+
          (t.tags&&t.tags.length?'<span class="task-tags">'+t.tags.map(function(tg){return '<span class="task-tag">'+esc(tg)+'</span>';}).join('')+'</span>':'')+
          fmtTimeEstimate(t)+
        '</div>'+
      '</div>'+
      '<div class="task-actions">'+
        statusActions+
        '<button class="act edit"   title="Edit"   onclick="openEditModal('+tid+','+
          JSON.stringify(t.title).replace(/</g,'\\u003c')+','+
          JSON.stringify(t.description||'').replace(/</g,'\\u003c')+','+
          t.priority+','+
          JSON.stringify(t.depends_on||[]).replace(/</g,'\\u003c')+')">Edit</button>'+
        '<button class="act remove" title="Remove" onclick="removeTask('+tid+')">Remove</button>'+
        priorityBadge(t.priority)+
        '<span style="font-size:11px;color:var(--muted)">#'+tid+'</span>'+
      '</div>'+
    '</div>';
  }).join('');
}

function fmtTimeEstimate(t) {
  const est = t.estimated_minutes || 0;
  const act = t.actual_minutes || 0;
  if (!est && !act) return '';
  let s = '';
  if (est > 0) s += 'est: ' + est + 'm';
  if (act > 0) {
    if (s) s += ' / ';
    s += 'actual: ' + act + 'm';
    if (est > 0) {
      const variance = Math.round((act - est) / est * 100);
      const sign = variance >= 0 ? '+' : '';
      s += ' (' + sign + variance + '%)';
    }
  }
  return '<span title="Time estimate vs actual">⏱ ' + s + '</span>';
}

function buildStatusActions(t) {
  const cls = t.status || 'pending';
  let btns = '';
  if (cls !== 'done')        btns += '<button class="act done"  onclick="setStatus('+t.id+',\'done\')">Done</button>';
  if (cls !== 'skipped')     btns += '<button class="act skip"  onclick="setStatus('+t.id+',\'skipped\')">Skip</button>';
  if (cls !== 'failed')      btns += '<button class="act fail"  onclick="setStatus('+t.id+',\'failed\')">Fail</button>';
  if (cls !== 'pending')     btns += '<button class="act reset" onclick="setStatus('+t.id+',\'pending\')">Reset</button>';
  return btns;
}

// ── Live output ──────────────────────────────────────────────────────────────

function appendLiveLog(chunk) {
  liveLogText += chunk;
  // Keep at most ~liveLogMaxLines worth of content (trimmed from top).
  const lines = liveLogText.split('\n');
  if (lines.length > 500) {
    liveLogText = lines.slice(lines.length - 500).join('\n');
  }
  renderLiveLog();
}

function renderLiveLog() {
  const box = document.getElementById('liveOutputBox');
  if (!box) return;
  // Use a text node for safe rendering of raw output.
  box.textContent = liveLogText;
  // Blinking cursor appended when running.
  const wrap = document.getElementById('liveOutputWrap');
  const isRunning = appState && appState.status === 'running';
  if (wrap) wrap.classList.toggle('live-output-running', isRunning);
  if (isRunning) {
    const cur = document.createElement('span');
    cur.className = 'live-cursor';
    cur.setAttribute('aria-hidden', 'true');
    box.appendChild(cur);
  }
  if (liveLogAutoScroll) {
    box.scrollTop = box.scrollHeight;
  }
}

window.clearLiveLog = function() {
  liveLogText = '';
  renderLiveLog();
};

// ── SSE ─────────────────────────────────────────────────────────────────────

function connectSSE() {
  if (evtSource) evtSource.close();
  const sseUrl = authToken ? '/api/events?token=' + encodeURIComponent(authToken) : '/api/events';
  evtSource = new EventSource(sseUrl);
  const dot = document.getElementById('liveDot');
  evtSource.onopen = () => {
    dot.classList.add('connected');
    // On reconnect, fetch current live log buffer.
    api('/api/livelog').then(d => {
      if (d.lines && d.lines.length) {
        liveLogText = d.lines.join('');
        renderLiveLog();
      }
    }).catch(() => {});
  };
  evtSource.onmessage = (e) => {
    try { render(JSON.parse(e.data)); } catch(_) {}
  };
  evtSource.addEventListener('log', (e) => {
    try {
      const d = JSON.parse(e.data);
      if (d.chunk) appendLiveLog(d.chunk);
    } catch(_) {}
  });
  evtSource.addEventListener('projects', (e) => {
    try {
      const d = JSON.parse(e.data);
      renderProjects(d.projects || [], d.stats || {});
    } catch(_) {}
  });
  evtSource.onerror = () => {
    dot.classList.remove('connected');
    evtSource.close();
    evtSource = null;
    // Probe the state endpoint to distinguish 401 from network error.
    fetch('/api/state', {headers: authHeaders()}).then(r => {
      if (r.status === 401) {
        showLoginModal();
      } else {
        setTimeout(connectSSE, 3000);
      }
    }).catch(() => setTimeout(connectSSE, 3000));
  };
}

// Track user scroll in live output to disable auto-scroll when they scroll up.
document.addEventListener('DOMContentLoaded', () => {
  const box = document.getElementById('liveOutputBox');
  if (box) {
    box.addEventListener('scroll', () => {
      const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
      liveLogAutoScroll = atBottom;
    });
  }
});

// ── Projects tab ─────────────────────────────────────────────────────────────

function loadProjects() {
  api('/api/projects').then(d => {
    renderProjects(d.projects || [], d.stats || {});
  }).catch(() => {});
}

window.toggleCompletedProjects = function() {
  showCompletedProjects = !showCompletedProjects;
  const btn = document.getElementById('toggleCompletedProjectsBtn');
  if (btn) btn.textContent = showCompletedProjects ? 'Hide completed' : 'Show completed';
  // Re-render with cached state.
  if (window._lastProjectsData) renderProjects(window._lastProjectsData.projects, window._lastProjectsData.stats);
};

function renderProjects(projects, stats) {
  window._lastProjectsData = {projects, stats};
  // Update aggregate stats.
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v === undefined ? '—' : v; };
  set('paTotal',  stats.total_projects  ?? projects.length);
  set('paActive', stats.active_runs     ?? 0);
  set('paTasks',  stats.total_tasks     ?? 0);
  set('paDone',   stats.done_tasks      ?? 0);
  set('paFailed', stats.failed_tasks    ?? 0);
  set('paSteps',  stats.total_steps     ?? 0);

  const list  = document.getElementById('projList');
  const empty = document.getElementById('projListEmpty');
  if (!list) return;

  if (!projects.length) {
    empty.style.display = '';
    list.innerHTML = '';
    return;
  }
  empty.style.display = 'none';

  // Filter out fully-completed projects unless toggle is on; preserve original index for API calls.
  const isCompleted = p => p.pm_mode && p.total_tasks > 0 && p.done_tasks >= p.total_tasks;
  const indexed  = projects.map((p, i) => ({p, i}));
  const visibleI = showCompletedProjects ? indexed : indexed.filter(({p}) => !isCompleted(p));
  const hiddenCount = projects.length - visibleI.length;
  const btn = document.getElementById('toggleCompletedProjectsBtn');
  if (btn && hiddenCount > 0 && !showCompletedProjects) {
    btn.textContent = 'Show completed (' + hiddenCount + ')';
  } else if (btn) {
    btn.textContent = showCompletedProjects ? 'Hide completed' : 'Show completed';
  }

  if (!visibleI.length) {
    list.innerHTML = '<div class="empty-state" style="padding:16px 0"><h3>All projects completed</h3><p>Click <strong>Show completed</strong> to view them.</p></div>';
    return;
  }

  list.innerHTML = visibleI.map(({p, i: idx}) => {
    const health = p.health || 'unknown';
    const pct    = p.total_tasks > 0 ? Math.round(p.done_tasks / p.total_tasks * 100) : 0;
    const goal   = p.goal ? esc(p.goal.substring(0, 80)) : '<em style="color:var(--muted)">no goal set</em>';
    const lastAct = p.last_activity ? relTime(new Date(p.last_activity)) : '—';
    const taskInfo = p.pm_mode
      ? p.done_tasks + '/' + p.total_tasks + ' tasks'
      : (p.total_steps ? p.total_steps + ' steps' : 'no steps');
    return ` + "`" + `
      <div class="proj-card">
        <div class="proj-health-dot ${health}"></div>
        <div class="proj-name">${esc(p.name)}</div>
        <div class="proj-goal" title="${esc(p.goal || '')}">${goal}</div>
        <div class="proj-meta">
          <span class="badge ${health}" style="font-size:10px">${health}</span>
          ${p.pm_mode ? ` + "`" + `<div class="proj-progress-wrap"><div class="proj-progress-bar"><div class="proj-progress-fill" style="width:${pct}%"></div></div><span>${pct}%</span></div>` + "`" + ` : ''}
          <span>${taskInfo}</span>
          <span title="last activity">${lastAct}</span>
          ${p.provider ? ` + "`" + `<span>${esc(p.provider)}</span>` + "`" + ` : ''}
        </div>
        <div class="proj-actions">
          <button class="btn success" onclick="projectRun(${idx},false)" title="Run">&#9654; Run</button>
          <button class="btn primary"  onclick="projectRun(${idx},true)"  title="Run PM">&#9654; PM</button>
          <button class="btn danger"   onclick="projectStop(${idx})"     title="Stop">&#9632; Stop</button>
        </div>
      </div>
    ` + "`" + `;
  }).join('');
}

function relTime(date) {
  const diff = Date.now() - date.getTime();
  if (diff < 60000)  return 'just now';
  if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff/3600000) + 'h ago';
  return Math.floor(diff/86400000) + 'd ago';
}

window.projectRun = function(idx, pm) {
  api('/api/projects/' + idx + '/run', {method:'POST', body: JSON.stringify({pm})})
    .then(() => { toast('Run started', 'ok'); setTimeout(loadProjects, 800); })
    .catch(() => toast('Failed to start run', 'err'));
};

window.projectStop = function(idx) {
  api('/api/projects/' + idx + '/stop', {method:'POST'})
    .then(d => { toast(d.ok ? 'Stopped' : 'Nothing running', d.ok ? 'ok' : 'err'); setTimeout(loadProjects, 800); })
    .catch(() => toast('Failed to stop', 'err'));
};

// ── Actions ─────────────────────────────────────────────────────────────────

window.refreshState = function() {
  api('/api/state').then(s => { render(s); toast('Refreshed', 'ok'); }).catch(() => toast('Load failed', 'err'));
};

window.apiRun = function(opts) {
  api('/api/run', opts).then(d => {
    if (d.ok) toast('Started: '+d.command, 'ok');
    else toast(d.error||'Failed to start', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.apiRunAdv = function(pm) {
  const opts = {
    pm:          pm,
    autoEvolve:  document.getElementById('optAutoEvolve').checked,
    planOnly:    document.getElementById('optPlanOnly').checked,
    retryFailed: document.getElementById('optRetryFailed').checked,
    innovate:    document.getElementById('optInnovate').checked,
    dryRun:      document.getElementById('optDryRun').checked,
    provider:    document.getElementById('optProvider').value,
    model:       document.getElementById('optModel').value.trim(),
  };
  api('/api/run', opts).then(d => {
    if (d.ok) toast('Started: '+d.command, 'ok');
    else toast(d.error||'Failed to start', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.apiStop = function() {
  api('/api/stop', {}).then(d => {
    toast(d.message || (d.ok ? 'Pause signal sent' : 'Stop failed'), d.ok ? 'ok' : 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Init ─────────────────────────────────────────────────────────────────────

window.submitInit = function() {
  const goal = document.getElementById('initGoal').value.trim();
  if (!goal) { toast('Goal is required', 'err'); return; }
  api('/api/init', {
    goal:         goal,
    provider:     document.getElementById('initProvider').value,
    maxSteps:     parseInt(document.getElementById('initMaxSteps').value)||0,
    instructions: document.getElementById('initInstructions').value.trim(),
    pmMode:       document.getElementById('initPMMode').checked,
  }).then(d => {
    if (d.ok) { toast('Project initialized!', 'ok'); refreshState(); }
    else toast(d.error||'Init failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Task CRUD ────────────────────────────────────────────────────────────────

function parseDepsInput(val) {
  if (!val || !val.trim()) return [];
  return val.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n > 0);
}

window.submitAddTask = function() {
  const title = document.getElementById('newTaskTitle').value.trim();
  if (!title) { toast('Title is required', 'err'); return; }
  api('/api/task/add', {
    title:       title,
    description: document.getElementById('newTaskDesc').value.trim(),
    priority:    parseInt(document.getElementById('newTaskPriority').value)||0,
    depends_on:  parseDepsInput(document.getElementById('newTaskDeps').value),
  }).then(d => {
    if (d.ok) {
      document.getElementById('newTaskTitle').value    = '';
      document.getElementById('newTaskDesc').value     = '';
      document.getElementById('newTaskPriority').value = '';
      document.getElementById('newTaskDeps').value     = '';
      toast('Task added: '+title, 'ok');
      refreshState();
    } else toast(d.error||'Add failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.setStatus = function(id, status) {
  api('/api/task/status', {id, status}).then(d => {
    if (d.ok) { toast('Task '+id+': '+status, 'ok'); refreshState(); }
    else toast(d.error||'Update failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.moveTask = function(id, direction) {
  api('/api/task/move', {id, direction}).then(d => {
    if (d.ok) { refreshState(); }
    else toast(d.error||'Move failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.removeTask = function(id) {
  pendingDeleteId = id;
  const task = appState && appState.plan && appState.plan.tasks
    ? appState.plan.tasks.find(t => t.id === id) : null;
  const title = task ? task.title : '#' + id;
  document.getElementById('deleteModalMsg').textContent =
    'Delete task "' + title + '"? This action cannot be undone.';
  const overlay = document.getElementById('delete-modal-overlay');
  overlay.style.display = 'flex';
};

window.closeDeleteModal = function() {
  document.getElementById('delete-modal-overlay').style.display = 'none';
  pendingDeleteId = null;
};

window.executeDeleteTask = function() {
  const id = pendingDeleteId;
  closeDeleteModal();
  if (!id) return;
  apiMethod('DELETE', '/api/tasks/' + id, null).then(d => {
    if (d.ok) { toast('Task #' + id + ' removed', 'ok'); refreshState(); }
    else toast(d.error || 'Remove failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Drag-and-drop handlers ───────────────────────────────────────────────────

window.onDragStart = function(e, id) {
  dragSrcId = id;
  e.dataTransfer.effectAllowed = 'move';
  // Use setTimeout so the class is applied after browser snapshot
  setTimeout(() => {
    const el = document.querySelector('.task-item[data-task-id="'+id+'"]');
    if (el) el.classList.add('dragging');
  }, 0);
};

window.onDragOver = function(e, id) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  document.querySelectorAll('.task-item').forEach(el => el.classList.remove('drag-over'));
  const el = document.querySelector('.task-item[data-task-id="'+id+'"]');
  if (el && id !== dragSrcId) el.classList.add('drag-over');
};

window.onDragLeave = function(e) {
  e.currentTarget.classList.remove('drag-over');
};

window.onDrop = function(e, targetId) {
  e.preventDefault();
  document.querySelectorAll('.task-item').forEach(el => el.classList.remove('drag-over', 'dragging'));
  if (dragSrcId === null || dragSrcId === targetId) { dragSrcId = null; return; }
  if (!appState || !appState.plan || !appState.plan.tasks) { dragSrcId = null; return; }

  const sorted = [...appState.plan.tasks].sort((a,b) => a.priority - b.priority);
  const ids = sorted.map(t => t.id);
  const fromIdx = ids.indexOf(dragSrcId);
  const toIdx   = ids.indexOf(targetId);
  if (fromIdx === -1 || toIdx === -1) { dragSrcId = null; return; }

  ids.splice(fromIdx, 1);
  ids.splice(toIdx, 0, dragSrcId);
  dragSrcId = null;

  apiMethod('POST', '/api/tasks/reorder', {ids}).then(d => {
    if (d.ok) refreshState();
    else toast(d.error || 'Reorder failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.onDragEnd = function(e) {
  document.querySelectorAll('.task-item').forEach(el => el.classList.remove('dragging', 'drag-over'));
  dragSrcId = null;
};

// ── Edit modal ───────────────────────────────────────────────────────────────

window.openEditModal = function(id, title, desc, priority, dependsOn) {
  document.getElementById('modalTaskId').value   = id;
  document.getElementById('modalTitle_').value   = title;
  document.getElementById('modalDesc').value     = desc;
  document.getElementById('modalPriority').value = priority;
  document.getElementById('modalDeps').value     = (dependsOn && dependsOn.length) ? dependsOn.join(',') : '';
  document.getElementById('modal-overlay').classList.add('open');
  document.getElementById('modalTitle_').focus();
};

window.closeModal = function() {
  document.getElementById('modal-overlay').classList.remove('open');
};

window.submitEditTask = function() {
  const id       = parseInt(document.getElementById('modalTaskId').value);
  const title    = document.getElementById('modalTitle_').value.trim();
  const desc     = document.getElementById('modalDesc').value.trim();
  const priority = parseInt(document.getElementById('modalPriority').value)||0;
  if (!title) { toast('Title is required', 'err'); return; }

  api('/api/task/edit', {
    id,
    title,
    description: desc,
    priority,
    depends_on: parseDepsInput(document.getElementById('modalDeps').value),
  }).then(d => {
    if (d.ok) { closeModal(); toast('Task updated', 'ok'); refreshState(); }
    else toast(d.error||'Edit failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Suggest ──────────────────────────────────────────────────────────────────

window.runSuggest = function() {
  const count = parseInt(document.getElementById('suggestCount').value)||5;
  document.getElementById('suggestBtn').disabled = true;
  document.getElementById('suggestStatusLine').style.display = '';
  document.getElementById('suggestSpinner').style.display    = '';
  document.getElementById('suggestStatusText').textContent   = 'Generating '+count+' ideas with AI...';
  document.getElementById('suggestLogWrap').style.display    = 'none';

  api('/api/suggest/run', {count}).then(d => {
    if (!d.ok) {
      stopSuggestPoll('Error: '+(d.error||'failed'));
      return;
    }
    suggestPollTimer = setInterval(pollSuggestStatus, 1500);
  }).catch(err => stopSuggestPoll('Request failed'));
};

function pollSuggestStatus() {
  api('/api/suggest/status').then(d => {
    if (d.running) {
      document.getElementById('suggestStatusText').textContent = 'Running... (this may take a minute)';
      return;
    }
    // Done
    clearInterval(suggestPollTimer);
    suggestPollTimer = null;
    document.getElementById('suggestBtn').disabled = false;
    document.getElementById('suggestSpinner').style.display = 'none';

    if (d.error) {
      document.getElementById('suggestStatusText').textContent = 'Error: '+d.error;
    } else {
      document.getElementById('suggestStatusText').textContent = 'Done! New tasks added to plan.';
    }

    if (d.log) {
      document.getElementById('suggestLogWrap').style.display = '';
      document.getElementById('suggestLogEl').textContent = d.log;
    }
    refreshState();
    if (!d.error) toast('Suggestions added to tasks!', 'ok');
  }).catch(() => {});
}

function stopSuggestPoll(msg) {
  clearInterval(suggestPollTimer);
  suggestPollTimer = null;
  document.getElementById('suggestBtn').disabled = false;
  document.getElementById('suggestSpinner').style.display = 'none';
  document.getElementById('suggestStatusText').textContent = msg;
  toast(msg, 'err');
}

// ── Settings ─────────────────────────────────────────────────────────────────

function loadConfig() {
  api('/api/config').then(cfg => {
    if (cfg.error) return;
    // Provider
    const provSel = document.getElementById('cfgProvider');
    if (cfg.provider) provSel.value = cfg.provider;
    // ClaudeCode
    document.getElementById('cfgCCModel').value = cfg.claudecode?.model || '';
    // Anthropic
    document.getElementById('cfgAnthropicModel').value = cfg.anthropic?.model || '';
    document.getElementById('cfgAnthropicBase').value  = cfg.anthropic?.base_url || '';
    const antKeyEl = document.getElementById('anthropicKeyStatus');
    antKeyEl.innerHTML = cfg.anthropic?.has_key
      ? '<span class="badge complete" style="font-size:10px">key set</span>'
      : '<span class="badge unknown"  style="font-size:10px">no key</span>';
    // OpenAI
    document.getElementById('cfgOpenAIModel').value = cfg.openai?.model || '';
    document.getElementById('cfgOpenAIBase').value  = cfg.openai?.base_url || '';
    const oaiKeyEl = document.getElementById('openaiKeyStatus');
    oaiKeyEl.innerHTML = cfg.openai?.has_key
      ? '<span class="badge complete" style="font-size:10px">key set</span>'
      : '<span class="badge unknown"  style="font-size:10px">no key</span>';
    // Ollama
    document.getElementById('cfgOllamaBase').value  = cfg.ollama?.base_url || '';
    document.getElementById('cfgOllamaModel').value = cfg.ollama?.model || '';
  }).catch(() => {});
}

window.saveConfigField = function(key, value) {
  if (value === undefined || value === null) return;
  api('/api/config/set', {key, value}).then(d => {
    if (d.ok) { toast('Saved: '+key, 'ok'); loadConfig(); }
    else toast(d.error||'Save failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.saveAnthropicCfg = function() {
  const key   = document.getElementById('cfgAnthropicKey').value.trim();
  const model = document.getElementById('cfgAnthropicModel').value.trim();
  const base  = document.getElementById('cfgAnthropicBase').value.trim();
  const saves = [];
  if (key)   saves.push(saveConfigField('anthropic.api_key', key));
  if (model) saves.push(saveConfigField('anthropic.model',   model));
  if (base)  saves.push(saveConfigField('anthropic.base_url', base));
  if (!saves.length) { toast('Nothing to save', 'info'); return; }
  Promise.all(saves).then(() => { document.getElementById('cfgAnthropicKey').value = ''; loadConfig(); });
};

window.saveOpenAICfg = function() {
  const key   = document.getElementById('cfgOpenAIKey').value.trim();
  const model = document.getElementById('cfgOpenAIModel').value.trim();
  const base  = document.getElementById('cfgOpenAIBase').value.trim();
  const saves = [];
  if (key)   saves.push(saveConfigField('openai.api_key', key));
  if (model) saves.push(saveConfigField('openai.model',   model));
  if (base)  saves.push(saveConfigField('openai.base_url', base));
  if (!saves.length) { toast('Nothing to save', 'info'); return; }
  Promise.all(saves).then(() => { document.getElementById('cfgOpenAIKey').value = ''; loadConfig(); });
};

window.saveOllamaCfg = function() {
  const base  = document.getElementById('cfgOllamaBase').value.trim();
  const model = document.getElementById('cfgOllamaModel').value.trim();
  const saves = [];
  if (base)  saves.push(saveConfigField('ollama.base_url', base));
  if (model) saves.push(saveConfigField('ollama.model',    model));
  if (!saves.length) { toast('Nothing to save', 'info'); return; }
  Promise.all(saves).then(() => loadConfig());
};

window.confirmReset = function() {
  if (!confirm('Reset project state? This clears step history and resets status. Goal and config are preserved.')) return;
  api('/api/reset', {}).then(d => {
    if (d.ok) { toast('Project reset', 'ok'); refreshState(); }
    else toast(d.error||'Reset failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Voice / STT ───────────────────────────────────────────────────────────────

let voiceMediaRecorder = null;
let voiceChunks = [];
let voiceRecording = false;
let voiceBlob = null;

window.openVoiceModal = function() {
  document.getElementById('voiceModalBackdrop').style.display = 'flex';
  document.getElementById('voiceStatus').textContent = 'Click Record to start recording...';
  document.getElementById('voiceTranscript').textContent = 'Transcription will appear here';
  document.getElementById('voiceTranscript').style.color = 'var(--muted)';
  document.getElementById('voiceOutput').style.display = 'none';
  document.getElementById('voiceOutput').textContent = '';
  document.getElementById('voiceSendBtn').disabled = true;
  voiceBlob = null; voiceChunks = [];
};

window.closeVoiceModal = function() {
  if (voiceRecording) stopVoiceRecording();
  document.getElementById('voiceModalBackdrop').style.display = 'none';
};

window.toggleVoiceRecording = async function() {
  if (voiceRecording) { stopVoiceRecording(); return; }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    voiceChunks = [];
    voiceBlob = null;
    document.getElementById('voiceSendBtn').disabled = true;
    document.getElementById('voiceOutput').style.display = 'none';

    // Prefer webm/opus; fallback to whatever the browser supports.
    const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
      ? 'audio/webm;codecs=opus'
      : (MediaRecorder.isTypeSupported('audio/ogg') ? 'audio/ogg' : '');
    const options = mimeType ? { mimeType } : {};
    voiceMediaRecorder = new MediaRecorder(stream, options);

    voiceMediaRecorder.ondataavailable = e => { if (e.data.size > 0) voiceChunks.push(e.data); };
    voiceMediaRecorder.onstop = () => {
      stream.getTracks().forEach(t => t.stop());
      const ext = (voiceMediaRecorder.mimeType || '').includes('ogg') ? 'ogg' : 'webm';
      voiceBlob = new Blob(voiceChunks, { type: voiceMediaRecorder.mimeType || 'audio/webm' });
      voiceBlob._ext = ext;
      document.getElementById('voiceStatus').textContent = 'Recorded ' + (voiceBlob.size/1024).toFixed(1) + ' KB. Click Execute to transcribe and run.';
      document.getElementById('voiceSendBtn').disabled = false;
      document.getElementById('voiceRecordBtn').classList.remove('recording');
      document.getElementById('voiceRecordBtn').innerHTML = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/></svg> Record';
      voiceRecording = false;
    };

    voiceMediaRecorder.start(200);
    voiceRecording = true;
    document.getElementById('voiceStatus').textContent = 'Recording... click Stop to finish.';
    document.getElementById('voiceRecordBtn').classList.add('recording');
    document.getElementById('voiceRecordBtn').innerHTML = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0zM5.5 5.5h5v5h-5z"/></svg> Stop';
  } catch (err) {
    document.getElementById('voiceStatus').textContent = 'Microphone error: ' + err.message;
  }
};

function stopVoiceRecording() {
  if (voiceMediaRecorder && voiceMediaRecorder.state !== 'inactive') voiceMediaRecorder.stop();
  voiceRecording = false;
}

window.sendVoiceAudio = async function() {
  if (!voiceBlob) { toast('No recording yet', 'info'); return; }

  document.getElementById('voiceStatus').textContent = 'Uploading and transcribing...';
  document.getElementById('voiceSendBtn').disabled = true;

  const ext = voiceBlob._ext || 'webm';
  const formData = new FormData();
  formData.append('audio', voiceBlob, 'recording.' + ext);

  try {
    const headers = authHeaders();
    // FormData sets its own Content-Type; remove explicit header.
    delete headers['Content-Type'];

    const resp = await fetch('/api/voice', { method: 'POST', headers, body: formData });
    const data = await resp.json();

    document.getElementById('voiceOutput').style.display = 'block';
    document.getElementById('voiceOutput').textContent = data.output || '';

    // Extract transcription line from output for display.
    const lines = (data.output || '').split('\n');
    const tLine = lines.find(l => l.includes('Transcription:'));
    const tVal  = lines.find(l => l.trim().startsWith('"') && l.trim().endsWith('"'));
    if (tVal) {
      document.getElementById('voiceTranscript').textContent = tVal.trim().replace(/^"|"$/g, '');
      document.getElementById('voiceTranscript').style.color = 'var(--text)';
    }

    if (data.ok) {
      document.getElementById('voiceStatus').textContent = 'Done! Check output below.';
      toast('Voice command executed', 'ok');
      refreshState();
    } else {
      document.getElementById('voiceStatus').textContent = 'Error: ' + (data.error || 'unknown');
      toast('Voice command failed', 'err');
    }
    document.getElementById('voiceSendBtn').disabled = false;
  } catch (err) {
    document.getElementById('voiceStatus').textContent = 'Request failed: ' + err.message;
    document.getElementById('voiceSendBtn').disabled = false;
    toast('Voice request failed', 'err');
  }
};

// ── Chat ─────────────────────────────────────────────────────────────────────

let chatTtsEnabled = false;
let chatVoiceMediaRecorder = null;
let chatVoiceChunks = [];
let chatVoiceRecording = false;
let chatVoiceBlob = null;
let spaceVoiceActive = false;

// Restore TTS preference.
(function() {
  const saved = localStorage.getItem('cloop_chat_tts');
  if (saved === 'true') {
    chatTtsEnabled = true;
    const el = document.getElementById('chatTtsToggle');
    if (el) el.checked = true;
  }
})();

window.toggleTTS = function(enabled) {
  chatTtsEnabled = enabled;
  localStorage.setItem('cloop_chat_tts', enabled ? 'true' : 'false');
  if (!enabled && window.speechSynthesis) window.speechSynthesis.cancel();
};

function speakText(text) {
  if (!chatTtsEnabled || !window.speechSynthesis) return;
  window.speechSynthesis.cancel();
  const utt = new SpeechSynthesisUtterance(text);
  utt.rate = 1.05;
  window.speechSynthesis.speak(utt);
}

function chatFmtTime(ts) {
  const d = ts ? new Date(ts) : new Date();
  return d.toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
}

function appendChatBubble(role, content, opts) {
  const box = document.getElementById('chatMessages');
  if (!box) return;
  const welcome = box.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  const row = document.createElement('div');
  row.className = 'chat-bubble-row ' + role;
  const initials = role === 'user' ? 'U' : 'AI';
  const action   = (opts && opts.action) ? opts.action : '';
  const ts       = (opts && opts.ts)     ? opts.ts     : null;
  const isError  = opts && opts.error;

  row.innerHTML =
    '<div class="chat-avatar ' + role + '">' + initials + '</div>' +
    '<div>' +
      '<div class="chat-bubble ' + role + (isError ? ' error' : '') + '">' +
        esc(content) +
        (action ? '<br><span class="chat-bubble-action">$ cloop ' + esc(action) + '</span>' : '') +
      '</div>' +
      '<div class="chat-bubble-time">' + chatFmtTime(ts) + '</div>' +
    '</div>';

  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
  return row;
}

function showChatThinking() {
  const box = document.getElementById('chatMessages');
  if (!box) return null;
  const el = document.createElement('div');
  el.className = 'chat-thinking';
  el.id = 'chatThinking';
  el.innerHTML = '<span class="spinner"></span> Thinking...';
  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
  return el;
}

function removeChatThinking() {
  const el = document.getElementById('chatThinking');
  if (el) el.remove();
}

window.submitChat = async function() {
  const input = document.getElementById('chatInput');
  if (!input) return;
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';

  appendChatBubble('user', msg, {ts: new Date()});
  showChatThinking();

  try {
    const resp = await fetch('/api/chat', {
      method: 'POST',
      headers: Object.assign({'Content-Type': 'application/json'}, authHeaders()),
      body: JSON.stringify({message: msg}),
    });
    if (resp.status === 401) { showLoginModal(); removeChatThinking(); return; }
    const data = await resp.json();
    removeChatThinking();
    const content = data.response || (data.ok ? 'Done.' : (data.error || 'Error'));
    appendChatBubble('assistant', content, {ts: new Date(), error: !data.ok, action: data.action});
    if (data.ok) speakText(content);
    if (data.ok) refreshState();
  } catch(err) {
    removeChatThinking();
    appendChatBubble('assistant', 'Request failed: ' + err.message, {ts: new Date(), error: true});
  }
};

window.clearChatHistory = function() {
  const box = document.getElementById('chatMessages');
  if (!box) return;
  box.innerHTML =
    '<div class="chat-welcome">' +
    '<div class="chat-welcome-icon">&#x1F4AC;</div>' +
    '<div class="chat-welcome-title">Chat with cloop</div>' +
    '<div class="chat-welcome-text">Type a natural language command to control your project.<br>' +
    'Examples: <em>"add a task to fix the login bug"</em>, <em>"start the run"</em>, <em>"show me task 3"</em>, <em>"pause"</em></div>' +
    '</div>';
};

function loadChatHistory() {
  fetch('/api/chat/history', {headers: authHeaders()}).then(r => r.json()).then(history => {
    if (!history || !history.length) return;
    const box = document.getElementById('chatMessages');
    if (!box) return;
    box.innerHTML = '';
    history.forEach(m => appendChatBubble(m.role, m.content, {ts: m.timestamp, action: m.action}));
  }).catch(() => {});
}

// ── Chat voice ────────────────────────────────────────────────────────────────

window.toggleChatVoice = async function() {
  if (chatVoiceRecording) { stopChatVoice(); return; }
  await startChatVoice();
};

async function startChatVoice() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({audio: true});
    chatVoiceChunks = []; chatVoiceBlob = null;
    const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
      ? 'audio/webm;codecs=opus'
      : (MediaRecorder.isTypeSupported('audio/ogg') ? 'audio/ogg' : '');
    chatVoiceMediaRecorder = new MediaRecorder(stream, mimeType ? {mimeType} : {});
    chatVoiceMediaRecorder.ondataavailable = e => { if (e.data.size > 0) chatVoiceChunks.push(e.data); };
    chatVoiceMediaRecorder.onstop = () => {
      stream.getTracks().forEach(t => t.stop());
      const ext = (chatVoiceMediaRecorder.mimeType || '').includes('ogg') ? 'ogg' : 'webm';
      chatVoiceBlob = new Blob(chatVoiceChunks, {type: chatVoiceMediaRecorder.mimeType || 'audio/webm'});
      chatVoiceBlob._ext = ext;
      chatVoiceRecording = false;
      document.getElementById('chatMicBtn').classList.remove('recording');
      document.getElementById('chatVoiceBar').style.display = 'none';
      sendChatVoice();
    };
    chatVoiceMediaRecorder.start(200);
    chatVoiceRecording = true;
    document.getElementById('chatMicBtn').classList.add('recording');
    document.getElementById('chatVoiceBar').style.display = 'flex';
  } catch(err) {
    toast('Microphone error: ' + err.message, 'err');
  }
}

window.stopChatVoice = function() {
  if (chatVoiceMediaRecorder && chatVoiceMediaRecorder.state !== 'inactive') chatVoiceMediaRecorder.stop();
};

window.cancelChatVoice = function() {
  if (chatVoiceMediaRecorder && chatVoiceMediaRecorder.state !== 'inactive') chatVoiceMediaRecorder.stop();
  chatVoiceBlob = null;
  chatVoiceRecording = false;
  document.getElementById('chatMicBtn').classList.remove('recording');
  document.getElementById('chatVoiceBar').style.display = 'none';
};

async function sendChatVoice() {
  if (!chatVoiceBlob) return;
  appendChatBubble('user', '&#x1F3A4; Voice message (transcribing\u2026)', {ts: new Date()});
  showChatThinking();

  const ext = chatVoiceBlob._ext || 'webm';
  const formData = new FormData();
  formData.append('audio', chatVoiceBlob, 'recording.' + ext);
  formData.append('execute', 'true');

  try {
    const headers = authHeaders();
    delete headers['Content-Type'];
    const resp = await fetch('/api/voice', {method: 'POST', headers, body: formData});
    if (resp.status === 401) { showLoginModal(); removeChatThinking(); return; }
    const data = await resp.json();
    removeChatThinking();

    // Update the placeholder bubble with actual transcription.
    const msgBox = document.getElementById('chatMessages');
    if (msgBox) {
      const userBubbles = msgBox.querySelectorAll('.chat-bubble-row.user');
      if (userBubbles.length > 0) {
        const lastBubble = userBubbles[userBubbles.length - 1].querySelector('.chat-bubble');
        const lines = (data.output || '').split('\n');
        const tVal  = lines.find(l => l.trim().startsWith('"') && l.trim().endsWith('"'));
        const tText = tVal ? tVal.trim().replace(/^"|"$/g, '') : '&#x1F3A4; (voice command)';
        if (lastBubble) lastBubble.textContent = '\uD83C\uDFA4 ' + (tVal ? tVal.trim().replace(/^"|"$/g, '') : '(voice command)');
      }
    }

    const content = data.output || (data.ok ? 'Done.' : (data.error || 'Error'));
    appendChatBubble('assistant', content, {ts: new Date(), error: !data.ok});
    if (data.ok) speakText(content);
    if (data.ok) refreshState();
    chatVoiceBlob = null;
  } catch(err) {
    removeChatThinking();
    appendChatBubble('assistant', 'Voice request failed: ' + err.message, {ts: new Date(), error: true});
  }
}

// ── Space push-to-talk (Chat tab only) ───────────────────────────────────────

document.addEventListener('keydown', async function(e) {
  if (activeTab !== 'chat') return;
  if (e.code !== 'Space') return;
  const tag = ((e.target && e.target.tagName) || '').toUpperCase();
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'BUTTON') return;
  if (spaceVoiceActive || chatVoiceRecording) return;
  e.preventDefault();
  spaceVoiceActive = true;
  await startChatVoice();
});

document.addEventListener('keyup', function(e) {
  if (e.code !== 'Space') return;
  if (!spaceVoiceActive) return;
  spaceVoiceActive = false;
  if (chatVoiceRecording) stopChatVoice();
});

// ── Init ─────────────────────────────────────────────────────────────────────

// On page load, probe the server. If it returns 401 show the login modal,
// otherwise proceed normally. This avoids the EventSource not reporting 401.
function checkAuthAndInit() {
  fetch('/api/state', {headers: authHeaders()}).then(r => {
    if (r.status === 401) {
      showLoginModal();
    } else {
      connectSSE();
      r.json().then(s => render(s)).catch(() => {});
    }
  }).catch(() => {
    // Network error — still try to connect SSE, it will retry on failure.
    connectSSE();
  });
}

checkAuthAndInit();
})();
</script>
</body>
</html>
`
