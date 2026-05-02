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

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/blocker"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/epic"
	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/riskmatrix"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/timeline"
)

// sseEvent is a typed SSE message. If Event is empty the browser receives a
// default "message" event; otherwise the named event type is sent.
type sseEvent struct {
	Event string // e.g. "" or "log"
	Data  string
}

// wsMessage is a typed WebSocket message envelope.
// Type values: "task_update", "step_output", "plan_complete", "projects", "error".
type wsMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// hubClient represents a single WebSocket connection with presence metadata.
type hubClient struct {
	ch    chan wsMessage
	id    string // unique per-connection identifier
	name  string // display name (e.g. "Swift Panda")
	color string // hex color code (e.g. "#58a6ff")
}

// conflictEntry records the last editor of a specific task field.
type conflictEntry struct {
	clientID string
	editedAt time.Time
}

// presenceUser is the JSON representation of a connected user sent to clients.
type presenceUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
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

// uiIPBucket is a token-bucket state for one remote IP in the UI server.
type uiIPBucket struct {
	tokens   float64
	lastSeen time.Time
}

// Server is the cloop web dashboard HTTP server.
type Server struct {
	WorkDir  string
	Port     int
	Token    string   // optional auth token; empty = no auth
	Projects []string // extra project directories for multi-project dashboard

	// RPS and Burst control the per-IP token-bucket rate limiter.
	// Zero values use 20 req/s and burst 50.
	RPS   float64
	Burst int

	mu      sync.Mutex
	clients map[chan sseEvent]struct{}
	lastMod time.Time

	// Hub registry: per-project WebSocket client presence tracking.
	// Key is the resolved workDir path.
	hubMu      sync.Mutex
	hubClients map[string]map[*hubClient]struct{}

	// Conflict tracker: per-project, per-task-field last-edit records.
	// Outer key: workDir, inner key: "taskID:field".
	conflictMu      sync.Mutex
	conflictTracker map[string]map[string]*conflictEntry

	// Rate limiting: tracks per-IP auth failure counts.
	authMu   sync.Mutex
	authFails map[string]*authFailEntry

	// Per-IP request rate-limit buckets.
	rlMu      sync.Mutex
	rlBuckets map[string]*uiIPBucket

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

	// Per-project chat conversation histories (keyed by resolved workDir path).
	chatMu        sync.Mutex
	chatHistories map[string][]ChatMessage
}

// New creates a new UI server for the given working directory and port.
// token is optional; if non-empty every API request must supply it via
// "Authorization: Bearer <token>" header or "?token=<token>" query param.
func New(workdir string, port int, token string) *Server {
	return &Server{
		WorkDir:         workdir,
		Port:            port,
		Token:           token,
		clients:         make(map[chan sseEvent]struct{}),
		hubClients:      make(map[string]map[*hubClient]struct{}),
		conflictTracker: make(map[string]map[string]*conflictEntry),
		authFails:       make(map[string]*authFailEntry),
		rlBuckets:       make(map[string]*uiIPBucket),
		chatHistories:   make(map[string][]ChatMessage),
	}
}

// uiAllow reports whether the request from ip is within the rate limit.
func (s *Server) uiAllow(ip string) bool {
	rps := s.RPS
	if rps <= 0 {
		rps = 20.0
	}
	burst := s.Burst
	if burst <= 0 {
		burst = 50
	}

	now := time.Now()
	s.rlMu.Lock()
	defer s.rlMu.Unlock()

	b, ok := s.rlBuckets[ip]
	if !ok {
		b = &uiIPBucket{tokens: float64(burst), lastSeen: now}
		s.rlBuckets[ip] = b
	}

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

// uiRateLimitMiddleware wraps next with per-IP token-bucket rate limiting.
func (s *Server) uiRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAllow(clientIP(r)) {
			rps := s.RPS
			if rps <= 0 {
				rps = 20.0
			}
			retryAfter := int(1.0/rps) + 1
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"}) //nolint:errcheck
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveWorkDir returns the effective working directory for a request.
// In multi-project mode the caller may supply ?project_idx=N to scope the
// request to a registered project's directory instead of the server's WorkDir.
func (s *Server) resolveWorkDir(r *http.Request) string {
	if idx := r.URL.Query().Get("project_idx"); idx != "" {
		i, err := strconv.Atoi(idx)
		if err == nil {
			entries := s.allProjectEntries()
			if i >= 0 && i < len(entries) {
				return entries[i].Path
			}
		}
	}
	return s.WorkDir
}

// Handler returns the HTTP handler for the server with all routes registered
// and security/auth middleware applied.  It does NOT start background goroutines
// (watchState, watchProjects); call Start() for the full lifecycle.
// This method exists primarily to support httptest-based unit tests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	return s.uiRateLimitMiddleware(securityHeaders(s.authMiddleware(mux)))
}

// registerRoutes wires all API and UI routes onto mux.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Dashboard SPA
	mux.HandleFunc("/", s.handleDashboard)

	// Read-only state, WebSocket, and SSE (SSE kept as fallback)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/ws", s.handleWS)
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
	mux.HandleFunc("GET /api/tasks", s.handleGetTasks)
	mux.HandleFunc("POST /api/tasks", s.handlePostTasks)
	mux.HandleFunc("POST /api/tasks/reorder", s.handleReorderTasks)
	mux.HandleFunc("PUT /api/tasks/{id}", s.handlePutTask)
	mux.HandleFunc("PATCH /api/tasks/{id}", s.handlePutTask)
	mux.HandleFunc("DELETE /api/tasks/{id}", s.handleDeleteTask)
	mux.HandleFunc("GET /api/tasks/{id}/blocker", s.handleTaskBlocker)

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
	mux.HandleFunc("POST /api/chat/plan", s.handlePlanChat)

	// Init & reset
	mux.HandleFunc("/api/init", s.handleInit)
	mux.HandleFunc("/api/reset", s.handleReset)

	// Knowledge Base
	mux.HandleFunc("GET /api/kb", s.handleKBList)
	mux.HandleFunc("POST /api/kb", s.handleKBAdd)
	mux.HandleFunc("DELETE /api/kb/{id}", s.handleKBDelete)
	mux.HandleFunc("GET /api/kb/search", s.handleKBSearch)

	// Timeline
	mux.HandleFunc("/api/timeline", s.handleTimeline)

	// Dependency graph
	mux.HandleFunc("GET /api/deps", s.handleDeps)
	mux.HandleFunc("GET /api/risk-matrix", s.handleRiskMatrix)

	// Analytics dashboard
	mux.HandleFunc("GET /api/analytics", s.handleAnalytics)
	mux.HandleFunc("GET /api/epics", s.handleEpics)

	// Multi-project dashboard
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/projects/events", s.handleProjectsEvents)
	mux.HandleFunc("POST /api/projects/new", s.handleProjectNew)
	mux.HandleFunc("POST /api/projects/{idx}/run", s.handleProjectRun)
	mux.HandleFunc("POST /api/projects/{idx}/stop", s.handleProjectStop)
}

// Start begins listening on the configured port and broadcasting state updates.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	go s.watchState()
	go s.watchProjects()

	addr := ":" + strconv.Itoa(s.Port)
	if s.Token != "" {
		fmt.Printf("cloop dashboard running at http://localhost%s (token auth enabled)\n", addr)
	} else {
		fmt.Printf("cloop dashboard running at http://localhost%s\n", addr)
	}
	return http.ListenAndServe(addr, s.uiRateLimitMiddleware(securityHeaders(s.authMiddleware(mux))))
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

// broadcast sends a state JSON payload to all connected SSE and WebSocket
// clients across all projects. SSE clients receive a default "message" event;
// WebSocket clients receive a "task_update" typed envelope.
func (s *Server) broadcast(data string) {
	s.mu.Lock()
	for ch := range s.clients {
		select {
		case ch <- sseEvent{Data: data}:
		default:
		}
	}
	s.mu.Unlock()

	wsData := json.RawMessage(data)
	msg := wsMessage{Type: "task_update", Data: wsData}
	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			select {
			case hc.ch <- msg:
			default:
			}
		}
	}
	s.hubMu.Unlock()
}

// broadcastToProject sends a WebSocket message only to clients connected to
// the given project (identified by its resolved workDir path).
func (s *Server) broadcastToProject(workDir string, msg wsMessage) {
	s.hubMu.Lock()
	clients := s.hubClients[workDir]
	s.hubMu.Unlock()
	for hc := range clients {
		select {
		case hc.ch <- msg:
		default:
		}
	}
}

// presenceUsers returns a snapshot of all users connected to a project.
func (s *Server) presenceUsers(workDir string) []presenceUser {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	clients := s.hubClients[workDir]
	users := make([]presenceUser, 0, len(clients))
	for hc := range clients {
		users = append(users, presenceUser{ID: hc.id, Name: hc.name, Color: hc.color})
	}
	return users
}

// broadcastPresence sends the current presence list to all clients in a project.
func (s *Server) broadcastPresence(workDir string) {
	users := s.presenceUsers(workDir)
	raw, _ := json.Marshal(map[string]interface{}{"users": users})
	s.broadcastToProject(workDir, wsMessage{Type: "presence", Data: raw})
}

// checkAndRecordEdit records that clientID edited the given fields of taskID in
// workDir. Returns true if a conflict is detected (same field edited by a
// different client within the last 2 seconds).
func (s *Server) checkAndRecordEdit(workDir, clientID string, taskID int, fields []string) bool {
	now := time.Now()
	s.conflictMu.Lock()
	defer s.conflictMu.Unlock()
	if s.conflictTracker[workDir] == nil {
		s.conflictTracker[workDir] = make(map[string]*conflictEntry)
	}
	conflict := false
	for _, field := range fields {
		key := fmt.Sprintf("%d:%s", taskID, field)
		if prev, ok := s.conflictTracker[workDir][key]; ok {
			if prev.clientID != clientID && now.Sub(prev.editedAt) < 2*time.Second {
				conflict = true
			}
		}
		s.conflictTracker[workDir][key] = &conflictEntry{clientID: clientID, editedAt: now}
	}
	return conflict
}

// presenceNames is a list of fun display names for anonymous users.
var presenceNames = []string{
	"Swift Panda", "Bold Fox", "Keen Owl", "Calm Deer", "Brave Wolf",
	"Quick Lynx", "Sharp Hawk", "Witty Otter", "Sage Raven", "Bright Ibis",
	"Cool Moose", "Deft Crane", "Eager Bison", "Fable Lynx", "Glad Ferret",
}

// presenceColors are the accent colors assigned to users (cycling).
var presenceColors = []string{
	"#58a6ff", "#3fb950", "#bc8cff", "#39c5cf", "#f85149",
	"#d29922", "#e3b341", "#ff7b72", "#79c0ff", "#56d364",
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
	wsData := json.RawMessage(data)
	logMsg := wsMessage{Type: "step_output", Data: wsData}
	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			select {
			case hc.ch <- logMsg:
			default:
			}
		}
	}
	s.hubMu.Unlock()
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
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, "no cloop project found", http.StatusNotFound)
		return
	}
	jsonOK(w, ps)
}

// handleGetTasks returns tasks filtered by query params: q, status (csv), tags (csv), assignee, priority (1-4).
// GET /api/tasks?q=text&status=pending,in_progress&tags=backend&assignee=alice&priority=1
func (s *Server) handleGetTasks(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"tasks": []*pm.Task{}, "total": 0})
		return
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	statusCSV := r.URL.Query().Get("status")
	tagsCSV := r.URL.Query().Get("tags")
	assignee := r.URL.Query().Get("assignee")
	priorityStr := r.URL.Query().Get("priority")

	statusSet := map[string]bool{}
	if statusCSV != "" {
		for _, sv := range strings.Split(statusCSV, ",") {
			if sv = strings.TrimSpace(sv); sv != "" {
				statusSet[sv] = true
			}
		}
	}
	tagSet := map[string]bool{}
	if tagsCSV != "" {
		for _, tv := range strings.Split(tagsCSV, ",") {
			if tv = strings.TrimSpace(tv); tv != "" {
				tagSet[tv] = true
			}
		}
	}
	var priority int
	if priorityStr != "" {
		priority, _ = strconv.Atoi(priorityStr)
	}

	out := make([]*pm.Task, 0, len(ps.Plan.Tasks))
	for _, t := range ps.Plan.Tasks {
		if q != "" {
			if !strings.Contains(strings.ToLower(t.Title), q) && !strings.Contains(strings.ToLower(t.Description), q) {
				continue
			}
		}
		if len(statusSet) > 0 {
			st := string(t.Status)
			if st == "" {
				st = "pending"
			}
			if !statusSet[st] {
				continue
			}
		}
		if len(tagSet) > 0 {
			found := false
			for _, tag := range t.Tags {
				if tagSet[tag] {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if assignee != "" && t.Assignee != assignee {
			continue
		}
		if priority > 0 && t.Priority != priority {
			continue
		}
		out = append(out, t)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	jsonOK(w, map[string]interface{}{"tasks": out, "total": len(ps.Plan.Tasks)})
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

// handleWS upgrades the connection to a WebSocket and streams typed JSON
// messages to the client. It also manages per-project presence tracking.
// Clients that cannot upgrade (e.g., proxies that strip the Upgrade header)
// should fall back to the /api/events SSE endpoint.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // local dashboard — origin check is unnecessary
	})
	if err != nil {
		return
	}
	defer conn.CloseNow() //nolint:errcheck

	ctx := r.Context()
	workDir := s.resolveWorkDir(r)

	// Assign a unique id, color-coded name and accent color to this connection.
	connID := fmt.Sprintf("%x", time.Now().UnixNano())
	s.hubMu.Lock()
	totalClients := 0
	for _, cl := range s.hubClients {
		totalClients += len(cl)
	}
	name  := presenceNames[totalClients%len(presenceNames)]
	color := presenceColors[totalClients%len(presenceColors)]
	// Override with user-supplied name/color from query params if provided.
	if qn := r.URL.Query().Get("name"); qn != "" {
		name = qn
	}
	if qc := r.URL.Query().Get("color"); qc != "" {
		color = qc
	}
	hc := &hubClient{
		ch:    make(chan wsMessage, 32),
		id:    connID,
		name:  name,
		color: color,
	}
	if s.hubClients[workDir] == nil {
		s.hubClients[workDir] = make(map[*hubClient]struct{})
	}
	s.hubClients[workDir][hc] = struct{}{}
	s.hubMu.Unlock()

	defer func() {
		s.hubMu.Lock()
		delete(s.hubClients[workDir], hc)
		if len(s.hubClients[workDir]) == 0 {
			delete(s.hubClients, workDir)
		}
		s.hubMu.Unlock()
		// Broadcast updated presence list after disconnection.
		s.broadcastPresence(workDir)
	}()

	// Send current state immediately.
	if ps, err := state.Load(workDir); err == nil {
		if raw, err := json.Marshal(ps); err == nil {
			if msg, err := json.Marshal(wsMessage{Type: "task_update", Data: raw}); err == nil {
				_ = conn.Write(ctx, websocket.MessageText, msg)
			}
		}
	}

	// Replay live log ring-buffer for reconnecting clients.
	s.liveLogMu.Lock()
	if len(s.liveLogLines) > 0 {
		buf := strings.Join(s.liveLogLines, "")
		s.liveLogMu.Unlock()
		if d, err := json.Marshal(map[string]string{"chunk": buf}); err == nil {
			if msg, err := json.Marshal(wsMessage{Type: "step_output", Data: d}); err == nil {
				_ = conn.Write(ctx, websocket.MessageText, msg)
			}
		}
	} else {
		s.liveLogMu.Unlock()
	}

	// Send initial presence list to this client, then announce to everyone.
	if users := s.presenceUsers(workDir); len(users) > 0 {
		if raw, err := json.Marshal(map[string]interface{}{"users": users, "you": connID}); err == nil {
			if msg, err := json.Marshal(wsMessage{Type: "presence", Data: raw}); err == nil {
				_ = conn.Write(ctx, websocket.MessageText, msg)
			}
		}
	}
	// Broadcast to others that a new user joined.
	go s.broadcastPresence(workDir)

	// Drain incoming frames (bidirectional hook for future use).
	go func() {
		for {
			_, _, err := conn.Read(ctx)
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "") //nolint:errcheck
			return
		case msg := <-hc.ch:
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				return
			}
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
	workDir := s.resolveWorkDir(r)
	cmd := exec.Command(exe, args...)
	cmd.Dir = workDir

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
			if ps, loadErr := state.Load(workDir); loadErr == nil {
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
	cfg, err := config.Load(s.resolveWorkDir(r))
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
	workDir := s.resolveWorkDir(r)
	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	if err := applyUIConfigKey(cfg, req.Key, req.Value); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.Save(workDir, cfg); err != nil {
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

	ps, err := state.Load(s.resolveWorkDir(r))
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

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Broadcast the new task to all WebSocket clients watching this project.
	addWorkDir := s.resolveWorkDir(r)
	if raw, err := json.Marshal(ps); err == nil {
		addRaw, _ := json.Marshal(map[string]interface{}{
			"task":  task,
			"state": json.RawMessage(raw),
		})
		s.broadcastToProject(addWorkDir, wsMessage{Type: "task_added", Data: addRaw})
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

	ps, err := state.Load(s.resolveWorkDir(r))
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
	if err := ps.SaveDirect(); err != nil {
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

	ps, err := state.Load(s.resolveWorkDir(r))
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

	if err := ps.SaveDirect(); err != nil {
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

	ps, err := state.Load(s.resolveWorkDir(r))
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

	if err := ps.SaveDirect(); err != nil {
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

	ps, err := state.Load(s.resolveWorkDir(r))
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
	if err := ps.SaveDirect(); err != nil {
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

	ps, err := state.Load(s.resolveWorkDir(r))
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

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Detect which fields were mutated and check for concurrent-edit conflicts.
	mutatedFields := []string{}
	if req.Title != "" {
		mutatedFields = append(mutatedFields, "title")
	}
	if req.Description != "" {
		mutatedFields = append(mutatedFields, "description")
	}
	if req.Priority > 0 {
		mutatedFields = append(mutatedFields, "priority")
	}
	if req.Status != "" {
		mutatedFields = append(mutatedFields, "status")
	}
	workDir := s.resolveWorkDir(r)
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = clientIP(r)
	}
	conflict := false
	if len(mutatedFields) > 0 {
		conflict = s.checkAndRecordEdit(workDir, clientID, id, mutatedFields)
	}

	// Broadcast the mutation to all WebSocket clients watching this project.
	if raw, err := json.Marshal(ps); err == nil {
		mutRaw, _ := json.Marshal(map[string]interface{}{
			"task":     task,
			"state":    json.RawMessage(raw),
			"conflict": conflict,
		})
		s.broadcastToProject(workDir, wsMessage{Type: "task_mutation", Data: mutRaw})
	}

	jsonOK(w, map[string]interface{}{"ok": true, "task": task, "conflict": conflict})
}

// handleDeleteTask removes a task by ID (DELETE /api/tasks/{id}).
func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.resolveWorkDir(r))
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
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Broadcast deletion to all WebSocket clients watching this project.
	workDir2 := s.resolveWorkDir(r)
	if raw, err := json.Marshal(ps); err == nil {
		delRaw, _ := json.Marshal(map[string]interface{}{
			"deleted_id": id,
			"state":      json.RawMessage(raw),
		})
		s.broadcastToProject(workDir2, wsMessage{Type: "task_deleted", Data: delRaw})
	}

	jsonOK(w, map[string]bool{"ok": true})
}

// handleTaskBlocker runs blocker detection (and optionally AI analysis) for a task
// (GET /api/tasks/{id}/blocker).
// Query params:
//
//	analyze=true   — also call the AI for root-cause + actions (requires provider config)
//	apply=true     — annotate the task with the AI recommendation (requires analyze=true)
func (s *Server) handleTaskBlocker(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil || ps.Plan == nil {
		jsonErr(w, "no task plan found", http.StatusNotFound)
		return
	}

	task := ps.Plan.TaskByID(id)
	if task == nil {
		jsonErr(w, fmt.Sprintf("task %d not found", id), http.StatusNotFound)
		return
	}

	info := blocker.Detect(workDir, task, ps.Plan)

	// Detection-only response
	if r.URL.Query().Get("analyze") != "true" {
		jsonOK(w, info)
		return
	}

	// AI analysis requested — need a provider
	cfg, cfgErr := config.Load(workDir)
	if cfgErr != nil {
		jsonErr(w, "config load error: "+cfgErr.Error(), http.StatusInternalServerError)
		return
	}

	pName := cfg.Provider
	if pName == "" {
		pName = "claudecode"
	}
	provCfg := provider.ProviderConfig{
		Name:             pName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	prov, provErr := provider.Build(provCfg)
	if provErr != nil {
		jsonErr(w, "provider error: "+provErr.Error(), http.StatusInternalServerError)
		return
	}

	model := ""
	switch pName {
	case "anthropic":
		model = cfg.Anthropic.Model
	case "openai":
		model = cfg.OpenAI.Model
	case "ollama":
		model = cfg.Ollama.Model
	case "claudecode":
		model = cfg.ClaudeCode.Model
	}

	ctx := r.Context()
	report, analyzeErr := blocker.Analyze(ctx, prov, model, 3*time.Minute, task, ps.Plan, workDir)
	if analyzeErr != nil {
		jsonErr(w, "analysis error: "+analyzeErr.Error(), http.StatusInternalServerError)
		return
	}

	// --apply: annotate the task
	if r.URL.Query().Get("apply") == "true" {
		annotation := "[ai-blocker] Recommendation: " + strings.ToUpper(report.Recommendation) +
			". Root cause: " + report.RootCause
		pm.AddAnnotation(task, "ai-blocker", annotation)
		if saveErr := ps.SaveDirect(); saveErr != nil {
			jsonErr(w, "save failed: "+saveErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	jsonOK(w, report)
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

	ps, err := state.Load(s.resolveWorkDir(r))
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

	if err := ps.SaveDirect(); err != nil {
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
	suggestWorkDir := s.resolveWorkDir(r)

	go func() {
		cmd := exec.Command(exe, "suggest", "--yes", "--count", strconv.Itoa(req.Count))
		cmd.Dir = suggestWorkDir
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
		if ps, loadErr := state.Load(suggestWorkDir); loadErr == nil {
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

	ps, err := state.Init(s.resolveWorkDir(r), req.Goal, req.MaxSteps)
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
	if err := ps.SaveDirect(); err != nil {
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
	workDir := s.resolveWorkDir(r)
	s.chatMu.Lock()
	hist := s.chatHistories[workDir]
	h := make([]ChatMessage, len(hist))
	copy(h, hist)
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
	chatWorkDir := s.resolveWorkDir(r)

	// Store user message.
	s.chatMu.Lock()
	s.chatHistories[chatWorkDir] = append(s.chatHistories[chatWorkDir], ChatMessage{
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
	doCmd := exec.Command(exe, "do", msg)
	doCmd.Dir = chatWorkDir
	out, cmdErr := doCmd.CombinedOutput()
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
	s.chatHistories[chatWorkDir] = append(s.chatHistories[chatWorkDir], ChatMessage{
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

// handlePlanChat streams an AI response that is contextualised with the full
// plan (tasks, statuses, annotations) via SSE.
// POST /api/chat/plan  {"message":"...","history":[{"role":"user","content":"..."},...]}
func (s *Server) handlePlanChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
		History []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"history"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Message) == "" {
		jsonErr(w, "message required", http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(req.Message)

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonErr(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	workDir := s.resolveWorkDir(r)
	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}

	// Build plan context.
	var sysB strings.Builder
	sysB.WriteString("You are a plan-aware AI assistant for the cloop AI product manager.\n")
	sysB.WriteString("You help the user understand, analyse, and improve their project plan.\n")
	sysB.WriteString("Be concise, practical, and reference specific task IDs when relevant.\n\n")

	ps, _ := state.Load(workDir)
	if ps != nil && ps.Plan != nil {
		sysB.WriteString("## Current Plan\n")
		sysB.WriteString("**Goal:** " + ps.Goal + "\n\n")
		total := len(ps.Plan.Tasks)
		done, inProg, failed, pending := 0, 0, 0, 0
		for _, t := range ps.Plan.Tasks {
			switch t.Status {
			case pm.TaskDone:
				done++
			case pm.TaskInProgress:
				inProg++
			case pm.TaskFailed:
				failed++
			default:
				pending++
			}
		}
		fmt.Fprintf(&sysB, "**Progress:** %d/%d done, %d in-progress, %d pending, %d failed\n\n",
			done, total, inProg, pending, failed)
		sysB.WriteString("### Tasks\n")
		for _, t := range ps.Plan.Tasks {
			fmt.Fprintf(&sysB, "- [#%d] **%s** — status: `%s`, priority: %d", t.ID, t.Title, t.Status, t.Priority)
			if t.Assignee != "" {
				fmt.Fprintf(&sysB, ", assignee: %s", t.Assignee)
			}
			if t.EstimatedMinutes > 0 {
				fmt.Fprintf(&sysB, ", est: %dm", t.EstimatedMinutes)
			}
			if t.ActualMinutes > 0 {
				fmt.Fprintf(&sysB, ", actual: %dm", t.ActualMinutes)
			}
			if len(t.DependsOn) > 0 {
				fmt.Fprintf(&sysB, ", depends on: %v", t.DependsOn)
			}
			if t.Pinned {
				sysB.WriteString(", pinned")
			}
			sysB.WriteString("\n")
			if t.Description != "" {
				fmt.Fprintf(&sysB, "  %s\n", t.Description)
			}
			if len(t.Annotations) > 0 {
				sysB.WriteString("  annotations:\n")
				for _, a := range t.Annotations {
					fmt.Fprintf(&sysB, "    • [%s] %s\n", a.Author, a.Text)
				}
			}
		}
	} else {
		sysB.WriteString("No plan is currently initialised for this project.\n")
	}

	// Build conversation prompt.
	var convB strings.Builder
	for _, h := range req.History {
		switch h.Role {
		case "user":
			fmt.Fprintf(&convB, "Human: %s\n\n", h.Content)
		case "assistant":
			fmt.Fprintf(&convB, "Assistant: %s\n\n", h.Content)
		}
	}
	fmt.Fprintf(&convB, "Human: %s\n\nAssistant: ", msg)

	// Build provider.
	pName := cfg.Provider
	if pName == "" {
		pName = "claudecode"
	}
	provCfg := provider.ProviderConfig{
		Name:             pName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	prov, buildErr := provider.Build(provCfg)
	if buildErr != nil {
		jsonErr(w, "provider: "+buildErr.Error(), http.StatusInternalServerError)
		return
	}

	model := ""
	switch pName {
	case "anthropic":
		model = cfg.Anthropic.Model
	case "openai":
		model = cfg.OpenAI.Model
	case "ollama":
		model = cfg.Ollama.Model
	case "claudecode":
		model = cfg.ClaudeCode.Model
	}

	// Start SSE response.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ctx := r.Context()
	opts := provider.Options{
		Model:        model,
		SystemPrompt: sysB.String(),
		WorkDir:      workDir,
		Timeout:      2 * time.Minute,
		OnToken: func(token string) {
			d, _ := json.Marshal(map[string]string{"token": token})
			fmt.Fprintf(w, "event: token\ndata: %s\n\n", d)
			flusher.Flush()
		},
	}

	_, callErr := prov.Complete(ctx, convB.String(), opts)
	if callErr != nil {
		d, _ := json.Marshal(map[string]string{"error": callErr.Error()})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", d)
	} else {
		fmt.Fprintf(w, "event: done\ndata: {}\n\n")
	}
	flusher.Flush()
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
	resetCmd := exec.Command(exe, "reset")
	resetCmd.Dir = s.resolveWorkDir(r)
	out, err := resetCmd.CombinedOutput()
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
	for ch := range s.clients {
		select {
		case ch <- sseEvent{Event: "projects", Data: string(payload)}:
		default:
		}
	}
	s.mu.Unlock()

	wsData := json.RawMessage(payload)
	projMsg := wsMessage{Type: "projects", Data: wsData}
	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			select {
			case hc.ch <- projMsg:
			default:
			}
		}
	}
	s.hubMu.Unlock()
}

// handleProjects returns all project statuses and aggregate stats.
func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	s.refreshProjectStatuses()
	s.projMu.RLock()
	statuses := s.projStatuses
	stats := multiui.Aggregate(statuses)
	s.projMu.RUnlock()
	// multi_project is true when there are multiple registered projects so the
	// frontend can enable the scoped-tabs experience.
	multiProject := len(statuses) > 1 || len(s.Projects) > 0
	jsonOK(w, map[string]interface{}{
		"projects":      statuses,
		"stats":         stats,
		"multi_project": multiProject,
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

// handleProjectNew creates a new cloop project directory, initialises it, and
// registers it in the multi-project registry so it appears in the dashboard.
//
// POST /api/projects/new
// Body: { "dir": "/abs/or/relative/path", "goal": "...", "provider": "...",
//         "model": "...", "pmMode": false, "autoRun": false }
func (s *Server) handleProjectNew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Dir      string `json:"dir"`
		Goal     string `json:"goal"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		PMMode   bool   `json:"pmMode"`
		AutoRun  bool   `json:"autoRun"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Goal = strings.TrimSpace(req.Goal)
	req.Dir = strings.TrimSpace(req.Dir)
	if req.Goal == "" {
		jsonErr(w, "goal is required", http.StatusBadRequest)
		return
	}
	if req.Dir == "" {
		jsonErr(w, "dir is required", http.StatusBadRequest)
		return
	}

	// Resolve to absolute path.
	abs, err := filepath.Abs(req.Dir)
	if err != nil {
		jsonErr(w, "invalid dir: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create the directory if it does not exist.
	if err := os.MkdirAll(abs, 0o755); err != nil {
		jsonErr(w, "cannot create dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Run `cloop init <goal>` in that directory.
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	args := []string{"init", req.Goal}
	if req.Provider != "" {
		args = append(args, "--provider", req.Provider)
	}
	if req.Model != "" {
		args = append(args, "--model", req.Model)
	}
	if req.PMMode {
		args = append(args, "--pm")
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = abs
	if out, initErr := cmd.CombinedOutput(); initErr != nil {
		jsonErr(w, "cloop init failed: "+string(out), http.StatusInternalServerError)
		return
	}

	// Register the new project in the multi-project registry.
	if regErr := multiui.AddPaths([]string{abs}); regErr != nil {
		// Non-fatal: project is created, just not registered.
		_ = regErr
	}

	// Optionally start a run immediately.
	if req.AutoRun {
		runArgs := []string{"run"}
		if req.PMMode {
			runArgs = append(runArgs, "--pm")
		}
		runCmd := exec.Command(exe, runArgs...)
		runCmd.Dir = abs
		runCmd.Stdout = os.Stderr
		runCmd.Stderr = os.Stderr
		if startErr := runCmd.Start(); startErr == nil {
			go func() { _ = runCmd.Wait() }()
		}
	}

	// Refresh project cache and return updated project list.
	s.refreshProjectStatuses()
	entries := s.allProjectEntries()
	newIdx := -1
	for i, e := range entries {
		if e.Path == abs {
			newIdx = i
			break
		}
	}

	jsonOK(w, map[string]interface{}{"ok": true, "dir": abs, "project_idx": newIdx})
}

// ── Knowledge Base handlers ──────────────────────────────────────────────────

// handleKBList returns all KB entries as JSON (GET /api/kb).
func (s *Server) handleKBList(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	store, err := kb.Load(workDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entries := store.Entries
	if entries == nil {
		entries = []*kb.Entry{}
	}
	jsonOK(w, map[string]interface{}{"entries": entries})
}

// handleKBAdd creates a new KB entry (POST /api/kb).
// Body: { "title": "...", "body": "...", "tags": ["a","b"] }
func (s *Server) handleKBAdd(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	var req struct {
		Title string   `json:"title"`
		Body  string   `json:"body"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	req.Body = strings.TrimSpace(req.Body)
	if req.Title == "" {
		http.Error(w, "title required", http.StatusBadRequest)
		return
	}
	entry, err := kb.Add(workDir, req.Title, req.Body, req.Tags)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "entry": entry})
}

// handleKBDelete removes a KB entry by ID (DELETE /api/kb/{id}).
func (s *Server) handleKBDelete(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := kb.Remove(workDir, id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true})
}

// handleKBSearch returns KB entries whose title, content, or tags contain the
// query string (case-insensitive substring match). GET /api/kb/search?q=...
func (s *Server) handleKBSearch(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	store, err := kb.Load(workDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var matched []*kb.Entry
	for _, e := range store.Entries {
		if q == "" ||
			strings.Contains(strings.ToLower(e.Title), q) ||
			strings.Contains(strings.ToLower(e.Content), q) ||
			func() bool {
				for _, t := range e.Tags {
					if strings.Contains(strings.ToLower(t), q) {
						return true
					}
				}
				return false
			}() {
			matched = append(matched, e)
		}
	}
	if matched == nil {
		matched = []*kb.Entry{}
	}
	jsonOK(w, map[string]interface{}{"entries": matched})
}

// handleTimeline returns timeline bar data derived from pkg/timeline for the
// SVG Gantt chart in the web UI. Response JSON:
//
//	{ "bars": [...], "planStart": "<RFC3339>", "now": "<RFC3339>" }
//
// Each bar includes task metadata needed for the tooltip (assignee, estimated
// vs actual minutes, depends_on).
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"bars": []struct{}{}, "planStart": time.Now().Format(time.RFC3339), "now": time.Now().Format(time.RFC3339)})
		return
	}

	// Determine plan start: earliest StartedAt among tasks, or now.
	planStart := time.Now()
	for _, t := range ps.Plan.Tasks {
		if t.StartedAt != nil && !t.StartedAt.IsZero() {
			if t.StartedAt.Before(planStart) {
				planStart = *t.StartedAt
			}
		}
	}
	// If no task has started yet, use a window starting 5 minutes ago so the
	// 'now' cursor appears near the left of the chart.
	allPending := true
	for _, t := range ps.Plan.Tasks {
		if t.Status != pm.TaskPending {
			allPending = false
			break
		}
	}
	if allPending {
		planStart = time.Now().Add(-5 * time.Minute)
	}

	bars := timeline.Build(ps.Plan, planStart)

	// Build enriched response bars with extra fields for the UI tooltip.
	type TimelineBar struct {
		TaskID           int   `json:"taskId"`
		Title            string `json:"title"`
		Start            string `json:"start"`
		End              string `json:"end"`
		Status           string `json:"status"`
		Assignee         string `json:"assignee"`
		EstimatedMinutes int    `json:"estimatedMinutes"`
		ActualMinutes    int    `json:"actualMinutes"`
		DependsOn        []int  `json:"dependsOn"`
	}

	// Build a task-id → Task map for quick lookup.
	taskMap := make(map[int]*pm.Task, len(ps.Plan.Tasks))
	for _, t := range ps.Plan.Tasks {
		taskMap[t.ID] = t
	}

	result := make([]TimelineBar, 0, len(bars))
	for _, b := range bars {
		tb := TimelineBar{
			TaskID: b.TaskID,
			Title:  b.Title,
			Start:  b.Start.Format(time.RFC3339),
			End:    b.End.Format(time.RFC3339),
			Status: string(b.Status),
		}
		if t, ok := taskMap[b.TaskID]; ok {
			tb.Assignee = t.Assignee
			tb.EstimatedMinutes = t.EstimatedMinutes
			tb.ActualMinutes = t.ActualMinutes
			if len(t.DependsOn) > 0 {
				tb.DependsOn = t.DependsOn
			} else {
				tb.DependsOn = []int{}
			}
		} else {
			tb.DependsOn = []int{}
		}
		result = append(result, tb)
	}

	jsonOK(w, map[string]interface{}{
		"bars":      result,
		"planStart": planStart.Format(time.RFC3339),
		"now":       time.Now().Format(time.RFC3339),
	})
}

// ── Dependency graph handler ─────────────────────────────────────────────────

// handleDeps returns nodes (id, title, status, priority) and edges (from, to)
// for the task dependency graph. GET /api/deps
func (s *Server) handleDeps(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"nodes": []struct{}{}, "edges": []struct{}{}})
		return
	}

	type Node struct {
		ID          int    `json:"id"`
		Title       string `json:"title"`
		Status      string `json:"status"`
		Priority    int    `json:"priority"`
		Description string `json:"description"`
		Assignee    string `json:"assignee,omitempty"`
		Deadline    string `json:"deadline,omitempty"`
	}
	type Edge struct {
		From int `json:"from"`
		To   int `json:"to"`
	}

	nodes := make([]Node, 0, len(ps.Plan.Tasks))
	edges := make([]Edge, 0)

	for _, t := range ps.Plan.Tasks {
		deadline := ""
		if t.Deadline != nil && !t.Deadline.IsZero() {
			deadline = t.Deadline.Format("2006-01-02 15:04")
		}
		nodes = append(nodes, Node{
			ID:          t.ID,
			Title:       t.Title,
			Status:      string(t.Status),
			Priority:    t.Priority,
			Description: t.Description,
			Assignee:    t.Assignee,
			Deadline:    deadline,
		})
		for _, dep := range t.DependsOn {
			// Edge means dep must complete before t → dep blocks t
			edges = append(edges, Edge{From: dep, To: t.ID})
		}
	}

	jsonOK(w, map[string]interface{}{"nodes": nodes, "edges": edges})
}

// ── Risk Matrix handler ───────────────────────────────────────────────────────

// handleRiskMatrix returns the cached risk/impact matrix entries for all
// active tasks as JSON. Scores come from the RiskScore and ImpactScore fields
// cached by `cloop task ai-risk-matrix --apply`. Tasks without cached scores
// have risk_score and impact_score equal to 0.
// GET /api/risk-matrix
func (s *Server) handleRiskMatrix(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"entries": []struct{}{}, "goal": ""})
		return
	}
	entries := riskmatrix.BuildFromCache(ps.Plan)
	jsonOK(w, map[string]interface{}{
		"entries": entries,
		"goal":    ps.Plan.Goal,
	})
}

// ── Analytics handler ─────────────────────────────────────────────────────────

// handleAnalytics returns a JSON payload with all data needed by the analytics
// dashboard tab. Accepts optional ?from=YYYY-MM-DD and ?to=YYYY-MM-DD query
// params. GET /api/analytics
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)

	// Parse optional date-range filter (default: last 30 days).
	const dayFmt = "2006-01-02"
	now := time.Now().UTC()
	fromDefault := now.AddDate(0, 0, -30).Truncate(24 * time.Hour)
	toDefault := now.Add(24 * time.Hour).Truncate(24 * time.Hour)

	parseDay := func(s string, def time.Time) time.Time {
		if s == "" {
			return def
		}
		if t, err := time.Parse(dayFmt, s); err == nil {
			return t.UTC()
		}
		return def
	}
	fromTime := parseDay(r.URL.Query().Get("from"), fromDefault)
	toTime := parseDay(r.URL.Query().Get("to"), toDefault).Add(24 * time.Hour) // inclusive

	// ── 1. Status donut (current plan state) ──────────────────────────────────
	type statusDonut struct {
		Labels []string `json:"labels"`
		Values []int    `json:"values"`
	}
	donut := statusDonut{
		Labels: []string{"Pending", "In Progress", "Done", "Failed", "Skipped", "Timed Out"},
		Values: make([]int, 6),
	}
	ps, stateErr := state.Load(workDir)
	if stateErr == nil && ps.Plan != nil {
		for _, t := range ps.Plan.Tasks {
			switch t.Status {
			case pm.TaskPending:
				donut.Values[0]++
			case pm.TaskInProgress:
				donut.Values[1]++
			case pm.TaskDone:
				donut.Values[2]++
			case pm.TaskFailed:
				donut.Values[3]++
			case pm.TaskSkipped:
				donut.Values[4]++
			default:
				donut.Values[5]++
			}
		}
	}

	// ── 2. Read cost ledger (source for cost trend + velocity + latency) ───────
	ledger, _ := cost.ReadLedger(workDir)

	// Build date → per-provider cost map, and date → count for velocity.
	type costKey struct {
		Date     string
		Provider string
	}
	costByDayProvider := map[costKey]float64{}
	velocityByDay := map[string]int{}
	providerSet := map[string]struct{}{}

	for _, e := range ledger {
		if e.Timestamp.IsZero() {
			continue
		}
		if e.Timestamp.Before(fromTime) || !e.Timestamp.Before(toTime) {
			continue
		}
		day := e.Timestamp.UTC().Format(dayFmt)
		k := costKey{Date: day, Provider: e.Provider}
		costByDayProvider[k] += e.EstimatedUSD
		velocityByDay[day]++
		if e.Provider != "" {
			providerSet[e.Provider] = struct{}{}
		}
	}

	// ── 3. Generate date labels spanning the range ────────────────────────────
	var dateLabels []string
	for d := fromTime; !d.After(toTime.Add(-24 * time.Hour)); d = d.AddDate(0, 0, 1) {
		dateLabels = append(dateLabels, d.Format(dayFmt))
	}
	if len(dateLabels) == 0 {
		dateLabels = []string{now.Format(dayFmt)}
	}

	// ── 4. Cost trend datasets ─────────────────────────────────────────────────
	type costDataset struct {
		Provider string    `json:"provider"`
		Values   []float64 `json:"values"`
	}
	var providers []string
	for p := range providerSet {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	costDatasets := make([]costDataset, 0, len(providers))
	for _, p := range providers {
		vals := make([]float64, len(dateLabels))
		for i, d := range dateLabels {
			vals[i] = costByDayProvider[costKey{Date: d, Provider: p}]
		}
		costDatasets = append(costDatasets, costDataset{Provider: p, Values: vals})
	}

	// ── 5. Velocity sparkline (tasks/day) ─────────────────────────────────────
	// Last 14 days regardless of selected range.
	velFrom := now.AddDate(0, 0, -13).Truncate(24 * time.Hour)
	var velLabels []string
	var velValues []int
	for d := velFrom; !d.After(now); d = d.AddDate(0, 0, 1) {
		day := d.Format(dayFmt)
		velLabels = append(velLabels, day)
		// Count from full ledger (not date-filtered).
		cnt := 0
		for _, e := range ledger {
			if !e.Timestamp.IsZero() && e.Timestamp.UTC().Format(dayFmt) == day {
				cnt++
			}
		}
		velValues = append(velValues, cnt)
	}

	// ── 6. Burndown chart ─────────────────────────────────────────────────────
	// Cumulative tasks completed (from ledger) vs. remaining (from plan).
	totalTasks := 0
	if stateErr == nil && ps.Plan != nil {
		totalTasks = len(ps.Plan.Tasks)
	}
	// Map day → cumulative done up to that day.
	cumDone := make([]int, len(dateLabels))
	remaining := make([]int, len(dateLabels))
	// Count completed tasks per day from the ledger.
	doneByDay := map[string]int{}
	for _, e := range ledger {
		if e.Timestamp.IsZero() {
			continue
		}
		if e.Timestamp.Before(fromTime) || !e.Timestamp.Before(toTime) {
			continue
		}
		doneByDay[e.Timestamp.UTC().Format(dayFmt)]++
	}
	running := 0
	for i, d := range dateLabels {
		running += doneByDay[d]
		cumDone[i] = running
		rem := totalTasks - running
		if rem < 0 {
			rem = 0
		}
		remaining[i] = rem
	}

	// ── 7. Latency histogram (from checkpoint history) ────────────────────────
	// Scan .cloop/task-checkpoints/ for "complete" events with ElapsedSec.
	type latHistEntry struct {
		Provider string  `json:"provider"`
		ElapsedS float64 `json:"elapsed_s"`
	}
	latByProvider := map[string][]float64{}

	cpBase := filepath.Join(workDir, ".cloop", "task-checkpoints")
	if entries, err := os.ReadDir(cpBase); err == nil {
		for _, taskDir := range entries {
			if !taskDir.IsDir() {
				continue
			}
			taskPath := filepath.Join(cpBase, taskDir.Name())
			files, err := os.ReadDir(taskPath)
			if err != nil {
				continue
			}
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				raw, err := os.ReadFile(filepath.Join(taskPath, f.Name()))
				if err != nil {
					continue
				}
				var cp struct {
					Event     string    `json:"event"`
					Provider  string    `json:"provider"`
					ElapsedSec float64  `json:"elapsed_sec"`
					Timestamp time.Time `json:"timestamp"`
				}
				if err := json.Unmarshal(raw, &cp); err != nil {
					continue
				}
				if cp.Event != "complete" || cp.ElapsedSec <= 0 {
					continue
				}
				if !cp.Timestamp.IsZero() {
					if cp.Timestamp.Before(fromTime) || !cp.Timestamp.Before(toTime) {
						continue
					}
				}
				prov := cp.Provider
				if prov == "" {
					prov = "unknown"
				}
				latByProvider[prov] = append(latByProvider[prov], cp.ElapsedSec)
			}
		}
	}

	// Build histogram buckets: 0-5s, 5-15s, 15-30s, 30-60s, 60-120s, >120s
	bucketLabels := []string{"0–5s", "5–15s", "15–30s", "30–60s", "1–2m", ">2m"}
	bucketEdges := []float64{5, 15, 30, 60, 120}

	bucket := func(sec float64) int {
		for i, edge := range bucketEdges {
			if sec < edge {
				return i
			}
		}
		return len(bucketEdges)
	}

	type latDataset struct {
		Provider string `json:"provider"`
		Counts   []int  `json:"counts"`
	}
	var latProviders []string
	for p := range latByProvider {
		latProviders = append(latProviders, p)
	}
	sort.Strings(latProviders)

	latDatasets := make([]latDataset, 0, len(latProviders))
	for _, p := range latProviders {
		counts := make([]int, len(bucketLabels))
		for _, s := range latByProvider[p] {
			counts[bucket(s)]++
		}
		latDatasets = append(latDatasets, latDataset{Provider: p, Counts: counts})
	}

	jsonOK(w, map[string]interface{}{
		"status_donut": donut,
		"burndown": map[string]interface{}{
			"labels":          dateLabels,
			"done_cumulative": cumDone,
			"remaining":       remaining,
		},
		"cost_trend": map[string]interface{}{
			"labels":   dateLabels,
			"datasets": costDatasets,
		},
		"velocity": map[string]interface{}{
			"labels": velLabels,
			"values": velValues,
		},
		"latency": map[string]interface{}{
			"buckets":  bucketLabels,
			"datasets": latDatasets,
		},
	})
}

// handleEpics returns the epic groupings derived from "epic:" task tags.
// It rebuilds epics from existing tags in the plan — no AI call is made here.
// GET /api/epics
func (s *Server) handleEpics(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)

	ps, err := state.Load(workDir)
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"epics": []interface{}{}})
		return
	}

	epics := epic.EpicsFromTags(ps.Plan)
	if len(epics) == 0 {
		jsonOK(w, map[string]interface{}{"epics": []interface{}{}})
		return
	}

	progress := epic.Progress(ps.Plan, epics)
	jsonOK(w, map[string]interface{}{"epics": progress})
}

// ── dashboard HTML ────────────────────────────────────────────────────────────

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cloop dashboard</title>
<script>(function(){var t=localStorage.getItem('cloop-theme')||(window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');document.documentElement.setAttribute('data-theme',t);})();</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js" crossorigin="anonymous"></script>
<style>
  :root {
    --bg:          #0d1117;
    --surface:     #161b22;
    --border:      #30363d;
    --text:        #e6edf3;
    --muted:       #8b949e;
    --accent:      #58a6ff;
    --green:       #3fb950;
    --yellow:      #d29922;
    --red:         #f85149;
    --cyan:        #39c5cf;
    --purple:      #bc8cff;
    --radius:      8px;
    --hover-bg:    #21262d;
    --terminal-bg: #090d14;
    --code-bg:     #0d1117;
    --on-accent:   #0d1117;
    --accent-hover:#79bcff;
  }
  [data-theme="light"] {
    --bg:          #ffffff;
    --surface:     #f6f8fa;
    --border:      #d0d7de;
    --text:        #1f2328;
    --muted:       #656d76;
    --accent:      #0969da;
    --green:       #1a7f37;
    --yellow:      #9a6700;
    --red:         #cf222e;
    --cyan:        #0969da;
    --purple:      #8250df;
    --hover-bg:    #eaeef2;
    --terminal-bg: #090d14;
    --code-bg:     #161b22;
    --on-accent:   #ffffff;
    --accent-hover:#0550ae;
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

  /* ── Presence bar ────────────────────────────────────────────────────────── */
  #presenceBar {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 4px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    min-height: 28px;
    flex-wrap: wrap;
  }
  #presenceBar:empty { display: none; }
  .presence-label { font-size: 11px; color: var(--muted); margin-right: 4px; flex-shrink: 0; }
  .presence-avatar {
    width: 24px; height: 24px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 10px; font-weight: 700; color: #fff;
    border: 2px solid var(--bg);
    cursor: default;
    position: relative;
    flex-shrink: 0;
    transition: transform .15s;
  }
  .presence-avatar:hover { transform: scale(1.15); z-index: 2; }
  .presence-avatar .presence-tooltip {
    display: none; position: absolute; top: 28px; left: 50%; transform: translateX(-50%);
    background: var(--surface); border: 1px solid var(--border); border-radius: 4px;
    padding: 3px 7px; font-size: 11px; white-space: nowrap; z-index: 99;
    box-shadow: 0 2px 6px rgba(0,0,0,.3);
  }
  .presence-avatar:hover .presence-tooltip { display: block; }
  .presence-avatar.you { border-color: var(--accent); }

  /* ── Conflict toast ────────────────────────────────────────────────────────── */
  #conflictToast {
    position: fixed; bottom: 72px; right: 16px; z-index: 9999;
    background: #d29922; color: #000; border-radius: 6px;
    padding: 10px 14px; font-size: 13px; max-width: 320px;
    box-shadow: 0 4px 12px rgba(0,0,0,.4);
    display: none; animation: slideUp .2s ease;
    cursor: pointer;
  }
  #conflictToast.visible { display: flex; align-items: flex-start; gap: 8px; }
  #conflictToast .conflict-icon { font-size: 16px; flex-shrink: 0; }
  #conflictToast .conflict-body { flex: 1; }
  #conflictToast .conflict-title { font-weight: 700; margin-bottom: 2px; }
  #conflictToast .conflict-dismiss { font-size: 16px; cursor: pointer; flex-shrink: 0; opacity: .7; }
  @keyframes slideUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }

  /* ── Unified filter bar ────────────────────────────────────────────────────── */
  .filter-bar {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 6px 24px;
    position: sticky;
    top: 52px;
    z-index: 19;
  }
  .filter-bar-inner {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .filter-search-input {
    flex: 1 1 180px;
    min-width: 120px;
    max-width: 260px;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--fg);
    font-size: 12px;
  }
  .filter-search-input:focus { outline: 2px solid var(--accent); border-color: transparent; }
  .filter-group { display: flex; align-items: center; gap: 5px; flex-shrink: 0; }
  .filter-label { font-size: 11px; color: var(--muted); white-space: nowrap; }
  .filter-check { display: flex; align-items: center; gap: 3px; font-size: 11px; cursor: pointer; user-select: none; white-space: nowrap; }
  .filter-check input[type=checkbox] { cursor: pointer; accent-color: var(--accent); }
  .filter-select {
    padding: 3px 6px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--fg);
    font-size: 11px;
    cursor: pointer;
    max-width: 130px;
  }
  .filter-select:focus { outline: 2px solid var(--accent); }
  .filter-tags-wrap { position: relative; }
  .filter-tag-toggle {
    padding: 3px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--fg);
    font-size: 11px;
    cursor: pointer;
    white-space: nowrap;
  }
  .filter-tag-toggle:hover, .filter-tag-toggle.active { border-color: var(--accent); color: var(--accent); }
  .filter-tags-panel {
    display: none;
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: 0 4px 16px rgba(0,0,0,.35);
    padding: 6px;
    z-index: 40;
    min-width: 140px;
    max-height: 200px;
    overflow-y: auto;
  }
  .filter-tags-panel.open { display: block; }
  .filter-tag-item {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 3px 4px;
    font-size: 11px;
    cursor: pointer;
    white-space: nowrap;
    border-radius: 3px;
  }
  .filter-tag-item:hover { background: var(--hover-bg); }
  .filter-tag-item input[type=checkbox] { cursor: pointer; accent-color: var(--accent); }
  .filter-clear-btn { padding: 3px 9px; font-size: 11px; flex-shrink: 0; }
  .filter-badge { font-size: 11px; color: var(--accent); white-space: nowrap; font-weight: 600; margin-left: auto; }
  @media(max-width:767px) {
    .filter-bar { top: 0; padding: 6px 12px; }
    .filter-bar-inner { gap: 6px; }
    .filter-search-input { max-width: 100%; }
    .filter-status-group { display: none; }
  }

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
  .pin-badge { font-size:14px; vertical-align:middle; }
  .task-links { display:flex; flex-wrap:wrap; gap:6px; margin-top:5px; }
  .task-link-item { display:inline-flex; align-items:center; gap:3px; font-size:11px; color:var(--accent); text-decoration:none; padding:2px 7px; border-radius:10px; border:1px solid rgba(88,166,255,.3); background:rgba(88,166,255,.08); }
  .task-link-item:hover { text-decoration:underline; background:rgba(88,166,255,.15); }

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
  .btn:hover { background:var(--hover-bg); border-color:var(--muted); }
  .btn.primary { background:var(--accent); color:var(--on-accent); border-color:var(--accent); }
  .btn.primary:hover { background:var(--accent-hover); }
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
  .act:hover { background:var(--hover-bg); color:var(--text); }
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

  /* ── Kanban board ── */
  .kanban-toolbar { display:flex; align-items:center; gap:10px; padding:12px 0 10px; flex-wrap:wrap; }
  .kanban-board {
    display:grid; grid-template-columns:repeat(4,1fr); gap:12px;
    align-items:start; padding-bottom:20px;
  }
  .kanban-col {
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); display:flex; flex-direction:column; min-height:120px;
  }
  .kanban-col-header {
    display:flex; align-items:center; justify-content:space-between;
    padding:9px 12px 8px; border-bottom:1px solid var(--border); flex-shrink:0;
  }
  .kanban-col-title { font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); }
  .kanban-col-count {
    font-size:11px; font-weight:600; background:var(--bg);
    border:1px solid var(--border); border-radius:10px; padding:1px 7px; color:var(--muted);
  }
  #kb-col-pending .kanban-col-header   { border-top:3px solid #8b949e; border-radius:var(--radius) var(--radius) 0 0; }
  #kb-col-in_progress .kanban-col-header { border-top:3px solid var(--cyan); border-radius:var(--radius) var(--radius) 0 0; }
  #kb-col-done .kanban-col-header      { border-top:3px solid var(--green); border-radius:var(--radius) var(--radius) 0 0; }
  #kb-col-failed .kanban-col-header    { border-top:3px solid var(--red); border-radius:var(--radius) var(--radius) 0 0; }
  .kanban-col-body {
    padding:8px; display:flex; flex-direction:column; gap:6px;
    flex:1; min-height:60px; transition:background .15s;
  }
  .kanban-col-body.kb-drag-over {
    background:rgba(88,166,255,.06); border-radius:0 0 var(--radius) var(--radius);
    outline:2px dashed rgba(88,166,255,.4); outline-offset:-4px;
  }
  /* Kanban card */
  .kb-card {
    background:var(--bg); border:1px solid var(--border); border-radius:5px;
    padding:8px 10px; cursor:grab; position:relative;
    border-left:3px solid transparent;
    transition:box-shadow .15s, opacity .2s, transform .2s;
    animation:kb-enter .18s ease-out;
  }
  @keyframes kb-enter { from { opacity:0; transform:translateY(-6px); } to { opacity:1; transform:none; } }
  .kb-card:hover { box-shadow:0 2px 8px rgba(0,0,0,.35); border-color:var(--muted); }
  .kb-card.kb-dragging { opacity:.35; transform:scale(.97); cursor:grabbing; }
  .kb-card.kb-compact .kb-card-desc,
  .kb-card.kb-compact .kb-card-tags,
  .kb-card.kb-compact .kb-card-meta { display:none; }
  /* Priority left-border colors */
  .kb-card.kbp1 { border-left-color:var(--red); }
  .kb-card.kbp2 { border-left-color:var(--yellow); }
  .kb-card.kbp3 { border-left-color:var(--cyan); }
  .kb-card-header { display:flex; align-items:flex-start; gap:6px; }
  .kb-card-title { font-size:12px; font-weight:500; flex:1; line-height:1.4; }
  .kb-avatar {
    width:22px; height:22px; border-radius:50%; background:var(--accent);
    color:#fff; font-size:9px; font-weight:700; display:flex; align-items:center;
    justify-content:center; flex-shrink:0; text-transform:uppercase;
  }
  .kb-card-desc { font-size:11px; color:var(--muted); margin-top:4px; line-height:1.4;
    display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; }
  .kb-card-tags { display:flex; flex-wrap:wrap; gap:3px; margin-top:5px; }
  .kb-chip { font-size:10px; padding:1px 5px; border-radius:3px; background:rgba(88,166,255,.12);
    color:var(--accent); border:1px solid rgba(88,166,255,.2); }
  .kb-card-meta { display:flex; align-items:center; gap:6px; margin-top:6px; flex-wrap:wrap; }
  .kb-deadline { font-size:10px; padding:1px 5px; border-radius:3px;
    background:rgba(248,81,73,.12); color:var(--red); border:1px solid rgba(248,81,73,.2); }
  .kb-deadline.kb-due-soon { background:rgba(210,153,34,.12); color:var(--yellow); border-color:rgba(210,153,34,.2); }
  .kb-deadline.kb-ok { background:rgba(63,185,80,.08); color:var(--green); border-color:rgba(63,185,80,.2); }
  .kb-taskid { font-size:10px; color:var(--muted); margin-left:auto; }
  @media (max-width:900px) { .kanban-board { grid-template-columns:repeat(2,1fr); } }
  @media (max-width:560px) { .kanban-board { grid-template-columns:1fr; } }

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
  .step-header:hover { background:var(--hover-bg); }
  .step-num { font-size:11px; color:var(--muted); font-weight:600; min-width:24px; flex-shrink:0; }
  .step-task { flex:1; font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .step-meta { font-size:11px; color:var(--muted); flex-shrink:0; display:flex; gap:8px; align-items:center; }
  .step-ok  { color:var(--green); }
  .step-bad { color:var(--red); }
  .step-chevron { color:var(--muted); transition:transform .2s; flex-shrink:0; font-size:9px; }
  .step-item.expanded .step-chevron { transform:rotate(90deg); }
  .step-output { display:none; background:var(--code-bg); border-top:1px solid var(--border); padding:10px 12px; font-family:monospace; font-size:11px; white-space:pre-wrap; word-break:break-all; max-height:360px; overflow-y:auto; color:#adbac7; }
  .step-item.expanded .step-output { display:block; }

  /* ── Live output panel ── */
  .live-output-wrap { margin-bottom: 24px; }
  .live-output-header { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
  .live-output-header .section-title { margin:0; }
  .live-output-clear { font-size:11px; color:var(--muted); background:none; border:none; cursor:pointer; padding:2px 6px; }
  .live-output-clear:hover { color:var(--text); }
  .live-output-box {
    background:var(--terminal-bg);
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
  .suggest-log { background:var(--code-bg); border:1px solid var(--border); border-radius:var(--radius); padding:12px; font-family:monospace; font-size:12px; white-space:pre-wrap; color:#adbac7; max-height:320px; overflow-y:auto; margin-top:10px; }
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

  /* ── Theme toggle button ── */
  .theme-toggle-btn {
    background: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--muted);
    cursor: pointer;
    padding: 5px 9px;
    font-size: 15px;
    line-height: 1;
    display: flex;
    align-items: center;
    flex-shrink: 0;
    transition: all .15s;
  }
  .theme-toggle-btn:hover { color: var(--text); border-color: var(--muted); background: var(--hover-bg); }

  /* ── Keyboard shortcut footer ── */
  #kb-footer {
    position: fixed; bottom: 0; left: 0; right: 0;
    background: var(--surface); border-top: 1px solid var(--border);
    padding: 5px 16px; display: flex; align-items: center; gap: 14px;
    font-size: 11px; color: var(--muted); z-index: 30; flex-wrap: wrap;
    user-select: none;
  }
  #kb-footer kbd {
    display: inline-block; padding: 1px 5px;
    border: 1px solid var(--border); border-radius: 3px;
    font-size: 10px; background: var(--bg); color: var(--text);
    font-family: inherit; margin-right: 2px;
  }
  #kb-footer .kb-sep { color: var(--border); }
  /* push main content up so footer doesn't overlap */
  body { padding-bottom: 30px; }

  /* ── Command palette ── */
  #cmd-backdrop {
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,.65); z-index: 200;
    align-items: flex-start; justify-content: center;
    padding-top: 15vh;
  }
  #cmd-backdrop.open { display: flex; }
  #cmd-palette {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; width: 520px; max-width: 95vw;
    box-shadow: 0 16px 48px rgba(0,0,0,.6);
    overflow: hidden;
  }
  #cmd-input-wrap {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 16px; border-bottom: 1px solid var(--border);
  }
  #cmd-input-icon { font-size: 14px; color: var(--muted); flex-shrink: 0; }
  #cmd-input {
    flex: 1; background: none; border: none; outline: none;
    color: var(--text); font-size: 14px; font-family: inherit;
  }
  #cmd-input::placeholder { color: var(--muted); }
  #cmd-shortcut-hint {
    font-size: 11px; color: var(--muted); flex-shrink: 0;
  }
  #cmd-results {
    max-height: 340px; overflow-y: auto; padding: 6px 0;
  }
  .cmd-item {
    display: flex; align-items: center; gap: 10px;
    padding: 9px 16px; cursor: pointer; font-size: 13px;
  }
  .cmd-item:hover, .cmd-item.selected {
    background: rgba(88,166,255,.1); color: var(--text);
  }
  .cmd-item-icon { font-size: 14px; flex-shrink: 0; width: 20px; text-align: center; }
  .cmd-item-label { flex: 1; }
  .cmd-item-shortcut { font-size: 11px; color: var(--muted); font-family: monospace; }
  .cmd-item-match em { color: var(--accent); font-style: normal; font-weight: 600; }
  .cmd-no-results { padding: 20px 16px; text-align: center; color: var(--muted); font-size: 13px; }
  #cmd-footer {
    padding: 6px 16px; border-top: 1px solid var(--border);
    font-size: 11px; color: var(--muted); display: flex; gap: 12px;
  }
  #cmd-footer kbd {
    display: inline-block; padding: 1px 4px;
    border: 1px solid var(--border); border-radius: 3px;
    font-size: 10px; background: var(--bg); color: var(--text);
    font-family: inherit;
  }

  /* ── Task keyboard focus highlight ── */
  .task-item.kb-focus {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

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

  /* ── Project selector (header, multi-project mode) ── */
  .proj-selector-wrap {
    display: none; position: relative; flex-shrink: 0;
  }
  .proj-selector-wrap.visible { display: flex; align-items: center; gap: 6px; }
  .proj-selector-btn {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 5px 10px; border-radius: var(--radius);
    border: 1px solid var(--border); background: var(--surface);
    color: var(--text); font-size: 12px; font-weight: 500;
    cursor: pointer; white-space: nowrap; max-width: 200px; overflow: hidden; text-overflow: ellipsis;
  }
  .proj-selector-btn:hover { border-color: var(--accent); }
  .proj-selector-btn .arrow { font-size: 9px; color: var(--muted); margin-left: 2px; flex-shrink: 0; }
  .proj-selector-dropdown {
    display: none; position: absolute; top: calc(100% + 4px); left: 0;
    min-width: 220px; max-width: 320px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); box-shadow: 0 8px 24px rgba(0,0,0,.4);
    z-index: 50; overflow: hidden;
  }
  .proj-selector-dropdown.open { display: block; }
  .proj-selector-item {
    display: flex; align-items: center; gap: 8px;
    padding: 8px 12px; font-size: 12px; cursor: pointer;
    border-bottom: 1px solid var(--border);
    overflow: hidden;
  }
  .proj-selector-item:last-child { border-bottom: none; }
  .proj-selector-item:hover { background: rgba(88,166,255,.08); }
  .proj-selector-item.active { background: rgba(88,166,255,.12); color: var(--accent); }
  .proj-selector-item .pi-name { font-weight: 600; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .proj-selector-item .pi-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }

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
  .proj-card { cursor: pointer; }
  .proj-card:hover { border-color: var(--accent); }
  .proj-card.selected { border-color: var(--accent); background: rgba(88,166,255,.06); }
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

  /* ── Assistant tab ── */
  .assistant-chips {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 4px;
  }
  .chip-label { font-size: 11px; color: var(--muted); margin-right: 4px; white-space: nowrap; }
  .assist-chip {
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    cursor: pointer;
    transition: background .15s, border-color .15s;
    white-space: nowrap;
  }
  .assist-chip:hover { background: rgba(88,166,255,.12); border-color: var(--accent); color: var(--accent); }
  .assistant-textarea {
    resize: none;
    overflow: hidden;
    min-height: 36px;
    max-height: 120px;
    line-height: 1.5;
  }
  .assistant-streaming-cursor {
    display: inline-block;
    width: 2px;
    height: 14px;
    background: var(--accent);
    margin-left: 2px;
    vertical-align: text-bottom;
    animation: blink 1s step-end infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

  /* ── Knowledge Base tab ── */
  .kb-tab-toolbar {
    display: flex; align-items: center; gap: 10px; padding: 12px 0 10px; flex-wrap: wrap;
  }
  .kb-search-wrap { flex: 1; min-width: 160px; max-width: 320px; }
  .kb-search-input { width: 100%; }
  .kb-add-form {
    background: var(--card-bg); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 14px 16px; margin-bottom: 16px;
  }
  .kb-form-row {
    display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px;
  }
  .kb-form-row .form-label { width: 48px; padding-top: 7px; flex-shrink: 0; }
  .kb-form-row .form-input, .kb-form-row textarea.form-input { flex: 1; }
  .kb-new-body { resize: vertical; font-family: inherit; }
  .kb-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 14px;
    margin-top: 4px;
  }
  .kb-entry-card {
    background: var(--card-bg); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 14px 14px 10px; display: flex; flex-direction: column; gap: 8px;
    position: relative; transition: border-color .15s;
  }
  .kb-entry-card:hover { border-color: var(--accent); }
  .kb-entry-title {
    font-weight: 600; font-size: 14px; color: var(--text); margin: 0;
    padding-right: 28px; word-break: break-word;
  }
  .kb-entry-body {
    font-size: 12px; color: var(--muted); line-height: 1.5;
    display: -webkit-box; -webkit-line-clamp: 4; -webkit-box-orient: vertical;
    overflow: hidden; word-break: break-word; white-space: pre-wrap;
  }
  .kb-tags { display: flex; flex-wrap: wrap; gap: 4px; }
  .kb-tag {
    font-size: 10px; background: rgba(88,166,255,.12); color: var(--accent);
    border-radius: 10px; padding: 1px 7px; font-weight: 500;
  }
  .kb-card-del {
    position: absolute; top: 8px; right: 8px; background: none; border: none;
    cursor: pointer; color: var(--muted); padding: 2px 5px; font-size: 14px;
    border-radius: 4px; line-height: 1;
  }
  .kb-card-del:hover { color: #ef4444; background: rgba(239,68,68,.1); }

  /* ── Analytics tab ── */
  .analytics-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
  }
  .analytics-card-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .04em;
    margin-bottom: 10px;
  }
  @media (max-width: 600px) {
    .analytics-grid { grid-template-columns: 1fr !important; }
  }

  /* ── Dependency graph tab ── */
  .deps-toolbar {
    display: flex; align-items: center; gap: 10px; padding: 12px 0 10px; flex-wrap: wrap;
  }
  .deps-container {
    position: relative; width: 100%; border: 1px solid var(--border); border-radius: var(--radius);
    background: var(--card-bg); overflow: hidden; min-height: 420px;
  }
  .deps-svg {
    display: block; width: 100%; height: 520px; cursor: default;
  }
  @media (max-width: 600px) { .deps-svg { height: 340px; } }
  .deps-empty {
    text-align: center; padding: 60px 20px; color: var(--muted);
  }
  /* SVG node circles */
  .deps-node { cursor: pointer; }
  .deps-node circle { stroke-width: 2.5; transition: r .15s; }
  .deps-node:hover circle { filter: brightness(1.2); }
  .deps-node text { font-size: 10px; fill: var(--text); pointer-events: none; user-select: none; }
  /* Edge lines with arrowheads */
  .deps-edge { stroke: var(--muted); stroke-width: 1.5; fill: none; marker-end: url(#deps-arrow); }
  /* Node status colors */
  .deps-node-pending    circle { fill: #6b7280; stroke: #9ca3af; }
  .deps-node-in_progress circle { fill: #3b82f6; stroke: #60a5fa; }
  .deps-node-done       circle { fill: #22c55e; stroke: #4ade80; }
  .deps-node-failed     circle { fill: #ef4444; stroke: #f87171; }
  .deps-node-skipped    circle { fill: #a855f7; stroke: #c084fc; }
  .deps-node-timed_out  circle { fill: #f97316; stroke: #fb923c; }
  /* Sidebar */
  .deps-sidebar {
    position: absolute; top: 0; right: 0; width: min(300px, 88%); height: 100%;
    background: var(--card-bg); border-left: 1px solid var(--border);
    box-shadow: -4px 0 16px rgba(0,0,0,.2); display: flex; flex-direction: column;
    z-index: 10; overflow-y: auto;
  }
  .deps-sidebar-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 14px 10px; border-bottom: 1px solid var(--border); flex-shrink: 0;
  }
  .deps-sidebar-title { font-weight: 600; font-size: 14px; color: var(--text); flex: 1; }
  .deps-sidebar-close {
    background: none; border: none; color: var(--muted); cursor: pointer;
    font-size: 16px; line-height: 1; padding: 2px 5px; border-radius: 4px;
  }
  .deps-sidebar-close:hover { color: var(--text); background: var(--hover-bg); }
  .deps-sidebar-body { padding: 12px 14px; font-size: 12px; color: var(--muted); flex: 1; }
  .deps-sidebar-body .deps-detail-row { margin-bottom: 8px; line-height: 1.5; }
  .deps-sidebar-body .deps-detail-label { font-weight: 600; color: var(--text); display: block; }
  .deps-legend { display: flex; flex-wrap: wrap; gap: 10px; padding: 8px 0 4px; font-size: 11px; color: var(--muted); }
  .deps-legend-item { display: flex; align-items: center; gap: 5px; }
  .deps-legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }

  /* ── Timeline / Gantt chart ── */
  .timeline-toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
    flex-wrap: wrap;
  }
  .timeline-chart-wrap {
    overflow-x: auto;
    overflow-y: visible;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0;
    position: relative;
  }
  .timeline-chart-wrap svg { display: block; }
  .tl-task-label { font-size: 12px; fill: var(--text); }
  .tl-tick-label { font-size: 10px; fill: var(--muted); }
  .tl-grid-line  { stroke: var(--border); stroke-width: 1; }
  .tl-row-even   { fill: var(--surface); }
  .tl-row-odd    { fill: var(--bg); }
  .tl-bar        { rx: 4; ry: 4; cursor: pointer; opacity: 0.88; transition: opacity .15s, filter .15s; }
  .tl-bar:hover  { opacity: 1; filter: brightness(1.15); }
  .tl-now-line   { stroke: #f87171; stroke-width: 2; stroke-dasharray: 4 3; }
  .tl-dep-arrow  { fill: none; stroke: var(--muted); stroke-width: 1.5; marker-end: url(#arrowhead); opacity: 0.6; }
  .tl-tooltip {
    position: fixed;
    pointer-events: none;
    display: none;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 12px;
    color: var(--text);
    box-shadow: 0 4px 12px rgba(0,0,0,.55);
    max-width: 320px;
    z-index: 9999;
    line-height: 1.5;
  }
  .tl-tooltip strong { display: block; margin-bottom: 4px; font-size: 13px; color: var(--text); }
  .tl-tooltip .tl-tip-row { color: var(--muted); }
  .tl-tooltip .tl-tip-status { font-weight: 600; }
  .timeline-legend {
    display: flex;
    gap: 14px;
    margin-top: 12px;
    flex-wrap: wrap;
  }
  .tl-legend-item {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: var(--muted);
  }
  .tl-legend-dot {
    width: 12px;
    height: 12px;
    border-radius: 2px;
    flex-shrink: 0;
  }

  /* ══════════════════════════════════════════════════════════════
     MOBILE RESPONSIVE — hamburger, FAB, breakpoints
     ══════════════════════════════════════════════════════════════ */

  /* ── Hamburger button (hidden on desktop) ── */
  .hamburger-btn {
    display: none;
    background: none;
    border: none;
    color: var(--text);
    cursor: pointer;
    padding: 6px;
    border-radius: 6px;
    min-width: 44px;
    min-height: 44px;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .hamburger-btn:hover { background: var(--hover-bg); }
  .hamburger-btn svg { display: block; pointer-events: none; }

  /* ── Mobile nav overlay + slide-in panel ── */
  .mobile-nav-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.6);
    z-index: 90;
  }
  .mobile-nav-overlay.open { display: block; }
  .mobile-nav-panel {
    position: absolute;
    top: 0; left: 0; bottom: 0;
    width: 240px;
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 12px 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    transform: translateX(-100%);
    transition: transform .2s ease;
  }
  .mobile-nav-overlay.open .mobile-nav-panel {
    transform: translateX(0);
  }
  .mobile-nav-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 4px 8px 12px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 6px;
  }
  .mobile-nav-title {
    font-size: 13px;
    font-weight: 700;
    color: var(--accent);
  }
  .mobile-nav-close {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 18px;
    min-width: 44px;
    min-height: 44px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    line-height: 1;
  }
  .mobile-nav-close:hover { color: var(--text); background: var(--hover-bg); }
  .mobile-nav-panel .m-tab-btn {
    width: 100%;
    text-align: left;
    padding: 12px 14px;
    font-size: 14px;
    font-weight: 500;
    border-radius: 8px;
    min-height: 44px;
    background: none;
    border: 1px solid transparent;
    color: var(--muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .mobile-nav-panel .m-tab-btn:hover { color: var(--text); background: var(--hover-bg); }
  .mobile-nav-panel .m-tab-btn.active { color: var(--text); background: var(--bg); border-color: var(--border); }
  .mobile-nav-panel .m-tab-btn .m-tab-icon { font-size: 16px; width: 20px; text-align: center; flex-shrink: 0; }

  /* ── FAB (floating action button, shown on mobile) ── */
  #fab-add-task {
    display: none;
    position: fixed;
    bottom: 24px;
    right: 20px;
    width: 56px;
    height: 56px;
    border-radius: 50%;
    background: var(--accent);
    color: #000;
    border: none;
    font-size: 24px;
    line-height: 1;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(0,0,0,.45);
    align-items: center;
    justify-content: center;
    z-index: 80;
    transition: background .15s, transform .1s;
    font-weight: 700;
  }
  #fab-add-task:hover { background: var(--accent-hover); transform: scale(1.05); }
  #fab-add-task:active { transform: scale(.95); }

  /* ══════════════════════════════════════════════════════════════
     BREAKPOINT: ≤ 767px  (phones — iPhone SE and up)
     ══════════════════════════════════════════════════════════════ */
  @media (max-width: 767px) {
    /* Show hamburger, hide desktop tab-nav */
    .hamburger-btn { display: inline-flex; }
    .tab-nav { display: none; }

    /* Header: compact, no-wrap */
    header { padding: 8px 12px; gap: 8px; }
    header h1 { font-size: 14px; }
    .updated-at { display: none; }

    /* Keyboard shortcut footer: hide (no room on phone) */
    #kb-footer { display: none; }
    body { padding-bottom: 72px; } /* FAB + safe area */

    /* Main */
    main { padding: 12px; max-width: 100%; }

    /* Stats grid: 2 columns */
    .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
    .stat-value { font-size: 18px; }

    /* Task cards: wrap actions below body */
    .task-item { flex-wrap: wrap; gap: 8px; }
    .task-actions { max-width: 100%; width: 100%; flex-wrap: wrap; }
    .task-desc { white-space: normal; }

    /* Touch targets: min 44px */
    .btn { min-height: 44px; padding: 10px 14px; }
    .act { min-height: 44px; padding: 6px 10px; font-size: 12px; }

    /* Add task bar: stack on mobile (FAB handles quick add) */
    .add-task-bar { flex-direction: column; }
    .add-task-bar input, .add-task-bar button { width: 100%; }

    /* Form rows: stack */
    .form-row { flex-direction: column; }
    .adv-grid  { grid-template-columns: 1fr; }
    .adv-row   { flex-direction: column; }

    /* Timeline / Gantt: horizontal scroll on small screen */
    .timeline-chart-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
    #timelineChart { min-width: 0; }
    #timelineChart svg { min-width: 560px; }

    /* Chat */
    .chat-layout { height: calc(100vh - 160px); }
    .chat-bubble { max-width: 88%; }

    /* Controls strip */
    .controls { gap: 6px; }
    .controls .btn { flex: 1 1 auto; }

    /* Project cards: stack */
    .proj-card { flex-direction: column; align-items: flex-start; gap: 8px; }
    .proj-goal { max-width: 100%; }
    .proj-actions { width: 100%; }
    .proj-actions .btn { flex: 1; justify-content: center; }

    /* Toast: full-width */
    #toast { right: 12px; left: 12px; max-width: none; bottom: 12px; }

    /* Init panel */
    .init-panel { padding: 16px; }

    /* FAB: show only on tasks tab (controlled by JS), hidden by default */
    #fab-add-task { display: flex; }

    /* Project selector: constrain width */
    .proj-selector-wrap { max-width: 160px; }
    .proj-selector-btn  { max-width: 140px; }

    /* Step meta: compact */
    .step-meta > *:not(:first-child):not(:last-child) { display: none; }
  }

  /* ══════════════════════════════════════════════════════════════
     BREAKPOINT: 480px–768px  (tablets — iPad portrait)
     ══════════════════════════════════════════════════════════════ */
  @media (min-width: 480px) and (max-width: 768px) {
    /* Keep tab-nav visible but make it horizontally scrollable */
    .tab-nav {
      display: flex;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: none;
      flex-wrap: nowrap;
    }
    .tab-nav::-webkit-scrollbar { display: none; }

    /* Hide hamburger on tablet since nav is visible */
    .hamburger-btn { display: none; }

    /* FAB: hide on tablet */
    #fab-add-task { display: none; }

    /* Stats grid: 3 columns */
    .stats-grid { grid-template-columns: repeat(3, 1fr); }

    /* Main: modest padding */
    main { padding: 16px; }

    /* Touch targets */
    .btn { min-height: 44px; }
    .act { min-height: 36px; }

    /* Timeline: horizontal scroll */
    .timeline-chart-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  }
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
    <!-- Project selector (shown in multi-project mode) -->
    <div class="proj-selector-wrap" id="projSelectorWrap">
      <button class="tab-btn" onclick="clearProjectSelection()" style="padding:4px 10px;font-size:12px" id="projBackBtn" title="Back to all projects">&#8592;</button>
      <div style="position:relative">
        <button class="proj-selector-btn" id="projSelectorBtn" onclick="toggleProjectSelector()" title="Switch project">
          <span id="projSelectorLabel">All Projects</span>
          <span class="arrow">&#9660;</span>
        </button>
        <div class="proj-selector-dropdown" id="projSelectorDropdown"></div>
      </div>
    </div>
    <!-- Project breadcrumb (kept for compatibility; hidden since selector replaces it) -->
    <div id="projectBreadcrumb" style="display:none;align-items:center;gap:8px;flex-shrink:0">
      <button class="tab-btn" onclick="clearProjectSelection()" style="padding:4px 10px;font-size:12px">&#8592; Projects</button>
      <span id="breadcrumbName" style="font-weight:600;color:var(--accent);font-size:13px;white-space:nowrap"></span>
    </div>
    <!-- Hamburger button (mobile only) -->
    <button class="hamburger-btn" id="hamburgerBtn" onclick="openMobileNav()" aria-label="Open navigation menu" aria-expanded="false">
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
        <line x1="3" y1="5"  x2="17" y2="5"/>
        <line x1="3" y1="10" x2="17" y2="10"/>
        <line x1="3" y1="15" x2="17" y2="15"/>
      </svg>
    </button>

    <div class="tab-nav" id="tabNav">
      <button class="tab-btn active" onclick="switchTab('overview')"  id="tbtn-overview">Overview</button>
      <button class="tab-btn"        onclick="switchTab('tasks')"     id="tbtn-tasks">Tasks</button>
      <button class="tab-btn"        onclick="switchTab('kanban')"    id="tbtn-kanban">Kanban</button>
      <button class="tab-btn"        onclick="switchTab('timeline')"  id="tbtn-timeline">Timeline</button>
      <button class="tab-btn"        onclick="switchTab('kb')"        id="tbtn-kb">Knowledge Base</button>
      <button class="tab-btn"        onclick="switchTab('deps')"      id="tbtn-deps">Dependencies</button>
      <button class="tab-btn"        onclick="switchTab('risk-matrix')" id="tbtn-risk-matrix">Risk Matrix</button>
      <button class="tab-btn"        onclick="switchTab('analytics')" id="tbtn-analytics">Analytics</button>
      <button class="tab-btn"        onclick="switchTab('chat')"      id="tbtn-chat">Chat</button>
      <button class="tab-btn"        onclick="switchTab('assistant')" id="tbtn-assistant">Assistant</button>
      <button class="tab-btn"        onclick="switchTab('projects')"  id="tbtn-projects">Projects</button>
      <button class="tab-btn"        onclick="switchTab('suggest')"   id="tbtn-suggest">Suggest</button>
      <button class="tab-btn"        onclick="switchTab('settings')"  id="tbtn-settings">Settings</button>
    </div>
    <div class="spacer"></div>
    <button class="theme-toggle-btn" id="themeToggleBtn" onclick="toggleTheme()" aria-label="Toggle dark/light mode" title="Toggle theme">
      <span id="themeToggleIcon">&#9788;</span>
    </button>
    <div class="updated-at" id="updatedAt"></div>
  </header>

  <!-- ── Presence bar ── -->
  <div id="presenceBar" role="status" aria-live="polite" aria-label="Connected collaborators"></div>

  <!-- ── Conflict toast ── -->
  <div id="conflictToast" role="alert" aria-live="assertive" onclick="dismissConflictToast()">
    <span class="conflict-icon">&#x26A0;&#xFE0F;</span>
    <div class="conflict-body">
      <div class="conflict-title">Edit conflict detected</div>
      <div class="conflict-msg" id="conflictMsg">Another user edited this task recently.</div>
    </div>
    <span class="conflict-dismiss" aria-label="Dismiss">&#x2715;</span>
  </div>

  <!-- ── Unified search / filter bar ── -->
  <div id="filterBar" class="filter-bar" style="display:none" role="search" aria-label="Filter tasks">
    <div class="filter-bar-inner">
      <input type="search" id="filterQ" class="filter-search-input" placeholder="&#x1F50D;&#xFE0E; Search title &amp; description…" aria-label="Search tasks" oninput="onFilterChange()">
      <div class="filter-group filter-status-group">
        <span class="filter-label">Status:</span>
        <label class="filter-check"><input type="checkbox" class="filter-status-cb" value="pending" onchange="onFilterChange()"> Pending</label>
        <label class="filter-check"><input type="checkbox" class="filter-status-cb" value="in_progress" onchange="onFilterChange()"> In Progress</label>
        <label class="filter-check"><input type="checkbox" class="filter-status-cb" value="done" onchange="onFilterChange()"> Done</label>
        <label class="filter-check"><input type="checkbox" class="filter-status-cb" value="failed" onchange="onFilterChange()"> Failed</label>
      </div>
      <div class="filter-group">
        <span class="filter-label">Priority:</span>
        <select id="filterPriority" class="filter-select" aria-label="Filter by priority" onchange="onFilterChange()">
          <option value="">Any</option>
          <option value="1">P1 Critical</option>
          <option value="2">P2 High</option>
          <option value="3">P3 Medium</option>
          <option value="4">P4 Low</option>
        </select>
      </div>
      <div class="filter-group">
        <span class="filter-label">Assignee:</span>
        <select id="filterAssignee" class="filter-select" aria-label="Filter by assignee" onchange="onFilterChange()">
          <option value="">Any</option>
        </select>
      </div>
      <div class="filter-group">
        <span class="filter-label">Tags:</span>
        <div class="filter-tags-wrap" id="filterTagsWrap">
          <button type="button" class="filter-tag-toggle" id="filterTagToggle" onclick="toggleTagDropdown(event)" aria-haspopup="listbox" aria-expanded="false">
            Tags <span id="filterTagCount"></span>&#9662;
          </button>
          <div class="filter-tags-panel" id="filterTagsPanel" role="listbox" aria-label="Tag filter"></div>
        </div>
      </div>
      <button class="btn filter-clear-btn" id="filterClearBtn" onclick="clearFilters()" style="display:none" title="Clear all filters">Clear filters</button>
      <span class="filter-badge" id="filterBadge" aria-live="polite"></span>
    </div>
  </div>

  <!-- ── Mobile navigation overlay ── -->
  <div class="mobile-nav-overlay" id="mobileNavOverlay" onclick="if(event.target===this)closeMobileNav()" aria-hidden="true">
    <nav class="mobile-nav-panel" role="navigation" aria-label="Main navigation">
      <div class="mobile-nav-header">
        <span class="mobile-nav-title">cloop</span>
        <button class="mobile-nav-close" onclick="closeMobileNav()" aria-label="Close navigation">&#x2715;</button>
      </div>
      <button class="m-tab-btn" onclick="switchTab('overview')"  id="mtbtn-overview"><span class="m-tab-icon">&#128200;</span>Overview</button>
      <button class="m-tab-btn" onclick="switchTab('tasks')"     id="mtbtn-tasks"><span class="m-tab-icon">&#10003;</span>Tasks</button>
      <button class="m-tab-btn" onclick="switchTab('kanban')"    id="mtbtn-kanban"><span class="m-tab-icon">&#9783;</span>Kanban</button>
      <button class="m-tab-btn" onclick="switchTab('timeline')"  id="mtbtn-timeline"><span class="m-tab-icon">&#128197;</span>Timeline</button>
      <button class="m-tab-btn" onclick="switchTab('kb')"        id="mtbtn-kb"><span class="m-tab-icon">&#128218;</span>Knowledge Base</button>
      <button class="m-tab-btn" onclick="switchTab('deps')"      id="mtbtn-deps"><span class="m-tab-icon">&#128279;</span>Dependencies</button>
      <button class="m-tab-btn" onclick="switchTab('risk-matrix')" id="mtbtn-risk-matrix"><span class="m-tab-icon">&#9888;</span>Risk Matrix</button>
      <button class="m-tab-btn" onclick="switchTab('analytics')" id="mtbtn-analytics"><span class="m-tab-icon">&#128200;</span>Analytics</button>
      <button class="m-tab-btn" onclick="switchTab('chat')"      id="mtbtn-chat"><span class="m-tab-icon">&#128172;</span>Chat</button>
      <button class="m-tab-btn" onclick="switchTab('assistant')" id="mtbtn-assistant"><span class="m-tab-icon">&#129302;</span>Assistant</button>
      <button class="m-tab-btn" onclick="switchTab('projects')"  id="mtbtn-projects"><span class="m-tab-icon">&#128193;</span>Projects</button>
      <button class="m-tab-btn" onclick="switchTab('suggest')"   id="mtbtn-suggest"><span class="m-tab-icon">&#128161;</span>Suggest</button>
      <button class="m-tab-btn" onclick="switchTab('settings')"  id="mtbtn-settings"><span class="m-tab-icon">&#9881;</span>Settings</button>
    </nav>
  </div>

  <main>
    <!-- ═══════════════════════════════════════════════════════════ OVERVIEW -->
    <div id="tab-overview" class="tab-panel active">

      <!-- Multi-project summary (shown in multi-project mode when no project is selected) -->
      <div id="multiProjectOverview" style="display:none">
        <div class="section">
          <div class="section-title">All Projects — Overview</div>
          <div id="multiProjectCards" class="stats-grid" style="margin-top:12px"></div>
        </div>
      </div>

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
          <div class="section-title" id="overviewSectionTitle">Overview</div>
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

    <!-- ══════════════════════════════════════════════════════════ KANBAN -->
    <div id="tab-kanban" class="tab-panel">
      <div class="kanban-toolbar">
        <span class="section-title" style="margin:0">Kanban Board</span>
        <button class="btn" id="kanbanCompactBtn" style="padding:3px 10px;font-size:11px" onclick="toggleKanbanCompact()">Compact</button>
        <button class="btn" style="padding:3px 10px;font-size:11px" onclick="refreshState()">Refresh</button>
      </div>
      <div id="kanbanBoard" class="kanban-board">
        <div class="kanban-col" id="kb-col-pending"     data-status="pending">
          <div class="kanban-col-header"><span class="kanban-col-title">Pending</span><span class="kanban-col-count" id="kb-cnt-pending">0</span></div>
          <div class="kanban-col-body" id="kb-body-pending"
               ondragover="kanbanColDragOver(event,'pending')"
               ondragleave="kanbanColDragLeave(event,'pending')"
               ondrop="kanbanColDrop(event,'pending')">
          </div>
        </div>
        <div class="kanban-col" id="kb-col-in_progress" data-status="in_progress">
          <div class="kanban-col-header"><span class="kanban-col-title">In Progress</span><span class="kanban-col-count" id="kb-cnt-in_progress">0</span></div>
          <div class="kanban-col-body" id="kb-body-in_progress"
               ondragover="kanbanColDragOver(event,'in_progress')"
               ondragleave="kanbanColDragLeave(event,'in_progress')"
               ondrop="kanbanColDrop(event,'in_progress')">
          </div>
        </div>
        <div class="kanban-col" id="kb-col-done"        data-status="done">
          <div class="kanban-col-header"><span class="kanban-col-title">Done</span><span class="kanban-col-count" id="kb-cnt-done">0</span></div>
          <div class="kanban-col-body" id="kb-body-done"
               ondragover="kanbanColDragOver(event,'done')"
               ondragleave="kanbanColDragLeave(event,'done')"
               ondrop="kanbanColDrop(event,'done')">
          </div>
        </div>
        <div class="kanban-col" id="kb-col-failed"      data-status="failed">
          <div class="kanban-col-header"><span class="kanban-col-title">Failed / Skipped</span><span class="kanban-col-count" id="kb-cnt-failed">0</span></div>
          <div class="kanban-col-body" id="kb-body-failed"
               ondragover="kanbanColDragOver(event,'failed')"
               ondragleave="kanbanColDragLeave(event,'failed')"
               ondrop="kanbanColDrop(event,'failed')">
          </div>
        </div>
      </div>
    </div>

    <!-- ══════════════════════════════════════════════════════════ TIMELINE -->
    <div id="tab-timeline" class="tab-panel">
      <div class="timeline-toolbar">
        <span class="section-title" style="margin:0">Gantt Chart</span>
        <button class="btn" style="padding:3px 10px;font-size:11px" onclick="loadTimeline()">Refresh</button>
        <span id="timelineStatus" style="font-size:11px;color:var(--muted)"></span>
      </div>
      <div id="timelineEmpty" class="empty-state" style="display:none">
        <h3>No tasks yet</h3>
        <p>Run <code>cloop run --pm</code> to generate a task plan, then return here to see the Gantt chart.</p>
      </div>
      <div id="timelineChart" class="timeline-chart-wrap">
        <div style="color:var(--muted);font-size:12px;padding:20px 0">Loading timeline...</div>
      </div>
      <div class="timeline-legend" id="timelineLegend" style="display:none">
        <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#22c55e"></div>Done</div>
        <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#3b82f6"></div>In Progress</div>
        <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#9ca3af"></div>Pending</div>
        <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#ef4444"></div>Failed</div>
        <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#f97316"></div>Timed Out</div>
        <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#6b7280"></div>Skipped</div>
        <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#f87171;width:2px;height:14px;border-radius:1px"></div>Now</div>
      </div>
      <!-- Tooltip -->
      <div id="tlTooltip" class="tl-tooltip"></div>
    </div>

    <!-- ══════════════════════════════════════════════ KNOWLEDGE BASE -->
    <div id="tab-kb" class="tab-panel">
      <div class="kb-tab-toolbar">
        <span class="section-title" style="margin:0">Knowledge Base</span>
        <div class="kb-search-wrap">
          <input class="form-input kb-search-input" id="kbSearchInput" placeholder="Search entries..." oninput="filterKBCards(this.value)">
        </div>
        <button class="btn primary" style="padding:4px 12px;font-size:12px" onclick="toggleKBAddForm()">+ Add Entry</button>
        <button class="btn" style="padding:4px 10px;font-size:12px" onclick="loadKB()">Refresh</button>
      </div>

      <!-- Add Entry form (hidden by default) -->
      <div id="kbAddForm" class="kb-add-form" style="display:none">
        <div class="section-title">New Entry</div>
        <div class="kb-form-row">
          <label class="form-label">Title</label>
          <input class="form-input" id="kbNewTitle" placeholder="Entry title..." style="flex:1">
        </div>
        <div class="kb-form-row">
          <label class="form-label">Body</label>
          <textarea class="form-input kb-new-body" id="kbNewBody" placeholder="Entry content..." rows="4"></textarea>
        </div>
        <div class="kb-form-row">
          <label class="form-label">Tags</label>
          <input class="form-input" id="kbNewTags" placeholder="Comma-separated tags, e.g. api,auth" style="flex:1">
        </div>
        <div style="display:flex;gap:8px;margin-top:6px">
          <button class="btn primary" onclick="submitKBAdd()">Save Entry</button>
          <button class="btn" onclick="toggleKBAddForm()">Cancel</button>
        </div>
      </div>

      <div id="kbEmpty" class="empty-state" style="display:none">
        <h3>No entries yet</h3>
        <p>Click <strong>+ Add Entry</strong> to add your first knowledge base entry.</p>
      </div>
      <div id="kbGrid" class="kb-grid"></div>
    </div>

    <!-- ══════════════════════════════════════════════ DEPENDENCIES -->
    <div id="tab-deps" class="tab-panel">
      <div class="deps-toolbar">
        <span class="section-title" style="margin:0">Task Dependency Graph</span>
        <button class="btn" style="padding:3px 10px;font-size:11px" onclick="loadDeps()">Refresh</button>
        <label style="font-size:12px;color:var(--muted);display:flex;align-items:center;gap:4px;margin-left:8px">
          <input type="checkbox" id="depsShowAll" onchange="loadDeps()"> Show all tasks
        </label>
      </div>
      <div id="depsEmpty" class="deps-empty" style="display:none">
        <div style="font-size:32px;margin-bottom:12px">&#128279;</div>
        <div style="font-size:15px;font-weight:600;margin-bottom:6px">No dependencies defined</div>
        <div style="font-size:13px;color:var(--muted)">Use <code>cloop task deps</code> to add dependencies between tasks.</div>
      </div>
      <div class="deps-legend">
        <span class="deps-legend-item"><span class="deps-legend-dot" style="background:#6b7280"></span>Pending</span>
        <span class="deps-legend-item"><span class="deps-legend-dot" style="background:#3b82f6"></span>In Progress</span>
        <span class="deps-legend-item"><span class="deps-legend-dot" style="background:#22c55e"></span>Done</span>
        <span class="deps-legend-item"><span class="deps-legend-dot" style="background:#ef4444"></span>Failed</span>
        <span class="deps-legend-item"><span class="deps-legend-dot" style="background:#a855f7"></span>Skipped</span>
        <span class="deps-legend-item"><span class="deps-legend-dot" style="background:#f97316"></span>Timed Out</span>
      </div>
      <div id="depsContainer" class="deps-container">
        <svg id="depsSvg" class="deps-svg"></svg>
      </div>
      <!-- Detail sidebar -->
      <div id="depsSidebar" class="deps-sidebar" style="display:none">
        <div class="deps-sidebar-header">
          <span id="depsSidebarTitle" class="deps-sidebar-title"></span>
          <button class="deps-sidebar-close" onclick="closeDepsDetail()" aria-label="Close">&#x2715;</button>
        </div>
        <div id="depsSidebarBody" class="deps-sidebar-body"></div>
      </div>
    </div>

    <!-- ══════════════════════════════════════════════ RISK MATRIX -->
    <div id="tab-risk-matrix" class="tab-panel">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
        <span class="section-title" style="margin:0">Risk Matrix</span>
        <button class="btn" style="padding:3px 10px;font-size:11px" onclick="loadRiskMatrix()">Refresh</button>
        <span id="rmStatus" style="font-size:11px;color:var(--muted)"></span>
      </div>
      <div id="rmEmpty" class="empty-state" style="display:none">
        <h3>No cached scores</h3>
        <p>Run <code>cloop task ai-risk-matrix --apply</code> to score and cache risk/impact data, then refresh.</p>
      </div>
      <div id="rmNoTasks" class="empty-state" style="display:none">
        <h3>No active tasks</h3>
        <p>All tasks are complete or no plan has been created yet.</p>
      </div>
      <!-- Canvas chart -->
      <div id="rmChartWrap" style="display:none">
        <canvas id="rmCanvas" style="border-radius:8px;display:block;max-width:100%"></canvas>
        <div style="display:flex;gap:14px;margin-top:10px;flex-wrap:wrap" id="rmLegend">
          <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(239,68,68,0.25);border:1px solid #ef4444"></div>Critical</div>
          <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(249,115,22,0.25);border:1px solid #f97316"></div>Mitigate</div>
          <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(34,197,94,0.25);border:1px solid #22c55e"></div>Leverage</div>
          <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(107,114,128,0.25);border:1px solid #6b7280"></div>Defer</div>
        </div>
        <p style="font-size:11px;color:var(--muted);margin-top:8px">Tip: Run <code>cloop task ai-risk-matrix --apply</code> to refresh scores.</p>
      </div>
      <!-- Table -->
      <div id="rmTable" style="display:none;margin-top:18px;overflow-x:auto">
        <table style="border-collapse:collapse;width:100%;font-size:13px">
          <thead>
            <tr>
              <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">#</th>
              <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Task</th>
              <th style="text-align:center;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Risk</th>
              <th style="text-align:center;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Impact</th>
              <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Quadrant</th>
            </tr>
          </thead>
          <tbody id="rmTableBody"></tbody>
        </table>
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

    <!-- ══════════════════════════════════════════════════════ ASSISTANT -->
    <div id="tab-assistant" class="tab-panel">
      <div class="chat-layout">
        <div class="chat-header">
          <span class="section-title" style="margin:0">&#129302; Plan Assistant</span>
          <span class="chat-hint">Ask questions about your plan — the AI has full task context</span>
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" onclick="clearAssistantPanel()">Clear</button>
        </div>
        <div class="assistant-chips" id="assistantChips">
          <span class="chip-label">Try asking:</span>
          <button class="assist-chip" onclick="assistantChipAsk('What tasks are blocked?')">What tasks are blocked?</button>
          <button class="assist-chip" onclick="assistantChipAsk('What should I work on next?')">What should I work on next?</button>
          <button class="assist-chip" onclick="assistantChipAsk('Summarise progress for stakeholders')">Summarise progress for stakeholders</button>
          <button class="assist-chip" onclick="assistantChipAsk('Which tasks are overdue or at risk?')">Which tasks are overdue or at risk?</button>
          <button class="assist-chip" onclick="assistantChipAsk('Give me a risk assessment of the current plan')">Risk assessment</button>
        </div>
        <div class="chat-messages" id="assistantMessages">
          <div class="chat-welcome" id="assistantWelcome">
            <div class="chat-welcome-icon">&#129302;</div>
            <div class="chat-welcome-title">Plan-Aware Assistant</div>
            <div class="chat-welcome-text">I have full knowledge of your plan — tasks, statuses, priorities, and annotations.<br>
            Ask me anything about your project or click a suggested question above.</div>
          </div>
        </div>
        <div class="chat-input-bar">
          <textarea class="form-input chat-input assistant-textarea" id="assistantInput"
                    rows="1" placeholder="Ask about your plan..."
                    onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();submitAssistantChat();}
                               autoGrowTextarea(this);"></textarea>
          <button class="btn primary" onclick="submitAssistantChat()" style="flex-shrink:0">
            <svg viewBox="0 0 16 16" fill="currentColor" width="13" height="13"><path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11z"/></svg>
            Send
          </button>
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
          <button class="btn primary" style="padding:4px 10px;font-size:12px" onclick="openNewProjectModal()">+ New Project</button>
          <button id="toggleCompletedProjectsBtn" class="btn" style="margin-left:auto;padding:3px 10px;font-size:11px" onclick="toggleCompletedProjects()">Show completed</button>
        </div>
        <div id="projListEmpty" style="display:none;color:var(--muted);font-size:13px;padding:12px 0">
          No projects loaded. Use <code>cloop ui --projects /path/a /path/b</code> or <code>--scan /root/Projects</code>.
        </div>
        <div id="projList" style="display:flex;flex-direction:column;gap:10px"></div>
      </div>

    </div>

    <!-- ═══════════════════════════════════════════════════════ ANALYTICS -->
    <div id="tab-analytics" class="tab-panel">
      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          Analytics
          <div style="display:flex;align-items:center;gap:8px;margin-left:auto;flex-wrap:wrap">
            <label style="font-size:12px;color:var(--muted)">From:</label>
            <input type="date" id="analyticsFrom" class="form-input" style="width:140px;padding:4px 8px;font-size:12px" onchange="loadAnalytics()">
            <label style="font-size:12px;color:var(--muted)">To:</label>
            <input type="date" id="analyticsTo" class="form-input" style="width:140px;padding:4px 8px;font-size:12px" onchange="loadAnalytics()">
            <button class="btn" style="padding:4px 10px;font-size:12px" onclick="analyticsResetRange()">Last 30d</button>
            <button class="btn" style="padding:4px 10px;font-size:12px" onclick="loadAnalytics()">&#8635; Refresh</button>
          </div>
        </div>

        <!-- Row 1: Donut + Velocity -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px" class="analytics-grid">
          <div class="analytics-card">
            <div class="analytics-card-title">Task Status</div>
            <div style="position:relative;height:220px;display:flex;align-items:center;justify-content:center">
              <canvas id="chartStatusDonut" aria-label="Task status donut chart" role="img"></canvas>
            </div>
          </div>
          <div class="analytics-card">
            <div class="analytics-card-title">Velocity — Tasks/Day (last 14 days)</div>
            <div style="position:relative;height:220px">
              <canvas id="chartVelocity" aria-label="Velocity sparkline chart" role="img"></canvas>
            </div>
          </div>
        </div>

        <!-- Row 2: Burndown -->
        <div style="margin-top:16px">
          <div class="analytics-card">
            <div class="analytics-card-title">Task Burn-Down</div>
            <div style="position:relative;height:240px">
              <canvas id="chartBurndown" aria-label="Task burndown chart" role="img"></canvas>
            </div>
          </div>
        </div>

        <!-- Row 3: Cost trend + Latency -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px" class="analytics-grid">
          <div class="analytics-card">
            <div class="analytics-card-title">Provider Cost Trend (USD/day)</div>
            <div style="position:relative;height:240px">
              <canvas id="chartCostTrend" aria-label="Provider cost trend chart" role="img"></canvas>
            </div>
          </div>
          <div class="analytics-card">
            <div class="analytics-card-title">Per-Provider Latency Histogram</div>
            <div style="position:relative;height:240px">
              <canvas id="chartLatency" aria-label="Per-provider latency histogram" role="img"></canvas>
            </div>
            <div id="analyticsLatencyEmpty" style="display:none;color:var(--muted);font-size:12px;text-align:center;padding:8px 0">
              No latency data yet — run tasks to populate.
            </div>
          </div>
        </div>

        <!-- Row 4: Epics progress -->
        <div style="margin-top:16px">
          <div class="analytics-card" id="epicsCard" style="display:none">
            <div class="analytics-card-title">Epic Progress</div>
            <div id="epicsList" style="padding:4px 0"></div>
          </div>
        </div>

        <div id="analyticsEmpty" style="display:none;color:var(--muted);font-size:13px;padding:16px 0;text-align:center">
          No data yet for the selected date range. Run some tasks to see analytics.
        </div>
        <div style="color:var(--muted);font-size:11px;margin-top:10px;text-align:right" id="analyticsLastRefresh"></div>
      </div>
    </div>

  </main>

  <!-- ── FAB: quick task add (mobile only) ── -->
  <button id="fab-add-task" onclick="fabAddTask()" aria-label="Add task" title="Add task" style="display:none">+</button>

</div>

<!-- New Project modal -->
<div id="new-project-overlay" onclick="if(event.target===this)closeNewProjectModal()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:480px;max-width:95vw">
    <h2 style="font-size:15px;font-weight:600;margin-bottom:16px">New Project</h2>
    <div class="form-group">
      <label class="form-label">Directory *</label>
      <input class="form-input" id="npDir" placeholder="/path/to/new-project">
    </div>
    <div class="form-group">
      <label class="form-label">Goal *</label>
      <textarea class="form-textarea" id="npGoal" placeholder="What do you want to build?" style="min-height:70px"></textarea>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Provider</label>
        <select class="form-select" id="npProvider">
          <option value="">default</option>
          <option value="claudecode">claudecode</option>
          <option value="anthropic">anthropic</option>
          <option value="openai">openai</option>
          <option value="ollama">ollama</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Model</label>
        <input class="form-input" id="npModel" placeholder="leave blank for default">
      </div>
    </div>
    <div class="adv-grid" style="margin-bottom:12px">
      <label class="adv-label"><input type="checkbox" id="npPMMode"> PM mode</label>
      <label class="adv-label"><input type="checkbox" id="npAutoRun"> Start run immediately</label>
    </div>
    <div id="npError" style="font-size:12px;color:var(--red);margin-bottom:8px;display:none"></div>
    <div class="modal-footer">
      <button class="btn" onclick="closeNewProjectModal()">Cancel</button>
      <button class="btn primary" onclick="submitNewProject()">Create Project</button>
    </div>
  </div>
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

<!-- ── Command Palette ─────────────────────────────────────────────────── -->
<div id="cmd-backdrop" role="dialog" aria-modal="true" aria-label="Command palette">
  <div id="cmd-palette">
    <div id="cmd-input-wrap">
      <span id="cmd-input-icon">⌘</span>
      <input id="cmd-input" type="text" placeholder="Type a command or search…" autocomplete="off" spellcheck="false" aria-label="Command palette search">
      <span id="cmd-shortcut-hint"><kbd>Esc</kbd> to close</span>
    </div>
    <div id="cmd-results" role="listbox"></div>
    <div id="cmd-footer">
      <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
      <span><kbd>Enter</kbd> select</span>
      <span><kbd>Esc</kbd> close</span>
    </div>
  </div>
</div>

<!-- ── Keyboard shortcut footer ───────────────────────────────────────── -->
<div id="kb-footer" role="complementary" aria-label="Keyboard shortcuts">
  <span><kbd>⌘K</kbd> palette</span>
  <span class="kb-sep">|</span>
  <span><kbd>j</kbd><kbd>k</kbd> navigate tasks</span>
  <span class="kb-sep">|</span>
  <span><kbd>Enter</kbd> open task</span>
  <span class="kb-sep">|</span>
  <span><kbd>n</kbd> new task</span>
  <span class="kb-sep">|</span>
  <span><kbd>r</kbd> refresh</span>
  <span class="kb-sep">|</span>
  <span><kbd>1</kbd>-<kbd>4</kbd> tabs</span>
  <span class="kb-sep">|</span>
  <span><kbd>Esc</kbd> close</span>
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

// ── Filter bar state ─────────────────────────────────────────────────────────
let filterState = { q: '', status: [], tags: [], assignee: '', priority: '' };
const FILTER_TABS = new Set(['tasks','kanban','timeline','deps']);

(function _loadFilterState() {
  try {
    const saved = localStorage.getItem('cloop_filter_state');
    if (saved) filterState = Object.assign({ q:'', status:[], tags:[], assignee:'', priority:'' }, JSON.parse(saved));
  } catch(e) {}
})();

// ── Multi-project mode ───────────────────────────────────────────────────────
let isMultiProject      = false;  // true when multiple projects are registered
let selectedProjectIdx  = null;   // null = no project selected (Projects landing page)
let selectedProjectName = '';

// pUrl appends ?project_idx=N to a URL when a project is selected in multi-project mode.
function pUrl(url) {
  if (selectedProjectIdx === null) return url;
  const sep = url.includes('?') ? '&' : '?';
  return url + sep + 'project_idx=' + selectedProjectIdx;
}

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
      checkAuthAndInit();
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
  document.querySelectorAll('.m-tab-btn').forEach(el => el.classList.remove('active'));
  const panel  = document.getElementById('tab-'   + name);
  const btn    = document.getElementById('tbtn-'  + name);
  const mBtn   = document.getElementById('mtbtn-' + name);
  if (panel) panel.classList.add('active');
  if (btn)   btn.classList.add('active');
  if (mBtn)  mBtn.classList.add('active');

  // Show/hide unified filter bar.
  _syncFilterBarVisibility(name);

  // Close mobile nav when a tab is selected.
  closeMobileNav();

  // Show/hide FAB: only on tasks tab.
  const fab = document.getElementById('fab-add-task');
  if (fab) fab.style.display = (name === 'tasks') ? 'flex' : 'none';

  // In multi-project mode, re-fetch state for the selected project when
  // switching to any project-scoped tab so the data is always current.
  const projectScopedTabs = ['overview','tasks','kanban','timeline','kb','deps','risk-matrix','analytics','chat','assistant','suggest'];
  if (isMultiProject && selectedProjectIdx === null && name === 'overview') {
    // No project selected: show the all-projects summary panel.
    // Always reload so the cards reflect the latest project statuses.
    loadProjects();
  } else if (isMultiProject && selectedProjectIdx !== null && projectScopedTabs.includes(name)) {
    api(pUrl('/api/state')).then(s => render(s)).catch(() => {
      if (name === 'tasks'  && appState) renderTasks(appState);
      if (name === 'kanban' && appState) renderKanban(appState);
    });
    if (name === 'timeline') loadTimeline();
    if (name === 'kb') loadKB();
    if (name === 'deps') loadDeps();
    if (name === 'risk-matrix') loadRiskMatrix();
    if (name === 'analytics') loadAnalytics();
    if (name === 'chat') loadChatHistory();
    if (name === 'assistant') loadAssistantHistory();
  } else {
    if (name === 'settings') loadConfig();
    if (name === 'tasks'  && appState) renderTasks(appState);
    if (name === 'kanban' && appState) renderKanban(appState);
    if (name === 'projects') loadProjects();
    if (name === 'chat') loadChatHistory();
    if (name === 'assistant') loadAssistantHistory();
    if (name === 'timeline') loadTimeline();
    if (name === 'kb') loadKB();
    if (name === 'deps') loadDeps();
    if (name === 'risk-matrix') loadRiskMatrix();
    if (name === 'analytics') loadAnalytics();
  }

  // In multi-project mode, show/hide breadcrumb and project selector.
  if (isMultiProject) {
    const bc = document.getElementById('projectBreadcrumb');
    updateProjectSelector();
    if (name === 'projects' || name === 'settings') {
      // Global tabs: hide breadcrumb
      if (bc) bc.style.display = 'none';
    } else {
      // Project-scoped tabs: show breadcrumb when a project is selected
      if (bc) bc.style.display = selectedProjectIdx !== null ? 'flex' : 'none';
    }
  }
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

  // In multi-project mode with no project selected, don't overwrite the UI
  // with single-project data from WebSocket events or stale fetches.
  if (isMultiProject && selectedProjectIdx === null) return;

  const multiPanel = document.getElementById('multiProjectOverview');
  if (multiPanel) multiPanel.style.display = 'none';

  const hasProject = s && s.goal;
  document.getElementById('initPanel').style.display    = hasProject ? 'none' : '';
  document.getElementById('projectPanel').style.display = hasProject ? '' : 'none';
  if (!hasProject) return;

  // Goal
  const goalEl = document.getElementById('goalText');
  goalEl.textContent = s.goal;
  goalEl.classList.toggle('empty', !s.goal);

  // Update the "Overview" section title to show the selected project name in multi-project mode.
  const overviewTitle = document.getElementById('overviewSectionTitle');
  if (overviewTitle) {
    overviewTitle.textContent = (isMultiProject && selectedProjectName) ? 'Overview — ' + selectedProjectName : 'Overview';
  }

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

  // Rebuild filter dropdowns from current task list.
  if (s.plan && s.plan.tasks) {
    rebuildTagOptions(s.plan.tasks);
    rebuildAssigneeOptions(s.plan.tasks);
    _restoreFilterInputs();
    _updateFilterClearBtn();
  }

  // Tasks tab
  if (activeTab === 'tasks')  renderTasks(s);
  // Kanban tab
  if (activeTab === 'kanban') renderKanban(s);

  // Timeline tab: refresh on state change so the 'now' cursor and bar colors stay current.
  if (activeTab === 'timeline') loadTimeline();

  document.getElementById('updatedAt').textContent = s.updated_at ? fmtDate(s.updated_at) : '';

  // Update live output running indicator.
  renderLiveLog();
}

// renderMultiProjectOverview shows a card grid summary of all projects on the
// Overview tab when no specific project is selected in multi-project mode.
function renderMultiProjectOverview() {
  const panel    = document.getElementById('multiProjectOverview');
  const initP    = document.getElementById('initPanel');
  const projP    = document.getElementById('projectPanel');
  if (!panel) return;
  if (initP) initP.style.display = 'none';
  if (projP) projP.style.display = 'none';
  panel.style.display = '';

  const data = window._lastProjectsData;
  const grid = document.getElementById('multiProjectCards');
  if (!grid) return;
  if (!data || !data.projects || !data.projects.length) {
    grid.innerHTML = '<div class="empty-state"><h3>No projects loaded</h3><p>Use <code>cloop ui --projects /path/a /path/b</code> to add projects.</p></div>';
    return;
  }
  grid.innerHTML = data.projects.map(function(p, i) {
    const health   = p.health || 'unknown';
    const hCol     = healthColor(health);
    const total    = p.total_tasks || 0;
    const done     = p.done_tasks  || 0;
    const pct      = total > 0 ? Math.round(100 * done / total) : -1;
    const nameSafe = JSON.stringify(p.name).replace(/"/g, '&quot;');
    const valueStr = pct >= 0 ? pct + '% done' : (p.total_steps || 0) + ' steps';
    const subStr   = pct >= 0 ? done + '/' + total + ' tasks' : (p.status || '');
    return '<div class="stat-card" style="cursor:pointer" onclick="openProject('+i+','+nameSafe+')" title="Open project">' +
      '<div class="stat-label" style="font-weight:600">' + esc(p.name) + '</div>' +
      '<div style="font-size:11px;margin:3px 0"><span style="color:' + hCol + '">&#9679;</span> ' + esc(health) + '</div>' +
      '<div class="stat-value" style="font-size:15px;margin-top:4px">' + esc(valueStr) + '</div>' +
      '<div class="stat-sub">' + esc(subStr) + '</div>' +
    '</div>';
  }).join('');
}

window.toggleStep = function(el) { el.classList.toggle('expanded'); };

// ── Filter bar ───────────────────────────────────────────────────────────────

function _saveFilterState() {
  try { localStorage.setItem('cloop_filter_state', JSON.stringify(filterState)); } catch(e) {}
}

// Returns whether any filter is active.
function _filterActive() {
  return !!(filterState.q || filterState.status.length || filterState.tags.length || filterState.assignee || filterState.priority);
}

// Apply filterState to a task array; returns a new filtered array.
function applyFilters(tasks) {
  if (!tasks) return [];
  let result = tasks;
  const q = filterState.q ? filterState.q.toLowerCase() : '';
  if (q) result = result.filter(t => (t.title||'').toLowerCase().includes(q) || (t.description||'').toLowerCase().includes(q));
  if (filterState.status && filterState.status.length) {
    const ss = new Set(filterState.status);
    result = result.filter(t => ss.has(t.status || 'pending'));
  }
  if (filterState.tags && filterState.tags.length) {
    const ts = new Set(filterState.tags);
    result = result.filter(t => (t.tags||[]).some(tg => ts.has(tg)));
  }
  if (filterState.assignee) result = result.filter(t => (t.assignee||'') === filterState.assignee);
  if (filterState.priority) result = result.filter(t => String(t.priority) === filterState.priority);
  return result;
}

// Update the "N of M tasks" badge.
function updateFilterBadge(visible, total) {
  const badge = document.getElementById('filterBadge');
  if (!badge) return;
  badge.textContent = _filterActive() ? visible + ' of ' + total + ' tasks' : '';
}

// Sync all filter DOM inputs to the current filterState (called on page load).
function _restoreFilterInputs() {
  const qEl = document.getElementById('filterQ');
  if (qEl) qEl.value = filterState.q || '';
  document.querySelectorAll('.filter-status-cb').forEach(cb => {
    cb.checked = (filterState.status||[]).includes(cb.value);
  });
  const prEl = document.getElementById('filterPriority');
  if (prEl) prEl.value = filterState.priority || '';
  const asEl = document.getElementById('filterAssignee');
  if (asEl) asEl.value = filterState.assignee || '';
  // Tags are rebuilt dynamically via rebuildTagOptions().
}

// Rebuild tag checkboxes from current task list.
function rebuildTagOptions(tasks) {
  const panel = document.getElementById('filterTagsPanel');
  if (!panel) return;
  const tagSet = new Set();
  (tasks||[]).forEach(t => (t.tags||[]).forEach(tg => tagSet.add(tg)));
  const tags = [...tagSet].sort();
  if (!tags.length) {
    panel.innerHTML = '<span style="color:var(--muted);padding:4px 8px;display:block;font-size:11px">No tags</span>';
    return;
  }
  panel.innerHTML = tags.map(tag =>
    '<label class="filter-tag-item"><input type="checkbox" class="filter-tag-cb" value="'+esc(tag)+'" onchange="onFilterChange()"'+
    ((filterState.tags||[]).includes(tag) ? ' checked' : '')+'> '+esc(tag)+'</label>'
  ).join('');
}

// Rebuild assignee dropdown from current task list.
function rebuildAssigneeOptions(tasks) {
  const sel = document.getElementById('filterAssignee');
  if (!sel) return;
  const people = [...new Set((tasks||[]).map(t => t.assignee||'').filter(Boolean))].sort();
  const cur = filterState.assignee || '';
  sel.innerHTML = '<option value="">Any</option>' +
    people.map(a => '<option value="'+esc(a)+'"'+(a===cur?' selected':'')+'>'+esc(a)+'</option>').join('');
}

window.onFilterChange = function() {
  const qEl = document.getElementById('filterQ');
  filterState.q = qEl ? qEl.value : '';
  filterState.status = Array.from(document.querySelectorAll('.filter-status-cb:checked')).map(cb => cb.value);
  filterState.tags   = Array.from(document.querySelectorAll('.filter-tag-cb:checked')).map(cb => cb.value);
  const asEl = document.getElementById('filterAssignee');
  filterState.assignee = asEl ? asEl.value : '';
  const prEl = document.getElementById('filterPriority');
  filterState.priority = prEl ? prEl.value : '';
  _saveFilterState();
  _updateFilterClearBtn();
  const tagCnt = document.getElementById('filterTagCount');
  if (tagCnt) tagCnt.textContent = filterState.tags.length ? '('+filterState.tags.length+') ' : '';
  // Re-render active panel.
  if (appState) {
    if (activeTab === 'tasks')    renderTasks(appState);
    if (activeTab === 'kanban')   renderKanban(appState);
    if (activeTab === 'deps' && _depsData)   renderDepsGraph(_depsData);
  }
  if (activeTab === 'timeline') loadTimeline();
};

window.clearFilters = function() {
  filterState = { q: '', status: [], tags: [], assignee: '', priority: '' };
  _saveFilterState();
  _restoreFilterInputs();
  document.querySelectorAll('.filter-tag-cb').forEach(cb => { cb.checked = false; });
  _updateFilterClearBtn();
  const tagCnt = document.getElementById('filterTagCount');
  if (tagCnt) tagCnt.textContent = '';
  if (appState) {
    if (activeTab === 'tasks')    renderTasks(appState);
    if (activeTab === 'kanban')   renderKanban(appState);
    if (activeTab === 'deps' && _depsData)   renderDepsGraph(_depsData);
  }
  if (activeTab === 'timeline') loadTimeline();
};

function _updateFilterClearBtn() {
  const btn = document.getElementById('filterClearBtn');
  if (btn) btn.style.display = _filterActive() ? '' : 'none';
}

window.toggleTagDropdown = function(e) {
  if (e) e.stopPropagation();
  const panel = document.getElementById('filterTagsPanel');
  const btn   = document.getElementById('filterTagToggle');
  if (!panel) return;
  const open = panel.classList.toggle('open');
  if (btn) {
    btn.classList.toggle('active', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
};

// Close tag dropdown when clicking outside.
document.addEventListener('click', function(e) {
  const wrap = document.getElementById('filterTagsWrap');
  if (wrap && !wrap.contains(e.target)) {
    const panel = document.getElementById('filterTagsPanel');
    const btn   = document.getElementById('filterTagToggle');
    if (panel) panel.classList.remove('open');
    if (btn) { btn.classList.remove('active'); btn.setAttribute('aria-expanded','false'); }
  }
});

// Show or hide the filter bar based on the active tab.
function _syncFilterBarVisibility(tabName) {
  const bar = document.getElementById('filterBar');
  if (bar) bar.style.display = FILTER_TABS.has(tabName) ? '' : 'none';
}

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
    updateFilterBadge(0, 0);
    container.innerHTML = '<div class="empty-state"><h3>No tasks yet</h3><p>Add a task above, or run <code>cloop run --pm</code> to generate a task plan.</p></div>';
    return;
  }
  const byId = [...s.plan.tasks].sort((a,b) => a.id - b.id);
  const sorted = [...byId.filter(t=>t.pinned), ...byId.filter(t=>!t.pinned)];
  const done    = sorted.filter(t => t.status==='done').length;
  const hidden  = ['done', 'skipped', 'failed', 'timed_out'];

  // Apply search/filter bar. When status filters are active they override the showCompleted toggle.
  let visible = applyFilters(sorted);
  if (!filterState.status.length) {
    visible = showCompletedTasks ? visible : visible.filter(t => !hidden.includes(t.status || 'pending'));
  }

  const hiddenCount = sorted.length - visible.length;
  badge.textContent = '(' + done + '/' + sorted.length + ' done' +
    (hiddenCount > 0 && !showCompletedTasks && !filterState.status.length ? ', ' + hiddenCount + ' hidden' : '') + ')';
  updateFilterBadge(visible.length, sorted.length);

  if (!visible.length) {
    const msg = _filterActive()
      ? '<div class="empty-state"><h3>No matching tasks</h3><p>Try adjusting your search or filters.</p></div>'
      : '<div class="empty-state"><h3>All tasks completed</h3><p>Click <strong>Show completed</strong> to view all tasks.</p></div>';
    container.innerHTML = msg;
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
        '<div class="task-title">'+(t.pinned?'<span class="pin-badge" title="Pinned">📌</span> ':'')+esc(t.title)+'</div>'+
        (t.description ? '<div class="task-desc">'+esc(t.description)+'</div>' : '')+
        '<div class="task-meta">'+
          '<span>'+esc(cls)+'</span>'+
          (t.role?'<span>'+esc(t.role)+'</span>':'')+
          (t.depends_on&&t.depends_on.length?'<span>deps: #'+t.depends_on.join(', #')+'</span>':'')+
          (t.tags&&t.tags.length?'<span class="task-tags">'+t.tags.map(function(tg){return '<span class="task-tag">'+esc(tg)+'</span>';}).join('')+'</span>':'')+
          fmtTimeEstimate(t)+
        '</div>'+
        fmtTaskLinks(t)+
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

function fmtTaskLinks(t) {
  if (!t.links || !t.links.length) return '';
  const kindIcon = { ticket: '🎫', pr: '🔀', doc: '📄', artifact: '📦' };
  const items = t.links.map(function(lnk) {
    const icon = kindIcon[lnk.kind] || '🔗';
    const label = lnk.label || lnk.url;
    return '<a class="task-link-item" href="'+esc(lnk.url)+'" target="_blank" rel="noopener" title="['+esc(lnk.kind)+'] '+esc(lnk.url)+'">'+icon+' '+esc(label)+'</a>';
  });
  return '<div class="task-links">'+items.join('')+'</div>';
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

// ── Kanban board ──────────────────────────────────────────────────────────────

let kanbanCompact = false;
let kbDragTaskId  = null;

window.toggleKanbanCompact = function() {
  kanbanCompact = !kanbanCompact;
  const btn = document.getElementById('kanbanCompactBtn');
  if (btn) btn.textContent = kanbanCompact ? 'Expanded' : 'Compact';
  if (appState) renderKanban(appState);
};

// Map status values to their column bucket (failed + skipped + timed_out → 'failed' col)
function kbColFor(status) {
  if (!status || status === 'pending')               return 'pending';
  if (status === 'in_progress')                      return 'in_progress';
  if (status === 'done')                             return 'done';
  return 'failed'; // failed | skipped | timed_out
}

function kbPriorityClass(p) {
  if (!p || p <= 0) return '';
  return p <= 1 ? 'kbp1' : p <= 3 ? 'kbp2' : 'kbp3';
}

function kbAvatarHtml(assignee) {
  if (!assignee) return '';
  const initials = assignee.split(/[\s._@-]+/).map(w => w[0]||'').join('').slice(0,2).toUpperCase() || '?';
  return '<div class="kb-avatar" title="'+esc(assignee)+'">'+esc(initials)+'</div>';
}

function kbDeadlineBadge(deadline) {
  if (!deadline) return '';
  const d = new Date(deadline);
  if (isNaN(d.getTime())) return '';
  const now = Date.now();
  const diff = d - now; // ms
  const label = d.toLocaleDateString();
  let cls = 'kb-deadline';
  if (diff < 0)              cls += ''; // overdue — red (default)
  else if (diff < 86400000*2) cls += ' kb-due-soon'; // < 2 days — yellow
  else                        cls += ' kb-ok';       // fine — green
  return '<span class="'+cls+'" title="Deadline: '+esc(label)+'">'+esc(label)+'</span>';
}

function renderKanban(s) {
  const board = document.getElementById('kanbanBoard');
  if (!board) return;
  if (!s || !s.plan || !s.plan.tasks || !s.plan.tasks.length) {
    ['pending','in_progress','done','failed'].forEach(col => {
      const body = document.getElementById('kb-body-'+col);
      const cnt  = document.getElementById('kb-cnt-'+col);
      if (body) body.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:8px 0;text-align:center">No tasks</div>';
      if (cnt)  cnt.textContent = '0';
    });
    updateFilterBadge(0, 0);
    return;
  }

  // Apply filter bar before grouping into columns.
  const filteredTasks = applyFilters(s.plan.tasks);
  updateFilterBadge(filteredTasks.length, s.plan.tasks.length);

  // Group tasks by column
  const groups = { pending:[], in_progress:[], done:[], failed:[] };
  for (const t of filteredTasks) {
    const col = kbColFor(t.status);
    groups[col].push(t);
  }

  // Sort each group: pinned first, then by priority
  for (const col of Object.keys(groups)) {
    groups[col].sort((a,b) => (a.priority||99) - (b.priority||99));
    groups[col] = [...groups[col].filter(t=>t.pinned), ...groups[col].filter(t=>!t.pinned)];
  }

  // Render each column
  for (const col of ['pending','in_progress','done','failed']) {
    const body = document.getElementById('kb-body-'+col);
    const cnt  = document.getElementById('kb-cnt-'+col);
    if (!body || !cnt) continue;
    cnt.textContent = groups[col].length;

    if (!groups[col].length) {
      body.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:10px 0;text-align:center">Drop tasks here</div>';
      continue;
    }

    body.innerHTML = groups[col].map(t => {
      const pc     = kbPriorityClass(t.priority);
      const avatar = kbAvatarHtml(t.assignee || '');
      const tags   = (t.tags && t.tags.length)
        ? '<div class="kb-card-tags">'+t.tags.map(tg=>'<span class="kb-chip">'+esc(tg)+'</span>').join('')+'</div>' : '';
      const dl     = kbDeadlineBadge(t.deadline || '');
      const compact = kanbanCompact ? ' kb-compact' : '';
      return (
        '<div class="kb-card '+pc+compact+'" draggable="true" data-task-id="'+t.id+'" '+
          'ondragstart="kbDragStart(event,'+t.id+')" '+
          'ondragend="kbDragEnd(event)">'+
          '<div class="kb-card-header">'+
            '<div class="kb-card-title">'+(t.pinned?'<span class="pin-badge" title="Pinned">📌</span> ':'')+esc(t.title)+'</div>'+
            avatar+
          '</div>'+
          (t.description ? '<div class="kb-card-desc">'+esc(t.description)+'</div>' : '')+
          tags+
          '<div class="kb-card-meta">'+
            dl+
            '<span class="kb-taskid">#'+t.id+'</span>'+
          '</div>'+
        '</div>'
      );
    }).join('');
  }
}

// ── Kanban drag-and-drop ─────────────────────────────────────────────────────

window.kbDragStart = function(e, id) {
  kbDragTaskId = id;
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', String(id));
  setTimeout(() => {
    const el = document.querySelector('.kb-card[data-task-id="'+id+'"]');
    if (el) el.classList.add('kb-dragging');
  }, 0);
};

window.kbDragEnd = function(e) {
  kbDragTaskId = null;
  document.querySelectorAll('.kb-card').forEach(el => el.classList.remove('kb-dragging'));
  document.querySelectorAll('.kanban-col-body').forEach(el => el.classList.remove('kb-drag-over'));
};

window.kanbanColDragOver = function(e, col) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  document.querySelectorAll('.kanban-col-body').forEach(el => el.classList.remove('kb-drag-over'));
  const body = document.getElementById('kb-body-'+col);
  if (body) body.classList.add('kb-drag-over');
};

window.kanbanColDragLeave = function(e, col) {
  // Only remove if leaving the column body itself (not entering a child card)
  if (!e.currentTarget.contains(e.relatedTarget)) {
    const body = document.getElementById('kb-body-'+col);
    if (body) body.classList.remove('kb-drag-over');
  }
};

window.kanbanColDrop = function(e, col) {
  e.preventDefault();
  document.querySelectorAll('.kanban-col-body').forEach(el => el.classList.remove('kb-drag-over'));
  const id = kbDragTaskId || parseInt(e.dataTransfer.getData('text/plain'), 10);
  if (!id) return;

  // Map column key to status string
  const statusMap = { pending:'pending', in_progress:'in_progress', done:'done', failed:'failed' };
  const newStatus = statusMap[col];
  if (!newStatus) return;

  // Check current status to avoid no-op
  const task = appState && appState.plan && appState.plan.tasks
    ? appState.plan.tasks.find(t => t.id === id) : null;
  if (task && kbColFor(task.status) === col) return; // already in this column

  apiMethod('PATCH', pUrl('/api/tasks/'+id), {status: newStatus}).then(d => {
    if (d.ok) {
      toast('Task #'+id+': moved to '+newStatus.replace('_',' '), 'ok');
      refreshState();
    } else {
      toast(d.error || 'Update failed', 'err');
    }
  }).catch(() => toast('Request failed', 'err'));
};

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

// ── Real-time push: WebSocket (primary) with SSE fallback ────────────────────

// wsBackoff tracks the reconnect delay for WebSocket (ms).
let wsBackoff = 1000;
let wsConn = null;      // active WebSocket
let sseUsed = false;    // true when we fell back to SSE

// ── Presence ─────────────────────────────────────────────────────────────────

// myClientID: set on first WS presence message so we can highlight "you".
let myClientID = null;

// renderPresenceBar updates the presence indicator strip below the header.
function renderPresenceBar(users) {
  const bar = document.getElementById('presenceBar');
  if (!bar) return;
  if (!users || users.length === 0) { bar.innerHTML = ''; return; }

  let html = '<span class="presence-label">&#x1F465; Online:</span>';
  for (const u of users) {
    const isYou = u.id === myClientID;
    const initials = u.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
    const cls = isYou ? 'presence-avatar you' : 'presence-avatar';
    const tip = isYou ? u.name + ' (you)' : u.name;
    html += '<div class="' + cls + '" style="background:' + u.color + '" title="' + tip + '">'
          + initials
          + '<span class="presence-tooltip">' + tip + '</span>'
          + '</div>';
  }
  bar.innerHTML = html;
}

// ── Conflict toast ────────────────────────────────────────────────────────────

let _conflictDismissTimer = null;

function showConflictToast(msg) {
  const toast = document.getElementById('conflictToast');
  const msgEl = document.getElementById('conflictMsg');
  if (!toast) return;
  if (msgEl) msgEl.textContent = msg || 'Another user edited this task recently.';
  toast.classList.add('visible');
  clearTimeout(_conflictDismissTimer);
  _conflictDismissTimer = setTimeout(dismissConflictToast, 6000);
}

window.dismissConflictToast = function() {
  const toast = document.getElementById('conflictToast');
  if (toast) toast.classList.remove('visible');
  clearTimeout(_conflictDismissTimer);
};

// ── Client ID (sent with every REST mutation for conflict detection) ──────────

// Persist a per-tab client ID so the server can detect concurrent edits.
let _clientID = sessionStorage.getItem('cloop-client-id');
if (!_clientID) {
  _clientID = 'ui-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  sessionStorage.setItem('cloop-client-id', _clientID);
}

// Intercept fetch to inject X-Client-ID on every mutating request.
(function() {
  const _orig = window.fetch.bind(window);
  window.fetch = function(url, opts) {
    if (opts && opts.method && opts.method !== 'GET' && opts.method !== 'HEAD') {
      opts.headers = Object.assign({}, opts.headers || {}, { 'X-Client-ID': _clientID });
    }
    return _orig(url, opts);
  };
})();

// handleRealtimeMsg dispatches a typed message from either WebSocket or SSE.
function handleRealtimeMsg(type, data) {
  const dot = document.getElementById('liveDot');
  if (dot) dot.classList.add('connected');
  switch (type) {
    case 'task_update':
    case 'plan_complete':
      // In multi-project mode, only render when the primary project (idx=0)
      // is explicitly selected. Ignore when no project is selected (null) or
      // when a non-primary project is selected.
      if (isMultiProject && selectedProjectIdx !== 0) return;
      try { render(data); } catch(_) {}
      // Refresh analytics if the analytics tab is active.
      if (activeTab === 'analytics') { try { loadAnalytics(); } catch(_) {} }
      break;
    case 'step_output':
      try { if (data.chunk) appendLiveLog(data.chunk); } catch(_) {}
      break;
    case 'projects':
      try {
        renderProjects(data.projects || [], data.stats || {});
        updateProjectSelector();
        // Keep the selected project's state fresh in multi-project mode.
        if (isMultiProject && selectedProjectIdx !== null) {
          api(pUrl('/api/state')).then(s => render(s)).catch(() => {});
        }
        // Refresh the overview cards if on the overview tab with no project selected.
        if (isMultiProject && selectedProjectIdx === null && activeTab === 'overview') {
          renderMultiProjectOverview();
        }
      } catch(_) {}
      break;
    case 'presence':
      try {
        // Remember own ID on first presence message.
        if (data.you && !myClientID) myClientID = data.you;
        renderPresenceBar(data.users || []);
      } catch(_) {}
      break;
    case 'task_mutation':
      // Re-render with latest state and show conflict toast if needed.
      try {
        if (data.state) {
          if (!isMultiProject || selectedProjectIdx === 0) {
            render(data.state);
          }
        }
        if (data.conflict) {
          const taskTitle = data.task && data.task.title ? '"' + data.task.title + '"' : 'a task';
          showConflictToast('Another user edited ' + taskTitle + ' at the same time. Review the latest version.');
        }
      } catch(_) {}
      break;
    case 'task_added':
    case 'task_deleted':
      // Re-render with the updated state snapshot.
      try {
        if (data.state) {
          if (!isMultiProject || selectedProjectIdx === 0) {
            render(data.state);
          }
        }
      } catch(_) {}
      break;
    case 'error':
      console.warn('cloop ws error:', data);
      break;
  }
}

function connectWS() {
  if (wsConn) { wsConn.close(); wsConn = null; }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const tok   = authToken ? '?token=' + encodeURIComponent(authToken) : '';
  const url   = proto + '//' + location.host + '/api/ws' + tok;
  const dot   = document.getElementById('liveDot');

  let ws;
  try { ws = new WebSocket(url); } catch(_) { _fallbackToSSE(); return; }
  wsConn = ws;

  ws.onopen = () => {
    wsBackoff = 1000; // reset on successful connect
    sseUsed = false;
    if (dot) dot.classList.add('connected');
    // On reconnect also refresh the live log buffer in case we missed output.
    api('/api/livelog').then(d => {
      if (d.lines && d.lines.length) {
        liveLogText = d.lines.join('');
        renderLiveLog();
      }
    }).catch(() => {});
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      handleRealtimeMsg(msg.type, msg.data);
    } catch(_) {}
  };

  ws.onclose = (ev) => {
    wsConn = null;
    if (dot) dot.classList.remove('connected');
    // If the close was a normal shutdown or we haven't tried SSE yet on the
    // first connection, probe the state endpoint to detect auth failures.
    fetch('/api/state', {headers: authHeaders()}).then(r => {
      if (r.status === 401) { showLoginModal(); return; }
      // Exponential backoff reconnect (cap at 30 s).
      const delay = Math.min(wsBackoff, 30000);
      wsBackoff = Math.min(wsBackoff * 2, 30000);
      setTimeout(connectWS, delay);
    }).catch(() => {
      const delay = Math.min(wsBackoff, 30000);
      wsBackoff = Math.min(wsBackoff * 2, 30000);
      setTimeout(connectWS, delay);
    });
  };

  ws.onerror = () => {
    // onerror is always followed by onclose; fallback only if WebSocket is
    // not supported at all (readyState stuck at CONNECTING).
    if (ws.readyState !== WebSocket.OPEN && ws.readyState !== WebSocket.CONNECTING) {
      _fallbackToSSE();
    }
  };
}

// _fallbackToSSE: used when WebSocket upgrades are blocked by a proxy.
function _fallbackToSSE() {
  if (sseUsed) return; // already in SSE mode
  sseUsed = true;
  connectSSE();
}

function connectSSE() {
  if (evtSource) evtSource.close();
  const sseUrl = authToken ? '/api/events?token=' + encodeURIComponent(authToken) : '/api/events';
  evtSource = new EventSource(sseUrl);
  const dot = document.getElementById('liveDot');
  evtSource.onopen = () => {
    dot.classList.add('connected');
    api('/api/livelog').then(d => {
      if (d.lines && d.lines.length) {
        liveLogText = d.lines.join('');
        renderLiveLog();
      }
    }).catch(() => {});
  };
  evtSource.onmessage = (e) => {
    try {
      handleRealtimeMsg('task_update', JSON.parse(e.data));
    } catch(_) {}
  };
  evtSource.addEventListener('log', (e) => {
    try { handleRealtimeMsg('step_output', JSON.parse(e.data)); } catch(_) {}
  });
  evtSource.addEventListener('projects', (e) => {
    try { handleRealtimeMsg('projects', JSON.parse(e.data)); } catch(_) {}
  });
  evtSource.onerror = () => {
    dot.classList.remove('connected');
    evtSource.close();
    evtSource = null;
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
    const projects = d.projects || [];
    isMultiProject = d.multi_project === true || projects.length > 1;
    renderProjects(projects, d.stats || {});
    updateProjectSelector();
    // Refresh the overview cards if we're on the overview tab with no project selected.
    if (isMultiProject && selectedProjectIdx === null && activeTab === 'overview') {
      renderMultiProjectOverview();
    }
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
    const health  = p.health || 'unknown';
    const pct     = p.total_tasks > 0 ? Math.round(p.done_tasks / p.total_tasks * 100) : 0;
    const goal    = p.goal ? esc(p.goal.substring(0, 80)) : '<em style="color:var(--muted)">no goal set</em>';
    const lastAct = p.last_activity ? relTime(new Date(p.last_activity)) : '—';
    const taskInfo = p.pm_mode
      ? p.done_tasks + '/' + p.total_tasks + ' tasks'
      : (p.total_steps ? p.total_steps + ' steps' : 'no steps');
    const selCls  = (selectedProjectIdx === idx) ? ' selected' : '';
    const nameSafe = JSON.stringify(p.name).replace(/"/g, '&quot;');
    return ` + "`" + `
      <div class="proj-card${selCls}" onclick="openProject(${idx},${nameSafe})" title="Open project">
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
        <div class="proj-actions" onclick="event.stopPropagation()">
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

// Opens a project in scoped-tabs mode: sets selectedProjectIdx and drills into Overview.
window.openProject = function(idx, name) {
  selectedProjectIdx  = idx;
  selectedProjectName = name;
  const bc = document.getElementById('projectBreadcrumb');
  if (bc) { bc.style.display = 'flex'; }
  const bn = document.getElementById('breadcrumbName');
  if (bn) bn.textContent = name;
  // Update selector label immediately.
  const label = document.getElementById('projSelectorLabel');
  if (label) label.textContent = name;
  const wrap = document.getElementById('projSelectorWrap');
  if (wrap) wrap.classList.add('visible');
  // Refresh project list highlight without changing tab.
  if (window._lastProjectsData) {
    renderProjects(window._lastProjectsData.projects, window._lastProjectsData.stats);
  }
  switchTab('overview');
  api(pUrl('/api/state')).then(s => render(s)).catch(() => {});
};

// Returns to the Projects landing page from a scoped project view.
window.clearProjectSelection = function() {
  selectedProjectIdx  = null;
  selectedProjectName = '';
  appState            = null;
  const bc = document.getElementById('projectBreadcrumb');
  if (bc) bc.style.display = 'none';
  const sw = document.getElementById('projSelectorWrap');
  if (sw) sw.classList.remove('visible');
  switchTab('projects');
};

// ── Project selector dropdown ─────────────────────────────────────────────────

// Populates and shows/hides the project selector based on isMultiProject.
function updateProjectSelector() {
  const wrap = document.getElementById('projSelectorWrap');
  const label = document.getElementById('projSelectorLabel');
  if (!wrap) return;
  if (!isMultiProject) { wrap.classList.remove('visible'); return; }
  wrap.classList.add('visible');
  if (label) label.textContent = selectedProjectIdx !== null ? selectedProjectName : 'All Projects';
  // Populate dropdown items from cached project data.
  const drop = document.getElementById('projSelectorDropdown');
  if (!drop) return;
  const projects = (window._lastProjectsData && window._lastProjectsData.projects) || [];
  drop.innerHTML = projects.map((p, i) => {
    const health = p.health || 'unknown';
    const activeCls = selectedProjectIdx === i ? ' active' : '';
    const dotStyle = 'background:' + healthColor(health);
    return '<div class="proj-selector-item'+activeCls+'" onclick="selectProjectFromDropdown('+i+','+JSON.stringify(p.name).replace(/"/g,'&quot;')+')">' +
      '<span class="pi-dot" style="'+dotStyle+'"></span>' +
      '<span class="pi-name">'+esc(p.name)+'</span>' +
      '<span style="font-size:10px;color:var(--muted)">'+health+'</span>' +
      '</div>';
  }).join('');
}

function healthColor(h) {
  const map = {running:'var(--cyan)',complete:'var(--green)',failed:'var(--red)',stalled:'var(--yellow)',idle:'var(--muted)',unknown:'var(--border)'};
  return map[h] || map.unknown;
}

window.toggleProjectSelector = function() {
  const drop = document.getElementById('projSelectorDropdown');
  if (!drop) return;
  drop.classList.toggle('open');
};

// Close dropdown on outside click.
document.addEventListener('click', function(e) {
  const wrap = document.getElementById('projSelectorWrap');
  if (wrap && !wrap.contains(e.target)) {
    const drop = document.getElementById('projSelectorDropdown');
    if (drop) drop.classList.remove('open');
  }
});

window.selectProjectFromDropdown = function(idx, name) {
  const drop = document.getElementById('projSelectorDropdown');
  if (drop) drop.classList.remove('open');
  if (selectedProjectIdx === idx) return; // already selected
  openProject(idx, name);
};

// ── New Project modal ─────────────────────────────────────────────────────────

window.openNewProjectModal = function() {
  document.getElementById('npDir').value     = '';
  document.getElementById('npGoal').value    = '';
  document.getElementById('npModel').value   = '';
  document.getElementById('npProvider').value = '';
  document.getElementById('npPMMode').checked = false;
  document.getElementById('npAutoRun').checked = false;
  document.getElementById('npError').style.display = 'none';
  const el = document.getElementById('new-project-overlay');
  if (el) { el.style.display = 'flex'; }
};

window.closeNewProjectModal = function() {
  const el = document.getElementById('new-project-overlay');
  if (el) el.style.display = 'none';
};

window.submitNewProject = function() {
  const dir      = document.getElementById('npDir').value.trim();
  const goal     = document.getElementById('npGoal').value.trim();
  const provider = document.getElementById('npProvider').value;
  const model    = document.getElementById('npModel').value.trim();
  const pmMode   = document.getElementById('npPMMode').checked;
  const autoRun  = document.getElementById('npAutoRun').checked;
  const errEl    = document.getElementById('npError');
  if (!dir)  { errEl.textContent = 'Directory is required'; errEl.style.display = ''; return; }
  if (!goal) { errEl.textContent = 'Goal is required'; errEl.style.display = ''; return; }
  errEl.style.display = 'none';
  api('/api/projects/new', {dir, goal, provider, model, pmMode, autoRun}).then(d => {
    if (!d.ok) { errEl.textContent = d.error || 'Failed to create project'; errEl.style.display = ''; return; }
    closeNewProjectModal();
    toast('Project created: ' + dir, 'ok');
    // Reload projects list and open the new project.
    api('/api/projects').then(pd => {
      const projects = pd.projects || [];
      isMultiProject = pd.multi_project === true || projects.length > 1;
      renderProjects(projects, pd.stats || {});
      updateProjectSelector();
      if (d.project_idx !== undefined && d.project_idx >= 0) {
        openProject(d.project_idx, dir.split('/').pop());
      }
    }).catch(() => {});
  }).catch(() => toast('Request failed', 'err'));
};

// ── Knowledge Base tab ───────────────────────────────────────────────────────

let _kbEntries = [];  // full entry list for client-side search

window.loadKB = function() { loadKB(); };

function loadKB() {
  api(pUrl('/api/kb')).then(data => {
    _kbEntries = data.entries || [];
    renderKBCards(_kbEntries);
  }).catch(() => toast('Failed to load knowledge base', 'err'));
}

function renderKBCards(entries) {
  const grid  = document.getElementById('kbGrid');
  const empty = document.getElementById('kbEmpty');
  if (!grid) return;
  if (!entries || entries.length === 0) {
    grid.innerHTML = '';
    if (empty) empty.style.display = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  grid.innerHTML = entries.map(e => {
    const tags = (e.tags || []).map(t => '<span class="kb-tag">' + esc(t) + '</span>').join('');
    const bodyText = (e.content || '').replace(/\n/g, '\n');
    return '<div class="kb-entry-card" data-id="' + e.id + '">' +
      '<button class="kb-card-del" onclick="deleteKBEntry(' + e.id + ')" title="Delete entry">&#x2715;</button>' +
      '<div class="kb-entry-title">' + esc(e.title) + '</div>' +
      (tags ? '<div class="kb-tags">' + tags + '</div>' : '') +
      (bodyText ? '<div class="kb-entry-body">' + esc(bodyText) + '</div>' : '') +
      '</div>';
  }).join('');
}

function filterKBCards(q) {
  if (!q) { renderKBCards(_kbEntries); return; }
  const lq = q.toLowerCase();
  const filtered = _kbEntries.filter(e =>
    (e.title || '').toLowerCase().includes(lq) ||
    (e.content || '').toLowerCase().includes(lq) ||
    (e.tags || []).some(t => t.toLowerCase().includes(lq))
  );
  renderKBCards(filtered);
}

window.toggleKBAddForm = function() {
  const form = document.getElementById('kbAddForm');
  if (!form) return;
  const visible = form.style.display !== 'none';
  form.style.display = visible ? 'none' : '';
  if (!visible) {
    document.getElementById('kbNewTitle').value = '';
    document.getElementById('kbNewBody').value = '';
    document.getElementById('kbNewTags').value = '';
    document.getElementById('kbNewTitle').focus();
  }
};

window.submitKBAdd = function() {
  const title = (document.getElementById('kbNewTitle').value || '').trim();
  const body  = (document.getElementById('kbNewBody').value  || '').trim();
  const tagsRaw = (document.getElementById('kbNewTags').value || '').trim();
  const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];
  if (!title) { toast('Title is required', 'err'); return; }
  apiMethod('POST', pUrl('/api/kb'), {title, body, tags}).then(d => {
    if (d.ok || d.entry) {
      toast('Entry added', 'ok');
      toggleKBAddForm();
      loadKB();
    } else {
      toast(d.error || 'Failed to add entry', 'err');
    }
  }).catch(() => toast('Failed to add entry', 'err'));
};

window.deleteKBEntry = function(id) {
  apiMethod('DELETE', pUrl('/api/kb/' + id), null).then(d => {
    if (d.ok) { toast('Entry deleted', 'ok'); loadKB(); }
    else toast(d.error || 'Delete failed', 'err');
  }).catch(() => toast('Delete failed', 'err'));
};

// ── Dependency graph tab ─────────────────────────────────────────────────────

window.loadDeps = function() { loadDeps(); };

let _depsData   = null;   // { nodes, edges }
let _depsNodes  = [];     // positioned nodes
let _dragNode   = null;   // node being dragged
let _simRunning = false;

const STATUS_COLORS = {
  pending:     '#6b7280',
  in_progress: '#3b82f6',
  done:        '#22c55e',
  failed:      '#ef4444',
  skipped:     '#a855f7',
  timed_out:   '#f97316',
};

function loadDeps() {
  api(pUrl('/api/deps')).then(data => {
    _depsData = data;
    renderDepsGraph(data);
  }).catch(() => {});
}

function renderDepsGraph(data) {
  const nodes  = data.nodes  || [];
  const edges  = data.edges  || [];
  const showAll = document.getElementById('depsShowAll') && document.getElementById('depsShowAll').checked;
  const emptyEl = document.getElementById('depsEmpty');
  const container = document.getElementById('depsContainer');
  const svg = document.getElementById('depsSvg');

  // Filter: when filter bar is active, use applyFilters; otherwise use showAll toggle.
  let visNodes;
  if (_filterActive() && appState && appState.plan && appState.plan.tasks) {
    const filteredIds = new Set(applyFilters(appState.plan.tasks).map(t => t.id));
    visNodes = nodes.filter(n => filteredIds.has(n.id));
    updateFilterBadge(visNodes.length, nodes.length);
  } else {
    visNodes = showAll ? nodes : nodes.filter(n => n.status !== 'done' && n.status !== 'skipped');
    updateFilterBadge(visNodes.length, nodes.length);
  }
  const visIds   = new Set(visNodes.map(n => n.id));
  const visEdges = edges.filter(e => visIds.has(e.from) && visIds.has(e.to));

  if (visNodes.length === 0) {
    if (emptyEl) emptyEl.style.display = '';
    container.style.display = 'none';
    return;
  }
  if (emptyEl) emptyEl.style.display = 'none';
  container.style.display = '';

  const W = svg.clientWidth  || svg.getBoundingClientRect().width  || 700;
  const H = svg.clientHeight || svg.getBoundingClientRect().height || 520;
  const R = 22; // node radius

  // Initialise positions with a grid layout, then run force simulation
  const posMap = {};
  visNodes.forEach((n, i) => {
    const cols = Math.max(1, Math.ceil(Math.sqrt(visNodes.length)));
    const col  = i % cols;
    const row  = Math.floor(i / cols);
    posMap[n.id] = {
      x: 60 + col * ((W - 120) / Math.max(cols - 1, 1)),
      y: 60 + row * ((H - 120) / Math.max(Math.ceil(visNodes.length / cols) - 1, 1)),
      vx: 0, vy: 0,
      node: n,
    };
  });
  _depsNodes = Object.values(posMap);

  // Build SVG
  svg.innerHTML = '';
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

  // Defs: arrowhead marker
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = '<marker id="deps-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="#6b7280"/></marker>';
  svg.appendChild(defs);

  // Edge layer
  const edgeLayer = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  edgeLayer.id = 'depsEdgeLayer';
  svg.appendChild(edgeLayer);

  // Node layer
  const nodeLayer = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  nodeLayer.id = 'depsNodeLayer';
  svg.appendChild(nodeLayer);

  // Draw edges
  visEdges.forEach(e => {
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    line.classList.add('deps-edge');
    line.dataset.from = e.from;
    line.dataset.to   = e.to;
    edgeLayer.appendChild(line);
  });

  // Draw nodes
  _depsNodes.forEach(p => {
    const n = p.node;
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.classList.add('deps-node', 'deps-node-' + n.status);
    g.dataset.id = n.id;

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', R);
    circle.setAttribute('cx', 0);
    circle.setAttribute('cy', 0);
    g.appendChild(circle);

    // Priority badge
    if (n.priority && n.priority <= 3) {
      const badge = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      badge.setAttribute('x', R - 6);
      badge.setAttribute('y', -(R - 6));
      badge.setAttribute('font-size', '9');
      badge.setAttribute('fill', '#facc15');
      badge.setAttribute('text-anchor', 'middle');
      badge.textContent = 'P' + n.priority;
      g.appendChild(badge);
    }

    // Label
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', 0);
    label.setAttribute('y', R + 14);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('font-size', '10');
    label.textContent = truncateLabel(n.title, 18);
    g.appendChild(label);

    // ID label inside circle
    const idTxt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    idTxt.setAttribute('x', 0);
    idTxt.setAttribute('y', 4);
    idTxt.setAttribute('text-anchor', 'middle');
    idTxt.setAttribute('font-size', '11');
    idTxt.setAttribute('font-weight', '600');
    idTxt.setAttribute('fill', '#fff');
    idTxt.setAttribute('pointer-events', 'none');
    idTxt.textContent = '#' + n.id;
    g.appendChild(idTxt);

    // Drag & click
    g.addEventListener('mousedown', e => startDrag(e, p));
    g.addEventListener('touchstart', e => startDrag(e, p), {passive: false});
    g.addEventListener('click', e => { e.stopPropagation(); openDepsDetail(n); });

    nodeLayer.appendChild(g);
  });

  updateDepsPositions();

  // Run force simulation
  runForce(visEdges, posMap, W, H, R);

  // Click on empty area closes sidebar
  svg.addEventListener('click', () => closeDepsDetail());
}

function truncateLabel(s, max) {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function updateDepsPositions() {
  const svg = document.getElementById('depsSvg');
  if (!svg) return;
  _depsNodes.forEach(p => {
    const g = svg.querySelector('.deps-node[data-id="' + p.node.id + '"]');
    if (g) g.setAttribute('transform', 'translate(' + p.x.toFixed(1) + ',' + p.y.toFixed(1) + ')');
  });
  // Update edges
  const edgeLayer = document.getElementById('depsEdgeLayer');
  if (!edgeLayer || !_depsData) return;
  const posMap = {};
  _depsNodes.forEach(p => { posMap[p.node.id] = p; });
  edgeLayer.querySelectorAll('.deps-edge').forEach(line => {
    const from = posMap[parseInt(line.dataset.from)];
    const to   = posMap[parseInt(line.dataset.to)];
    if (!from || !to) return;
    const dx = to.x - from.x, dy = to.y - from.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const R = 22;
    // shorten path so arrowhead touches circle edge
    const sx = from.x + dx / dist * R;
    const sy = from.y + dy / dist * R;
    const ex = to.x   - dx / dist * (R + 8);
    const ey = to.y   - dy / dist * (R + 8);
    line.setAttribute('d', 'M' + sx.toFixed(1) + ',' + sy.toFixed(1) + ' L' + ex.toFixed(1) + ',' + ey.toFixed(1));
  });
}

function runForce(edges, posMap, W, H, R) {
  if (_simRunning) return;
  _simRunning = true;
  let iter = 0;
  const maxIter = 200;
  const idealLen = 130;

  function step() {
    if (iter++ > maxIter || !_simRunning) { _simRunning = false; return; }
    const nodes = _depsNodes;
    // Repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = b.x - a.x, dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
        const force = Math.min(3000 / (dist * dist), 8);
        const fx = force * dx / dist, fy = force * dy / dist;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }
    // Spring attraction along edges
    edges.forEach(e => {
      const a = posMap[e.from], b = posMap[e.to];
      if (!a || !b) return;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const force = (dist - idealLen) * 0.04;
      const fx = force * dx / dist, fy = force * dy / dist;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    });
    // Center gravity
    nodes.forEach(p => {
      p.vx += (W / 2 - p.x) * 0.005;
      p.vy += (H / 2 - p.y) * 0.005;
    });
    // Dampen & integrate
    const dampen = 0.8;
    nodes.forEach(p => {
      if (p === _dragNode) { p.vx = 0; p.vy = 0; return; }
      p.vx *= dampen; p.vy *= dampen;
      p.x  = Math.max(R + 2, Math.min(W - R - 2, p.x + p.vx));
      p.y  = Math.max(R + 2, Math.min(H - R - 2, p.y + p.vy));
    });
    updateDepsPositions();
    requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Drag support ─────────────────────────────────────────────────────────────

function startDrag(evt, posNode) {
  _dragNode = posNode;
  evt.preventDefault && evt.preventDefault();
  const svg = document.getElementById('depsSvg');
  const rect = svg.getBoundingClientRect();
  const W = rect.width, H = rect.height;
  const vbW = parseFloat(svg.getAttribute('viewBox').split(' ')[2]) || W;
  const vbH = parseFloat(svg.getAttribute('viewBox').split(' ')[3]) || H;
  const scaleX = vbW / W, scaleY = vbH / H;

  function getPos(e) {
    const touch = e.touches ? e.touches[0] : e;
    return {
      x: (touch.clientX - rect.left)  * scaleX,
      y: (touch.clientY - rect.top)   * scaleY,
    };
  }

  function onMove(e) {
    if (!_dragNode) return;
    const pos = getPos(e);
    _dragNode.x = pos.x;
    _dragNode.y = pos.y;
    _dragNode.vx = 0;
    _dragNode.vy = 0;
    updateDepsPositions();
  }
  function onUp() {
    _dragNode = null;
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup',   onUp);
    document.removeEventListener('touchmove', onMove);
    document.removeEventListener('touchend',  onUp);
  }
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup',   onUp);
  document.addEventListener('touchmove', onMove, {passive: false});
  document.addEventListener('touchend',  onUp);
}

// ── Detail sidebar ────────────────────────────────────────────────────────────

function openDepsDetail(node) {
  const sidebar = document.getElementById('depsSidebar');
  if (!sidebar) return;
  document.getElementById('depsSidebarTitle').textContent = '#' + node.id + ' ' + node.title;
  const statusLabel = {
    pending: 'Pending', in_progress: 'In Progress', done: 'Done',
    failed: 'Failed', skipped: 'Skipped', timed_out: 'Timed Out',
  }[node.status] || node.status;
  const color = STATUS_COLORS[node.status] || '#6b7280';
  let html = '';
  html += '<div class="deps-detail-row"><span class="deps-detail-label">Status</span>'
        + '<span style="color:' + color + '">' + statusLabel + '</span></div>';
  html += '<div class="deps-detail-row"><span class="deps-detail-label">Priority</span>'
        + 'P' + (node.priority || '?') + '</div>';
  if (node.assignee) {
    html += '<div class="deps-detail-row"><span class="deps-detail-label">Assignee</span>'
          + esc(node.assignee) + '</div>';
  }
  if (node.deadline) {
    html += '<div class="deps-detail-row"><span class="deps-detail-label">Deadline</span>'
          + esc(node.deadline) + '</div>';
  }
  if (node.description) {
    html += '<div class="deps-detail-row"><span class="deps-detail-label">Description</span>'
          + '<div style="margin-top:4px;white-space:pre-wrap;line-height:1.5">' + esc(node.description) + '</div></div>';
  }
  // Show blocking/blocked-by info
  if (_depsData) {
    const blockedBy = (_depsData.edges || []).filter(e => e.to   === node.id).map(e => '#' + e.from);
    const blocks    = (_depsData.edges || []).filter(e => e.from === node.id).map(e => '#' + e.to);
    if (blockedBy.length) {
      html += '<div class="deps-detail-row"><span class="deps-detail-label">Blocked by</span>'
            + blockedBy.join(', ') + '</div>';
    }
    if (blocks.length) {
      html += '<div class="deps-detail-row"><span class="deps-detail-label">Blocks</span>'
            + blocks.join(', ') + '</div>';
    }
  }
  document.getElementById('depsSidebarBody').innerHTML = html;
  sidebar.style.display = 'flex';
}

window.closeDepsDetail = function() {
  const sidebar = document.getElementById('depsSidebar');
  if (sidebar) sidebar.style.display = 'none';
};

// ── Risk Matrix tab ───────────────────────────────────────────────────────────

window.loadRiskMatrix = function() { loadRiskMatrix(); };

function loadRiskMatrix() {
  const status  = document.getElementById('rmStatus');
  const empty   = document.getElementById('rmEmpty');
  const noTasks = document.getElementById('rmNoTasks');
  const wrap    = document.getElementById('rmChartWrap');
  const tbl     = document.getElementById('rmTable');
  const tbody   = document.getElementById('rmTableBody');
  if (status) status.textContent = 'Loading…';
  if (empty)   empty.style.display   = 'none';
  if (noTasks) noTasks.style.display = 'none';
  if (wrap)    wrap.style.display    = 'none';
  if (tbl)     tbl.style.display     = 'none';

  api(pUrl('/api/risk-matrix')).then(data => {
    if (status) status.textContent = '';
    const entries = data.entries || [];

    if (entries.length === 0) {
      if (noTasks) noTasks.style.display = 'flex';
      return;
    }

    // Check if any task has cached scores.
    const hasScores = entries.some(e => e.risk_score > 0 && e.impact_score > 0);
    if (!hasScores) {
      if (empty) empty.style.display = 'flex';
      return;
    }

    // Draw canvas chart.
    if (wrap) wrap.style.display = 'block';
    renderRiskMatrixCanvas(entries);

    // Populate table.
    if (tbl) tbl.style.display = 'block';
    if (tbody) {
      const qColors = { Critical:'#ef4444', Mitigate:'#f97316', Leverage:'#22c55e', Defer:'#9ca3af' };
      const td = 'padding:5px 10px;border-bottom:1px solid var(--border)';
      tbody.innerHTML = entries.filter(function(e){ return e.risk_score > 0; }).map(function(e) {
        const col = qColors[e.quadrant] || '#9ca3af';
        const title = e.task_title.length > 60 ? e.task_title.slice(0,57) + '\u2026' : e.task_title;
        return '<tr>' +
          '<td style="'+td+'">#'+e.task_id+'</td>' +
          '<td style="'+td+'">'+esc(title)+'</td>' +
          '<td style="'+td+';text-align:center">'+e.risk_score+'/10</td>' +
          '<td style="'+td+';text-align:center">'+e.impact_score+'/10</td>' +
          '<td style="'+td+';color:'+col+';font-weight:500">'+(e.quadrant||'\u2014')+'</td>' +
          '</tr>';
      }).join('');
    }
  }).catch(() => {
    if (status) status.textContent = 'Failed to load';
  });
}

function renderRiskMatrixCanvas(entries) {
  const canvas = document.getElementById('rmCanvas');
  if (!canvas) return;

  const dpr = window.devicePixelRatio || 1;
  const W = Math.min(640, window.innerWidth - 40);
  const H = Math.round(W * 0.75);
  canvas.width  = W * dpr;
  canvas.height = H * dpr;
  canvas.style.width  = W + 'px';
  canvas.style.height = H + 'px';

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const PAD = { top: 28, right: 16, bottom: 44, left: 44 };
  const pw = W - PAD.left - PAD.right;
  const ph = H - PAD.top  - PAD.bottom;
  const MID_X = PAD.left + pw * 0.5;
  const MID_Y = PAD.top  + ph * 0.5;

  // Detect theme.
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  const textCol = isDark ? '#94a3b8' : '#64748b';
  const borderCol = isDark ? '#334155' : '#cbd5e1';

  // Quadrant backgrounds.
  const quads = [
    { x: PAD.left, y: PAD.top,  w: MID_X-PAD.left, h: MID_Y-PAD.top,   color:'rgba(249,115,22,0.10)', label:'MITIGATE', lx: PAD.left+6,  ly: PAD.top+14  },
    { x: MID_X,    y: PAD.top,  w: PAD.left+pw-MID_X, h: MID_Y-PAD.top, color:'rgba(239,68,68,0.14)',  label:'CRITICAL', lx: MID_X+6,     ly: PAD.top+14  },
    { x: PAD.left, y: MID_Y,    w: MID_X-PAD.left, h: PAD.top+ph-MID_Y, color:'rgba(107,114,128,0.08)',label:'DEFER',    lx: PAD.left+6,  ly: MID_Y+14    },
    { x: MID_X,    y: MID_Y,    w: PAD.left+pw-MID_X, h: PAD.top+ph-MID_Y,color:'rgba(34,197,94,0.10)',label:'LEVERAGE', lx: MID_X+6,     ly: MID_Y+14    },
  ];
  for (const q of quads) {
    ctx.fillStyle = q.color;
    ctx.fillRect(q.x, q.y, q.w, q.h);
    ctx.fillStyle = isDark ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.2)';
    ctx.font = 'bold 10px system-ui';
    ctx.fillText(q.label, q.lx, q.ly);
  }

  // Axes.
  ctx.strokeStyle = borderCol;
  ctx.lineWidth = 1;
  ctx.strokeRect(PAD.left, PAD.top, pw, ph);
  ctx.setLineDash([4,4]);
  ctx.beginPath(); ctx.moveTo(MID_X, PAD.top); ctx.lineTo(MID_X, PAD.top+ph); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(PAD.left, MID_Y); ctx.lineTo(PAD.left+pw, MID_Y); ctx.stroke();
  ctx.setLineDash([]);

  // Axis ticks.
  ctx.fillStyle = textCol;
  ctx.font = '10px system-ui';
  for (let v = 1; v <= 10; v++) {
    const x = PAD.left + (v-1)/9 * pw;
    ctx.fillText(v, x - (v >= 10 ? 5 : 3), PAD.top + ph + 14);
  }
  for (let v = 1; v <= 10; v++) {
    const y = PAD.top + ph - (v-1)/9 * ph;
    ctx.fillText(v, PAD.left - (v >= 10 ? 20 : 14), y + 4);
  }

  // Axis labels.
  ctx.fillStyle = isDark ? '#cbd5e1' : '#475569';
  ctx.font = '11px system-ui';
  ctx.fillText('Impact \u2192', PAD.left + pw/2 - 20, H - 4);
  ctx.save();
  ctx.translate(12, PAD.top + ph/2 + 24);
  ctx.rotate(-Math.PI/2);
  ctx.fillText('Risk \u2192', 0, 0);
  ctx.restore();

  // Plot points.
  const dotColors = { Critical:'#ef4444', Mitigate:'#f97316', Leverage:'#22c55e', Defer:'#9ca3af' };
  const placed = [];
  for (const e of entries) {
    if (!e.risk_score || !e.impact_score) continue;
    let x = PAD.left + (e.impact_score-1)/9 * pw;
    let y = PAD.top  + ph - (e.risk_score-1)/9 * ph;
    // Nudge overlapping labels.
    let tries = 0;
    while (placed.some(p => Math.abs(p.x-x) < 20 && Math.abs(p.y-y) < 14) && tries < 8) {
      x += 16; tries++;
    }
    placed.push({x, y});
    const col = dotColors[e.quadrant] || '#94a3b8';
    ctx.fillStyle = col;
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, 2*Math.PI);
    ctx.fill();
    ctx.fillStyle = col;
    ctx.font = 'bold 10px system-ui';
    ctx.fillText('#' + e.task_id, x + 7, y + 4);
  }
}

// ── Timeline (Gantt) tab ─────────────────────────────────────────────────────

window.loadTimeline = function() { loadTimeline(); };

function loadTimeline() {
  api(pUrl('/api/timeline')).then(data => {
    renderTimeline(data);
  }).catch(() => {
    document.getElementById('timelineStatus').textContent = 'Failed to load timeline.';
  });
}

function renderTimeline(data) {
  // Apply filter bar: restrict to matching task IDs.
  let bars = data.bars || [];
  if (_filterActive() && appState && appState.plan && appState.plan.tasks) {
    const filteredIds = new Set(applyFilters(appState.plan.tasks).map(t => t.id));
    bars = bars.filter(b => filteredIds.has(b.taskId));
    updateFilterBadge(bars.length, (data.bars||[]).length);
  } else {
    updateFilterBadge((data.bars||[]).length, (data.bars||[]).length);
  }
  const nowStr = data.now;

  const chartWrap = document.getElementById('timelineChart');
  const emptyEl   = document.getElementById('timelineEmpty');
  const legendEl  = document.getElementById('timelineLegend');
  const statusEl  = document.getElementById('timelineStatus');

  if (!bars.length) {
    chartWrap.style.display = 'none';
    if (emptyEl) emptyEl.style.display = '';
    if (legendEl) legendEl.style.display = 'none';
    if (statusEl) statusEl.textContent = '';
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';
  chartWrap.style.display = '';
  if (legendEl) legendEl.style.display = 'flex';

  // Time range.
  let earliest = new Date(bars[0].start);
  let latest   = new Date(bars[0].end);
  bars.forEach(b => {
    const s = new Date(b.start), e = new Date(b.end);
    if (s < earliest) earliest = s;
    if (e > latest)   latest   = e;
  });
  // Snap earliest to 30-min boundary.
  const snapMs = 30 * 60 * 1000;
  earliest = new Date(Math.floor(earliest.getTime() / snapMs) * snapMs);
  // Ensure at least 1-hour window.
  if (latest - earliest < 60 * 60 * 1000) {
    latest = new Date(earliest.getTime() + 60 * 60 * 1000);
  }
  // Pad right by one tick.
  latest = new Date(latest.getTime() + snapMs);

  const totalMs = latest - earliest;

  // SVG layout constants.
  const PAD_LEFT   = 230;
  const PAD_RIGHT  = 20;
  const PAD_TOP    = 44;
  const ROW_H      = 38;
  const BAR_PAD    = 7;
  const BAR_H      = ROW_H - BAR_PAD * 2;
  const CHART_W    = Math.max(700, chartWrap.clientWidth - PAD_LEFT - PAD_RIGHT - 2);
  const SVG_W      = PAD_LEFT + CHART_W + PAD_RIGHT;
  const SVG_H      = PAD_TOP + bars.length * ROW_H + 20;

  const msToX = (ms) => PAD_LEFT + (ms / totalMs) * CHART_W;
  const tsToX = (ts) => msToX(new Date(ts) - earliest);

  // Build id → bar index map for dependency arrows.
  const idxMap = {};
  bars.forEach((b, i) => { idxMap[b.taskId] = i; });

  // Color by status.
  function barColor(status) {
    switch (status) {
      case 'done':        return '#22c55e';
      case 'in_progress': return '#3b82f6';
      case 'failed':      return '#ef4444';
      case 'timed_out':   return '#f97316';
      case 'skipped':     return '#6b7280';
      default:            return '#9ca3af'; // pending
    }
  }

  function statusLabel(status) {
    switch (status) {
      case 'in_progress': return 'In Progress';
      case 'timed_out':   return 'Timed Out';
      default:            return status.charAt(0).toUpperCase() + status.slice(1);
    }
  }

  function fmtMins(m) {
    if (!m) return '—';
    const h = Math.floor(m / 60), mm = m % 60;
    return h ? h + 'h ' + mm + 'm' : mm + 'm';
  }

  // Read CSS custom properties for theme-aware SVG colors.
  const _cs = getComputedStyle(document.documentElement);
  const svgBg      = _cs.getPropertyValue('--bg').trim()      || '#0d1117';
  const svgSurface = _cs.getPropertyValue('--surface').trim() || '#161b22';
  const svgMuted   = _cs.getPropertyValue('--muted').trim()   || '#8b949e';

  // Build SVG as a string for simplicity (avoids DOM thrash on re-renders).
  let svg = ` + "`" + `<svg width="${SVG_W}" height="${SVG_H}" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit">` + "`" + `;

  // Arrow marker definition.
  svg += ` + "`" + `<defs>
    <marker id="arrowhead" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
      <polygon points="0 0, 7 3.5, 0 7" fill="${svgMuted}" opacity="0.7"/>
    </marker>
  </defs>` + "`" + `;

  // Background.
  svg += ` + "`" + `<rect width="${SVG_W}" height="${SVG_H}" fill="${svgBg}"/>` + "`" + `;

  // Tick marks and vertical grid lines.
  const tickIntervalMs = 30 * 60 * 1000; // 30 min
  const labelEvery = 2; // label every 2 ticks (= 1 hour)
  let tick = earliest.getTime(), tickCount = 0;
  while (tick <= latest.getTime()) {
    const x = msToX(tick - earliest.getTime());
    svg += ` + "`" + `<line x1="${x.toFixed(1)}" y1="${PAD_TOP}" x2="${x.toFixed(1)}" y2="${SVG_H - 10}" class="tl-grid-line"/>` + "`" + `;
    if (tickCount % labelEvery === 0) {
      const d = new Date(tick);
      const label = d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
      svg += ` + "`" + `<text x="${x.toFixed(1)}" y="${PAD_TOP - 8}" class="tl-tick-label" text-anchor="middle">${label}</text>` + "`" + `;
    }
    tick += tickIntervalMs;
    tickCount++;
  }

  // Date label.
  svg += ` + "`" + `<text x="${PAD_LEFT}" y="14" font-size="11" fill="${svgMuted}">${earliest.toLocaleDateString()}</text>` + "`" + `;

  // Task rows.
  bars.forEach((b, i) => {
    const y = PAD_TOP + i * ROW_H;
    const rowFill = i % 2 === 0 ? svgSurface : svgBg;
    svg += ` + "`" + `<rect x="0" y="${y}" width="${SVG_W}" height="${ROW_H}" fill="${rowFill}"/>` + "`" + `;

    // Label (truncated to ~28 chars).
    let label = ` + "`[${b.taskId}] ${b.title}`" + `;
    if (label.length > 30) label = label.slice(0, 29) + '…';
    // Escape HTML entities in the label.
    const safeLabel = label.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    svg += ` + "`" + `<text x="${PAD_LEFT - 8}" y="${y + ROW_H / 2 + 4}" class="tl-task-label" text-anchor="end">${safeLabel}</text>` + "`" + `;

    // Bar.
    const bx = tsToX(b.start);
    const bxEnd = tsToX(b.end);
    const bw = Math.max(4, bxEnd - bx);
    const by = y + BAR_PAD;
    const color = barColor(b.status);

    // We encode tooltip data as data-* attributes; JS attaches mouseover.
    const tipTitle = ` + "`[${b.taskId}] ${b.title}`" + `.replace(/"/g, '&quot;');
    const assignee = b.assignee ? ` + "`Assignee: ${b.assignee}`" + ` : '';
    const est  = fmtMins(b.estimatedMinutes);
    const act  = fmtMins(b.actualMinutes);
    const sl   = statusLabel(b.status);
    const tipMeta = ` + "`${sl}${assignee ? ' · ' + assignee : ''} | Est: ${est} · Actual: ${act}`" + `.replace(/"/g, '&quot;');

    svg += ` + "`" + `<rect class="tl-bar" x="${bx.toFixed(1)}" y="${by}" width="${bw.toFixed(1)}" height="${BAR_H}"
      rx="4" ry="4" fill="${color}"
      data-title="${tipTitle}" data-meta="${tipMeta}"/>` + "`" + `;
  });

  // Dependency arrows — drawn after rows so they appear on top.
  // For each task with dependencies, draw a path from dep's bar end to this task's bar start.
  bars.forEach((b, i) => {
    if (!b.dependsOn || !b.dependsOn.length) return;
    const y2 = PAD_TOP + i * ROW_H + ROW_H / 2; // mid of current bar row
    const x2 = tsToX(b.start); // start of current bar

    b.dependsOn.forEach(depId => {
      const depIdx = idxMap[depId];
      if (depIdx === undefined) return;
      const dep = bars[depIdx];
      const y1 = PAD_TOP + depIdx * ROW_H + ROW_H / 2; // mid of dep row
      const x1 = tsToX(dep.end); // end of dep bar

      // Cubic bezier: exit right from dep end, enter left of current start.
      const cx1 = x1 + Math.abs(x2 - x1) * 0.4 + 10;
      const cx2 = x2 - Math.abs(x2 - x1) * 0.4 - 10;
      svg += ` + "`" + `<path class="tl-dep-arrow" d="M${x1.toFixed(1)},${y1.toFixed(1)} C${cx1.toFixed(1)},${y1.toFixed(1)} ${cx2.toFixed(1)},${y2.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}"/>` + "`" + `;
    });
  });

  // 'Now' cursor.
  const nowX = tsToX(nowStr);
  if (nowX >= PAD_LEFT && nowX <= PAD_LEFT + CHART_W) {
    svg += ` + "`" + `<line x1="${nowX.toFixed(1)}" y1="${PAD_TOP - 2}" x2="${nowX.toFixed(1)}" y2="${SVG_H - 10}" class="tl-now-line"/>` + "`" + `;
    svg += ` + "`" + `<text x="${nowX.toFixed(1)}" y="${PAD_TOP - 12}" font-size="10" fill="#f87171" text-anchor="middle">now</text>` + "`" + `;
  }

  svg += '</svg>';

  chartWrap.innerHTML = svg;

  // Attach tooltip handlers to bars.
  const tip = document.getElementById('tlTooltip');
  chartWrap.querySelectorAll('.tl-bar').forEach(bar => {
    bar.addEventListener('mouseenter', () => {
      tip.innerHTML = ` + "`<strong>${bar.dataset.title}</strong><div class=\"tl-tip-row\">${bar.dataset.meta}</div>`" + `;
      tip.style.display = 'block';
    });
    bar.addEventListener('mousemove', (e) => {
      const x = e.clientX + 14;
      const y = e.clientY - 10;
      const tw = tip.offsetWidth;
      const ww = window.innerWidth;
      tip.style.left = (x + tw > ww ? e.clientX - tw - 14 : x) + 'px';
      tip.style.top  = y + 'px';
    });
    bar.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
  });

  if (statusEl) statusEl.textContent = bars.length + ' task' + (bars.length !== 1 ? 's' : '');
}

// ── Actions ─────────────────────────────────────────────────────────────────

window.refreshState = function() {
  api(pUrl('/api/state')).then(s => { render(s); toast('Refreshed', 'ok'); }).catch(() => toast('Load failed', 'err'));
};

window.apiRun = function(opts) {
  api(pUrl('/api/run'), opts).then(d => {
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
  api(pUrl('/api/run'), opts).then(d => {
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
  api(pUrl('/api/init'), {
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
  api(pUrl('/api/task/add'), {
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
  api(pUrl('/api/task/status'), {id, status}).then(d => {
    if (d.ok) { toast('Task '+id+': '+status, 'ok'); refreshState(); }
    else toast(d.error||'Update failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.moveTask = function(id, direction) {
  api(pUrl('/api/task/move'), {id, direction}).then(d => {
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
  apiMethod('DELETE', pUrl('/api/tasks/' + id), null).then(d => {
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

  apiMethod('POST', pUrl('/api/tasks/reorder'), {ids}).then(d => {
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
  api(pUrl('/api/task/edit'), {
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

  api(pUrl('/api/suggest/run'), {count}).then(d => {
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
  api(pUrl('/api/reset'), {}).then(d => {
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
    const resp = await fetch(pUrl('/api/chat'), {
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
  fetch(pUrl('/api/chat/history'), {headers: authHeaders()}).then(r => r.json()).then(history => {
    if (!history || !history.length) return;
    const box = document.getElementById('chatMessages');
    if (!box) return;
    box.innerHTML = '';
    history.forEach(m => appendChatBubble(m.role, m.content, {ts: m.timestamp, action: m.action}));
  }).catch(() => {});
}

// ── Plan Assistant tab ────────────────────────────────────────────────────────

const ASSISTANT_STORAGE_KEY = 'cloop_assistant_history';
let assistantHistory = []; // [{role, content}]
let assistantStreaming = false;

function loadAssistantHistory() {
  try {
    const raw = sessionStorage.getItem(ASSISTANT_STORAGE_KEY);
    if (raw) {
      assistantHistory = JSON.parse(raw) || [];
    }
  } catch(e) {
    assistantHistory = [];
  }
  const box = document.getElementById('assistantMessages');
  if (!box) return;
  box.innerHTML = '';
  if (assistantHistory.length === 0) {
    box.innerHTML = '<div class="chat-welcome" id="assistantWelcome">' +
      '<div class="chat-welcome-icon">&#129302;</div>' +
      '<div class="chat-welcome-title">Plan-Aware Assistant</div>' +
      '<div class="chat-welcome-text">I have full knowledge of your plan — tasks, statuses, priorities, and annotations.<br>' +
      'Ask me anything about your project or click a suggested question above.</div>' +
      '</div>';
    return;
  }
  assistantHistory.forEach(m => appendAssistantBubble(m.role, m.content, false));
}

function saveAssistantHistory() {
  try {
    sessionStorage.setItem(ASSISTANT_STORAGE_KEY, JSON.stringify(assistantHistory));
  } catch(e) {}
}

function appendAssistantBubble(role, content, streaming) {
  const box = document.getElementById('assistantMessages');
  if (!box) return null;
  const welcome = box.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  const row = document.createElement('div');
  row.className = 'chat-bubble-row ' + role;
  const initials = role === 'user' ? 'U' : 'AI';

  const bubbleDiv = document.createElement('div');
  bubbleDiv.className = 'chat-bubble ' + role;
  bubbleDiv.textContent = content;
  if (streaming) {
    const cursor = document.createElement('span');
    cursor.className = 'assistant-streaming-cursor';
    cursor.id = 'assistantCursor';
    bubbleDiv.appendChild(cursor);
  }

  const timeDiv = document.createElement('div');
  timeDiv.className = 'chat-bubble-time';
  timeDiv.textContent = chatFmtTime(new Date());

  const avatarDiv = document.createElement('div');
  avatarDiv.className = 'chat-avatar ' + role;
  avatarDiv.textContent = initials;

  const inner = document.createElement('div');
  inner.appendChild(bubbleDiv);
  inner.appendChild(timeDiv);

  row.appendChild(avatarDiv);
  row.appendChild(inner);
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
  return { row, bubbleDiv };
}

window.assistantChipAsk = function(question) {
  const inp = document.getElementById('assistantInput');
  if (inp) inp.value = question;
  submitAssistantChat();
};

function autoGrowTextarea(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

window.submitAssistantChat = async function() {
  if (assistantStreaming) return;
  const input = document.getElementById('assistantInput');
  if (!input) return;
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  input.style.height = 'auto';

  // Add user bubble.
  appendAssistantBubble('user', msg, false);
  assistantHistory.push({role: 'user', content: msg});

  // Show streaming assistant bubble.
  const result = appendAssistantBubble('assistant', '', true);
  if (!result) return;
  const { bubbleDiv } = result;
  let accumulated = '';

  assistantStreaming = true;
  const box = document.getElementById('assistantMessages');

  try {
    const body = JSON.stringify({
      message: msg,
      history: assistantHistory.slice(0, -1), // exclude the user message just added
    });
    const resp = await fetch(pUrl('/api/chat/plan'), {
      method: 'POST',
      headers: Object.assign({'Content-Type': 'application/json'}, authHeaders()),
      body,
    });
    if (resp.status === 401) { showLoginModal(); return; }
    if (!resp.ok || !resp.body) {
      const errText = await resp.text().catch(() => 'Request failed');
      bubbleDiv.textContent = errText;
      bubbleDiv.classList.add('error');
      assistantStreaming = false;
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line

      let eventType = '';
      for (const line of lines) {
        if (line.startsWith('event: ')) {
          eventType = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          const raw = line.slice(6).trim();
          if (eventType === 'token') {
            try {
              const d = JSON.parse(raw);
              accumulated += (d.token || '');
              // Update bubble text while keeping cursor.
              const cursor = document.getElementById('assistantCursor');
              bubbleDiv.textContent = accumulated;
              if (cursor) bubbleDiv.appendChild(cursor);
              if (box) box.scrollTop = box.scrollHeight;
            } catch(e) {}
          } else if (eventType === 'error') {
            try {
              const d = JSON.parse(raw);
              accumulated = d.error || 'Error';
              bubbleDiv.textContent = accumulated;
              bubbleDiv.classList.add('error');
            } catch(e) {}
          } else if (eventType === 'done') {
            // Remove cursor.
            const cursor = document.getElementById('assistantCursor');
            if (cursor) cursor.remove();
          }
          eventType = '';
        }
      }
    }
  } catch(err) {
    const cursor = document.getElementById('assistantCursor');
    if (cursor) cursor.remove();
    accumulated = 'Request failed: ' + err.message;
    bubbleDiv.textContent = accumulated;
    bubbleDiv.classList.add('error');
  }

  // Remove blinking cursor if still present.
  const cursor = document.getElementById('assistantCursor');
  if (cursor) cursor.remove();

  assistantStreaming = false;

  if (accumulated && !bubbleDiv.classList.contains('error')) {
    assistantHistory.push({role: 'assistant', content: accumulated});
    saveAssistantHistory();
  }
};

window.clearAssistantPanel = function() {
  assistantHistory = [];
  saveAssistantHistory();
  const box = document.getElementById('assistantMessages');
  if (!box) return;
  box.innerHTML = '<div class="chat-welcome" id="assistantWelcome">' +
    '<div class="chat-welcome-icon">&#129302;</div>' +
    '<div class="chat-welcome-title">Plan-Aware Assistant</div>' +
    '<div class="chat-welcome-text">I have full knowledge of your plan — tasks, statuses, priorities, and annotations.<br>' +
    'Ask me anything about your project or click a suggested question above.</div>' +
    '</div>';
};

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

// ── Keyboard shortcuts & Command Palette ─────────────────────────────────────

// Maps 1-8 to tab names in left-to-right order.
const TAB_KEYS = ['overview','tasks','kanban','timeline','chat','assistant','projects','suggest','settings'];

// All commands registered in the palette.
const CMD_REGISTRY = [
  { label:'Overview',        icon:'🏠', shortcut:'1', action:()=>switchTab('overview') },
  { label:'Tasks',           icon:'📋', shortcut:'2', action:()=>switchTab('tasks') },
  { label:'Kanban',          icon:'🗂', shortcut:'3', action:()=>switchTab('kanban') },
  { label:'Timeline',        icon:'📅', shortcut:'4', action:()=>switchTab('timeline') },
  { label:'Chat',            icon:'💬', shortcut:'5', action:()=>switchTab('chat') },
  { label:'Assistant',       icon:'🤖', shortcut:'6', action:()=>switchTab('assistant') },
  { label:'Projects',        icon:'📁', shortcut:'7', action:()=>switchTab('projects') },
  { label:'Suggest',         icon:'💡', shortcut:'8', action:()=>switchTab('suggest') },
  { label:'Settings',        icon:'⚙️', shortcut:'9', action:()=>switchTab('settings') },
  { label:'Refresh state',   icon:'🔄', shortcut:'r',  action:()=>{ api(pUrl('/api/state')).then(s=>render(s)).catch(()=>{}); toast('Refreshed','ok'); } },
  { label:'New task',        icon:'➕', shortcut:'n',  action:()=>{ switchTab('tasks'); setTimeout(()=>{ const el=document.getElementById('newTaskTitle'); if(el){el.focus();} },100); } },
  { label:'Start run',       icon:'▶️', shortcut:'',   action:()=>submitRun() },
  { label:'Stop run',        icon:'⏹', shortcut:'',   action:()=>submitStop() },
  { label:'Show kanban',     icon:'🗂', shortcut:'',   action:()=>switchTab('kanban') },
  { label:'Show timeline',   icon:'📊', shortcut:'',   action:()=>switchTab('timeline') },
  { label:'Show chat',       icon:'🤖', shortcut:'',   action:()=>switchTab('chat') },
  { label:'Show assistant',  icon:'🤖', shortcut:'',   action:()=>switchTab('assistant') },
  { label:'Add task',        icon:'✏️', shortcut:'',   action:()=>{ switchTab('tasks'); setTimeout(()=>{ const el=document.getElementById('newTaskTitle'); if(el){el.focus();} },100); } },
  { label:'Run plan',        icon:'🚀', shortcut:'',   action:()=>submitRun() },
  { label:'Reset session',   icon:'🗑', shortcut:'',   action:()=>submitReset() },
];

// ── Command palette state ────────────────────────────────────────────────────
let cmdOpen = false;
let cmdSelectedIdx = 0;
let cmdFiltered = [...CMD_REGISTRY];

function openCommandPalette() {
  cmdOpen = true;
  cmdSelectedIdx = 0;
  cmdFiltered = [...CMD_REGISTRY];
  document.getElementById('cmd-backdrop').classList.add('open');
  const inp = document.getElementById('cmd-input');
  inp.value = '';
  renderCmdResults('');
  setTimeout(() => inp.focus(), 30);
}

function closeCommandPalette() {
  cmdOpen = false;
  document.getElementById('cmd-backdrop').classList.remove('open');
}

function renderCmdResults(query) {
  const q = query.trim().toLowerCase();
  cmdFiltered = q
    ? CMD_REGISTRY.filter(c => c.label.toLowerCase().includes(q))
    : [...CMD_REGISTRY];
  if (cmdSelectedIdx >= cmdFiltered.length) cmdSelectedIdx = 0;

  const container = document.getElementById('cmd-results');
  if (!cmdFiltered.length) {
    container.innerHTML = '<div class="cmd-no-results">No matching commands</div>';
    return;
  }
  container.innerHTML = cmdFiltered.map((c, i) => {
    const labelHtml = q
      ? esc(c.label).replace(new RegExp('('+escRe(q)+')', 'gi'), '<em>$1</em>')
      : esc(c.label);
    const sel = i === cmdSelectedIdx ? ' selected' : '';
    return '<div class="cmd-item'+sel+'" role="option" aria-selected="'+(i===cmdSelectedIdx)+'" data-idx="'+i+'" onclick="cmdSelect('+i+')" onmouseenter="cmdHover('+i+')">'+
      '<span class="cmd-item-icon">'+c.icon+'</span>'+
      '<span class="cmd-item-label cmd-item-match">'+labelHtml+'</span>'+
      (c.shortcut ? '<span class="cmd-item-shortcut"><kbd>'+esc(c.shortcut)+'</kbd></span>' : '')+
    '</div>';
  }).join('');
  scrollCmdItemIntoView();
}

function escRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function scrollCmdItemIntoView() {
  const container = document.getElementById('cmd-results');
  const sel = container.querySelector('.cmd-item.selected');
  if (sel) sel.scrollIntoView({ block: 'nearest' });
}

window.cmdSelect = function(idx) {
  const cmd = cmdFiltered[idx];
  if (!cmd) return;
  closeCommandPalette();
  cmd.action();
};

window.cmdHover = function(idx) {
  cmdSelectedIdx = idx;
  document.querySelectorAll('.cmd-item').forEach((el,i) => {
    el.classList.toggle('selected', i === idx);
    el.setAttribute('aria-selected', i === idx ? 'true' : 'false');
  });
};

document.getElementById('cmd-input').addEventListener('input', function() {
  renderCmdResults(this.value);
});

document.getElementById('cmd-input').addEventListener('keydown', function(e) {
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    cmdSelectedIdx = Math.min(cmdSelectedIdx + 1, cmdFiltered.length - 1);
    renderCmdResults(this.value);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    cmdSelectedIdx = Math.max(cmdSelectedIdx - 1, 0);
    renderCmdResults(this.value);
  } else if (e.key === 'Enter') {
    e.preventDefault();
    cmdSelect(cmdSelectedIdx);
  } else if (e.key === 'Escape') {
    e.preventDefault();
    closeCommandPalette();
  }
});

// Close palette when clicking backdrop (not palette itself).
document.getElementById('cmd-backdrop').addEventListener('click', function(e) {
  if (e.target === this) closeCommandPalette();
});

// ── Task keyboard navigation state ───────────────────────────────────────────
let kbTaskIdx = -1; // index into currently visible task list items

function getTaskItems() {
  return Array.from(document.querySelectorAll('#taskListFull .task-item'));
}

function kbFocusTask(idx) {
  const items = getTaskItems();
  if (!items.length) return;
  idx = Math.max(0, Math.min(idx, items.length - 1));
  kbTaskIdx = idx;
  items.forEach((el, i) => el.classList.toggle('kb-focus', i === idx));
  items[idx].scrollIntoView({ block: 'nearest' });
}

function kbClearFocus() {
  kbTaskIdx = -1;
  getTaskItems().forEach(el => el.classList.remove('kb-focus'));
}

// ── Global keyboard shortcut handler ─────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  // Never intercept when typing in a real input/editable area.
  const tag = ((e.target && e.target.tagName) || '').toUpperCase();
  const inInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target.isContentEditable;

  // Cmd/Ctrl+K — open command palette (always, even in inputs).
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    if (cmdOpen) { closeCommandPalette(); } else { openCommandPalette(); }
    return;
  }

  // Escape — close any open modal / palette.
  if (e.key === 'Escape') {
    if (cmdOpen) { closeCommandPalette(); return; }
    const modal = document.getElementById('modal-overlay');
    if (modal && modal.classList.contains('open')) { closeModal(); return; }
    const voice = document.querySelector('.voice-modal-backdrop');
    if (voice) { voice.remove(); return; }
    kbClearFocus();
    return;
  }

  // All remaining shortcuts are blocked when typing in inputs.
  if (inInput) return;
  // Also block when palette is open.
  if (cmdOpen) return;

  // 1-7: switch to tab by number.
  if (e.key >= '1' && e.key <= '7' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    const idx = parseInt(e.key, 10) - 1;
    if (TAB_KEYS[idx]) { switchTab(TAB_KEYS[idx]); kbClearFocus(); }
    return;
  }

  // r: refresh state.
  if (e.key === 'r' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    api(pUrl('/api/state')).then(s => render(s)).catch(() => {});
    toast('Refreshed', 'ok');
    return;
  }

  // n: new task — switch to Tasks tab and focus the add-task input.
  if (e.key === 'n' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    switchTab('tasks');
    kbClearFocus();
    setTimeout(() => { const el = document.getElementById('newTaskTitle'); if (el) el.focus(); }, 100);
    return;
  }

  // j/k: move focus through task list (only on Tasks tab).
  if ((e.key === 'j' || e.key === 'k') && activeTab === 'tasks') {
    e.preventDefault();
    const items = getTaskItems();
    if (!items.length) return;
    if (kbTaskIdx < 0) {
      kbFocusTask(e.key === 'j' ? 0 : items.length - 1);
    } else {
      kbFocusTask(kbTaskIdx + (e.key === 'j' ? 1 : -1));
    }
    return;
  }

  // Enter: open edit modal for the focused task.
  if (e.key === 'Enter' && activeTab === 'tasks' && kbTaskIdx >= 0) {
    e.preventDefault();
    const items = getTaskItems();
    const item = items[kbTaskIdx];
    if (item) {
      const editBtn = item.querySelector('.act.edit');
      if (editBtn) editBtn.click();
    }
    return;
  }
}, true); // use capture so we run before chat voice handler

// ── Init ─────────────────────────────────────────────────────────────────────

// On page load, probe the server. If it returns 401 show the login modal,
// otherwise detect multi-project mode and start WebSocket (SSE as fallback).
function checkAuthAndInit() {
  fetch('/api/state', {headers: authHeaders()}).then(r => {
    if (r.status === 401) {
      showLoginModal();
      return;
    }
    // Also check for multi-project mode.
    fetch('/api/projects', {headers: authHeaders()}).then(pr => pr.json()).then(pd => {
      const projects = pd.projects || [];
      isMultiProject = pd.multi_project === true || projects.length > 1;
      connectWS();
      if (isMultiProject) {
        // In multi-project mode, Projects list is the landing page.
        renderProjects(projects, pd.stats || {});
        updateProjectSelector();
        switchTab('projects');
      } else {
        r.json().then(s => render(s)).catch(() => {});
      }
    }).catch(() => {
      connectWS();
      r.json().then(s => render(s)).catch(() => {});
    });
  }).catch(() => {
    connectWS();
  });
}

// ── Theme toggle ─────────────────────────────────────────────────────────────

function _applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const icon = document.getElementById('themeToggleIcon');
  if (icon) {
    // Sun = currently dark (click to go light), Moon = currently light (click to go dark).
    icon.textContent = theme === 'light' ? '\u263D' : '\u2600';
  }
  const btn = document.getElementById('themeToggleBtn');
  if (btn) btn.setAttribute('aria-label', theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode');
}

// Sync icon with whatever the FOUC script already set.
(function() {
  const t = document.documentElement.getAttribute('data-theme') || 'dark';
  _applyTheme(t);
})();

window.toggleTheme = function() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  localStorage.setItem('cloop-theme', next);
  _applyTheme(next);
  // Re-render timeline if it's the active tab so SVG colors update.
  if (typeof activeTab !== 'undefined' && activeTab === 'timeline') {
    renderTimeline();
  }
};

checkAuthAndInit();

// ── Analytics dashboard ────────────────────────────────────────

// Chart.js instances — stored so we can destroy+recreate on refresh.
let _chartDonut = null, _chartVelocity = null, _chartBurndown = null,
    _chartCost = null, _chartLatency = null;

// 30-second auto-refresh timer (only fires when analytics tab is visible).
let _analyticsTimer = null;

// Palette for multi-provider datasets.
const _paletteBg   = ['rgba(88,166,255,.7)','rgba(63,185,80,.7)','rgba(188,140,255,.7)','rgba(57,197,207,.7)','rgba(248,81,73,.7)','rgba(210,153,34,.7)'];
const _paletteLine = ['#58a6ff','#3fb950','#bc8cff','#39c5cf','#f85149','#d29922'];

function analyticsResetRange() {
  const to   = new Date();
  const from = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const fmt = d => d.toISOString().slice(0,10);
  const fi = document.getElementById('analyticsFrom');
  const ti = document.getElementById('analyticsTo');
  if (fi) fi.value = fmt(from);
  if (ti) ti.value = fmt(to);
  loadAnalytics();
}

window.loadAnalytics = function() {
  // Initialise date pickers if empty.
  const fi = document.getElementById('analyticsFrom');
  const ti = document.getElementById('analyticsTo');
  if (fi && !fi.value) {
    const from = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    fi.value = from.toISOString().slice(0,10);
  }
  if (ti && !ti.value) {
    ti.value = new Date().toISOString().slice(0,10);
  }

  const fromVal = fi ? fi.value : '';
  const toVal   = ti ? ti.value : '';
  const qs = (fromVal ? '&from=' + fromVal : '') + (toVal ? '&to=' + toVal : '');

  api(pUrl('/api/analytics?' + qs)).then(d => {
    _renderAnalytics(d);
  }).catch(err => {
    console.warn('analytics load error', err);
  });

  // Load epics panel separately (no date filter needed).
  api(pUrl('/api/epics')).then(d => {
    _renderEpics(d);
  }).catch(() => {});

  // Restart 30s auto-refresh timer.
  if (_analyticsTimer) clearTimeout(_analyticsTimer);
  _analyticsTimer = setTimeout(() => {
    if (activeTab === 'analytics') loadAnalytics();
  }, 30000);
};

function _destroyChart(ch) {
  try { if (ch) ch.destroy(); } catch(_) {}
  return null;
}

function _analyticsColors() {
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  return {
    text:   isDark ? '#e6edf3' : '#1f2328',
    muted:  isDark ? '#8b949e' : '#656d76',
    grid:   isDark ? 'rgba(48,54,61,.6)' : 'rgba(208,215,222,.6)',
  };
}

function _renderAnalytics(d) {
  const clr = _analyticsColors();
  const tickOpts = { color: clr.muted, font: { size: 11 } };
  const gridOpts = { color: clr.grid };
  const legendOpts = { labels: { color: clr.text, font: { size: 11 }, boxWidth: 12 } };

  // ── Status Donut ──────────────────────────────────────────────
  _chartDonut = _destroyChart(_chartDonut);
  const donutCtx = document.getElementById('chartStatusDonut');
  if (donutCtx && d.status_donut) {
    const nonzero = d.status_donut.values.some(v => v > 0);
    donutCtx.closest('div').style.display = nonzero ? '' : 'none';
    if (nonzero) {
      _chartDonut = new Chart(donutCtx, {
        type: 'doughnut',
        data: {
          labels: d.status_donut.labels,
          datasets: [{
            data: d.status_donut.values,
            backgroundColor: ['#8b949e','#39c5cf','#3fb950','#f85149','#d29922','#bc8cff'],
            borderWidth: 0,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '60%',
          plugins: { legend: legendOpts, tooltip: { callbacks: {
            label: ctx => ' ' + ctx.label + ': ' + ctx.raw
          }}}
        }
      });
    }
  }

  // ── Velocity Sparkline ────────────────────────────────────────
  _chartVelocity = _destroyChart(_chartVelocity);
  const velCtx = document.getElementById('chartVelocity');
  if (velCtx && d.velocity) {
    _chartVelocity = new Chart(velCtx, {
      type: 'bar',
      data: {
        labels: d.velocity.labels.map(l => l.slice(5)), // MM-DD
        datasets: [{
          label: 'Tasks completed',
          data: d.velocity.values,
          backgroundColor: 'rgba(88,166,255,.6)',
          borderColor: '#58a6ff',
          borderWidth: 1,
          borderRadius: 3,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { ...tickOpts, maxRotation: 45 }, grid: gridOpts },
          y: { ticks: { ...tickOpts, stepSize: 1 }, grid: gridOpts, beginAtZero: true }
        }
      }
    });
  }

  // ── Burndown ──────────────────────────────────────────────────
  _chartBurndown = _destroyChart(_chartBurndown);
  const bdCtx = document.getElementById('chartBurndown');
  if (bdCtx && d.burndown) {
    _chartBurndown = new Chart(bdCtx, {
      type: 'line',
      data: {
        labels: d.burndown.labels.map(l => l.slice(5)),
        datasets: [
          {
            label: 'Done (cumulative)',
            data: d.burndown.done_cumulative,
            borderColor: '#3fb950',
            backgroundColor: 'rgba(63,185,80,.15)',
            fill: true,
            tension: 0.3,
            pointRadius: 2,
          },
          {
            label: 'Remaining',
            data: d.burndown.remaining,
            borderColor: '#f85149',
            backgroundColor: 'rgba(248,81,73,.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 2,
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: legendOpts },
        scales: {
          x: { ticks: { ...tickOpts, maxRotation: 45 }, grid: gridOpts },
          y: { ticks: tickOpts, grid: gridOpts, beginAtZero: true }
        }
      }
    });
  }

  // ── Cost Trend ────────────────────────────────────────────────
  _chartCost = _destroyChart(_chartCost);
  const costCtx = document.getElementById('chartCostTrend');
  if (costCtx && d.cost_trend) {
    const datasets = (d.cost_trend.datasets || []).map((ds, i) => ({
      label: ds.provider,
      data: ds.values,
      borderColor: _paletteLine[i % _paletteLine.length],
      backgroundColor: _paletteBg[i % _paletteBg.length],
      fill: false,
      tension: 0.3,
      pointRadius: 2,
    }));
    if (datasets.length === 0) {
      datasets.push({
        label: 'No data',
        data: (d.cost_trend.labels || []).map(() => 0),
        borderColor: clr.muted,
        fill: false,
        tension: 0,
        pointRadius: 0,
      });
    }
    _chartCost = new Chart(costCtx, {
      type: 'line',
      data: { labels: (d.cost_trend.labels || []).map(l => l.slice(5)), datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: legendOpts },
        scales: {
          x: { ticks: { ...tickOpts, maxRotation: 45 }, grid: gridOpts },
          y: { ticks: { ...tickOpts, callback: v => '$' + v.toFixed(4) }, grid: gridOpts, beginAtZero: true }
        }
      }
    });
  }

  // ── Latency Histogram ─────────────────────────────────────────
  _chartLatency = _destroyChart(_chartLatency);
  const latCtx = document.getElementById('chartLatency');
  const latEmpty = document.getElementById('analyticsLatencyEmpty');
  const hasLatency = d.latency && d.latency.datasets && d.latency.datasets.length > 0;
  if (latEmpty) latEmpty.style.display = hasLatency ? 'none' : 'block';
  if (latCtx && hasLatency) {
    const datasets = d.latency.datasets.map((ds, i) => ({
      label: ds.provider,
      data: ds.counts,
      backgroundColor: _paletteBg[i % _paletteBg.length],
      borderColor: _paletteLine[i % _paletteLine.length],
      borderWidth: 1,
      borderRadius: 3,
    }));
    _chartLatency = new Chart(latCtx, {
      type: 'bar',
      data: { labels: d.latency.buckets, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: legendOpts },
        scales: {
          x: { ticks: tickOpts, grid: gridOpts },
          y: { ticks: { ...tickOpts, stepSize: 1 }, grid: gridOpts, beginAtZero: true }
        }
      }
    });
  }

  // Empty state.
  const anyData = (d.burndown && d.burndown.done_cumulative && d.burndown.done_cumulative.some(v => v > 0)) ||
                  hasLatency ||
                  (d.cost_trend && d.cost_trend.datasets && d.cost_trend.datasets.length > 0);
  const emptyEl = document.getElementById('analyticsEmpty');
  if (emptyEl) emptyEl.style.display = anyData ? 'none' : 'block';

  // Last-refresh timestamp.
  const lr = document.getElementById('analyticsLastRefresh');
  if (lr) lr.textContent = 'Last refreshed: ' + new Date().toLocaleTimeString();
}

// ── Epics panel renderer ───────────────────────────────────────
function _renderEpics(d) {
  const card = document.getElementById('epicsCard');
  const list = document.getElementById('epicsList');
  if (!card || !list) return;

  const epics = (d && d.epics) || [];
  if (epics.length === 0) {
    card.style.display = 'none';
    return;
  }

  const epicPalette = [
    '#58a6ff', '#3fb950', '#f78166', '#d2a8ff', '#ffa657', '#79c0ff', '#ff7b72',
  ];

  let html = '';
  epics.forEach((ep, i) => {
    const color = epicPalette[i % epicPalette.length];
    const total = ep.total || 0;
    const done  = ep.done  || 0;
    const pct   = total > 0 ? Math.round(done * 100 / total) : 0;
    const desc  = ep.description || '';

    html += '<div style="margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">';
    html += '<span style="font-size:13px;font-weight:600;color:' + color + '">' + esc(ep.name) + '</span>';
    html += '<span style="font-size:11px;color:var(--muted)">' + done + ' / ' + total + ' done &nbsp;(' + pct + '%)</span>';
    html += '</div>';
    if (desc) {
      html += '<div style="font-size:11px;color:var(--muted);margin-bottom:5px">' + esc(desc) + '</div>';
    }
    // Progress bar
    html += '<div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden">';
    html += '<div style="height:100%;width:' + pct + '%;background:' + color + ';border-radius:4px;transition:width .3s"></div>';
    html += '</div>';
    // Stat badges
    html += '<div style="display:flex;gap:8px;margin-top:4px;flex-wrap:wrap">';
    if (ep.pending  > 0) html += '<span style="font-size:10px;color:var(--muted)">' + ep.pending  + ' pending</span>';
    if (ep.failed   > 0) html += '<span style="font-size:10px;color:#f78166">'      + ep.failed   + ' failed</span>';
    if (ep.skipped  > 0) html += '<span style="font-size:10px;color:var(--muted)">' + ep.skipped  + ' skipped</span>';
    html += '</div>';
    html += '</div>';
  });

  list.innerHTML = html;
  card.style.display = '';
}

// ── Mobile nav helpers ─────────────────────────────────────────
window.openMobileNav = function() {
  const overlay = document.getElementById('mobileNavOverlay');
  const btn     = document.getElementById('hamburgerBtn');
  if (!overlay) return;
  overlay.classList.add('open');
  overlay.setAttribute('aria-hidden', 'false');
  if (btn) btn.setAttribute('aria-expanded', 'true');
  // Trap focus: first close button
  const closeBtn = overlay.querySelector('.mobile-nav-close');
  if (closeBtn) setTimeout(() => closeBtn.focus(), 50);
};

window.closeMobileNav = function() {
  const overlay = document.getElementById('mobileNavOverlay');
  const btn     = document.getElementById('hamburgerBtn');
  if (!overlay) return;
  overlay.classList.remove('open');
  overlay.setAttribute('aria-hidden', 'true');
  if (btn) btn.setAttribute('aria-expanded', 'false');
};

// Close mobile nav on Escape key.
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('mobileNavOverlay');
    if (overlay && overlay.classList.contains('open')) {
      closeMobileNav();
    }
  }
});

// ── FAB: quick-add task on mobile ─────────────────────────────
window.fabAddTask = function() {
  // Switch to tasks tab if not there already.
  if (activeTab !== 'tasks') {
    switchTab('tasks');
  }
  // Scroll to add-task input and focus it.
  const input = document.getElementById('newTaskTitle');
  if (input) {
    input.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => input.focus(), 150);
  }
};

})();
</script>
</body>
</html>
`
