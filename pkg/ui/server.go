// Package ui implements a local web dashboard for monitoring and controlling cloop.
package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Server is the cloop web dashboard HTTP server.
type Server struct {
	WorkDir string
	Port    int

	mu      sync.Mutex
	clients map[chan string]struct{}
	lastMod time.Time

	// Suggest background job state
	suggestMu      sync.Mutex
	suggestRunning bool
	suggestLog     bytes.Buffer
	suggestErr     string
	suggestDone    bool
}

// New creates a new UI server for the given working directory and port.
func New(workdir string, port int) *Server {
	return &Server{
		WorkDir: workdir,
		Port:    port,
		clients: make(map[chan string]struct{}),
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

	// Task management
	mux.HandleFunc("/api/task/add", s.handleTaskAdd)
	mux.HandleFunc("/api/task/status", s.handleTaskStatus)
	mux.HandleFunc("/api/task/move", s.handleTaskMove)
	mux.HandleFunc("/api/task/edit", s.handleTaskEdit)
	mux.HandleFunc("/api/task/remove", s.handleTaskRemove)

	// Config
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/set", s.handleConfigSet)

	// Suggest
	mux.HandleFunc("/api/suggest/run", s.handleSuggestRun)
	mux.HandleFunc("/api/suggest/status", s.handleSuggestStatus)

	// Init & reset
	mux.HandleFunc("/api/init", s.handleInit)
	mux.HandleFunc("/api/reset", s.handleReset)

	go s.watchState()

	addr := ":" + strconv.Itoa(s.Port)
	fmt.Printf("cloop dashboard running at http://localhost%s\n", addr)
	return http.ListenAndServe(addr, mux)
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

// broadcast sends a state JSON payload to all connected SSE clients.
func (s *Server) broadcast(data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- data:
		default:
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 4)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	if ps, err := state.Load(s.WorkDir); err == nil {
		if data, err := json.Marshal(ps); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
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
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	go func() { _ = cmd.Wait() }()
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

// handleTaskEdit edits a task's title, description, and/or priority.
func (s *Server) handleTaskEdit(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID          int    `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
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
		if ps, err := state.Load(s.WorkDir); err == nil {
			if data, err := json.Marshal(ps); err == nil {
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
</style>
</head>
<body>
<div class="layout">
  <header>
    <h1>cloop <span>dashboard</span></h1>
    <div class="live-dot" id="liveDot"></div>
    <div class="tab-nav">
      <button class="tab-btn active" onclick="switchTab('overview')"  id="tbtn-overview">Overview</button>
      <button class="tab-btn"        onclick="switchTab('tasks')"     id="tbtn-tasks">Tasks</button>
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
            <div id="statusBadge"></div>
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
          <button class="btn primary" onclick="submitAddTask()">Add Task</button>
        </div>
      </div>
      <div class="section">
        <div class="section-title">Tasks <span id="taskCountBadge" style="color:var(--muted);font-weight:400;text-transform:none;letter-spacing:0"></span></div>
        <div class="task-list" id="taskListFull">
          <div class="empty-state"><h3>No tasks yet</h3><p>Add a task above, or run <code>cloop run --pm</code> to generate a task plan.</p></div>
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

  </main>
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
};

// ── Helpers ─────────────────────────────────────────────────────────────────

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
  const opts = body !== undefined
    ? { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) }
    : { method: 'GET' };
  return fetch(url, opts).then(r => r.json());
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
}

window.toggleStep = function(el) { el.classList.toggle('expanded'); };

// ── Render tasks tab ─────────────────────────────────────────────────────────

function renderTasks(s) {
  const container = document.getElementById('taskListFull');
  const badge     = document.getElementById('taskCountBadge');
  if (!s || !s.plan || !s.plan.tasks || !s.plan.tasks.length) {
    badge.textContent = '';
    container.innerHTML = '<div class="empty-state"><h3>No tasks yet</h3><p>Add a task above, or run <code>cloop run --pm</code> to generate a task plan.</p></div>';
    return;
  }
  const sorted = [...s.plan.tasks].sort((a,b) => a.priority - b.priority);
  const done = sorted.filter(t => t.status==='done').length;
  badge.textContent = '('+done+'/'+sorted.length+' done)';

  container.innerHTML = sorted.map(t => {
    const cls = t.status || 'pending';
    const statusActions = buildStatusActions(t);
    return '<div class="task-item '+esc(cls)+'">'+
      '<div class="task-icon">'+taskIcon(cls)+'</div>'+
      '<div class="task-body">'+
        '<div class="task-title">'+esc(t.title)+'</div>'+
        (t.description ? '<div class="task-desc">'+esc(t.description)+'</div>' : '')+
        '<div class="task-meta">'+
          '<span>'+esc(cls)+'</span>'+
          (t.role?'<span>'+esc(t.role)+'</span>':'')+
        '</div>'+
      '</div>'+
      '<div class="task-actions">'+
        statusActions+
        '<button class="act" title="Move up"    onclick="moveTask('+t.id+',\'up\')">↑</button>'+
        '<button class="act" title="Move down"  onclick="moveTask('+t.id+',\'down\')">↓</button>'+
        '<button class="act edit"   title="Edit"   onclick="openEditModal('+t.id+','+
          JSON.stringify(t.title).replace(/</g,'\\u003c')+','+
          JSON.stringify(t.description||'').replace(/</g,'\\u003c')+','+
          t.priority+')">Edit</button>'+
        '<button class="act remove" title="Remove" onclick="removeTask('+t.id+')">Remove</button>'+
        priorityBadge(t.priority)+
        '<span style="font-size:11px;color:var(--muted)">#'+t.id+'</span>'+
      '</div>'+
    '</div>';
  }).join('');
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

// ── SSE ─────────────────────────────────────────────────────────────────────

function connectSSE() {
  if (evtSource) evtSource.close();
  evtSource = new EventSource('/api/events');
  const dot = document.getElementById('liveDot');
  evtSource.onopen = () => dot.classList.add('connected');
  evtSource.onmessage = (e) => {
    try { render(JSON.parse(e.data)); } catch(_) {}
  };
  evtSource.onerror = () => {
    dot.classList.remove('connected');
    setTimeout(connectSSE, 3000);
  };
}

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

window.submitAddTask = function() {
  const title = document.getElementById('newTaskTitle').value.trim();
  if (!title) { toast('Title is required', 'err'); return; }
  api('/api/task/add', {
    title:       title,
    description: document.getElementById('newTaskDesc').value.trim(),
    priority:    parseInt(document.getElementById('newTaskPriority').value)||0,
  }).then(d => {
    if (d.ok) {
      document.getElementById('newTaskTitle').value    = '';
      document.getElementById('newTaskDesc').value     = '';
      document.getElementById('newTaskPriority').value = '';
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
  if (!confirm('Remove task #'+id+'?')) return;
  api('/api/task/remove', {id}).then(d => {
    if (d.ok) { toast('Task #'+id+' removed', 'ok'); refreshState(); }
    else toast(d.error||'Remove failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Edit modal ───────────────────────────────────────────────────────────────

window.openEditModal = function(id, title, desc, priority) {
  document.getElementById('modalTaskId').value   = id;
  document.getElementById('modalTitle_').value   = title;
  document.getElementById('modalDesc').value     = desc;
  document.getElementById('modalPriority').value = priority;
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

  api('/api/task/edit', {id, title, description: desc, priority}).then(d => {
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

// ── Init ─────────────────────────────────────────────────────────────────────

connectSSE();
refreshState();
})();
</script>
</body>
</html>
`
