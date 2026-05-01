// Package ui implements a local web dashboard for monitoring and controlling cloop.
package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
)

// Server is the cloop web dashboard HTTP server.
type Server struct {
	WorkDir string
	Port    int

	mu       sync.Mutex
	clients  map[chan string]struct{}
	lastMod  time.Time
	lastHash string
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
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/run", s.handleRun)
	mux.HandleFunc("/api/stop", s.handleStop)

	// Background goroutine: poll state file and broadcast changes via SSE.
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
			// drop if client is slow
		}
	}
}

// handleDashboard serves the single-page HTML dashboard.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, dashboardHTML)
}

// handleState returns the current project state as JSON.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ps, err := state.Load(s.WorkDir)
	if err != nil {
		http.Error(w, `{"error":"no cloop project found"}`, http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(ps)
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

	// Send initial state immediately.
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

// handleRun starts `cloop run` (optionally --pm) in the background.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	pm := r.URL.Query().Get("pm") == "1"
	args := []string{"run"}
	if pm {
		args = append(args, "--pm")
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = s.WorkDir
	// Redirect output to server stderr so user can see it in the terminal.
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
		return
	}
	// Detach: don't wait for it.
	go func() { _ = cmd.Wait() }()

	label := "run"
	if pm {
		label = "run --pm"
	}
	fmt.Fprintf(w, `{"ok":true,"started":%q}`, label)
}

// handleStop sends SIGTERM to any running `cloop run` processes.
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	// Use pkill to signal any cloop processes in the working directory.
	out, err := exec.Command("pkill", "-SIGINT", "-f", "cloop run").CombinedOutput()
	if err != nil {
		// pkill exits 1 if no process matched; not a real error.
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "no running cloop process found"
		}
		fmt.Fprintf(w, `{"ok":false,"message":%q}`, msg)
		return
	}
	fmt.Fprint(w, `{"ok":true,"message":"pause signal sent"}`)
}

// dashboardHTML is the single-page application served at /.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cloop dashboard</title>
<style>
  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #e6edf3;
    --muted:    #8b949e;
    --accent:   #58a6ff;
    --green:    #3fb950;
    --yellow:   #d29922;
    --red:      #f85149;
    --cyan:     #39c5cf;
    --purple:   #bc8cff;
    --radius:   8px;
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

  /* Layout */
  .layout { display: flex; flex-direction: column; min-height: 100vh; }
  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    display: flex;
    align-items: center;
    gap: 16px;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  header h1 {
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.3px;
  }
  header h1 span { color: var(--muted); font-weight: 400; }
  .live-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--muted);
    flex-shrink: 0;
    transition: background 0.3s;
  }
  .live-dot.connected { background: var(--green); animation: pulse 2s infinite; }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
  .spacer { flex: 1; }
  .updated-at { font-size: 12px; color: var(--muted); }

  main { flex: 1; padding: 24px; max-width: 1200px; margin: 0 auto; width: 100%; }

  /* Sections */
  .section { margin-bottom: 24px; }
  .section-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--muted);
    margin-bottom: 12px;
  }

  /* Cards */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
  }

  /* Goal card */
  .goal-card {
    display: flex;
    align-items: flex-start;
    gap: 16px;
  }
  .goal-text {
    flex: 1;
    font-size: 16px;
    font-weight: 500;
    line-height: 1.4;
  }
  .goal-text.empty { color: var(--muted); font-style: italic; }

  /* Status badge */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .badge.running    { background: rgba(57,197,207,0.15); color: var(--cyan);   border: 1px solid rgba(57,197,207,0.3);  }
  .badge.complete   { background: rgba(63,185,80,0.15);  color: var(--green);  border: 1px solid rgba(63,185,80,0.3);   }
  .badge.failed     { background: rgba(248,81,73,0.15);  color: var(--red);    border: 1px solid rgba(248,81,73,0.3);   }
  .badge.paused,
  .badge.initialized { background: rgba(210,153,34,0.15); color: var(--yellow); border: 1px solid rgba(210,153,34,0.3); }
  .badge.evolving   { background: rgba(188,140,255,0.15); color: var(--purple); border: 1px solid rgba(188,140,255,0.3); }
  .badge.unknown    { background: rgba(139,148,158,0.15); color: var(--muted);  border: 1px solid rgba(139,148,158,0.3); }
  .badge-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
  .badge.running .badge-dot { animation: pulse 1.5s infinite; }

  /* Stats grid */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 12px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 16px;
  }
  .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 4px; }
  .stat-value { font-size: 22px; font-weight: 700; color: var(--text); }
  .stat-value.accent { color: var(--accent); }
  .stat-sub { font-size: 11px; color: var(--muted); margin-top: 2px; }

  /* Controls */
  .controls { display: flex; gap: 8px; flex-wrap: wrap; }
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 14px;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
    text-decoration: none;
  }
  .btn:hover { background: #21262d; border-color: #8b949e; }
  .btn.primary { background: var(--accent); color: #0d1117; border-color: var(--accent); }
  .btn.primary:hover { background: #79bcff; border-color: #79bcff; }
  .btn.danger { color: var(--red); border-color: rgba(248,81,73,0.4); }
  .btn.danger:hover { background: rgba(248,81,73,0.1); border-color: var(--red); }
  .btn.success { color: var(--green); border-color: rgba(63,185,80,0.4); }
  .btn.success:hover { background: rgba(63,185,80,0.1); border-color: var(--green); }
  .btn svg { width: 14px; height: 14px; }

  /* Task list */
  .task-list { display: flex; flex-direction: column; gap: 8px; }
  .task-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
    transition: border-color 0.2s;
  }
  .task-item.in_progress { border-color: var(--cyan); background: rgba(57,197,207,0.05); }
  .task-item.done        { border-color: rgba(63,185,80,0.3); }
  .task-item.failed      { border-color: rgba(248,81,73,0.3); }
  .task-item.skipped     { opacity: 0.5; }
  .task-status-icon { font-size: 16px; flex-shrink: 0; margin-top: 1px; }
  .task-body { flex: 1; min-width: 0; }
  .task-title { font-weight: 500; }
  .task-desc { font-size: 12px; color: var(--muted); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .task-meta { font-size: 11px; color: var(--muted); margin-top: 4px; display: flex; gap: 12px; }
  .task-id { font-size: 11px; color: var(--muted); flex-shrink: 0; margin-top: 3px; }
  .task-priority {
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .task-priority.p1 { background: rgba(248,81,73,0.15); color: var(--red); }
  .task-priority.p2 { background: rgba(210,153,34,0.15); color: var(--yellow); }
  .task-priority.p3 { background: rgba(57,197,207,0.15); color: var(--cyan); }

  /* Step history */
  .step-list { display: flex; flex-direction: column; gap: 6px; }
  .step-item {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .step-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: var(--surface);
    cursor: pointer;
    user-select: none;
  }
  .step-header:hover { background: #21262d; }
  .step-num {
    font-size: 11px;
    color: var(--muted);
    font-weight: 600;
    min-width: 28px;
    flex-shrink: 0;
  }
  .step-task {
    flex: 1;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .step-meta { font-size: 11px; color: var(--muted); flex-shrink: 0; display: flex; gap: 10px; align-items: center; }
  .step-exit-ok  { color: var(--green); }
  .step-exit-bad { color: var(--red); }
  .step-chevron { color: var(--muted); transition: transform 0.2s; flex-shrink: 0; font-size: 10px; }
  .step-item.expanded .step-chevron { transform: rotate(90deg); }
  .step-output {
    display: none;
    background: #0d1117;
    border-top: 1px solid var(--border);
    padding: 12px 14px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 400px;
    overflow-y: auto;
    color: #adbac7;
  }
  .step-item.expanded .step-output { display: block; }

  /* Token bar */
  .token-bar { margin-top: 8px; }
  .token-bar-track {
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
  }
  .token-bar-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 2px;
    transition: width 0.5s ease;
  }

  /* Empty state */
  .empty-state {
    text-align: center;
    padding: 40px 20px;
    color: var(--muted);
  }
  .empty-state h3 { font-size: 16px; margin-bottom: 8px; }
  .empty-state p  { font-size: 13px; }

  /* Toast */
  #toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 10px 16px;
    font-size: 13px;
    opacity: 0;
    transform: translateY(8px);
    transition: all 0.2s ease;
    pointer-events: none;
    z-index: 100;
    max-width: 320px;
  }
  #toast.show { opacity: 1; transform: translateY(0); }
  #toast.ok   { border-color: rgba(63,185,80,0.5); color: var(--green); }
  #toast.err  { border-color: rgba(248,81,73,0.5); color: var(--red); }

  @media (max-width: 600px) {
    main { padding: 16px; }
    header { padding: 10px 16px; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="layout">
  <header>
    <h1>cloop <span>dashboard</span></h1>
    <div class="live-dot" id="liveDot" title="Live connection"></div>
    <div class="spacer"></div>
    <div class="updated-at" id="updatedAt"></div>
  </header>
  <main>
    <!-- Goal + Status -->
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
          <div class="stat-value" id="statProvider" style="font-size:14px;margin-top:4px">—</div>
          <div class="stat-sub" id="statModel"></div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Mode</div>
          <div class="stat-value" id="statMode" style="font-size:14px;margin-top:4px">—</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Tokens</div>
          <div class="stat-value accent" id="statTokens">—</div>
          <div class="stat-sub" id="statTokensSub"></div>
          <div class="token-bar" id="tokenBarWrap" style="display:none">
            <div class="token-bar-track"><div class="token-bar-fill" id="tokenBarFill" style="width:0%"></div></div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Created</div>
          <div class="stat-value" id="statCreated" style="font-size:13px;margin-top:4px">—</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Updated</div>
          <div class="stat-value" id="statUpdated" style="font-size:13px;margin-top:4px">—</div>
        </div>
      </div>
    </div>

    <!-- Controls -->
    <div class="section">
      <div class="section-title">Controls</div>
      <div class="controls">
        <button class="btn success" onclick="apiRun(false)">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0zm3.5 7.5l-5-3a.5.5 0 0 0-.75.43v6a.5.5 0 0 0 .75.43l5-3a.5.5 0 0 0 0-.86z"/></svg>
          Run
        </button>
        <button class="btn primary" onclick="apiRun(true)">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0zm3.5 7.5l-5-3a.5.5 0 0 0-.75.43v6a.5.5 0 0 0 .75.43l5-3a.5.5 0 0 0 0-.86z"/></svg>
          Run (PM mode)
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
    </div>

    <!-- Tasks (PM mode) -->
    <div class="section" id="tasksSection" style="display:none">
      <div class="section-title">Tasks</div>
      <div class="task-list" id="taskList"></div>
    </div>

    <!-- Step History -->
    <div class="section">
      <div class="section-title">Step History</div>
      <div class="step-list" id="stepList">
        <div class="empty-state">
          <h3>No steps yet</h3>
          <p>Start a run to see step history here.</p>
        </div>
      </div>
    </div>
  </main>
</div>
<div id="toast"></div>

<script>
(function() {
  'use strict';

  let state = null;
  let evtSource = null;

  // ── Helpers ──────────────────────────────────────────────────────────────

  function fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {month:'short',day:'numeric'}) + ' ' +
           d.toLocaleTimeString(undefined, {hour:'2-digit',minute:'2-digit'});
  }

  function fmtNum(n) {
    if (n == null || n === 0) return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K';
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

  function statusBadge(status) {
    const s = status || 'unknown';
    const labels = {
      running: 'Running', complete: 'Complete', failed: 'Failed',
      paused: 'Paused', initialized: 'Ready', evolving: 'Evolving'
    };
    const label = labels[s] || s;
    return '<span class="badge ' + esc(s) + '"><span class="badge-dot"></span>' + esc(label) + '</span>';
  }

  function taskIcon(status) {
    const icons = {
      pending:     '◦',
      in_progress: '◎',
      done:        '✓',
      failed:      '✗',
      skipped:     '⊘',
    };
    return icons[status] || '◦';
  }

  function priorityBadge(p) {
    if (p <= 1)  return '<span class="task-priority p1">P1</span>';
    if (p <= 3)  return '<span class="task-priority p2">P2</span>';
    return '<span class="task-priority p3">P' + p + '</span>';
  }

  // ── Render ───────────────────────────────────────────────────────────────

  function render(s) {
    state = s;

    // Goal
    const goalEl = document.getElementById('goalText');
    if (s.goal) {
      goalEl.textContent = s.goal;
      goalEl.classList.remove('empty');
    } else {
      goalEl.textContent = 'No goal set (run cloop init first)';
      goalEl.classList.add('empty');
    }

    // Status badge
    document.getElementById('statusBadge').innerHTML = statusBadge(s.status);

    // Stats
    const steps = (s.steps || []).length;
    document.getElementById('statSteps').textContent = steps;
    if (s.max_steps > 0) {
      document.getElementById('statStepsSub').textContent = 'of ' + s.max_steps + ' max';
    } else {
      document.getElementById('statStepsSub').textContent = 'unlimited';
    }
    document.getElementById('statProvider').textContent = s.provider || 'claudecode';
    document.getElementById('statModel').textContent    = s.model || '';
    document.getElementById('statMode').textContent     = s.pm_mode ? 'Product Manager' : 'Feedback Loop';
    document.getElementById('statCreated').textContent  = fmtDate(s.created_at);
    document.getElementById('statUpdated').textContent  = fmtDate(s.updated_at);

    // Tokens
    const ti = s.total_input_tokens || 0, to = s.total_output_tokens || 0;
    const total = ti + to;
    document.getElementById('statTokens').textContent   = fmtNum(total) === '—' ? '0' : fmtNum(total);
    document.getElementById('statTokensSub').textContent = ti > 0 ? fmtNum(ti) + ' in / ' + fmtNum(to) + ' out' : '';

    // Tasks
    const plan = s.plan;
    const taskSection = document.getElementById('tasksSection');
    if (plan && plan.tasks && plan.tasks.length > 0) {
      taskSection.style.display = '';
      const sorted = [...plan.tasks].sort((a, b) => a.priority - b.priority);
      document.getElementById('taskList').innerHTML = sorted.map(t => {
        const cls = t.status || 'pending';
        return '<div class="task-item ' + esc(cls) + '">' +
          '<div class="task-status-icon">' + taskIcon(cls) + '</div>' +
          '<div class="task-body">' +
            '<div class="task-title">' + esc(t.title) + '</div>' +
            (t.description ? '<div class="task-desc">' + esc(t.description) + '</div>' : '') +
            '<div class="task-meta">' +
              '<span>' + esc(cls) + '</span>' +
              (t.role ? '<span>' + esc(t.role) + '</span>' : '') +
            '</div>' +
          '</div>' +
          '<div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0">' +
            '<div class="task-id">#' + t.id + '</div>' +
            priorityBadge(t.priority) +
          '</div>' +
        '</div>';
      }).join('');
    } else {
      taskSection.style.display = 'none';
    }

    // Steps
    const stepListEl = document.getElementById('stepList');
    const allSteps = (s.steps || []);
    if (allSteps.length === 0) {
      stepListEl.innerHTML = '<div class="empty-state"><h3>No steps yet</h3><p>Start a run to see step history here.</p></div>';
    } else {
      // Show newest first, keep expansion state by index.
      const expanded = {};
      stepListEl.querySelectorAll('.step-item.expanded').forEach(el => {
        expanded[el.dataset.idx] = true;
      });

      const reversed = [...allSteps].reverse();
      stepListEl.innerHTML = reversed.map((st, i) => {
        const idx = allSteps.length - 1 - i;
        const isExp = expanded[idx] ? ' expanded' : '';
        const exitCls = st.exit_code === 0 ? 'step-exit-ok' : 'step-exit-bad';
        return '<div class="step-item' + isExp + '" data-idx="' + idx + '" onclick="toggleStep(this)">' +
          '<div class="step-header">' +
            '<span class="step-num">#' + (st.step + 1) + '</span>' +
            '<span class="step-task">' + esc(st.task || '(no description)') + '</span>' +
            '<div class="step-meta">' +
              (st.duration ? '<span>' + esc(st.duration) + '</span>' : '') +
              '<span class="' + exitCls + '">' + (st.exit_code === 0 ? 'OK' : 'exit ' + st.exit_code) + '</span>' +
              (st.output_tokens ? '<span>' + fmtNum(st.output_tokens) + ' tok</span>' : '') +
            '</div>' +
            '<span class="step-chevron">&#9654;</span>' +
          '</div>' +
          '<div class="step-output">' + esc(st.output || '') + '</div>' +
        '</div>';
      }).join('');
    }

    // Updated-at timestamp in header
    document.getElementById('updatedAt').textContent = s.updated_at ? fmtDate(s.updated_at) : '';
  }

  window.toggleStep = function(el) {
    el.classList.toggle('expanded');
  };

  // ── SSE ──────────────────────────────────────────────────────────────────

  function connectSSE() {
    if (evtSource) evtSource.close();
    evtSource = new EventSource('/api/events');
    const dot = document.getElementById('liveDot');

    evtSource.onopen = () => {
      dot.classList.add('connected');
    };

    evtSource.onmessage = (e) => {
      try {
        const s = JSON.parse(e.data);
        render(s);
      } catch(_) {}
    };

    evtSource.onerror = () => {
      dot.classList.remove('connected');
      // Retry after 3s
      setTimeout(connectSSE, 3000);
    };
  }

  // ── Actions ──────────────────────────────────────────────────────────────

  window.refreshState = function() {
    fetch('/api/state')
      .then(r => r.json())
      .then(s => { render(s); toast('State refreshed', 'ok'); })
      .catch(() => toast('Could not load state', 'err'));
  };

  window.apiRun = function(pm) {
    const url = '/api/run' + (pm ? '?pm=1' : '');
    fetch(url, {method:'POST'})
      .then(r => r.json())
      .then(data => {
        if (data.ok) toast('Started: cloop ' + data.started, 'ok');
        else toast(data.error || 'Failed to start', 'err');
      })
      .catch(() => toast('Request failed', 'err'));
  };

  window.apiStop = function() {
    fetch('/api/stop', {method:'POST'})
      .then(r => r.json())
      .then(data => {
        toast(data.message || (data.ok ? 'Pause signal sent' : 'Stop failed'), data.ok ? 'ok' : 'err');
      })
      .catch(() => toast('Request failed', 'err'));
  };

  // ── Init ─────────────────────────────────────────────────────────────────

  connectSSE();
  refreshState();
})();
</script>
</body>
</html>
`
