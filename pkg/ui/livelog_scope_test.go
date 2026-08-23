package ui

// Cross-tenant isolation of live harness output (Task 20189).
//
// Live output is raw stdout from an AI harness working inside a project's
// repository. On a multi-tenant hub, delivering one project's chunk to a
// client subscribed to another is an active disclosure across an identity
// boundary — the disclosed party never took an action to opt in, and the
// receiving party never needed a permission they lacked. Scope, not
// permission, is the control that has to hold here.
//
// The defects these tests pin down, all in the hub broadcast path:
//
//   1. broadcastLog walked every room in s.hubClients and every SSE client
//      in s.clients, so each chunk went to all of them.
//   2. The replay buffer was a single global []string on Server, so there
//      was no per-project backlog to hand back even if a reader wanted one.
//   3. The three replay sites (WebSocket connect, SSE connect, and
//      GET /api/livelog) handed that global buffer to whoever asked —
//      handleLiveLog resolved a workDir and then used it only for a /proc
//      probe, never for the lines it returned.
//
// Each test names the project whose bytes must not travel and asserts on
// the receiving side of a boundary, so a regression fails loudly rather
// than degrading quietly.

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"

	"nhooyr.io/websocket"
)

// secretOutput is what project A's harness prints. Any appearance of this
// string on a project-B channel is the leak.
const secretOutput = "ALICE-PRIVATE-TOKEN-abc123 /home/alice/payments/secrets.go\n"

// twoTenantHub registers two projects owned by two distinct identities in a
// throwaway registry, and returns their directories plus a Server wired to
// both. Project A is at ?project_idx=0, project B at ?project_idx=1.
//
// The owners are real registry owners rather than decoration: they are what
// makes this a *tenant* boundary. Owner-based visibility filtering is a
// separate control with its own tests (TestOIDCFilterHelpersUnit); what is
// under test here is that the log path keys off the resolved project at all.
func twoTenantHub(t *testing.T) (dirA, dirB string, srv *Server) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	dirA = setupProjectDir(t, "alice: ship the payments service", nil)
	dirB = setupProjectDir(t, "bob: ship the infra service", nil)

	if err := multiui.AddPathsOwned([]string{dirA}, "alice@example.com"); err != nil {
		t.Fatalf("register project A: %v", err)
	}
	if err := multiui.AddPathsOwned([]string{dirB}, "bob@example.com"); err != nil {
		t.Fatalf("register project B: %v", err)
	}

	srv = New(dirA, 0, "")
	srv.Projects = []string{dirB}
	return dirA, dirB, srv
}

// subscribe registers a hub client in the room for workDir, exactly as
// handleWS does after resolving the project, and returns it. identity is the
// signed-in user the connection belongs to.
func subscribe(t *testing.T, srv *Server, workDir, email string) *hubClient {
	t.Helper()
	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     email,
		user:   &oidcauth.Identity{Sub: email, Email: email},
	}
	srv.hubMu.Lock()
	if srv.hubClients[workDir] == nil {
		srv.hubClients[workDir] = make(map[*hubClient]struct{})
	}
	srv.hubClients[workDir][hc] = struct{}{}
	srv.hubMu.Unlock()
	return hc
}

// subscribeSSE is the SSE counterpart of subscribe.
func subscribeSSE(t *testing.T, srv *Server, workDir, email string) *sseClient {
	t.Helper()
	c := &sseClient{
		ch:      make(chan sseEvent, sseClientBufferSize),
		resync:  make(chan struct{}, 1),
		user:    &oidcauth.Identity{Sub: email, Email: email},
		workDir: workDir,
	}
	srv.mu.Lock()
	srv.clients[c] = struct{}{}
	srv.mu.Unlock()
	return c
}

// drainWSMessages returns every message currently queued for hc.
func drainWSMessages(hc *hubClient) []wsMessage {
	var out []wsMessage
	for {
		select {
		case m := <-hc.ch:
			out = append(out, m)
		default:
			return out
		}
	}
}

// drainSSEEvents returns every event currently queued for c.
func drainSSEEvents(c *sseClient) []sseEvent {
	var out []sseEvent
	for {
		select {
		case e := <-c.ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

// TestLiveLogDoesNotCrossProjectsOverWebSocket is defect (1) on the
// WebSocket side: a client subscribed to project B must receive zero log
// frames while project A is producing output.
func TestLiveLogDoesNotCrossProjectsOverWebSocket(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)

	alice := subscribe(t, srv, dirA, "alice@example.com")
	bob := subscribe(t, srv, dirB, "bob@example.com")

	srv.broadcastLog(dirA, secretOutput)

	// Bob's room must be silent.
	for _, m := range drainWSMessages(bob) {
		if m.Type == "step_output" {
			t.Fatalf("project B received a step_output frame from project A's run: %s", string(m.Data))
		}
	}

	// Alice must still get her own output, or the fix would be "deliver
	// nothing", which passes the leak assertion for the wrong reason.
	var delivered bool
	for _, m := range drainWSMessages(alice) {
		if m.Type == "step_output" && strings.Contains(string(m.Data), "ALICE-PRIVATE-TOKEN") {
			delivered = true
		}
	}
	if !delivered {
		t.Fatal("project A's own subscriber did not receive its step_output frame")
	}
}

// TestLiveLogDoesNotCrossProjectsOverSSE is defect (1) on the SSE fallback
// path, which fanned out over a flat s.clients set with no project key at
// all until sseClient gained a workDir.
func TestLiveLogDoesNotCrossProjectsOverSSE(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)

	alice := subscribeSSE(t, srv, dirA, "alice@example.com")
	bob := subscribeSSE(t, srv, dirB, "bob@example.com")

	srv.broadcastLog(dirA, secretOutput)

	for _, e := range drainSSEEvents(bob) {
		if strings.Contains(e.Data, "ALICE-PRIVATE-TOKEN") {
			t.Fatalf("project B's SSE stream received project A's output: %s", e.Data)
		}
	}

	var delivered bool
	for _, e := range drainSSEEvents(alice) {
		if e.Event == "log" && strings.Contains(e.Data, "ALICE-PRIVATE-TOKEN") {
			delivered = true
		}
	}
	if !delivered {
		t.Fatal("project A's own SSE subscriber did not receive its log event")
	}
}

// TestLiveLogAPIIsScopedToResolvedProject is defect (3) at GET /api/livelog,
// which resolved a workDir and then returned the global buffer regardless.
func TestLiveLogAPIIsScopedToResolvedProject(t *testing.T) {
	dirA, _, srv := twoTenantHub(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	srv.broadcastLog(dirA, secretOutput)

	// project_idx=1 is project B, which has produced nothing.
	got := apiGET(t, ts, "/api/livelog?project_idx=1")
	raw, err := json.Marshal(got["lines"])
	if err != nil {
		t.Fatalf("marshal lines: %v", err)
	}
	if strings.Contains(string(raw), "ALICE-PRIVATE-TOKEN") {
		t.Fatalf("/api/livelog scoped to project B returned project A's lines: %s", raw)
	}
	if lines, ok := got["lines"].([]interface{}); ok && len(lines) != 0 {
		t.Fatalf("project B has produced no output; want 0 lines, got %d", len(lines))
	}

	// project_idx=0 is project A, which must still see its own output —
	// the endpoint has to stay useful, not just quiet.
	gotA := apiGET(t, ts, "/api/livelog?project_idx=0")
	rawA, err := json.Marshal(gotA["lines"])
	if err != nil {
		t.Fatalf("marshal lines: %v", err)
	}
	if !strings.Contains(string(rawA), "ALICE-PRIVATE-TOKEN") {
		t.Fatalf("/api/livelog scoped to project A lost its own lines: %s", rawA)
	}
}

// TestLateWebSocketConnectReplaysOnlyItsOwnProject is defect (2)+(3) on the
// connect path: a tab opening on project B *after* project A has produced
// output must get an empty replay. This is the case a restart or a slow
// client hits, and it goes through the real handleWS connect sequence.
func TestLateWebSocketConnectReplaysOnlyItsOwnProject(t *testing.T) {
	dirA, _, srv := twoTenantHub(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Project A runs and produces output before anyone connects to B.
	srv.broadcastLog(dirA, secretOutput)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws?project_idx=1"
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial project B: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(-1)

	// Read the connect burst (initial state, replay, run_state, presence).
	// Anything containing A's output is the leak; a step_output frame at
	// all is one, since B has produced nothing to replay.
	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()
	for {
		_, data, err := conn.Read(readCtx)
		if err != nil {
			break // deadline reached: the connect burst is over
		}
		if strings.Contains(string(data), "ALICE-PRIVATE-TOKEN") {
			t.Fatalf("late connect to project B replayed project A's output: %s", data)
		}
		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err == nil && msg.Type == "step_output" {
			t.Fatalf("project B replayed a step_output frame despite producing no output: %s", data)
		}
	}
}

// TestLateSSEConnectReplaysOnlyItsOwnProject is the SSE half of the same
// late-connect case.
func TestLateSSEConnectReplaysOnlyItsOwnProject(t *testing.T) {
	dirA, _, srv := twoTenantHub(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	srv.broadcastLog(dirA, secretOutput)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events?project_idx=1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open SSE for project B: %v", err)
	}
	defer resp.Body.Close()

	// Read until the context deadline closes the stream; the connect burst
	// (snapshot + replay) arrives well inside it.
	buf := make([]byte, 64*1024)
	var body strings.Builder
	for {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
		if body.Len() > 1<<20 {
			break
		}
	}
	if strings.Contains(body.String(), "ALICE-PRIVATE-TOKEN") {
		t.Fatalf("late SSE connect to project B replayed project A's output: %s", body.String())
	}
	if strings.Contains(body.String(), "event: log") {
		t.Fatalf("project B replayed a log event despite producing no output: %s", body.String())
	}
}

// TestLiveLogReplayIsPerProject exercises the buffer directly: two projects
// producing concurrently must keep separate backlogs, and a project that
// never ran must replay nothing rather than inheriting a neighbour's.
func TestLiveLogReplayIsPerProject(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)

	srv.broadcastLog(dirA, "alice line 1\n")
	srv.broadcastLog(dirB, "bob line 1\n")
	srv.broadcastLog(dirA, "alice line 2\n")

	a := strings.Join(srv.liveLogReplay(dirA), "")
	b := strings.Join(srv.liveLogReplay(dirB), "")

	if !strings.Contains(a, "alice line 1") || !strings.Contains(a, "alice line 2") {
		t.Errorf("project A replay lost its own lines: %q", a)
	}
	if strings.Contains(a, "bob") {
		t.Errorf("project A replay contains project B's output: %q", a)
	}
	if !strings.Contains(b, "bob line 1") {
		t.Errorf("project B replay lost its own line: %q", b)
	}
	if strings.Contains(b, "alice") {
		t.Errorf("project B replay contains project A's output: %q", b)
	}
	if got := srv.liveLogReplay(filepath.Join(t.TempDir(), "never-ran")); got != nil {
		t.Errorf("a project that never ran replayed %v; want nothing", got)
	}
	// An unresolved project must not resolve to anyone's buffer.
	if got := srv.liveLogReplay(""); got != nil {
		t.Errorf("empty workDir replayed %v; want nothing", got)
	}
}

// TestLiveLogRunFlagIsPerProject covers the run flag that shared the same
// global: project A running must not make project B's dashboard render Stop.
func TestLiveLogRunFlagIsPerProject(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)

	srv.liveLogStartRun(dirA)
	if !srv.liveLogRunningFor(dirA) {
		t.Error("project A should be running")
	}
	if srv.liveLogRunningFor(dirB) {
		t.Error("project B reported running because project A is")
	}

	srv.liveLogSetRunning(dirA, false)
	if srv.liveLogRunningFor(dirA) {
		t.Error("project A should have stopped")
	}
}

// TestLiveLogStartRunClearsOnlyItsOwnBacklog: dispatching a run for one
// project must not wipe another's replay buffer.
func TestLiveLogStartRunClearsOnlyItsOwnBacklog(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)

	srv.broadcastLog(dirA, "alice old line\n")
	srv.broadcastLog(dirB, "bob keep me\n")

	srv.liveLogStartRun(dirA)

	if got := strings.Join(srv.liveLogReplay(dirA), ""); got != "" {
		t.Errorf("starting a run for A left its old backlog: %q", got)
	}
	if got := strings.Join(srv.liveLogReplay(dirB), ""); !strings.Contains(got, "bob keep me") {
		t.Errorf("starting a run for A cleared project B's backlog: %q", got)
	}
}

// TestLiveLogEvictsDeletedProject: deleting a project must drop its buffer,
// so the bytes cannot be replayed to whoever registers that path next.
func TestLiveLogEvictsDeletedProject(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	srv.broadcastLog(dirB, "bob private output\n")
	if got := srv.liveLogReplay(dirB); len(got) == 0 {
		t.Fatal("precondition: project B should have buffered output")
	}

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/projects/1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete project B: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/projects/1 returned %d", resp.StatusCode)
	}

	if got := srv.liveLogReplay(dirB); got != nil {
		t.Errorf("deleted project still replays %v", got)
	}
	// Project A is untouched.
	_ = dirA
}

// TestLiveLogRoomsAreBounded: the map must not grow with the number of
// projects the daemon has ever run, and eviction must prefer idle rooms
// over a project with a live run behind it.
func TestLiveLogRoomsAreBounded(t *testing.T) {
	srv := New(t.TempDir(), 0, "")

	running := filepath.Join(t.TempDir(), "running-project")
	srv.liveLogStartRun(running)
	srv.broadcastLog(running, "live run output\n")

	for i := 0; i < liveLogMaxRooms*3; i++ {
		srv.broadcastLog(filepath.Join(t.TempDir(), "idle", string(rune('a'+i%26)), strings.Repeat("x", i%7+1)), "noise\n")
	}

	srv.liveLogMu.Lock()
	n := len(srv.liveLogRooms)
	srv.liveLogMu.Unlock()
	if n > liveLogMaxRooms {
		t.Errorf("live log rooms grew to %d; cap is %d", n, liveLogMaxRooms)
	}

	if got := strings.Join(srv.liveLogReplay(running), ""); !strings.Contains(got, "live run output") {
		t.Errorf("eviction dropped the running project's buffer in favour of idle ones: %q", got)
	}
}

// TestLiveLogLinesAreCappedPerProject: one noisy project must not be able
// to grow its own room without bound.
func TestLiveLogLinesAreCappedPerProject(t *testing.T) {
	srv := New(t.TempDir(), 0, "")
	dir := filepath.Join(t.TempDir(), "noisy")

	for i := 0; i < liveLogMaxLines*3; i++ {
		srv.broadcastLog(dir, "line\n")
	}
	if got := len(srv.liveLogReplay(dir)); got > liveLogMaxLines {
		t.Errorf("buffer grew to %d lines; cap is %d", got, liveLogMaxLines)
	}
}

// ── structural guards ────────────────────────────────────────────────────

// liveLogAccessors are the only ways to reach the buffer. Each takes the
// project workDir as its first parameter.
var liveLogAccessors = map[string]bool{
	"liveLogAppend":     true,
	"liveLogReplay":     true,
	"liveLogStartRun":   true,
	"liveLogSetRunning": true,
	"liveLogRunningFor": true,
	"liveLogEvict":      true,
	"liveLogRoomFor":    true,
}

// resolvedProjectExprs are the expressions a call site may pass as that
// workDir. Each is a value that came from resolving a project — the
// request's ?project_idx (resolveWorkDir), a connection's captured project,
// a registry entry's path, or the server's own primary project.
//
// The allowlist is the point of the gate: a new call site passing something
// else has to be added here deliberately, which is the moment to check that
// the value really does name one project and not "whatever ran last".
var resolvedProjectExprs = map[string]bool{
	"workDir":             true,
	"c.workDir":           true,
	"hc.workDir":          true,
	"entry.Path":          true,
	"s.WorkDir":           true,
	"s.resolveWorkDir(r)": true,
}

// TestLiveLogBufferIsUnreachableWithoutAWorkDir is the guard the task asks
// for: it fails if any handler can read the live log without having
// resolved a project first.
//
// It enforces two properties that together make the original bug
// unexpressible:
//
//   - The liveLogRooms map is referenced only inside livelog.go. Nothing
//     else may reach past the accessors and index it directly.
//   - Every accessor call passes a project-resolved workDir. handleLiveLog
//     computing `workDir := s.resolveWorkDir(r)` and then reading a global
//     buffer — the shape of defect (3) — cannot survive this.
func TestLiveLogBufferIsUnreachableWithoutAWorkDir(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Property 1: the raw map is private to livelog.go.
			if sel.Sel.Name == "liveLogRooms" && name != "livelog.go" {
				t.Errorf("%s:%d: reaches into s.liveLogRooms directly; use the workDir-keyed accessors in livelog.go",
					name, fset.Position(sel.Pos()).Line)
			}
			return true
		})

		// Property 2: every accessor call names a resolved project.
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !liveLogAccessors[sel.Sel.Name] {
				return true
			}
			// The accessor definitions themselves live in livelog.go and
			// call each other with their own workDir parameter; that is
			// covered by the "workDir" entry in the allowlist.
			if len(call.Args) == 0 {
				t.Errorf("%s:%d: %s called with no project argument",
					name, fset.Position(call.Pos()).Line, sel.Sel.Name)
				return true
			}
			var buf strings.Builder
			if err := printer.Fprint(&buf, fset, call.Args[0]); err != nil {
				t.Fatalf("print arg: %v", err)
			}
			if !resolvedProjectExprs[buf.String()] {
				t.Errorf("%s:%d: %s(%s, …) — first argument is not a recognised resolved project. "+
					"Resolve the project (s.resolveWorkDir(r)) and pass it, or add the expression to "+
					"resolvedProjectExprs after confirming it names exactly one project.",
					name, fset.Position(call.Pos()).Line, sel.Sel.Name, buf.String())
			}
			return true
		})
	}
}

// TestServerHasNoUnkeyedLiveLogState fails if a global live-log field is
// reintroduced alongside the map. Defect (2) was exactly this: a `[]string`
// and a `bool` on Server that no amount of care at the read sites could
// have made per-project.
func TestServerHasNoUnkeyedLiveLogState(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Server" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, f := range st.Fields.List {
			for _, fname := range f.Names {
				if !strings.HasPrefix(fname.Name, "liveLog") {
					continue
				}
				var buf strings.Builder
				if err := printer.Fprint(&buf, fset, f.Type); err != nil {
					t.Fatalf("print field type: %v", err)
				}
				typ := buf.String()
				// Only a mutex and a workDir-keyed map are allowed. A bare
				// slice or bool here is a shared buffer by construction.
				if typ != "sync.Mutex" && typ != "map[string]*liveLogRoom" {
					t.Errorf("Server.%s has type %s; live-log state must be keyed by workDir "+
						"(map[string]*liveLogRoom) so it cannot be shared between tenants",
						fname.Name, typ)
				}
			}
		}
		return false
	})
}
