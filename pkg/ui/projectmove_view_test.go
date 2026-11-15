package ui

// A move as the dashboard and `cloop executor move` see it (Task 20496): the
// route that reads one move with what cleaning up after it removes, the
// cleanup that removes nothing without a confirmation and a device's copy
// only after a verified move, the projects list saying a project is moving,
// the progress pushed to the project's dashboards, and who may do each.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// serveMoveAPI serves one request through the hub's handler, as a browser on
// the hub's own origin would send it: Host 127.0.0.1, a JSON body.
func serveMoveAPI(t *testing.T, srv *Server, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// moveViewBody is GET /api/projects/{idx}/move/{id}'s answer, and a cleanup's.
type moveViewBody struct {
	Move    projectmove.Move `json:"move"`
	Cleanup moveCleanupPlan  `json:"cleanup"`
	Code    string           `json:"code"`
	Error   string           `json:"error"`
}

// decodeMoveView reads a move's view, or a refusal carrying its plan.
func decodeMoveView(t *testing.T, raw []byte) moveViewBody {
	t.Helper()
	var v moveViewBody
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

func getMoveView(t *testing.T, srv *Server, id string) moveViewBody {
	t.Helper()
	rec := serveMoveAPI(t, srv, http.MethodGet, "/api/projects/0/move/"+id, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET move %s = HTTP %d: %s", id, rec.Code, rec.Body.String())
	}
	return decodeMoveView(t, rec.Body.Bytes())
}

func TestAMovesViewAndItsConfirmedCleanup(t *testing.T) {
	// Its own project list: index 0 is this test's project, whoever asks.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir, db, srv, ts := movingProject(t)
	box := newHarnessExec("mv-view-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, box.id, executor.KindContainer)

	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-view-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	store := m.Detail.Capture.Store

	// The view: the move whole, and what cleaning up after it removes.
	v := getMoveView(t, srv, m.ID)
	plan := v.Cleanup
	if v.Move.ID != m.ID || len(v.Move.Detail.Capture.Git.Branches) == 0 {
		t.Errorf("the view's move = %+v", v.Move)
	}
	if !plan.Allowed || !plan.Verified || plan.Store != store || plan.StoreBytes <= 0 || len(plan.Refs) == 0 ||
		plan.Command != "cloop executor move cleanup "+m.ID {
		t.Errorf("plan = %+v", plan)
	}
	// The source was the hub's own tree, the project's home: nothing of it
	// is removed, and the plan says so.
	if plan.Source != nil || !strings.Contains(strings.Join(plan.Kept, " "), "never removes") {
		t.Errorf("plan's source %+v, kept %q", plan.Source, plan.Kept)
	}

	// Without a confirmation: refused with the plan, nothing removed.
	rec := serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{}`)
	if v := decodeMoveView(t, rec.Body.Bytes()); rec.Code != http.StatusConflict || v.Code != "cleanup_unconfirmed" || v.Cleanup.Store != store {
		t.Fatalf("an unconfirmed cleanup = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	rec = serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", "")
	if rec.Code != http.StatusConflict {
		t.Errorf("a cleanup with no body = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(store); err != nil {
		t.Fatalf("an unconfirmed cleanup removed the store: %v", err)
	}
	// Only JSON, and only from the hub's own origin.
	req := httptest.NewRequest(http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", strings.NewReader("confirm=true"))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form := httptest.NewRecorder()
	srv.Handler().ServeHTTP(form, req)
	if form.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a form-encoded cleanup = HTTP %d, want 415", form.Code)
	}
	if rec := serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`,
		"Origin", "https://evil.example"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "CROSS_ORIGIN") {
		t.Errorf("a cross-origin cleanup = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(store); err != nil {
		t.Fatalf("a refused cleanup removed the store: %v", err)
	}

	// Confirmed: the store and the refs go, the project stays.
	rec = serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	done := decodeMoveView(t, rec.Body.Bytes())
	if done.Cleanup.CleanedAt == nil || done.Cleanup.Allowed || done.Move.Detail.Retained.CleanedAt.IsZero() {
		t.Errorf("after cleanup: %+v", done.Cleanup)
	}
	if _, err := os.Stat(store); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the store survived: %v", err)
	}
	if out, err := runGitIn(dir, "rev-parse", "--verify", "--quiet", "refs/cloop/move/"+m.ID); err == nil {
		t.Errorf("the hidden ref survived: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "keep.txt")); err != nil {
		t.Errorf("cleanup touched the project's tree: %v", err)
	}
	// Again: nothing left to do, and still a 200.
	if rec := serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`); rec.Code != http.StatusOK {
		t.Errorf("a second cleanup = HTTP %d: %s", rec.Code, rec.Body.String())
	}

	// A move that is not the project's, and an id that is not one.
	if rec := serveMoveAPI(t, srv, http.MethodGet, "/api/projects/0/move/ffffffffffffffff", ""); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown move = HTTP %d", rec.Code)
	}
	if rec := serveMoveAPI(t, srv, http.MethodGet, "/api/projects/0/move/..%2Fx", ""); rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
		t.Errorf("a malformed move id = HTTP %d", rec.Code)
	}
}

// runGitIn runs git in dir and returns its output.
func runGitIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestCleanupRemovesAVerifiedDevicesCopyOnlyWhileItIsUnchanged(t *testing.T) {
	// Its own project list: index 0 is this test's project, whoever asks.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir, dev, srv, base := deviceSourcedProject(t, "mv-clean-dev1")
	box := newHarnessExec("mv-clean-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, srv, box.id, executor.KindContainer)

	code, m, raw := startMoveOver(t, base, `{"target":"mv-clean-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	wc := dev.workDir(dir)

	plan := getMoveView(t, srv, m.ID).Cleanup
	src := plan.Source
	if src == nil || src.Executor != dev.id || !strings.HasSuffix(src.WorkDir, executor.DeviceWorkDir(dir)) || !src.Removable {
		t.Fatalf("the plan's source copy = %+v (plan %+v)", src, plan)
	}

	// Written to after the capture: the device keeps it, and nothing else
	// is removed either.
	moveWrite(t, filepath.Join(wc, "app.go"), "package app // edited after the move\n")
	rec := serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`)
	if v := decodeMoveView(t, rec.Body.Bytes()); rec.Code != http.StatusConflict || v.Code != "source_copy_changed" {
		t.Fatalf("cleanup of a changed copy = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if b, err := os.ReadFile(filepath.Join(wc, "app.go")); err != nil || !strings.Contains(string(b), "after the move") {
		t.Fatalf("the changed copy was touched: %q %v", b, err)
	}
	if _, err := os.Stat(plan.Store); err != nil {
		t.Fatalf("a refused cleanup removed the store: %v", err)
	}

	// As the capture found it again, but holding a file git ignores, which no
	// move carries: kept until the caller says that may go too.
	moveWrite(t, filepath.Join(wc, "app.go"), "package app // edited on the device\n")
	moveWrite(t, filepath.Join(wc, ".git", "info", "exclude"), "*.env\n")
	moveWrite(t, filepath.Join(wc, "local.env"), "API_KEY=only-here\n")
	rec = serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`)
	var ignored struct {
		Code     string   `json:"code"`
		Ignored  int      `json:"ignored"`
		Examples []string `json:"examples"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ignored)
	if rec.Code != http.StatusConflict || ignored.Code != "source_copy_ignored" || ignored.Ignored != 1 ||
		len(ignored.Examples) != 1 || ignored.Examples[0] != "local.env" {
		t.Fatalf("cleanup of a copy holding an ignored file = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(wc, "local.env")); err != nil {
		t.Fatalf("the ignored file went: %v", err)
	}

	// Removing it is work on the device, and the device is restricted to a
	// group the caller is not in: refused before anything is asked of it.

	cp, err := srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if err := cp.AddExecutorAudience(dev.id, "group", "device-operators", "test"); err != nil {
		t.Fatal(err)
	}
	asked := len(dev.steps())
	rec = serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "executor_audience_denied") || len(dev.steps()) != asked {
		t.Fatalf("cleanup by a caller off the device's access list = HTTP %d: %s (device asked %d more times)",
			rec.Code, rec.Body.String(), len(dev.steps())-asked)
	}
	if err := cp.ClearExecutorAudience(dev.id); err != nil {
		t.Fatal(err)
	}

	// Removed, ignored file and all, and the move says so.
	rec = serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true,"discard_ignored":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	done := decodeMoveView(t, rec.Body.Bytes())
	r := done.Move.Detail.Retained
	if r == nil || r.SourceRemovedAt.IsZero() || !strings.Contains(r.SourceRemoved, dev.id) || r.CleanedAt.IsZero() {
		t.Errorf("retained after cleanup = %+v", r)
	}
	if s := done.Cleanup.Source; s == nil || s.RemovedAt == nil || s.Removable {
		t.Errorf("the plan after cleanup = %+v", s)
	}
	entries, err := os.ReadDir(wc)
	if err != nil || len(entries) != 0 {
		t.Errorf("the device's copy holds %d entries (%v), want it empty", len(entries), err)
	}
	if steps := strings.Join(dev.steps(), ","); !strings.Contains(steps, "move-discard") {
		t.Errorf("device steps = %s", steps)
	}
	// The hub's tree, which the move built from the device, is untouched.
	if b, err := os.ReadFile(filepath.Join(dir, "app.go")); err != nil || !strings.Contains(string(b), "edited on the device") {
		t.Errorf("the hub's copy = %q %v", b, err)
	}
	rows, _, err := cp.ListAuditEvents(statedb.AuditFilter{EntityType: "project_move", EntityID: m.ID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var refused, cleaned bool
	for _, row := range rows {
		if row.EventType != auditaction.ActionProjectMoveCleanup.String() {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal([]byte(row.Payload), &p)
		switch {
		case p["outcome"] == "refused":
			refused = true
		case strings.Contains(asString(p["source_removed"]), dev.id):
			cleaned = true
		}
	}
	if !refused || !cleaned {
		t.Errorf("the trail records the refusal %v and the removal %v", refused, cleaned)
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func TestCleanupKeepsADevicesCopyTheProjectWorksInAgain(t *testing.T) {
	// Its own project list: index 0 is this test's project, whoever asks.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir, dev, srv, base := deviceSourcedProject(t, "mv-clean-dev2")
	box := newHarnessExec("mv-clean-box2", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, srv, box.id, executor.KindContainer)
	code, m, raw := startMoveOver(t, base, `{"target":"mv-clean-box2"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	if m = waitForMove(t, srv, m.ID); m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s: %s", m.Phase, m.Error)
	}
	// Someone bound the project back to the device by hand.
	db, err := srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.BindProjectExecutor(dir, dev.id, "test"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	plan := getMoveView(t, srv, m.ID).Cleanup
	if plan.Source == nil || plan.Source.Removable || !strings.Contains(plan.Source.Reason, "bound to") {
		t.Fatalf("the plan's source copy = %+v", plan.Source)
	}
	rec := serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`)
	if v := decodeMoveView(t, rec.Body.Bytes()); rec.Code != http.StatusConflict || v.Code != "source_copy_kept" {
		t.Fatalf("cleanup = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	// Leaving it where it is cleans up the rest.
	rec = serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true,"keep_source":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup keeping the source = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if r := decodeMoveView(t, rec.Body.Bytes()).Move.Detail.Retained; r == nil || !r.SourceKept || !r.SourceRemovedAt.IsZero() {
		t.Errorf("retained = %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dev.workDir(dir), "app.go")); err != nil {
		t.Errorf("the device's copy was touched: %v", err)
	}
	if strings.Contains(strings.Join(dev.steps(), ","), "move-discard") {
		t.Error("the device was asked to discard a copy the project works in")
	}

	// Once the project has left the device again, the kept copy can still be
	// removed: the rest was cleaned up already, so that is all cleanup does.
	db, err = srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.BindProjectExecutor(dir, box.id, "test"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	plan = getMoveView(t, srv, m.ID).Cleanup
	if !plan.Allowed || plan.Source == nil || !plan.Source.Removable || plan.CleanedAt == nil || len(plan.Refs) != 0 {
		t.Fatalf("the plan for a kept copy = %+v (source %+v)", plan, plan.Source)
	}
	rec = serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("removing the kept copy = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if r := decodeMoveView(t, rec.Body.Bytes()).Move.Detail.Retained; r == nil || r.SourceRemovedAt.IsZero() || r.SourceKept {
		t.Errorf("retained after removing the kept copy = %+v", r)
	}
	if entries, _ := os.ReadDir(dev.workDir(dir)); len(entries) != 0 {
		t.Errorf("the kept copy holds %d entries after its removal", len(entries))
	}
}

func TestAFailedMovesCleanupNeverTouchesTheSource(t *testing.T) {
	// Its own project list: index 0 is this test's project, whoever asks.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir, db, srv, ts := movingProject(t)
	dev := newFakeMoveDevice(t, "mv-fail-dev")
	registerMoveExec(t, dev)
	recordExecutor(t, db, dev.id, executor.KindRemoteAgent)
	moveWrite(t, filepath.Join(dev.workDir(dir), "somebodys-work.txt"), "do not lose me\n")
	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-fail-dev"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	if m = waitForMove(t, srv, m.ID); m.Phase != projectmove.PhaseRolledBack {
		t.Fatalf("move ended %s: %s", m.Phase, m.Error)
	}
	plan := getMoveView(t, srv, m.ID).Cleanup
	if !plan.Allowed || plan.Verified || plan.Source != nil || plan.Store == "" {
		t.Fatalf("plan = %+v", plan)
	}
	rec := serveMoveAPI(t, srv, http.MethodPost, "/api/projects/0/move/"+m.ID+"/cleanup", `{"confirm":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup = HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(plan.Store); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the store survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keep.txt")); err != nil {
		t.Errorf("the source lost a file: %v", err)
	}
}

func TestTheProjectsListSaysAProjectIsMoving(t *testing.T) {
	// Its own project list: index 0 is this test's project, whoever asks.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "listed while it moves", nil)
	db := hubWithControlPlane(t, dir)
	srv := New(dir, 0, "")
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: "mv-list-dev", Name: "Edge rack 7", Kind: executor.KindRemoteAgent,
		Status: "ready", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	open, err := db.CreateProjectMove(statedb.ProjectMoveRow{ID: "1122334455667788", ProjectPath: dir, Phase: "capture",
		TargetBinding: "mv-list-dev"})
	if err != nil {
		t.Fatal(err)
	}
	list := func() multiui.ProjectStatus {
		t.Helper()
		rec := serveMoveAPI(t, srv, http.MethodGet, "/api/projects", "")
		var out struct {
			Projects []multiui.ProjectStatus `json:"projects"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Projects) == 0 {
			t.Fatalf("GET /api/projects = %d %s (%v)", rec.Code, rec.Body.String(), err)
		}
		return out.Projects[0]
	}
	srv.dropMovingIndex()
	p := list()
	if p.Moving == nil || p.Moving.ID != open.ID || p.Moving.Phase != "capture" || p.Moving.Target != "mv-list-dev" || p.Moving.To != "Edge rack 7" {
		t.Fatalf("moving = %+v", p.Moving)
	}
	// A feature moves with its project.
	moving := map[string]multiui.MovingStatus{dir: *p.Moving}
	statuses := []multiui.ProjectStatus{{Path: filepath.Join(dir, ".cloop", "features", "f1")}, {Path: "/elsewhere"}}
	overlayMoving(statuses, moving)
	if statuses[0].Moving == nil || statuses[0].Moving.ID != open.ID || statuses[1].Moving != nil {
		t.Errorf("features' moving = %+v, %+v", statuses[0].Moving, statuses[1].Moving)
	}
	// Ended: the list says nothing.
	if _, err := db.AdvanceProjectMove(statedb.ProjectMoveUpdate{ID: open.ID, FromPhase: "capture", FromVersion: open.Version,
		Phase: "failed", FailedPhase: "capture", Error: "test"}); err != nil {
		t.Fatal(err)
	}
	srv.dropMovingIndex()
	if p := list(); p.Moving != nil {
		t.Errorf("moving after the move ended = %+v", p.Moving)
	}
}

// TestAStoppingServerReadsNoMoreMoves: once Shutdown has begun, a projects
// list opens the control plane no more to read the open moves. One sent
// while the server stood down, after a lost lease say, would otherwise open
// the database after Run returned, recreating it in a directory its owner
// was removing.
func TestAStoppingServerReadsNoMoreMoves(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "stopping", nil)
	db := hubWithControlPlane(t, dir)
	srv := New(dir, 0, "")
	if _, err := db.CreateProjectMove(statedb.ProjectMoveRow{ID: "99aa99aa99aa99aa", ProjectPath: dir, Phase: "capture",
		TargetBinding: "local"}); err != nil {
		t.Fatal(err)
	}
	srv.dropMovingIndex()
	if got := srv.movingProjects(); len(got) != 1 {
		t.Fatalf("a running server's open moves = %v, want the one recorded", got)
	}
	srv.stopMovingIndex()
	if got := srv.movingProjects(); len(got) != 1 {
		t.Errorf("a stopping server forgot what it knew: %v", got)
	}
	srv.dropMovingIndex()
	if got := srv.movingProjects(); len(got) != 0 {
		t.Errorf("a stopping server read the open moves again: %v", got)
	}
}

// wsCollector reads one WebSocket's messages of one type.
type wsCollector struct {
	mu   sync.Mutex
	msgs []json.RawMessage
	any  chan struct{}
}

func collectWS(t *testing.T, base, path, kind string) *wsCollector {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+path, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	c := &wsCollector{any: make(chan struct{}, 1)}
	go func() {
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var msg wsMessage
			if json.Unmarshal(raw, &msg) != nil {
				continue
			}
			select {
			case c.any <- struct{}{}:
			default:
			}
			if msg.Type == kind {
				c.mu.Lock()
				c.msgs = append(c.msgs, msg.Data)
				c.mu.Unlock()
			}
		}
	}()
	select {
	case <-c.any:
	case <-time.After(10 * time.Second):
		t.Fatal("the WebSocket said nothing after connecting")
	}
	return c
}

func (c *wsCollector) snapshot() []json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]json.RawMessage(nil), c.msgs...)
}

func TestAMovesProgressIsPushedToItsProject(t *testing.T) {
	// Its own project list: index 0 is this test's project, whoever asks.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	_, db, srv, ts := movingProject(t)
	box := newHarnessExec("mv-push-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, box.id, executor.KindContainer)
	ws := collectWS(t, ts.URL, "/api/ws", "project_move")

	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-push-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	var phases []string
	deadline := time.Now().Add(30 * time.Second)
	for {
		phases = phases[:0]
		var last projectmove.Move
		for _, data := range ws.snapshot() {
			var p struct {
				Move projectmove.Move `json:"move"`
			}
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatalf("a project_move frame: %v: %s", err, data)
			}
			if p.Move.ID != m.ID {
				t.Fatalf("a frame for move %s", p.Move.ID)
			}
			if c := p.Move.Detail.Capture; c != nil && (len(c.Git.Branches) > 0 || len(c.Files) > 0) {
				t.Errorf("a pushed frame carries the capture's manifest: %s", data)
			}
			phases = append(phases, string(p.Move.Phase))
			last = p.Move
		}
		if last.Phase == projectmove.PhaseDone {
			if last.Detail.Verify == nil || last.Detail.Retained == nil {
				t.Errorf("the last frame = %+v", last.Detail)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("frames so far: %v", phases)
		}
		time.Sleep(20 * time.Millisecond)
	}
	want := []string{"preflight", "quiesce", "capture", "switch", "seed", "verify", "done"}
	at := 0
	for _, p := range phases {
		if at < len(want) && p == want[at] {
			at++
		}
	}
	if at != len(want) {
		t.Errorf("phases pushed = %v, want them to pass through %v in order", phases, want)
	}
	// The project's card: moving while it moved, not since.
	rec := serveMoveAPI(t, srv, http.MethodGet, "/api/projects", "")
	var list struct {
		Projects []multiui.ProjectStatus `json:"projects"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Projects) == 0 || list.Projects[0].Moving != nil {
		t.Errorf("the projects list after the move: %s (%v)", rec.Body.String(), err)
	}
}

// moveRequest sends method path as c and returns the status and whole body.
func moveRequest(t *testing.T, c *http.Client, method, url, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// TestMoveRoutesRefuseAViewerAndACallerOffTheAccessList: moving and cleaning
// up are an administrator's, on the target's access list; following a move is
// any reader's; a caller who cannot see the project cannot tell it has moves.
func TestMoveRoutesRefuseAViewerAndACallerOffTheAccessList(t *testing.T) {
	// Its own project list: index 0 is this test's project, whoever asks.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	db := hubWithControlPlane(t, srv.WorkDir)
	setProvider(t, srv.WorkDir, "ollama")
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
		{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		{Claim: authz.ClaimGroup, Value: "outsiders", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	box := newHarnessExec("mv-rbac-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, box.id, executor.KindContainer)
	if err := db.AddExecutorAudience(box.id, "group", "owners", "test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(srv.WorkDir) })
	as := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	viewer, outsider, owner, nobody := as("readers"), as("outsiders"), as("owners"), as("contractors")
	start := ts.URL + "/api/projects/0/move"

	if code, body := moveRequest(t, viewer, http.MethodPost, start, `{"target":"mv-rbac-box"}`); code != http.StatusForbidden {
		t.Errorf("a viewer's move = HTTP %d: %s", code, body)
	}
	if code, body := moveRequest(t, outsider, http.MethodPost, start, `{"target":"mv-rbac-box"}`); code != http.StatusForbidden ||
		!strings.Contains(string(body), "executor_audience_denied") {
		t.Errorf("a move by an administrator off the target's access list = HTTP %d: %s", code, body)
	}
	if code, body := moveRequest(t, nobody, http.MethodPost, start, `{"target":"mv-rbac-box"}`); code != http.StatusNotFound {
		t.Errorf("a move by a caller who cannot see the project = HTTP %d: %s", code, body)
	}

	code, body := moveRequest(t, owner, http.MethodPost, start, `{"target":"mv-rbac-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("the owner's move = HTTP %d: %s", code, body)
	}
	var started struct {
		Move projectmove.Move `json:"move"`
	}
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatal(err)
	}
	m := waitForMove(t, srv, started.Move.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s: %s", m.Phase, m.Error)
	}
	view := ts.URL + "/api/projects/0/move/" + m.ID
	if code, body := moveRequest(t, viewer, http.MethodGet, view, ""); code != http.StatusOK {
		t.Errorf("a viewer following the move = HTTP %d: %s", code, body)
	}
	if code, body := moveRequest(t, nobody, http.MethodGet, view, ""); code != http.StatusNotFound {
		t.Errorf("a caller who cannot see the project, reading its move = HTTP %d: %s", code, body)
	}
	for _, c := range []struct {
		who    string
		client *http.Client
		want   int
	}{{"a viewer", viewer, http.StatusForbidden}, {"a caller who cannot see the project", nobody, http.StatusNotFound}} {
		if code, body := moveRequest(t, c.client, http.MethodPost, view+"/cleanup", `{"confirm":true}`); code != c.want {
			t.Errorf("%s cleaning up = HTTP %d, want %d: %s", c.who, code, c.want, body)
		}
	}
	if _, err := os.Stat(m.Detail.Capture.Store); err != nil {
		t.Fatalf("a refused cleanup removed the store: %v", err)
	}
	if code, body := moveRequest(t, owner, http.MethodPost, view+"/cleanup", `{"confirm":true}`); code != http.StatusOK {
		t.Errorf("the owner cleaning up = HTTP %d: %s", code, body)
	}
}
