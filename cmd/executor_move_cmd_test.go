package cmd

// `cloop executor move` (Task 20496) against hubs in this process: one with
// single sign-on, reached with the session `cloop login` stored, and one on
// this machine without sign-in, reached with no credential at all. The move
// goes to an executor that works in the hub's own tree, so the whole move —
// preflight, quiesce, capture, switch, seed, verify — runs here; the device
// half is pkg/ui's and tests/e2e's to prove.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// treeExec is a container executor that works in the hub's own tree: what a
// move needs nothing on the target for. It starts nothing.
type treeExec struct{ ssohubtest.StubExecutor }

func (e *treeExec) Kind() string { return executor.KindContainer }
func (e *treeExec) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer, SharesHostFilesystem: true, SupportsStream: true}
}

// runMoveCLI runs `cloop executor move <args>` as a terminal would.
func runMoveCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags(executorMoveCmd)
	t.Cleanup(func() { resetFlags(executorMoveCmd) })
	var out bytes.Buffer
	rootCmd.SetArgs(append([]string{"executor", "move"}, args...))
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := rootCmd.ExecuteContextC(ctx)
	return out.String(), err
}

// quietProvider gives a project a provider the hub brokers no credential for,
// so a sandboxed target's harness check has nothing to say.
func quietProvider(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte("provider: ollama\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// moveIDFrom finds the move id the command printed.
func moveIDFrom(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "(move ")
	if i < 0 || len(out) < i+len("(move ")+16 {
		t.Fatalf("no move id in:\n%s", out)
	}
	return out[i+len("(move ") : i+len("(move ")+16]
}

func TestExecutorMoveOnAHubWithSignIn(t *testing.T) {
	w := newRemoteWorld(t)
	quietProvider(t, w.hub.Dir)
	box := &treeExec{ssohubtest.StubExecutor{IDValue: "move-cli-box"}}
	w.hub.AddExecutor(t, box, "Build box 7")
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(w.hub.Dir) })

	// A viewer may read the plan's answer but not move anything.
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	if out, err := runMoveCLI(t, "0", "--to", box.ID(), "--yes"); err == nil {
		t.Fatalf("a viewer's move was not refused:\n%s", out)
	}

	w.as(t, rootEmail)
	// The dry run is the preflight, and changes nothing.
	out, err := runMoveCLI(t, "0", "--to", box.ID(), "--dry-run", "--json")
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	var rep projectmove.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Target.Binding != box.ID() || rep.Blocked {
		t.Fatalf("dry run --json = %v\n%s", err, out)
	}
	db := w.hub.ControlPlane(t)
	if moves, _ := db.ListProjectMoves(statedb.ProjectMoveFilter{}); len(moves) != 0 {
		t.Fatalf("a dry run started %d move(s)", len(moves))
	}
	// A target that is not one is refused before anything is asked.
	if _, err := runMoveCLI(t, "0", "--to", "label:gpu=true"); err == nil {
		t.Error("a label target was accepted")
	}
	if _, err := runMoveCLI(t, "0"); err == nil || !strings.Contains(err.Error(), "--to") {
		t.Errorf("no --to: %v", err)
	}

	// The move, followed to its end.
	out, err = runMoveCLI(t, "0", "--to", box.ID(), "--yes")
	if err != nil {
		t.Fatalf("move: %v\n%s", err, out)
	}
	for _, want := range []string{"Move preflight for", "Moving", "✓ quiesce", "✓ capture", "✓ verify", "Done:", "cloop executor move cleanup"} {
		if !strings.Contains(out, want) {
			t.Errorf("the move's output lacks %q:\n%s", want, out)
		}
	}
	id := moveIDFrom(t, out)
	if got, _, _ := db.ProjectExecutor(w.hub.Dir); got != box.ID() {
		t.Errorf("binding = %q", got)
	}

	// Its status, found among the projects without being told which.
	out, err = runMoveCLI(t, "status", id)
	if err != nil || !strings.Contains(out, "Move "+id) || !strings.Contains(out, "verified") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	out, err = runMoveCLI(t, "status", id, "--json")
	var view moveView
	if err != nil || json.Unmarshal([]byte(out), &view) != nil || view.Move.Phase != projectmove.PhaseDone ||
		view.Cleanup == nil || !view.Cleanup.Allowed {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
	if _, err := runMoveCLI(t, "status", "0000000000000000"); err == nil {
		t.Error("the status of a move nobody made was found")
	}
	if _, err := runMoveCLI(t, "status", "not-an-id"); err == nil {
		t.Error("a malformed id was accepted")
	}

	// Cleanup asks first; without a terminal or --yes nothing is removed.
	store := view.Cleanup.Store
	if out, err := runMoveCLI(t, "cleanup", id); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("an unconfirmed cleanup: %v\n%s", err, out)
	}
	if _, err := os.Stat(store); err != nil {
		t.Fatalf("an unconfirmed cleanup removed the store: %v", err)
	}
	out, err = runMoveCLI(t, "cleanup", id, "--yes", "--project", "0")
	if err != nil || !strings.Contains(out, "Cleaned up after move "+id) || !strings.Contains(out, "never removes") {
		t.Fatalf("cleanup: %v\n%s", err, out)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Errorf("the store survived: %v", err)
	}
	if out, err := runMoveCLI(t, "cleanup", id, "--yes"); err != nil || !strings.Contains(out, "already") {
		t.Errorf("a second cleanup: %v\n%s", err, out)
	}
}

// TestExecutorMoveOnALocalHub: a hub on this machine without sign-in answers
// a terminal that holds no session for it, and refuses nothing for want of
// one.
func TestExecutorMoveOnALocalHub(t *testing.T) {
	credentialHome(t)
	t.Setenv("HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "shop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "moved from a terminal", 0); err != nil {
		t.Fatal(err)
	}
	quietProvider(t, dir)
	srv := ui.New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	box := &treeExec{ssohubtest.StubExecutor{IDValue: "move-cli-local-box"}}
	if err := executor.Register(box); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(box.ID()); executor.DefaultRegistry.Unbind(dir) })
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: box.ID(), Name: box.ID(), Kind: box.Kind(),
		Status: statedb.ExecutorStatusOnline, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	out, err := runMoveCLI(t, "shop", "--to", box.ID(), "--yes", "--json", "--hub", ts.URL)
	if err != nil {
		t.Fatalf("move: %v\n%s", err, out)
	}
	var view moveView
	if err := json.Unmarshal([]byte(out), &view); err != nil || view.Move.Phase != projectmove.PhaseDone {
		t.Fatalf("move --json: %v\n%s", err, out)
	}
	out, err = runMoveCLI(t, "cleanup", view.Move.ID, "--yes", "--json", "--hub", ts.URL)
	if err != nil {
		t.Fatalf("cleanup: %v\n%s", err, out)
	}
	// --json keeps stdout to one document: what it removes went to stderr,
	// which this test's buffer shares, so the document is what follows it.
	at := strings.Index(out, "\n{\n")
	var done moveView
	if at < 0 || json.Unmarshal([]byte(out[at+1:]), &done) != nil || done.Cleanup == nil || done.Cleanup.CleanedAt == nil {
		t.Fatalf("cleanup --json:\n%s", out)
	}
	if !strings.HasPrefix(out, "Cleaning up after move "+view.Move.ID) {
		t.Errorf("cleanup did not say what it removes first:\n%s", out)
	}
}
