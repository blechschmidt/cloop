package ui

// Project moves over a real hub (Task 20494): the engine driven by the hub's
// own driver against a project that is a git repository with changes no
// commit holds — onto an executor sharing the hub's tree, and onto a device
// that provisions the move's carrier branch exactly as a remote agent does
// (gitprovision) and runs the device half of the move in-process. The phase
// failures and the crash points are covered over fakes in pkg/projectmove;
// here it is the wiring: the switch's transaction, the run gate, the lease,
// the resume, the audit rows and the cleanup.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeMoveDevice is a device executor: it keeps working copies under root,
// provisions a workload's workspace the way a remote agent does, and runs the
// move's device steps in-process instead of a cloop binary.
type fakeMoveDevice struct {
	id   string
	root string

	mu     sync.Mutex
	runs   map[string]*fakeMoveRun
	argv   [][]string
	failOn string
	// onStep, when set, runs as each step is dispatched.
	onStep func(step string)
}

type fakeMoveRun struct {
	out  string
	code int
	done chan struct{}
}

func newFakeMoveDevice(t *testing.T, id string) *fakeMoveDevice {
	return &fakeMoveDevice{id: id, root: t.TempDir(), runs: map[string]*fakeMoveRun{}}
}

func (d *fakeMoveDevice) ID() string   { return d.id }
func (d *fakeMoveDevice) Kind() string { return executor.KindRemoteAgent }
func (d *fakeMoveDevice) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote, SupportsWorkspaceProvisioning: true,
		SupportsProjectSeed: true, ReturnsProjectState: true, SupportsBranchBundle: true, SupportsWriteBack: true,
		SupportsSecretFiles: true, NetworkEgress: true}
}
func (d *fakeMoveDevice) HealthCheck(context.Context) error { return nil }
func (d *fakeMoveDevice) Signal(context.Context, string, executor.Signal) error {
	return nil
}
func (d *fakeMoveDevice) SupportsRevocation() bool { return true }
func (d *fakeMoveDevice) HoldsLease(string) bool   { return false }
func (d *fakeMoveDevice) Leases() []string         { return nil }
func (d *fakeMoveDevice) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, State: executor.RevokeStateRevoked}
}
func (d *fakeMoveDevice) Revocations() []executor.RevokeOutcome { return nil }

// workDir is where the device keeps a project's working copy.
func (d *fakeMoveDevice) workDir(project string) string {
	return filepath.Join(d.root, executor.DeviceWorkDir(project))
}

func (d *fakeMoveDevice) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	d.mu.Lock()
	id := fmt.Sprintf("%s-%d", d.id, len(d.argv)+1)
	r := &fakeMoveRun{done: make(chan struct{})}
	d.runs[id] = r
	d.argv = append(d.argv, append([]string(nil), spec.Argv...))
	fail, onStep := d.failOn, d.onStep
	d.mu.Unlock()
	if onStep != nil && len(spec.Argv) > 2 {
		onStep(spec.Argv[2])
	}
	if filepath.IsAbs(spec.WorkDir) {
		return executor.Handle{}, fmt.Errorf("fake device: workdir %q escapes its root", spec.WorkDir)
	}
	go func() {
		defer close(r.done)
		dir := filepath.Join(d.root, spec.WorkDir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			r.out, r.code = err.Error(), 1
			return
		}
		ctx := context.Background()
		if spec.Workspace.NeedsProvisioning() {
			if err := gitprovision.Provision(ctx, gitprovision.Request{Dir: dir, Workspace: spec.Workspace,
				BranchBundleFile: spec.BranchBundleFile, Host: d.id}); err != nil {
				r.out, r.code = err.Error()+"\n", 1
				return
			}
		}
		// Every step is `cloop workspace <step> --move <id>`; the discard
		// also names what it checks the copy against (Task 20496).
		discard := len(spec.Argv) > 5 && spec.Argv[2] == "move-discard"
		if (len(spec.Argv) != 5 && !discard) || spec.Argv[0] != "cloop" || spec.Argv[1] != "workspace" || spec.Argv[3] != "--move" {
			r.out, r.code = fmt.Sprintf("fake device: unexpected argv %q\n", spec.Argv), 2
			return
		}
		step, moveID := spec.Argv[2], spec.Argv[4]
		var opts projectmove.DiscardOptions
		if discard {
			opts.MoveID = moveID
			for i := 5; i < len(spec.Argv); i++ {
				switch spec.Argv[i] {
				case "--discard-ignored":
					opts.DiscardIgnored = true
				case "--snapshot", "--refs", "--files":
					if i+1 < len(spec.Argv) {
						*map[string]*string{"--snapshot": &opts.Snapshot, "--refs": &opts.Refs, "--files": &opts.Files}[spec.Argv[i]] = spec.Argv[i+1]
						i++
					}
				}
			}
		}
		if step == fail {
			r.out, r.code = "fake device: "+step+" failed\n", 1
			return
		}
		var (
			rep projectmove.WorkingCopyReport
			err error
		)
		switch step {
		case "move-probe":
			rep, err = projectmove.ProbeWorkingCopy(ctx, dir, moveID)
		case "move-seed":
			rep, err = projectmove.SeedWorkingCopy(ctx, dir, moveID)
		case "move-verify":
			rep, err = projectmove.ReportWorkingCopy(ctx, dir, moveID)
		case "move-discard":
			if !discard {
				err = errors.New("move-discard needs what the move captured")
				break
			}
			rep, err = projectmove.DiscardWorkingCopy(ctx, dir, opts)
		default:
			err = fmt.Errorf("unknown command %q", step)
		}
		if err != nil {
			r.out, r.code = err.Error()+"\n", 1
			return
		}
		line, _ := projectmove.FormatReport(rep)
		r.out = "workspace: ready\n" + line + "\n"
	}()
	return executor.Handle{ID: id, ExecutorID: d.id, StartedAt: time.Now()}, nil
}

func (d *fakeMoveDevice) run(id string) *fakeMoveRun {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.runs[id]
}

func (d *fakeMoveDevice) Stream(_ context.Context, id string) (<-chan executor.LogLine, error) {
	r := d.run(id)
	if r == nil {
		return nil, executor.ErrHandleNotFound
	}
	ch := make(chan executor.LogLine, 1)
	go func() {
		<-r.done
		ch <- executor.LogLine{HandleID: id, Text: r.out, Seq: 1, Time: time.Now()}
		close(ch)
	}()
	return ch, nil
}

func (d *fakeMoveDevice) Status(_ context.Context, id string) (executor.Status, error) {
	r := d.run(id)
	if r == nil {
		return executor.Status{}, executor.ErrHandleNotFound
	}
	select {
	case <-r.done:
		return executor.Status{HandleID: id, ExecutorID: d.id, State: executor.StateExited, ExitCode: r.code}, nil
	default:
		return executor.Status{HandleID: id, ExecutorID: d.id, State: executor.StateRunning}, nil
	}
}

func (d *fakeMoveDevice) steps() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, a := range d.argv {
		if len(a) > 2 {
			out = append(out, a[2])
		}
	}
	return out
}

// movingProject is a project whose directory is a repository with every kind
// of change no commit holds, and .cloop files of its own.
func movingProject(t *testing.T) (string, *statedb.DB, *Server, *httptest.Server) {
	t.Helper()
	dir := setupProjectDir(t, "moving", nil)
	db := hubWithControlPlane(t, dir)
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	// A provider the hub brokers no credential for, so the target's harness
	// preflight has nothing to refuse.
	setProvider(t, dir, "ollama")
	moveWrite(t, filepath.Join(dir, "keep.txt"), "base\n")
	moveWrite(t, filepath.Join(dir, "rename-me.txt"), "rename\n")
	moveWrite(t, filepath.Join(dir, "delete-me.txt"), "delete\n")
	moveWrite(t, filepath.Join(dir, "blob.bin"), string([]byte{0, 1, 2, 3, 255, 254}))
	moveWrite(t, filepath.Join(dir, ".gitignore"), ".cloop/state.db*\n")
	moveGit(t, dir, "init", "-q", "-b", "main")
	moveGit(t, dir, "remote", "add", "origin", "https://git.example.com/acme/moving.git")
	moveGit(t, dir, "add", "keep.txt", "rename-me.txt", "delete-me.txt", "blob.bin", ".gitignore")
	moveGit(t, dir, "commit", "-q", "-m", "base")
	moveGit(t, dir, "mv", "rename-me.txt", "renamed.txt")
	if err := os.Remove(filepath.Join(dir, "delete-me.txt")); err != nil {
		t.Fatal(err)
	}
	moveWrite(t, filepath.Join(dir, "keep.txt"), "changed\n")
	moveWrite(t, filepath.Join(dir, "blob.bin"), string([]byte{9, 0, 8, 0, 7}))
	moveWrite(t, filepath.Join(dir, "untracked", "new.txt"), "untracked\n")
	moveWrite(t, filepath.Join(dir, ".cloop", "artifacts", "1_output.txt"), "output\n")
	return dir, db, srv, ts
}

// recordExecutor gives a registered executor the control-plane row a binding
// needs.
func recordExecutor(t *testing.T, db *statedb.DB, id, kind string) {
	t.Helper()
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: id, Name: id, Kind: kind, Status: "ready", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

// startMoveOver asks the hub to move project 0 and returns the move.
func startMoveOver(t *testing.T, base, body string) (int, projectmove.Move, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/api/projects/0/move", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Move projectmove.Move `json:"move"`
	}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out.Move, string(raw)
}

// waitForMove waits for this process to stop driving the move and returns it.
func waitForMove(t *testing.T, srv *Server, id string) projectmove.Move {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for srv.moveRun().driving(id) {
		if time.Now().After(deadline) {
			t.Fatalf("move %s is still being driven", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
	m, err := (projectmove.DBStore{Open: srv.controlPlaneDB}).Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// gitOut is git's output in dir.
func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// auditActions lists the project.move rows in the control plane's trail.
func auditActions(t *testing.T, db *statedb.DB, id string) []string {
	t.Helper()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project_move", EntityID: id, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.EventType)
	}
	sort.Strings(out)
	return out
}

func TestAProjectMovesOntoAnExecutorSharingItsTree(t *testing.T) {
	dir, db, srv, ts := movingProject(t)
	box := newHarnessExec("mv-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, "mv-box", executor.KindContainer)
	index := mustReadFile(t, filepath.Join(dir, ".git", "index"))
	status := gitOut(t, dir, "status", "--porcelain=v2")

	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if got, _, _ := db.ProjectExecutor(dir); got != "mv-box" {
		t.Errorf("binding = %q", got)
	}
	if got, _ := executor.DefaultRegistry.Binding(dir); got != "mv-box" {
		t.Errorf("registry binding = %q", got)
	}
	c := m.Detail.Capture
	if c == nil || c.Delivery != projectmove.DeliverSameTree || !c.Git.Repository || !c.Git.Snapshot.Dirty {
		t.Fatalf("capture = %+v", c)
	}
	for _, f := range []string{projectmove.CarrierBundle, projectmove.CarrierFiles} {
		if _, err := os.Stat(filepath.Join(c.Store, f)); err != nil {
			t.Errorf("the store has no %s: %v", f, err)
		}
	}
	if got := gitOut(t, dir, "rev-parse", "refs/cloop/move/"+m.ID); got != c.Git.Snapshot.Commit {
		t.Errorf("hidden ref = %s", got)
	}
	// The source is as it was: the move only read it.
	if !bytes.Equal(index, mustReadFile(t, filepath.Join(dir, ".git", "index"))) {
		t.Error("the move rewrote the source's index")
	}
	if got := gitOut(t, dir, "status", "--porcelain=v2"); got != status {
		t.Errorf("the source's status changed:\n%s\nvs\n%s", status, got)
	}
	if v := m.Detail.Verify; v == nil || v.Checked == 0 || len(v.Mismatches) > 0 {
		t.Errorf("verify = %+v", v)
	}
	if r := m.Detail.Retained; r == nil || r.Command != "cloop executor move cleanup "+m.ID || r.Store != c.Store {
		t.Errorf("retained = %+v", r)
	}
	want := []string{auditaction.ActionProjectMoveDone.String(), auditaction.ActionProjectMoveStart.String(), auditaction.ActionProjectMoveSwitch.String()}
	if got := auditActions(t, db, m.ID); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("audit = %v, want %v", got, want)
	}

	// The moves list names it.
	resp, err := http.Get(ts.URL + "/api/projects/0/moves")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Moves []projectmove.Move `json:"moves"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Moves) != 1 || list.Moves[0].ID != m.ID {
		t.Errorf("moves = %+v", list.Moves)
	}

	// Cleaning up removes the refs and the store, and says so, once.
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/projects/0/move/%s/cleanup", ts.URL, m.ID), strings.NewReader(`{"confirm":true}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("cleanup = HTTP %d: %s", resp.StatusCode, body)
		}
	}
	if _, err := os.Stat(c.Store); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the store survived cleanup: %v", err)
	}
	if out, err := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", "refs/cloop/move/"+m.ID).CombinedOutput(); err == nil {
		t.Errorf("the hidden ref survived cleanup: %s", out)
	}
	if got := auditActions(t, db, m.ID); len(got) != 4 || got[0] != auditaction.ActionProjectMoveCleanup.String() {
		t.Errorf("audit after cleanup = %v", got)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("cleanup removed the project: %v", err)
	}
}

func TestNoRunStartsWhileAMoveIsOpen(t *testing.T) {
	dir := setupProjectDir(t, "gated", nil)
	db := hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)
	open, err := db.CreateProjectMove(statedb.ProjectMoveRow{ID: "0011223344556677", ProjectPath: dir, Phase: "capture", TargetBinding: "mv-x"})
	if err != nil {
		t.Fatal(err)
	}
	post := func(path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, body := post("/api/run?project_idx=0", "{}"); code != http.StatusConflict || body["code"] != "project_moving" || body["move"] != open.ID {
		t.Errorf("run = HTTP %d %v", code, body)
	}
	if code, body := post("/api/projects/0/executor", `{"executor_id":"local"}`); code != http.StatusConflict || body["code"] != "project_moving" {
		t.Errorf("rebind = HTTP %d %v", code, body)
	}
	if code, body := post("/api/projects/0/move", `{"target":"local"}`); code != http.StatusConflict || body["code"] != "move_in_progress" {
		t.Errorf("a second move = HTTP %d %v", code, body)
	}
	// Every dispatch path meets the gate, a feature's too.
	_, _, err = startWorkload(dir, []string{"cloop", "run"}, nil)
	var moving *projectMovingError
	if !errors.As(err, &moving) || moving.Move.ID != open.ID {
		t.Errorf("dispatch = %v", err)
	}
	if err := checkNoOpenMove(filepath.Join(dir, ".cloop", "features", "f1")); !errors.As(err, &moving) {
		t.Errorf("a feature's dispatch = %v", err)
	}
	// The dashboard's helper workloads too: one would run in the working
	// copy the move is seeding.
	if _, err := runWorkload(context.Background(), dir, []string{"cloop", "suggest"}, nil); !errors.As(err, &moving) {
		t.Errorf("a helper workload = %v", err)
	}
	rec := httptest.NewRecorder()
	jsonWorkloadErr(rec, err)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "project_moving") {
		t.Errorf("rendered = %d %s", rec.Code, rec.Body.String())
	}
	// Once the move has ended, dispatches pass the gate again.
	if _, err := db.AdvanceProjectMove(statedb.ProjectMoveUpdate{ID: open.ID, FromPhase: "capture", FromVersion: open.Version,
		Phase: "failed", FailedPhase: "capture", Error: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := checkNoOpenMove(dir); err != nil {
		t.Errorf("after the move ended: %v", err)
	}
}

func TestAMoveToADeviceSeedsAndVerifiesItsWorkingCopy(t *testing.T) {
	dir, db, srv, ts := movingProject(t)
	dev := newFakeMoveDevice(t, "mv-dev1")
	registerMoveExec(t, dev)
	recordExecutor(t, db, dev.id, executor.KindRemoteAgent)
	before := treeOf(t, dir)

	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-dev1"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if got := strings.Join(dev.steps(), ","); got != "move-probe,move-seed,move-verify" {
		t.Errorf("device steps = %s", got)
	}
	copyDir := dev.workDir(dir)
	after := treeOf(t, copyDir)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Errorf("the device's copy differs from the source:\n%v\nvs\n%v", before, after)
	}
	if got := gitOut(t, copyDir, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop"); got != gitOut(t, dir, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop") {
		t.Errorf("status differs on the device:\n%s", got)
	}
	if got := gitOut(t, copyDir, "config", "remote.origin.url"); got != "https://git.example.com/acme/moving.git" {
		t.Errorf("origin on the device = %s", got)
	}
	if b, err := os.ReadFile(filepath.Join(copyDir, ".cloop", "artifacts", "1_output.txt")); err != nil || string(b) != "output\n" {
		t.Errorf("artifact on the device = %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(copyDir, ".cloop", "config.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the project's config reached the device: %v", err)
	}
	if got, _, _ := db.ProjectExecutor(dir); got != dev.id {
		t.Errorf("binding = %q", got)
	}
	if _, err := os.Stat(filepath.Join(m.Detail.Capture.Store, "seed.bundle")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the carrier was left in the store: %v", err)
	}
}

func TestAMoveToADeviceThatAlreadyHoldsWorkRollsBack(t *testing.T) {
	dir, db, srv, ts := movingProject(t)
	dev := newFakeMoveDevice(t, "mv-dev2")
	registerMoveExec(t, dev)
	recordExecutor(t, db, dev.id, executor.KindRemoteAgent)
	recordExecutor(t, db, "local", executor.KindLocalProcess)
	if err := db.BindProjectExecutor(dir, "local", "test"); err != nil {
		t.Fatal(err)
	}
	moveWrite(t, filepath.Join(dev.workDir(dir), "somebodys-work.txt"), "do not lose me\n")

	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-dev2"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseRolledBack || m.FailedPhase != projectmove.PhaseSeed || !strings.Contains(m.Error, "never overwrites") {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if got, _, _ := db.ProjectExecutor(dir); got != "local" {
		t.Errorf("binding after the rollback = %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dev.workDir(dir), "somebodys-work.txt")); string(b) != "do not lose me\n" {
		t.Error("the device's own work was touched")
	}
	// The bundle is kept.
	if _, err := os.Stat(filepath.Join(m.Detail.Capture.Store, projectmove.CarrierBundle)); err != nil {
		t.Errorf("the bundle was not kept: %v", err)
	}
	want := []string{auditaction.ActionProjectMoveRollback.String(), auditaction.ActionProjectMoveStart.String(), auditaction.ActionProjectMoveSwitch.String()}
	if got := auditActions(t, db, m.ID); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("audit = %v, want %v", got, want)
	}
	// A rolled-back move frees the project: runs start again.
	if err := checkNoOpenMove(dir); err != nil {
		t.Errorf("gate after the rollback: %v", err)
	}
}

func TestARollbackToAnExecutorThatIsGoneLeavesTheProjectUnbound(t *testing.T) {
	dir, db, srv, ts := movingProject(t)
	dev := newFakeMoveDevice(t, "mv-dev3")
	registerMoveExec(t, dev)
	recordExecutor(t, db, dev.id, executor.KindRemoteAgent)
	old := newHarnessExec("mv-old", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, old)
	recordExecutor(t, db, "mv-old", executor.KindContainer)
	if err := db.BindProjectExecutor(dir, "mv-old", "test"); err != nil {
		t.Fatal(err)
	}
	// The seed fails, and by then the executor the move replaced has been
	// removed from the hub.
	dev.failOn = "move-seed"
	dev.onStep = func(step string) {
		if step == "move-seed" {
			if err := db.DeleteExecutor("mv-old"); err != nil {
				t.Errorf("delete the old executor: %v", err)
			}
		}
	}
	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-dev3"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseRolledBack || !strings.Contains(m.Error, "left unbound") {
		t.Fatalf("move ended %s: %s", m.Phase, m.Error)
	}
	if id, bound, _ := db.ProjectExecutor(dir); bound {
		t.Errorf("binding = %q, want none", id)
	}
	if err := checkNoOpenMove(dir); err != nil {
		t.Errorf("gate after the rollback: %v", err)
	}
}

func TestAnOpenMoveResumesUnderItsLeaseAfterARestart(t *testing.T) {
	dir, db, _, _ := movingProject(t)
	box := newHarnessExec("mv-box2", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, "mv-box2", executor.KindContainer)

	// A hub that recorded the move and stopped before it drove it.
	first := New(dir, 0, "")
	req := httptest.NewRequest(http.MethodPost, "/api/projects/0/move", nil)
	env := &moveEnv{s: first, r: req, now: time.Now()}
	m, _, err := first.moveEngine().Start(context.Background(), env, projectmove.StartRequest{
		Project: projectmove.Project{Name: "moving", Path: dir}, Target: "mv-box2", StartedBy: "alice"})
	env.close()
	if err != nil {
		t.Fatal(err)
	}
	if m.Phase != projectmove.PhaseQuiesce {
		t.Fatalf("recorded at %s", m.Phase)
	}

	// While another live process holds its lease, nobody else drives it.
	held, err := hublease.Acquire(hublease.Options{Store: db, Scope: moveLeaseScope(m.ID), InstanceID: "elsewhere"})
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(dir, 0, "")
	_, err = restarted.driveMove(context.Background(), m.ID)
	var conflict *hublease.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("drive under a held lease = %v", err)
	}
	if cur, _ := (projectmove.DBStore{Open: restarted.controlPlaneDB}).Get(context.Background(), m.ID); cur.Phase != projectmove.PhaseQuiesce {
		t.Fatalf("a process without the lease moved it to %s", cur.Phase)
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}

	// The restarted hub's sweep takes it up and finishes it.
	restarted.sweepProjectMoves(context.Background())
	out := waitForMove(t, restarted, m.ID)
	if out.Phase != projectmove.PhaseDone {
		t.Fatalf("resumed move ended %s at %s: %s", out.Phase, out.FailedPhase, out.Error)
	}
	if got, _, _ := db.ProjectExecutor(dir); got != "mv-box2" {
		t.Errorf("binding = %q", got)
	}
	steps := out.Detail.Timeline
	if len(steps) == 0 || steps[len(steps)-1].Member != restarted.hubInstanceID() {
		t.Errorf("timeline = %+v", steps)
	}
}

// treeOf is what a working tree holds outside .git and .cloop.
func treeOf(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		top := strings.Split(filepath.ToSlash(rel), "/")[0]
		if top == ".git" || top == ".cloop" {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			out = append(out, fmt.Sprintf("%s %x %v", filepath.ToSlash(rel), b, info.Mode().Perm()&0o100 != 0))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
