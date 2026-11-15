package ui

// Moves from a device's working copy (Task 20495), over a real hub: the
// engine driven by the hub's own driver, the device answering the capture
// in-process through pkg/executor/movecapture — exactly the code its agent
// runs behind the protocol's capture frames, which pkg/executor/remote's
// loopback tests and tests/e2e drive over a real connection.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/movecapture"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeCaptureDevice is a device that also answers capture requests, as its
// agent would.
type fakeCaptureDevice struct {
	*fakeMoveDevice
	protocol int
	asked    []string
}

func newFakeCaptureDevice(t *testing.T, id string) *fakeCaptureDevice {
	return &fakeCaptureDevice{fakeMoveDevice: newFakeMoveDevice(t, id), protocol: remote.ProtocolVersion}
}

func (d *fakeCaptureDevice) CaptureVersion() (int, bool) { return d.protocol, true }

// memAnswer is an answer held in memory.
type memAnswer struct{ parts map[string][]byte }

func (a *memAnswer) WriteTo(part string, w io.Writer) (int64, error) {
	if a.parts == nil {
		return 0, errors.New("released")
	}
	n, err := w.Write(a.parts[part])
	return int64(n), err
}

func (a *memAnswer) Release() { a.parts = nil }

func (d *fakeCaptureDevice) captureWorkingCopy(ctx context.Context, req remote.CaptureRequest) (captureAnswer, error) {
	d.mu.Lock()
	d.asked = append(d.asked, req.Mode)
	d.mu.Unlock()
	if !remote.SupportsProjectCapture(d.protocol) {
		return nil, fmt.Errorf("%w: too old", remote.ErrCaptureUnsupported)
	}
	scratch, err := os.MkdirTemp("", "fake-capture-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	mreq := movecapture.Request{Root: d.root, WorkDir: req.WorkDir, Mode: req.Mode, MoveID: req.MoveID,
		Scratch: filepath.Join(scratch, "s"), MaxBundleBytes: req.Limits.Bundle, MaxFilesBytes: req.Limits.Files}
	for _, f := range req.Features {
		mreq.Features = append(mreq.Features, movecapture.Feature{Slug: f.Slug, Dir: f.Dir})
	}
	parts := map[string][]byte{}
	var doc movecapture.Document
	if req.Mode == remote.CaptureInspect {
		doc, err = movecapture.Inspect(ctx, mreq)
	} else {
		var res movecapture.Result
		res, err = movecapture.Capture(ctx, mreq)
		doc = res.Doc
		for part, p := range map[string]string{remote.CapturePartBundle: res.BundlePath, remote.CapturePartFiles: res.TarPath} {
			if p == "" {
				continue
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil, rerr
			}
			parts[part] = b
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", remote.ErrCaptureRefused, err)
	}
	raw, err := doc.Encode()
	if err != nil {
		return nil, err
	}
	parts[remote.CapturePartDocument] = raw
	return &memAnswer{parts: parts}, nil
}

// recordOn records an executor in srv's control plane.
func recordOn(t *testing.T, srv *Server, id, kind string) {
	t.Helper()
	db, err := srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recordExecutor(t, db, id, kind)
}

// deviceSourcedProject is a project whose hub directory holds only .cloop,
// bound to a device whose working copy holds a commit no remote has,
// uncommitted and untracked work, and a run's output.
func deviceSourcedProject(t *testing.T, devID string) (dir string, dev *fakeCaptureDevice, srv *Server, base string) {
	t.Helper()
	dir = setupProjectDir(t, "moving off a device", nil)
	db := hubWithControlPlane(t, dir)
	srv = New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	setProvider(t, dir, "ollama")
	dev = newFakeCaptureDevice(t, devID)
	registerMoveExec(t, dev)
	recordExecutor(t, db, dev.id, executor.KindRemoteAgent)
	if err := db.BindProjectExecutor(dir, dev.id, "test"); err != nil {
		t.Fatal(err)
	}
	if err := executor.Bind(dir, dev.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	wc := dev.workDir(dir)
	moveGit(t, filepath.Dir(wc), "init", "-q", "-b", "main", wc)
	moveWrite(t, filepath.Join(wc, "app.go"), "package app\n")
	moveWrite(t, filepath.Join(wc, "keep.txt"), "kept\n")
	moveGit(t, wc, "add", "-A")
	moveGit(t, wc, "commit", "-q", "-m", "made on the device")
	moveGit(t, wc, "remote", "add", "origin", "https://git.example.com/acme/devproj.git")
	moveWrite(t, filepath.Join(wc, "app.go"), "package app // edited on the device\n")
	moveWrite(t, filepath.Join(wc, "notes", "draft.md"), "not yet committed\n")
	moveWrite(t, filepath.Join(wc, ".cloop", "artifacts", "3_output.txt"), "task three's output, from the device\n")
	moveWrite(t, filepath.Join(wc, ".cloop", "config.yaml"), "provider: claudecode\n")
	return dir, dev, srv, ts.URL
}

func TestAMoveFromADeviceRebuildsTheHubsTree(t *testing.T) {
	dir, dev, srv, base := deviceSourcedProject(t, "mv-cap-dev1")
	box := newHarnessExec("mv-cap-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, srv, box.id, executor.KindContainer)
	wc := dev.workDir(dir)
	devStatus := gitOut(t, wc, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop")

	// The preflight reads the device's working copy over the capture
	// protocol, and finds the work.
	status, rep, raw := preflightOver(t, http.DefaultClient, base, "target=mv-cap-box")
	if status != http.StatusOK {
		t.Fatalf("preflight = HTTP %d: %s", status, raw)
	}
	if !findingOf(rep, projectmove.KindWorkingTree, projectmove.SeverityWillCarry, "1 changed and 1 untracked") {
		t.Errorf("the preflight did not read the device's working copy:\n%s", raw)
	}
	for _, f := range rep.Findings {
		if f.Kind == projectmove.KindSourceUnseen {
			t.Errorf("the device's working copy is still reported unseen:\n%s", raw)
		}
	}

	code, m, raw := startMoveOver(t, base, `{"target":"mv-cap-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	c := m.Detail.Capture
	if c.Delivery != projectmove.DeliverHubTree || c.From != "device mv-cap-dev1" || c.Scan == nil || c.Scan.Result != "clean" {
		t.Errorf("capture = delivery %s from %q, scan %+v", c.Delivery, c.From, c.Scan)
	}
	if fmt.Sprint(treeOf(t, wc)) != fmt.Sprint(treeOf(t, dir)) {
		t.Errorf("the hub's tree differs from the device's:\n%v\nvs\n%v", treeOf(t, dir), treeOf(t, wc))
	}
	if got := gitOut(t, dir, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop"); got != devStatus {
		t.Errorf("status on the hub:\n%s\nwant\n%s", got, devStatus)
	}
	if b, err := os.ReadFile(filepath.Join(dir, ".cloop", "artifacts", "3_output.txt")); err != nil || !strings.Contains(string(b), "from the device") {
		t.Errorf("the device's run output did not arrive: %q %v", b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".cloop", "config.yaml")); strings.Contains(string(b), "claudecode") {
		t.Error("the device's configuration replaced the hub's")
	}
	// Asked by the preflight above, by the move's own preflight, then for
	// the capture.
	if got := strings.Join(dev.asked, ","); got != "inspect,inspect,capture" {
		t.Errorf("the device was asked %s", got)
	}
	if got := gitOut(t, dir, "status", "--porcelain", "--", ".cloop"); got != "" {
		t.Errorf("git sees the hub's .cloop: %s", got)
	}
}

func TestAMoveFromADeviceToAnotherDeviceSeedsIt(t *testing.T) {
	dir, dev, srv, base := deviceSourcedProject(t, "mv-cap-dev2")
	other := newFakeMoveDevice(t, "mv-cap-dev3")
	registerMoveExec(t, other)
	recordOn(t, srv, other.id, executor.KindRemoteAgent)

	code, m, raw := startMoveOver(t, base, `{"target":"mv-cap-dev3"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	from, to := dev.workDir(dir), other.workDir(dir)
	if fmt.Sprint(treeOf(t, from)) != fmt.Sprint(treeOf(t, to)) {
		t.Errorf("the target device's copy differs from the source's:\n%v\nvs\n%v", treeOf(t, to), treeOf(t, from))
	}
	if b, err := os.ReadFile(filepath.Join(to, ".cloop", "artifacts", "3_output.txt")); err != nil || !strings.Contains(string(b), "from the device") {
		t.Errorf("the run output did not reach the target: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(to, ".cloop", "config.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the source's configuration travelled: %v", err)
	}
	if got := strings.Join(other.steps(), ","); got != "move-probe,move-seed,move-verify" {
		t.Errorf("target steps = %s", got)
	}
}

// TestACaptureCarryingAGrantedValueIsRefused: a value the project's runs are
// given never leaves the device in a capture; the move fails at capture,
// before anything switches, naming the grant and not the value.
func TestACaptureCarryingAGrantedValueIsRefused(t *testing.T) {
	t.Setenv("CLOOP_SECRET_KEY", "move-capture-scan-test-passphrase")
	dir, dev, srv, base := deviceSourcedProject(t, "mv-cap-dev4")
	box := newHarnessExec("mv-cap-box2", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, srv, box.id, executor.KindContainer)
	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatal(err)
	}
	value := randomHexValue(t, "acme-deploy-key")
	ctx := context.Background()
	sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: "acme-deploy", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"DEPLOY_KEY":"` + value + `"}`), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: dir}, TTL: time.Hour, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	closeDB()
	// A run wrote the key it was given into the tree.
	moveWrite(t, filepath.Join(dev.workDir(dir), "deploy.env"), "DEPLOY_KEY="+value+"\n")

	code, m, raw := startMoveOver(t, base, `{"target":"mv-cap-box2"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseFailed || m.FailedPhase != projectmove.PhaseCapture {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if !strings.Contains(m.Error, "acme-deploy") || strings.Contains(m.Error, value) {
		t.Errorf("the refusal must name the secret and never its value: %s", m.Error)
	}
	if !strings.Contains(m.Error, "deploy.env") {
		t.Errorf("the refusal does not name the file holding the value: %s", m.Error)
	}
	if strings.Contains(raw, value) {
		t.Error("a response carried the value")
	}
	db, err := srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got, _, _ := db.ProjectExecutor(dir); got != dev.id {
		t.Errorf("binding = %q, want the device still", got)
	}
	if store, err := moveStoreDir(m.ID); err == nil {
		for _, name := range []string{projectmove.CarrierBundle, projectmove.CarrierFiles} {
			if b, err := os.ReadFile(filepath.Join(store, name)); err == nil && bytes.Contains(b, []byte(value)) {
				t.Errorf("the refused capture's %s stayed in the store", name)
			}
		}
	}
	if entries, _ := projectmove.HubDirEntries(dir); len(entries) != 0 {
		t.Errorf("the hub's directory was seeded from a refused capture: %v", entries)
	}
}

// TestACaptureWithAGrantedValueInARemoteURLIsRefused: the manifest's strings
// are scanned too — a seed writes a remote's URL into the target's
// configuration.
func TestACaptureWithAGrantedValueInARemoteURLIsRefused(t *testing.T) {
	t.Setenv("CLOOP_SECRET_KEY", "move-capture-remote-test-passphrase")
	dir, dev, srv, base := deviceSourcedProject(t, "mv-cap-dev5")
	box := newHarnessExec("mv-cap-box5", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, srv, box.id, executor.KindContainer)
	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatal(err)
	}
	value := randomHexValue(t, "acme-forge-token")
	ctx := context.Background()
	sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: "acme-forge", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"FORGE_TOKEN":"` + value + `"}`), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: dev.id}, TTL: time.Hour, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	closeDB()
	moveGit(t, dev.workDir(dir), "remote", "set-url", "origin", "https://git.example.com/"+value+"/devproj.git")

	code, m, raw := startMoveOver(t, base, `{"target":"mv-cap-box5"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseFailed || m.FailedPhase != projectmove.PhaseCapture ||
		!strings.Contains(m.Error, "manifest.remotes[0].url") || strings.Contains(m.Error, value) {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
		t.Error("the hub's directory was seeded from a refused capture")
	}
	// Nothing the device wrote was recorded before it was scanned.
	if b, err := json.Marshal(m); err != nil || bytes.Contains(b, []byte(value)) {
		t.Errorf("the move's record carries the value (%v)", err)
	}
}

// TestAMoveFromAnOldAgentIsRefusedAtPreflight: a device whose agent speaks a
// protocol below the capture's is never asked; the preflight blocks the move,
// naming the upgrade, and nothing is stopped or captured.
func TestAMoveFromAnOldAgentIsRefusedAtPreflight(t *testing.T) {
	dir := setupProjectDir(t, "moving off an old device", nil)
	db := hubWithControlPlane(t, dir)
	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	setProvider(t, dir, "ollama")
	old, err := remote.NewExecutor(remote.Options{ID: "mv-old-agent", Name: "old-edge"})
	if err != nil {
		t.Fatal(err)
	}
	registerMoveExec(t, old)
	recordExecutor(t, db, old.ID(), executor.KindRemoteAgent)
	end := connectAt(t, old, remote.MinProjectCaptureVersion-1, "v0.0.7")
	defer end()
	box := newHarnessExec("mv-old-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, box.id, executor.KindContainer)
	if err := db.BindProjectExecutor(dir, old.ID(), "test"); err != nil {
		t.Fatal(err)
	}
	if err := executor.Bind(dir, old.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	status, rep, raw := preflightOver(t, http.DefaultClient, ts.URL, "target=mv-old-box")
	if status != http.StatusOK {
		t.Fatalf("preflight = HTTP %d: %s", status, raw)
	}
	if !rep.Blocked || !findingOf(rep, projectmove.KindSourceAgent, projectmove.SeverityBlocker, "") {
		t.Fatalf("an old agent must block the move:\n%s", raw)
	}
	for _, f := range rep.Findings {
		if f.Kind == projectmove.KindSourceAgent && (!strings.Contains(strings.ToLower(f.Remedy), "upgrade") ||
			!strings.Contains(f.Message, fmt.Sprintf("v%d", remote.MinProjectCaptureVersion))) {
			t.Errorf("the finding must name the protocol and the upgrade: %+v", f)
		}
	}

	code, m, raw := startMoveOver(t, ts.URL, `{"target":"mv-old-box"}`)
	if code != http.StatusConflict || !strings.Contains(raw, "move_blocked") {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	if m.Phase != projectmove.PhaseFailed || m.FailedPhase != projectmove.PhasePreflight || m.Detail.Capture != nil {
		t.Errorf("move = %s at %s, capture %+v", m.Phase, m.FailedPhase, m.Detail.Capture)
	}
	if store, err := moveStoreDir(m.ID); err == nil {
		if _, err := os.Stat(store); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a refused move wrote a store: %v", err)
		}
	}
	if old.PinnedCaptureBytes() != 0 {
		t.Error("the old agent was asked for a capture")
	}
}

// TestAMoveFromAPoolCapturesTheProjectsVolume: a project bound to an executor
// pool that keeps runner volumes is captured from a runner on the volume
// holding its tenant — the move queues a request the dispatcher hands only to
// such a runner, never to one holding nothing — and the runner is retired.
func TestAMoveFromAPoolCapturesTheProjectsVolume(t *testing.T) {
	// The fresh runner stays put, so the strict assignment below is what
	// keeps the capture off it.
	prevAfter := movePoolNudgeAfter
	movePoolNudgeAfter = time.Hour
	t.Cleanup(func() { movePoolNudgeAfter = prevAfter })
	r := newPoolRig(t)
	hubWithControlPlane(t, r.dir)
	setProvider(t, r.dir, "ollama")
	poolID, token := r.createPool(map[string]any{"name": "k8s-vol", "max_runners": 4})
	r.bind(poolID)
	// The controller reports a volume, so the pool keeps the project's work.
	if st, body := r.call(http.MethodPost, "/api/pool-controller/status", token, map[string]any{
		"healthy": true, "storage": map[string]any{"claims": 1, "bound": 1}}); st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("controller status: %d %v", st, body)
	}
	box := newHarnessExec("mv-pool-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, r.srv, box.id, executor.KindContainer)

	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	db := store.DB()
	tenant := executorpoolTenantFor(t, r.srv, poolID, r.dir)
	member := r.srv.hubInstanceID()
	mint := func(holds, executorID string) {
		t.Helper()
		body := map[string]any{"count": 1}
		if holds != "" {
			body["holds"] = []string{holds}
		}
		st, out := r.call(http.MethodPost, poolRunnersPath, token, body)
		if st != http.StatusCreated {
			t.Fatalf("mint a runner: %d %v", st, out)
		}
		enrollment := out["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
		if _, err := db.MarkExecutorPoolRunnerEnrolled(enrollment, executorID, member, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	// A fresh runner, holding nothing, and the runner on the project's volume.
	mint("", "runner-fresh")
	mint(tenant, "runner-vol")
	runner := newFakeCaptureDevice(t, "runner-vol")
	registerMoveExec(t, runner)
	wc := runner.workDir(r.dir)
	moveGit(t, filepath.Dir(wc), "init", "-q", "-b", "main", wc)
	moveWrite(t, filepath.Join(wc, "kept-on-the-volume.txt"), "from the volume\n")
	moveGit(t, wc, "add", "-A")
	moveGit(t, wc, "commit", "-q", "-m", "work kept on the runner's volume")
	moveWrite(t, filepath.Join(wc, "wip.txt"), "uncommitted on the volume\n")

	code, m, raw := startMoveOver(t, r.ts.URL, `{"target":"mv-pool-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	// The dispatcher's part: the request goes only to the runner holding
	// the project's tenant.
	qid := moveCaptureQueueID(m.ID)
	deadline := time.Now().Add(30 * time.Second)
	for {
		q, err := db.GetPoolQueueEntry(qid)
		if err == nil && q.State == "waiting" {
			if q.Handler != moveCaptureHandler || q.ProjectPath != r.dir {
				t.Fatalf("the request = %+v", q)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the move queued no request for the volume: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The janitor leaves a capture's request alone while its move captures.
	r.srv.settleMoveCaptureEntries(store, time.Now())
	if q, _ := db.GetPoolQueueEntry(qid); q.State != "waiting" {
		t.Fatalf("the janitor took back a capturing move's request: %s", q.State)
	}
	project := statedbProject(tenant)
	if ok, err := db.AssignPoolQueueEntryTo(qid, "runner-fresh", member, time.Now(), project); err != nil || ok {
		t.Fatalf("a runner holding nothing took the capture: %v %v", ok, err)
	}
	if pick := pickCaptureRunner([]string{"", "prj-" + strings.Repeat("0", 32), tenant}, tenant); pick != 2 {
		t.Errorf("pickCaptureRunner = %d, want the runner holding the tenant", pick)
	}
	if ok, err := db.AssignPoolQueueEntryTo(qid, "runner-vol", member, time.Now(), project); err != nil || !ok {
		t.Fatalf("the runner on the volume did not take the capture: %v %v", ok, err)
	}

	m = waitForMove(t, r.srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if c := m.Detail.Capture; !strings.Contains(c.From, "runner runner-vol") || c.Delivery != projectmove.DeliverHubTree {
		t.Errorf("capture from %q, delivery %s", c.From, c.Delivery)
	}
	if b, err := os.ReadFile(filepath.Join(r.dir, "wip.txt")); err != nil || string(b) != "uncommitted on the volume\n" {
		t.Errorf("the volume's uncommitted work did not arrive: %q %v", b, err)
	}
	if rr, _ := store.RunnerByExecutor("runner-vol"); rr.State != "retired" {
		t.Errorf("the runner the move captured from is %s, want retired", rr.State)
	}
	if rr, _ := store.RunnerByExecutor("runner-fresh"); rr.State == "busy" {
		t.Error("the fresh runner was handed the capture")
	}
	if q, _ := db.GetPoolQueueEntry(qid); q.State != "dispatched" {
		t.Errorf("the request ended %s, want dispatched", q.State)
	}
}

// executorpoolTenantFor is the tenant the project at dir has on pool poolID.
func executorpoolTenantFor(t *testing.T, srv *Server, poolID, dir string) string {
	t.Helper()
	store, err := srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	tenant, _, _, ok := executorpool.TenantOf(poolID, dir, srv.poolAccessFor(store))
	if !ok {
		t.Fatal("the hub cannot say whose the project is")
	}
	return tenant
}

// statedbProject is a strict capture assignment for tenant.
func statedbProject(tenant string) statedb.PoolRunnerProject {
	return statedb.PoolRunnerProject{Tenant: tenant, Strict: true}
}

// TestACapturingMoveMakesRoomOnItsPool: a pool keeping an idle runner that
// holds nothing would never start one on the project's volume while that
// runner meets its demand; the waiting capture retires it, so the pool's
// controller replaces it on the volume.
func TestACapturingMoveMakesRoomOnItsPool(t *testing.T) {
	prevAfter, prevEvery := movePoolNudgeAfter, movePoolNudgeEvery
	movePoolNudgeAfter, movePoolNudgeEvery = 0, 50*time.Millisecond
	t.Cleanup(func() { movePoolNudgeAfter, movePoolNudgeEvery = prevAfter, prevEvery })
	r := newPoolRig(t)
	hubWithControlPlane(t, r.dir)
	setProvider(t, r.dir, "ollama")
	poolID, token := r.createPool(map[string]any{"name": "k8s-room", "max_runners": 4})
	r.bind(poolID)
	if st, body := r.call(http.MethodPost, "/api/pool-controller/status", token, map[string]any{
		"healthy": true, "storage": map[string]any{"claims": 1, "bound": 1}}); st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("controller status: %d %v", st, body)
	}
	box := newHarnessExec("mv-room-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, r.srv, box.id, executor.KindContainer)
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	db := store.DB()
	member := r.srv.hubInstanceID()
	st, out := r.call(http.MethodPost, poolRunnersPath, token, map[string]any{"count": 1})
	if st != http.StatusCreated {
		t.Fatalf("mint a runner: %d %v", st, out)
	}
	enrollment := out["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
	if _, err := db.MarkExecutorPoolRunnerEnrolled(enrollment, "runner-idle-fresh", member, time.Now()); err != nil {
		t.Fatal(err)
	}

	code, m, raw := startMoveOver(t, r.ts.URL, `{"target":"mv-room-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if rr, _ := store.RunnerByExecutor("runner-idle-fresh"); rr.State == statedb.PoolRunnerRetired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the idle runner holding nothing was never retired to make room")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The controller's replacement, on the project's volume, takes it.
	tenant := executorpoolTenantFor(t, r.srv, poolID, r.dir)
	st, out = r.call(http.MethodPost, poolRunnersPath, token, map[string]any{"count": 1, "holds": []string{tenant}})
	if st != http.StatusCreated {
		t.Fatalf("mint the replacement: %d %v", st, out)
	}
	enrollment = out["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
	if _, err := db.MarkExecutorPoolRunnerEnrolled(enrollment, "runner-on-volume", member, time.Now()); err != nil {
		t.Fatal(err)
	}
	runner := newFakeCaptureDevice(t, "runner-on-volume")
	registerMoveExec(t, runner)
	if ok, err := db.AssignPoolQueueEntryTo(moveCaptureQueueID(m.ID), "runner-on-volume", member, time.Now(), statedbProject(tenant)); err != nil || !ok {
		t.Fatalf("the replacement did not take the capture: %v %v", ok, err)
	}
	m = waitForMove(t, r.srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	// The volume held no working copy: nothing was carried, and nothing lost.
	if c := m.Detail.Capture; c.Git.Repository || len(c.Files) != 0 {
		t.Errorf("an empty volume's capture = %+v", c)
	}
}

// busyCapturer answers busy a number of times, then captures.
type busyCapturer struct {
	busy  int
	asked int
}

func (b *busyCapturer) CaptureVersion() (int, bool) { return remote.ProtocolVersion, true }

func (b *busyCapturer) captureWorkingCopy(context.Context, remote.CaptureRequest) (captureAnswer, error) {
	b.asked++
	if b.asked <= b.busy {
		return nil, fmt.Errorf("%w: another move's capture", remote.ErrCaptureBusy)
	}
	return &memAnswer{parts: map[string][]byte{}}, nil
}

// TestACaptureWaitsForABusyDevice: an agent captures one working copy at a
// time, so a second move's capture asks again rather than failing.
func TestACaptureWaitsForABusyDevice(t *testing.T) {
	prevWait, prevPoll := moveCaptureBusyWait, moveCaptureBusyPoll
	moveCaptureBusyWait, moveCaptureBusyPoll = time.Minute, time.Millisecond
	t.Cleanup(func() { moveCaptureBusyWait, moveCaptureBusyPoll = prevWait, prevPoll })
	b := &busyCapturer{busy: 3}
	if _, err := captureWhenFree(context.Background(), b, remote.CaptureRequest{}); err != nil || b.asked != 4 {
		t.Fatalf("err = %v after %d asks, want a capture on the fourth", err, b.asked)
	}
	moveCaptureBusyWait = 0
	b = &busyCapturer{busy: 100}
	if _, err := captureWhenFree(context.Background(), b, remote.CaptureRequest{}); !errors.Is(err, remote.ErrCaptureBusy) {
		t.Fatalf("past the wait: err = %v, want busy", err)
	}
}

// TestACaptureTrackingTheHubsFilesIsRefused: a working copy whose repository
// tracks a file of .cloop the hub keeps for itself — its database, its
// configuration — is refused at capture: restored in the hub's directory it
// would write over the hub's own. The specs a project commits by design
// travel.
func TestACaptureTrackingTheHubsFilesIsRefused(t *testing.T) {
	dir, dev, srv, base := deviceSourcedProject(t, "mv-cap-dev6")
	box := newHarnessExec("mv-cap-box6", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, srv, box.id, executor.KindContainer)
	wc := dev.workDir(dir)
	moveWrite(t, filepath.Join(wc, ".cloop", "requirements.yaml"), "requirements: []\n")
	moveGit(t, wc, "add", "-f", ".cloop/config.yaml", ".cloop/requirements.yaml")
	moveGit(t, wc, "commit", "-q", "-m", "track the configuration")
	hubConfig, err := os.ReadFile(filepath.Join(dir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	code, m, raw := startMoveOver(t, base, `{"target":"mv-cap-box6"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseFailed || m.FailedPhase != projectmove.PhaseCapture ||
		!strings.Contains(m.Error, ".cloop/config.yaml") || !strings.Contains(m.Error, "git rm --cached") {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".cloop", "config.yaml")); !bytes.Equal(b, hubConfig) {
		t.Error("the hub's configuration was written over")
	}
	if store, err := moveStoreDir(m.ID); err == nil {
		for _, name := range []string{projectmove.CarrierBundle, projectmove.CarrierFiles} {
			if _, err := os.Stat(filepath.Join(store, name)); err == nil {
				t.Errorf("the refused capture's %s stayed in the store", name)
			}
		}
	}

	// Untracked again, the requirements spec still committed: it moves.
	moveGit(t, wc, "rm", "-q", "--cached", ".cloop/config.yaml")
	moveGit(t, wc, "commit", "-q", "-m", "untrack the configuration")
	code, m, raw = startMoveOver(t, base, `{"target":"mv-cap-box6"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	if b, err := os.ReadFile(filepath.Join(dir, ".cloop", "requirements.yaml")); err != nil || string(b) != "requirements: []\n" {
		t.Errorf("the committed requirements spec: %q %v", b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".cloop", "config.yaml")); !bytes.Equal(b, hubConfig) {
		t.Error("the hub's configuration was written over")
	}
}

// TestALapsedGrantsValueIsStillScannedFor: a grant revoked since the runs it
// served still has its value looked for — a run may have left it in the tree.
func TestALapsedGrantsValueIsStillScannedFor(t *testing.T) {
	t.Setenv("CLOOP_SECRET_KEY", "move-capture-lapsed-test-passphrase")
	dir, dev, srv, base := deviceSourcedProject(t, "mv-cap-dev7")
	box := newHarnessExec("mv-cap-box7", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordOn(t, srv, box.id, executor.KindContainer)
	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatal(err)
	}
	value := randomHexValue(t, "acme-old-key")
	ctx := context.Background()
	sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: "acme-old", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"OLD_KEY":"` + value + `"}`), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: dir}, TTL: time.Hour, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Revoke(ctx, g.ID, "test"); err != nil {
		t.Fatal(err)
	}
	closeDB()
	moveWrite(t, filepath.Join(dev.workDir(dir), "old.env"), "OLD_KEY="+value+"\n")

	code, m, raw := startMoveOver(t, base, `{"target":"mv-cap-box7"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	m = waitForMove(t, srv, m.ID)
	if m.Phase != projectmove.PhaseFailed || m.FailedPhase != projectmove.PhaseCapture ||
		!strings.Contains(m.Error, "acme-old") || strings.Contains(m.Error, value) {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
}

// TestCaptureRequestsOfEndedMovesAreTakenBack: a capture cut short — the hub
// stopped part-way — leaves its request in the pool's queue; the janitor takes
// it back, and retires the runner it was handed, once the move is no longer
// capturing.
func TestCaptureRequestsOfEndedMovesAreTakenBack(t *testing.T) {
	r := newPoolRig(t)
	hubWithControlPlane(t, r.dir)
	poolID, token := r.createPool(map[string]any{"name": "k8s-janitor", "max_runners": 4})
	r.bind(poolID)
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	db := store.DB()
	member := r.srv.hubInstanceID()
	tenant := executorpoolTenantFor(t, r.srv, poolID, r.dir)
	st, out := r.call(http.MethodPost, poolRunnersPath, token, map[string]any{"count": 1, "holds": []string{tenant}})
	if st != http.StatusCreated {
		t.Fatalf("mint a runner: %d %v", st, out)
	}
	enrollment := out["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
	if _, err := db.MarkExecutorPoolRunnerEnrolled(enrollment, "runner-left", member, time.Now()); err != nil {
		t.Fatal(err)
	}
	q := statedb.PoolQueueRow{ID: moveCaptureQueueID("mv-gone"), PoolID: poolID, ProjectPath: r.dir,
		Handler: moveCaptureHandler, Reason: "waiting", Member: member}
	if err := db.EnqueuePoolRun(q); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.AssignPoolQueueEntryTo(q.ID, "runner-left", member, time.Now(), statedbProject(tenant)); err != nil || !ok {
		t.Fatalf("assign: %v %v", ok, err)
	}
	r.srv.settleMoveCaptureEntries(store, time.Now())
	if got, _ := db.GetPoolQueueEntry(q.ID); got.State != statedb.PoolQueueCancelled {
		t.Errorf("the request of a move that is gone is %s, want cancelled", got.State)
	}
	if rr, _ := store.RunnerByExecutor("runner-left"); rr.State != statedb.PoolRunnerRetired {
		t.Errorf("the runner it was handed is %s, want retired", rr.State)
	}
}

func TestForgeDeliveryCountsFeaturesWorkNoRemoteHas(t *testing.T) {
	m := movegit.Manifest{Repository: true, MoveID: "mv1", Carried: []movegit.Ref{
		{Name: "refs/cloop/move-feature/mv1/0/heads/feature-x"},
		{Name: "refs/cloop/move-feature/mv1/0/heads/pushed-y", Pushed: true},
		{Name: "refs/cloop/move-feature/mv1/0/tags/v1"},
		{Name: "refs/cloop/move-feature/mv1/1/stash/0"},
	}}
	err := forgeHoldsEverything(m)
	if err == nil || !strings.Contains(err.Error(), "feature-x") || strings.Contains(err.Error(), "pushed-y") ||
		!strings.Contains(err.Error(), "stashes hold 1") {
		t.Fatalf("forgeHoldsEverything = %v", err)
	}
	m.Carried = m.Carried[1:3]
	if err := forgeHoldsEverything(m); err != nil {
		t.Errorf("pushed branches and tags: %v", err)
	}
}

func TestDocumentCarriesLooksEverywhereAndNamesNoValue(t *testing.T) {
	const value = "corp-internal-api-key-7f3a9c2e1b"
	scan := gitproxy.PushScan{Mode: gitproxy.ScanValues, Secrets: []gitproxy.ScanSecret{{Value: value, Grant: "g1"}}}
	for name, doc := range map[string]movecapture.Document{
		"a note":           {Notes: []string{"see " + value}},
		"an excluded path": {Excluded: []string{"x/" + value}},
		"a branch":         {Manifest: &movegit.Manifest{Branches: []movegit.Ref{{Name: "refs/heads/" + value}}}},
		"a kept example":   {Kept: []projectmove.Item{{Examples: []string{value}}}},
		"an inventory key": {Inspection: &movecapture.Inspection{FeatureFiles: map[string]projectmove.FileInventory{value: {}}}},
	} {
		where, found := documentCarries(doc, scan)
		if !found || strings.Contains(where, value) || where == "" {
			t.Errorf("%s: found %v at %q", name, found, where)
		}
	}
	if _, found := documentCarries(movecapture.Document{Notes: []string{"nothing here"}, WorkDir: "/w"}, scan); found {
		t.Error("a clean document")
	}
}
