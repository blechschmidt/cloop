package ui

// Task 20517: a helper dispatched to a device while a run of its project works
// in the project's directory there must not prepare that directory over the
// run. On sgx-rust-attestation the Requirements tab's spec file read did, the
// run took the tasks added on the hub since it started for its own, and the
// hub merged them back as duplicates.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// deviceStub is a remote agent as the hub sees one: a tree of its own, sent
// the project as a seed, every start recorded. A helper prints a framed reply
// and exits; a run goes on until the test ends it.
type deviceStub struct {
	id string

	mu    sync.Mutex
	specs map[string]executor.Spec
	order []string
	live  map[string]bool
}

func newDeviceStub(id string) *deviceStub {
	return &deviceStub{id: id, specs: map[string]executor.Spec{}, live: map[string]bool{}}
}

// hold makes handleID a run working on the device.
func (d *deviceStub) hold(handleID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.live[handleID] = true
}

// end makes handleID's run over.
func (d *deviceStub) end(handleID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.live[handleID] = false
}

func (d *deviceStub) ID() string   { return d.id }
func (d *deviceStub) Kind() string { return executor.KindRemoteAgent }
func (d *deviceStub) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote, SupportsProjectSeed: true,
		ReturnsProjectState: true, SupportsWorkspaceProvisioning: true}
}
func (d *deviceStub) HealthCheck(context.Context) error { return nil }
func (d *deviceStub) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := fmt.Sprintf("%s-%d", d.id, len(d.order)+1)
	d.specs[id] = spec
	d.order = append(d.order, id)
	d.live[id] = spec.Labels[executor.LabelWorkload] == executor.WorkloadRun
	return executor.Handle{ID: id, ExecutorID: d.id, StartedAt: time.Now()}, nil
}
func (d *deviceStub) Stream(_ context.Context, id string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine, 1)
	ch <- executor.LogLine{Text: `{"ok":true}` + "\n"}
	close(ch)
	return ch, nil
}
func (d *deviceStub) Status(_ context.Context, id string) (executor.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	live, known := d.live[id]
	switch {
	case !known:
		return executor.Status{}, executor.ErrHandleNotFound
	case live:
		return executor.Status{HandleID: id, ExecutorID: d.id, State: executor.StateRunning}, nil
	}
	return executor.Status{HandleID: id, ExecutorID: d.id, State: executor.StateExited}, nil
}
func (d *deviceStub) Signal(context.Context, string, executor.Signal) error { return nil }

// starts counts the workloads started.
func (d *deviceStub) starts() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.order)
}

// last is the spec of the latest start.
func (d *deviceStub) last(t *testing.T) executor.Spec {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.order) == 0 {
		t.Fatal("nothing was started on the device")
	}
	return d.specs[d.order[len(d.order)-1]]
}

// virtualStub is a virtual executor on a device: its own ID, its parent's
// directory.
type virtualStub struct {
	*deviceStub
	parent string
}

func (v virtualStub) Kind() string     { return executor.KindVirtual }
func (v virtualStub) ParentID() string { return v.parent }

// helperOn dispatches the Requirements tab's spec file read for dir, as
// handleRequirementSpecRead does, and returns what the device was sent.
func helperOn(t *testing.T, dev *deviceStub, dir string) executor.Spec {
	t.Helper()
	if _, err := runCloopSubcommandFor(context.Background(), "/usr/local/bin/cloop", dir, time.Minute, nil, nil,
		"requirements", "validate", "--json"); err != nil {
		t.Fatalf("dispatch the helper: %v", err)
	}
	return dev.last(t)
}

func TestAHelperBesideARunInItsDirectoryGoesWithoutTheProject(t *testing.T) {
	withControlPlaneDir(t, "")
	dir := setupProjectDir(t, "shared tree", []*pm.Task{
		{ID: 1, Title: "Build the enclave", Status: pm.TaskPending},
		{ID: 2, Title: "Push it", Status: pm.TaskPending},
	})
	dev := newDeviceStub("edge-shared-tree")
	registerStub(t, dev)
	if err := executor.Bind(dir, dev.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	// Nothing runs: a helper is sent the project and prepares the directory,
	// as before.
	spec := helperOn(t, dev, dir)
	if spec.Labels[executor.LabelWorkload] != executor.WorkloadHelper {
		t.Errorf("a helper was labelled %q, want %q", spec.Labels[executor.LabelWorkload], executor.WorkloadHelper)
	}
	if len(spec.ProjectSeed) == 0 || spec.Workspace.Kind != executor.WorkspaceExecutor {
		t.Fatalf("with no run, a helper went with seed %d bytes and workspace %q; it needs the project",
			len(spec.ProjectSeed), spec.Workspace.Kind)
	}

	// A run is dispatched the way every run is, which records it.
	_, run, err := startWorkload(dir, []string{"/usr/local/bin/cloop", "run", "--pm"}, nil)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	t.Cleanup(func() { takeSeededDispatch(dev, run.ID) })
	runSpec := dev.last(t)
	if runSpec.Labels[executor.LabelWorkload] != executor.WorkloadRun {
		t.Errorf("the run was labelled %q, want %q", runSpec.Labels[executor.LabelWorkload], executor.WorkloadRun)
	}
	if len(runSpec.ProjectSeed) == 0 {
		t.Fatal("the run went without the project")
	}

	// A Split preview of a task the run was sent as it is may be made on the
	// run's copy; one of a task added since, or changed, may not.
	if why := runCopyDiffers(dir, &pm.Task{ID: 1, Title: "Build the enclave"}, "the Split preview"); why != "" {
		t.Errorf("a task the run has as the hub does was refused: %s", why)
	}
	if why := runCopyDiffers(dir, &pm.Task{ID: 3, Title: "Added while the run works"}, "the Split preview"); !strings.Contains(why, "added or changed after the run started") {
		t.Errorf("a task added after the run started = %q, want it refused", why)
	}
	if why := runCopyDiffers(dir, &pm.Task{ID: 2, Title: "Push it", Description: "edited"}, "the Split preview"); why == "" {
		t.Error("a task changed after the run started was let through")
	}

	// While it works, a helper goes without the project: the device runs it
	// in the run's directory as the run has it.
	spec = helperOn(t, dev, dir)
	if len(spec.ProjectSeed) != 0 || spec.SeedStartable != nil || spec.HumanGates {
		t.Errorf("beside the run a helper still carried the project (%d bytes), which the device "+
			"places over the run's database", len(spec.ProjectSeed))
	}
	if spec.Workspace.Kind != executor.WorkspaceExecutor || spec.Workspace.NeedsProvisioning() {
		t.Errorf("beside the run a helper's workspace is %+v, want the device's own, fetched by nobody", spec.Workspace)
	}
	if spec.WorkDir != runSpec.WorkDir || spec.WorkDir != executor.DeviceWorkDir(dir) {
		t.Errorf("the helper runs in %q, the run in %q", spec.WorkDir, runSpec.WorkDir)
	}

	// Through a virtual executor on the same device: the same directory.
	vx := virtualStub{deviceStub: newDeviceStub("edge-shared-tree-vx"), parent: dev.ID()}
	registerStub(t, vx)
	shared, handle := shareRunTree(runSpec, vx, dir)
	if handle != run.ID || len(shared.ProjectSeed) != 0 {
		t.Errorf("a virtual executor of the run's device shares its directory: got handle %q, seed %d bytes",
			handle, len(shared.ProjectSeed))
	}

	// Another project on the device, another device, a tree of its own: all
	// prepared as before.
	other := setupProjectDir(t, "another project", []*pm.Task{{ID: 1, Title: "x", Status: pm.TaskPending}})
	if _, h := shareRunTree(runSpec, dev, other); h != "" {
		t.Errorf("a helper for another project shares run %s's directory", h)
	}
	elsewhere := newDeviceStub("edge-elsewhere")
	registerStub(t, elsewhere)
	if _, h := shareRunTree(runSpec, elsewhere, dir); h != "" {
		t.Errorf("a helper on another device shares run %s's directory", h)
	}
	box := newHarnessExec("box-shared-tree", executor.KindContainer, executor.IsolationContainer)
	if _, h := shareRunTree(runSpec, box, dir); h != "" {
		t.Errorf("a container, whose run has a tree of its own, shares run %s's", h)
	}

	// The run's workload ends before the hub settles it: its directory is
	// free, and a helper is sent the project again.
	dev.end(run.ID)
	if spec = helperOn(t, dev, dir); len(spec.ProjectSeed) == 0 {
		t.Error("after the run's workload ended a helper went without the project")
	}
	// And a record whose workload the device does not know is no run.
	dev.hold(run.ID)
	rememberSeededRun(dev, "h-lost-sight", dir, projectseed.Provenance{ExecutorID: dev.ID()}, nil)
	t.Cleanup(func() { takeSeededDispatch(dev, "h-lost-sight") })
	takeSeededDispatch(dev, run.ID)
	if spec = helperOn(t, dev, dir); len(spec.ProjectSeed) == 0 {
		t.Error("a record of a workload the device does not know kept a helper from the project")
	}
}

// TestAHelperBesideARunGoesWithoutABranchToBuild: a feature's run on a
// device is shipped its branch, which the device builds into the feature's
// directory; a helper for the feature beside the run must not rebuild it.
func TestAHelperBesideARunGoesWithoutABranchToBuild(t *testing.T) {
	dev := newDeviceStub("edge-shared-branch")
	registerStub(t, dev)
	dir := t.TempDir()
	dev.hold("h-feature-run")
	rememberSeededRun(dev, "h-feature-run", dir, projectseed.Provenance{ExecutorID: dev.ID()}, nil)
	t.Cleanup(func() { takeSeededDispatch(dev, "h-feature-run") })

	spec := executor.Spec{
		WorkDir:          executor.DeviceWorkDir(dir),
		Argv:             []string{"cloop", "task", "decompose", "3", "--dry-run", "--json"},
		ProjectSeed:      []byte("seed"),
		BranchBundleFile: "/tmp/feature.bundle",
		Workspace: executor.Workspace{Kind: executor.WorkspaceBundle, SizeLimitMB: 512,
			Branch: &executor.BranchBundle{Branch: "cloop/feature/x", Head: strings.Repeat("a", 40), Bytes: 10}},
	}
	got, handle := shareRunTree(spec, dev, dir)
	if handle != "h-feature-run" {
		t.Fatalf("shareRunTree found run %q", handle)
	}
	if got.BranchBundleFile != "" || got.Workspace.Branch != nil || len(got.ProjectSeed) != 0 {
		t.Errorf("beside the feature's run the helper still builds its branch: %+v", got.Workspace)
	}
	if got.Workspace.SizeLimitMB != 512 {
		t.Errorf("the disk bound went from 512 to %d", got.Workspace.SizeLimitMB)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("the shared spec does not validate: %v", err)
	}
}

func TestAReproductionIsRefusedBesideARun(t *testing.T) {
	dev := newDeviceStub("edge-shared-repro")
	registerStub(t, dev)
	dir := t.TempDir()
	if err := refuseBesideRun(dev, dir, "a reproduction"); err != nil {
		t.Fatalf("with no run: %v", err)
	}
	dev.hold("h-repro-run")
	rememberSeededRun(dev, "h-repro-run", dir, projectseed.Provenance{ExecutorID: dev.ID()}, nil)
	t.Cleanup(func() { takeSeededDispatch(dev, "h-repro-run") })
	err := refuseBesideRun(dev, dir, "a reproduction")
	if !errors.Is(err, errRunInTree) || !strings.Contains(err.Error(), dev.ID()) {
		t.Fatalf("beside a run = %v, want errRunInTree naming the executor", err)
	}
}

// TestAModelCallOnATaskTheRunsCopyLacksSaysWhy: a model call that ran in a
// run's directory reads the run's copy of the project, which has no task
// added on the hub after the run started. Its "task not found" is said as
// what it is.
func TestAModelCallOnATaskTheRunsCopyLacksSaysWhy(t *testing.T) {
	out := []byte(framed(t, map[string]any{"error": fmt.Sprintf("task 25 not found: %v", statedb.ErrTaskNotFound)}))
	ended := &workloadEndedError{err: errors.New("exit status 1")}

	w := httptest.NewRecorder()
	if readModelCall(w, out, &runTreeSharedError{err: ended, executor: "sgx"}, "Split failed: ", &struct{}{}) {
		t.Fatal("readModelCall took a failure for a result")
	}
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "added after the run started") ||
		!strings.Contains(w.Body.String(), "sgx") {
		t.Errorf("in a run's directory = %d %s, want 409 saying the run's copy lacks the task", w.Code, w.Body)
	}

	// Anywhere else, or any other failure, as it came.
	w = httptest.NewRecorder()
	readModelCall(w, out, ended, "Split failed: ", &struct{}{})
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "run started") {
		t.Errorf("outside a run's directory = %d %s, want the device's own 502", w.Code, w.Body)
	}
	other := []byte(framed(t, map[string]any{"error": "the model timed out"}))
	w = httptest.NewRecorder()
	readModelCall(w, other, &runTreeSharedError{err: ended, executor: "sgx"}, "", &struct{}{})
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "the model timed out") {
		t.Errorf("another failure in a run's directory = %d %s, want it as it came", w.Code, w.Body)
	}
}

// TestAHelperBesideARunFetchesNothing: whatever the project's workspace —
// a checkout fetched from its forge, the working copy a move placed, the
// device's own directory — a helper beside a run asks the device to fetch
// nothing into the run's tree. An agent older than the rule prepares nothing
// for the device's own directory but the seed, which is gone.
func TestAHelperBesideARunFetchesNothing(t *testing.T) {
	dev := newDeviceStub("edge-shared-kinds")
	registerStub(t, dev)
	dir := t.TempDir()
	dev.hold("h-kinds")
	rememberSeededRun(dev, "h-kinds", dir, projectseed.Provenance{ExecutorID: dev.ID()}, nil)
	t.Cleanup(func() { takeSeededDispatch(dev, "h-kinds") })

	for name, ws := range map[string]executor.Workspace{
		"git":       {Kind: executor.WorkspaceGit, Repo: "https://github.com/bb-selforg/cloop-hello-world.git", Ref: "main", CredentialGrant: "grant_x"},
		"moved":     {Kind: executor.WorkspaceGit, Repo: "https://github.com/bb-selforg/cloop-hello-world.git", Keep: true},
		"executor":  {Kind: executor.WorkspaceExecutor},
		"unlimited": {Kind: executor.WorkspaceGit, Repo: "https://example.com/a.git", SizeLimitMB: 64},
	} {
		spec := executor.Spec{WorkDir: executor.DeviceWorkDir(dir), Argv: []string{"cloop", "suggest", "--json"},
			ProjectSeed: []byte("seed"), Workspace: ws}
		got, handle := shareRunTree(spec, dev, dir)
		if handle != "h-kinds" {
			t.Fatalf("%s: shareRunTree found run %q", name, handle)
		}
		if got.Workspace.NeedsProvisioning() || got.Workspace.Kind != executor.WorkspaceExecutor ||
			got.Workspace.CredentialGrant != "" || got.Workspace.Repo != "" {
			t.Errorf("%s: beside the run the helper's workspace is %+v, which the device prepares", name, got.Workspace)
		}
		if got.Workspace.SizeLimitMB != ws.SizeLimitMB {
			t.Errorf("%s: the disk bound went from %d to %d", name, ws.SizeLimitMB, got.Workspace.SizeLimitMB)
		}
		if len(got.ProjectSeed) != 0 {
			t.Errorf("%s: the helper still carries the project", name)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("%s: the shared spec does not validate: %v", name, err)
		}
	}
}

// TestAModelCallBesideAnAdoptedRunIsRefused: a run this process adopted after
// a restart came with no record of its seed, so nothing tells the hub which
// task the run's copy holds under an ID; a Split preview there is refused.
// With no run in the directory, nothing is refused.
func TestAModelCallBesideAnAdoptedRunIsRefused(t *testing.T) {
	withControlPlaneDir(t, "")
	dir := setupProjectDir(t, "adopted run", []*pm.Task{{ID: 1, Title: "Build the enclave", Status: pm.TaskPending}})
	dev := newDeviceStub("edge-shared-adopted")
	registerStub(t, dev)
	if err := executor.Bind(dir, dev.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	task := &pm.Task{ID: 1, Title: "Build the enclave"}

	if why := runCopyDiffers(dir, task, "the Split preview"); why != "" {
		t.Fatalf("with no run: %s", why)
	}
	dev.hold("h-adopted")
	rememberSeededRun(dev, "h-adopted", dir, projectseed.Provenance{ExecutorID: dev.ID()}, nil)
	t.Cleanup(func() { takeSeededDispatch(dev, "h-adopted") })
	if why := runCopyDiffers(dir, task, "the Split preview"); !strings.Contains(why, "cannot check") {
		t.Fatalf("beside an adopted run = %q, want refused for want of the seed's record", why)
	}
	dev.end("h-adopted")
	if why := runCopyDiffers(dir, task, "the Split preview"); why != "" {
		t.Fatalf("once the run's workload ended: %s", why)
	}
}

// TestAHelperBesideARunIsSharedBeforeItsWorkspaceIsBuilt: the decision is made
// on the spec as the dispatch has it before applyWorkspace — the hub's path —
// so a feature's branch is never shipped for a helper that will not use it,
// and the helper lands in the device's directory for the project all the same.
func TestAHelperBesideARunIsSharedBeforeItsWorkspaceIsBuilt(t *testing.T) {
	dev := newDeviceStub("edge-shared-early")
	registerStub(t, dev)
	dir := t.TempDir()
	dev.hold("h-early")
	rememberSeededRun(dev, "h-early", dir, projectseed.Provenance{ExecutorID: dev.ID()}, nil)
	t.Cleanup(func() { takeSeededDispatch(dev, "h-early") })

	spec := uiSpec(dir, []string{"cloop", "requirements", "validate", "--json"}, nil)
	spec.Workspace.SizeLimitMB = 128 // as applySandbox leaves it, from sandbox.yaml
	got, handle := shareRunTree(spec, dev, dir)
	if handle != "h-early" {
		t.Fatalf("shareRunTree found run %q", handle)
	}
	if got.WorkDir != executor.DeviceWorkDir(dir) {
		t.Errorf("the helper runs in %q, want the device's %q", got.WorkDir, executor.DeviceWorkDir(dir))
	}
	if got.Workspace.Kind != executor.WorkspaceExecutor || got.Workspace.SizeLimitMB != 128 {
		t.Errorf("workspace = %+v", got.Workspace)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("the shared spec does not validate: %v", err)
	}
	if err := executor.CheckSandboxSupport(dev, got.SandboxRequirements(), dir); err != nil {
		t.Errorf("the device cannot take the shared spec: %v", err)
	}
}

// TestSplitAndBlockerBesideARunRefuseATaskTheRunsCopyLacks drives the two
// routes: a task added on the hub while a device runs is refused with 409 and
// the reason, before anything is dispatched; a task the run was sent as it is
// goes on to the dispatch (and here to the harness preflight, which this
// fixture does not satisfy).
func TestSplitAndBlockerBesideARunRefuseATaskTheRunsCopyLacks(t *testing.T) {
	withControlPlaneDir(t, "")
	dir := setupProjectDir(t, "split beside a run", []*pm.Task{
		{ID: 1, Title: "Build the enclave", Status: pm.TaskPending},
	})
	dev := newDeviceStub("edge-shared-split")
	registerStub(t, dev)
	if err := executor.Bind(dir, dev.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	_, run, err := startWorkload(dir, []string{"/usr/local/bin/cloop", "run", "--pm"}, nil)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	t.Cleanup(func() { takeSeededDispatch(dev, run.ID) })
	started := dev.starts()

	// Task 2 is added on the hub while the device works on the plan it was sent.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, &pm.Task{ID: 2, Title: "Add a GitHub Action", Status: pm.TaskPending})
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	ts := newTestServerFor(t, New(dir, 0, ""))
	for _, path := range []string{"/api/tasks/2/decompose", "/api/tasks/2/blocker"} {
		code, body := rawJSON(t, ts, http.MethodPost, path, map[string]any{})
		if code != http.StatusConflict || !strings.Contains(fmt.Sprint(body["error"]), "added or changed after the run started") {
			t.Errorf("%s for a task added while the run works = %d %v, want 409 with the reason", path, code, body)
		}
	}
	if n := dev.starts(); n != started {
		t.Errorf("a refused call started %d workload(s) on the device", n-started)
	}
	// Task 1 is in the run's copy as it is here: not refused for that.
	code, body := rawJSON(t, ts, http.MethodPost, "/api/tasks/1/decompose", map[string]any{})
	if strings.Contains(fmt.Sprint(body["error"]), "after the run started") {
		t.Errorf("a task the run has as the hub does = %d %v", code, body)
	}
}
