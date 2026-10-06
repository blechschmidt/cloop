package orchestrator

// Adopting a newer build at a task boundary (Task 20389), with the system
// replaced: the binary is a stand-in ELF file, the probe answers what each test
// scripts, and the exec is a recorder that says what the run looked like at the
// moment it would have replaced itself, then fails — which is also the path
// every refusal takes: the run carries on on its own build. The real exec, with
// real binaries and a real hub, is tests/e2e/buildadopt_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hooks"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// adoptSelf is the process the tests' runs believe they are.
var adoptSelf = runbuild.Ident{PID: 4242, StartTicks: 777, BootID: "boot-adopt"}

// adoptOwnBuild is the build the tests' runs believe they run.
var adoptOwnBuild = runbuild.Build{Version: "dev+gaaaaaaa", Sequence: 100}

// fakeELF writes a file runbuild.Open accepts: executable, ELF magic, owned by
// this user, not group-writable. Nothing ever runs it.
func fakeELF(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cloop")
	data := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 60)...)
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// execCall is what the run looked like when it would have replaced itself.
type execCall struct {
	argv         []string
	handoff      runbuild.Handoff
	handoffErr   error
	storesClosed bool
	tasks        map[int]pm.TaskStatus
}

// adoptRig scripts the system adoption asks.
type adoptRig struct {
	t        *testing.T
	dir      string
	binary   string
	mu       sync.Mutex
	probed   int
	report   runbuild.Build
	probeErr error
	kids     []runbuild.Child
	argsErr  error
	argsSeen []string
	execs    []execCall
	execErr  error
	o        *Orchestrator
}

func newAdoptRig(t *testing.T, dir string) *adoptRig {
	return &adoptRig{t: t, dir: dir, binary: fakeELF(t),
		report:  runbuild.Build{Version: "dev+gbbbbbbb", Sequence: 101, Schema: latestSchema(t)},
		execErr: errors.New("exec format error (test)")}
}

func latestSchema(t *testing.T) int {
	t.Helper()
	n, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// install puts the rig's hooks on o.
func (r *adoptRig) install(o *Orchestrator) {
	r.o = o
	o.selfBuild = adoptOwnBuild
	o.selfBuild.Schema = latestSchema(r.t)
	o.adopt = adoptHooks{
		self:      func() (runbuild.Ident, error) { return adoptSelf, nil },
		startPath: func() (string, error) { return r.binary, nil },
		open:      runbuild.Open,
		probe: func(ctx context.Context, c *runbuild.Candidate) (runbuild.Build, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.probed++
			return r.report, r.probeErr
		},
		children: func() ([]runbuild.Child, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.kids, nil
		},
		checkArgs: func(ctx context.Context, c *runbuild.Candidate, args []string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.argsSeen = args
			return r.argsErr
		},
		exec:      r.exec,
		childWait: 50 * time.Millisecond,
	}
}

func (r *adoptRig) exec(c *runbuild.Candidate, argv, env []string) error {
	call := execCall{argv: argv, storesClosed: r.o.statedb == nil && r.o.queue == nil, tasks: map[int]pm.TaskStatus{}}
	for _, kv := range env {
		if path, ok := strings.CutPrefix(kv, runbuild.EnvHandoff+"="); ok {
			data, err := os.ReadFile(path)
			if err == nil {
				err = json.Unmarshal(data, &call.handoff)
			}
			call.handoffErr = err
		}
	}
	if s, err := state.Load(r.dir); err == nil && s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			call.tasks[t.ID] = t.Status
		}
	}
	r.mu.Lock()
	r.execs = append(r.execs, call)
	r.mu.Unlock()
	return r.execErr
}

func (r *adoptRig) execCalls() []execCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]execCall(nil), r.execs...)
}

func requestAdoption(t *testing.T, dir, id string, run runbuild.Ident) {
	t.Helper()
	if err := state.RequestAdoption(dir, &runbuild.Request{ID: id, RequestedAt: time.Now(),
		RequestedBy: "alice@example.com", Run: run}); err != nil {
		t.Fatal(err)
	}
}

// adoptProvider answers each task by title and lets a test act while a task
// is in flight.
type adoptProvider struct {
	mu      sync.Mutex
	calls   []string
	during  map[string]func()
	release map[string]chan struct{}
}

func (p *adoptProvider) Complete(ctx context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	// The task being executed, not the finished ones the prompt lists too.
	title := ""
	if _, cur, ok := strings.Cut(prompt, "## CURRENT TASK"); ok {
		for _, cand := range []string{"Task one", "Task two", "Task three"} {
			if strings.Contains(cur, ": "+cand+"**") {
				title = cand
				break
			}
		}
	}
	p.mu.Lock()
	p.calls = append(p.calls, title)
	fn := p.during[title]
	ch := p.release[title]
	p.mu.Unlock()
	if fn != nil {
		fn()
	}
	if ch != nil {
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(30 * time.Second):
			return nil, errors.New("never released")
		}
	}
	return &provider.Result{Output: "did " + title + "\nTASK_DONE", Provider: "mock"}, nil
}
func (p *adoptProvider) Name() string         { return "mock" }
func (p *adoptProvider) DefaultModel() string { return "mock-model" }

func adoptProject(t *testing.T, tasks ...*pm.Task) string {
	t.Helper()
	dir := tempDir(t)
	s := initState(t, dir, "adopt goal", 0)
	s.Plan = &pm.Plan{Goal: "adopt goal", Tasks: tasks}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func twoTasks() []*pm.Task {
	return []*pm.Task{
		{ID: 1, Title: "Task one", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "Task two", Priority: 2, Status: pm.TaskPending},
	}
}

func adoptionRows(t *testing.T, dir string) []state.EventRow {
	return eventsOf(t, dir, state.EventRunAdoption)
}

// A request filed while task 1 runs waits for the boundary: the run hands
// over after task 1 is stored done and before task 2 starts, with its stores
// closed and a handoff that carries the run. The exec then fails here, which
// the run journals and survives: task 2 runs on the old build.
func TestAdopt_RequestMidTaskWaitsForTheBoundary(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	rig := newAdoptRig(t, dir)
	prov := &adoptProvider{during: map[string]func(){
		"Task one": func() { requestAdoption(t, dir, "req-1", adoptSelf) },
	}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run = %v", err)
	}

	calls := rig.execCalls()
	if len(calls) != 1 {
		t.Fatalf("exec was attempted %d times, want once", len(calls))
	}
	c := calls[0]
	if c.tasks[1] != pm.TaskDone || c.tasks[2] != pm.TaskPending {
		t.Fatalf("at the exec: task 1 %s, task 2 %s — want done and still pending", c.tasks[1], c.tasks[2])
	}
	if !c.storesClosed {
		t.Error("the run exec'd with its database handles open")
	}
	if c.handoffErr != nil {
		t.Fatalf("handoff: %v", c.handoffErr)
	}
	h := c.handoff
	if !h.Run.Same(adoptSelf) || h.RequestID != "req-1" || h.RequestedBy != "alice@example.com" ||
		h.From.Sequence != 100 || h.To.Sequence != 101 || h.Exe != rig.binary || h.RunID == "" ||
		!strings.Contains(h.Reason, "alice@example.com") || h.Parallel {
		t.Fatalf("handoff = %+v", h)
	}
	if h.ProcessStart.IsZero() || h.SessionStart.IsZero() {
		t.Fatalf("handoff lacks the process or session start: %+v", h)
	}
	if got := strings.Join(prov.calls, ","); got != "Task one,Task two" {
		t.Fatalf("provider calls = %s", got)
	}
	if taskStatus(t, dir, 2) != pm.TaskDone {
		t.Fatal("task 2 did not run after the failed exec")
	}
	rows := adoptionRows(t, dir)
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "exec failed") {
		t.Fatalf("adoption journal = %+v", rows)
	}
	if s, _ := state.Load(dir); s.AdoptRequest != nil && s.AdoptRequest.ID != "" {
		t.Fatalf("the request was left behind: %+v", s.AdoptRequest)
	}
	if _, err := os.Stat(runbuild.HandoffPath(filepath.Join(dir, ".cloop"), os.Getpid())); !os.IsNotExist(err) {
		t.Fatalf("a failed exec left its handoff file: %v", err)
	}
	// The record says which process and build ran.
	s, _ := state.Load(dir)
	if s.RunOwner == nil || s.RunOwner.Build.Sequence != 100 || !s.RunOwner.Ident.Same(adoptSelf) || !s.RunOwner.Adoptable {
		t.Fatalf("run owner = %+v", s.RunOwner)
	}
	started := eventsOf(t, dir, state.EventSessionStarted)
	if len(started) != 1 || !strings.Contains(started[0].Details, `"sequence":100`) {
		t.Fatalf("run started rows = %+v", started)
	}
}

// Every refusal is journalled with its reason and clears the request; the run
// finishes its plan on its own build and never execs.
func TestAdopt_RefusalsKeepTheRunOnItsBuild(t *testing.T) {
	schema := latestSchema(t)
	cases := []struct {
		name   string
		setup  func(r *adoptRig)
		reason string
	}{
		{"older", func(r *adoptRig) { r.report.Sequence = 99 }, "older than this run's build"},
		{"equal", func(r *adoptRig) { r.report.Sequence = 100 }, "same sequence"},
		{"missing sequence", func(r *adoptRig) { r.report.Sequence = 0 }, "carries no sequence"},
		{"no schema", func(r *adoptRig) { r.report.Schema = 0 }, "does not report the schema"},
		{"schema behind", func(r *adoptRig) { r.report.Schema = schema - 1 }, "behind the project database"},
		{"broken binary", func(r *adoptRig) { r.probeErr = errors.New("`version --json` failed: signal: segmentation fault") }, "segmentation fault"},
		{"not a binary", func(r *adoptRig) {
			_ = os.WriteFile(r.binary, []byte("#!/bin/sh\n"), 0o755)
		}, "not an ELF executable"},
		{"same binary", func(r *adoptRig) {
			self, _ := os.Executable()
			r.binary = self
		}, "still holds the build this run is executing"},
		{"children", func(r *adoptRig) { r.kids = []runbuild.Child{{PID: 99, Comm: "sleep"}} }, "pid 99 (sleep)"},
		{"command line", func(r *adoptRig) {
			r.argsErr = errors.New("does not accept this run's command line (Error: unknown flag: --gone)")
		}, "unknown flag: --gone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := adoptProject(t, twoTasks()...)
			requestAdoption(t, dir, "req-"+tc.name, adoptSelf)
			rig := newAdoptRig(t, dir)
			tc.setup(rig)
			o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
			rig.install(o)
			if err := o.Run(context.Background()); err != nil {
				t.Fatalf("Run = %v", err)
			}
			if n := len(rig.execCalls()); n != 0 {
				t.Fatalf("exec attempted %d times", n)
			}
			if taskStatus(t, dir, 1) != pm.TaskDone || taskStatus(t, dir, 2) != pm.TaskDone {
				t.Fatal("the plan did not finish on the run's own build")
			}
			rows := adoptionRows(t, dir)
			if len(rows) != 1 || !strings.Contains(rows[0].Message, tc.reason) ||
				!strings.Contains(rows[0].Message, "alice@example.com") {
				t.Fatalf("adoption journal = %+v; want one refusal mentioning %q", rows, tc.reason)
			}
			if s, _ := state.Load(dir); s.AdoptRequest != nil {
				t.Fatalf("the refused request was left behind: %+v", s.AdoptRequest)
			}
		})
	}
}

// A run on a container or device executor keeps that executor's upgrade path.
func TestAdopt_IsolatedRunRefusesARequest(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "sandbox-run.json"),
		[]byte(`{"executor_id":"box","executor_kind":"container","started_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	requestAdoption(t, dir, "req-c", adoptSelf)
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows := adoptionRows(t, dir)
	if len(rig.execCalls()) != 0 || len(rows) != 1 || !strings.Contains(rows[0].Message, "container executor") {
		t.Fatalf("execs %d, journal %+v", len(rig.execCalls()), rows)
	}
	if s, _ := state.Load(dir); s.RunOwner == nil || s.RunOwner.Adoptable || s.RunOwner.Executor != "container" {
		t.Fatalf("run owner = %+v; want a non-adoptable container run", s.RunOwner)
	}
}

// A request addressed to another process is not this run's to act on, nor to
// clear.
func TestAdopt_RequestForAnotherProcessIsLeftAlone(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	other := adoptSelf
	other.StartTicks++
	requestAdoption(t, dir, "req-other", other)
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rig.execCalls()) != 0 || rig.probed != 0 || len(adoptionRows(t, dir)) != 0 {
		t.Fatalf("execs %d, probes %d, journal %+v", len(rig.execCalls()), rig.probed, adoptionRows(t, dir))
	}
	if s, _ := state.Load(dir); s.AdoptRequest == nil || s.AdoptRequest.ID != "req-other" {
		t.Fatalf("another run's request was cleared: %+v", s.AdoptRequest)
	}
}

// Following new builds: a newer binary at the start path is adopted with no
// request; a refused one is asked once, not at every boundary.
func TestAdopt_FollowNewBuilds(t *testing.T) {
	tasks := append(twoTasks(), &pm.Task{ID: 3, Title: "Task three", Priority: 3, Status: pm.TaskPending},
		&pm.Task{ID: 4, Title: "Task four", Priority: 4, Status: pm.TaskPending})

	dir := adoptProject(t, tasks...)
	if err := state.SetFollowBuilds(dir, true); err != nil {
		t.Fatal(err)
	}
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := rig.execCalls()
	if len(calls) == 0 || calls[0].handoff.Reason != "this project follows new builds" || calls[0].handoff.RequestID != "" {
		t.Fatalf("follow mode: %d exec(s), %+v", len(calls), calls)
	}
	// A failed exec is tried again at the next boundaries, three times in
	// all, and then the file is given up on.
	if len(calls) != maxAdoptAttempts || rig.probed != maxAdoptAttempts {
		t.Fatalf("a file whose exec fails: %d exec(s), %d probe(s); want %d of each", len(calls), rig.probed, maxAdoptAttempts)
	}
	rows := adoptionRows(t, dir)
	// Newest first.
	if len(rows) != maxAdoptAttempts || !strings.Contains(rows[0].Message, "not trying this file again") {
		t.Fatalf("journal = %+v", rows)
	}

	dir = adoptProject(t, tasks...)
	if err := state.SetFollowBuilds(dir, true); err != nil {
		t.Fatal(err)
	}
	rig = newAdoptRig(t, dir)
	rig.report.Sequence = 99
	o = newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.probed != 1 || len(rig.execCalls()) != 0 || len(adoptionRows(t, dir)) != 1 {
		t.Fatalf("an older build: probed %d, execs %d, journal %+v", rig.probed, len(rig.execCalls()), adoptionRows(t, dir))
	}
}

// Without the option or a request, nothing is probed at all.
func TestAdopt_OffByDefault(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.probed != 0 || len(rig.execCalls()) != 0 {
		t.Fatalf("probed %d, execs %d", rig.probed, len(rig.execCalls()))
	}
}

// A parallel run drains first: with tasks 1 and 2 in one round and task 3
// waiting for the next, a request filed while the round runs is acted on only
// once both have finished — and before task 3 starts.
func TestAdopt_ParallelRunDrainsFirst(t *testing.T) {
	dir := adoptProject(t,
		&pm.Task{ID: 1, Title: "Task one", Priority: 1, Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "Task two", Priority: 1, Status: pm.TaskPending},
		&pm.Task{ID: 3, Title: "Task three", Priority: 2, Status: pm.TaskPending})
	slow := make(chan struct{})
	prov := &adoptProvider{
		release: map[string]chan struct{}{"Task one": slow},
		during: map[string]func(){
			"Task two": func() {
				requestAdoption(t, dir, "req-par", adoptSelf)
				// Task one is still running: let it finish a little later.
				go func() { time.Sleep(300 * time.Millisecond); close(slow) }()
			},
		},
	}
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true, MaxParallel: 2}, prov)
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := rig.execCalls()
	if len(calls) != 1 {
		t.Fatalf("exec attempted %d times, want once", len(calls))
	}
	c := calls[0]
	if c.tasks[1] != pm.TaskDone || c.tasks[2] != pm.TaskDone || c.tasks[3] != pm.TaskPending {
		t.Fatalf("at the exec: %v — want 1 and 2 done, 3 not started", c.tasks)
	}
	if !c.handoff.Parallel {
		t.Error("the handoff does not say the parallel loop handed over")
	}
	if taskStatus(t, dir, 3) != pm.TaskDone {
		t.Fatal("task 3 did not run after the failed exec")
	}
}

// The new image continues the run: no "Run started", no --replan, no
// --retry-failed, no pre_plan hook; the counters, the run id and the process
// start come from the handoff; the journal and the audit trail say which build
// it left and why; the request it answered is cleared.
func TestAdopt_ResumedImageContinuesTheRun(t *testing.T) {
	dir := adoptProject(t,
		&pm.Task{ID: 1, Title: "Task one", Priority: 1, Status: pm.TaskDone},
		&pm.Task{ID: 2, Title: "Task two", Priority: 2, Status: pm.TaskPending},
		&pm.Task{ID: 3, Title: "Task three", Priority: 3, Status: pm.TaskFailed})
	requestAdoption(t, dir, "req-done", adoptSelf)
	marker := filepath.Join(t.TempDir(), "pre_plan_ran")
	t.Cleanup(func() { processStartOverride.Store(nil); pinnedRunID.Store(nil) })

	started := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	h := &runbuild.Handoff{
		Run: adoptSelf, Reason: "requested by alice@example.com", RequestID: "req-done",
		RequestedBy: "alice@example.com", From: runbuild.Build{Version: "dev+g0000001", Sequence: 99},
		To: runbuild.Build{Version: "dev+gaaaaaaa", Sequence: 100}, Exe: "/usr/local/bin/cloop-latest",
		RunID: "run_handed_over", ProcessStart: started, SessionStart: started, SessionStartStep: 0,
		EvolveStep: 4, ConsecutiveErrors: 1, Status: "running", Reexecs: 2,
	}
	cfg := Config{WorkDir: dir, PMMode: true, Resumed: true, Handoff: h, Replan: true, RetryFailed: true,
		Hooks: hooks.Config{PrePlan: "touch " + marker},
		// What the command line and config.yaml would say again: not the
		// new image's to apply.
		Model: "flag-model", Effort: "max", MaxParallel: 1, InnovateMode: true}
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, cfg, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	s, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Plan == nil || len(s.Plan.Tasks) != 3 {
		t.Fatalf("--replan was applied on a resumed run: %+v", s.Plan)
	}
	if got := s.Plan.TaskByID(3).Status; got != pm.TaskFailed {
		t.Fatalf("--retry-failed reset task 3 on a resumed run (now %s)", got)
	}
	if s.Plan.TaskByID(2).Status != pm.TaskDone || s.Plan.TaskByID(2).RunID != "run_handed_over" {
		t.Fatalf("task 2: %s, run id %q", s.Plan.TaskByID(2).Status, s.Plan.TaskByID(2).RunID)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the pre_plan hook ran again in the new image")
	}
	if s.Model == "flag-model" || s.Effort == "max" || s.InnovateMode {
		t.Fatalf("the new image re-applied the command line: model %q effort %q innovate %v", s.Model, s.Effort, s.InnovateMode)
	}
	if rows := eventsOf(t, dir, state.EventSessionStarted); len(rows) != 0 {
		t.Fatalf("a resumed run announced a new start: %+v", rows)
	}
	re := eventsOf(t, dir, state.EventRunReexecuted)
	if len(re) != 1 || !strings.Contains(re[0].Message, "dev+g0000001 → dev+gaaaaaaa") ||
		!strings.Contains(re[0].Message, "alice@example.com") {
		t.Fatalf("run_reexecuted rows = %+v", re)
	}
	if s.RunOwner == nil || s.RunOwner.Reexecs != 3 || s.RunOwner.Previous == nil ||
		s.RunOwner.Previous.Sequence != 99 || !s.RunOwner.StartedAt.Equal(started) ||
		s.RunOwner.Exe != "/usr/local/bin/cloop-latest" || s.RunOwner.RunID != "run_handed_over" {
		t.Fatalf("run owner = %+v", s.RunOwner)
	}
	if s.AdoptRequest != nil {
		t.Fatalf("the answered request was left behind: %+v", s.AdoptRequest)
	}
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "run.reexecuted"})
	if err != nil || len(evs) != 1 || !strings.Contains(evs[0].Payload, `"run_id":"run_handed_over"`) {
		t.Fatalf("audit rows = %+v, %v", evs, err)
	}
}

// The counters carried across an exec still end the run: one failure on top
// of the two the old image counted reaches --max-failures 3.
func TestAdopt_ResumedImageKeepsTheFailureCount(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	t.Cleanup(func() { processStartOverride.Store(nil); pinnedRunID.Store(nil) })
	h := &runbuild.Handoff{Run: adoptSelf, Reason: "this project follows new builds",
		From: runbuild.Build{Version: "x", Sequence: 99}, ConsecutiveErrors: 2, SessionStart: time.Now()}
	prov := &mockProvider{name: "mock", results: []*provider.Result{{Output: "", Provider: "mock"}}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Resumed: true, Handoff: h, MaxFailures: 3}, prov)
	newAdoptRig(t, dir).install(o)
	err := o.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "3 consecutive") {
		t.Fatalf("Run = %v; want the third consecutive failure to end the run", err)
	}
}

// A stop that lands while the run is handing over wins: no exec, and the run
// pauses as for any stop.
func TestAdopt_StopDuringHandoverIsNotLostToTheExec(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	requestAdoption(t, dir, "req-stop", adoptSelf)
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := o.adopt.probe
	o.adopt.probe = func(pctx context.Context, c *runbuild.Candidate) (runbuild.Build, error) {
		b, err := probe(pctx, c)
		cancel() // the stop arrives as validation finishes
		return b, err
	}
	err := o.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v; want the stop", err)
	}
	if n := len(rig.execCalls()); n != 0 {
		t.Fatalf("exec attempted %d times after the stop", n)
	}
	if s, _ := state.Load(dir); s.Status != "paused" {
		t.Fatalf("status %q after the stop; want paused", s.Status)
	}
	if _, err := os.Stat(runbuild.HandoffPath(filepath.Join(dir, ".cloop"), os.Getpid())); !os.IsNotExist(err) {
		t.Fatalf("the abandoned handoff was left behind: %v", err)
	}
}

// The second check: a stop that lands after the handoff is written and the
// stores are closed, just before the exec, still wins — and the run reopens
// its stores to record the pause.
func TestAdopt_StopJustBeforeTheExecWins(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	requestAdoption(t, dir, "req-late-stop", adoptSelf)
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handoff := runbuild.HandoffPath(filepath.Join(dir, ".cloop"), os.Getpid())
	var written, closed bool
	o.adopt.beforeExec = func() {
		_, err := os.Stat(handoff)
		written = err == nil
		closed = o.statedb == nil
		cancel()
	}
	if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v; want the stop", err)
	}
	if !written || !closed {
		t.Fatalf("at the last moment: handoff written %v, stores closed %v", written, closed)
	}
	if n := len(rig.execCalls()); n != 0 {
		t.Fatalf("exec attempted %d times after the stop", n)
	}
	if _, err := os.Stat(handoff); !os.IsNotExist(err) {
		t.Fatalf("the abandoned handoff was left behind: %v", err)
	}
	if s, _ := state.Load(dir); s.Status != "paused" {
		t.Fatalf("status %q after the stop; want paused", s.Status)
	}
}

// "Adopt the hub's build" never moves a run past the hub that asked: a binary
// ahead of it is a deploy that may still be rolled back.
func TestAdopt_RequestNeverPassesTheHubThatAsked(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	if err := state.RequestAdoption(dir, &runbuild.Request{ID: "req-hub", RequestedAt: time.Now(),
		RequestedBy: "alice@example.com", Run: adoptSelf, Hub: runbuild.Build{Version: "dev+gbbbbbbb", Sequence: 100}}); err != nil {
		t.Fatal(err)
	}
	rig := newAdoptRig(t, dir)
	rig.report.Sequence = 102
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows := adoptionRows(t, dir)
	if len(rig.execCalls()) != 0 || len(rows) != 1 || !strings.Contains(rows[0].Message, "newer than the hub that asked") {
		t.Fatalf("execs %d, journal %+v", len(rig.execCalls()), rows)
	}
}

// Following new builds waits until a deployed file has been in place for the
// settle time — a request does not.
func TestAdopt_FollowWaitsForTheDeployToSettle(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	if err := state.SetFollowBuilds(dir, true); err != nil {
		t.Fatal(err)
	}
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	o.adopt.settle = time.Hour
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.probed != 0 || len(rig.execCalls()) != 0 {
		t.Fatalf("a file deployed moments ago was probed %d times", rig.probed)
	}
}

// A transient probe failure is retried at later boundaries, then given up.
func TestAdopt_ProbeFailuresAreRetriedThenGivenUp(t *testing.T) {
	dir := adoptProject(t,
		&pm.Task{ID: 1, Title: "Task one", Priority: 1, Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "Task two", Priority: 2, Status: pm.TaskPending},
		&pm.Task{ID: 3, Title: "Task three", Priority: 3, Status: pm.TaskPending})
	if err := state.SetFollowBuilds(dir, true); err != nil {
		t.Fatal(err)
	}
	rig := newAdoptRig(t, dir)
	rig.probeErr = errors.New("did not answer within 10s")
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.probed != maxAdoptAttempts {
		t.Fatalf("probed %d times; want %d attempts and no more", rig.probed, maxAdoptAttempts)
	}
}

// A disk-reserve note the next disk check has not acted on holds adoption
// back, and keeps the request for a later boundary.
func TestAdopt_WaitsForAPendingReserveNote(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	requestAdoption(t, dir, "req-reserve", adoptSelf)
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	o.reserveSpent = "an outcome write needed the reserve"
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.probed != 0 {
		t.Fatalf("probed %d times with a reserve note pending", rig.probed)
	}
	if s, _ := state.Load(dir); s.AdoptRequest == nil || s.AdoptRequest.ID != "req-reserve" {
		t.Fatalf("the request was dropped: %+v", s.AdoptRequest)
	}
}

// A save that fails just before the exec abandons the adoption, not the run:
// the run carries on on its own build and finishes its plan.
func TestAdopt_FailedSaveAbandonsTheAdoptionNotTheRun(t *testing.T) {
	dir := adoptProject(t, twoTasks()...)
	requestAdoption(t, dir, "req-save", adoptSelf)
	rig := newAdoptRig(t, dir)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &adoptProvider{})
	rig.install(o)
	failNext := false
	probe := o.adopt.probe
	o.adopt.probe = func(ctx context.Context, c *runbuild.Candidate) (runbuild.Build, error) {
		failNext = true // the next write is the pre-adoption save
		return probe(ctx, c)
	}
	real := saveState
	saveState = func(s *state.ProjectState, mode saveMode) error {
		if failNext {
			failNext = false
			return errors.New("injected: database is locked")
		}
		return real(s, mode)
	}
	t.Cleanup(func() { saveState = real })
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run = %v; want the run to carry on", err)
	}
	if n := len(rig.execCalls()); n != 0 {
		t.Fatalf("exec attempted %d times without the state saved", n)
	}
	rows := adoptionRows(t, dir)
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "could not be saved first") {
		t.Fatalf("journal = %+v", rows)
	}
	if taskStatus(t, dir, 2) != pm.TaskDone {
		t.Fatal("the run did not finish its plan")
	}
}
