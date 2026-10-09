package ui

// A failed-over run is the project's run (Task 20396): end to end through the
// hub's own failover wiring — the supervisor, the SQL session store,
// failoverHandler — over fake devices the test takes down. The replacement is
// dispatched through startWorkloadAs and followed as handleRun follows a run:
// its live log reaches a WebSocket client, the project it was sent comes back
// and is merged, and the project ends not running with its tasks settled. A
// lost executor nothing replaced leaves the project paused, naming it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedNode is a fake edge device: it does not share the hub's filesystem, so
// the hub sends it the project as a seed and merges back what it returns. The
// test takes it down at will, writes its workloads' output, and finishes
// them, editing the copy of the project the workload was sent the way a run
// on the device would.
type seedNode struct {
	id   string
	kind string

	mu        sync.Mutex
	down      bool
	starts    int
	order     []string
	workloads map[string]*seedWorkload
}

// seedWorkload is one workload a seedNode started.
type seedWorkload struct {
	handle    string
	spec      executor.Spec
	dir       string // where its seed was materialised, "" without one
	subs      []*nodeSub
	ended     bool
	state     executor.State
	exitCode  int
	errText   string
	result    []byte
	abandoned string
	signals   []executor.Signal
}

func newSeedNode(t *testing.T, id string) *seedNode {
	n := &seedNode{id: id, kind: executor.KindContainer, workloads: map[string]*seedWorkload{}}
	t.Cleanup(func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		for _, w := range n.workloads {
			if w.dir != "" {
				_ = os.RemoveAll(w.dir)
			}
		}
	})
	return n
}

func (n *seedNode) ID() string   { return n.id }
func (n *seedNode) Kind() string { return n.kind }
func (n *seedNode) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation: executor.IsolationContainer, SupportsStream: true, MaxConcurrent: 4,
		SupportsWorkspaceProvisioning: true, SupportsProjectSeed: true, ReturnsProjectState: true,
		Platform: "linux", Arch: "amd64",
	}
}

func (n *seedNode) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return executor.Handle{}, fmt.Errorf("dial %s: connection refused", n.id)
	}
	n.starts++
	w := &seedWorkload{handle: fmt.Sprintf("h-%s-%d", n.id, n.starts), spec: spec, state: executor.StateRunning}
	if len(spec.ProjectSeed) > 0 {
		dir, err := os.MkdirTemp("", "cloop-seednode-")
		if err != nil {
			return executor.Handle{}, err
		}
		if err := projectseed.Write(dir, spec.ProjectSeed); err != nil {
			_ = os.RemoveAll(dir)
			return executor.Handle{}, err
		}
		w.dir = dir
	}
	n.workloads[w.handle] = w
	n.order = append(n.order, w.handle)
	return executor.Handle{ID: w.handle, ExecutorID: n.id, StartedAt: time.Now()}, nil
}

func (n *seedNode) workload(handleID string) (*seedWorkload, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, ok := n.workloads[handleID]
	return w, ok
}

// Signal: a node that died hears nothing; a live one ends the workload — an
// interrupted run pauses and exits zero, a killed one is killed.
func (n *seedNode) Signal(_ context.Context, handleID string, sig executor.Signal) error {
	n.mu.Lock()
	w, ok := n.workloads[handleID]
	if ok {
		w.signals = append(w.signals, sig)
	}
	down := n.down
	n.mu.Unlock()
	if !ok {
		return executor.ErrHandleNotFound
	}
	if down {
		return fmt.Errorf("dial %s: connection refused", n.id)
	}
	switch sig {
	case executor.SignalInterrupt:
		n.finish(handleID, executor.StateExited, 0, "", nil)
	case executor.SignalKill:
		n.finish(handleID, executor.StateKilled, 137, "killed at cloop's request", nil)
	}
	return nil
}

// Status cannot tell a node that died from a slow one: running, until the
// workload ended.
func (n *seedNode) Status(_ context.Context, handleID string) (executor.Status, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, ok := n.workloads[handleID]
	if !ok {
		return executor.Status{}, executor.ErrHandleNotFound
	}
	return executor.Status{HandleID: handleID, ExecutorID: n.id, State: w.state, ExitCode: w.exitCode, Error: w.errText}, nil
}

func (n *seedNode) Stream(ctx context.Context, handleID string) (<-chan executor.LogLine, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, ok := n.workloads[handleID]
	if !ok {
		return nil, executor.ErrHandleNotFound
	}
	sub := &nodeSub{ch: make(chan executor.LogLine), gone: make(chan struct{})}
	if w.ended {
		sub.close()
		return sub.ch, nil
	}
	w.subs = append(w.subs, sub)
	go func() {
		select {
		case <-ctx.Done():
			sub.close()
		case <-sub.gone:
		}
	}()
	return sub.ch, nil
}

func (n *seedNode) HealthCheck(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return fmt.Errorf("dial %s: connection refused", n.id)
	}
	return nil
}

// Abandon implements executor.Abandoner, as the remote driver does: the
// workload is terminal from here on, with the reason in its status.
func (n *seedNode) Abandon(_ context.Context, handleID, reason string) error {
	n.mu.Lock()
	w, ok := n.workloads[handleID]
	if ok {
		w.abandoned = reason
	}
	n.mu.Unlock()
	if !ok {
		return executor.ErrHandleNotFound
	}
	n.finish(handleID, executor.StateFailed, 0, "abandoned by the control plane: "+reason, nil)
	return nil
}

// ProjectResult implements executor.ProjectResultFetcher.
func (n *seedNode) ProjectResult(handleID string) (executor.ProjectResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, ok := n.workloads[handleID]
	if !ok || len(w.result) == 0 {
		return executor.ProjectResult{}, executor.ErrProjectResultUnavailable
	}
	data := w.result
	w.result = nil
	return executor.ProjectResult{Data: data, Redact: func(s string) string { return s }}, nil
}

var (
	_ executor.Abandoner            = (*seedNode)(nil)
	_ executor.ProjectResultFetcher = (*seedNode)(nil)
)

// finish ends a workload: its status, the result it sends back, and every
// stream of it closed — in that order, as an agent sends them.
func (n *seedNode) finish(handleID string, st executor.State, code int, errText string, result []byte) {
	n.mu.Lock()
	w, ok := n.workloads[handleID]
	if !ok || w.ended {
		n.mu.Unlock()
		return
	}
	w.ended, w.state, w.exitCode, w.errText = true, st, code, errText
	if result != nil {
		w.result = result
	}
	subs := w.subs
	w.subs = nil
	n.mu.Unlock()
	for _, s := range subs {
		s.close()
	}
}

// complete finishes a workload the way a run on the device does: edit marks
// what it did in its copy of the project, which is harvested and sent back,
// and it exits zero.
func (n *seedNode) complete(t *testing.T, handleID string, edit func(st *state.ProjectState)) {
	t.Helper()
	w, ok := n.workload(handleID)
	if !ok || w.dir == "" {
		t.Fatalf("%s has no seeded workload %s", n.id, handleID)
	}
	st, err := state.Load(w.dir)
	if err != nil {
		t.Fatalf("load the device's copy of the project: %v", err)
	}
	edit(st)
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save the device's copy of the project: %v", err)
	}
	result, err := projectseed.Harvest(w.dir, w.spec.ProjectSeed, nil)
	if err != nil {
		t.Fatalf("harvest the device's copy of the project: %v", err)
	}
	n.finish(handleID, executor.StateExited, 0, "", result)
}

// say writes one line of a workload's output and waits until every
// subscriber has taken it, then a second so the first was acted on.
func (n *seedNode) say(t *testing.T, handleID, line string) {
	t.Helper()
	waitWatchers(t, handleID, func() int {
		n.mu.Lock()
		defer n.mu.Unlock()
		if w := n.workloads[handleID]; w != nil {
			return len(w.subs)
		}
		return 0
	})
	for _, text := range []string{line + "\n", "(sync)\n"} {
		n.mu.Lock()
		w := n.workloads[handleID]
		var subs []*nodeSub
		if w != nil {
			subs = append(subs, w.subs...)
		}
		n.mu.Unlock()
		if len(subs) == 0 {
			t.Fatalf("nothing is watching workload %s on %s", handleID, n.id)
		}
		for _, s := range subs {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				continue
			}
			select {
			case s.ch <- executor.LogLine{Text: text}:
			case <-s.gone:
			case <-time.After(10 * time.Second):
				s.mu.Unlock()
				t.Fatalf("a watcher of workload %s on %s stopped reading", handleID, n.id)
			}
			s.mu.Unlock()
		}
	}
}

func (n *seedNode) kill() {
	n.mu.Lock()
	n.down = true
	n.mu.Unlock()
}

func (n *seedNode) revive() {
	n.mu.Lock()
	n.down = false
	n.mu.Unlock()
}

func (n *seedNode) startCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.starts
}

// last returns the workload the node started most recently.
func (n *seedNode) last(t *testing.T) *seedWorkload {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.order) == 0 {
		t.Fatalf("%s started nothing", n.id)
	}
	return n.workloads[n.order[len(n.order)-1]]
}

// endAll ends every workload still running, as a node's shutdown would.
func (n *seedNode) endAll() {
	n.mu.Lock()
	var ids []string
	for id, w := range n.workloads {
		if !w.ended {
			ids = append(ids, id)
		}
	}
	n.mu.Unlock()
	for _, id := range ids {
		n.finish(id, executor.StateExited, 0, "", nil)
	}
}

// trackRig is a project on fake devices, the hub's Server following it and
// serving it over HTTP, and a supervisor wired as startExecutorSupervisor
// wires one.
type trackRig struct {
	dir   string
	srv   *Server
	ts    *httptest.Server
	nodes []*seedNode
	sv    *executor.Supervisor
	clock *manualClock
	sched *executorstore.Scheduler
	db    *statedb.DB
}

func newTrackRig(t *testing.T, nodes int, tasks []*pm.Task) *trackRig {
	t.Helper()
	prevWrite := runProgressMinWrite.Swap(0)
	t.Cleanup(func() { runProgressMinWrite.Store(prevWrite) })
	// A registry of its own, so the hub serves this one project.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	dir := setupProjectDir(t, "failed-over runs are tracked", tasks)
	withControlPlaneDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(failoverConfig("")), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &trackRig{dir: dir, clock: &manualClock{now: time.Now()}}
	reg := executor.NewRegistry()
	suffix := strings.ReplaceAll(filepath.Base(dir), ".", "-")
	for i := 0; i < nodes; i++ {
		n := newSeedNode(t, fmt.Sprintf("dev%d-%s", i+1, suffix))
		r.nodes = append(r.nodes, n)
		if err := reg.Register(n); err != nil {
			t.Fatal(err)
		}
		if err := executor.DefaultRegistry.Register(n); err != nil {
			t.Fatal(err)
		}
		node := n
		t.Cleanup(func() { executor.DefaultRegistry.Unregister(node.id) })
	}
	if err := executor.Bind(dir, r.nodes[0].id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	r.srv = New(dir, 0, "")
	r.srv.RPS, r.srv.Burst = 1000, 1000
	r.ts = httptest.NewServer(r.srv.Handler())
	t.Cleanup(r.ts.Close)

	sched, db, err := newScheduler(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r.sched, r.db = sched, db
	cfg := executor.DefaultSupervisorConfig()
	cfg.Policy = executor.HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}
	cfg.JitterFraction = 0
	r.sv = executor.NewSupervisor(reg, cfg,
		executor.WithClock(r.clock),
		executor.WithHealthStore(sched),
		executor.WithSessionStore(sched),
		executor.WithEventSink(sched),
		executor.WithFailoverHandler(failoverHandler(dir)),
		executor.WithFailoverLimit(failoverLimit),
		executor.WithCandidateFilter(failoverPlaceable),
	)
	// Last registered, first run: every run ends and is settled before the
	// project directory is removed.
	t.Cleanup(func() {
		for _, n := range r.nodes {
			n.endAll()
		}
		r.waitUntil(t, "the hub to stop following the project", func() bool {
			_, ok := r.srv.trackedRun(r.dir)
			return !ok
		})
	})
	return r
}

// dispatch starts the project's run on its bound executor — the first node —
// through startWorkloadAs, and follows it as handleRun does.
func (r *trackRig) dispatch(t *testing.T) string {
	t.Helper()
	ex, h, err := startWorkloadAs(nil, newHarnessClearance(r.dir, harnessWho{}, ""), "",
		r.dir, []string{"cloop", "run"}, map[string]string{"handler": "run"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.ID() != r.nodes[0].id {
		t.Fatalf("dispatched to %s, want the bound %s", ex.ID(), r.nodes[0].id)
	}
	followTestRun(t, r.srv, r.dir, ex, h)
	return h.ID
}

func (r *trackRig) killAndProbe(n *seedNode) {
	n.kill()
	r.clock.advance(time.Hour)
	r.sv.ProbeOnce(context.Background())
}

func (r *trackRig) waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (r *trackRig) task(t *testing.T, id int) *pm.Task {
	t.Helper()
	st, err := state.Load(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	task := st.Plan.TaskByID(id)
	if task == nil {
		t.Fatalf("task %d is gone", id)
	}
	return task
}

func (r *trackRig) journal(t *testing.T, typ statedb.EventType) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(r.dir, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	var out []state.EventRow
	for _, row := range rows {
		if row.Type == typ {
			out = append(out, row)
		}
	}
	return out
}

func (r *trackRig) journalSays(t *testing.T, typ statedb.EventType, parts ...string) bool {
	t.Helper()
	for _, e := range r.journal(t, typ) {
		all := true
		for _, p := range parts {
			if !strings.Contains(e.Message, p) {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

// tracked reports the run the hub follows for the project.
func (r *trackRig) tracked() (executorID, handleID string, ok bool) {
	run, ok := r.srv.trackedRun(r.dir)
	if !ok || run.ex == nil {
		return "", "", false
	}
	return run.ex.ID(), run.handleID, true
}

// wsWatcher is a dashboard's WebSocket, subscribed to the project.
type wsWatcher struct {
	mu   sync.Mutex
	msgs []wsMessage
	conn *websocket.Conn
}

func openProjectStream(t *testing.T, ts *httptest.Server, idx int) *wsWatcher {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + fmt.Sprintf("/api/ws?project_idx=%d", idx)
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		cancel()
		t.Fatalf("dial the hub's WebSocket: %v", err)
	}
	conn.SetReadLimit(-1)
	w := &wsWatcher{conn: conn}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m wsMessage
			if json.Unmarshal(data, &m) == nil {
				w.mu.Lock()
				w.msgs = append(w.msgs, m)
				w.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = conn.Close(websocket.StatusNormalClosure, "")
		<-done
	})
	return w
}

// count is how many messages have arrived so far.
func (w *wsWatcher) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.msgs)
}

// waitFor waits until a message of type typ whose data contains every part
// has arrived, and returns its position.
func (w *wsWatcher) waitFor(t *testing.T, what, typ string, parts ...string) int {
	t.Helper()
	return w.waitForAfter(t, 0, what, typ, parts...)
}

// waitForAfter is waitFor counting only messages from position from on.
func (w *wsWatcher) waitForAfter(t *testing.T, from int, what, typ string, parts ...string) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		for i := from; i < len(w.msgs); i++ {
			m := w.msgs[i]
			if m.Type != typ {
				continue
			}
			ok := true
			for _, p := range parts {
				if !strings.Contains(string(m.Data), p) {
					ok = false
				}
			}
			if ok {
				w.mu.Unlock()
				return i
			}
		}
		w.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the dashboard never received %s", what)
	return -1
}

// TestFailedOverRunBecomesTheProjectsRun is the scenario the task is named
// for. A run on a device is lost mid-task; the hub starts it again on a
// second device and follows it there as the project's run: the replacement is
// sent a fresh copy of the plan the failover settled, its placement record
// names the device it runs on, the stranded run is given up, the replacement's
// output reaches a dashboard over the WebSocket, the project it sends back is
// merged into the hub's, and when it ends the project is not running and its
// tasks are settled.
func TestFailedOverRunBecomesTheProjectsRun(t *testing.T) {
	r := newTrackRig(t, 2, []*pm.Task{
		{ID: 1, Title: "first", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "second", Status: pm.TaskPending, Priority: 2},
	})
	ws := openProjectStream(t, r.ts, 0)
	h1 := r.dispatch(t)
	r.nodes[0].say(t, h1, "━━━ Task 1/2: first ━━━")
	ws.waitFor(t, "the first run's output", "step_output", "Task 1/2: first")

	r.killAndProbe(r.nodes[0])

	// A replacement on the second device, followed as the project's run.
	if got := r.nodes[1].startCount(); got != 1 {
		t.Fatalf("the second device started %d workloads, want the one replacement", got)
	}
	w2 := r.nodes[1].last(t)
	if exID, h, ok := r.tracked(); !ok || exID != r.nodes[1].id || h != w2.handle {
		t.Fatalf("the hub follows %s/%s (tracked %v), want the replacement %s/%s", exID, h, ok, r.nodes[1].id, w2.handle)
	}
	if !r.srv.projectExecuting(r.dir) {
		t.Fatal("the project is not executing while its replacement runs")
	}
	// Dispatched as any run is: a fresh seed of the plan as the failover left
	// it — task 1 back to pending — and a run of its own.
	if w2.dir == "" {
		t.Fatal("the replacement was not sent the project")
	}
	seeded, err := state.Load(w2.dir)
	if err != nil {
		t.Fatal(err)
	}
	if task := seeded.Plan.TaskByID(1); task == nil || task.Status != pm.TaskPending || task.FailCount != 1 {
		t.Fatalf("the replacement's copy of task 1 is %+v, want pending with the lost attempt counted", task)
	}
	if got := w2.spec.Labels["handler"]; got != "failover" {
		t.Errorf("the replacement's handler label is %q, want failover", got)
	}
	if w2.spec.Labels[executor.LabelRunID] == "" {
		t.Error("the replacement carries no run id for its tasks and audit rows to join on")
	}
	// Executor attribution (Task 20244): the placement record names the
	// device it runs on, not the one that was lost.
	if rec, ok := artifact.LoadSandboxRun(r.dir); !ok || rec.ExecutorID != r.nodes[1].id || rec.RunID != w2.spec.Labels[executor.LabelRunID] {
		t.Fatalf("the placement record = %+v (%v), want the replacement's executor %s and run id", rec, ok, r.nodes[1].id)
	}
	// The stranded run is given up, not left beside its replacement.
	if w1, _ := r.nodes[0].workload(h1); w1 == nil || w1.abandoned == "" || !strings.Contains(w1.abandoned, r.nodes[1].id) {
		t.Fatalf("the stranded run was not abandoned naming its replacement: %+v", w1)
	}
	// Its session is the next attempt of the stranded one's.
	sessions, err := r.sched.RunningSessions(r.nodes[1].id)
	if err != nil || len(sessions) != 1 || sessions[0].Attempt != 2 {
		t.Fatalf("the replacement's session = %+v, %v; want one, attempt 2", sessions, err)
	}
	if row, err := r.db.GetExecutorSession(sessions[0].ID); err != nil || row.RequeuedFrom == "" {
		t.Fatalf("the replacement's session row = %+v, %v; want it linked to the stranded one", row, err)
	}
	if !r.journalSays(t, state.EventFailover, "Run failed over from executor "+r.nodes[0].id+" to "+r.nodes[1].id) {
		t.Error("the event history does not say the run failed over from the lost device to the second")
	}

	// The replacement's live log reaches the dashboard, after a line saying
	// where the run went.
	ws.waitFor(t, "the failover notice in the live log", "step_output",
		"executor "+r.nodes[0].id+" stopped answering", "failed over to "+r.nodes[1].id)
	r.nodes[1].say(t, w2.handle, "replacement working on task 1")
	ws.waitFor(t, "the replacement's output", "step_output", "replacement working on task 1")

	// It finishes both tasks on the device; the hub merges what it sends back
	// and settles the run.
	mark := ws.count()
	r.nodes[1].complete(t, w2.handle, func(st *state.ProjectState) {
		for _, task := range st.Plan.Tasks {
			task.Status = pm.TaskDone
			task.Result = "done on the replacement"
		}
		st.Status = "complete"
	})
	r.waitUntil(t, "the replacement's run to be settled", func() bool {
		_, _, ok := r.tracked()
		return !ok
	})
	for _, id := range []int{1, 2} {
		task := r.task(t, id)
		if task.Status != pm.TaskDone || task.Result != "done on the replacement" {
			t.Errorf("task %d is %s (%q) after the replacement finished it, want its result merged", id, task.Status, task.Result)
		}
		// Attributed to where it ran (Task 20244): the replacement's device,
		// under the replacement's run id — stamped by the hub at the merge.
		if task.ExecutorID != r.nodes[1].id || task.RunID != w2.spec.Labels[executor.LabelRunID] {
			t.Errorf("task %d is attributed to %q / run %q, want the replacement's %q / %q",
				id, task.ExecutorID, task.RunID, r.nodes[1].id, w2.spec.Labels[executor.LabelRunID])
		}
	}
	if r.srv.projectExecuting(r.dir) {
		t.Fatal("the project still executes after its replacement ended")
	}
	if got := loadStatus(t, r.dir); got == "running" {
		t.Fatalf("the project is %q after its replacement ended", got)
	}
	// The dashboard hears the replacement's own end.
	ws.waitForAfter(t, mark, "the replacement's end", "run_state", `"running":false`)
	if len(r.journal(t, state.EventProjectResult)) == 0 {
		t.Error("the merge of the replacement's result is not in the event history")
	}
	r.waitUntil(t, "the replacement's session to close", func() bool {
		row, err := r.db.GetExecutorSession(sessions[0].ID)
		return err == nil && row.State == statedb.ExecutorSessionFinished
	})
}

// TestLostExecutorWithNoReplacementLeavesRunning: a project on the only device
// there is. When the supervisor declares the device lost, the project leaves
// "running" at once — not when someone presses Stop — paused with an
// executor_lost reason naming the device, its task back to pending, the
// dashboard told, and the event history saying the device was lost. Starting
// the project again once the device is back dispatches a run as normal.
func TestLostExecutorWithNoReplacementLeavesRunning(t *testing.T) {
	r := newTrackRig(t, 1, []*pm.Task{{ID: 1, Title: "only", Status: pm.TaskPending}})
	ws := openProjectStream(t, r.ts, 0)
	h1 := r.dispatch(t)
	r.nodes[0].say(t, h1, "━━━ Task 1/1: only ━━━")
	if !r.srv.projectExecuting(r.dir) {
		t.Fatal("the project is not executing while its run is")
	}
	mark := ws.count()

	r.killAndProbe(r.nodes[0])

	if _, _, ok := r.tracked(); ok {
		t.Fatal("the hub still follows a run whose device was lost")
	}
	if r.srv.projectExecuting(r.dir) {
		t.Fatal("a project whose device was lost is still executing")
	}
	st, err := state.LoadLite(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != "executor_lost" ||
		!strings.Contains(st.PauseReason.Detail, r.nodes[0].id) {
		t.Fatalf("the project is %q with reason %+v, want paused executor_lost naming %s", st.Status, st.PauseReason, r.nodes[0].id)
	}
	if task := r.task(t, 1); task.Status != pm.TaskPending || task.FailCount != 1 {
		t.Fatalf("task 1 is %s (fail count %d), want pending for a retry", task.Status, task.FailCount)
	}
	if w1, _ := r.nodes[0].workload(h1); w1 == nil || w1.abandoned == "" {
		t.Fatal("the stranded run was not given up")
	}
	if !r.journalSays(t, state.EventFailover, "Executor "+r.nodes[0].id+" was lost") {
		t.Error("the event history does not say the device was lost")
	}
	ws.waitForAfter(t, mark, "the run's stop", "run_state", `"running":false`)

	// The device comes back and the project is started again: an ordinary
	// dispatch, through the Run button's own handler.
	r.nodes[0].revive()
	resp, err := http.Post(r.ts.URL+"/api/run", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Run after the loss = HTTP %d, want 200", resp.StatusCode)
	}
	if got := r.nodes[0].startCount(); got != 2 {
		t.Fatalf("the device started %d workloads, want the run after the loss too", got)
	}
	w := r.nodes[0].last(t)
	if exID, h, ok := r.tracked(); !ok || exID != r.nodes[0].id || h != w.handle {
		t.Fatalf("the hub follows %s/%s (%v), want the new run", exID, h, ok)
	}
	r.nodes[0].complete(t, w.handle, func(st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		st.Status = "complete"
	})
	r.waitUntil(t, "the new run to be settled", func() bool {
		_, _, ok := r.tracked()
		return !ok
	})
	if task := r.task(t, 1); task.Status != pm.TaskDone {
		t.Fatalf("task 1 is %s after the run after the loss finished it", task.Status)
	}
}

// TestStopOnAFailedOverProjectStopsTheReplacement: once a run has failed over,
// the Stop button reaches the replacement — the run the hub now follows — and
// not the lost device.
func TestStopOnAFailedOverProjectStopsTheReplacement(t *testing.T) {
	r := newTrackRig(t, 2, []*pm.Task{{ID: 1, Title: "only", Status: pm.TaskPending}})
	h1 := r.dispatch(t)
	r.nodes[0].say(t, h1, "━━━ Task 1/1: only ━━━")
	r.killAndProbe(r.nodes[0])
	w2 := r.nodes[1].last(t)
	if _, h, ok := r.tracked(); !ok || h != w2.handle {
		t.Fatalf("the hub does not follow the replacement (tracking %s, %v)", h, ok)
	}

	out := apiPOST(t, r.ts, "/api/stop", map[string]interface{}{})
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("Stop on a failed-over project: %v", out)
	}
	w, _ := r.nodes[1].workload(w2.handle)
	if w == nil || len(w.signals) != 1 || w.signals[0] != executor.SignalInterrupt {
		t.Fatalf("the replacement received %v, want one interrupt", w.signals)
	}
	if w1, _ := r.nodes[0].workload(h1); len(w1.signals) != 0 {
		t.Errorf("the lost device was signalled %v; it was given up, not stopped", w1.signals)
	}
	r.waitUntil(t, "the stopped replacement to be settled", func() bool {
		_, _, ok := r.tracked()
		return !ok
	})
	if r.srv.projectExecuting(r.dir) {
		t.Fatal("the project still executes after its replacement was stopped")
	}
}

// TestFailoverNeverMovesARunOntoARestrictedExecutor: an executor restricted
// to an access list is checked against the claims of the person starting a
// run, and a failover starts it on nobody's behalf. Placement passes over it,
// so with no other executor the run stops with its device; and a replacement
// routed to it anyway — from another member, or after an access list was
// added — is refused at dispatch.
func TestFailoverNeverMovesARunOntoARestrictedExecutor(t *testing.T) {
	r := newTrackRig(t, 2, []*pm.Task{{ID: 1, Title: "only", Status: pm.TaskPending}})
	if err := r.db.AddExecutorAudience(r.nodes[1].id, "group", "platform", "admin@example"); err != nil {
		t.Fatal(err)
	}
	h1 := r.dispatch(t)
	r.nodes[0].say(t, h1, "━━━ Task 1/1: only ━━━")
	r.killAndProbe(r.nodes[0])

	if got := r.nodes[1].startCount(); got != 0 {
		t.Fatalf("the restricted executor was handed the run (%d starts)", got)
	}
	st, err := state.LoadLite(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.PauseReason == nil || st.PauseReason.Code != "executor_lost" || !strings.Contains(st.PauseReason.Detail, "no executor could take the run") {
		t.Fatalf("the project is %q with reason %+v, want executor_lost with nowhere to go", st.Status, st.PauseReason)
	}

	row, ok, err := r.db.ExecutorSessionForHandle(r.nodes[0].id, h1)
	if err != nil || !ok || row.State != statedb.ExecutorSessionRequeued {
		t.Fatalf("the stranded session = %+v, %v, %v; want requeued", row, ok, err)
	}
	ev := executor.FailoverEvent{From: r.nodes[0].id, To: r.nodes[1].id, Session: executor.Session{
		ID: row.ID, ExecutorID: row.ExecutorID, HandleID: row.HandleID, ProjectPath: row.ProjectPath, Attempt: row.Attempt,
		Spec: executor.Spec{WorkDir: row.ProjectPath, Argv: []string{"cloop", "run"}, Labels: map[string]string{"project": r.dir}},
	}}
	if err := r.srv.startReplacement(context.Background(), r.dir, ev); err == nil || !strings.Contains(err.Error(), "access list") {
		t.Fatalf("a replacement routed to the restricted executor = %v, want a refusal naming its access list", err)
	}
	if got := r.nodes[1].startCount(); got != 0 {
		t.Fatalf("the restricted executor was started (%d starts)", got)
	}
}

// TestProjectExecutingConsultsTheSessionStore: a run the hub follows whose
// driver still calls it alive — or cannot be reached — is not executing once
// the failover claim has taken its session as replaced or exhausted, and is
// while a replacement may still be on its way. With no verdict at all, an
// unreachable driver still fails closed.
func TestProjectExecutingConsultsTheSessionStore(t *testing.T) {
	dir := setupProjectDir(t, "liveness by the session store", nil)
	withControlPlaneDir(t, dir)
	srv := New(dir, 0, "")
	sched, db, err := newScheduler(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	open := func(t *testing.T, id, exID, handle string, attempt int, from string) executor.Session {
		t.Helper()
		sess := executor.Session{ID: id, ExecutorID: exID, HandleID: handle, ProjectPath: dir,
			ClaimToken: "tok-" + id, Attempt: attempt, StartedAt: time.Now(),
			Spec: executor.Spec{WorkDir: dir, Argv: []string{"cloop", "run"}}}
		if from == "" {
			err = sched.OpenSession(sess)
		} else {
			err = sched.OpenRequeuedSession(sess, from)
		}
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}
	claim := func(t *testing.T, s executor.Session, max int, at time.Time) {
		t.Helper()
		if _, _, err := sched.ClaimRequeue(s.ID, s.ClaimToken, max, at); err != nil {
			t.Fatal(err)
		}
	}
	follow := func(ex executor.Executor, handle string) {
		srv.trackRun(dir, ex, handle)
	}
	t.Cleanup(func() { srv.untrackRun(dir) })

	unknown := &stubExecutor{status: executor.Status{State: executor.StateUnknown}}
	unreachable := &stubExecutor{err: fmt.Errorf("agent is not connected")}

	t.Run("no verdict, unreachable driver: fails closed", func(t *testing.T) {
		follow(unreachable, "h-none")
		if !srv.projectExecuting(dir) {
			t.Fatal("an unreachable driver with no failover verdict reads as not executing")
		}
	})
	t.Run("requeued, replacement pending: still executing", func(t *testing.T) {
		s := open(t, "s-pending", unknown.ID(), "h-pending", 1, "")
		claim(t, s, 2, time.Now())
		follow(unknown, "h-pending")
		if !srv.projectExecuting(dir) {
			t.Fatal("a run whose replacement may still be starting reads as not executing")
		}
	})
	t.Run("requeued long ago, nothing replaced it: not executing", func(t *testing.T) {
		s := open(t, "s-stale", unknown.ID(), "h-stale", 1, "")
		claim(t, s, 2, time.Now().Add(-2*failoverReplacementWindow))
		follow(unknown, "h-stale")
		if srv.projectExecuting(dir) {
			t.Fatal("a run the claim took long ago, with no replacement, reads as executing")
		}
	})
	t.Run("replaced: not executing", func(t *testing.T) {
		s := open(t, "s-replaced", unknown.ID(), "h-replaced", 1, "")
		claim(t, s, 2, time.Now())
		open(t, "s-successor", "elsewhere", "h-successor", 2, "s-replaced")
		follow(unknown, "h-replaced")
		if srv.projectExecuting(dir) {
			t.Fatal("a run a failover replaced reads as executing")
		}
	})
	t.Run("failover_exhausted, unreachable driver: not executing", func(t *testing.T) {
		s := open(t, "s-exhausted", unreachable.ID(), "h-exhausted", 3, "")
		claim(t, s, 2, time.Now())
		follow(unreachable, "h-exhausted")
		if srv.projectExecuting(dir) {
			t.Fatal("an exhausted run reads as executing because its driver cannot be reached")
		}
	})
}

// TestRedispatchArgsOnlyRestartsARun: the session row a replacement is
// started from is read back from a database, so only a `cloop run` with flags
// a dispatch passes is ever started again.
func TestRedispatchArgsOnlyRestartsARun(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"/usr/bin/cloop", "run"}, "run"},
		{[]string{"cloop", "run", "--pm"}, "run --pm"},
		{[]string{"cloop", "init", "goal"}, ""},
		{[]string{"cloop"}, ""},
		{[]string{"cloop", "run", "--provider", "x"}, ""},
		{[]string{"cloop", "run", "--dangerously-skip-permissions"}, ""},
	} {
		got, err := redispatchArgs(executor.Spec{Argv: tc.argv})
		if tc.want == "" {
			if err == nil {
				t.Errorf("redispatchArgs(%q) = %q, want a refusal", tc.argv, got)
			}
			continue
		}
		if err != nil || strings.Join(got, " ") != tc.want {
			t.Errorf("redispatchArgs(%q) = %q, %v; want %q", tc.argv, got, err, tc.want)
		}
	}
}

// TestFailoverServerFindsTheRunsFollower: the process-wide supervisor hands a
// failover to the Server following the stranded run, else to the one serving
// the control plane, and to nobody when there is neither — never to a Server
// of some other control plane.
func TestFailoverServerFindsTheRunsFollower(t *testing.T) {
	cp := t.TempDir()
	other := &Server{WorkDir: t.TempDir()}
	registerRunServer(other)
	t.Cleanup(func() { unregisterRunServer(other) })
	if got := failoverServer(cp, "ex", "h", "/proj"); got != nil {
		t.Fatalf("failoverServer picked a Server of another control plane (%s)", got.WorkDir)
	}

	hub := &Server{WorkDir: cp}
	registerRunServer(hub)
	t.Cleanup(func() { unregisterRunServer(hub) })
	if got := failoverServer(cp, "ex", "h", "/proj"); got != hub {
		t.Fatal("failoverServer did not pick the Server serving the control plane")
	}

	follower := &Server{WorkDir: t.TempDir()}
	follower.trackRun("/proj", &stubExecutor{}, "h")
	registerRunServer(follower)
	t.Cleanup(func() { unregisterRunServer(follower) })
	stub := &stubExecutor{}
	if got := failoverServer(cp, stub.ID(), "h", "/proj"); got != follower {
		t.Fatal("failoverServer did not pick the Server following the stranded run")
	}
}
