package ui

// The failover cap and the node-killer quarantine, end to end through the hub
// (Task 20391): the production supervisor wiring — the SQL session store, the
// audit sink, failoverHandler, the cap read from the hub's configuration —
// over fake executors the test kills one after another. Since Task 20396 the
// hub follows each run the way it follows one a person started, so a
// replacement is the project's run, and a run nothing replaced leaves the
// project paused with the lost executor named.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// dyingNode is an executor the test takes down at will. It shares the hub's
// filesystem, as a container on the hub's own host does, so a dispatch needs
// no project seed. Each workload it starts streams what the test writes into
// it, one line at a time, to every subscriber — the hub's session watcher and
// the run's own follower both read it — and each send returns only once every
// subscriber has taken the line.
type dyingNode struct {
	id string

	mu      sync.Mutex
	down    bool
	starts  int
	subs    map[string][]*nodeSub
	ended   map[string]bool
	signals map[string][]executor.Signal
}

// nodeSub is one subscriber to a workload's output.
type nodeSub struct {
	ch     chan executor.LogLine
	gone   chan struct{}
	mu     sync.Mutex
	closed bool
}

// close ends the subscription: gone first, which releases a sender blocked on
// it, then the channel, under the lock a sender holds while it sends.
func (s *nodeSub) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.gone)
	close(s.ch)
}

func newDyingNode(id string) *dyingNode {
	return &dyingNode{
		id: id, subs: map[string][]*nodeSub{}, ended: map[string]bool{},
		signals: map[string][]executor.Signal{},
	}
}

func (n *dyingNode) ID() string   { return n.id }
func (n *dyingNode) Kind() string { return executor.KindContainer }
func (n *dyingNode) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation: executor.IsolationContainer, SupportsStream: true, MaxConcurrent: 4,
		SharesHostFilesystem: true, Platform: "linux", Arch: "amd64",
	}
}

func (n *dyingNode) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return executor.Handle{}, fmt.Errorf("dial %s: connection refused", n.id)
	}
	n.starts++
	id := fmt.Sprintf("h-%s-%d", n.id, n.starts)
	n.subs[id] = nil
	return executor.Handle{ID: id, ExecutorID: n.id, StartedAt: time.Now()}, nil
}

// Signal records the signal; a node that died hears nothing, and one that
// lives ends the workload on a kill, as a container runtime does.
func (n *dyingNode) Signal(_ context.Context, handleID string, sig executor.Signal) error {
	n.mu.Lock()
	n.signals[handleID] = append(n.signals[handleID], sig)
	down := n.down
	n.mu.Unlock()
	if down {
		return fmt.Errorf("dial %s: connection refused", n.id)
	}
	if sig == executor.SignalKill || sig == executor.SignalInterrupt {
		n.end(handleID)
	}
	return nil
}

// Status cannot tell a node that died from one that is slow, like a driver
// whose daemon stopped answering: running until the workload ended.
func (n *dyingNode) Status(_ context.Context, handleID string) (executor.Status, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ended[handleID] {
		return executor.Status{HandleID: handleID, ExecutorID: n.id, State: executor.StateExited}, nil
	}
	return executor.Status{HandleID: handleID, ExecutorID: n.id, State: executor.StateRunning}, nil
}

// Stream never closes on its own: a node that died does not tell anyone its
// workloads ended. A subscription ends with its context, or when the test
// ends the workload.
func (n *dyingNode) Stream(ctx context.Context, handleID string) (<-chan executor.LogLine, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.subs[handleID]; !ok && !n.ended[handleID] {
		return nil, executor.ErrHandleNotFound
	}
	sub := &nodeSub{ch: make(chan executor.LogLine), gone: make(chan struct{})}
	if n.ended[handleID] {
		sub.close()
		return sub.ch, nil
	}
	n.subs[handleID] = append(n.subs[handleID], sub)
	go func() {
		select {
		case <-ctx.Done():
			sub.close()
		case <-sub.gone:
		}
	}()
	return sub.ch, nil
}

func (n *dyingNode) HealthCheck(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return fmt.Errorf("dial %s: connection refused", n.id)
	}
	return nil
}

func (n *dyingNode) kill() {
	n.mu.Lock()
	n.down = true
	n.mu.Unlock()
}

// revive brings a node back, as a device that panicked comes back after its
// reboot.
func (n *dyingNode) revive() {
	n.mu.Lock()
	n.down = false
	n.mu.Unlock()
}

func (n *dyingNode) startCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.starts
}

// end finishes a workload: its status turns terminal and every stream of it
// closes.
func (n *dyingNode) end(handleID string) {
	n.mu.Lock()
	subs := n.subs[handleID]
	delete(n.subs, handleID)
	n.ended[handleID] = true
	n.mu.Unlock()
	for _, s := range subs {
		s.close()
	}
}

// say writes one line of the run's output on handleID and waits until every
// subscriber — the session watcher included — has acted on it.
func (n *dyingNode) say(t *testing.T, handleID, line string) {
	t.Helper()
	waitWatchers(t, handleID, func() int {
		n.mu.Lock()
		defer n.mu.Unlock()
		return len(n.subs[handleID])
	})
	for _, text := range []string{line + "\n", "(sync)\n"} {
		n.mu.Lock()
		subs := append([]*nodeSub(nil), n.subs[handleID]...)
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

// workloadWatchers is how many subscribers a followed workload has: the
// hub's session watcher, which records the tasks a run announces, and the
// run's own follower, which streams its output to the dashboards.
const workloadWatchers = 2

// waitWatchers waits until a workload has its watchers. Both subscribe from
// goroutines of their own, so a line written the moment a run starts could
// otherwise reach one of them only.
func waitWatchers(t *testing.T, handleID string, count func() int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for count() < workloadWatchers {
		if time.Now().After(deadline) {
			t.Fatalf("workload %s has %d watchers, want %d", handleID, count(), workloadWatchers)
		}
		time.Sleep(time.Millisecond)
	}
}

// endAll ends every workload the node still has.
func (n *dyingNode) endAll() {
	n.mu.Lock()
	ids := make([]string, 0, len(n.subs))
	for id := range n.subs {
		ids = append(ids, id)
	}
	n.mu.Unlock()
	for _, id := range ids {
		n.end(id)
	}
}

// manualClock is a supervisor clock the test moves by hand.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *manualClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }
func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// failoverRig is a project, three nodes registered with the hub, the hub's
// Server following the project's runs, and a supervisor wired the way
// startExecutorSupervisor wires one.
type failoverRig struct {
	dir   string
	srv   *Server
	nodes []*dyingNode
	sv    *executor.Supervisor
	clock *manualClock
	sched *executorstore.Scheduler
	db    *statedb.DB
}

// failoverConfig is the project's config.yaml for a failover test: the mock
// provider, so a dispatch to an isolating executor needs no Claude credential,
// plus whatever the test adds.
func failoverConfig(extra string) string {
	return "provider: mock\n" + extra
}

func newFailoverRig(t *testing.T, configYAML string, tasks []*pm.Task) *failoverRig {
	t.Helper()
	// Every announcement is written as it arrives, so a node the test kills
	// straight after one is charged with it.
	prevWrite := runProgressMinWrite.Swap(0)
	t.Cleanup(func() { runProgressMinWrite.Store(prevWrite) })
	dir := setupProjectDir(t, "failover cap", tasks)
	withControlPlaneDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(failoverConfig(configYAML)), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &failoverRig{dir: dir, clock: &manualClock{now: time.Now()}}
	reg := executor.NewRegistry()
	suffix := strings.ReplaceAll(filepath.Base(dir), ".", "-")
	for _, name := range []string{"n1", "n2", "n3"} {
		n := newDyingNode(name + "-" + suffix)
		r.nodes = append(r.nodes, n)
		if err := reg.Register(n); err != nil {
			t.Fatal(err)
		}
		// A replacement is found in the process registry.
		if err := executor.DefaultRegistry.Register(n); err != nil {
			t.Fatal(err)
		}
		node := n
		t.Cleanup(func() { executor.DefaultRegistry.Unregister(node.id) })
	}
	// The hub serving this control plane, which follows the runs.
	r.srv = New(dir, 0, "")

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
	// Registered last, so it runs first: every run still in flight ends and is
	// settled before the project directory goes, rather than writing into it
	// while it is removed.
	t.Cleanup(func() { r.endRuns(t) })
	return r
}

// endRuns ends every workload on every node and waits for the hub to settle
// the project's run.
func (r *failoverRig) endRuns(t *testing.T) {
	t.Helper()
	for _, n := range r.nodes {
		n.endAll()
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := r.srv.trackedRun(r.dir); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("the hub still follows a run of %s after every workload ended", r.dir)
}

// dispatch starts the run on the first node the way the hub dispatches one —
// startWorkloadAs, with the project bound to that node — and follows it the
// way handleRun does.
func (r *failoverRig) dispatch(t *testing.T) (string, string) {
	t.Helper()
	n := r.nodes[0]
	if err := executor.Bind(r.dir, n.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(r.dir) })
	ex, h, err := startWorkloadAs(nil, newHarnessClearance(r.dir, harnessWho{}, ""), "",
		r.dir, []string{"cloop", "run"}, map[string]string{"handler": "run"})
	if err != nil {
		t.Fatal(err)
	}
	followTestRun(t, r.srv, r.dir, ex, h)
	sessions, err := r.sched.RunningSessions(n.id)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("the dispatch was not recorded as one session: %v, %v", sessions, err)
	}
	return sessions[0].ID, h.ID
}

// followTestRun follows a dispatched run exactly as handleRun does after its
// startWorkloadAs: live log, tracked handle, owner row, run state, consumer.
func followTestRun(t *testing.T, s *Server, dir string, ex executor.Executor, h executor.Handle) {
	t.Helper()
	s.liveLogStartRun(dir)
	streamCtx, cancel := context.WithCancel(context.Background())
	s.trackRunWithCancel(dir, ex, h.ID, cancel)
	s.recordRunDispatch(dir, "run", ex, h.ID)
	s.broadcastRunState(dir, true, true)
	s.publishRunState(dir, true)
	lines, err := ex.Stream(streamCtx, h.ID)
	if err != nil {
		cancel()
		t.Fatalf("stream the run: %v", err)
	}
	go s.consumeRunOutput(dir, ex, h.ID, lines, nil)
}

// running returns the one session in flight, and the node holding it.
func (r *failoverRig) running(t *testing.T) (executor.Session, *dyingNode) {
	t.Helper()
	sessions, err := r.sched.RunningSessions("")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("%d sessions in flight, want 1", len(sessions))
	}
	for _, n := range r.nodes {
		if n.id == sessions[0].ExecutorID {
			return sessions[0], n
		}
	}
	t.Fatalf("session %s runs on %s, which is not one of the test's nodes", sessions[0].ID, sessions[0].ExecutorID)
	return executor.Session{}, nil
}

// killAndProbe takes n down and lets the supervisor notice.
func (r *failoverRig) killAndProbe(n *dyingNode) {
	n.kill()
	r.clock.advance(time.Hour) // every node is due for a probe again
	r.sv.ProbeOnce(context.Background())
}

func (r *failoverRig) redispatches() int {
	total := 0
	for _, n := range r.nodes {
		total += n.startCount()
	}
	return total - 1 // the first start is the dispatch, not a failover
}

func (r *failoverRig) task(t *testing.T, id int) *pm.Task {
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

func (r *failoverRig) auditRows(t *testing.T, action auditaction.Action) []map[string]any {
	t.Helper()
	rows, _, err := r.db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, row := range rows {
		var p map[string]any
		_ = json.Unmarshal([]byte(row.Payload), &p)
		out = append(out, p)
	}
	return out
}

func (r *failoverRig) journal(t *testing.T) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(r.dir, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	var out []state.EventRow
	for _, row := range rows {
		if row.Type == state.EventFailover {
			out = append(out, row)
		}
	}
	return out
}

// requireLost asserts the project is no longer running and is paused with an
// executor_lost reason naming exec, and that the hub follows no run of it.
func (r *failoverRig) requireLost(t *testing.T, exec string, contains ...string) {
	t.Helper()
	if _, ok := r.srv.trackedRun(r.dir); ok {
		t.Fatal("the hub still follows a run of a project whose executor was lost")
	}
	if r.srv.projectExecuting(r.dir) {
		t.Fatal("a project whose executor was lost is still executing")
	}
	st, err := state.LoadLite(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeExecutorLost {
		t.Fatalf("the project is %q with reason %+v, want paused executor_lost", st.Status, st.PauseReason)
	}
	for _, want := range append([]string{exec}, contains...) {
		if !strings.Contains(st.PauseReason.Detail, want) {
			t.Errorf("the pause reason %q does not say %q", st.PauseReason.Detail, want)
		}
	}
}

// TestFailoverCapStopsANodeKillerAtMaxAttempts is the scenario the cap exists
// for: a run that takes down every node it lands on. Its losses fall under a
// different task each time — as they do when the run itself, not one task,
// takes the node down — so no task is quarantined, and the cap is what stops
// it. With executors.failover.max_attempts at its default of 2 and three
// nodes, the hub re-dispatches exactly twice, and when the third node goes
// down the run is carried nowhere — not even back to the first node, which
// has rebooted and is healthy. The task it was running last fails, naming
// every node, and the project is paused with the lost executor named.
func TestFailoverCapStopsANodeKillerAtMaxAttempts(t *testing.T) {
	r := newFailoverRig(t, "", []*pm.Task{
		{ID: 1, Title: "first", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "second", Status: pm.TaskPending, Priority: 2},
		{ID: 3, Title: "third", Status: pm.TaskPending, Priority: 3},
	})
	if got := failoverLimit(); got != 2 {
		t.Fatalf("the hub's cap is %d, want the default 2", got)
	}

	first, handle := r.dispatch(t)
	r.nodes[0].say(t, handle, "━━━ Task 1/3: first ━━━")

	// Node 1 dies running task 1: the task goes back to pending for the
	// replacement, and the run is re-dispatched.
	r.killAndProbe(r.nodes[0])
	if got := r.redispatches(); got != 1 {
		t.Fatalf("%d re-dispatches after the first lost node, want 1", got)
	}
	if task := r.task(t, 1); task.Status != pm.TaskPending || task.Quarantined() {
		t.Fatalf("after one lost node task 1 is %s (quarantined %v), want pending for a retry", task.Status, task.Quarantined())
	}

	// The replacement finishes task 1 and is on task 2 when its node dies.
	sess, node := r.running(t)
	if sess.Attempt != 2 {
		t.Fatalf("the replacement is attempt %d, want 2", sess.Attempt)
	}
	node.say(t, sess.HandleID, "✓ Task 1 complete: first")
	node.say(t, sess.HandleID, "━━━ Task 2/3: second ━━━")
	r.killAndProbe(node)
	if got := r.redispatches(); got != 2 {
		t.Fatalf("%d re-dispatches after the second lost node, want 2", got)
	}
	if task := r.task(t, 2); task.Status != pm.TaskPending || task.Quarantined() {
		t.Fatalf("task 2 is %s (quarantined %v), want pending: one node went down under it", task.Status, task.Quarantined())
	}

	// The last replacement is on task 3 when its node goes down too.
	// Meanwhile the first node has rebooted and is healthy again, so a hub
	// without the cap would have somewhere to send the run. That is the cap:
	// nothing re-dispatches.
	last, node := r.running(t)
	if last.Attempt != 3 {
		t.Fatalf("the last replacement is attempt %d, want 3", last.Attempt)
	}
	node.say(t, last.HandleID, "✓ Task 2 complete: second")
	node.say(t, last.HandleID, "━━━ Task 3/3: third ━━━")
	r.nodes[0].revive()
	r.clock.advance(time.Hour)
	r.sv.ProbeOnce(context.Background())
	if h := r.sv.Health(r.nodes[0].id); h.State != executor.NodeReady {
		t.Fatalf("the rebooted node is %s, want ready — the cap must be what stops the run, not a lack of nodes", h.State)
	}
	r.killAndProbe(node)
	if got := r.redispatches(); got != 2 {
		t.Fatalf("%d re-dispatches in all, want exactly max_attempts = 2", got)
	}
	if got := r.nodes[0].startCount(); got != 1 {
		t.Fatalf("the rebooted node was handed the run again (%d starts)", got)
	}
	if sessions, _ := r.sched.RunningSessions(""); len(sessions) != 0 {
		t.Fatalf("%d sessions still in flight after the cap, want none", len(sessions))
	}
	row, err := r.db.GetExecutorSession(last.ID)
	if err != nil || row.State != statedb.ExecutorSessionFailoverExhausted {
		t.Fatalf("the last session is %q (%v), want failover_exhausted", row.State, err)
	}
	if lost, _ := r.sched.LostNodes(last.ID); len(lost) != 3 || lost[0].SessionID != first {
		t.Fatalf("the run's lost nodes = %+v, want all three, starting with the first dispatch", lost)
	}

	// The task it was on fails, naming every node and when.
	task := r.task(t, 3)
	if task.Status != pm.TaskFailed || task.Quarantined() {
		t.Fatalf("task 3 is %s (quarantined %v), want failed and not quarantined", task.Status, task.Quarantined())
	}
	for _, n := range r.nodes {
		if !strings.Contains(task.Result, n.id) {
			t.Errorf("the failure reason %q does not name %s", task.Result, n.id)
		}
	}
	if !strings.Contains(task.Result, "unreachable 20") {
		t.Errorf("the failure reason %q does not say when the nodes went unreachable", task.Result)
	}
	if v, err := taskrecover.ReadVerdict(r.dir, 3); err != nil || v.Status != pm.TaskFailed || v.Source != taskrecover.SourceFailover {
		t.Fatalf("verdict = %+v, %v; want a failover verdict failing the task, for recovery to honour", v, err)
	}
	// The project stops with the last executor (Task 20396).
	r.requireLost(t, node.id, "max_attempts")

	// Audited through the registry.
	if got := r.auditRows(t, auditaction.ActionExecutorFailover); len(got) != 2 {
		t.Errorf("%d executor.failover rows, want 2", len(got))
	}
	exhausted := r.auditRows(t, auditaction.ActionExecutorFailoverExhausted)
	if len(exhausted) != 1 {
		t.Fatalf("%d executor.failover_exhausted rows, want 1", len(exhausted))
	}
	if nodes, _ := exhausted[0]["nodes"].([]any); len(nodes) != 3 {
		t.Errorf("the exhausted row names %d nodes, want all 3: %v", len(nodes), exhausted[0])
	}

	// Journalled for the developer: each requeue, each failover, and the run
	// that was not re-dispatched, naming every node.
	var requeued, failedOver, stopped int
	for _, e := range r.journal(t) {
		switch {
		case strings.Contains(e.Message, "requeued for retry"):
			requeued++
		case strings.Contains(e.Message, "Run failed over from executor"):
			failedOver++
		case strings.Contains(e.Message, "was lost and the run was not re-dispatched"):
			stopped++
			for _, n := range r.nodes {
				if !strings.Contains(e.Message, n.id) {
					t.Errorf("the exhaustion row does not name %s: %q", n.id, e.Message)
				}
			}
		}
	}
	if requeued != 2 || failedOver != 2 || stopped != 1 {
		t.Errorf("journal rows: %d requeued, %d failed over, %d stopped; want 2, 2, 1", requeued, failedOver, stopped)
	}
}

// TestFailoverStopsAtAQuarantinedNodeKiller: a task two distinct nodes went
// down under is quarantined, and the run is not carried to a third node
// (Task 20396): the replacement's gate would hold that task anyway, and the
// attribution that convicted it is the run's own account. The project leaves
// "running" at once, paused naming the lost executor and the quarantine, and
// the task runs again only after an explicit reset.
func TestFailoverStopsAtAQuarantinedNodeKiller(t *testing.T) {
	r := newFailoverRig(t, "", []*pm.Task{
		{ID: 1, Title: "fork bomb", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "innocent", Status: pm.TaskPending, Priority: 2},
	})
	_, handle := r.dispatch(t)
	r.nodes[0].say(t, handle, "━━━ Task 1/2: fork bomb ━━━")
	r.killAndProbe(r.nodes[0])
	if got := r.redispatches(); got != 1 {
		t.Fatalf("%d re-dispatches after the first lost node, want 1", got)
	}

	// The replacement picks task 1 up again, and its node dies too: two
	// distinct nodes under one task.
	sess, node := r.running(t)
	node.say(t, sess.HandleID, "━━━ Task 1/2: fork bomb ━━━")
	r.killAndProbe(node)

	if got := r.redispatches(); got != 1 {
		t.Fatalf("%d re-dispatches, want 1: a quarantine stops the run", got)
	}
	task := r.task(t, 1)
	if task.Status != pm.TaskFailed || !task.Quarantined() {
		t.Fatalf("after two distinct lost nodes task 1 is %s (quarantined %v), want failed and quarantined", task.Status, task.Quarantined())
	}
	if nodes := pm.DistinctNodes(task.Quarantine.Nodes); len(nodes) != 2 || nodes[0] != r.nodes[0].id {
		t.Fatalf("the mark names %v, want the two nodes that went down, first one first", nodes)
	}
	if other := r.task(t, 2); other.Status != pm.TaskPending || other.Quarantined() {
		t.Fatalf("task 2 is %s (quarantined %v); nothing went down under it", other.Status, other.Quarantined())
	}
	if got := r.nodes[2].startCount(); got != 0 {
		t.Fatalf("the third node was handed the run (%d starts)", got)
	}
	r.requireLost(t, node.id, "task 1", "quarantined")
	if got := r.auditRows(t, auditaction.ActionTaskQuarantine); len(got) != 1 {
		t.Errorf("%d task.quarantine rows, want 1", len(got))
	}
	// The supervisor's record says why nothing was re-dispatched.
	var stopped bool
	for _, row := range r.auditRows(t, auditaction.ActionExecutorFailover) {
		if e, _ := row["error"].(string); strings.Contains(e, "quarantined") {
			stopped = true
		}
	}
	if !stopped {
		t.Error("no executor.failover row says the quarantine stopped the run")
	}

	// --retry-failed's automatic reset leaves it alone; only an explicit
	// reset releases it, and then it starts with no evidence against it.
	mark, err := state.ReleaseQuarantine(r.dir, 1, "operator@example", "test")
	if err != nil || mark == nil {
		t.Fatalf("ReleaseQuarantine = %v, %v; want the mark back", mark, err)
	}
	if r.task(t, 1).Quarantined() {
		t.Fatal("the mark survived the explicit reset")
	}
	if losses, _ := r.db.TaskNodeLosses(1); len(losses) != 0 {
		t.Fatalf("the reset left %d losses on the task", len(losses))
	}
	if got := r.auditRows(t, auditaction.ActionTaskQuarantineRelease); len(got) != 1 {
		t.Errorf("%d task.quarantine_release rows, want 1", len(got))
	}
}

// TestFailoverExhaustedFailsTheTaskNamingEachNode: a run that loses a node
// under each of two different tasks is no node killer — but with
// max_attempts 1 the second loss is past the cap, and the task it was running
// fails, naming both nodes and when, instead of going back to pending for the
// next dispatch to carry onto a third node. The cap comes from the hub's
// config.yaml, read at the claim.
func TestFailoverExhaustedFailsTheTaskNamingEachNode(t *testing.T) {
	r := newFailoverRig(t, "executors:\n  failover:\n    max_attempts: 1\n", []*pm.Task{
		{ID: 1, Title: "first", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "second", Status: pm.TaskPending, Priority: 2},
	})
	if got := failoverLimit(); got != 1 {
		t.Fatalf("the hub's cap is %d, want config.yaml's 1", got)
	}

	_, handle := r.dispatch(t)
	r.nodes[0].say(t, handle, "━━━ Task 1/2: first ━━━")
	r.killAndProbe(r.nodes[0])
	if got := r.redispatches(); got != 1 {
		t.Fatalf("%d re-dispatches, want 1", got)
	}

	// The replacement finishes task 1 and moves on to task 2 before its node
	// goes down — as a run on a device reports it, so the hub's own plan never
	// shows task 2 in progress.
	sess, node := r.running(t)
	node.say(t, sess.HandleID, "✓ Task 1 complete: first")
	node.say(t, sess.HandleID, "━━━ Task 2/2: second ━━━")
	r.killAndProbe(node)

	if got := r.redispatches(); got != 1 {
		t.Fatalf("%d re-dispatches, want exactly max_attempts = 1", got)
	}
	task := r.task(t, 2)
	if task.Status != pm.TaskFailed {
		t.Fatalf("task 2 is %s, want failed — not quietly pending for the next dispatch", task.Status)
	}
	if task.Quarantined() {
		t.Fatal("task 2 was quarantined; only one node went down under it")
	}
	for _, n := range []*dyingNode{r.nodes[0], node} {
		if !strings.Contains(task.Result, n.id) {
			t.Errorf("the reason %q does not name %s", task.Result, n.id)
		}
	}
	if !strings.Contains(task.Result, "max_attempts (1)") {
		t.Errorf("the reason %q does not name the cap", task.Result)
	}
	if v, err := taskrecover.ReadVerdict(r.dir, 2); err != nil || v.Reason != failoverReasonExhausted {
		t.Fatalf("verdict = %+v, %v; want failover_exhausted", v, err)
	}
	// Task 1 lost one node and finished on the next; it is not blamed again.
	if first := r.task(t, 1); first.Quarantined() || first.Status == pm.TaskFailed {
		t.Fatalf("task 1 is %s (quarantined %v)", first.Status, first.Quarantined())
	}
	r.requireLost(t, node.id)
}

// TestRedispatchRefusesAnExhaustedSession: whatever an event claims — it can
// arrive from another hub member — a session the claim did not leave
// requeued, or one already replaced, is never started again.
func TestRedispatchRefusesAnExhaustedSession(t *testing.T) {
	r := newFailoverRig(t, "executors:\n  failover:\n    max_attempts: 0\n", []*pm.Task{
		{ID: 1, Title: "t", Status: pm.TaskPending},
	})
	id, _ := r.dispatch(t)
	r.killAndProbe(r.nodes[0])
	if got := r.redispatches(); got != 0 {
		t.Fatalf("%d re-dispatches under max_attempts 0, want none", got)
	}

	sess, err := r.db.GetExecutorSession(id)
	if err != nil || sess.State != statedb.ExecutorSessionFailoverExhausted {
		t.Fatalf("session = %q, %v", sess.State, err)
	}
	ev := executor.FailoverEvent{
		From: r.nodes[0].id, To: r.nodes[1].id,
		Session: executor.Session{ID: id, Spec: executor.Spec{WorkDir: r.dir, Argv: []string{"cloop", "run"}}},
	}
	if err := redispatchSession(context.Background(), r.dir, ev, r.srv); err == nil {
		t.Fatal("an exhausted session was re-dispatched on a forged event")
	}
	if err := r.srv.startReplacement(context.Background(), r.dir, ev); err == nil {
		t.Fatal("an exhausted session was re-dispatched through the agent-owner path")
	}
	if r.nodes[1].startCount() != 0 {
		t.Fatal("the replacement was started")
	}
	r.requireLost(t, r.nodes[0].id, "max_attempts")
}

// TestFailoverWithNowhereToGoRequeuesTheTasks: a lost node's run with no
// executor left to take it is settled all the same — its task goes back to
// pending with its fail count raised, as failover always documented, rather
// than staying in progress on a dead node — nothing is started, and the
// project leaves "running" naming the lost executor (Task 20396).
func TestFailoverWithNowhereToGoRequeuesTheTasks(t *testing.T) {
	r := newFailoverRig(t, "", []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskPending}})
	_, handle := r.dispatch(t)
	r.nodes[0].say(t, handle, "━━━ Task 1/1: t ━━━")

	// The other two go down first, in a round of their own, so the lost
	// node's failover finds them already unreachable.
	for _, n := range r.nodes[1:] {
		n.kill()
	}
	r.clock.advance(time.Hour)
	r.sv.ProbeOnce(context.Background())
	for _, n := range r.nodes[1:] {
		if h := r.sv.Health(n.id); h.State != executor.NodeUnreachable {
			t.Fatalf("%s is %s, want unreachable before the run's own node goes", n.id, h.State)
		}
	}
	r.killAndProbe(r.nodes[0])

	if got := r.redispatches(); got != 0 {
		t.Fatalf("%d re-dispatches with every node down, want none", got)
	}
	task := r.task(t, 1)
	if task.Status != pm.TaskPending || task.FailCount != 1 || task.Quarantined() {
		t.Fatalf("task 1 is %s (fail count %d, quarantined %v), want pending for a retry with its count raised",
			task.Status, task.FailCount, task.Quarantined())
	}
	var said bool
	for _, e := range r.journal(t) {
		if strings.Contains(e.Message, r.nodes[0].id+" was lost") && strings.Contains(e.Message, "no executor could take its run") {
			said = true
		}
	}
	if !said {
		t.Error("the journal does not say the run had nowhere to go")
	}
	r.requireLost(t, r.nodes[0].id, "no executor could take the run")
}
