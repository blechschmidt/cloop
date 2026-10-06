package ui

// The failover cap and the node-killer quarantine, end to end through the hub
// (Task 20391): the production supervisor wiring — the SQL session store, the
// audit sink, failoverHandler, the cap read from the hub's configuration —
// over fake executors the test kills one after another.

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
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// dyingNode is an executor the test takes down at will. Each workload it
// starts gets a stream the test writes the run's output into, one line at a
// time: an unbuffered channel, so a send returns only once the hub's session
// watcher has taken the line — and a second send only once it has finished
// acting on the first.
type dyingNode struct {
	id string

	mu      sync.Mutex
	down    bool
	starts  int
	streams map[string]chan executor.LogLine
}

func newDyingNode(id string) *dyingNode {
	return &dyingNode{id: id, streams: map[string]chan executor.LogLine{}}
}

func (n *dyingNode) ID() string   { return n.id }
func (n *dyingNode) Kind() string { return executor.KindContainer }
func (n *dyingNode) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation: executor.IsolationContainer, SupportsStream: true, MaxConcurrent: 4,
		Platform: "linux", Arch: "amd64",
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
	n.streams[id] = make(chan executor.LogLine)
	return executor.Handle{ID: id, ExecutorID: n.id, StartedAt: time.Now()}, nil
}

func (n *dyingNode) Signal(context.Context, string, executor.Signal) error { return nil }
func (n *dyingNode) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{State: executor.StateRunning}, nil
}

// Stream never closes on its own: a node that died does not tell anyone its
// workloads ended. The test's cleanup closes them.
func (n *dyingNode) Stream(_ context.Context, handleID string) (<-chan executor.LogLine, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch, ok := n.streams[handleID]
	if !ok {
		return nil, executor.ErrHandleNotFound
	}
	return ch, nil
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

// say writes one line of the run's output on handleID and waits until the
// session watcher has acted on it.
func (n *dyingNode) say(t *testing.T, handleID, line string) {
	t.Helper()
	n.mu.Lock()
	ch := n.streams[handleID]
	n.mu.Unlock()
	if ch == nil {
		t.Fatalf("%s has no workload %s", n.id, handleID)
	}
	for _, text := range []string{line + "\n", "(sync)\n"} {
		select {
		case ch <- executor.LogLine{Text: text}:
		case <-time.After(10 * time.Second):
			t.Fatalf("nothing is watching workload %s on %s", handleID, n.id)
		}
	}
}

func (n *dyingNode) closeStreams() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, ch := range n.streams {
		close(ch)
		delete(n.streams, id)
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

// failoverRig is a project, three nodes registered with the hub, and a
// supervisor wired the way startExecutorSupervisor wires one.
type failoverRig struct {
	dir   string
	nodes []*dyingNode
	sv    *executor.Supervisor
	clock *manualClock
	sched *executorstore.Scheduler
	db    *statedb.DB
}

func newFailoverRig(t *testing.T, configYAML string, tasks []*pm.Task) *failoverRig {
	t.Helper()
	// Every announcement is written as it arrives, so a node the test kills
	// straight after one is charged with it.
	prevWrite := runProgressMinWrite.Swap(0)
	t.Cleanup(func() { runProgressMinWrite.Store(prevWrite) })
	dir := setupProjectDir(t, "failover cap", tasks)
	withControlPlaneDir(t, dir)
	if configYAML != "" {
		if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(configYAML), 0o600); err != nil {
			t.Fatal(err)
		}
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
		// redispatchSession finds the replacement in the process registry.
		if err := executor.DefaultRegistry.Register(n); err != nil {
			t.Fatal(err)
		}
		node := n
		t.Cleanup(func() {
			executor.DefaultRegistry.Unregister(node.id)
			node.closeStreams()
		})
	}

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
	)
	return r
}

// dispatch starts the run on the first node the way startWorkloadAs records
// one: a session, and the watcher that follows its output.
func (r *failoverRig) dispatch(t *testing.T) (string, string) {
	t.Helper()
	n := r.nodes[0]
	spec := executor.Spec{
		WorkDir: r.dir, Argv: []string{"cloop", "run"},
		Labels: map[string]string{"project": r.dir, "handler": "run"},
	}
	h, err := n.Start(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	id := openSessionFor(r.dir, n, h, spec)
	if id == "" {
		t.Fatal("the dispatch was not recorded as a session")
	}
	go watchSessionExit(r.dir, n, h.ID, id)
	return id, h.ID
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

// TestFailoverCapStopsANodeKillerAtMaxAttempts is the scenario the cap exists
// for. A run's task takes down every node it lands on. With
// executors.failover.max_attempts at its default of 2 and three nodes, the hub
// re-dispatches exactly twice; the task is quarantined once two distinct nodes
// have gone down under it, and fails naming them; and when the third node goes
// down the run is not carried anywhere else.
func TestFailoverCapStopsANodeKillerAtMaxAttempts(t *testing.T) {
	r := newFailoverRig(t, "", []*pm.Task{
		{ID: 1, Title: "fork bomb", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "innocent", Status: pm.TaskPending, Priority: 2},
	})
	if got := failoverLimit(); got != 2 {
		t.Fatalf("the hub's cap is %d, want the default 2", got)
	}

	first, handle := r.dispatch(t)
	r.nodes[0].say(t, handle, "━━━ Task 1/2: fork bomb ━━━")

	// Node 1 dies running task 1: the task goes back to pending for the
	// replacement, and the run is re-dispatched.
	r.killAndProbe(r.nodes[0])
	if got := r.redispatches(); got != 1 {
		t.Fatalf("%d re-dispatches after the first lost node, want 1", got)
	}
	if task := r.task(t, 1); task.Status != pm.TaskPending || task.Quarantined() {
		t.Fatalf("after one lost node task 1 is %s (quarantined %v), want pending for a retry", task.Status, task.Quarantined())
	}

	// The replacement picks task 1 up again, and its node dies too: two
	// distinct nodes under one task. It is quarantined and fails; the run
	// itself still has one re-dispatch left.
	sess, node := r.running(t)
	if sess.Attempt != 2 {
		t.Fatalf("the replacement is attempt %d, want 2", sess.Attempt)
	}
	node.say(t, sess.HandleID, "━━━ Task 1/2: fork bomb ━━━")
	r.killAndProbe(node)
	if got := r.redispatches(); got != 2 {
		t.Fatalf("%d re-dispatches after the second lost node, want 2", got)
	}
	task := r.task(t, 1)
	if task.Status != pm.TaskFailed || !task.Quarantined() {
		t.Fatalf("after two distinct lost nodes task 1 is %s (quarantined %v), want failed and quarantined", task.Status, task.Quarantined())
	}
	if nodes := pm.DistinctNodes(task.Quarantine.Nodes); len(nodes) != 2 || nodes[0] != r.nodes[0].id {
		t.Fatalf("the mark names %v, want the two nodes that went down, first one first", nodes)
	}
	for _, n := range pm.DistinctNodes(task.Quarantine.Nodes) {
		if !strings.Contains(task.Result, n) {
			t.Errorf("the failure reason %q does not name %s", task.Result, n)
		}
	}
	if !strings.Contains(task.Result, "unreachable 20") {
		t.Errorf("the failure reason %q does not say when the nodes went unreachable", task.Result)
	}
	if v, err := taskrecover.ReadVerdict(r.dir, 1); err != nil || v.Status != pm.TaskFailed || v.Source != taskrecover.SourceFailover {
		t.Fatalf("verdict = %+v, %v; want a failover verdict failing the task, for recovery to honour", v, err)
	}
	if other := r.task(t, 2); other.Status != pm.TaskPending || other.Quarantined() {
		t.Fatalf("task 2 is %s (quarantined %v); nothing went down under it", other.Status, other.Quarantined())
	}

	// The last replacement does not run task 1 — a real run's gate holds it —
	// and its node goes down anyway. Meanwhile the first node has rebooted and
	// is healthy again, so a hub without the cap would have somewhere to send
	// the run. That is the cap: nothing re-dispatches.
	last, node := r.running(t)
	if last.Attempt != 3 {
		t.Fatalf("the last replacement is attempt %d, want 3", last.Attempt)
	}
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

	// Audited through the registry, in both chains.
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
	if got := r.auditRows(t, auditaction.ActionTaskQuarantine); len(got) != 1 {
		t.Errorf("%d task.quarantine rows, want 1", len(got))
	}

	// Journalled for the developer: the requeue, the quarantine, and the run
	// that was not re-dispatched, naming every node.
	var requeued, quarantined, stopped bool
	for _, e := range r.journal(t) {
		switch {
		case strings.Contains(e.Message, "requeued for retry"):
			requeued = true
		case strings.Contains(e.Message, "quarantined as a suspected node killer"):
			quarantined = true
		case strings.Contains(e.Message, "run not re-dispatched"):
			stopped = true
			for _, n := range r.nodes {
				if !strings.Contains(e.Message, n.id) {
					t.Errorf("the exhaustion row does not name %s: %q", n.id, e.Message)
				}
			}
		}
	}
	if !requeued || !quarantined || !stopped {
		t.Errorf("journal rows: requeued %v, quarantined %v, run stopped %v; want all three", requeued, quarantined, stopped)
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
	if err := redispatchSession(context.Background(), r.dir, ev); err == nil {
		t.Fatal("an exhausted session was re-dispatched on a forged event")
	}
	if r.nodes[1].startCount() != 0 {
		t.Fatal("the replacement was started")
	}
}

// TestFailoverWithNowhereToGoRequeuesTheTasks: a lost node's run with no
// executor left to take it is settled all the same — its task goes back to
// pending with its fail count raised, as failover always documented, rather
// than staying in progress on a dead node — and nothing is started.
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
		if strings.Contains(e.Message, "no executor could take its run") {
			said = true
		}
	}
	if !said {
		t.Error("the journal does not say the run had nowhere to go")
	}
}
