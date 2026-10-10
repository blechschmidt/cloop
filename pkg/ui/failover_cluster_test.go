package ui

// A failed-over run on a hub cluster (Task 20396): the replacement is started
// — and followed — by the member able to start it, which is not the one that
// followed the stranded run. Two real Servers with their own hubcluster.Node
// over one state.db, as in cluster_test.go; the supervisor runs in the member
// that followed the stranded run, and the replacement executor is an edge
// agent whose socket the other member holds. tests/cluster runs the same
// shape with real processes and real agents.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TestFailedOverRunIsFollowedByTheMemberHoldingItsReplacement: member A
// follows a run on device 1; device 1 is lost; the replacement goes to device
// 2, an edge agent connected to member B. B starts it, takes the run's owner
// row over and follows it; A gives up the stranded run without settling the
// project under the replacement; the replacement's output reaches a dashboard
// attached to A; and when it ends B settles it — result merged, owner row
// released, A's dashboard told the run stopped.
func TestFailedOverRunIsFollowedByTheMemberHoldingItsReplacement(t *testing.T) {
	prevWrite := runProgressMinWrite.Swap(0)
	t.Cleanup(func() { runProgressMinWrite.Store(prevWrite) })
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	dir := setupProjectDir(t, "a failover across hub members", []*pm.Task{
		{ID: 1, Title: "only", Status: pm.TaskPending},
	})
	withControlPlaneDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(failoverConfig("")), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newClusterMember(t, dir)
	b := newClusterMember(t, dir)
	waitCluster(t, "the members to see each other", func() bool {
		return a.node.HasPeers() && b.node.HasPeers()
	})
	// The supervisor that notices device 1 is lost runs in A's process.
	prevCluster := processCluster.Load()
	processCluster.Store(a.node)
	t.Cleanup(func() { processCluster.Store(prevCluster) })

	suffix := strings.ReplaceAll(filepath.Base(dir), ".", "-")
	dev1 := newSeedNode(t, "dev1-"+suffix)
	dev2 := newSeedNode(t, "dev2-"+suffix)
	dev2.kind = executor.KindRemoteAgent
	reg := executor.NewRegistry()
	for _, n := range []*seedNode{dev1, dev2} {
		if err := reg.Register(n); err != nil {
			t.Fatal(err)
		}
		if err := executor.DefaultRegistry.Register(n); err != nil {
			t.Fatal(err)
		}
		node := n
		t.Cleanup(func() { executor.DefaultRegistry.Unregister(node.id) })
	}
	// Device 2's socket is held by B.
	if err := b.node.Assert(ownerAgent, dev2.id, nil); err != nil {
		t.Fatal(err)
	}
	if err := executor.Bind(dir, dev1.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	t.Cleanup(func() {
		dev1.endAll()
		dev2.endAll()
		waitCluster(t, "both members to stop following the project", func() bool {
			_, onA := a.srv.trackedRun(dir)
			_, onB := b.srv.trackedRun(dir)
			return !onA && !onB
		})
		awaitQuietProject(t, dir)
	})

	clock := &manualClock{now: time.Now()}
	sched, db, err := newScheduler(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := executor.DefaultSupervisorConfig()
	cfg.Policy = executor.HealthPolicy{DegradeAfter: 1, UnreachableAfter: 1}
	cfg.JitterFraction = 0
	sv := executor.NewSupervisor(reg, cfg,
		executor.WithClock(clock),
		executor.WithHealthStore(sched),
		executor.WithSessionStore(sched),
		executor.WithEventSink(sched),
		executor.WithFailoverHandler(failoverHandler(dir)),
		executor.WithFailoverLimit(failoverLimit),
		executor.WithCandidateFilter(failoverPlaceable),
	)

	// A dispatches the run to device 1 and follows it.
	ex, h1, err := startWorkloadAs(nil, newHarnessClearance(dir, harnessWho{}, ""), "",
		dir, []string{"cloop", "run"}, map[string]string{"handler": "run"})
	if err != nil {
		t.Fatal(err)
	}
	followTestRun(t, a.srv, dir, ex, h1)
	if o, _, found := a.srv.clusterRunOwner(dir); !found || !o.Self {
		t.Fatal("A does not own the run it dispatched")
	}
	ws := openProjectStream(t, a.ts, 0)
	dev1.say(t, h1.ID, "━━━ Task 1/1: only ━━━")

	// Device 1 is lost.
	dev1.kill()
	clock.advance(time.Hour)
	sv.ProbeOnce(context.Background())

	// B started the replacement on device 2 and follows it.
	if got := dev2.startCount(); got != 1 {
		t.Fatalf("device 2 started %d workloads, want the replacement", got)
	}
	w2 := dev2.last(t)
	waitCluster(t, "B to follow the replacement", func() bool {
		run, ok := b.srv.trackedRun(dir)
		return ok && run.handleID == w2.handle
	})
	if o, meta, found := b.srv.clusterRunOwner(dir); !found || !o.Self || meta.Handle != w2.handle || meta.Executor != dev2.id {
		t.Fatalf("the run's owner row = %+v (%+v, found %v), want B's, naming the replacement", o, meta, found)
	}
	if w2.dir == "" || w2.spec.Labels["handler"] != "failover" {
		t.Fatalf("the replacement was not dispatched as a run of the project: seed %q, labels %v", w2.dir, w2.spec.Labels)
	}
	// A let the stranded run go — told by B — and did not settle the project.
	waitCluster(t, "A to give up the stranded run", func() bool {
		_, ok := a.srv.trackedRun(dir)
		return !ok
	})
	if w1, _ := dev1.workload(h1.ID); w1 == nil || w1.abandoned == "" {
		t.Fatal("A did not abandon the stranded run")
	}
	if st, err := state.LoadLite(dir); err != nil || (st.PauseReason != nil && st.PauseReason.Code == "executor_lost") {
		t.Fatalf("the project was settled as lost although its run failed over: %+v, %v", st, err)
	}
	if !a.srv.projectExecuting(dir) || !b.srv.projectExecuting(dir) {
		t.Fatal("a member reads the failed-over project as not executing")
	}

	// The replacement's output reaches a dashboard attached to A.
	dev2.say(t, w2.handle, "replacement on the other member")
	ws.waitFor(t, "the replacement's output, relayed from B", "step_output", "replacement on the other member")

	// It finishes on device 2; B merges the result and settles the run.
	mark := ws.count()
	dev2.complete(t, w2.handle, func(st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		st.Status = "complete"
	})
	waitCluster(t, "B to settle the replacement", func() bool {
		_, ok := b.srv.trackedRun(dir)
		return !ok
	})
	waitCluster(t, "the run's owner row to be released", func() bool {
		_, _, found := b.srv.clusterRunOwner(dir)
		return !found
	})
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if task := st.Plan.TaskByID(1); task.Status != pm.TaskDone {
		t.Fatalf("task 1 is %s after the replacement finished it on device 2", task.Status)
	}
	ws.waitForAfter(t, mark, "the replacement's end, relayed", "run_state", `"running":false`)
	if a.srv.projectExecuting(dir) || b.srv.projectExecuting(dir) {
		t.Fatal(fmt.Sprintf("the project still executes after its replacement ended (A %v, B %v)",
			a.srv.projectExecuting(dir), b.srv.projectExecuting(dir)))
	}
}

// TestABindingChangeReachesEveryMember: the executor registry consults its
// in-memory mirror of a project's binding before the database, and a member
// mirrors the bindings it makes. A project rebound through one member — away
// from a device that was lost, say — was therefore still dispatched to the old
// executor by a member that had mirrored the old binding. A binding change is
// now published, and every member drops its mirror so the database answers
// (Task 20396).
func TestABindingChangeReachesEveryMember(t *testing.T) {
	dir, a, b := clusterPair(t)
	_ = a
	// The mirror a member would hold of a binding made through it.
	if err := executor.Bind(dir, "stale-executor"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	if id, ok := executor.DefaultRegistry.Binding(dir); !ok || id != "stale-executor" {
		t.Fatalf("binding = %q, %v; want the mirrored stale-executor", id, ok)
	}
	b.srv.publishBindingChange(dir)
	waitCluster(t, "the stale mirror to be dropped on the other member", func() bool {
		id, ok := executor.DefaultRegistry.Binding(dir)
		return !ok || id != "stale-executor"
	})
}
