package state

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestARunningPlanAdoptsAQuarantineAndItsRelease: the mark is never the run's
// to write (Task 20391), so a run holding the plan takes the database's word
// for it at each sync — a task marked meanwhile is held from the next sync,
// and one a person released may run again — while the run's own save still
// cannot write a mark back or away.
func TestARunningPlanAdoptsAQuarantineAndItsRelease(t *testing.T) {
	dir := t.TempDir()
	run, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	run.PMMode = true
	run.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{{ID: 1, Title: "suspect", Status: pm.TaskPending}}}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}

	db, err := statedb.Open(DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mark := pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller, MarkedAt: time.Now(), Nodes: []pm.NodeLoss{
		{ExecutorID: "a", SessionID: "s1"}, {ExecutorID: "b", SessionID: "s2"},
	}}
	if err := db.PutTaskQuarantine(1, mark); err != nil {
		t.Fatal(err)
	}

	run.SyncFromDisk()
	if !run.Plan.TaskByID(1).Quarantined() {
		t.Fatal("a mark made while the run held the plan was not adopted at its sync")
	}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	if q, _ := db.TaskQuarantine(1); q == nil {
		t.Fatal("the run's save erased the mark")
	}

	if _, err := ReleaseQuarantine(dir, 1, "operator", "test"); err != nil {
		t.Fatal(err)
	}
	run.SyncFromDisk()
	if run.Plan.TaskByID(1).Quarantined() {
		t.Fatal("a release was not adopted: the run would hold a task a person reset")
	}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	if q, _ := db.TaskQuarantine(1); q != nil {
		t.Fatal("the run's save wrote a released mark back")
	}
}
