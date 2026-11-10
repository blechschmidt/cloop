package statedb

// Tests for Task 20486's storage: a task's pool placement, a cordoned pool,
// what a controller says of itself and its volumes.

import (
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestPoolPlacementNamesTheTasksRunner: every reader joins the placement in by
// the task's executor id, and no save writes it — a stale copy that names
// another pool cannot change what the record says.
func TestPoolPlacementNamesTheTasksRunner(t *testing.T) {
	db := openFresh(t)
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "on a runner", Status: pm.TaskDone, ExecutorID: "agent-1", ExecutorKind: "remote"},
		{ID: 2, Title: "on the host", Status: pm.TaskDone, ExecutorID: "local", ExecutorKind: "localprocess"},
		{ID: 3, Title: "not run", Status: pm.TaskPending},
	}}
	if err := db.SaveState(&State{Goal: "g", Plan: plan}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPoolPlacement(PoolPlacementRow{ExecutorID: "agent-1", PoolID: "pool-a", PoolName: "gpu",
		RunnerName: "gpu-x1y2"}); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		st, err := db.LoadState()
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Plan.TaskByID(1); got.ExecutorPool != "gpu" || got.ExecutorRunner != "gpu-x1y2" {
			t.Fatalf("%s: task 1 ran on %q / %q, want gpu / gpu-x1y2", when, got.ExecutorPool, got.ExecutorRunner)
		}
		for _, id := range []int{2, 3} {
			if got := st.Plan.TaskByID(id); got.ExecutorPool != "" || got.ExecutorRunner != "" {
				t.Fatalf("%s: task %d names a pool: %+v", when, id, got)
			}
		}
		one, err := db.LoadTask(1)
		if err != nil {
			t.Fatal(err)
		}
		if one.ExecutorPool != "gpu" {
			t.Fatalf("%s: LoadTask reads no placement: %+v", when, one)
		}
	}
	check("after the record")

	stale, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	stale.Plan.TaskByID(1).ExecutorPool, stale.Plan.TaskByID(1).ExecutorRunner = "forged", "forged-1"
	stale.Plan.TaskByID(3).ExecutorPool = "forged"
	if err := db.SaveState(stale); err != nil {
		t.Fatal(err)
	}
	check("after a save that names other pools")

	// The record is updated in place, and refuses what it cannot hold.
	if err := db.RecordPoolPlacement(PoolPlacementRow{ExecutorID: "agent-1", PoolName: "gpu-renamed",
		RunnerName: "gpu-x1y2"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := db.LoadState(); st.Plan.TaskByID(1).ExecutorPool != "gpu-renamed" {
		t.Fatal("a second record of the same runner did not replace the first")
	}
	for _, bad := range []PoolPlacementRow{{PoolName: "x"}, {ExecutorID: "a"}, {ExecutorID: "a", PoolName: "x\x1fy"}} {
		if err := db.RecordPoolPlacement(bad); err == nil {
			t.Errorf("RecordPoolPlacement(%+v) accepted", bad)
		}
	}
}

func TestExecutorPoolCordonAndControllerRecords(t *testing.T) {
	db := openFresh(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.CreateExecutorPool(ExecutorPoolRow{ID: "pool-a", Name: "a", MaxRunners: 2}); err != nil {
		t.Fatal(err)
	}
	if changed, err := db.SetExecutorPoolCordon("pool-a", true, "admin", "upgrade", now); err != nil || !changed {
		t.Fatalf("cordon: %v %v", changed, err)
	}
	row, err := db.GetExecutorPool("pool-a")
	if err != nil {
		t.Fatal(err)
	}
	if !row.Cordoned() || row.CordonedBy != "admin" || row.CordonReason != "upgrade" || !row.CordonedAt.Equal(now) {
		t.Fatalf("the cordoned pool: %+v", row)
	}
	// A cordon keeps its first stamp; a mint is refused while it lasts.
	if changed, _ := db.SetExecutorPoolCordon("pool-a", true, "other", "later", now.Add(time.Hour)); changed {
		t.Fatal("cordoning a cordoned pool changed it")
	}
	err = db.MintExecutorPoolRunners("pool-a", []EnrollmentTokenRow{{ID: "tok", SecretHash: "h"}},
		[]ExecutorPoolRunnerRow{{EnrollmentID: "tok", Name: "a-1"}}, now)
	if !errors.Is(err, ErrExecutorPoolCordoned) {
		t.Fatalf("a mint for a cordoned pool: %v", err)
	}
	if changed, err := db.SetExecutorPoolCordon("pool-a", false, "admin", "", now); err != nil || !changed {
		t.Fatalf("uncordon: %v %v", changed, err)
	}
	if row, _ := db.GetExecutorPool("pool-a"); row.Cordoned() || row.CordonReason != "" {
		t.Fatalf("the uncordoned pool: %+v", row)
	}

	if err := db.PutExecutorPoolCredential(ExecutorPoolCredentialRow{ID: "cred", PoolID: "pool-a", SecretHash: "h"}); err != nil {
		t.Fatal(err)
	}
	if changed, err := db.NoteExecutorPoolController("cred", "v0.0.8", 4); err != nil || !changed {
		t.Fatalf("note the controller: %v %v", changed, err)
	}
	if changed, err := db.NoteExecutorPoolController("cred", "v0.0.8", 4); err != nil || changed {
		t.Fatalf("note the same controller again: %v %v, want no write", changed, err)
	}
	cred, err := db.GetExecutorPoolCredential("cred")
	if err != nil || cred.ControllerVersion != "v0.0.8" || cred.ControllerProtocol != 4 {
		t.Fatalf("the credential's controller: %+v %v", cred, err)
	}

	if err := db.PutPoolControllerStatus(PoolControllerStatusRow{PoolID: "pool-a", CredentialID: "cred", Healthy: true,
		Storage: `{"claims":2,"bound":2}`}); err != nil {
		t.Fatal(err)
	}
	reports, err := db.PoolControllerStatuses("pool-a")
	if err != nil || len(reports) != 1 || reports[0].Storage != `{"claims":2,"bound":2}` {
		t.Fatalf("the controller's report: %+v %v", reports, err)
	}

	if _, err := db.RevokeExecutorPool("pool-a", "admin", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetExecutorPoolCordon("pool-a", true, "admin", "", now); !errors.Is(err, ErrExecutorPoolRevoked) {
		t.Fatalf("cordon a revoked pool: %v", err)
	}
}

// TestCreateExecutorPoolWithIsAllOrNothing: a create whose credential cannot
// be written leaves no pool behind — none open to everyone because its access
// list was lost with it, and no name taken by a pool nobody can use.
func TestCreateExecutorPoolWithIsAllOrNothing(t *testing.T) {
	db := openFresh(t)
	if err := db.CreateExecutorPool(ExecutorPoolRow{ID: "pool-other", Name: "other", MaxRunners: 1}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutExecutorPoolCredential(ExecutorPoolCredentialRow{ID: "taken", PoolID: "pool-other", SecretHash: "h"}); err != nil {
		t.Fatal(err)
	}
	audience := []ExecutorAudienceEntry{{Kind: "group", Value: "ml-team", AddedBy: "admin"}}
	err := db.CreateExecutorPoolWith(ExecutorPoolRow{ID: "pool-new", Name: "new", MaxRunners: 2}, audience,
		&ExecutorPoolCredentialRow{ID: "taken", SecretHash: "h2", CreatedBy: "admin"})
	if err == nil {
		t.Fatal("a create whose credential id is taken succeeded")
	}
	if _, err := db.GetExecutorPool("pool-new"); !errors.Is(err, ErrExecutorPoolNotFound) {
		t.Fatalf("a failed create left its pool: %v", err)
	}
	if entries, _ := db.ExecutorPoolAudience("pool-new"); len(entries) != 0 {
		t.Fatalf("a failed create left its access list: %+v", entries)
	}
	if err := db.CreateExecutorPoolWith(ExecutorPoolRow{ID: "pool-new", Name: "new", MaxRunners: 2}, audience,
		&ExecutorPoolCredentialRow{ID: "fresh", SecretHash: "h2", CreatedBy: "admin"}); err != nil {
		t.Fatalf("the name was not free after the failed create: %v", err)
	}
	entries, err := db.ExecutorPoolAudience("pool-new")
	if err != nil || len(entries) != 1 || entries[0].Kind != "group" || entries[0].Value != "ml-team" {
		t.Fatalf("the access list: %+v %v", entries, err)
	}
	if cred, err := db.GetExecutorPoolCredential("fresh"); err != nil || cred.PoolID != "pool-new" {
		t.Fatalf("the credential: %+v %v", cred, err)
	}
	if err := db.CreateExecutorPoolWith(ExecutorPoolRow{ID: "pool-x", Name: "x", MaxRunners: 1},
		[]ExecutorAudienceEntry{{Kind: "planet", Value: "mars"}}, nil); err == nil {
		t.Fatal("an unknown principal kind was accepted")
	}
}
