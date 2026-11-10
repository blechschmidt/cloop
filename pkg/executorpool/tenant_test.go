package executorpool_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestATenantIsThePoolTheProjectAndItsOwner(t *testing.T) {
	base := executorpool.ProjectTenant("pool-a", "/srv/web", "alice@example.com")
	if !executorpool.ValidTenant(base) {
		t.Fatalf("%q is not a valid tenant", base)
	}
	if again := executorpool.ProjectTenant("pool-a", "/srv/web/", "alice@example.com"); again != base {
		t.Fatalf("the same project is two tenants: %s and %s", base, again)
	}
	for what, other := range map[string]string{
		"another pool":    executorpool.ProjectTenant("pool-b", "/srv/web", "alice@example.com"),
		"another project": executorpool.ProjectTenant("pool-a", "/srv/api", "alice@example.com"),
		"another owner":   executorpool.ProjectTenant("pool-a", "/srv/web", "bob@example.com"),
		"no owner":        executorpool.ProjectTenant("pool-a", "/srv/web", ""),
	} {
		if other == base {
			t.Errorf("%s is the same tenant", what)
		}
	}
	if strings.Contains(base, "web") || strings.Contains(base, "alice") {
		t.Errorf("a tenant names what it digests: %s", base)
	}
	for _, bad := range []string{"", "prj-", "prj-XYZ", "prj-" + strings.Repeat("0", 31), "x" + base[1:], base + "0"} {
		if executorpool.ValidTenant(bad) {
			t.Errorf("%q passed as a tenant", bad)
		}
	}
}

// TestTheFeedSplitsDemandByProject is what a controller reads to give a
// project back its own volume: each project's waiting runs, oldest first,
// a feature's counted as its project's, and what each runner holds and was
// handed.
func TestTheFeedSplitsDemandByProject(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 5})
	acc := access{bindings: map[string]string{}, owners: map[string]string{"/srv/web": "alice@example.com"},
		parents: map[string]string{"/srv/web/.cloop/features/login": "/srv/web"}}
	for i, project := range []string{"/srv/web", "/srv/api", "/srv/web/.cloop/features/login"} {
		acc.bindings[project] = p.Binding()
		if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: string(rune('a' + i)), PoolID: p.ID, ProjectPath: project}); err != nil {
			t.Fatal(err)
		}
	}
	web := executorpool.ProjectTenant(p.ID, "/srv/web", "alice@example.com")
	api := executorpool.ProjectTenant(p.ID, "/srv/api", "")
	snap, _, err := s.Snapshot(p, acc)
	if err != nil {
		t.Fatal(err)
	}
	want := []executorpool.ProjectDemand{{Tenant: web, Queued: 2}, {Tenant: api, Queued: 1}}
	if snap.Demand != 3 || len(snap.QueuedProjects) != 2 || snap.QueuedProjects[0] != want[0] || snap.QueuedProjects[1] != want[1] {
		t.Fatalf("queued projects %+v (demand %d), want %+v", snap.QueuedProjects, snap.Demand, want)
	}

	opts := runnerOpts
	opts.Holds = []string{web, ""}
	cfgs, err := s.MintRunners(p, 2, opts)
	if err != nil {
		t.Fatal(err)
	}
	if cfgs[0].Holds != web || cfgs[1].Holds != "" {
		t.Fatalf("the mint echoed holds %q and %q", cfgs[0].Holds, cfgs[1].Holds)
	}
	holder, err := redeem(t, s, db, cfgs[0].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.AssignPoolQueueEntryTo("a", holder.AgentID, "member-a", c.now(),
		statedb.PoolRunnerProject{Tenant: web, Name: "web", Owner: "alice@example.com"}); err != nil || !ok {
		t.Fatalf("assign: %v, %v", ok, err)
	}
	before := snap.Revision
	snap, _, _ = s.Snapshot(p, acc)
	if snap.Revision == before {
		t.Fatal("the revision did not change when a runner was handed a run")
	}
	got := map[string]executorpool.RunnerState{}
	for _, r := range snap.RunnerStates {
		got[r.EnrollmentID] = r
	}
	busy := got[cfgs[0].EnrollmentID]
	if busy.State != statedb.PoolRunnerBusy || busy.Holds != web || busy.Project != web ||
		busy.ProjectName != "web" || busy.ProjectOwner != "alice@example.com" {
		t.Fatalf("the busy runner reads %+v", busy)
	}
	if pending := got[cfgs[1].EnrollmentID]; pending.Holds != "" || pending.Project != "" {
		t.Fatalf("the pending runner reads %+v", pending)
	}
	// api's run is now the oldest waiting, and web keeps its feature's.
	if len(snap.QueuedProjects) != 2 || snap.QueuedProjects[0] != (executorpool.ProjectDemand{Tenant: api, Queued: 1}) ||
		snap.QueuedProjects[1] != (executorpool.ProjectDemand{Tenant: web, Queued: 1}) {
		t.Fatalf("after one web run was handed over: %+v", snap.QueuedProjects)
	}

	// A run whose starter may not read the project now is demand for a
	// runner holding nothing.
	acc.barred = map[string]bool{"mallory@example.com": true}
	acc.bindings["/srv/docs"] = p.Binding()
	if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: "m", PoolID: p.ID, ProjectPath: "/srv/docs",
		Starter: "mallory@example.com"}); err != nil {
		t.Fatal(err)
	}
	docs := executorpool.ProjectTenant(p.ID, "/srv/docs", "")
	demandBefore := snap.Demand
	snap, _, _ = s.Snapshot(p, acc)
	if snap.Demand != demandBefore+1 {
		t.Fatalf("the barred starter's run is not demand: %d, was %d", snap.Demand, demandBefore)
	}
	for _, d := range snap.QueuedProjects {
		if d.Tenant == docs {
			t.Fatalf("a barred starter's run is counted under its project: %+v", snap.QueuedProjects)
		}
	}

	// A hub that cannot say whose a project is counts its runs and names no
	// tenant for them.
	acc.broken = true
	snap, _, _ = s.Snapshot(p, acc)
	if snap.QueuedProjects == nil || len(snap.QueuedProjects) != 0 {
		t.Fatalf("with access broken: %+v", snap.QueuedProjects)
	}
}

func TestMintingRefusesWhatIsNotATenant(t *testing.T) {
	s, _, _ := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 5})
	for _, holds := range [][]string{{"web"}, {"", ""}, {"prj-" + strings.Repeat("g", 32)}} {
		opts := runnerOpts
		opts.Holds = holds
		if _, err := s.MintRunners(p, 1, opts); !errors.Is(err, executorpool.ErrInvalidSpec) {
			t.Errorf("holds %q: %v", holds, err)
		}
	}
}

// TestARunnerHoldingAProjectIsHandedOnlyThatProjectsRuns is the isolation
// rule, at the one statement that decides it.
func TestARunnerHoldingAProjectIsHandedOnlyThatProjectsRuns(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 5})
	web := executorpool.ProjectTenant(p.ID, "/srv/web", "")
	api := executorpool.ProjectTenant(p.ID, "/srv/api", "")
	for _, q := range []statedb.PoolQueueRow{{ID: "w", PoolID: p.ID, ProjectPath: "/srv/web"},
		{ID: "a", PoolID: p.ID, ProjectPath: "/srv/api"}, {ID: "x", PoolID: p.ID, ProjectPath: "/srv/x"}} {
		if err := db.EnqueuePoolRun(q); err != nil {
			t.Fatal(err)
		}
	}
	opts := runnerOpts
	opts.Holds = []string{web, ""}
	cfgs, err := s.MintRunners(p, 2, opts)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := redeem(t, s, db, cfgs[0].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := redeem(t, s, db, cfgs[1].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}
	apiRun := statedb.PoolRunnerProject{Tenant: api, Name: "api"}
	if ok, err := db.AssignPoolQueueEntryTo("a", holder.AgentID, "m", c.now(), apiRun); err != nil || ok {
		t.Fatalf("a runner holding web's data was handed api's run: %v, %v", ok, err)
	}
	if ok, _ := db.AssignPoolQueueEntryTo("x", holder.AgentID, "m", c.now(), statedb.PoolRunnerProject{}); ok {
		t.Fatal("a runner holding web's data was handed a run whose project the hub could not name")
	}
	if q, _ := db.GetPoolQueueEntry("a"); q.State != statedb.PoolQueueWaiting || q.Attempts != 0 {
		t.Fatalf("the refused run is %s after %d attempts", q.State, q.Attempts)
	}
	// The clean runner takes api's run, and says so.
	if ok, err := db.AssignPoolQueueEntryTo("a", clean.AgentID, "m", c.now(), apiRun); err != nil || !ok {
		t.Fatalf("a clean runner refused api's run: %v, %v", ok, err)
	}
	if r, _ := s.RunnerByExecutor(clean.AgentID); r.Project != api || r.Holds != "" {
		t.Fatalf("the clean runner records %+v", r)
	}
	// Returned unstarted, it holds what it was handed: never another's next.
	if moved, err := db.MovePoolRunnerIdle(clean.AgentID); err != nil || !moved {
		t.Fatalf("back to idle: %v, %v", moved, err)
	}
	if r, _ := s.RunnerByExecutor(clean.AgentID); r.Holds != api || r.Project != "" || r.State != statedb.PoolRunnerIdle {
		t.Fatalf("returned to idle it reads %+v", r)
	}
	if moved, _ := db.MovePoolQueueEntry("a", []string{statedb.PoolQueueAssigned}, statedb.PoolQueueWaiting, "", c.now()); !moved {
		t.Fatal("could not requeue the api run")
	}
	if ok, _ := db.AssignPoolQueueEntryTo("w", clean.AgentID, "m", c.now(), statedb.PoolRunnerProject{Tenant: web}); ok {
		t.Fatal("a runner handed api's run once was handed web's next")
	}
	if ok, err := db.AssignPoolQueueEntryTo("w", holder.AgentID, "m", c.now(), statedb.PoolRunnerProject{Tenant: web}); err != nil || !ok {
		t.Fatalf("the runner holding web's data refused web's run: %v, %v", ok, err)
	}
}
