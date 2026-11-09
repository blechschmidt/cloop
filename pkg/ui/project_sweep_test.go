package ui

// The project sweep runs every two seconds regardless of what anybody is doing,
// so it is the hub's floor cost and it scaled with tenants rather than with
// activity: at 500 registered projects one iteration took 4.4s idle and 11.4s
// when a single project had written to its state — both longer than the tick
// that schedules them (BenchmarkWatchProjectsTick).
//
// Making it cheap meant three deferrals — one /proc walk per tick instead of
// one per project, reloading only the projects whose state moved, and skipping
// the stat for projects that are demonstrably dormant. Each of those trades
// work for an assumption, so these tests are about the assumptions: a project
// that starts, stops, or changes must still surface as promptly as it did when
// the sweep did everything for everyone, every time.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// statDue is where the "skip the stat" decision is made, and every promptness
// guarantee the deferral relies on is one of its early returns.
func TestStatDueKeepsInterestingProjectsOnTheFastCadence(t *testing.T) {
	const path = "/srv/projects/demo"
	now := time.Now()
	// Long enough ago that the dormancy test below would otherwise fire.
	stale := now.Add(-2 * statBackoffAfter)

	cases := []struct {
		name       string
		running    bool
		subscribed bool
		lastMod    time.Time
		seen       bool
		want       bool
	}{
		{name: "never seen before", seen: false, want: true},
		{name: "a run is executing in it", seen: true, lastMod: stale, running: true, want: true},
		{name: "somebody has it open", seen: true, lastMod: stale, subscribed: true, want: true},
		{name: "written to recently", seen: true, lastMod: now.Add(-time.Second), want: true},
		{name: "dormant", seen: true, lastMod: stale, want: true}, // first look arms the timer
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sw := newProjectSweep()
			if tc.seen {
				sw.lastMod[path] = tc.lastMod
			}
			subs := map[string]struct{}{}
			if tc.subscribed {
				subs[path] = struct{}{}
			}
			if got := sw.statDue(path, now, tc.running, subs); got != tc.want {
				t.Fatalf("statDue = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStatDueDefersOnlyDormantProjects is the other half: the deferral has to
// actually happen, or none of the cost went away.
func TestStatDueDefersOnlyDormantProjects(t *testing.T) {
	const path = "/srv/projects/dormant"
	now := time.Now()
	sw := newProjectSweep()
	sw.lastMod[path] = now.Add(-2 * statBackoffAfter)
	noSubs := map[string]struct{}{}

	// First look arms the timer and still stats.
	if !sw.statDue(path, now, false, noSubs) {
		t.Fatal("the tick that notices a project has gone dormant should still stat it")
	}
	// Subsequent ticks inside the window are skipped — this is the saving.
	if sw.statDue(path, now.Add(2*time.Second), false, noSubs) {
		t.Fatal("a dormant project must not be statted on the very next tick")
	}
	// And it comes back on its own, without needing anything to happen.
	if !sw.statDue(path, now.Add(statBackoff+time.Second), false, noSubs) {
		t.Fatalf("a dormant project must still be statted every %s", statBackoff)
	}
}

// TestStatDueResumesImmediatelyWhenAProjectStarts is the promptness guarantee
// the task turns on: deferral must never delay a project that starts.
//
// It cannot, because liveness does not come from the stat — the process scan
// runs on every tick and is never deferred — but the deferral timer has to be
// dropped as well, or the tick *after* the run starts would skip the stat and
// the dashboard would show a running project with state from minutes ago.
func TestStatDueResumesImmediatelyWhenAProjectStarts(t *testing.T) {
	const path = "/srv/projects/waking"
	now := time.Now()
	sw := newProjectSweep()
	sw.lastMod[path] = now.Add(-2 * statBackoffAfter)
	noSubs := map[string]struct{}{}

	sw.statDue(path, now, false, noSubs)
	if sw.statDue(path, now.Add(2*time.Second), false, noSubs) {
		t.Fatal("precondition: the project should be deferred at this point")
	}
	// A run appears.
	if !sw.statDue(path, now.Add(4*time.Second), true, noSubs) {
		t.Fatal("a project with a run behind it must be statted on the same tick the run is seen")
	}
	// And it stays on the fast cadence afterwards rather than resuming the
	// backoff it was in.
	if !sw.statDue(path, now.Add(6*time.Second), true, noSubs) {
		t.Fatal("a running project must stay on the fast cadence")
	}
}

// TestStatDueResumesWhenSomebodyOpensTheProject is the same guarantee for the
// other way a dormant project becomes interesting.
func TestStatDueResumesWhenSomebodyOpensTheProject(t *testing.T) {
	const path = "/srv/projects/watched"
	now := time.Now()
	sw := newProjectSweep()
	sw.lastMod[path] = now.Add(-2 * statBackoffAfter)

	sw.statDue(path, now, false, map[string]struct{}{})
	if sw.statDue(path, now.Add(2*time.Second), false, map[string]struct{}{}) {
		t.Fatal("precondition: the project should be deferred at this point")
	}
	subs := map[string]struct{}{path: {}}
	if !sw.statDue(path, now.Add(4*time.Second), false, subs) {
		t.Fatal("opening a project must put it back on the fast cadence at once")
	}
}

// TestInvalidateForcesARestatAfterTheSweepRepairsAProject covers the one write
// a deferral could hide.
//
// Stale-run recovery fires precisely when nothing is running and nobody is
// watching — the same conditions that qualify a project for backoff — so a
// repair made while deferred would not be re-read for up to statBackoff, and
// the dashboard would go on showing a run the sweep had already cleaned up.
func TestInvalidateForcesARestatAfterTheSweepRepairsAProject(t *testing.T) {
	const path = "/srv/projects/repaired"
	now := time.Now()
	sw := newProjectSweep()
	sw.lastMod[path] = now.Add(-2 * statBackoffAfter)
	noSubs := map[string]struct{}{}

	sw.statDue(path, now, false, noSubs)
	if sw.statDue(path, now.Add(2*time.Second), false, noSubs) {
		t.Fatal("precondition: the project should be deferred at this point")
	}

	sw.invalidate(path) // the sweep just repaired it

	if !sw.statDue(path, now.Add(4*time.Second), false, noSubs) {
		t.Fatal("a project the sweep repaired must be re-statted on the next tick")
	}
	if _, seen := sw.lastMod[path]; seen {
		t.Error("invalidate must clear the remembered timestamp, or the re-stat would " +
			"compare equal and the repair would not register as a change")
	}
}

// TestSweepSurfacesAnExternalStateChange drives the real tick end to end: a
// project's state is written behind the hub's back, exactly as `cloop task add`
// from a terminal would, and the sweep has to notice on the next tick and
// republish the project's counts.
//
// This is the assertion the incremental status refresh could break. Reloading
// only the projects whose state files moved is only sound if "moved" is
// detected correctly — a miss here would leave the dashboard showing a task
// count that never updates again.
func TestSweepSurfacesAnExternalStateChange(t *testing.T) {
	dir := setupProjectDir(t, "sweep integration", []*pm.Task{
		{ID: 1, Title: "first", Status: pm.TaskPending},
	})
	srv := New(dir, 0, "")
	sw := newProjectSweep()

	srv.sweepProjectsTick(sw, time.Now())
	if got := statusFor(t, srv, dir).TotalTasks; got != 1 {
		t.Fatalf("after the first tick TotalTasks = %d, want 1", got)
	}

	// Write from outside the hub.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, &pm.Task{ID: 2, Title: "second", Status: pm.TaskPending})
	if err := ps.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	srv.sweepProjectsTick(sw, time.Now())
	if got := statusFor(t, srv, dir).TotalTasks; got != 2 {
		t.Fatalf("after an external write TotalTasks = %d, want 2 — the sweep did not "+
			"notice the state file moved", got)
	}
}

// TestSweepKeepsUnchangedProjectStatuses is the other side of the incremental
// refresh: a project nobody touched must keep the status it had, rather than
// being dropped or blanked because the sweep skipped reloading it.
//
// The two projects share a tick, and only one of them changes — which is
// precisely the shape that used to cost a full reload of both.
func TestSweepKeepsUnchangedProjectStatuses(t *testing.T) {
	busy := setupProjectDir(t, "the busy tenant", []*pm.Task{
		{ID: 1, Title: "one", Status: pm.TaskPending},
	})
	quiet := setupProjectDir(t, "the quiet tenant", []*pm.Task{
		{ID: 1, Title: "one", Status: pm.TaskDone},
		{ID: 2, Title: "two", Status: pm.TaskDone},
	})
	srv := New(busy, 0, "")
	srv.Projects = []string{quiet}
	sw := newProjectSweep()

	srv.sweepProjectsTick(sw, time.Now())
	before := statusFor(t, srv, quiet)
	if before.TotalTasks != 2 || before.DoneTasks != 2 {
		t.Fatalf("precondition: quiet project loaded as %+v", before)
	}

	// Only the busy project moves.
	ps, err := state.Load(busy)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	ps.Plan.Tasks[0].Status = pm.TaskDone
	if err := ps.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	srv.sweepProjectsTick(sw, time.Now())

	if got := statusFor(t, srv, busy).DoneTasks; got != 1 {
		t.Errorf("the changed project's DoneTasks = %d, want 1", got)
	}
	after := statusFor(t, srv, quiet)
	if after.TotalTasks != before.TotalTasks || after.DoneTasks != before.DoneTasks ||
		after.Goal != before.Goal || !after.HasProject {
		t.Errorf("the untouched project's status changed across a tick:\n before %+v\n after  %+v",
			before, after)
	}
}

// TestSweepRediscoversADeregisteredProject guards the carry-over pruning. The
// sweep drops per-project bookkeeping for projects that have left the registry;
// if it dropped the wrong thing, a project that came back would either be
// invisible or be treated as unchanged forever.
func TestSweepRediscoversADeregisteredProject(t *testing.T) {
	primary := setupProjectDir(t, "primary", nil)
	guest := setupProjectDir(t, "guest", []*pm.Task{{ID: 1, Title: "one", Status: pm.TaskPending}})

	srv := New(primary, 0, "")
	srv.Projects = []string{guest}
	sw := newProjectSweep()
	srv.sweepProjectsTick(sw, time.Now())
	if _, ok := sw.lastMod[guest]; !ok {
		t.Fatal("precondition: the guest project should be tracked after one tick")
	}

	// Deregister it. Its carry-over must go with it.
	srv.projectsMu.Lock()
	srv.Projects = nil
	srv.projectsMu.Unlock()
	srv.sweepProjectsTick(sw, time.Now())
	if _, ok := sw.lastMod[guest]; ok {
		t.Error("carry-over for a deregistered project was not pruned — the maps grow " +
			"with every project the hub has ever seen")
	}

	// Re-register it: it must be picked up again, not mistaken for known-good.
	srv.projectsMu.Lock()
	srv.Projects = []string{guest}
	srv.projectsMu.Unlock()
	srv.sweepProjectsTick(sw, time.Now())
	if got := statusFor(t, srv, guest).TotalTasks; got != 1 {
		t.Errorf("a re-registered project reported TotalTasks = %d, want 1", got)
	}
}

// TestRefreshHealthFollowsLivenessNotTime is what lets the sweep skip reloading
// an unchanged project. Health follows liveness, which moves without the state
// moving, so a cached status has to reach the same verdict a reload would.
//
// And the verdict is liveness alone (Task 20479): a status last written three
// hours ago is the ordinary state of a run three hours into one task, which is
// running while a run executes it — the old rule called it "stalled" fifteen
// minutes in — and stalled only once nothing does.
func TestRefreshHealthFollowsLivenessNotTime(t *testing.T) {
	long := multiui.ProjectStatus{
		HasProject:   true,
		Status:       "running",
		Goal:         "something",
		LastActivity: time.Now().Add(-3 * time.Hour),
		Running:      true,
		Health:       multiui.HealthUnknown,
	}
	long.RefreshHealth()
	if long.Health != multiui.HealthRunning {
		t.Errorf("a run three hours into one task = %v, want %v — a long task is not a stalled one",
			long.Health, multiui.HealthRunning)
	}

	gone := long
	gone.LastActivity = time.Now()
	gone.Running = false
	gone.RefreshHealth()
	if gone.Health != multiui.HealthStalled {
		t.Errorf("a running status with nothing executing it = %v, want %v — stall detection "+
			"does not survive being served from the status cache", gone.Health, multiui.HealthStalled)
	}
}

// writeRunningStatusAt records a "running" project status as written at the
// given moment, with one in-progress task that started then: exactly what a
// project looks like that far into a task, because a run writes its state when
// a task starts and when it ends, and nothing in between.
func writeRunningStatusAt(t *testing.T, dir string, at time.Time) {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	started := at
	ps.Plan.Tasks[0].Status = pm.TaskInProgress
	ps.Plan.Tasks[0].StartedAt = &started
	ps.Status = "running"
	if err := ps.SaveDirect(); err != nil {
		t.Fatalf("state.SaveDirect: %v", err)
	}
	// SaveDirect stamps the time of the write; put it back where the task
	// left it.
	db, err := statedb.Open(state.StateDBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close()
	if err := db.SaveRunStatus("running", nil, at); err != nil {
		t.Fatalf("SaveRunStatus: %v", err)
	}
}

// TestSweepNeverCallsALongRunningTaskStalled drives the real tick end to end,
// in both directions (Task 20479).
//
// The long project is three hours into one task with its run executing; the
// abandoned one wrote "running" a moment ago and has nothing behind it. The old
// rule judged both by the age of the last write, and got both wrong: the long
// task was "stalled" fifteen minutes in, and the abandoned run "running" for
// fifteen minutes after it died.
func TestSweepNeverCallsALongRunningTaskStalled(t *testing.T) {
	long := setupProjectDir(t, "a long task", []*pm.Task{{ID: 1, Title: "train the model", Status: pm.TaskPending}})
	abandoned := setupProjectDir(t, "an abandoned run", []*pm.Task{{ID: 1, Title: "one", Status: pm.TaskPending}})
	writeRunningStatusAt(t, long, time.Now().Add(-3*time.Hour))
	writeRunningStatusAt(t, abandoned, time.Now())

	srv := New(long, 0, "")
	srv.Projects = []string{abandoned}
	srv.trackRun(long, &stubExecutor{status: executor.Status{State: executor.StateRunning}}, "h1")
	t.Cleanup(func() { srv.untrackRun(long) })
	sw := newProjectSweep()

	// Several ticks, so the verdict is not an artefact of the first one.
	for i := 0; i < 3; i++ {
		srv.sweepProjectsTick(sw, time.Now())
		got := statusFor(t, srv, long)
		if !got.Running || got.Health != multiui.HealthRunning {
			t.Fatalf("tick %d: a run three hours into one task reported running=%v health=%v, "+
				"want running=true health=%v", i, got.Running, got.Health, multiui.HealthRunning)
		}
	}
	_, statuses := srv.cachedProjectView()
	if active := multiui.Aggregate(statuses).ActiveRuns; active != 1 {
		t.Errorf("ActiveRuns = %d, want 1 — the long task's run is active", active)
	}

	// The abandoned run is read before stale-run recovery's grace has passed,
	// so the status still claims a run: that, with nothing executing it, is a
	// stall, however recently it was written.
	got := statusFor(t, srv, abandoned)
	if got.Running || got.Health != multiui.HealthStalled {
		t.Errorf("a running status written just now with no run behind it reported running=%v "+
			"health=%v, want running=false health=%v", got.Running, got.Health, multiui.HealthStalled)
	}
}

// TestSweepRepublishesLivenessWithoutAStateWrite: health follows liveness, and
// liveness moves without the state moving — a run started from a terminal is
// seen before its first write, and one killed outright writes nothing on its
// way out. The sweep reloads only projects whose state files moved, so unless
// it also notices the scan contradicting a cached status, the card's Run/Stop
// button and its health would wait for some unrelated write to catch up.
func TestSweepRepublishesLivenessWithoutAStateWrite(t *testing.T) {
	dir := setupProjectDir(t, "liveness only", []*pm.Task{{ID: 1, Title: "one", Status: pm.TaskPending}})
	srv := New(dir, 0, "")
	sw := newProjectSweep()

	srv.sweepProjectsTick(sw, time.Now())
	if got := statusFor(t, srv, dir); got.Running {
		t.Fatalf("precondition: a project with nothing executing it reported running: %+v", got)
	}

	// A run appears; the project's state is not touched.
	srv.trackRun(dir, &stubExecutor{status: executor.Status{State: executor.StateRunning}}, "h1")
	srv.sweepProjectsTick(sw, time.Now())
	if got := statusFor(t, srv, dir); !got.Running {
		t.Fatal("a run that appeared without writing the state was not published — the " +
			"cached status still says nothing is executing the project")
	}

	// And it goes, again without a write. Its status never claimed a run, so
	// stale-run recovery has nothing to repair and writes nothing either.
	srv.untrackRun(dir)
	srv.sweepProjectsTick(sw, time.Now())
	if got := statusFor(t, srv, dir); got.Running {
		t.Fatal("a run that vanished without writing the state is still published as running")
	}
}

// TestSweepToleratesAVanishedProject covers a registered project whose state is
// deleted underneath the hub. Two things must hold: the tick survives it, and
// the project stops reporting the task counts of a database that is gone.
//
// The second is the one the incremental refresh could have lost. Reloading
// every project on any change used to clear this as a side effect; skipping
// unchanged projects means a disappearance has to be recognised as a change in
// its own right, or the dashboard keeps the last counts forever.
func TestSweepToleratesAVanishedProject(t *testing.T) {
	primary := setupProjectDir(t, "primary", nil)
	gone := setupProjectDir(t, "doomed", []*pm.Task{{ID: 1, Title: "one", Status: pm.TaskDone}})
	srv := New(primary, 0, "")
	srv.Projects = []string{gone}
	sw := newProjectSweep()

	srv.sweepProjectsTick(sw, time.Now())
	if got := statusFor(t, srv, gone); !got.HasProject || got.TotalTasks != 1 {
		t.Fatalf("precondition: doomed project loaded as %+v", got)
	}

	if err := os.RemoveAll(filepath.Join(gone, ".cloop")); err != nil {
		t.Fatalf("rm: %v", err)
	}
	srv.sweepProjectsTick(sw, time.Now()) // must not panic or hang

	if got := statusFor(t, srv, gone); got.HasProject || got.TotalTasks != 0 {
		t.Errorf("a project whose state was deleted still reports %+v — the sweep kept "+
			"serving counts for a database that is gone", got)
	}
}

// statusFor returns the cached status the sweep published for one project.
func statusFor(t *testing.T, srv *Server, dir string) multiui.ProjectStatus {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs(%s): %v", dir, err)
	}
	_, statuses := srv.cachedProjectView()
	for _, st := range statuses {
		if st.Path == abs {
			return st
		}
	}
	t.Fatalf("no cached status for %s", abs)
	return multiui.ProjectStatus{}
}
