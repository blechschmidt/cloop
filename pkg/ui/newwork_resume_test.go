package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Work added on the hub while a run on a device is out is carried on with
// (Task 20516). The defect as the operator met it on sgx-rust-attestation:
// task #19 was added while the device worked on #18, the device finished #18
// and came back, and the project sat "Paused: the run finished the plan it
// was sent, but 1 task here still has work left — added or reset on the hub
// while it was out" until someone pressed Run — once for every batch of
// tasks added while a device worked.

// workAddedRun is the hub's copy of a project whose run on a device was sent
// task 1, with task 2 added on the hub while the run was out, and the device's
// report of the run: task 1 done, the plan it was sent complete.
func workAddedRun(t *testing.T) (dir string, ex *resultExecutor) {
	t.Helper()
	dir = remoteProject(t)
	title := "Create a file named hello which contains the string world"
	st, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Plan.Tasks = append(st.Plan.Tasks, &pm.Task{ID: 2, Title: "Add a second file", Priority: 2, Status: pm.TaskPending})
	if err := st.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	ex = &resultExecutor{
		stubExecutor: stubExecutor{status: executor.Status{State: executor.StateExited}},
		id:           "FL6HRGvUlqxf96aO", returns: true,
		result: executor.ProjectResult{Data: gzResult(t, projectseed.Result{
			Format: 1, Status: "complete", Tasks: []projectseed.TaskChange{finishedTask(title, pm.TaskDone)},
		})},
	}
	rememberSeededDispatch(ex, "h1", projectseed.Provenance{
		ExecutorID: ex.id, ExecutorKind: executor.KindRemoteAgent, Isolation: "remote", RunID: "run_x", Identity: "local",
		// What the hub recorded as it built the seed: task 1, and only it.
		Sent: &projectseed.SeedWork{Startable: map[int]string{1: projectseed.TitleDigest(title)}},
	})
	return dir, ex
}

// resumerFor starts srv's resumer and returns the channel its restarts are
// reported on.
func resumerFor(t *testing.T, srv *Server) <-chan string {
	t.Helper()
	started := make(chan string, 4)
	srv.autoResumeStart = func(workDir string) error {
		started <- workDir
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.watchResumeAtOnce(ctx)
	waitFor(t, 5*time.Second, "the resumer to start", func() bool {
		srv.resumeNowMu.Lock()
		defer srv.resumeNowMu.Unlock()
		return srv.resumeNow != nil
	})
	return started
}

func TestARemoteRunThatFinishedItsPlanIsCarriedOnWithWorkAddedMeanwhile(t *testing.T) {
	dir, ex := workAddedRun(t)
	srv := &Server{WorkDir: dir}
	started := resumerFor(t, srv)

	srv.runEnded(dir, ex, "h1")

	select {
	case got := <-started:
		if got != dir {
			t.Fatalf("restarted %s, want %s", got, dir)
		}
	case <-time.After(10 * time.Second):
		st, _ := state.LoadLite(dir)
		t.Fatalf("the hub did not start a run for the task added while the run was out (status %q, %+v) — "+
			"the reported bug", st.Status, st.PauseReason)
	}

	st, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Plan.TaskByID(1).Status; got != pm.TaskDone {
		t.Errorf("task 1 is %q, want the run's outcome, done", got)
	}
	if got := st.Plan.TaskByID(2).Status; got != pm.TaskPending {
		t.Errorf("task 2 is %q, want pending for the next run", got)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeWorkAdded ||
		!strings.Contains(st.PauseReason.Detail, "task #2 was added or reset here while the run was out") {
		t.Errorf("status %q, pause %+v; want paused work_added naming task 2", st.Status, st.PauseReason)
	}
	events := projectResultEvents(t, dir)
	if len(events) != 1 || !strings.Contains(events[0].Message, "(#2), so the hub starts another run for it") {
		t.Errorf("the journal row does not say the hub carries on with #2: %+v", events)
	}
	// A machine started that run: the trail says so, and why — written once
	// the dispatch has returned, so just after the restart was seen.
	waitFor(t, 10*time.Second, "the restart's run.cap_resumed row", func() bool {
		return len(auditRowsOf(t, dir, auditaction.ActionRunCapResumed)) > 0
	})
	rows := auditRowsOf(t, dir, auditaction.ActionRunCapResumed)
	if len(rows) != 1 {
		t.Fatalf("run.cap_resumed rows = %d, want 1", len(rows))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rows[0].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload["paused_detail"].(string), "task #2 was added") {
		t.Errorf("run.cap_resumed records %v", payload)
	}
}

// A run the hub was asked to stop, that finished before the stop reached it,
// is not started again: the stop stands, and the journal says what it held.
// Stop pressed once the device's workload has exited, while the hub has yet
// to settle the run, is such a stop too.
func TestAStopThatMissedTheRunIsNotOverriddenByWorkAdded(t *testing.T) {
	dir, ex := workAddedRun(t)
	srv := &Server{WorkDir: dir}
	started := resumerFor(t, srv)
	srv.trackRun(dir, ex, "h1")
	if d := srv.interruptRun(dir); d.Signalled != 0 || !d.Finished {
		t.Fatalf("Stop on a run whose workload had exited: %+v, want it noted, nothing signalled", d)
	}

	srv.runEnded(dir, ex, "h1")

	select {
	case got := <-started:
		t.Fatalf("a run someone stopped was started again: %s", got)
	case <-time.After(300 * time.Millisecond):
	}
	st, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeOperator {
		t.Fatalf("status %q, pause %+v; want paused by the operator", st.Status, st.PauseReason)
	}
	// Nor does the sweep start it later.
	if srv.maybeAutoResume(dir) {
		t.Error("the sweep restarted a run someone stopped")
	}
	events := projectResultEvents(t, dir)
	if len(events) != 1 || !strings.Contains(events[0].Message,
		"(#2), and the run was asked to stop, so the hub does not start another for it") {
		t.Errorf("no journal row says the stop held the run back from task 2: %+v", events)
	}
}

// A run started for added work that then brings nothing back is not followed
// by another, and that one by another (Task 20516): the dispatch retires the
// pause it acted on, and only a run's own merge decides that it is followed.
func TestARunThatBringsNothingBackIsNotRestartedAgainAndAgain(t *testing.T) {
	dir := pausedProject(t, pausereason.NewUntil(pausereason.CodeWorkAdded,
		"task #2 was added or reset here while the run was out", time.Now().Add(-time.Second)))
	srv := &Server{WorkDir: dir}
	started := resumerFor(t, srv)
	ex := &resultExecutor{
		stubExecutor: stubExecutor{status: executor.Status{State: executor.StateExited}},
		id:           "FL6HRGvUlqxf96aO", returns: true, err: executor.ErrProjectResultUnavailable,
	}
	rememberSeededDispatch(ex, "h2", projectseed.Provenance{ExecutorID: ex.id, RunID: "run_y", Identity: "local",
		Sent: &projectseed.SeedWork{Startable: map[int]string{}}})
	// What the dispatch's record does once the workload exists.
	srv.retireDuePause(dir, ex, "h2")
	st, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.PauseReason == nil || st.PauseReason.ResumedByHub() {
		t.Fatalf("the dispatched run left its project paused %+v, which the hub would restart again", st.PauseReason)
	}

	srv.trackRun(dir, ex, "h2")
	srv.runEnded(dir, ex, "h2")
	select {
	case got := <-started:
		t.Fatalf("a run that brought nothing back was followed by another: %s", got)
	case <-time.After(300 * time.Millisecond):
	}
	if srv.maybeAutoResume(dir) {
		t.Error("the sweep restarts a run that brought nothing back")
	}
	st, err = state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeStale ||
		!strings.Contains(st.PauseReason.Detail, "has not reported its outcome") {
		t.Errorf("status %q, pause %+v; want it saying the run never reported", st.Status, st.PauseReason)
	}

	// And a stored pause the dispatch could not retire is not taken for the
	// verdict of a run that brought nothing back.
	dir2 := pausedProject(t, pausereason.NewUntil(pausereason.CodeWorkAdded,
		"task #2 was added or reset here while the run was out", time.Now().Add(-time.Second)))
	rememberSeededDispatch(ex, "h3", projectseed.Provenance{ExecutorID: ex.id, RunID: "run_z", Identity: "local"})
	srv.trackRun(dir2, ex, "h3")
	srv.runEnded(dir2, ex, "h3")
	select {
	case got := <-started:
		t.Fatalf("the previous run's pause started a run after one that brought nothing back: %s", got)
	case <-time.After(300 * time.Millisecond):
	}
}

// One start of a project's run at a time on a member, none while its last run
// is being settled, and settling forgets only the run it settled.
func TestOneStartAtATimeAndNoneWhileSettling(t *testing.T) {
	defer func(w time.Duration) { runSettleWait = w }(runSettleWait)
	runSettleWait = 300 * time.Millisecond
	dir := setupProjectDir(t, "g", nil)
	srv := &Server{WorkDir: dir}
	if _, err := srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("first start refused: %v", err)
	}
	if !srv.projectExecuting(dir) {
		t.Error("a start in progress does not count as a run: Run would start a second one")
	}
	if _, err := srv.claimRun(dir, "auto_resume"); !errors.Is(err, errRunStarting) {
		t.Fatalf("a second start while one is in progress = %v, want errRunStarting", err)
	}
	srv.releaseRunClaim(dir) // the first start gave up
	if _, err := srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("a start after the first gave up was refused: %v", err)
	}
	ex := &resultExecutor{stubExecutor: stubExecutor{status: executor.Status{State: executor.StateExited}}, id: "e1"}
	srv.trackRun(dir, ex, "h1") // ...and dispatched: tracked from here
	if srv.runStarting(dir) {
		t.Error("a tracked run still counts as a start in progress")
	}
	// Over, and not being settled: a new run replaces it, as it always did
	// (a stream something left open never ends on its own).
	if _, err := srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("a start beside a finished run nobody settles was refused: %v", err)
	}
	srv.releaseRunClaim(dir)
	srv.markRunSettling(dir, "h1")
	if _, err := srv.claimRun(dir, "run"); !errors.Is(err, errRunStarting) {
		t.Fatalf("a start while the last run is settled for longer than a start waits = %v, want errRunStarting", err)
	}
	if !srv.settlingRun(dir) {
		t.Error("settlingRun says no while runEnded settles the run")
	}
	// A settle that ends while a start waits lets it go ahead.
	go func() {
		time.Sleep(100 * time.Millisecond)
		srv.untrackSettledRun(dir, "h1")
	}()
	if _, err := srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("a start that waited out the settle was refused: %v", err)
	}
	// The settled run's release leaves that start's claim alone.
	srv.trackRun(dir, ex, "h1")
	srv.releaseClaimUnlessStarting(dir)
	if srv.runStarting(dir) {
		t.Error("a tracked run still counts as a start in progress")
	}
	srv.untrackSettledRun(dir, "h1")
	if _, err := srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("start refused: %v", err)
	}
	srv.trackRun(dir, ex, "h1")
	srv.markRunSettling(dir, "h1")
	// A start in progress beside the settled run — begun before it was being
	// settled — keeps its mark when the settled run is let go of.
	srv.runHandleMu.Lock()
	srv.runStarts[dir] = time.Now()
	srv.runHandleMu.Unlock()
	srv.untrackSettledRun(dir, "h1")
	if !srv.runStarting(dir) {
		t.Fatal("letting go of the settled run released a newer start")
	}
	srv.releaseRunClaim(dir)

	// A newer run tracked meanwhile — adopted, say — is not forgotten with
	// the one settled.
	srv.trackRun(dir, ex, "h1")
	srv.markRunSettling(dir, "h1")
	srv.trackRun(dir, ex, "h2")
	srv.untrackSettledRun(dir, "h1")
	if run, ok := srv.trackedRun(dir); !ok || run.handleID != "h2" {
		t.Fatalf("settling h1 forgot the newer run: tracked %+v %v", run, ok)
	}
	srv.untrackSettledRun(dir, "h2")
	if _, ok := srv.trackedRun(dir); ok {
		t.Error("the settled run is still tracked")
	}

	// A settle that returned part-way — a panic — does not hold the project.
	srv.trackRun(dir, ex, "h3")
	srv.markRunSettling(dir, "h3")
	srv.clearRunSettling(dir, "h3")
	if srv.settlingRun(dir) {
		t.Fatal("a settle that returned still holds the project")
	}
	if _, err := srv.claimRun(dir, "run"); err != nil {
		t.Fatalf("a start after a settle that returned part-way was refused: %v", err)
	}
	srv.releaseRunClaim(dir)
}

// An automatic start asks again, once it holds the start, whether the pause it
// read is still one to restart: Stop, or a person's Run, may have settled it
// in between.
func TestAnAutomaticStartAsksAgainOnceItHoldsTheStart(t *testing.T) {
	dir := pausedProject(t, pausereason.New(pausereason.CodeOperator, "run stopped"))
	srv := New(dir, 0, "")
	if err := srv.startAutoResumeRun(dir); !errors.Is(err, errResumeDeclined) {
		t.Fatalf("startAutoResumeRun on a stopped project = %v, want errResumeDeclined", err)
	}
	if srv.runStarting(dir) {
		t.Error("the declined start kept its mark")
	}
}

// A run on this filesystem that ended before it wrote its status leaves the
// previous run's pause stored; that pause is not taken for this run's.
func TestAHostRunIsFollowedOnlyOnItsOwnPause(t *testing.T) {
	recorded := time.Now().Add(-time.Minute)
	dir := pausedProject(t, pausereason.NewUntil(pausereason.CodeReadersChanged, "bravo no longer lists it", recorded))
	srv := &Server{WorkDir: dir}
	started := resumerFor(t, srv)
	srv.resumeAtOnceAfter(dir, false, projectseed.MergeReport{}, recorded.Add(time.Second))
	select {
	case got := <-started:
		t.Fatalf("an earlier run's pause started a run: %s", got)
	case <-time.After(300 * time.Millisecond):
	}
	srv.resumeAtOnceAfter(dir, false, projectseed.MergeReport{}, recorded.Add(-time.Second))
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the run's own readers-change pause was not followed at once")
	}
}

// Stop on a project the hub is about to start again by itself cancels that
// start, as the project move preflight tells people it does.
func TestStopCancelsTheRunTheHubWouldStart(t *testing.T) {
	dir := pausedProject(t, pausereason.NewUntil(pausereason.CodeWorkAdded,
		"task #2 was added or reset here while the run was out", time.Now().Add(-time.Second)))
	ts := newTestServer(t, dir, nil)
	out := apiPOST(t, ts, "/api/stop", map[string]interface{}{})
	if ok, _ := out["ok"].(bool); !ok || !strings.Contains(fmt.Sprint(out["message"]), "cancelled the run the hub was about to start") {
		t.Fatalf("POST /api/stop = %v", out)
	}
	st, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeOperator {
		t.Fatalf("pause %+v, want stopped by the operator", st.PauseReason)
	}
	rows, _, err := state.ListEvents(dir, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Type == state.EventSessionPaused && strings.Contains(r.Message, "Stop cancelled the run the hub was about to start") &&
			strings.Contains(r.Message, "task #2 was added") {
			found = true
		}
	}
	if !found {
		t.Errorf("the journal does not say the stop cancelled the restart: %+v", rows)
	}
}

// The sweep restarts a work_added pause runEnded could not hand to its
// resumer, whatever the cap-resume setting says: that setting is about usage
// caps, and this run stopped only because it could not see the work.
func TestTheSweepCarriesOnWithWorkAddedWhateverTheCapSetting(t *testing.T) {
	now := time.Now()
	dir := pausedProject(t, pausereason.NewUntil(pausereason.CodeWorkAdded,
		"task #4 was added or reset here while the run was out", now.Add(-time.Minute)))
	srv, resumed := resumeProbe(t, dir, now)
	off := false
	cfg, err := srv.loadHubConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.UI.AutoResumeOnCapReset = &off
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	srv.runAutoResumeSweep(t.Context())
	if len(*resumed) != 1 || (*resumed)[0] != dir {
		t.Fatalf("the sweep resumed %v, want [%s]", *resumed, dir)
	}
}
