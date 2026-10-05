package orchestrator

// Tests for the free-space floor and the reserve (Task 20381).
//
// Nothing here fills a disk. The volumes a run measures come from an injected
// probe, scripted per call, and the write that runs out of space is an
// injected error with the kernel's ENOSPC in it. The reserve itself is real —
// sixteen megabytes of preallocated temp space — because what releasing it
// does to the next write is the point.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/diskreserve"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

const (
	floorMB = 1024
	floorB  = int64(floorMB) << 20
	lowB    = 100 << 20       // well below the floor
	midB    = floorB + 50<<20 // above the floor, short of floor + 10%
	highB   = 4 * floorB      // plenty
)

// fakeDisk answers the run's free-space probe from a script: call i gets
// free[i], and the last value repeats. onCall runs on the goroutine that
// probed — the orchestrator's — so it may read the run's state race-free.
type fakeDisk struct {
	mu     sync.Mutex
	free   []int64
	calls  int
	onCall func(call int)
}

func (f *fakeDisk) probe(paths ...string) ([]diskusage.Volume, error) {
	f.mu.Lock()
	i := f.calls
	f.calls++
	v := f.free[len(f.free)-1]
	if i < len(f.free) {
		v = f.free[i]
	}
	cb := f.onCall
	f.mu.Unlock()
	if cb != nil {
		cb(i)
	}
	return []diskusage.Volume{{Mount: "/srv/data", Path: paths[0], Device: 7, FreeBytes: v}}, nil
}

func (f *fakeDisk) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// diskProject is a project whose plan holds tasks.
func diskProject(t *testing.T, autoEvolve bool, tasks ...*pm.Task) string {
	t.Helper()
	dir := tempDir(t)
	s := initState(t, dir, "disk goal", 0)
	s.AutoEvolve = autoEvolve
	s.Plan = &pm.Plan{Goal: "disk goal", Tasks: tasks}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// diskOrchestrator builds a run with the floor at floorMB, probing fd, and
// re-measuring every few milliseconds instead of every minute.
func diskOrchestrator(t *testing.T, dir string, cfg Config, prov provider.Provider, fd *fakeDisk) *Orchestrator {
	t.Helper()
	cfg.WorkDir = dir
	cfg.PMMode = true
	if cfg.MinFreeDiskMB == 0 {
		cfg.MinFreeDiskMB = floorMB
	}
	o := newOrchestrator(t, dir, cfg, prov)
	o.diskProbe = fd.probe
	o.testDiskPoll = 5 * time.Millisecond
	return o
}

// pauseSeen is what the run looked like, in memory and on disk, while it
// waited.
type pauseSeen struct {
	status   string
	reason   pausereason.Reason
	stored   *state.ProjectState
	provider int
}

func snapshotPause(t *testing.T, o *Orchestrator, dir string, calls func() int) pauseSeen {
	t.Helper()
	ps := pauseSeen{status: o.state.Status}
	if o.state.PauseReason != nil {
		ps.reason = *o.state.PauseReason
	}
	stored, err := state.LoadLite(dir)
	if err != nil {
		t.Errorf("reading the stored state while the run waits: %v", err)
	}
	ps.stored = stored
	if calls != nil {
		ps.provider = calls()
	}
	return ps
}

func taskStatus(t *testing.T, dir string, id int) pm.TaskStatus {
	t.Helper()
	s, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range s.Plan.Tasks {
		if task.ID == id {
			return task.Status
		}
	}
	t.Fatalf("no task #%d", id)
	return ""
}

// TestDiskFloor_BelowTheFloorNothingStarts: the run measures before the
// attempt, finds the volume below the floor, starts nothing, and records a
// disk_low pause — stored, not only in memory — whose detail names the volume,
// the free space and the floor, with a journal row saying the same. A stop
// while it waits ends the run and says so.
func TestDiskFloor_BelowTheFloorNothingStarts(t *testing.T) {
	dir := diskProject(t, false, &pm.Task{ID: 1, Title: "Build it", Priority: 1, Status: pm.TaskPending})
	prov := &mockProvider{name: "mock", results: []*provider.Result{{Output: "done\nTASK_DONE", Provider: "mock"}}}
	fd := &fakeDisk{free: []int64{lowB}}
	o := diskOrchestrator(t, dir, Config{}, prov, fd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var seen pauseSeen
	fd.onCall = func(i int) {
		if i == 2 { // the second re-measurement: the pause is long since stored
			seen = snapshotPause(t, o, dir, func() int { return prov.calls })
			cancel()
		}
	}

	err := o.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want the stop's context.Canceled", err)
	}
	if errors.Is(err, ErrStateNotPersisted) {
		t.Fatalf("Run = %v: the pause or the stop was not stored", err)
	}
	if prov.calls != 0 || seen.provider != 0 {
		t.Fatalf("the provider was called %d time(s) on a disk below the floor", prov.calls)
	}
	if got := taskStatus(t, dir, 1); got != pm.TaskPending {
		t.Errorf("task #1 is %s, want pending: no attempt may start below the floor", got)
	}

	if seen.status != "paused" || seen.reason.Code != pausereason.CodeDiskLow {
		t.Fatalf("while waiting the run was %q / %+v, want paused / disk_low", seen.status, seen.reason)
	}
	for _, want := range []string{"/srv/data", diskusage.HumanBytes(lowB), diskusage.HumanBytes(floorB)} {
		if !strings.Contains(seen.reason.Detail, want) {
			t.Errorf("pause detail %q does not name %q", seen.reason.Detail, want)
		}
	}
	if seen.stored == nil || !seen.stored.PausedFor(pausereason.CodeDiskLow) {
		t.Errorf("the stored state while waiting = %+v, want the disk_low pause on disk", seen.stored)
	}
	if !seen.stored.ClaimsLiveRun() {
		t.Error("a waiting disk_low pause does not claim a live run — the dashboard would offer Start")
	}

	paused := eventsOf(t, dir, state.EventSessionPaused)
	if len(paused) != 1 {
		t.Fatalf("session_paused rows = %d, want 1", len(paused))
	}
	for _, want := range []string{`"pause_code":"disk_low"`, `"floor_bytes":1073741824`, `"before":"task #1"`} {
		if !strings.Contains(paused[0].Details, want) {
			t.Errorf("journal details %s lack %s", paused[0].Details, want)
		}
	}

	// The stop, recorded as what it was.
	final, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !final.PausedFor(pausereason.CodeCancelled) || !strings.Contains(final.PauseReason.Detail, "waiting for disk space") {
		t.Errorf("after the stop the run is %q / %+v, want a cancelled pause naming the wait", final.Status, final.PauseReason)
	}
	if final.ClaimsLiveRun() {
		t.Error("a stopped run still claims to be live")
	}
}

// TestDiskFloor_SpaceReturningResumesTheRun: the run waits until every volume
// is back above the floor plus a tenth — not merely above the floor — then
// carries on by itself and does the work, journalling the resume.
func TestDiskFloor_SpaceReturningResumesTheRun(t *testing.T) {
	dir := diskProject(t, false, &pm.Task{ID: 1, Title: "Build it", Priority: 1, Status: pm.TaskPending})
	fd := &fakeDisk{free: []int64{lowB, lowB, midB, midB, highB}}
	var probesAtFirstCall int
	prov := &callbackProvider{onCall: func() { probesAtFirstCall = fd.count() }, output: "done\nTASK_DONE"}
	o := diskOrchestrator(t, dir, Config{}, prov, fd)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if prov.calls != 1 {
		t.Fatalf("provider calls = %d, want 1 after the disk recovered", prov.calls)
	}
	// Calls 0–3 return low, low, mid, mid: the run resumes at call 4, the
	// first reading above floor + 10%, and only then makes its attempt — and
	// the attempt's own check (call 5) passes too.
	if probesAtFirstCall != 6 {
		t.Errorf("the attempt started after %d probe(s), want 6: it must wait out readings above the floor but short of the resume margin", probesAtFirstCall)
	}
	if got := taskStatus(t, dir, 1); got != pm.TaskDone {
		t.Errorf("task #1 = %s, want done", got)
	}
	final, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "complete" || final.PauseReason != nil {
		t.Errorf("final status %q / %+v, want complete with no pause reason", final.Status, final.PauseReason)
	}
	resumed := 0
	for _, e := range eventsOf(t, dir, state.EventSessionStarted) {
		if strings.Contains(e.Message, "Run resumed: disk space recovered") && strings.Contains(e.Details, `"resumed_from":"disk_low"`) {
			resumed++
		}
	}
	if resumed != 1 {
		t.Errorf("resume journal rows = %d, want 1", resumed)
	}
	// Room again, so the reserve is back in place.
	if diskreserve.Held(dir) < diskreserve.Size {
		t.Error("the reserve was not put in place once there was room")
	}
}

// TestDiskFloor_ParallelWorkersStartNothingNew: the round in flight when the
// disk fills finishes and records its outcomes; the next round does not
// launch until there is room, and then it does.
func TestDiskFloor_ParallelWorkersStartNothingNew(t *testing.T) {
	dir := diskProject(t, false,
		&pm.Task{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "B", Priority: 1, Status: pm.TaskPending},
		&pm.Task{ID: 3, Title: "C", Priority: 1, Status: pm.TaskPending},
	)
	// Call 0: the first round's check, room. Call 1: the second round's,
	// low — the first round filled the disk. Calls 2–3: still low. Call 4:
	// room again.
	fd := &fakeDisk{free: []int64{highB, lowB, lowB, lowB, highB}}
	prov := &safeProvider{name: "mock", output: "done\nTASK_DONE"}
	o := diskOrchestrator(t, dir, Config{Parallel: true, MaxParallel: 2}, prov, fd)
	var seen pauseSeen
	var doneWhilePaused []pm.TaskStatus
	fd.onCall = func(i int) {
		if i == 3 {
			seen = snapshotPause(t, o, dir, func() int { prov.mu.Lock(); defer prov.mu.Unlock(); return prov.calls })
			for _, task := range o.state.Plan.Tasks {
				doneWhilePaused = append(doneWhilePaused, task.Status)
			}
		}
	}

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seen.status != "paused" || seen.reason.Code != pausereason.CodeDiskLow {
		t.Fatalf("while waiting the run was %q / %+v, want paused / disk_low", seen.status, seen.reason)
	}
	if seen.provider != 2 {
		t.Errorf("provider calls while paused = %d, want 2: the in-flight round finishes, nothing new starts", seen.provider)
	}
	want := []pm.TaskStatus{pm.TaskDone, pm.TaskDone, pm.TaskPending}
	if fmt.Sprint(doneWhilePaused) != fmt.Sprint(want) {
		t.Errorf("task statuses while paused = %v, want %v", doneWhilePaused, want)
	}
	if !strings.Contains(eventsOf(t, dir, state.EventSessionPaused)[0].Details, `"before":"task #3"`) {
		t.Error("the pause's journal row does not name the round it held back")
	}
	for id := 1; id <= 3; id++ {
		if got := taskStatus(t, dir, id); got != pm.TaskDone {
			t.Errorf("task #%d = %s after the disk recovered, want done", id, got)
		}
	}
}

// TestDiskFloor_EvolveRoundWaitsForSpace: an evolve round is work like a task
// attempt — it asks the provider for more and writes what comes back — so it
// does not start below the floor either, in either loop.
func TestDiskFloor_EvolveRoundWaitsForSpace(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel=%v", parallel), func(t *testing.T) {
			dir := diskProject(t, true, &pm.Task{ID: 1, Title: "Done already", Priority: 1, Status: pm.TaskDone})
			prov := &mockProvider{name: "mock"}
			fd := &fakeDisk{free: []int64{lowB}}
			cfg := Config{}
			if parallel {
				cfg.Parallel, cfg.MaxParallel = true, 2
			}
			o := diskOrchestrator(t, dir, cfg, prov, fd)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var seen pauseSeen
			fd.onCall = func(i int) {
				if i == 1 {
					seen = snapshotPause(t, o, dir, func() int { return prov.calls })
					cancel()
				}
			}
			if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v, want context.Canceled", err)
			}
			if prov.calls != 0 {
				t.Errorf("the provider was asked for an evolve round %d time(s) below the floor", prov.calls)
			}
			if seen.reason.Code != pausereason.CodeDiskLow {
				t.Errorf("pause while waiting = %+v, want disk_low", seen.reason)
			}
			if rows := eventsOf(t, dir, state.EventSessionPaused); len(rows) != 1 || !strings.Contains(rows[0].Details, `"before":"an evolve round"`) {
				t.Errorf("session_paused rows = %+v, want one naming the evolve round", rows)
			}
			if rows := eventsOf(t, dir, state.EventPlanComplete); len(rows) != 0 {
				t.Errorf("the plan's completion was announced %d time(s) before the run had room to evolve", len(rows))
			}
		})
	}
}

// TestDiskFloor_ENOSPCOnTheVerdictSpendsTheReserve: the disk fills between
// the check and the outcome. The verdict write fails with ENOSPC; the reserve
// is released, the verdict is written again and lands, the outcome is stored,
// and the run pauses before it starts anything else — whatever the volume
// reads — until there is room for the reserve again.
func TestDiskFloor_ENOSPCOnTheVerdictSpendsTheReserve(t *testing.T) {
	dir := diskProject(t, false,
		&pm.Task{ID: 1, Title: "Fill the disk", Priority: 1, Status: pm.TaskPending},
		&pm.Task{ID: 2, Title: "After", Priority: 2, Status: pm.TaskPending},
	)
	if _, err := diskreserve.Ensure(dir); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	var (
		mu             sync.Mutex
		verdictCalls   int
		reserveAtRetry = int64(-1)
	)
	prevWrite := writeVerdictFile
	t.Cleanup(func() { writeVerdictFile = prevWrite })
	writeVerdictFile = func(workDir string, v taskrecover.Verdict) error {
		mu.Lock()
		verdictCalls++
		n := verdictCalls
		mu.Unlock()
		switch n {
		case 1:
			if v.TaskID != 1 || v.Status != pm.TaskDone {
				t.Errorf("first verdict write = task #%d %s, want task #1's completion", v.TaskID, v.Status)
			}
			return &os.PathError{Op: "write", Path: taskrecover.VerdictPath(workDir, v.TaskID), Err: syscall.ENOSPC}
		case 2:
			mu.Lock()
			reserveAtRetry = diskreserve.Held(workDir)
			mu.Unlock()
		}
		return prevWrite(workDir, v)
	}

	// Room at every reading: the pause after the release is the reserve's
	// doing, not the probe's.
	fd := &fakeDisk{free: []int64{highB}}
	var seen pauseSeen
	prov := &mockProvider{name: "mock", results: []*provider.Result{
		{Output: "done\nTASK_DONE", Provider: "mock"},
		{Output: "done\nTASK_DONE", Provider: "mock"},
	}}
	o := diskOrchestrator(t, dir, Config{}, prov, fd)
	fd.onCall = func(i int) {
		if i == 2 { // the first re-measurement of the pause after task #1
			seen = snapshotPause(t, o, dir, func() int { return prov.calls })
		}
	}

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reserveAtRetry != 0 {
		t.Errorf("the reserve held %d bytes when the verdict was retried, want 0: it must be released first", reserveAtRetry)
	}
	v, err := taskrecover.ReadVerdict(dir, 1)
	if err != nil {
		t.Fatalf("task #1's verdict did not land: %v", err)
	}
	if v.Status != pm.TaskDone {
		t.Errorf("verdict status = %s, want done", v.Status)
	}
	if seen.status != "paused" || seen.reason.Code != pausereason.CodeDiskLow {
		t.Fatalf("after the reserve was spent the run was %q / %+v, want paused / disk_low", seen.status, seen.reason)
	}
	if !strings.Contains(seen.reason.Detail, "task #1's verdict") || !strings.Contains(seen.reason.Detail, "reserve") {
		t.Errorf("pause detail %q does not say the reserve was spent on task #1's verdict", seen.reason.Detail)
	}
	if seen.provider != 1 {
		t.Errorf("provider calls at the pause = %d, want 1: task #2 must wait", seen.provider)
	}
	if rows := eventsOf(t, dir, state.EventSessionPaused); len(rows) != 1 || !strings.Contains(rows[0].Details, "reserve_spent") {
		t.Errorf("session_paused rows = %+v, want one carrying reserve_spent", rows)
	}
	for id := 1; id <= 2; id++ {
		if got := taskStatus(t, dir, id); got != pm.TaskDone {
			t.Errorf("task #%d = %s, want done", id, got)
		}
	}
	if diskreserve.Held(dir) < diskreserve.Size {
		t.Error("the reserve was not put back once there was room")
	}
}

// TestDiskFloor_ENOSPCTwiceStopsStateNotPersisted: when the write fails again
// with the reserve released, the run stops as it did before the reserve
// existed, and the stop is recorded as state_not_persisted.
func TestDiskFloor_ENOSPCTwiceStopsStateNotPersisted(t *testing.T) {
	dir := diskProject(t, false, &pm.Task{ID: 1, Title: "Fill the disk", Priority: 1, Status: pm.TaskPending})
	if _, err := diskreserve.Ensure(dir); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	full := &os.PathError{Op: "write", Path: "state.db", Err: syscall.ENOSPC}
	failed := withFailingSave(t, func(s *state.ProjectState, mode saveMode) bool {
		return mode == mergeExternal && s.Plan != nil && s.Plan.Tasks[0].Status == pm.TaskDone
	})
	// withFailingSave answers errSaveInjected; this test wants the kernel's
	// word for it, so wrap the store once more.
	inner := saveState
	saveState = func(s *state.ProjectState, mode saveMode) error {
		if err := inner(s, mode); err != nil {
			return fmt.Errorf("save: %w", full)
		}
		return nil
	}

	fd := &fakeDisk{free: []int64{highB}}
	prov := &mockProvider{name: "mock", results: []*provider.Result{{Output: "done\nTASK_DONE", Provider: "mock"}}}
	o := diskOrchestrator(t, dir, Config{}, prov, fd)

	err := o.Run(context.Background())
	if !errors.Is(err, ErrStateNotPersisted) {
		t.Fatalf("Run = %v, want ErrStateNotPersisted", err)
	}
	if *failed != 2 {
		t.Errorf("the outcome write was tried %d time(s), want 2: once, then once more on the reserve", *failed)
	}
	if diskreserve.Held(dir) != 0 {
		t.Error("the reserve was not released for the retry")
	}
	final, lerr := state.LoadLite(dir)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if !final.PausedFor(pausereason.CodeStateNotPersisted) {
		t.Errorf("stored status %q / %+v, want state_not_persisted", final.Status, final.PauseReason)
	}
}

// TestDiskFloor_ZeroTurnsItOff: with the floor at 0 a run starts on any disk,
// keeps no reserve, and gives back one an earlier run left.
func TestDiskFloor_ZeroTurnsItOff(t *testing.T) {
	dir := diskProject(t, false, &pm.Task{ID: 1, Title: "Build it", Priority: 1, Status: pm.TaskPending})
	if _, err := diskreserve.Ensure(dir); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	fd := &fakeDisk{free: []int64{lowB}}
	prov := &mockProvider{name: "mock", results: []*provider.Result{{Output: "done\nTASK_DONE", Provider: "mock"}}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, MinFreeDiskMB: 0}, prov)
	o.diskProbe = fd.probe

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fd.count() != 0 {
		t.Errorf("free space was measured %d time(s) with the check off", fd.count())
	}
	if got := taskStatus(t, dir, 1); got != pm.TaskDone {
		t.Errorf("task #1 = %s, want done", got)
	}
	if _, err := os.Stat(diskreserve.Path(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the reserve is still there with the check off (%v)", err)
	}
}

// TestDiskFloor_UnmeasurableVolumeDoesNotHoldTheRun: a probe that fails is
// reported, and the run carries on — an unknown is not a full disk.
func TestDiskFloor_UnmeasurableVolumeDoesNotHoldTheRun(t *testing.T) {
	dir := diskProject(t, false, &pm.Task{ID: 1, Title: "Build it", Priority: 1, Status: pm.TaskPending})
	prov := &mockProvider{name: "mock", results: []*provider.Result{{Output: "done\nTASK_DONE", Provider: "mock"}}}
	o := diskOrchestrator(t, dir, Config{}, prov, &fakeDisk{free: []int64{highB}})
	o.diskProbe = func(...string) ([]diskusage.Volume, error) {
		return nil, errors.New("statfs: function not implemented")
	}
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := taskStatus(t, dir, 1); got != pm.TaskDone {
		t.Errorf("task #1 = %s, want done", got)
	}
}

func TestRoundNoun(t *testing.T) {
	cases := map[string][]*pm.Task{
		"the next round":      nil,
		"task #4":             {{ID: 4}},
		"tasks #4 and #7":     {{ID: 4}, {ID: 7}},
		"tasks #4, #7 and #9": {{ID: 4}, {ID: 7}, {ID: 9}},
	}
	for want, ready := range cases {
		if got := roundNoun(ready); got != want {
			t.Errorf("roundNoun(%d tasks) = %q, want %q", len(ready), got, want)
		}
	}
	if got := diskResumeBytes(1000); got != 1100 {
		t.Errorf("diskResumeBytes(1000) = %d, want 1100", got)
	}
}

// callbackProvider is a sequential provider that runs onCall before it
// answers, on the orchestrator's goroutine.
type callbackProvider struct {
	onCall func()
	output string
	calls  int
}

func (c *callbackProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	if c.calls == 0 && c.onCall != nil {
		c.onCall()
	}
	c.calls++
	return &provider.Result{Output: c.output, Provider: "mock"}, nil
}
func (c *callbackProvider) Name() string         { return "mock" }
func (c *callbackProvider) DefaultModel() string { return "mock-model" }
