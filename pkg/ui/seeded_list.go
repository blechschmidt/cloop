package ui

// seeded_list.go is the projects list's view of a run carried out as a seed
// (Task 20514).
//
// A project bound to an executor that cannot read this hub's filesystem runs
// on a copy of itself on the device and brings its state back only when the
// run ends (run_result.go). Until then the hub's copy says how the *previous*
// run ended. /api/state has shown the run in flight over that copy since Tasks
// 20349 (its status) and 50 (the plan it is working through), but the projects
// list was built from the copy alone. So the grid's card, the project
// switcher, the feature chips and the glasses' list described the previous run
// for as long as the current one lasted. On 2026-11-22 a run of
// sgx-rust-attestation was working through its tasks on the sgx device, its
// lease renewed "while its run is live", and its card said health "idle" with
// "Paused: executor … stopped answering and nothing replaced the run", left on
// the copy by the run before it.
//
// The list now shows such a run as /api/state does: running, without the
// previous run's pause, and with the counts of the plan the device reports.
// Like the overlay on /api/state it is a view: the status cache keeps saying
// what the databases say, because stale-run detection compares the status the
// record claims with what is executing, and a view in its place would claim a
// run the record does not.

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
)

// seededTallies keeps the counts of each seeded run's plan, by project path,
// with what they were counted from. The list is served on every page load and
// pushed on every change anywhere on the hub, and a count takes a load of the
// project and a merge of the device's report, which only a new report or a
// change to the hub's copy can change.
type seededTallies struct {
	mu sync.Mutex
	m  map[string]seededTally
}

// seededTally is the counts of one run's plan and what they were counted from.
type seededTally struct {
	run    string            // the run: executor and handle
	report [sha256.Size]byte // the device's report
	record time.Time         // the hub copy's state files
	counts multiui.ProjectStatus
}

func (t *seededTallies) lookup(path string, key seededTally) (multiui.ProjectStatus, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	got, ok := t.m[path]
	if !ok || got.run != key.run || got.report != key.report || !got.record.Equal(key.record) {
		return multiui.ProjectStatus{}, false
	}
	return got.counts, true
}

func (t *seededTallies) store(path string, tally seededTally) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = make(map[string]seededTally)
	}
	t.m[path] = tally
}

// keepOnly forgets the counts of every project not in live, so the map is
// bounded by the seeded runs in flight.
func (t *seededTallies) keepOnly(live map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for path := range t.m {
		if _, ok := live[path]; !ok {
			delete(t.m, path)
		}
	}
}

// seededRunViews returns statuses with each project whose seeded run is in
// flight described as that run, and a signature of what it says about them —
// empty when there is none — so the project watcher can tell when a device's
// progress changed the list.
//
// statuses is the shared status cache; a project this changes is changed on a
// copy.
func (s *Server) seededRunViews(statuses []multiui.ProjectStatus) ([]multiui.ProjectStatus, string) {
	var (
		out  []multiui.ProjectStatus
		live map[string]struct{}
		sig  []string
	)
	for i := range statuses {
		// A run in flight is live by the scan that set Running: this
		// member's tracked handles and other members' owner rows are both
		// in it. So only projects with a run are asked about, which keeps
		// this to the handful of those rather than the whole registry.
		if !statuses[i].Running || !statuses[i].HasProject {
			continue
		}
		v, ok := s.seededRunView(statuses[i])
		if !ok {
			continue
		}
		if out == nil {
			out = append([]multiui.ProjectStatus(nil), statuses...)
			live = make(map[string]struct{}, 1)
		}
		out[i] = v
		live[v.Path] = struct{}{}
		sig = append(sig, fmt.Sprintf("%s\x00%s\x00%s\x00%d/%d/%d/%d\x00%d", v.Path, v.Status, v.Health,
			v.TotalTasks, v.DoneTasks, v.FailedTasks, v.ActiveTasks, v.LastActivity.UnixNano()))
	}
	s.seededTallies.keepOnly(live)
	if out == nil {
		return statuses, ""
	}
	sort.Strings(sig)
	return out, strings.Join(sig, "\x01")
}

// seededRunView is st as the seeded run in flight for it would describe it, and
// false when no such run is in flight.
//
// Running, as overlaySeededRunStatus says it, so the pause the previous run
// left — the reason the card printed under it — goes too. The counts are those
// of the plan /api/state shows: the hub's copy with the device's newest report
// merged over it, when this member holds one. A run another member follows is
// reported to that member, so its counts stay the hub copy's, as its plan does
// on /api/state.
func (s *Server) seededRunView(st multiui.ProjectStatus) (multiui.ProjectStatus, bool) {
	self, live := s.seededRunLive(st.Path)
	if !live {
		return st, false
	}
	if self {
		if c, ok := s.seededRunCounts(st.Path); ok {
			st.TotalTasks, st.DoneTasks, st.FailedTasks, st.ActiveTasks =
				c.TotalTasks, c.DoneTasks, c.FailedTasks, c.ActiveTasks
			if c.LastActivity.After(st.LastActivity) {
				st.LastActivity = c.LastActivity
			}
		}
	}
	if st.Status != "running" && st.Status != "evolving" {
		st.Status = "running"
		st.PauseReason = nil
	}
	st.Running = true
	st.RefreshHealth()
	return st, true
}

// seededRunCounts returns the task counts, and the newest task start or finish,
// of the plan the seeded run this member follows for workDir is working
// through: the hub's copy with the device's newest report merged over it,
// exactly as /api/state renders it. False when there is no report to count.
func (s *Server) seededRunCounts(workDir string) (multiui.ProjectStatus, bool) {
	run, ok := s.seededRunHandle(workDir)
	if !ok {
		return multiui.ProjectStatus{}, false
	}
	fetcher, ok := run.ex.(executor.InterimProjectResultFetcher)
	if !ok {
		return multiui.ProjectStatus{}, false
	}
	res, err := fetcher.InterimProjectResult(run.handleID)
	if err != nil || len(res.Data) == 0 {
		return multiui.ProjectStatus{}, false
	}
	record, _ := stateModTime(workDir)
	key := seededTally{
		run:    seededKey(run.ex.ID(), run.handleID),
		report: sha256.Sum256(res.Data),
		record: record,
	}
	if c, ok := s.seededTallies.lookup(workDir, key); ok {
		return c, true
	}

	ps, err := state.LoadLite(workDir)
	if err != nil {
		return multiui.ProjectStatus{}, false
	}
	// The same merge /api/state shows, on a copy of the plan. A report that
	// arrived since the fetch above is the one merged; its digest differs, so
	// the next lookup counts again.
	s.overlaySeededRunPlan(workDir, ps)
	var c multiui.ProjectStatus
	c.CountTasks(ps.Plan)
	if ps.Plan != nil {
		for _, t := range ps.Plan.Tasks {
			if t == nil {
				continue
			}
			for _, at := range []*time.Time{t.StartedAt, t.CompletedAt} {
				if at != nil && at.After(c.LastActivity) {
					c.LastActivity = *at
				}
			}
		}
	}
	key.counts = c
	s.seededTallies.store(workDir, key)
	return c, true
}
