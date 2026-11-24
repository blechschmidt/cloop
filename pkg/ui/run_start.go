package ui

// run_start.go: one start of a project's run at a time on a hub member, and a
// started run's predecessor's pause retired (Task 20516).
//
// The hub starts runs by itself — after a usage cap, a readers change, and
// since Task 20516 the moment a run on a device comes back to work that was
// added on the hub while it was out. That last one fires exactly when a person
// is likely to be looking at the project, and may press Run at the same
// moment. Every start path checked projectExecuting and then took the
// project's run claim, but neither says anything about a start still in
// progress: a dispatch takes seconds (the seed, a feature's bundle, an image),
// nothing is tracked until it returns, and the cluster claim is granted again
// to the member that already holds it. Two starts on one member could both
// dispatch a harness into the same project, which then race for the same
// tasks. claimRun now refuses a second start while one is in progress or while
// runEnded is settling the project's last run, and projectExecuting counts a
// start in progress as a run. runEnded forgets only the run it settled, so a
// run started just before it began settling is not let go of with it.
//
// And a run carried out as a seed retires, as it is dispatched, the pause the
// hub would otherwise restart its project for (retireDuePause).

import (
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
)

// errRunStarting is claimRun's answer while this member is already starting
// the project's run, or still follows one.
var errRunStarting = errors.New("a run for this project is already being started or settled on this hub member")

// runStartGrace bounds how long a start counts as in progress. Every start
// path ends its start — the run tracked, or the claim released — within the
// dispatch it makes; this only keeps a start whose path panicked between the
// two from holding the project for the life of the process. Far above the
// slowest dispatch: an image pull on a slow link.
const runStartGrace = 30 * time.Minute

// runSettleGrace bounds how long a run being settled holds back the next
// start, for the same reason: runEnded clears its mark as it returns, panic or
// not, and only a settle stuck for good would hold the project longer. Far
// above the slowest settle: a result fetched from a slow device, a push
// write-back reported.
const runSettleGrace = 15 * time.Minute

// runSettleWait is how long a start waits for the project's last run to be
// settled before it is refused (claimRun). A run's end reaches the dashboard
// before runEnded has merged its result, so Run is offered — and pressed —
// in that moment; it starts once the result is in, rather than answering
// that a run is in progress. A variable so a test can shorten it.
var runSettleWait = 30 * time.Second

// beginRunStart records that this member is starting workDir's run, and
// reports whether it may: not while it is starting one already, and not while
// runEnded is settling one — a run started then would be dispatched from a
// plan its predecessor's result has not been merged into yet.
//
// A run this member follows whose workload has exited, and which nobody is
// settling, does not stop a start: its output stream can stay open as long as
// anything the agent left behind holds it, and a new run replaces it, as it
// always did.
func (s *Server) beginRunStart(workDir string) bool {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	if run, ok := s.runHandles[workDir]; ok && settlingNow(run) {
		return false
	}
	if at, ok := s.runStarts[workDir]; ok && time.Since(at) < runStartGrace {
		return false
	}
	if s.runStarts == nil {
		s.runStarts = make(map[string]time.Time)
	}
	s.runStarts[workDir] = time.Now()
	return true
}

// endRunStart forgets that this member is starting workDir's run: the start
// was given up, or the run is tracked now (trackRunWithCancel), which answers
// for it from here on.
func (s *Server) endRunStart(workDir string) {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	delete(s.runStarts, workDir)
}

// markRunSettling records that runEnded is settling handleID's run of
// workDir, when it is the run this member follows.
func (s *Server) markRunSettling(workDir, handleID string) {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	if run, ok := s.runHandles[workDir]; ok && run.handleID == handleID {
		run.settling = time.Now()
		s.runHandles[workDir] = run
	}
}

// clearRunSettling takes the mark off handleID's run of workDir if it is still
// followed: runEnded returning without having forgotten it — a panic part-way
// — leaves it as it was before it was settled, an ended run the next start
// replaces.
func (s *Server) clearRunSettling(workDir, handleID string) {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	if run, ok := s.runHandles[workDir]; ok && run.handleID == handleID && !run.settling.IsZero() {
		run.settling = time.Time{}
		s.runHandles[workDir] = run
	}
}

// settlingNow reports whether run is being settled, within runSettleGrace.
func settlingNow(run dispatchedRun) bool {
	return !run.settling.IsZero() && time.Since(run.settling) < runSettleGrace
}

// settlingRun reports whether runEnded is settling a run of workDir here.
func (s *Server) settlingRun(workDir string) bool {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	run, ok := s.runHandles[workDir]
	return ok && settlingNow(run)
}

// awaitSettled waits, up to runSettleWait, for runEnded to finish settling the
// project's last run, and reports whether it has.
func (s *Server) awaitSettled(workDir string) bool {
	deadline := time.Now().Add(runSettleWait)
	for s.settlingRun(workDir) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return true
}

// untrackSettledRun forgets handleID's run of workDir as runEnded finishes
// settling it, and releases the project's run claim — unless another run of
// the project has been started here since, whose tracked handle or start in
// progress the claim now belongs to. Forgetting whatever was tracked, as
// untrackRun does, let go of that newer run: untracked while it ran, and its
// claim released for a third run to take.
func (s *Server) untrackSettledRun(workDir, handleID string) {
	s.runHandleMu.Lock()
	run, tracked := s.runHandles[workDir]
	if tracked && run.handleID != handleID {
		s.runHandleMu.Unlock()
		return
	}
	delete(s.runHandles, workDir)
	s.runHandleMu.Unlock()
	s.releaseClaimUnlessStarting(workDir)
}

// releaseClaimUnlessStarting releases workDir's run claim for a run this
// member has let go of, unless a start of the project is in progress here: the
// claim was taken again for that start (a member re-claiming what it holds
// only refreshes the row), and releasing it, or the start's mark, would leave
// that run unclaimed and a second start free to begin beside it.
func (s *Server) releaseClaimUnlessStarting(workDir string) {
	if s.runStarting(workDir) {
		return
	}
	s.releaseRunClaim(workDir)
}

// runStarting reports whether this member is starting workDir's run.
func (s *Server) runStarting(workDir string) bool {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	at, ok := s.runStarts[workDir]
	return ok && time.Since(at) < runStartGrace
}

// retireDuePause records, as a run carried out as a seed is dispatched for
// workDir, that a pause the hub restarts by itself has been acted on.
//
// Such a run works on its own copy of the project, so the hub's copy keeps the
// previous run's status until this run's result is merged into it. A usage
// cap's, a readers change's or added work's pause left there would read as due
// again the moment this run ended without bringing anything back — a run that
// failed to start its project, a device too old to report — and the hub would
// start another run, and that one another, without end. It is replaced with
// what it will say should this run never report: that a run was started and
// has not reported back. A run on this filesystem writes its own status as it
// starts, and is left alone.
func (s *Server) retireDuePause(workDir string, ex executor.Executor, handleID string) {
	if !isSeededDispatch(ex, handleID) {
		return
	}
	st, err := state.LoadLite(workDir)
	if err != nil || st == nil || st.Status != "paused" || !st.PauseReason.ResumedByHub() {
		return
	}
	st.SetPaused(pausereason.New(pausereason.CodeStale,
		fmt.Sprintf("a run started on executor %s has not reported its outcome", ex.ID())))
	if err := st.SaveDirect(); err != nil {
		s.log().Warn(logger.EventSessionStart, 0, "could not retire the pause a started run acted on",
			map[string]interface{}{"project": workDir, "error": err.Error()})
	}
}
