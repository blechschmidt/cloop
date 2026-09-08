package ui

// stale_recovery.go resolves tasks stranded by a run that died, at the moment
// the hub notices it died.
//
// The orchestrator recovers stale tasks too, but only when the next run starts.
// That is too late to be the whole answer: until someone presses Run, the
// dashboard keeps rendering a task as in_progress with a spinner on it, and
// there is no process anywhere that intends to finish it. To an operator that
// is indistinguishable from a task that is merely slow, which is how a dead
// run's leftovers get read as "stuck" — the report that produced this file,
// with liebid's task 63 sitting in_progress for hours after its run was
// OOM-killed while its finished output lay in the live artifact.
//
// The watcher already samples per-project run state on a tick and dedups the
// result into a running→stopped edge. That edge is the honest trigger: it fires
// exactly once, and only after a run this hub had seen running has stopped
// being visible. See pkg/taskrecover for what recovery then decides.

import (
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// reconcileStaleTasksOnStartup sweeps every registered project once, as the
// hub comes up.
//
// The running→stopped edge cannot cover this case, because the edge needs a
// previous state and a hub that has just started has none. That is not a corner
// case: the incident this file exists for took out the hub and the run
// together, so by the time anything was watching again there was no transition
// left to observe and the finished task simply stayed in_progress. A hub that
// restarts should not need someone to press Run before it stops showing work
// that nothing is doing.
//
// Failures are per-project and non-fatal — one unreadable project must not stop
// the sweep, and none of this is worth delaying startup over.
func (s *Server) reconcileStaleTasksOnStartup() {
	for _, e := range s.allProjectEntries() {
		s.reconcileStaleTasks(e.Path)
	}
}

// wasRunning reports the last run state this server broadcast for workDir, and
// whether it has ever broadcast one. Read under the same mutex broadcastRunState
// writes, so the edge test and the broadcast agree on ordering.
func (s *Server) wasRunning(workDir string) (running, known bool) {
	s.runStateMu.Lock()
	defer s.runStateMu.Unlock()
	prev, ok := s.runStates[workDir]
	return prev, ok
}

// reconcileStaleTasks repairs tasks left in_progress by a run that has exited,
// then pushes the repaired plan to connected clients.
//
// Callers must have observed a running→stopped transition. The liveness checks
// here are a second line of defence rather than the primary one: resetting a
// task out from under a process that is still executing it would be a far worse
// bug than the one this fixes, so the check is repeated immediately before the
// write as well as before the read. A run that starts inside that window loses
// nothing — it runs its own recovery pass before it schedules anything.
func (s *Server) reconcileStaleTasks(workDir string) {
	if workDir == "" || s.projectExecuting(workDir) {
		return
	}

	st, err := state.Load(workDir)
	if err != nil || st == nil || st.Plan == nil {
		return
	}

	// ProjectState.WorkDir is a *persisted* field and Load only fills it when
	// it is empty, so a project whose directory was copied, moved or restored
	// comes back pointing at wherever it used to live — and SaveDirect follows
	// that pointer rather than the path we read from. Reconciling would then
	// judge one project by another's artifacts and write the verdict into the
	// wrong plan. Refuse instead: a repair skipped is recoverable, a repair
	// applied to the wrong project is not.
	if !sameDir(st.WorkDir, workDir) {
		s.log().Warn(logger.EventCheckpoint, 0, "stale-task recovery: skipped, state points at another directory",
			map[string]interface{}{"project": workDir, "state_workdir": st.WorkDir})
		return
	}

	outcomes := taskrecover.Reconcile(workDir, st.Plan)
	if len(outcomes) == 0 {
		return
	}

	// Re-check before committing: a run may have started while we were
	// loading. Dropping the repair is always safe, writing over a live run is
	// not.
	if s.projectExecuting(workDir) {
		return
	}
	if err := st.SaveDirect(); err != nil {
		s.log().Warn(logger.EventCheckpoint, 0, "stale-task recovery: persist repaired plan",
			map[string]interface{}{"project": workDir, "error": err.Error()})
		return
	}

	for _, oc := range outcomes {
		taskrecover.LogOutcome(workDir, oc)
	}

	s.broadcastStateDiff(workDir, st)
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
}

// sameDir reports whether two paths denote the same directory, resolving
// symlinks where it can. An empty stored WorkDir is treated as a match: Load
// backfills it from the load path in that case, so there is no other directory
// it could mean.
func sameDir(a, b string) bool {
	if a == "" {
		return true
	}
	resolve := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			return real
		}
		return abs
	}
	return resolve(a) == resolve(b)
}

// projectExecuting reports whether anything is currently executing this
// project — a local `cloop run` process, or a run this hub is streaming from an
// executor. Both are checked because neither alone is sufficient: a remote
// executor's workload owns tasks without any local process to find, and an
// externally started CLI run has no live-log stream here.
func (s *Server) projectExecuting(workDir string) bool {
	return multiui.IsCloopRunningInDir(workDir) || s.liveLogRunningFor(workDir)
}
