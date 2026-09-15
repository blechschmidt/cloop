package ui

// stale_recovery.go resolves what a dead run left behind, at the moment the hub
// notices it died.
//
// A run that exits normally tidies up after itself: it writes a terminal status
// for the project and a terminal status for whatever task it was executing. A
// run that is killed — OOM killer, SIGKILL, host reboot — writes neither, and
// what it leaves is a project the dashboard renders as running forever. Both
// halves of that are on-screen state:
//
//   - ProjectState.Status is what the Run/Stop button and the health dot render
//     from, so a stale "running" means a Stop button that can never succeed.
//   - Tasks left in_progress render with a spinner, indistinguishable from a
//     task that is merely slow.
//
// Until this file, only the second half was repaired automatically (Task 20207)
// and the first half was repaired only when a human pressed Stop and read
// "cleared stale running status" — the report behind Task 20209. They are one
// event with two consequences, so they are repaired together, by one function,
// at every moment the hub can learn a run is gone:
//
//	dispatch site   the output stream closed          runEnded, with the
//	                                                  executor's verdict
//	watcher tick    running→stopped, or a persisted   reconcileDeadRun
//	                "running" with nothing behind it
//	startup         no edge to observe; sweep once    reconcileDeadRunsOnStartup
//	Stop pressed    the button found no process       handleStop
//
// See pkg/taskrecover for what recovery then decides about each task.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// staleRunGrace is how long a project must look dead before the watcher infers
// a stale status from the absence of a process alone.
//
// The other triggers have positive evidence — a stream that closed, a handle
// the driver calls terminal — and need no delay. Inference from an empty /proc
// scan has none, so it waits: a scan can miss a process that is mid-exec, and
// pausing a live run would be a worse bug than the one being fixed. Two
// watcher ticks is enough for a transient miss to correct itself.
const staleRunGrace = 5 * time.Second

// staleRunRetry is how long the watcher waits before trying again after a
// repair it could not apply. Reaching this at all means something is wrong with
// the project — its state points at another directory, its database will not
// open — and retrying such a project on every tick would cost a full state load
// and a warning line each time, forever.
const staleRunRetry = time.Minute

// workloadStatusTimeout bounds the Status call made while settling a finished
// run. The driver may be a remote agent, and a hub must not block a watcher
// tick or a run goroutine on an unreachable one.
const workloadStatusTimeout = 5 * time.Second

// dispatchedRun is the workload this hub started for a project.
//
// It is remembered so that liveness can be settled by asking the driver rather
// than by inferring it from whether output is still arriving. Those are not the
// same question: the output stream stays open while *anything* holding the
// workload's stdout is alive, so a background process the agent left behind
// keeps it open long after the run itself is gone. A hub reading the stream as
// liveness then believes the project is running forever, which is exactly the
// state a human had to clear by hand.
type dispatchedRun struct {
	ex       executor.Executor
	handleID string
}

// trackRun remembers the workload dispatched for workDir.
func (s *Server) trackRun(workDir string, ex executor.Executor, handleID string) {
	if workDir == "" || ex == nil || handleID == "" {
		return
	}
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	if s.runHandles == nil {
		s.runHandles = make(map[string]dispatchedRun)
	}
	s.runHandles[workDir] = dispatchedRun{ex: ex, handleID: handleID}
}

// untrackRun forgets workDir's workload. The map is therefore bounded by the
// number of runs currently in flight rather than by the number this hub has
// ever started.
func (s *Server) untrackRun(workDir string) {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	delete(s.runHandles, workDir)
}

// trackedRun returns the workload dispatched for workDir, if this hub started
// one and it has not yet been settled.
func (s *Server) trackedRun(workDir string) (dispatchedRun, bool) {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	run, ok := s.runHandles[workDir]
	return run, ok
}

// projectExecuting reports whether anything is currently executing this
// project.
//
// Three sources, in order of authority:
//
//   - A local `cloop run` process. Conclusive when present, and free.
//   - The driver's own view of a workload this hub dispatched. Conclusive
//     whenever there is one, and the only source that works for an isolated
//     executor, whose workload owns tasks with no local process to find.
//   - The live-log flag, for a run this hub is streaming but whose handle it no
//     longer holds.
//
// The flag is the fallback rather than the answer because the stream it tracks
// outlives the workload whenever something inherited the workload's stdout: a
// background process the agent left behind holds the pipe open, the driver
// never reports EOF, and a hub reading that as liveness believes the project is
// running forever — which is the state a human had to clear by hand.
//
// It fails closed: a driver that cannot be reached is treated as still running
// it, because refusing to repair is always recoverable and repairing a live run
// is not.
func (s *Server) projectExecuting(workDir string) bool {
	if multiui.IsCloopRunningInDir(workDir) {
		return true
	}
	if run, ok := s.trackedRun(workDir); ok {
		ctx, cancel := context.WithTimeout(context.Background(), workloadStatusTimeout)
		defer cancel()
		st, err := run.ex.Status(ctx, run.handleID)
		if err != nil {
			return true
		}
		return !st.State.Terminal()
	}
	return s.liveLogRunningFor(workDir)
}

// runVerdict is how a run ended, in terms a project's event journal can carry.
// The zero value says only that the run is gone, which is all the watcher and
// the startup sweep ever know.
type runVerdict struct {
	// Detail names the cause in a sentence fragment, e.g. "it was killed by a
	// signal cloop did not send". Empty when nothing is known.
	Detail string
	// OOM reports that the evidence points at an out-of-memory kill, which is
	// worth saying out loud because the remedy is different from every other
	// cause: give the executor more memory, or make the task smaller.
	OOM bool
	// Requested reports that cloop itself asked for the kill — the Stop
	// button, not a crash. It is the difference between a pause the operator
	// chose and one that happened to them, and only the latter is worth
	// flagging as something that went wrong (Task 20285).
	Requested bool
}

// deadRunPauseReason turns a verdict about a vanished run into the reason the
// dashboard shows. A stop the operator asked for is not a fault and should not
// be dressed as one; everything else is a run that ended without saying so.
func deadRunPauseReason(v runVerdict) pausereason.Reason {
	if v.Requested {
		return pausereason.New(pausereason.CodeOperator, "run stopped")
	}
	detail := "previous run ended without reporting an outcome"
	if v.Detail != "" {
		detail = "previous run ended unexpectedly: " + v.Detail
	}
	return pausereason.New(pausereason.CodeStale, detail)
}

// runEnded settles a run whose output stream has closed. Every dispatch site
// funnels through it so a run that died the same way is recorded the same way,
// whichever handler started it.
//
// Callers must have cleared their live-log running flag first: this asks
// projectExecuting whether anything is still running the project, and a flag
// left standing would answer yes about the very run being settled.
func (s *Server) runEnded(workDir string, ex executor.Executor, handleID string) {
	verdict := workloadVerdict(ex, handleID)
	s.untrackRun(workDir)
	s.reconcileDeadRun(workDir, verdict)
}

// workloadVerdict asks the driver how a finished workload ended.
//
// The OOM determination rests on one property of the drivers: a termination
// cloop requested carries the reason the requester gave, so a kill that reports
// only the kernel's bare account ("signal: killed", or a container's exit 137)
// is by construction one nothing in cloop asked for. On a host that just lost a
// process to SIGKILL without anyone sending it, the OOM killer is far and away
// the likeliest explanation — so the message says "typically", and names the
// alternative rather than asserting a cause it cannot prove.
func workloadVerdict(ex executor.Executor, handleID string) runVerdict {
	if ex == nil || handleID == "" {
		return runVerdict{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), workloadStatusTimeout)
	defer cancel()
	st, err := ex.Status(ctx, handleID)
	if err != nil {
		return runVerdict{Detail: "its executor could not say how it ended"}
	}

	switch {
	case unrequestedKill(st):
		return runVerdict{
			Detail: "it was killed by a signal that cloop did not send — typically the kernel's " +
				"out-of-memory killer, otherwise an external kill",
			OOM: true,
		}
	case st.State == executor.StateKilled:
		// unrequestedKill already claimed the signal kills above, so what is
		// left here is a stop cloop asked for.
		return runVerdict{
			Detail:    "it was killed before it finished (" + st.Error + ")",
			Requested: true,
		}
	case st.State == executor.StateFailed:
		detail := st.Error
		if detail == "" {
			detail = "the executor lost track of it"
		}
		return runVerdict{Detail: "its executor reported a failure (" + detail + ")"}
	case st.ExitCode != 0:
		return runVerdict{Detail: fmt.Sprintf("it exited with status %d", st.ExitCode)}
	default:
		return runVerdict{Detail: "it exited without recording an outcome"}
	}
}

// unrequestedKill reports whether a status describes a SIGKILL that cloop did
// not ask for. Exit 137 is the same event seen through a container runtime,
// which reports 128+SIGKILL rather than a signal.
func unrequestedKill(st executor.Status) bool {
	if st.ExitCode == 137 {
		return true
	}
	if st.State != executor.StateKilled {
		return false
	}
	return st.Error == "" || strings.Contains(st.Error, "signal: killed")
}

// reconcileDeadRunsOnStartup sweeps every registered project once, as the hub
// comes up.
//
// The running→stopped edge cannot cover this case, because the edge needs a
// previous state and a hub that has just started has none. That is not a corner
// case: the incident this file exists for took out the hub and the run
// together, so by the time anything was watching again there was no transition
// left to observe. A hub that restarts should not need someone to press Run
// before it stops showing work that nothing is doing.
//
// Failures are per-project and non-fatal — one unreadable project must not stop
// the sweep, and none of this is worth delaying startup over.
func (s *Server) reconcileDeadRunsOnStartup() {
	for _, e := range s.allProjectEntries() {
		s.reconcileDeadRun(e.Path, runVerdict{})
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

// reconcileDeadRun repairs everything a departed run left behind for one
// project: the tasks it stranded in_progress, and the "running" status it never
// got to clear. It is a no-op for a project whose run ended cleanly, because a
// run that ended cleanly left neither.
//
// It reports whether it cleared a stale running status, which is what the Stop
// button branches on to choose between "we signalled the run" and "there was
// nothing to signal, so we tidied up after it".
//
// The liveness checks are a second line of defence rather than the primary one:
// resetting a task out from under a process that is still executing it would be
// far worse than the bug this fixes, so the check is repeated immediately before
// the write as well as before the read. A run that starts inside that window
// loses nothing — it runs its own recovery pass before it schedules anything.
func (s *Server) reconcileDeadRun(workDir string, verdict runVerdict) bool {
	if workDir == "" || s.projectExecuting(workDir) {
		return false
	}

	st, err := state.Load(workDir)
	if err != nil || st == nil {
		return false
	}

	// ProjectState.WorkDir is a *persisted* field and Load only fills it when
	// it is empty, so a project whose directory was copied, moved or restored
	// comes back pointing at wherever it used to live — and SaveDirect follows
	// that pointer rather than the path we read from. Reconciling would then
	// judge one project by another's artifacts and write the verdict into the
	// wrong plan. Refuse instead: a repair skipped is recoverable, a repair
	// applied to the wrong project is not.
	if !sameDir(st.WorkDir, workDir) {
		s.log().Warn(logger.EventCheckpoint, 0, "stale-run recovery: skipped, state points at another directory",
			map[string]interface{}{"project": workDir, "state_workdir": st.WorkDir})
		return false
	}

	outcomes := taskrecover.Reconcile(workDir, st.Plan)

	// "paused" is the terminal the orchestrator itself writes on a graceful
	// interrupt, and it is deliberately used for a killed run too: the field
	// says whether a run is in flight and whether one may be started, and both
	// answers are the same however the last one ended. A second terminal status
	// would only fragment the recovery path — but *why* it ended now rides
	// along in the pause reason rather than only in the event journal, so a
	// dashboard can distinguish "this crashed" from "this finished cleanly"
	// without joining two stores (Task 20285).
	claimed := st.Status
	staleStatus := claimed == "running" || claimed == "evolving"
	if staleStatus {
		st.SetPaused(deadRunPauseReason(verdict))
	}

	if len(outcomes) == 0 && !staleStatus {
		return false
	}

	// Re-check before committing: a run may have started while we were
	// loading. Dropping the repair is always safe, writing over a live run is
	// not.
	if s.projectExecuting(workDir) {
		return false
	}
	if err := st.SaveDirect(); err != nil {
		s.log().Warn(logger.EventCheckpoint, 0, "stale-run recovery: persist repaired state",
			map[string]interface{}{"project": workDir, "error": err.Error()})
		return false
	}

	for _, oc := range outcomes {
		taskrecover.LogOutcome(workDir, oc)
	}
	if staleStatus {
		logDeadRun(workDir, claimed, verdict, len(outcomes))
		s.broadcastRunState(workDir, false, true)
	}

	s.broadcastStateDiff(workDir, st)
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
	return staleStatus
}

// logDeadRun records the death in the project's event journal, so the timeline
// says why a project stopped instead of only showing that it did.
//
// Best-effort, like every other event write: observability must never be the
// reason a repair fails.
func logDeadRun(workDir, claimed string, verdict runVerdict, repaired int) {
	var b strings.Builder
	b.WriteString("The run ended without recording an outcome")
	if verdict.Detail != "" {
		b.WriteString(": ")
		b.WriteString(verdict.Detail)
	}
	fmt.Fprintf(&b, ". Its status was reset from %s to paused so the project can be started again", claimed)
	switch repaired {
	case 0:
	case 1:
		b.WriteString(", and 1 task it left in progress was recovered")
	default:
		fmt.Fprintf(&b, ", and %d tasks it left in progress were recovered", repaired)
	}
	b.WriteString(".")
	if verdict.OOM {
		b.WriteString(" If this repeats, give the executor more memory or reduce what the run holds at once.")
	}

	state.LogEvent(workDir, state.EventRow{
		Type:    state.EventSessionFailed,
		Step:    state.NoStep,
		Message: b.String(),
	})
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
