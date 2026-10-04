package ui

// run_stop.go asks a project's run to stop, wherever the run is executing
// (Task 20348).
//
// The Stop button used to find runs by scanning this host's /proc for a
// `cloop run` whose working directory is the project. That finds a run the hub
// forked here, and nothing else. A run on an edge device is on another
// machine, and a run in a container sees a different filesystem, so a /proc
// scan never matches either. Pressing Stop on such a project answered "no
// running cloop process found" while the run carried on. The executor the hub
// dispatched to already knows how to deliver the signal; the budget stop was
// the only caller that asked it.

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

// runStopTimeout bounds asking an executor to stop a run. The driver may be a
// remote agent, and a Stop request must not hang on an unreachable one.
const runStopTimeout = 10 * time.Second

// stopDelivery is what asking a project's run to stop achieved.
type stopDelivery struct {
	// Signalled counts the deliveries that succeeded: the workload the hub
	// dispatched, plus any other `cloop run` found in the project directory.
	Signalled int
	// LocalFound counts the local `cloop run` processes found, whether or not
	// signalling them worked.
	LocalFound int
	// ExecutorErr is why the executor running the project's workload could not
	// be asked to stop it.
	ExecutorErr error
}

// failure describes a stop that found something to stop and could not deliver
// it, and reports whether there was one. A stop that found nothing is not a
// failure here: the caller decides what nothing means.
func (d stopDelivery) failure() (string, bool) {
	if d.Signalled > 0 {
		return "", false
	}
	if d.ExecutorErr != nil {
		return fmt.Sprintf("could not reach the executor running this project: %v", d.ExecutorErr), true
	}
	if d.LocalFound > 0 {
		return "found cloop processes but signalling failed (permission denied?)", true
	}
	return "", false
}

// interruptRun asks whatever is executing workDir to stop, the way Ctrl-C
// would: the run returns the task it was working on to pending and pauses, so
// starting it again picks up where it left off.
//
// Interrupt rather than kill. A killed run writes nothing, and the task it was
// executing stays in_progress until a recovery pass resets it.
//
// The dispatched workload is asked first, because the executor is the only
// route to a run on an isolated executor. The /proc scan follows for runs
// nobody dispatched — a `cloop run` started from a terminal in the project —
// which have no handle to ask.
func (s *Server) interruptRun(workDir string) stopDelivery {
	var d stopDelivery
	// reached is the host PID the executor delivered to, when it has one. A
	// run the hub forked on this host is also in the /proc scan below, and
	// must not be interrupted twice: a second SIGINT is how a CLI is
	// conventionally told to stop being graceful.
	reached := 0
	if run, ok := s.trackedRun(workDir); ok && run.ex != nil {
		ctx, cancel := context.WithTimeout(context.Background(), runStopTimeout)
		// A workload that already ended has nothing to stop, and counting a
		// signal to it as a delivery would tell the caller a run was stopped
		// when the project may only be showing a stale status.
		st, statusErr := run.ex.Status(ctx, run.handleID)
		if statusErr != nil || !st.State.Terminal() {
			if err := run.ex.Signal(ctx, run.handleID, executor.SignalInterrupt); err != nil {
				d.ExecutorErr = err
			} else {
				d.Signalled++
				// So that settling it counts a cancellation: an interrupted
				// run pauses and exits zero, which alone reads as finished.
				s.noteStopRequested(workDir, run.handleID)
				if statusErr == nil && run.ex.Kind() == executor.KindLocalProcess {
					reached = st.PID
				}
			}
		}
		cancel()
	}
	for _, pid := range multiui.CloopRunPIDsInDir(workDir) {
		if pid == reached {
			continue
		}
		d.LocalFound++
		d.Signalled += signalPIDs([]int{pid}, syscall.SIGINT)
	}
	return d
}
