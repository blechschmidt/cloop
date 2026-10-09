// executor_supervisor.go wires the liveness supervisor into the Web UI
// (Task 20162).
//
// Three things are joined here, and each of them is the reason the other two
// are not enough on their own:
//
//   - The supervisor probes registered executors and flips their scheduling
//     state. Without it, a remote edge device that dropped off the network
//     stays "registered" forever and the next run is dispatched into a void.
//   - Session tracking records every workload the UI dispatches, with the claim
//     token that makes requeue exactly-once. Without it the supervisor knows a
//     node died but not what died with it.
//   - The failover handler turns "node N is unreachable and held session S"
//     into "task T is failed-with-retry and a replacement run is started on
//     node M". Without it the first two produce an accurate, useless report.
//
// The supervisor is package-level rather than a Server field for the same
// reason controlPlaneDirValue is: startWorkload has no Server receiver, because
// it is called from handlers that only know a project path.

package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var (
	supervisorMu    sync.RWMutex
	fleetSupervisor *executor.Supervisor
	fleetStopFn     func()
)

// executorSupervisor returns the running supervisor, or nil before bootstrap.
// Every caller must handle nil: a Server built as a struct literal (as many
// tests do) never bootstraps, and the Executors panel must still render.
func executorSupervisor() *executor.Supervisor {
	supervisorMu.RLock()
	defer supervisorMu.RUnlock()
	return fleetSupervisor
}

// newScheduler opens a Scheduler over the control plane's database.
//
// It opens a fresh handle per call rather than holding one open for the process
// lifetime, matching lookupProjectExecutor. The cost is a file open on a path
// that is already in the OS cache; the benefit is that no long-lived handle
// stands between the database and `cloop db maintain`.
func newScheduler(dir string) (*executorstore.Scheduler, *statedb.DB, error) {
	if dir == "" {
		return nil, nil, fmt.Errorf("ui: control plane directory is not set")
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil, nil, fmt.Errorf("ui: open control-plane database: %w", err)
	}
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return sched, db, nil
}

// startExecutorSupervisor launches fleet supervision for the control plane
// rooted at dir. It is idempotent; a second call is a no-op.
//
// Failure to start is logged and swallowed. A control plane whose database
// cannot be opened must still serve the dashboard — losing liveness
// supervision degrades scheduling, but refusing to boot loses everything.
func startExecutorSupervisor(dir string) {
	supervisorMu.Lock()
	defer supervisorMu.Unlock()
	if fleetSupervisor != nil {
		return
	}

	sched, db, err := newScheduler(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: executor supervisor disabled: %v\n", err)
		return
	}

	sv := executor.NewSupervisor(
		executor.DefaultRegistry,
		executor.DefaultSupervisorConfig(),
		executor.WithHealthStore(sched),
		executor.WithSessionStore(sched),
		executor.WithEventSink(sched),
		executor.WithFailoverHandler(failoverHandler(dir)),
		// The cap is read from the hub's configuration at each claim (Task
		// 20391): hub-scope, so a per-instance overlay applies.
		executor.WithFailoverLimit(failoverLimit),
		// One process speaks for each executor (Task 20354). Nil — probe
		// everything — for a standalone hub.
		executor.WithProbeFilter(clusterProbeFilter(currentCluster())),
		// A run is never moved onto an executor restricted to an access list
		// (Task 20396): nobody who could be checked against it is there.
		executor.WithCandidateFilter(failoverPlaceable),
	)
	stop := sv.Start(context.Background())

	// Fleet auto-update shares the supervisor's lifetime and its database
	// handle (Task 20331). It re-reads the policy on every tick rather than at
	// start, so turning it on from the dashboard takes effect without a hub
	// restart — and a hub that never turns it on pays one query per interval
	// rather than holding machinery it will not use.
	autoCtx, stopAuto := context.WithCancel(context.Background())
	go newAutoUpdater(db, sv).run(autoCtx)

	fleetSupervisor = sv
	fleetStopFn = func() {
		stopAuto()
		stop()
		_ = db.Close()
	}
}

// stopExecutorSupervisor halts supervision and releases the database handle.
// Called from the server's graceful shutdown path so a restarting process does
// not leave a probe goroutine writing to a closing database.
func stopExecutorSupervisor() {
	supervisorMu.Lock()
	stop := fleetStopFn
	fleetSupervisor = nil
	fleetStopFn = nil
	supervisorMu.Unlock()
	if stop != nil {
		stop()
	}
}

// ------------------------------------------------------------ session records

// openSessionFor records a dispatched workload as in flight and returns its
// session ID, or "" when session tracking is unavailable.
//
// Session tracking is best-effort by design. If the control plane's database
// cannot be written, the correct outcome is a run that starts and cannot be
// failed over — not a run that refuses to start. Losing failover for one
// workload is a worse-but-working system; refusing to dispatch is an outage.
func openSessionFor(dir string, ex executor.Executor, handle executor.Handle, spec executor.Spec) string {
	if dir == "" || ex == nil {
		return ""
	}
	sched, db, err := newScheduler(dir)
	if err != nil {
		return ""
	}
	defer db.Close()

	sessionID, err := executorstore.NewSessionID()
	if err != nil {
		return ""
	}
	token, err := executorstore.NewClaimToken()
	if err != nil {
		return ""
	}
	sess := executor.Session{
		ID:          sessionID,
		ExecutorID:  ex.ID(),
		HandleID:    handle.ID,
		ProjectPath: spec.WorkDir,
		ClaimToken:  token,
		Attempt:     1,
		StartedAt:   handle.StartedAt,
		Spec:        spec,
	}
	if err := sched.OpenSession(sess); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record executor session: %v\n", err)
		return ""
	}
	return sessionID
}

// closeSession marks a session terminal once its workload finishes.
func closeSession(dir, sessionID, state string) {
	if dir == "" || sessionID == "" {
		return
	}
	sched, db, err := newScheduler(dir)
	if err != nil {
		return
	}
	defer db.Close()

	// A session already claimed by a failover is gone from `running`, and
	// closing it again would be a no-op at best. ErrExecutorSessionNotFound
	// is therefore expected here and not worth reporting.
	if err := sched.CloseSession(sessionID, state, time.Now().UTC()); err != nil &&
		!errors.Is(err, statedb.ErrExecutorSessionNotFound) {
		fmt.Fprintf(os.Stderr, "ui: close executor session %s: %v\n", sessionID, err)
	}
}

// runProgressMinWrite is the least time between two writes of one session's
// running-task record, in nanoseconds. Atomic so a test can lower it while
// other tests' watchers read it.
var runProgressMinWrite atomic.Int64

func init() { runProgressMinWrite.Store(int64(time.Second)) }

// recordRunningTasks stores the tasks a session's run last announced, for the
// failover that needs them if the node is lost. Best-effort: a write that
// fails costs the attribution of one failover, never the run.
func recordRunningTasks(dir, sessionID string, tasks []int) {
	sched, db, err := newScheduler(dir)
	if err != nil {
		return
	}
	defer db.Close()
	if _, err := sched.SetRunningTasks(sessionID, tasks); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record running tasks of session %s: %v\n", sessionID, err)
	}
}

// recordedRunningTasks reads the tasks a session last recorded as running.
func recordedRunningTasks(dir, sessionID string) []int {
	sched, db, err := newScheduler(dir)
	if err != nil {
		return nil
	}
	defer db.Close()
	tasks, err := sched.RunningTasksOf(sessionID)
	if err != nil {
		return nil
	}
	return tasks
}

// watchSessionExit closes a session when its workload reaches a terminal state.
//
// It mirrors wipeLeaseOnExit's strategy — subscribe to the stream, because the
// driver closing the channel is exactly the moment the workload is done — and
// falls back to polling for drivers that cannot stream. Both paths are bounded
// so a lost workload cannot leave a session "running" forever, which would make
// the node look permanently busy and stop it draining.
func watchSessionExit(dir string, ex executor.Executor, handleID, sessionID string) {
	defer recoverGoroutine("executor session watch: " + sessionID)
	if sessionID == "" {
		return
	}

	const maxWatch = 24 * time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), maxWatch)
	defer cancel()

	terminal := statedb.ExecutorSessionFinished
	if lines, err := ex.Stream(ctx, handleID); err == nil {
		// Another subscriber owns the content. This one reads it for the
		// close, and for which tasks the run says it is working on, which a
		// failover needs if this node is lost (Task 20391). It starts from
		// what the session already recorded, so a run this process adopted
		// after a restart keeps its attribution until it announces more.
		progress := runProgress{running: recordedRunningTasks(dir, sessionID)}
		// A change is written at once when the last write is old enough, and
		// otherwise by the next tick: a workload printing task headers as
		// fast as it can must not turn each one into a database write.
		var (
			lastWrite time.Time
			dirty     bool
		)
		flush := func() {
			recordRunningTasks(dir, sessionID, progress.tasks())
			lastWrite, dirty = time.Now(), false
		}
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
	stream:
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					if dirty {
						flush()
					}
					break stream
				}
				if progress.observe(line.Text) {
					dirty = true
					if time.Since(lastWrite) >= time.Duration(runProgressMinWrite.Load()) {
						flush()
					}
				}
			case <-tick.C:
				if dirty {
					flush()
				}
			}
		}
	} else {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
	poll:
		for {
			select {
			case <-ctx.Done():
				break poll
			case <-ticker.C:
				st, err := ex.Status(ctx, handleID)
				if err != nil {
					terminal = statedb.ExecutorSessionFailed
					break poll
				}
				if st.State.Terminal() {
					if st.State != executor.StateExited {
						terminal = statedb.ExecutorSessionFailed
					}
					break poll
				}
			}
		}
	}

	// Read the final status so a crashed workload is recorded as failed
	// rather than finished. A status we cannot read is reported as failed:
	// "we do not know how it ended" is much closer to failed than to clean.
	statusCtx, statusCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer statusCancel()
	if st, err := ex.Status(statusCtx, handleID); err == nil {
		if st.State == executor.StateExited && st.ExitCode == 0 {
			terminal = statedb.ExecutorSessionFinished
		} else {
			terminal = statedb.ExecutorSessionFailed
		}
	}
	closeSession(dir, sessionID, terminal)
}

// ----------------------------------------------------------------- failover

// failoverHandler builds the callback the supervisor invokes for each session
// stranded on a node that went unreachable.
//
// By the time this runs the claim has already been won, so it is guaranteed to
// execute at most once per session per failure. That is what makes it safe to
// do something as consequential as starting a second agent run.
//
// It runs for every claimed session (Task 20391): one with a replacement, one
// with nowhere to go, and one the claim found exhausted. All three have tasks
// to settle — see settleFailover. A placed one is started again as the
// project's run (failover_runs.go, Task 20396); every other one — and one
// whose replacement could not start — ends with its executor, and the project
// is settled paused with an executor_lost reason rather than left "running".
func failoverHandler(dir string) executor.FailoverHandler {
	return func(ctx context.Context, ev executor.FailoverEvent) error {
		// Before settling, which may hand the project to nobody: the server
		// following the stranded run is found by that run.
		s := failoverServer(dir, ev.From, ev.Session.HandleID, executorstore.FailoverProjectPath(ev.Session))
		// Settle first, dispatch second. If the re-dispatch fails, the tasks
		// are still visibly pending and a human can press Run; if the order
		// were reversed and settling failed, a run would be in flight against
		// tasks the UI still shows as in progress on a dead node.
		out := settleFailover(dir, ev)
		cause := failoverStopCause(ev, out)
		if cause == nil {
			if cause = redispatchSession(ctx, dir, ev, s); cause == nil {
				return nil
			}
		}
		settleLostRun(s, dir, ev, out, cause)
		if ev.Err != nil {
			return ev.Err
		}
		return cause
	}
}

// failoverLimit reads executors.failover.max_attempts from the hub's own
// configuration, overlay included, at each claim — so an operator who lowers
// it is obeyed by the next failover without a restart. A configuration that
// cannot be read yields the default, never "no cap".
func failoverLimit() int {
	cfg, err := controlPlaneConfig()
	if err != nil || cfg == nil {
		return config.FailoverMaxAttemptsDefault
	}
	return cfg.Executors.Failover.MaxRedispatches()
}

// requireRequeued refuses a re-dispatch of a session the store does not hold
// as requeued, or one a failover has already replaced.
func requireRequeued(dir, sessionID string) error {
	sched, db, err := newScheduler(dir)
	if err != nil {
		return fmt.Errorf("failover: cannot confirm session %s may be re-dispatched: %w", sessionID, err)
	}
	defer db.Close()
	st, replaced, err := sched.SessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failover: cannot confirm session %s may be re-dispatched: %w", sessionID, err)
	}
	switch {
	case st != statedb.ExecutorSessionRequeued:
		return fmt.Errorf("failover: session %s is %s, not requeued; nothing re-dispatches it", sessionID, st)
	case replaced:
		return fmt.Errorf("failover: session %s has already been re-dispatched", sessionID)
	}
	return nil
}

// redispatchSession starts the stranded workload's run again on the
// replacement node, as the project's run, on the hub member able to start it:
// this one, or — for an edge agent connected to another member — that one
// (Task 20354). s is this process's hub; the run is followed there.
func redispatchSession(ctx context.Context, dir string, ev executor.FailoverEvent, s *Server) error {
	if ev.To == "" {
		return fmt.Errorf("failover: no replacement executor for session %s", ev.Session.ID)
	}
	if ev.Exhausted {
		return fmt.Errorf("failover: session %s is exhausted; nothing re-dispatches it", ev.Session.ID)
	}
	// The claim's record, not the event, decides (Task 20391). The event can
	// arrive from another hub member (agentOpRedispatch), and whatever it
	// says, a session the claim closed as failover_exhausted — or one already
	// replaced — is never started again here.
	if err := requireRequeued(dir, ev.Session.ID); err != nil {
		return err
	}
	// A replacement that is an edge agent connected to another hub member
	// can only be started there (Task 20354), and is followed there.
	if routed, err := redispatchOnAgentOwner(ctx, ev); routed {
		return err
	}
	// Everything a run started by a person passes — the harness credential,
	// a fresh lease, the sandbox, the firewall levels composed for the
	// replacement, the resource ceilings as they stand now, the revocation
	// guarantee — through the one dispatch path, pinned to the executor the
	// failover placed it on. Before Task 20396 this replayed the stored spec,
	// which lacks the leased credentials and the project seed by design, so
	// a replacement on an isolating executor started without either.
	return s.startReplacement(ctx, dir, ev)
}
