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
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pm"
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
	)
	stop := sv.Start(context.Background())

	fleetSupervisor = sv
	fleetStopFn = func() {
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
		for range lines {
			// Another subscriber owns the content; we only need the close.
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
func failoverHandler(dir string) executor.FailoverHandler {
	return func(ctx context.Context, ev executor.FailoverEvent) error {
		// Mark first, dispatch second. If the re-dispatch fails, the task is
		// still visibly pending and a human can press Run; if the order were
		// reversed and marking failed, a run would be in flight against a
		// task the UI still shows as in-progress on a dead node.
		if err := requeueTasksForFailover(ev); err != nil {
			fmt.Fprintf(os.Stderr, "ui: failover mark tasks for %s: %v\n", ev.Session.ProjectPath, err)
		}
		return redispatchSession(ctx, dir, ev)
	}
}

// requeueTasksForFailover returns the project's in-flight tasks to pending so
// the replacement run picks them up.
//
// "Failed-with-retry" is what this means operationally: the attempt on the dead
// node did fail, and the task is going to be retried. It is recorded as a
// FailCount bump plus a return to pending rather than as TaskFailed, because
// TaskFailed is a terminal state that the orchestrator will not re-run without
// --retry-failed — and a task whose executor died deserves an automatic retry,
// not a manual one.
func requeueTasksForFailover(ev executor.FailoverEvent) error {
	projectPath := ev.Session.ProjectPath
	if projectPath == "" {
		return nil
	}
	st, err := state.Load(projectPath)
	if err != nil {
		return fmt.Errorf("load project state: %w", err)
	}
	if st == nil || st.Plan == nil {
		return nil
	}

	var requeued []int
	for _, task := range st.Plan.Tasks {
		if task.Status != pm.TaskInProgress {
			continue
		}
		task.Status = pm.TaskPending
		task.FailCount++
		requeued = append(requeued, task.ID)
	}
	if len(requeued) == 0 {
		return nil
	}
	if err := st.SaveDirect(); err != nil {
		return fmt.Errorf("persist requeued tasks: %w", err)
	}

	for _, id := range requeued {
		state.LogEventDetails(projectPath, state.EventRow{
			Type:    statedb.EventTaskStatusChange,
			TaskID:  id,
			Message: fmt.Sprintf("executor %s became unreachable; task requeued for retry", ev.From),
		}, map[string]any{
			"executor":   ev.From,
			"session_id": ev.Session.ID,
			"failover":   true,
		})
	}
	return nil
}

// redispatchSession starts the stranded workload on the replacement node and
// records the new session, linked to the one it replaces.
func redispatchSession(ctx context.Context, dir string, ev executor.FailoverEvent) error {
	if ev.To == "" {
		return fmt.Errorf("failover: no replacement executor for session %s", ev.Session.ID)
	}
	spec := ev.Session.Spec
	if err := spec.Validate(); err != nil {
		// A session with no recorded spec cannot be re-dispatched. Say so
		// plainly: the tasks are already back to pending, so the run is
		// recoverable by hand, and pretending otherwise would hide it.
		return fmt.Errorf("failover: session %s has no re-dispatchable spec: %w", ev.Session.ID, err)
	}
	target, err := executor.Get(ev.To)
	if err != nil {
		return fmt.Errorf("failover: replacement executor %s: %w", ev.To, err)
	}

	// Detached from ctx: ctx belongs to the probe round that noticed the
	// failure, and the replacement run must outlive it exactly as the
	// original outlived the HTTP request that started it.
	handle, err := target.Start(context.WithoutCancel(ctx), spec)
	if err != nil {
		return fmt.Errorf("failover: start on %s: %w", ev.To, err)
	}

	sched, db, err := newScheduler(dir)
	if err != nil {
		// The workload is running; we just cannot track it. Report rather
		// than kill it — the user's task is making progress either way.
		return fmt.Errorf("failover: started on %s but could not record session: %w", ev.To, err)
	}
	defer db.Close()

	sessionID, err := executorstore.NewSessionID()
	if err != nil {
		return fmt.Errorf("failover: mint session ID: %w", err)
	}
	token, err := executorstore.NewClaimToken()
	if err != nil {
		return fmt.Errorf("failover: mint claim token: %w", err)
	}
	next := executor.Session{
		ID:          sessionID,
		ExecutorID:  target.ID(),
		HandleID:    handle.ID,
		ProjectPath: spec.WorkDir,
		TaskID:      ev.Session.TaskID,
		ClaimToken:  token,
		Attempt:     ev.Session.Attempt + 1,
		StartedAt:   handle.StartedAt,
		Spec:        spec,
	}
	if err := sched.OpenRequeuedSession(next, ev.Session.ID); err != nil {
		return fmt.Errorf("failover: record replacement session: %w", err)
	}
	go watchSessionExit(dir, target, handle.ID, sessionID)
	return nil
}
