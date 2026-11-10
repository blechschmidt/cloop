package ui

// executor_pool_queue.go: runs waiting for an executor pool's runner (Task
// 20482).
//
// A project bound to a pool has no executor until its run is handed a runner,
// so starting it does not dispatch anything: the run is admitted as any run is
// — the person may start it, may use the pool, has a concurrency slot — and
// then queued. It waits, paused with the reason pool_capacity, which says
// whether a runner is coming; the pool's controller learns of it from its
// feed and starts one. The hub member that runner connects to hands it the
// run (executor_pools.go, dispatchPool), and the run starts there the way an
// automatic resume does: acting for the person who started it, on their
// grants, holding their concurrency slot, with nobody's request in hand.
//
// What is decided when, and why:
//
//   - The pool's access list and its owner's access to the project are
//     checked when the run is queued, against the person's own sign-in — the
//     only time their claims are in hand — and the queue row remembers the
//     list's fingerprint. A list changed since takes the run out of the queue
//     rather than re-judging it on claims nobody holds (demand.go).
//   - What the run needs of an executor is judged against the pool's
//     declared runners when it is queued, so a run no runner of the pool could
//     take is refused at once instead of waiting forever, and against the real
//     runner when it is handed one.
//   - The concurrency slot the run was admitted with is held by the queue row
//     while it waits, handed to the run when it starts, and given back exactly
//     once otherwise — by whichever member wins the row's move out of the
//     queue (statedb.MovePoolQueueEntry).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// queuePoolRun queues workDir's run for poolID, writing the response. slot is
// the concurrency slot the request was admitted with; it goes to the queue
// row, or back to the tenant if the run is refused.
func (s *Server) queuePoolRun(w http.ResponseWriter, r *http.Request, workDir, poolID, handler string, slot *heldSlot) {
	refuse := func(status int, body map[string]any) {
		slot.giveBack()
		writeJSONStatus(w, status, body)
	}
	store, err := s.poolStore()
	if err != nil {
		refuse(http.StatusServiceUnavailable, map[string]any{"error": "executor pools are unavailable: " + err.Error(),
			"code": "executor_pool_unavailable"})
		return
	}
	pool, err := store.Get(poolID)
	if errors.Is(err, executorpool.ErrNotFound) {
		refuse(http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("this project is bound to executor pool %q, which does not exist; bind it to "+
				"another executor or pool", poolID),
			"code": "executor_pool_missing", "pool_id": poolID})
		return
	}
	if err != nil {
		refuse(http.StatusServiceUnavailable, map[string]any{"error": "read executor pool: " + err.Error(),
			"code": "executor_pool_unavailable"})
		return
	}
	if pool.Revoked() {
		refuse(http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("this project is bound to executor pool %s, which was revoked; bind it to "+
				"another executor or pool", pool.Name),
			"code": "executor_pool_revoked", "pool_id": pool.ID})
		return
	}

	// Who may use the pool: its access list, against this person's sign-in.
	entries, err := store.Audience(pool.ID)
	if err != nil {
		refuse(http.StatusServiceUnavailable, map[string]any{
			"error": fmt.Sprintf("cannot determine who may use executor pool %s right now", pool.Name),
			"code":  "executor_pool_audience_unavailable", "remediation": err.Error(), "pool_id": pool.ID})
		return
	}
	if members := audienceMembers(entries); len(members) > 0 && !authz.Admits(members, s.callerSubject(r)) {
		refuse(http.StatusForbidden, map[string]any{
			"error": fmt.Sprintf("executor pool %s is restricted and your account is not on its access list — "+
				"ask an administrator to admit you, or bind this project to another executor", pool.Name),
			"code": "executor_pool_audience_denied", "pool_id": pool.ID})
		return
	}
	// Whose machines the runners are: an owned pool runs only what its owner
	// may read.
	if pool.Owner != "" {
		ok, err := s.identityMayReadProject(pool.Owner, workDir)
		if err != nil || !ok {
			refuse(http.StatusConflict, map[string]any{
				"error": fmt.Sprintf("executor pool %s belongs to someone who may not read this project, so its "+
					"runners may not run it; bind the project to another pool", pool.Name),
				"code": "executor_pool_owner_denied", "pool_id": pool.ID})
			return
		}
	}
	// What the run needs, against what the pool's runners will be.
	req, err := poolRunRequirements(workDir)
	if err != nil {
		slot.giveBack()
		jsonWorkloadErr(w, err)
		return
	}
	if rej, rejected := pool.Admits(req); rejected {
		slot.giveBack()
		jsonWorkloadErr(w, &executor.PlacementError{Constraint: rej.Constraint,
			Rejections: []executor.Rejection{rej}, Considered: 1})
		return
	}
	encoded, err := executorpool.EncodeRequirements(req)
	if err != nil {
		refuse(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	snap, _, _ := store.Snapshot(pool, s.poolAccessFor(store))
	reason := s.queuedReasonFor(store, pool, snap)
	row := statedb.PoolQueueRow{
		ID:           "q-" + artifact.NewRunID(),
		PoolID:       pool.ID,
		ProjectPath:  workDir,
		Handler:      handler,
		Starter:      s.harnessWhoFor(r).identity,
		Payer:        s.runIdentity(r, workDir),
		AudienceFP:   executorpool.AudienceFingerprint(entries),
		Requirements: encoded,
		Slot:         marshalSlot(slot),
		Reason:       reason,
		Member:       s.hubInstanceID(),
	}
	if err := store.DB().EnqueuePoolRun(row); err != nil {
		switch {
		case errors.Is(err, statedb.ErrPoolRunAlreadyQueued):
			refuse(http.StatusConflict, map[string]any{
				"error": "a run of this project is already waiting for a runner — stop it before starting another",
				"code":  "executor_pool_run_queued", "running": true})
		case errors.Is(err, statedb.ErrExecutorPoolRevoked):
			refuse(http.StatusConflict, map[string]any{"error": "executor pool " + pool.Name + " was revoked",
				"code": "executor_pool_revoked", "pool_id": pool.ID})
		default:
			refuse(http.StatusInternalServerError, map[string]any{"error": "queue the run: " + err.Error()})
		}
		return
	}
	// The slot belongs to the queue row now: given back or handed on from
	// there, exactly once.
	store.AuditQueue(row, "queued", s.auditActor(r), reason)
	s.setPoolCapacityPause(workDir, reason)
	s.poolChanged(pool.ID)
	writeJSONStatus(w, http.StatusAccepted, map[string]any{
		"ok": true, "queued": true, "queue_id": row.ID, "pool_id": pool.ID, "pool": pool.Name,
		"reason": reason, "command": "cloop run",
	})
}

// poolRunRequirements is what a run of workDir needs of an executor, as a
// pool's runner is judged: what its sandbox spec asks for, and isolation from
// the hub, which every runner offers.
func poolRunRequirements(workDir string) (executor.Requirements, error) {
	resolved, err := sandbox.Resolve(workDir)
	if err != nil {
		return executor.Requirements{}, err
	}
	req := resolved.Requirements()
	req.RequireIsolation = true
	return req, nil
}

// queuedReason says why a queued run waits, for its project's readers.
func queuedReason(pool executorpool.Pool, snap executorpool.Snapshot) string {
	switch {
	case snap.Idle > 0:
		return fmt.Sprintf("waiting for pool capacity: handing it to an idle runner of executor pool %s", pool.Name)
	case snap.Pending > 0 && snap.Pending >= snap.Demand+1:
		return fmt.Sprintf("waiting for pool capacity: a runner of executor pool %s is starting", pool.Name)
	case snap.Runners >= pool.MaxRunners:
		return fmt.Sprintf("waiting for pool capacity: all %d runners executor pool %s may have are busy",
			pool.MaxRunners, pool.Name)
	}
	return fmt.Sprintf("waiting for pool capacity: executor pool %s has no idle runner, and its controller "+
		"is asked to start one (%d of %d in use)", pool.Name, snap.Runners, pool.MaxRunners)
}

// setPoolCapacityPause records on the project that its run waits in a pool's
// queue, and tells the dashboards.
func (s *Server) setPoolCapacityPause(workDir, reason string) {
	s.setRunStatus(workDir, func(st *state.ProjectState) {
		st.SetPaused(pausereason.New(pausereason.CodePoolCapacity, reason))
	})
}

// setRunStatus rewrites the project's run status alone, and broadcasts it.
func (s *Server) setRunStatus(workDir string, set func(*state.ProjectState)) {
	st, err := state.LoadLite(workDir)
	if err != nil || st == nil {
		return
	}
	set(st)
	if err := st.SaveRunStatus(); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record %s's run status: %v\n", workDir, err)
		return
	}
	s.broadcastStateDiff(workDir, st)
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
}

// startQueuedPoolRun starts the queued run q on the runner ex, which this
// member holds and dispatchPool just assigned it. It follows the run here the
// way handleRun follows one. tenant is the run's project's (Task 20484), ""
// when the hub could not say whose the project is; the start names it, and a
// runner whose volume holds another tenant's data refuses the start.
func (s *Server) startQueuedPoolRun(q statedb.PoolQueueRow, ex executor.Executor, tenant string) {
	defer recoverGoroutine("executor pool run start")
	store, err := s.poolStore()
	if err != nil {
		return
	}
	workDir := q.ProjectPath
	slot := s.slotFromRow(q.Slot)
	attempt := q.Attempts + 1 // AssignPoolQueueEntry counted this one

	// failRun ends the hand-over for a reason that is the run's own — its
	// project, its person, its grants: the run leaves the queue and its
	// project says why, and the runner, handed nothing, waits for the next.
	failRun := func(reason string) {
		if moved, _ := store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
			statedb.PoolQueueFailed, reason, time.Now()); moved {
			s.settleClosedPoolRun(q, "failed", reason, "system")
		}
		if spent, ok := ex.(interface{ Spent() bool }); ok && !spent.Spent() {
			_, _ = store.DB().MovePoolRunnerIdle(ex.ID())
		} else {
			s.retirePoolRunner(ex.ID(), "its run could not be started on it")
		}
		s.poolChanged(q.PoolID)
	}
	// failRunner ends it for a reason that may be the runner's — anything a
	// misconfigured image or a lost link produces. The runner is retired,
	// never handed another run, and the run goes back to the queue for a fresh
	// one, up to MaxRunAttempts runners; after that it fails with the reason.
	failRunner := func(reason string) {
		s.retirePoolRunner(ex.ID(), "its run could not be started on it")
		if attempt >= executorpool.MaxRunAttempts {
			final := fmt.Sprintf("%s (on %d runners in turn)", reason, attempt)
			if moved, _ := store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
				statedb.PoolQueueFailed, final, time.Now()); moved {
				s.settleClosedPoolRun(q, "failed", final, "system")
			}
		} else if moved, _ := store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
			statedb.PoolQueueWaiting, reason, time.Now()); moved {
			store.AuditQueue(q, "requeued", "system", reason)
		}
		s.poolChanged(q.PoolID)
	}

	if !hasProjectDB(workDir) {
		failRun("the project no longer exists")
		return
	}
	if !s.isRegisteredProject(workDir) {
		// This member does not serve it — its registry may lag another's.
		// The run goes back to the queue, its runner to waiting; MaxRunAttempts
		// bounds how often that can happen.
		reason := "the hub member holding its runner does not serve the project"
		if attempt >= executorpool.MaxRunAttempts {
			failRun(reason)
			return
		}
		if moved, _ := store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
			statedb.PoolQueueWaiting, reason, time.Now()); moved {
			store.AuditQueue(q, "requeued", "system", reason)
		}
		_, _ = store.DB().MovePoolRunnerIdle(ex.ID())
		return
	}
	if s.projectExecuting(workDir) {
		failRun("the project's run was started another way while this one waited")
		return
	}
	if owner, err := s.claimRun(workDir, q.Handler); err != nil {
		failRun(fmt.Sprintf("the project's run is held by hub member %s", owner.InstanceID))
		return
	}

	// Acting for the person who started it, as recorded when it was queued:
	// on their grants, and refused rather than run on anyone else's.
	acct := s.accountForStarter(workDir, q.Starter)
	s.openSpendCursor(workDir, q.Payer)
	labels := map[string]string{"handler": q.Handler, labelExecutorPool: q.PoolID, labelPoolQueueID: q.ID}
	if tenant != "" {
		labels[executor.LabelPoolTenant] = tenant
	}
	started, handle, err := startWorkloadAs(acct.envFor, newResumeClearance(acct), q.Payer, workDir,
		[]string{s.selfExe(), "run"}, labels, onPoolRunner(ex), s.recordingRunHolding(workDir, q.Handler, slot))
	if err != nil {
		s.releaseRunClaim(workDir)
		reason := "the run could not be started on its runner: " + err.Error()
		if poolRunFault(err) {
			failRun(reason)
		} else {
			failRunner(reason)
		}
		return
	}

	// The slot is the run's from here — unless the row left the queue while
	// the run started (the pool was revoked, the run stopped): whoever moved
	// it gave the slot back, and the run is stopped like any run someone asked
	// to stop, without giving it back a second time.
	moved, err := false, error(nil)
	for i := 0; i < 3; i++ {
		if moved, err = store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
			statedb.PoolQueueDispatched, "", time.Now()); err == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	switch {
	case err != nil:
		// The row could not be written; the run is real, and the janitor
		// finds its session and records it dispatched.
		fmt.Fprintf(os.Stderr, "ui: record queued run %s dispatched: %v\n", q.ID, err)
	case !moved:
		fmt.Fprintf(os.Stderr, "ui: queued run %s was taken out of the queue while it started; stopping it\n", q.ID)
		slot.disown()
		slot = nil
		_ = started.Signal(context.Background(), handle.ID, executor.SignalInterrupt)
	}
	q.ExecutorID = started.ID()
	store.AuditQueue(q, "dispatched", "system", "")
	s.setRunStatus(workDir, func(st *state.ProjectState) {
		st.Status, st.PauseReason = "running", nil
	})

	s.liveLogStartRun(workDir)
	streamCtx, cancelStream := context.WithCancel(context.Background())
	s.trackRunWithCancel(workDir, started, handle.ID, cancelStream)
	s.broadcastRunState(workDir, true, true)
	s.publishRunState(workDir, true)
	s.poolChanged(q.PoolID)

	lines, streamErr := started.Stream(streamCtx, handle.ID)
	if streamErr != nil {
		cancelStream()
		s.liveLogSetRunning(workDir, false)
		s.publishRunState(workDir, false)
		s.runEnded(workDir, started, handle.ID)
		slot.giveBack()
		return
	}
	go s.consumeRunOutput(workDir, started, handle.ID, lines, slot.giveBack)
}

// poolRunFault reports whether a queued run's start failed for a reason that
// is the run's own — no grant for the harness, a starter the hub cannot act
// for, a sandbox grant or a directory the hub refuses — which no other runner
// would change. Anything else may be the runner's.
func poolRunFault(err error) bool {
	if _, ok := asHarnessRefusal(err); ok {
		return true
	}
	if _, ok := errStarterUnavailable(err); ok {
		return true
	}
	var grantDenied *sandbox.GrantDeniedError
	return errors.As(err, &grantDenied)
}

// Labels a queued run's workload carries, naming its pool and queue entry.
const (
	labelExecutorPool = "executor_pool"
	labelPoolQueueID  = "pool_queue_id"
)

// onPoolRunner pins a dispatch to ex, the runner a queued run was assigned.
func onPoolRunner(ex executor.Executor) dispatchOption {
	return func(o *dispatchOptions) { o.target, o.poolRun = ex, true }
}

// settleClosedPoolRun finishes a run that left the queue without starting —
// cancelled, failed, or taken out because its pool was revoked: its
// concurrency slot goes back, its project says why, and the trail records it.
// Only the caller that won the row's move calls this, so each happens once.
func (s *Server) settleClosedPoolRun(q statedb.PoolQueueRow, action, reason, actor string) {
	if slot := s.slotFromRow(q.Slot); slot != nil {
		slot.giveBack()
	}
	if store, err := s.poolStore(); err == nil {
		store.AuditQueue(q, action, actor, reason)
	}
	code := pausereason.CodeAbort
	if action == "cancelled" && !strings.Contains(reason, "revoked") {
		code = pausereason.CodeOperator
	}
	s.setRunStatus(q.ProjectPath, func(st *state.ProjectState) {
		// Only a project still saying it waits for the pool: one whose run
		// started another way since has a status of its own.
		if st.PausedFor(pausereason.CodePoolCapacity) {
			st.SetPaused(pausereason.New(code, "the run waiting for its executor pool "+action+": "+reason))
		}
	})
	s.poolChanged(q.PoolID)
}

// cancelQueuedPoolRun takes workDir's waiting run out of its pool's queue, for
// a person who pressed Stop. It reports whether there was one; starting
// reports a run already being handed to a runner, which Stop reaches once it
// runs.
func (s *Server) cancelQueuedPoolRun(r *http.Request, workDir string) (cancelled, starting bool) {
	store, err := s.poolStore()
	if err != nil {
		return false, false
	}
	q, ok, err := store.DB().OpenPoolQueueEntry(workDir)
	if err != nil || !ok {
		return false, false
	}
	from := []string{statedb.PoolQueueWaiting}
	if q.State == statedb.PoolQueueAssigned {
		// Being started by a live member: Stop reaches it once it runs. A
		// hand-over whose member went away, and whose runner never got as far
		// as a session, is the queue's to cancel.
		if s.poolMemberAlive(q.Member) && time.Since(q.UpdatedAt) < poolStartDeadline {
			return false, true
		}
		if sessions, err := store.DB().ListExecutorSessions(q.ExecutorID, false); err != nil || len(sessions) > 0 {
			return false, true
		}
		from = []string{statedb.PoolQueueAssigned}
	}
	moved, err := store.DB().MovePoolQueueEntry(q.ID, from, statedb.PoolQueueCancelled,
		"stopped before a runner took it", time.Now())
	if err != nil || !moved {
		// Taken by a runner in the meantime.
		return false, err == nil
	}
	if q.State == statedb.PoolQueueAssigned && q.ExecutorID != "" {
		s.retirePoolRunnerIf(q.ExecutorID, "its run could not be started on it", statedb.PoolRunnerBusy)
	}
	s.settleClosedPoolRun(q, "cancelled", "stopped before a runner took it", s.auditActor(r))
	return true, false
}

// stopQueuedPoolRun answers Stop for a project whose run waits in a pool's
// queue; handled is false when it has none.
func (s *Server) stopQueuedPoolRun(w http.ResponseWriter, r *http.Request, workDir string, extra map[string]any) (handled bool) {
	cancelled, starting := s.cancelQueuedPoolRun(r, workDir)
	if !cancelled && !starting {
		return false
	}
	body := map[string]any{"ok": cancelled}
	for k, v := range extra {
		body[k] = v
	}
	if cancelled {
		body["message"] = "the run waiting for its executor pool was taken out of the queue"
	} else {
		body["message"] = "the run is being started on a runner; press Stop again in a moment"
	}
	jsonOK(w, body)
	return true
}
