package ui

// dispatch_intent.go: no run goes unsupervised (Task 20419).
//
// A dispatch used to become supervised in steps that could each fail or be
// cut short, and two of the gaps left a workload nobody would ever stop:
//
//   - The executor session — what failover finds a lost node's work by — was
//     recorded best-effort: a dispatch whose session could not be written ran
//     untracked, and was never failed over or adopted.
//   - A member that died between creating the workload and recording the run
//     left a claim marked "dispatching", which the leader cleared as one with
//     nothing behind it. The project could be started again beside a workload
//     whose lease nobody kept or revoked.
//
// So a dispatch is on record before its workload exists. startWorkloadAs
// writes an intent — the run id, the executor, the member, the leases — before
// it asks the executor for anything, and refuses the dispatch when that write
// fails; it completes the intent with the handle, and refuses — stopping the
// workload it just started, releasing its lease — when that, the session or
// the run's own record cannot be written. The intent is retired once the run
// is on record, or when the workload ends. An intent whose member is gone
// names a workload no member supervises, and the member that would have
// adopted it stops it instead and takes its credentials back (reapOrphanedDispatches).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// errDispatchUnrecorded is the refusal of a dispatch whose record could not be
// written: nothing would supervise its workload, so it is not run.
var errDispatchUnrecorded = errors.New("the run was refused: its dispatch could not be recorded, so nothing " +
	"would supervise its workload")

// testDispatchRecordHook, when set, is handed every control-plane handle a
// dispatch writes its records through — its intent, its session — before the
// write: where a test makes those writes fail (SetQueryOnly). Nil in
// production.
var testDispatchRecordHook func(db *statedb.DB)

// openDispatchRecordDB opens the control plane's database for a dispatch's
// record.
func openDispatchRecordDB(dir string) (*statedb.DB, error) {
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil, err
	}
	db.AsControlPlane()
	if testDispatchRecordHook != nil {
		testDispatchRecordHook(db)
	}
	return db, nil
}

// dispatchIntent is one dispatch's intent, nil-safe: a dispatch made where no
// membership judges dead dispatchers — a standalone hub, a test — writes none.
type dispatchIntent struct {
	dir        string
	runID      string
	executorID string
}

// recordDispatchIntent writes the intent of dispatching runID to ex, before
// the workload exists. Nil without an error when there is nobody to reap for:
// no control plane, or no cluster membership.
func recordDispatchIntent(runID string, ex executor.Executor, workDir string, leaseIDs []string) (*dispatchIntent, error) {
	dir := controlPlaneDir()
	n := currentCluster()
	if dir == "" || n == nil || ex == nil || runID == "" {
		return nil, nil
	}
	db, err := openDispatchRecordDB(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: open the control plane: %w", errDispatchUnrecorded, err)
	}
	defer db.Close()
	if err := db.PutDispatchIntent(statedb.DispatchIntentRow{
		RunID: runID, InstanceID: n.ID(), ExecutorID: ex.ID(), Driver: ex.Kind(),
		ProjectPath: workDir, LeaseIDs: leaseIDs, State: statedb.DispatchIntentDispatching,
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", errDispatchUnrecorded, err)
	}
	// The project's run claim says how far the dispatch got, so a claim this
	// member leaves by dying now holds its project while the leader stops what
	// the dispatch started (hubcluster.RunClaimMeta.MayHaveWorkload).
	if o, found, err := n.Lookup(ownerRun, workDir); err == nil && found && o.Self {
		var meta runOwnerMeta
		if o.Meta(&meta) == nil && meta.Dispatching {
			meta.Executor, meta.RunID = ex.ID(), runID
			if _, err := n.UpdateMeta(ownerRun, workDir, meta); err != nil {
				return nil, fmt.Errorf("%w: mark the run's claim: %w", errDispatchUnrecorded, err)
			}
		}
	}
	return &dispatchIntent{dir: dir, runID: runID, executorID: ex.ID()}, nil
}

// started completes the intent with the workload's handle and the egress
// sessions bound to it.
func (in *dispatchIntent) started(handleID string, egressIDs []string) error {
	if in == nil {
		return nil
	}
	db, err := openDispatchRecordDB(in.dir)
	if err != nil {
		return fmt.Errorf("%w: open the control plane: %w", errDispatchUnrecorded, err)
	}
	defer db.Close()
	ok, err := db.MarkDispatchStarted(in.runID, handleID, egressIDs)
	if err != nil {
		return fmt.Errorf("%w: %w", errDispatchUnrecorded, err)
	}
	if !ok {
		return fmt.Errorf("%w: its intent vanished while the workload was being started", errDispatchUnrecorded)
	}
	return nil
}

// forget retires the intent: the run is on record, or its workload is over.
func (in *dispatchIntent) forget() {
	if in == nil {
		return
	}
	forgetDispatchIntent(in.dir, in.runID)
}

// forgetDispatchIntent retires runID's intent.
func forgetDispatchIntent(dir, runID string) {
	if dir == "" || runID == "" {
		return
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return
	}
	defer db.Close()
	if err := db.DeleteDispatchIntent(runID); err != nil {
		fmt.Fprintf(os.Stderr, "ui: retire the dispatch intent of run %s: %v\n", runID, err)
	}
}

// forgetDispatchIntentForHandle retires the intent naming handleID on
// executorID: the run's record names the workload now.
func forgetDispatchIntentForHandle(executorID, handleID string) error {
	dir := controlPlaneDir()
	if dir == "" || executorID == "" || handleID == "" {
		return nil
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.DeleteDispatchIntentForHandle(executorID, handleID)
	return err
}

// refuseUnrecordedDispatch stops a workload whose dispatch could not be
// recorded and takes back what it was given (Task 20419): nothing would
// supervise it — fail it over, adopt it, or revoke its credentials after its
// member died — so it is not left running. The lease and the egress session
// close here, and again, idempotently, when the workload's watcher sees it
// end. The intent stays until then, so a member that dies before the workload
// has stopped leaves it findable.
func refuseUnrecordedDispatch(ex executor.Executor, handleID string, lease *secretLease, egress *runEgress,
	sessionID string, cause error) error {
	if !errors.Is(cause, errDispatchUnrecorded) {
		cause = fmt.Errorf("%w: %w", errDispatchUnrecorded, cause)
	}
	abandonWorkload(ex, handleID, "stopped: "+cause.Error())
	if sessionID != "" {
		closeSession(controlPlaneDir(), sessionID, statedb.ExecutorSessionFailed)
	}
	egress.close("the dispatch could not be recorded")
	lease.Close()
	fmt.Fprintf(os.Stderr, "ui: %v — workload %s on %s was stopped and its credentials taken back\n",
		cause, handleID, ex.ID())
	return cause
}

// ── the reaper ───────────────────────────────────────────────────────────────

// reapsFor reports whether this member stops what a stopped member's dispatch
// to executorID left behind: the member holding the agent's socket for an
// edge agent, the leader for any other — the members that would have adopted
// the run had it been recorded.
func (s *Server) reapsFor(executorID string) bool {
	n := s.clusterNode()
	if n == nil {
		return false
	}
	if agent := s.agentForExecutorID(executorID); agent != "" {
		return n.Owns(ownerAgent, agent)
	}
	return n.LeadsAdoption()
}

// reapOrphanedDispatches stops the workloads of dispatches whose member died
// before recording their run, and takes their credentials back. An intent
// whose run is on record after all — the member died between recording it and
// retiring the intent — is retired instead: that run is adoption's.
func (s *Server) reapOrphanedDispatches() {
	n := s.clusterNode()
	dir := controlPlaneDir()
	if n == nil || dir == "" {
		return
	}
	defer recoverGoroutine("reap orphaned dispatches")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return
	}
	intents, err := db.ListDispatchIntents()
	_ = db.Close()
	if err != nil || len(intents) == 0 {
		return
	}
	for _, in := range intents {
		if in.InstanceID == "" || in.InstanceID == n.ID() || n.Serving(in.InstanceID) {
			continue
		}
		if s.dispatchRecorded(in) {
			forgetDispatchIntent(dir, in.RunID)
			continue
		}
		if !s.reapsFor(in.ExecutorID) {
			continue
		}
		s.reapDispatch(dir, in)
	}
}

// dispatchRecorded reports whether in's workload is a recorded run's: some
// member's run claim names its handle.
func (s *Server) dispatchRecorded(in statedb.DispatchIntentRow) bool {
	if in.HandleID == "" {
		return false
	}
	_, meta, found := s.clusterRunOwner(in.ProjectPath)
	return found && meta.Handle == in.HandleID && meta.Executor == in.ExecutorID
}

// reapDispatch stops one orphaned dispatch's workload and retires what it held.
func (s *Server) reapDispatch(dir string, in statedb.DispatchIntentRow) {
	reason := fmt.Sprintf("hub member %s started this workload (run %s) and stopped before recording it, so "+
		"nothing supervised it", in.InstanceID, in.RunID)
	ex, err := executor.Get(in.ExecutorID)
	if err != nil {
		noteDispatch(dir, in.RunID, fmt.Sprintf("executor %s is not registered on hub member %s, which cannot "+
			"stop the workload", in.ExecutorID, s.hubInstanceID()))
		return
	}
	handleID := in.HandleID
	if ex.Kind() != executor.KindRemoteAgent {
		// The workload's row, if its driver wrote one, is a dead member's:
		// rehydrated here so the driver can stop it.
		if att, ok := ex.(interface{ AttachHandleStore(executor.HandleStore) }); ok {
			if store := s.clusterHandleStoreFor(); store != nil {
				att.AttachHandleStore(store)
			}
		}
		if handleID == "" {
			handleID = handleForRun(ex.ID(), in.RunID)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
	defer cancel()

	stopped, detail := false, ""
	if handleID != "" {
		if _, err := ex.Status(ctx, handleID); err == nil {
			abandonWorkload(ex, handleID, reason)
			stopped = true
		} else if errors.Is(err, executor.ErrHandleNotFound) && ex.Kind() == executor.KindRemoteAgent {
			// The agent offers the workload when it reconnects, and a hub that
			// has no record of it refuses the offer and stops it.
			detail = "its agent is not connected here; it stops the workload when it reconnects and no hub claims it"
		}
	}
	if !stopped && detail == "" {
		if rr, ok := ex.(executor.RunReaper); ok {
			if reaped, err := rr.ReapRun(ctx, in.RunID); err != nil {
				detail = "the workload could not be stopped: " + err.Error()
			} else {
				stopped = true
				if len(reaped) > 0 {
					fmt.Fprintf(os.Stderr, "ui: stopped %s, the workload of run %s that stopped hub member %s left "+
						"unrecorded\n", strings.Join(reaped, ", "), in.RunID, in.InstanceID)
				}
			}
		} else if handleID == "" {
			// Nothing names a workload and nothing can find one: the dispatch
			// never got as far as starting it.
			stopped = true
		}
	}

	// Its credentials go whether or not the workload could be found: no hub
	// process keeps them, and none will.
	for _, leaseID := range in.LeaseIDs {
		out := s.revokeLeaseEverywhere(ctx, leaseID, "", reason, remote.RevokeScrub, "janitor")
		retireLeaseRecord(leaseID, reason)
		if out.State == remote.RevokeStateRevoked {
			settleRevocationsOfLease(leaseID, "taken back with a workload nothing supervised")
		}
	}
	retireRunEgressRecords(in.EgressIDs, reason)
	if handleID != "" {
		for _, id := range runningSessionsFor(ex, handleID) {
			closeSession(dir, id, statedb.ExecutorSessionFailed)
		}
	}
	if !stopped {
		noteDispatch(dir, in.RunID, detail)
		return
	}
	forgetDispatchIntent(dir, in.RunID)
	s.log().Warn("cluster", 0, "stopped a workload whose hub member died before recording its run",
		map[string]interface{}{"project": in.ProjectPath, "run": in.RunID, "executor": in.ExecutorID,
			"handle": handleID, "member": in.InstanceID})
}

// handleForRun finds the handle of runID's workload among executorID's rows.
func handleForRun(executorID, runID string) string {
	dir := controlPlaneDir()
	if dir == "" || runID == "" {
		return ""
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return ""
	}
	defer db.Close()
	rows, err := db.ListExecutorHandles(executorID)
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if statedb.UnmarshalHandleMeta(r.MetaJSON)[executor.MetaRunID] == runID {
			return r.HandleID
		}
	}
	return ""
}

// noteDispatch records why an intent is still outstanding.
func noteDispatch(dir, runID, detail string) {
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return
	}
	defer db.Close()
	_ = db.NoteDispatchIntent(runID, detail)
}

// reapDispatchingClaim deals with a dispatching claim a dead member left: what
// its dispatch started is stopped first, and only then is the claim cleared —
// so the project cannot be started again beside a workload nobody supervises.
// It reports whether the claim may go.
func (s *Server) reapDispatchingClaim(o hubcluster.Owner, meta runOwnerMeta) bool {
	if meta.RunID == "" {
		return true // the dispatch never reached an executor
	}
	dir := controlPlaneDir()
	if dir == "" {
		return true
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return false
	}
	in, err := db.GetDispatchIntent(meta.RunID)
	_ = db.Close()
	if errors.Is(err, statedb.ErrDispatchIntentNotFound) {
		return true // reaped, or retired with its workload
	}
	if err != nil || !s.reapsFor(in.ExecutorID) {
		return false
	}
	s.reapDispatch(dir, in)
	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		return false
	}
	defer db.Close()
	_, err = db.GetDispatchIntent(meta.RunID)
	return errors.Is(err, statedb.ErrDispatchIntentNotFound)
}
