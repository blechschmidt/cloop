package ui

// run_takeover.go: what a hub process adopting a run takes over besides its
// output stream (Task 20382).
//
// Adoption (cluster_runs.go) reattaches to a run another process dispatched —
// a hub restarted in the same directory, or a peer that died or lost the
// agent. The stream, the settle and the merge of a seeded run's result all
// came across with it since Task 20354. Two things the dispatching process
// held did not:
//
//	The run's secret lease. It lived in that process's memory: the keepalive
//	extending it, the janitor watching its TTL, the release ending it with the
//	run. After a restart the device kept the credentials and no hub held
//	them — never extended, never swept, never released, and absent from the
//	Secrets panel. Leases are now recorded durably (secret_leases) and the
//	adopter takes them over: the same lease id, kept alive here and released
//	here when the run ends. One that lapsed, or whose grants were withdrawn,
//	while no hub held it is taken back from the device instead — what the
//	janitor would have done had anything been watching.
//
//	The run's executor session. Its watcher died with the process, and the
//	startup sweep closed the row as failed before the device had reconnected
//	— a run that went on to succeed, recorded as failed, and nothing left for
//	failover to find if the device then died holding it. The sweep now leaves
//	a device's session open (pkg/executor/reconcile), and the adopter watches
//	it to its end, as its dispatcher would have.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// restoreSecretLease takes over leaseID for this process: the broker's record
// moves here, and the returned lease is kept alive from this process until it
// is closed. It carries no material — the workload has it already — so it
// renders nothing; closing it releases the lease at the broker.
func restoreSecretLease(controlPlaneDir, workDir, leaseID string) (*secretLease, error) {
	broker, db, closeDB, err := openUIBrokerDB(controlPlaneDir)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), leaseTimeout)
	defer cancel()
	lease, err := broker.Restore(ctx, leaseID)
	if err != nil {
		closeDB()
		return nil, err
	}
	sl := &secretLease{
		broker: broker, lease: lease, closer: closeDB, expiry: lease.ExpiresAt,
		workDir: workDir, auditDB: db, controlPlane: controlPlaneDir,
	}
	sl.startKeepalive(leaseKeepaliveTick)
	return sl, nil
}

// takeOverRunLeases takes over the leases an adopted run holds, binds them to
// its handle, and closes each when the workload ends.
func (s *Server) takeOverRunLeases(workDir string, ex executor.Executor, handleID string, leaseIDs []string) {
	for _, id := range leaseIDs {
		if liveLeases.held(id) {
			continue // already held here: this process adopted the run before
		}
		if ex.Capabilities().SecretFilesFromHostPath {
			// The material is files in a lease directory on the host of the
			// process that held it — which alone could keep them current or
			// wipe them — read by a run that outlived it: a forked child is
			// reparented, not killed. They are wiped now, before the record
			// goes (Task 20419); the run carries on without them. Death
			// detection wipes them too (onMembershipChange); this is the
			// adopter making sure, since retiring the record says they are
			// gone.
			if _, gone := wipeDeadMembersLeaseDirs(controlPlaneDir(), id); gone {
				const why = "its credential files were wiped when the hub process holding them stopped"
				retireLeaseRecord(id, why)
				settleRevocationsOfLease(id, why)
			} else {
				// A directory not visible from here, or a wipe that failed: the
				// record stays, so the lease lapses on schedule and the sweep
				// takes the files back through the adopted handle's bindings.
				fmt.Fprintf(os.Stderr, "ui: lease %s of the adopted run on %s: not every credential file it "+
					"materialised could be wiped from this host; its record is kept until it lapses\n", id, ex.ID())
			}
			continue
		}
		sl, err := restoreSecretLease(controlPlaneDir(), workDir, id)
		switch {
		case err == nil:
			sl.bindHandle(ex.ID(), handleID)
			// The hub scrubs the run's output with what its lease carries —
			// the live log, and the result it merges into the project. The
			// handle this process rehydrated has no such set; its dispatcher
			// built one from the Spec, which is never persisted.
			if r, ok := ex.(executor.HandleRedactor); ok {
				r.AddHandleRedactions(handleID, sl.broker.RedactionValues(id)...)
			}
			// And the run's pushes are scanned for the same values (Task
			// 20436) — recorded before its sessions are restored below, so
			// no push through one is scanned without them, and forgotten
			// once the run and every session naming it are over.
			adoptRunPushScan(sl.lease.RunID, workDir, id, sl.broker.RedactionCredentials(id))
			go func(runID string) {
				watchWorkloadExit(ex, handleID)
				endRunPushScan(runID)
			}(sl.lease.RunID)
			liveLeases.add(sl)
			go wipeLeaseOnExit(ex, handleID, sl, nil)
			s.log().Info("cluster", 0, "took over the secret lease of an adopted run",
				map[string]interface{}{"project": workDir, "lease": id, "executor": ex.ID(), "handle": handleID,
					"expires_at": sl.ExpiresAt().UTC().Format(time.RFC3339)})
			// A grant revoked while no hub held the lease is taken back from
			// the workload now, before anything is restored on its behalf;
			// the lease keeps the grants nobody revoked (Task 20403).
			s.withdrawOnAdoption(sl)
			// And a label grant its executor's labels stopped matching while
			// no hub held it (Task 20432).
			s.relabelAdoptedLease(sl)
			// And what it feeds: the run's git proxy and Kubernetes monitor
			// sessions, under the ids and tokens its workload holds, and the
			// App tokens behind them (Task 20383).
			restoreLeaseSessions(sl)
		case errors.Is(err, secretbroker.ErrLeaseRevoked):
			// Revoked while no hub process held it (Task 20419): the material
			// is taken back from the workload this process can now reach, and
			// nothing the lease fed is restored.
			s.enforceRevokedTakeover(workDir, ex, handleID, id, err)
		case errors.Is(err, secretbroker.ErrLeaseMoved), errors.Is(err, secretbroker.ErrLeaseNotFound):
			// Held by the process that adopted the run first, or already
			// released: either way not this process's to keep.
		case leaseRefusedForGood(err):
			s.withdrawLapsedLease(id, fmt.Sprintf("the hub process that adopted its run could not take the lease over: %v", err))
		default:
			// Nothing decided — the store could not be read. The record stays,
			// and the janitor sweeps it once it lapses.
			fmt.Fprintf(os.Stderr, "ui: take over lease %s of the run on %s: %v\n", id, ex.ID(), err)
		}
	}
}

// withdrawOnAdoption takes back, from every holder, the grants a lease taken
// over with an adopted run carried that were revoked while no hub held it.
func (s *Server) withdrawOnAdoption(sl *secretLease) {
	if sl == nil || sl.lease == nil || len(sl.lease.Withdrawn) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
	defer cancel()
	for _, w := range sl.lease.Withdrawn {
		reason := w.Reason + " while no hub process held its lease; taken back by the process that adopted the run"
		if testWithdrawGrantFanout != nil {
			err := sl.withdrawGrant(ctx, w.GrantID, reason)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ui: withdraw grant %s from lease %s: %v\n", w.GrantID, sl.lease.ID, err)
			}
			testWithdrawGrantFanout(sl.lease.ID, w.GrantID, reason)
			if err == nil {
				settleRevocation(sl.lease.ID, w.GrantID, "taken back by the hub process that adopted its run")
			}
			continue
		}
		out := s.revokeLeaseEverywhere(ctx, sl.lease.ID, w.GrantID, reason, remote.RevokeScrub, "janitor")
		adoptionEnforcements.record(sl.lease.ID, out)
		// A grant revoked on the lease itself (Task 20419) is settled once
		// it is taken back; for any other withdrawn grant there is no such
		// record, and this changes nothing.
		if out.State == remote.RevokeStateRevoked {
			settleRevocation(sl.lease.ID, w.GrantID, "taken back by the hub process that adopted its run")
		}
	}
	s.broadcastSecretsUpdate("grant_revoked", sl.lease.ID)
}

// testWithdrawGrantFanout, when set, stands in for the fan-out that takes one
// grant of an adopted lease back from its holders, as testRevokeLapsedLease
// does for a whole lease. The hub's own side of the withdrawal still runs. Nil
// in production.
var testWithdrawGrantFanout func(leaseID, grantID, reason string)

// leaseRefusedForGood reports whether a takeover was refused for a reason that
// will not change: the lease lapsed while nobody held it, or a grant it carries
// was revoked, expired, or no longer reaches the requester.
func leaseRefusedForGood(err error) bool {
	for _, final := range []error{
		secretbroker.ErrLeaseExpired,
		secretbroker.ErrGrantRevoked,
		secretbroker.ErrGrantExpired,
		secretbroker.ErrGrantNotFound,
		secretbroker.ErrInvalidGrant,
		secretbroker.ErrSecretNotFound,
	} {
		if errors.Is(err, final) {
			return true
		}
	}
	return false
}

// withdrawLapsedLease takes a lease nobody may hold any more back from every
// executor holding it, and retires its record.
func (s *Server) withdrawLapsedLease(leaseID, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
	defer cancel()
	var out leaseRevocation
	if testRevokeLapsedLease != nil {
		testRevokeLapsedLease(leaseID, reason)
		out.State = remote.RevokeStateRevoked
	} else {
		out = s.revokeLeaseEverywhere(ctx, leaseID, "", reason, remote.RevokeScrub, "janitor")
		adoptionEnforcements.record(leaseID, out)
	}
	retireLeaseRecord(leaseID, reason)
	// Taken back whole: a revocation of it on record is enforced (Task 20419).
	if out.State == remote.RevokeStateRevoked {
		settleRevocationsOfLease(leaseID, "taken back when the lease could not be taken over: "+reason)
	}
	s.broadcastSecretsUpdate("lease_expired", leaseID)
}

// testRevokeLapsedLease, when set, stands in for the fan-out that scrubs a
// lapsed lease off every executor holding it, so a test can watch it without
// building the process-wide agent hub. Nil in production.
var testRevokeLapsedLease func(leaseID, reason string)

// retireRunLeases releases the leases of a run that ended while no hub process
// held them: the run is over, its device wiped its copy when the workload
// ended, and what is left is the release its holder never wrote.
func (s *Server) retireRunLeases(leaseIDs []string, reason string) {
	for _, id := range leaseIDs {
		if liveLeases.held(id) {
			continue
		}
		retireLeaseRecord(id, reason)
	}
}

// retireLeaseRecord retires leaseID's record, if it still has one, and the
// records of the sessions it fed (Task 20383): nothing will restore those now.
func retireLeaseRecord(leaseID, reason string) {
	broker, db, closeDB, err := openUIBrokerDB(controlPlaneDir())
	if err != nil {
		return
	}
	defer closeDB()
	retireLeaseSessionRecords(db, leaseID, "its lease was retired: "+reason)
	rec, err := broker.LeaseRecordFor(leaseID)
	if err != nil {
		return
	}
	if _, err := broker.RetireRecord(rec, reason); err != nil {
		fmt.Fprintf(os.Stderr, "ui: retire the record of lease %s: %v\n", leaseID, err)
	}
}

// sweepOrphanedLeaseRecords retires the recorded leases that lapsed while no
// live hub process held them, and returns them for the janitor to take back
// from the devices that may still hold them — so a lease's TTL binds across a
// restart as it does within one process. Only the leader sweeps: every member
// sees the same records, and one revocation per lapsed lease is enough.
//
// A lease held by a live process — this one or a peer — is that process's
// janitor's business, and a lease that has not lapsed may still be taken over
// by the process its run's agent reconnects to.
func (s *Server) sweepOrphanedLeaseRecords(now time.Time) []remote.ExpiredLease {
	n := s.clusterNode()
	dir := controlPlaneDir()
	if n == nil || !n.IsLeader() || dir == "" {
		return nil
	}
	// The rows first, through a plain handle: a broker costs a key derivation
	// to open, and on almost every tick there is nothing to sweep.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil
	}
	rows, err := db.ListSecretLeases()
	_ = db.Close()
	if err != nil {
		return nil
	}
	self := leaseHolderID()
	orphaned := func(holder string, expiresAt time.Time) bool {
		if now.Before(expiresAt) {
			return false
		}
		if holder == self {
			return false // this process's own: the registry decides, above
		}
		return holder == "" || !n.Serving(holder)
	}
	var due []statedb.SecretLeaseRow
	for _, row := range rows {
		if orphaned(row.Holder, row.ExpiresAt) || (row.Holder == self && !now.Before(row.ExpiresAt) && !liveLeases.held(row.LeaseID)) {
			due = append(due, row)
		}
	}
	if len(due) == 0 {
		return nil
	}
	broker, bdb, closeDB, err := openUIBrokerDB(dir)
	if err != nil {
		return nil
	}
	defer closeDB()
	var out []remote.ExpiredLease
	for _, row := range due {
		rec, err := broker.LeaseRecordFor(row.LeaseID)
		if err != nil || rec.Holder != row.Holder || now.Before(rec.ExpiresAt) {
			continue // released, taken over or extended since the scan
		}
		reason := fmt.Sprintf("lease TTL expired %s ago, after the hub process holding it stopped",
			now.Sub(rec.ExpiresAt).Round(time.Second))
		retired, err := broker.RetireRecord(rec, reason)
		if err != nil || !retired {
			continue
		}
		// The sessions it fed go with it (Task 20383): nothing restores a
		// session whose lease is gone.
		retireLeaseSessionRecords(bdb, rec.ID, "its lease was retired: "+reason)
		out = append(out, remote.ExpiredLease{LeaseID: rec.ID, Reason: reason})
	}
	return out
}

// watchAdoptedSessions watches the executor session of an adopted run's
// workload to its end, as the process that dispatched it would have.
func watchAdoptedSessions(ex executor.Executor, handleID string) {
	defer recoverGoroutine("watch adopted session: " + handleID)
	for _, id := range runningSessionsFor(ex, handleID) {
		go watchSessionExit(controlPlaneDir(), ex, handleID, id)
	}
}

// closeAdoptedSessions closes the executor session of an adopted run that had
// already ended, with how it ended.
func closeAdoptedSessions(ex executor.Executor, handleID string, st executor.Status, stErr error) {
	state := statedb.ExecutorSessionFailed
	if stErr == nil && st.State == executor.StateExited && st.ExitCode == 0 {
		state = statedb.ExecutorSessionFinished
	}
	for _, id := range runningSessionsFor(ex, handleID) {
		closeSession(controlPlaneDir(), id, state)
	}
}

// runningSessionsFor returns the ids of the running sessions of handleID on ex.
func runningSessionsFor(ex executor.Executor, handleID string) []string {
	dir := controlPlaneDir()
	if dir == "" || ex == nil || handleID == "" {
		return nil
	}
	sched, db, err := newScheduler(dir)
	if err != nil {
		return nil
	}
	defer db.Close()
	sessions, err := sched.RunningSessions(ex.ID())
	if err != nil {
		return nil
	}
	var out []string
	for _, sess := range sessions {
		if sess.HandleID == handleID {
			out = append(out, sess.ID)
		}
	}
	return out
}
