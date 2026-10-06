package ui

// session_janitor.go retires the records of proxy sessions nobody will
// restore (Task 20383): the leader's half of proxy_session_store.go, as
// sweepOrphanedLeaseRecords is for secret_leases.

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sessionSweepInterval is how often the leader looks for records to retire.
// A closed session's record is retired on the first sweep after it closed, a
// lapsed one on the first after its TTL — nothing waits on either.
const sessionSweepInterval = time.Minute

// sessionRecordGrace is how long a record is left alone after it was written
// or taken over before the janitor may judge it by its lease: a lease-path
// session is recorded while its lease is being built, a moment before the
// lease's own record exists, and a restore takes the session over a moment
// before it serves it.
const sessionRecordGrace = 2 * time.Minute

// maybeSweepProxySessionRecords runs sweepProxySessionRecords at most every
// sessionSweepInterval, off the watcher goroutine.
func (s *Server) maybeSweepProxySessionRecords(now time.Time) {
	n := s.clusterNode()
	if n == nil || !n.IsLeader() {
		return
	}
	s.clusterMu.Lock()
	due := now.Sub(s.lastSessionSweep) >= sessionSweepInterval
	if due {
		s.lastSessionSweep = now
	}
	s.clusterMu.Unlock()
	if due {
		go func() {
			defer recoverGoroutine("sweep proxy session records")
			s.sweepProxySessionRecords(now)
		}()
	}
}

// sweepProxySessionRecords retires the records of sessions that ended or
// lapsed, and of GitHub App token slots whose lease is gone. Only the leader
// sweeps: every member sees the same rows.
//
// A record is retired when it was closed; when it is open and past its TTL by
// more than sessionRecordGrace, whoever holds it; or when it is open but its
// holder is not a live hub process — or is this one, and serves it no more —
// and either its TTL has run out or the lease it stood on has no record. An
// open, unexpired record whose holder is alive is that holder's business: it
// closes the session when it ends, and its reaper when it lapses.
func (s *Server) sweepProxySessionRecords(now time.Time) int {
	n := s.clusterNode()
	dir := controlPlaneDir()
	if n == nil || !n.IsLeader() || dir == "" {
		return 0
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return 0
	}
	defer db.Close()
	// And the CI relay's (Task 20390), which stand on no lease.
	ci := s.closeCIRecordsSwitchedOff(db)
	ci += sweepCISessionRecords(db, now, leaseHolderID(), n.IsAlive, s.ciSessionServed)
	return sweepSessionRecords(db, now, leaseHolderID(), n.IsAlive) + ci
}

// closeCIRecordsSwitchedOff ends the CI session records no live hub process
// serves whose instance has federation switched off — the sessions a stopped
// process suspended, its configuration switched off since, by Settings on
// another member or in the file, while it was down or after it came back on
// another port — as that process would have had it been serving them: none
// may relay again (Task 20390). Each record is held to its own instance's
// configuration, which this process reads as that instance does: every
// instance's overlay lives in this directory. It returns how many it closed.
func (s *Server) closeCIRecordsSwitchedOff(db *statedb.DB) int {
	byInstance := map[string][]statedb.CISessionRow{}
	for _, row := range dormantCISessionRecords(db, s.ciSessionServed) {
		byInstance[row.Instance] = append(byInstance[row.Instance], row)
	}
	n := 0
	for instance, rows := range byInstance {
		if s.ciInstanceSwitchedOff(instance) {
			n += closeCISessionRecordRows(db, rows, "CI federation is disabled", s.ciSessionServed)
		}
	}
	return n
}

// sweepSessionRecords is sweepProxySessionRecords over db, as the process
// self, with alive answering whether another hub process is live.
func sweepSessionRecords(db *statedb.DB, now time.Time, self string, alive func(string) bool) int {
	retired := 0
	rows, err := db.ListProxySessions(statedb.ProxySessionFilter{})
	if err == nil && len(rows) > 0 {
		leases := map[string]bool{}
		if recs, lerr := db.ListSecretLeases(); lerr == nil {
			for _, r := range recs {
				leases[r.LeaseID] = true
			}
		} else {
			leases = nil // unknown: judge no record by its lease
		}
		unheld := func(row statedb.ProxySessionRow) bool {
			if row.Holder == "" {
				return true
			}
			if row.Holder == self {
				return !servedHere(row)
			}
			return !alive(row.Holder)
		}
		for _, row := range rows {
			var reason string
			switch {
			case !row.Open():
				reason = row.CloseReason
			case !now.Before(row.ExpiresAt.Add(sessionRecordGrace)):
				// Well past its TTL: no registry serves a session that far
				// gone, whoever holds the record — including a live holder
				// whose own close of it failed to land.
				reason = fmt.Sprintf("lapsed at %s", row.ExpiresAt.UTC().Format(time.RFC3339))
			case !unheld(row):
				continue
			case !now.Before(row.ExpiresAt):
				reason = fmt.Sprintf("lapsed at %s while no hub process held it",
					row.ExpiresAt.UTC().Format(time.RFC3339))
			case leases != nil && row.LeaseID != "" && !leases[row.LeaseID] &&
				now.Sub(row.UpdatedAt) >= sessionRecordGrace:
				reason = "its lease ended while no hub process held the session"
			default:
				continue
			}
			if retireSessionRow(db, row, reason) {
				retired++
			}
		}
	}
	// A slot outlives its lease only when the process holding both stopped
	// between the two deletes.
	_, _ = db.DeleteOrphanedAppTokenSlots()
	return retired
}

// servedHere reports whether this process serves the session a record names.
func servedHere(row statedb.ProxySessionRow) bool {
	switch row.Kind {
	case statedb.ProxySessionGit:
		svc := activeGitProxy()
		return svc != nil && svc.reg != nil && svc.reg.Known(row.SessionID)
	case statedb.ProxySessionKube:
		svc := activeKubeGuard()
		return svc != nil && svc.reg != nil && svc.reg.Known(row.SessionID)
	case statedb.ProxySessionEgress:
		svc := activeEgressProxy()
		return svc != nil && svc.broker.Session(row.SessionID) != nil
	}
	return false
}
