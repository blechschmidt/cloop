package ui

// lease_revocation.go: a revocation outlives the hub member holding the lease
// (Task 20419).
//
// Revoking a lease used to be a fan-out: each live member took the lease back
// from what it held, and POST /api/leases/{id}/revoke answered 404 when none
// of them held it. A lease whose holder member had died was held by nobody, so
// the fan-out reached nothing and recorded nothing; the member that adopted
// the dead member's run then took the lease over and restored its git proxy and
// Kubernetes monitor sessions. An incident responder's revoke was undone
// without a trace.
//
// Now a revocation is written down before any holder is asked
// (secretbroker.RecordLeaseRevocation), and four things act on the record:
//
//   - the broker refuses to hand a revoked lease to a new holder, so the member
//     adopting the run takes the material back instead (run_takeover.go), and
//     refuses to extend it, so a holder the fan-out could not reach stops
//     keeping it alive;
//   - the member that adopts what a dead member left — the leader for a
//     container, Pod or host process, the member holding an agent's socket for
//     the agent's — brings the dead member's workloads within reach before its
//     drivers are asked (reachOrphanedHolders), rather than waiting for its
//     next sweep or, for a run no member can adopt, for the workload to exit;
//   - each member's lease janitor enforces a pending revocation of a lease it
//     holds, and the leader one whose holder is gone;
//   - the request answers 202 when nothing could reach the workload yet, with
//     a per-holder pending state that says when the revocation takes effect,
//     instead of a 404 that read as "there was nothing to revoke".

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// recordedRevocation is what recording a revocation learned about its lease.
type recordedRevocation struct {
	// Recorded: the revocation is on record and binds whoever takes the lease
	// over, now or after the member holding it died.
	Recorded bool
	// Known: the lease has a record, or this process holds it — a lease the
	// hub knows of, whether or not anything reachable holds it now.
	Known bool
	Rev   secretbroker.LeaseRevocation
}

// recordLeaseRevocation writes a revocation down before any holder is asked.
// A lease nobody has a record of and this process does not hold is not
// recorded: there is nothing such a record could bind.
func (s *Server) recordLeaseRevocation(leaseID, grantID string, action remote.RevokeAction, reason, actor string) recordedRevocation {
	var out recordedRevocation
	broker, closeDB, err := openUIBroker(s.WorkDir)
	if err != nil {
		if !isBrokerUnconfigured(err) {
			fmt.Fprintf(os.Stderr, "ui: record revocation of lease %s: %v\n", leaseID, err)
		}
		return out
	}
	defer closeDB()
	_, recErr := broker.LeaseRecordFor(leaseID)
	out.Known = recErr == nil || liveLeases.held(leaseID)
	if !out.Known {
		return out
	}
	rev := secretbroker.LeaseRevocation{
		LeaseID: leaseID, GrantID: strings.TrimSpace(grantID), Action: string(action), Reason: reason, Actor: actor,
	}
	if sl := liveLeases.get(leaseID); sl != nil && sl.lease != nil {
		rev.ExecutorID, rev.ProjectID = sl.lease.ExecutorID, sl.lease.ProjectID
		if rev.Holder == "" && !sl.isHandedOver() {
			rev.Holder = leaseHolderID()
		}
	}
	recorded, ok, err := broker.RecordLeaseRevocation(rev)
	if err != nil {
		// The fan-out still runs; what is lost is that a member adopting the
		// run later would not know. Said where an operator will look.
		fmt.Fprintf(os.Stderr, "ui: the revocation of lease %s could not be recorded, so a hub member that "+
			"takes the lease over later would not know of it: %v\n", leaseID, err)
		return out
	}
	out.Recorded, out.Rev = ok, recorded
	return out
}

// holderGone reports whether the hub process recorded as holding a lease no
// longer serves this control plane: dead, left, or heartbeating without
// answering. A lease no process is recorded as holding counts as gone.
func (s *Server) holderGone(holder string) bool {
	holder = strings.TrimSpace(holder)
	if holder == "" {
		return true
	}
	if holder == leaseHolderID() || holder == s.hubInstanceID() {
		return false
	}
	n := s.clusterNode()
	if n == nil {
		// A standalone hub holds what it holds; any other holder is a
		// predecessor of this process, which is gone.
		return true
	}
	return !n.Serving(holder)
}

// concludeRevocation settles a recorded revocation that out found enforced, or
// adds to out the pending account of a holder nothing could reach — a member
// the fan-out could not ask, or the workload of a holder that is gone.
func (s *Server) concludeRevocation(rec recordedRevocation, out *leaseRevocation) {
	if !rec.Recorded {
		return
	}
	// A member that could not be asked is most often one that stopped a moment
	// ago and is not yet judged dead. Unreachable said the revocation was lost
	// on it; on record, it is pending, and it binds that member all the same.
	out.pendUnasked(rec.Rev)
	if !out.reached() && s.holderGone(rec.Rev.Holder) {
		out.Pending = append(out.Pending, pendingRevocationOutcome(rec.Rev))
	}
	out.State = aggregateState(out.holders(), out.WipedLocally)
	switch {
	case len(out.Pending) > 0:
		noteRevocation(rec.Rev, out.Pending[len(out.Pending)-1].Error)
	case out.State == remote.RevokeStateRevoked:
		settleRevocation(rec.Rev.LeaseID, rec.Rev.GrantID, revokeNote(*out))
	default:
		noteRevocation(rec.Rev, revokeNote(*out))
	}
}

// pendUnasked moves the unreachable account of each member the fan-out could
// not ask from Remote to Pending, for a revocation on record.
func (lr *leaseRevocation) pendUnasked(rev secretbroker.LeaseRevocation) {
	if len(lr.unasked) == 0 {
		return
	}
	kept := lr.Remote[:0]
	for _, r := range lr.Remote {
		member, isMember := strings.CutPrefix(r.ExecutorID, "hub member ")
		if !isMember || r.State != remote.RevokeStateUnreachable || !slices.Contains(lr.unasked, member) {
			kept = append(kept, r)
			continue
		}
		lr.Pending = append(lr.Pending, unaskedMemberOutcome(rev, member, r.Error))
	}
	lr.Remote = kept
}

// unaskedMemberOutcome is the pending account of a hub member a recorded
// revocation could not be put to. The record binds it whether it stopped or
// was only cut off: the lease janitor puts the revocation to it again until it
// answers, the member that adopts its run takes the material back instead of
// taking the lease over, and no hub process extends the lease meanwhile.
func unaskedMemberOutcome(rev secretbroker.LeaseRevocation, member, cause string) executor.RevokeOutcome {
	then := "takes the credential back instead of taking the lease over"
	if rev.GrantID != "" {
		then = "takes this grant's credential back"
	}
	if cause == "" {
		cause = "no answer"
	}
	action := executor.RevokeAction(rev.Action)
	if !action.Valid() {
		action = executor.RevokeScrub
	}
	return executor.RevokeOutcome{
		LeaseID: rev.LeaseID, GrantID: rev.GrantID, ExecutorID: "hub member " + member,
		State: executor.RevokeStatePending, Action: action, Reason: rev.Reason, SentAt: time.Now(),
		Error: fmt.Sprintf("recorded; takes effect when hub member %s answers, or when its run is reached if it "+
			"stopped: it could not be asked (%s). The record binds it all the same — the lease janitor asks it "+
			"again until it answers, the member that adopts its run or reaches its workload %s, and no hub "+
			"process extends the lease", member, cause, then),
	}
}

// pendingRevocationOutcome is the holder a recorded revocation is waiting for:
// the workload of a lease whose holder stopped before it could be told.
func pendingRevocationOutcome(rev secretbroker.LeaseRevocation) executor.RevokeOutcome {
	who := "the hub process that held it"
	if rev.Holder != "" {
		who = "hub member " + rev.Holder
	}
	executorID := rev.ExecutorID
	if executorID == "" {
		executorID = who
	}
	action := executor.RevokeAction(rev.Action)
	if !action.Valid() {
		action = executor.RevokeScrub
	}
	then := "takes the credential back instead of taking the lease over"
	if rev.GrantID != "" {
		then = "takes this grant's credential back, and the lease keeps only what nobody revoked"
	}
	return executor.RevokeOutcome{
		LeaseID: rev.LeaseID, GrantID: rev.GrantID, ExecutorID: executorID,
		State: executor.RevokeStatePending, Action: action, Reason: rev.Reason, SentAt: time.Now(),
		Error: fmt.Sprintf("recorded; takes effect when %s's run is reached: %s stopped before it could be "+
			"told, and the member that adopts the run — or reaches its workload — %s", who, who, then),
	}
}

// settleRevocation records a revocation enforced by this process.
func settleRevocation(leaseID, grantID, detail string) {
	withRevocationDB(func(db *statedb.DB) {
		if _, err := db.MarkLeaseRevocationEnforced(leaseID, grantID, leaseHolderIDOrProcess(), detail,
			time.Now().UTC()); err != nil {
			fmt.Fprintf(os.Stderr, "ui: settle the revocation of lease %s: %v\n", leaseID, err)
		}
	})
}

// noteRevocation records why a revocation is still pending.
func noteRevocation(rev secretbroker.LeaseRevocation, detail string) {
	withRevocationDB(func(db *statedb.DB) {
		if err := db.NoteLeaseRevocation(rev.LeaseID, rev.GrantID, detail); err != nil {
			fmt.Fprintf(os.Stderr, "ui: note the revocation of lease %s: %v\n", rev.LeaseID, err)
		}
	})
}

// settleRevocationsOfLease settles every pending revocation of leaseID — the
// whole lease and each grant of it — once its material was taken back whole.
func settleRevocationsOfLease(leaseID, detail string) {
	withRevocationDB(func(db *statedb.DB) {
		revs, err := db.LeaseRevocations(leaseID)
		if err != nil {
			return
		}
		for _, r := range revs {
			if r.Pending() {
				_, _ = db.MarkLeaseRevocationEnforced(r.LeaseID, r.GrantID, leaseHolderIDOrProcess(), detail,
					time.Now().UTC())
			}
		}
	})
}

// withRevocationDB runs fn over the control plane's database, if there is one.
func withRevocationDB(fn func(db *statedb.DB)) {
	dir := controlPlaneDir()
	if dir == "" {
		return
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return
	}
	defer db.Close()
	db.AsControlPlane()
	fn(db)
}

// leaseHolderIDOrProcess names this process in a settled revocation.
func leaseHolderIDOrProcess() string {
	if id := leaseHolderID(); id != "" {
		return id
	}
	return fmt.Sprintf("pid %d", os.Getpid())
}

// ── reaching what a dead member left ─────────────────────────────────────────

// namesLease reports whether a run's owner row names leaseID among the
// leases the run holds.
func (m runOwnerMeta) namesLease(leaseID string) bool {
	if leaseID == "" {
		return false
	}
	if slices.Contains(m.Leases, leaseID) {
		return true
	}
	return m.Workspace != nil && m.Workspace.Lease == leaseID
}

// adoptsRun reports whether this member is the one to adopt a run whose owner
// is gone: the member holding the agent's socket for a run on an edge agent,
// the leader for any other (adoptOrphanedRuns).
func (s *Server) adoptsRun(meta runOwnerMeta) bool {
	n := s.clusterNode()
	if n == nil {
		return false
	}
	if agent := s.agentForExecutorID(meta.Executor); agent != "" {
		return n.Owns(ownerAgent, agent)
	}
	// A workload whose row a serving member claimed is tracked by that
	// member's driver already (Task 20419): the run is that member's to adopt
	// — the only one that can stream it — whoever leads now.
	if owner, found := handleOwner(meta.Handle); found && owner != "" {
		if owner == n.ID() {
			return true
		}
		if n.Serving(owner) {
			return false
		}
	}
	return n.LeadsAdoption()
}

// reachOrphanedHolders brings within this member's reach the workloads a dead
// member left holding leaseID, before a revocation asks this member's drivers:
//
//   - the run whose owner row names the lease is adopted now, by the member
//     that would adopt it at its next sweep — and adoption, finding the lease
//     revoked, takes the material back rather than the lease over;
//   - a dead member's workload rows on this member's own drivers that bind the
//     lease are rehydrated by the leader, so the drivers' lease index knows
//     them: what reaches a workload whose run no member can adopt — its claim
//     was never recorded, or the executor is not this member's to adopt for.
//
// A standalone hub has nothing to reach: its predecessor's workloads were
// rehydrated when it started.
func (s *Server) reachOrphanedHolders(leaseID string) {
	n := s.clusterNode()
	if n == nil || strings.TrimSpace(leaseID) == "" {
		return
	}
	defer recoverGoroutine("reach the holders of lease " + leaseID)
	if orphans, err := n.Orphans(ownerRun); err == nil {
		for _, o := range orphans {
			var meta runOwnerMeta
			if o.Meta(&meta) != nil || meta.Dispatching || !meta.namesLease(leaseID) || !s.adoptsRun(meta) {
				continue
			}
			s.adoptRun(o, meta, "a revocation of its lease had to reach its workload")
		}
	}
	if n.LeadsAdoption() {
		s.rehydrateOrphanedHandles(func(r executor.HandleRecord) bool { return handleBindsLease(r, leaseID) })
	}
}

// rehydrateOrphanedHandles has every local driver adopt the workload rows a
// dead member left that want reports true for, and reports how many drivers
// it asked. A driver adopts every row of a dead member it is shown, which is
// what the member adopting that member's runs does anyway: the rows of runs
// adopted after this are found already tracked.
func (s *Server) rehydrateOrphanedHandles(want func(executor.HandleRecord) bool) int {
	store := s.clusterHandleStoreFor()
	n := s.clusterNode()
	if store == nil || n == nil {
		return 0
	}
	asked := 0
	for _, ex := range executor.List() {
		if ex == nil || ex.Kind() == executor.KindRemoteAgent {
			continue // an agent's workloads are adopted by the member holding its socket
		}
		att, ok := ex.(interface{ AttachHandleStore(executor.HandleStore) })
		if !ok {
			continue
		}
		rows, err := store.ListHandles(ex.ID())
		if err != nil {
			continue
		}
		need := false
		for _, r := range rows {
			owner := strings.TrimSpace(r.Meta[handleMetaInstance])
			if owner != "" && owner != n.ID() && want(r) {
				need = true
				break
			}
		}
		if need {
			att.AttachHandleStore(store)
			asked++
		}
	}
	return asked
}

// handleBindsLease reports whether a workload row records material of leaseID
// — or does not record what it holds, in which case it may.
func handleBindsLease(r executor.HandleRecord, leaseID string) bool {
	if !r.SecretsRecorded {
		return true
	}
	for _, b := range r.Secrets {
		if b.LeaseID == leaseID {
			return true
		}
	}
	return false
}

// ── adoption meets a revoked lease ───────────────────────────────────────────

// enforceRevokedTakeover takes the material of a revoked lease back from the
// run this process is adopting, instead of taking the lease over (Task
// 20419): the workload is reachable from here now — its handle rehydrated in
// a local driver, or its agent connected here — and nothing else would. The
// lease's record and the records of the sessions it fed are retired, so
// nothing restores them.
func (s *Server) enforceRevokedTakeover(workDir string, ex executor.Executor, handleID, leaseID string, refusal error) {
	rev, _ := secretbroker.RevocationOf(refusal)
	if rev.LeaseID == "" {
		rev.LeaseID = leaseID
	}
	action := executor.RevokeAction(rev.Action)
	if !action.Valid() {
		action = executor.RevokeScrub
	}
	reason := strings.TrimSpace(rev.Reason)
	if reason == "" {
		reason = "revoked"
	}
	who := rev.Actor
	if who == "" {
		who = "an operator"
	}
	reason = fmt.Sprintf("%s (revoked by %s while no hub process held the lease; taken back by the process that "+
		"adopted the run)", reason, who)
	actor := rev.Actor
	if actor == "" {
		actor = "janitor"
	}
	var out leaseRevocation
	if testEnforceRevokedLease != nil {
		testEnforceRevokedLease(leaseID, reason, action)
		out = leaseRevocation{WipedLocally: true, State: remote.RevokeStateRevoked}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
		out = s.revokeLeaseHereReaching(ctx, leaseID, "", reason, action, actor, false)
		cancel()
	}
	retireLeaseRecord(leaseID, "revoked while no hub process held it")
	adoptionEnforcements.record(leaseID, out)
	s.log().Info("cluster", 0, "an adopted run's lease was revoked while no hub process held it; its material "+
		"was taken back instead of the lease taken over",
		map[string]interface{}{"project": workDir, "lease": leaseID, "executor": ex.ID(), "handle": handleID,
			"state": string(out.State), "revoked_by": rev.Actor})
	if out.State == remote.RevokeStateRevoked {
		settleRevocationsOfLease(leaseID, "taken back by the hub process that adopted its run")
	} else {
		noteRevocation(rev, revokeNote(out))
	}
	s.broadcastSecretsUpdate("lease_revoked", leaseID)
}

// testEnforceRevokedLease, when set, stands in for the revocation that takes a
// revoked lease's material back from an adopted run, as testRevokeLapsedLease
// does for a lapsed one. Nil in production.
var testEnforceRevokedLease func(leaseID, reason string, action executor.RevokeAction)

// ── the janitor's half ───────────────────────────────────────────────────────

// revocationRetry spaces the janitor's attempts at one pending revocation:
// once a minute at first, backing off to every half hour, so a revocation
// waiting on a device that is away does not write an audit row a minute.
type revocationRetry struct {
	mu   sync.Mutex
	next map[[2]string]time.Time
	gap  map[[2]string]time.Duration
}

var pendingRevocationRetry = &revocationRetry{next: map[[2]string]time.Time{}, gap: map[[2]string]time.Duration{}}

// due reports whether the revocation (lease, grant) may be tried at now, and
// if so books the next attempt.
func (r *revocationRetry) due(key [2]string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if next, ok := r.next[key]; ok && now.Before(next) {
		return false
	}
	gap := r.gap[key]
	switch {
	case gap == 0:
		gap = time.Minute
	case gap < 30*time.Minute:
		gap *= 2
	}
	r.gap[key], r.next[key] = gap, now.Add(gap)
	return true
}

// forget drops a revocation that is no longer pending.
func (r *revocationRetry) forget(key [2]string) {
	r.mu.Lock()
	delete(r.next, key)
	delete(r.gap, key)
	r.mu.Unlock()
}

// revocationRetention is how long an enforced revocation is kept, for the
// trail an operator reads after an incident and for a member adopting a run
// that would otherwise take the lease over.
const revocationRetention = 30 * 24 * time.Hour

// reconcileRecordedRevocations enforces the revocations still pending that
// this member can act on: one of a lease it holds — the fan-out did not reach
// it, or it took the lease over after the revocation was recorded — and, on
// the leader, one whose holder is gone. The leader also prunes revocations
// enforced long ago.
func (s *Server) reconcileRecordedRevocations(ctx context.Context, now time.Time) {
	dir := controlPlaneDir()
	if dir == "" || !samePath(dir, s.WorkDir) {
		return
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return
	}
	pending, err := db.ListLeaseRevocations(true)
	leader := s.isLeader() || s.clusterNode().LeadsAdoption()
	if leader {
		if _, perr := db.PruneLeaseRevocations(now.Add(-revocationRetention)); perr != nil {
			fmt.Fprintf(os.Stderr, "ui: prune enforced lease revocations: %v\n", perr)
		}
	}
	holders := map[string]string{}
	recorded := map[string]bool{}
	if err == nil {
		for _, rev := range pending {
			if row, gerr := db.GetSecretLease(rev.LeaseID); gerr == nil {
				holders[rev.LeaseID], recorded[rev.LeaseID] = row.Holder, true
			}
		}
	}
	_ = db.Close()
	if err != nil || len(pending) == 0 {
		return
	}
	for _, row := range pending {
		key := [2]string{row.LeaseID, row.GrantID}
		rev := secretbroker.LeaseRevocation{
			LeaseID: row.LeaseID, GrantID: row.GrantID, Action: row.Action, Reason: row.Reason, Actor: row.Actor,
			ExecutorID: row.ExecutorID, ProjectID: row.ProjectID, Holder: row.Holder, RevokedAt: row.RevokedAt,
		}
		sl := liveLeases.get(row.LeaseID)
		own := sl != nil && sl.lease != nil && !sl.isHandedOver() &&
			(sl.controlPlane == "" || samePath(sl.controlPlane, s.WorkDir))
		holder := row.Holder
		if h, ok := holders[row.LeaseID]; ok {
			holder = h
		}
		switch {
		case own:
		case leader && (!recorded[row.LeaseID] || s.holderGone(holder)):
		default:
			// A live holder's own janitor enforces it, and anything else is
			// the leader's.
			continue
		}
		if !pendingRevocationRetry.due(key, now) {
			continue
		}
		action := executor.RevokeAction(row.Action)
		if !action.Valid() {
			action = executor.RevokeScrub
		}
		reason := row.Reason
		if reason == "" {
			reason = "revoked"
		}
		reason += " (a recorded revocation, enforced by the lease janitor)"
		actor := row.Actor
		if actor == "" {
			actor = "janitor"
		}
		out := s.revokeLeaseEverywhere(ctx, row.LeaseID, row.GrantID, reason, action, actor)
		rev.Holder = holder
		rec := recordedRevocation{Recorded: true, Known: true, Rev: rev}
		if !recorded[row.LeaseID] && !out.reached() {
			// The lease ended — released with its run, or swept once it lapsed
			// — and nothing this member can reach still holds its material.
			settleRevocation(row.LeaseID, row.GrantID, "the lease had ended, and no reachable workload held its material")
			pendingRevocationRetry.forget(key)
			continue
		}
		s.concludeRevocation(rec, &out)
		if out.State == remote.RevokeStateRevoked {
			pendingRevocationRetry.forget(key)
		}
		s.broadcastSecretsUpdate("lease_revoked", row.LeaseID)
	}
}

// ── a cordon whose agent's member stopped ─────────────────────────────────────

// recordedLeasesOf returns the leases recorded as issued to executorID or to
// a virtual executor running through it.
func recordedLeasesOf(executorID string) []string {
	dir := controlPlaneDir()
	if dir == "" || strings.TrimSpace(executorID) == "" {
		return nil
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil
	}
	defer db.Close()
	rows, err := db.ListSecretLeases()
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		if r.ExecutorID == executorID || virtualParentOf(r.ExecutorID) == executorID {
			out = append(out, r.LeaseID)
		}
	}
	return out
}

// ── what adoption took back, for the revocation that caused it ──────────────

// adoptionEnforcements carries what a member took back from a run it adopted
// to the revocation that had it adopt the run (reachOrphanedHolders): adoption
// finds the lease revoked and takes the material back itself, so by the time
// the revocation asks the drivers the workload holds nothing — and without
// this the revocation that did the work would report reaching nobody.
var adoptionEnforcements = &enforcementLog{byLease: map[string]takenBack{}}

type enforcementLog struct {
	mu      sync.Mutex
	byLease map[string]takenBack
}

type takenBack struct {
	at  time.Time
	out leaseRevocation
}

// enforcementTTL bounds how long an adoption's outcome waits to be collected:
// the revocation that caused the adoption collects it as soon as adoption
// returns, so anything older belongs to an adoption no revocation asked for.
const enforcementTTL = time.Minute

// record files what adopting a run took back of leaseID.
func (l *enforcementLog) record(leaseID string, out leaseRevocation) {
	if leaseID == "" || (!out.reached() && len(out.Pending) == 0) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for id, tb := range l.byLease {
		if now.Sub(tb.at) > enforcementTTL {
			delete(l.byLease, id)
		}
	}
	prev := l.byLease[leaseID]
	prev.at = now
	prev.out.WipedLocally = prev.out.WipedLocally || out.WipedLocally
	prev.out.Remote = append(prev.out.Remote, out.Remote...)
	prev.out.Local = append(prev.out.Local, out.Local...)
	l.byLease[leaseID] = prev
}

// take returns, and forgets, what adopting a run took back of leaseID.
func (l *enforcementLog) take(leaseID string) (leaseRevocation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tb, ok := l.byLease[leaseID]
	delete(l.byLease, leaseID)
	if !ok || time.Since(tb.at) > enforcementTTL {
		return leaseRevocation{}, false
	}
	return tb.out, true
}

// mergeTakenBack folds what an adoption took back into out, which the
// drivers' own answers are added to after: an executor that already answered
// during the adoption is not asked twice.
func mergeTakenBack(out *leaseRevocation, prior leaseRevocation) map[string]bool {
	answered := map[string]bool{}
	out.WipedLocally = out.WipedLocally || prior.WipedLocally
	for _, r := range prior.Remote {
		out.Remote = append(out.Remote, r)
		answered[r.ExecutorID] = true
	}
	for _, r := range prior.Local {
		out.Local = append(out.Local, r)
		answered[r.ExecutorID] = true
	}
	return answered
}
