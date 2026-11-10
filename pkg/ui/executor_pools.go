package ui

// executor_pools.go: the hub's side of executor pools (Task 20482).
//
// pkg/executorpool decides who may see what and mints what a controller asks
// for; this file is where the hub keeps a pool's state moving:
//
//   - a long-lived store over the control plane's database, which the agent
//     endpoint, the controllers' feeds and the queue all read;
//   - the runner authority the agent endpoint asks about runner tokens and
//     the runners they enroll (remote.RunnerAuthority);
//   - change notices: whatever changes a pool's demand or runners on one hub
//     member — a run queued, a runner enrolled or retired, the pool revoked —
//     wakes the feeds and the dispatcher here and, through the cluster bus,
//     on every other member, so a controller is told within a bus poll of the
//     change wherever its feed is served;
//   - the dispatcher: the member holding an idle runner's connection hands it
//     the oldest queued run the pool may see (executor_pool_queue.go starts
//     it), because only that member can send the runner a start frame;
//   - retirement: a runner is retired when its run is settled, when it leaves
//     before it was handed one, when it has idled too long, or when its pool
//     is revoked — never left to be reported as a failed device.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// busTopicPool carries a change to one executor pool (key: the pool's ID)
// from the member it happened on to every other one.
const busTopicPool = "executor_pool"

// Timing of the pool machinery.
var (
	// poolDispatchTick is how often each member looks for queued runs its
	// idle runners could take, besides being told: a lost bus event costs at
	// most this much.
	poolDispatchTick = 5 * time.Second
	// poolRunnerOfflineGrace is how long a runner that went offline before it
	// was handed a run has to come back before it is retired.
	poolRunnerOfflineGrace = 30 * time.Second
	// poolRunnerMaxIdle retires a runner nobody handed a run: the demand it
	// was started for went away, and its place under max_runners is better
	// spent on a fresh one when demand returns.
	poolRunnerMaxIdle = 15 * time.Minute
	// poolJanitorTick is how often the leader expires lapsed runner tokens
	// and retires idle runners.
	poolJanitorTick = time.Minute
	// poolQueueRetention is how long closed queue rows and retired runner rows
	// are kept for the dashboard and the audit trail's context.
	poolQueueRetention = 7 * 24 * time.Hour
)

// poolBusNotice is busTopicPool's payload.
type poolBusNotice struct {
	// Retire names runners whose connections the member holding them must
	// end — retired by the leader's janitor, or by the pool's revocation.
	Retire []string `json:"retire,omitempty"`
	// Reason is why, for those connections' last frame.
	Reason string `json:"reason,omitempty"`
}

// poolState is a Server's executor pool machinery.
type poolState struct {
	mu    sync.Mutex
	db    *statedb.DB
	store *executorpool.Store
	// closed is set by Shutdown: nothing reopens the handle after it.
	closed bool
	// waiters holds, per pool, a channel closed at the next change: what a
	// controller's feed blocks on.
	waiters map[string]chan struct{}
	// kick asks the dispatcher to look at a pool now.
	kick chan string
	// dispatching guards one dispatcher pass per pool at a time.
	dispatching map[string]bool
}

// poolStore returns the pool store over this hub's control plane, opening it
// on first use. The handle is held for the process's life — the agent
// endpoint and the feeds ask it on every connect — and closed by Shutdown.
func (s *Server) poolStore() (*executorpool.Store, error) {
	s.pools.mu.Lock()
	defer s.pools.mu.Unlock()
	if s.pools.store != nil {
		return s.pools.store, nil
	}
	if s.pools.closed {
		return nil, errors.New("this hub is shutting down")
	}
	if strings.TrimSpace(s.WorkDir) == "" {
		return nil, errors.New("this hub has no control plane to keep executor pools in")
	}
	db, err := statedb.Open(state.DBPath(s.WorkDir))
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	s.pools.db, s.pools.store = db.AsControlPlane(), executorpool.NewStore(db)
	return s.pools.store, nil
}

// closePools releases the pool store's database handle.
func (s *Server) closePools() {
	s.pools.mu.Lock()
	db := s.pools.db
	s.pools.db, s.pools.store, s.pools.closed = nil, nil, true
	s.pools.mu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}

// ── change notices ─────────────────────────────────────────────────────────

// poolChanged announces that something about poolID changed here: the feeds
// and the dispatcher on this member wake, and every other member is told.
func (s *Server) poolChanged(poolID string) {
	s.poolChangedLocal(poolID)
	if n := s.clusterNode(); n != nil && poolID != "" {
		n.Publish(busTopicPool, poolID, poolBusNotice{})
	}
	// And the dashboards watching it scale, on every member (Task 20486).
	s.notePoolDashboard(poolID)
}

// poolChangedLocal wakes this member's feeds and dispatcher for poolID.
func (s *Server) poolChangedLocal(poolID string) {
	if poolID == "" {
		return
	}
	s.pools.mu.Lock()
	if ch, ok := s.pools.waiters[poolID]; ok {
		close(ch)
		delete(s.pools.waiters, poolID)
	}
	kick := s.pools.kick
	s.pools.mu.Unlock()
	if kick != nil {
		select {
		case kick <- poolID:
		default:
			// The dispatcher has a backlog; its next tick looks at every pool.
		}
	}
}

// poolWaitCh is closed at the next change to poolID on this member.
func (s *Server) poolWaitCh(poolID string) <-chan struct{} {
	s.pools.mu.Lock()
	defer s.pools.mu.Unlock()
	if s.pools.waiters == nil {
		s.pools.waiters = map[string]chan struct{}{}
	}
	ch, ok := s.pools.waiters[poolID]
	if !ok {
		ch = make(chan struct{})
		s.pools.waiters[poolID] = ch
	}
	return ch
}

// onBusPool handles another member's pool change.
func (s *Server) onBusPool(ev hubcluster.Event) {
	var p poolBusNotice
	_ = ev.Decode(&p)
	for _, id := range p.Retire {
		s.retireRunnerHere(id, p.Reason)
	}
	s.poolChangedLocal(ev.Key)
}

// onPoolBusGap: events were lost, so every feed re-reads.
func (s *Server) onPoolBusGap() {
	s.pools.mu.Lock()
	ids := make([]string, 0, len(s.pools.waiters))
	for id := range s.pools.waiters {
		ids = append(ids, id)
	}
	s.pools.mu.Unlock()
	for _, id := range ids {
		s.poolChangedLocal(id)
	}
}

// ── access ─────────────────────────────────────────────────────────────────

// poolAccess answers executorpool.Access from the hub's own records: the
// bindings in the shared database, never a member's in-memory mirror, and the
// project access policy (access.go).
type poolAccess struct {
	s  *Server
	db *statedb.DB
}

func (a poolAccess) Binding(projectPath string) (string, error) {
	if a.db == nil {
		return "", errors.New("no control-plane database")
	}
	// A feature runs on its project's executor, and has no binding of its own.
	id, ok, err := a.db.ProjectExecutor(policyProjectPath(projectPath))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return id, nil
}

func (a poolAccess) OwnerMayRead(owner, projectPath string) (bool, error) {
	return a.s.identityMayReadProject(owner, projectPath)
}

// poolAccessFor is the Access the pools judge queued runs with.
func (s *Server) poolAccessFor(store *executorpool.Store) executorpool.Access {
	return poolAccess{s: s, db: store.DB()}
}

// identityMayReadProject reports whether the person whose owner key is key —
// a lowercased email, or "sub:<subject>" — may read the project at workDir,
// under the policy a request of theirs would be judged by: with no claims
// beyond who they are, since nobody signed in is asking.
func (s *Server) identityMayReadProject(key, workDir string) (bool, error) {
	if !s.isRegisteredProject(policyProjectPath(workDir)) {
		// Not a refusal: a member whose registry has not caught up decides
		// nothing about a project another member serves.
		return false, fmt.Errorf("project %s is not registered on this hub member", workDir)
	}
	if !s.oidcEnabled() {
		// One operator, who reads everything.
		return true, nil
	}
	user := identityFromOwnerKey(key)
	if user == nil {
		return false, nil
	}
	sub := subjectFromIdentity(user)
	scope := s.workDirScope(workDir)
	if s.authzActive() {
		return s.subjectAuthority(sub, scope).Allows(authz.PermProjectRead), nil
	}
	if d, ok := s.membershipBinds(sub, scope); ok {
		return d.Allows(authz.PermProjectRead), nil
	}
	return true, nil
}

// identityFromOwnerKey is the identity an owner key names.
func identityFromOwnerKey(key string) *oidcauth.Identity {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if sub, ok := strings.CutPrefix(key, "sub:"); ok {
		if sub == "" {
			return nil
		}
		return &oidcauth.Identity{Sub: sub}
	}
	return &oidcauth.Identity{Email: key, Sub: key}
}

// ── the runner authority ───────────────────────────────────────────────────

// poolRunnerAuthority answers the agent endpoint about runner tokens.
type poolRunnerAuthority struct{ s *Server }

func (a poolRunnerAuthority) AdmitRunner(rec remote.EnrollmentRecord) error {
	store, err := a.s.poolStore()
	if err != nil {
		return err
	}
	return store.AdmitRunner(rec.ID)
}

func (a poolRunnerAuthority) RunnerEnrolled(agent remote.AgentRecord) error {
	store, err := a.s.poolStore()
	if err != nil {
		return err
	}
	r, err := store.RunnerEnrolled(agent.EnrollmentID, agent.AgentID, agent.Name, a.s.hubInstanceID())
	if err != nil {
		return err
	}
	a.s.poolChanged(r.PoolID)
	return nil
}

func (a poolRunnerAuthority) IsRunner(agentID string) (bool, error) {
	store, err := a.s.poolStore()
	if err != nil {
		return false, err
	}
	_, err = store.RunnerByExecutor(agentID)
	if errors.Is(err, statedb.ErrPoolRunnerNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// A retired runner is still one: its credential is revoked, and an agent
	// presenting it is refused as a runner rather than adopted as a device.
	return true, nil
}

// poolRunnerStatus wraps the agent hub's status callback: a runner that goes
// offline before it was handed a run is retired at once — its controller
// stopped it, or it died — rather than kept as a device the supervisor would
// report unreachable. A runner that was handed one is left to its run's
// settlement, or to the failover that settles a lost one.
func (s *Server) poolRunnerStatus(next func(string, string, time.Time)) func(string, string, time.Time) {
	return func(executorID, status string, at time.Time) {
		if next != nil {
			next(executorID, status, at)
		}
		if status == remote.StatusOnline {
			return
		}
		ex, err := executor.Get(executorID)
		if err != nil || !executor.IsEphemeral(ex) {
			return
		}
		// A runner that said goodbye for good (Task 20483) — stopped by its
		// controller or its node — will not be back: there is nothing to wait
		// for, and every second it stays idle on the record is one a queued
		// run could be handed to it.
		leaving := false
		if l, ok := ex.(interface{ Leaving() bool }); ok {
			leaving = l.Leaving()
		}
		go func() {
			defer recoverGoroutine("executor pool runner offline")
			// A grace first: a runner whose hub member is restarting, or
			// whose link dropped for a moment, reconnects — here, or to
			// another member, which records itself as the runner's member.
			if !leaving {
				time.Sleep(poolRunnerOfflineGrace)
			}
			store, err := s.poolStore()
			if err != nil {
				return
			}
			r, err := store.RunnerByExecutor(executorID)
			if err != nil || r.State != statedb.PoolRunnerIdle {
				return
			}
			if r.Member != s.hubInstanceID() || s.holdsRunner(executorID) {
				return
			}
			s.retirePoolRunnerIf(executorID, "it left before it was handed a run", statedb.PoolRunnerIdle)
		}()
	}
}

// poolRunnerOnConnect wraps the agent hub's connect callback with
// poolRunnerConnected.
func (s *Server) poolRunnerOnConnect(next func(remote.AgentRecord, remote.AgentCapabilities, string)) func(remote.AgentRecord, remote.AgentCapabilities, string) {
	return func(agent remote.AgentRecord, caps remote.AgentCapabilities, agentVersion string) {
		if next != nil {
			next(agent, caps, agentVersion)
		}
		s.poolRunnerConnected(agent)
	}
}

// poolRunnerConnected records which member holds a runner's connection, and
// has this member's dispatcher look for a run for it.
func (s *Server) poolRunnerConnected(agent remote.AgentRecord) {
	ex, err := executor.Get(agent.AgentID)
	if err != nil || !executor.IsEphemeral(ex) {
		return
	}
	store, err := s.poolStore()
	if err != nil {
		return
	}
	if err := store.DB().SetExecutorPoolRunnerMember(agent.AgentID, s.hubInstanceID()); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record runner %s's member: %v\n", agent.AgentID, err)
	}
	r, err := store.RunnerByExecutor(agent.AgentID)
	if err != nil {
		return
	}
	if r.State == statedb.PoolRunnerRetired {
		// Retired between its enrollment and this handshake (Task 20483): a
		// controller scaling down the moment the feed showed it idle. The
		// retirement found no session to tell, and the handshake then built
		// the runner a fresh executor; tell it now, on the session it has,
		// and drop the records the connect just wrote back.
		reason := r.RetireReason
		if reason == "" {
			reason = "it was retired"
		}
		s.retireRunnerHere(agent.AgentID, reason)
		s.forgetRunnerRecords(store.DB(), agent.AgentID)
	}
	s.poolChangedLocal(r.PoolID)
}

// ── retirement ─────────────────────────────────────────────────────────────

// retirePoolRunner retires a runner: its record and its credential, and its
// connection wherever it is held. Idempotent; the call that retires it writes
// the audit row.
func (s *Server) retirePoolRunner(executorID, reason string) {
	s.retirePoolRunnerIf(executorID, reason)
}

// retirePoolRunnerIf is retirePoolRunner for a runner still in one of states
// (any state when none are given): a caller that judged a runner idle from an
// earlier read must not end it after another member handed it a run.
func (s *Server) retirePoolRunnerIf(executorID, reason string, states ...string) {
	s.retirePoolRunnerBy("", executorID, reason, states...)
}

// retirePoolRunnerBy is retirePoolRunnerIf with the audit row naming actor —
// the controller credential that asked (Task 20483) — and reports whether
// this call retired the runner.
func (s *Server) retirePoolRunnerBy(actor, executorID, reason string, states ...string) bool {
	store, err := s.poolStore()
	if err != nil {
		return false
	}
	r, err := store.RunnerByExecutor(executorID)
	if err != nil {
		return false
	}
	retired, err := store.RetireRunnerBy(actor, executorID, reason, states...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: retire runner %s: %v\n", executorID, err)
		return false
	}
	if !retired && len(states) > 0 {
		// It moved on — or was retired by someone else, who ended it.
		return false
	}
	s.retireRunnerHere(executorID, reason)
	if retired {
		hubmetrics.ExecutorPoolRunnersRetired.Inc(retireReasonLabel(reason))
	}
	s.forgetRunnerRecords(store.DB(), executorID)
	if n := s.clusterNode(); n != nil {
		n.Publish(busTopicPool, r.PoolID, poolBusNotice{Retire: []string{executorID}, Reason: reason})
	}
	s.poolChangedLocal(r.PoolID)
	return retired
}

// forgetRunnerRecords removes what the fleet view keeps of a retired runner:
// its executors row, its health row and anything its isolation probe found. A
// runner is not a device to list, probe or report on once its run is over.
func (s *Server) forgetRunnerRecords(db *statedb.DB, executorID string) {
	if db == nil || executorID == "" {
		return
	}
	if err := db.DeleteExecutor(executorID); err != nil {
		fmt.Fprintf(os.Stderr, "ui: forget retired runner %s: %v\n", executorID, err)
	}
	if err := db.DeleteExecutorHealth(executorID); err != nil {
		fmt.Fprintf(os.Stderr, "ui: forget retired runner %s's health: %v\n", executorID, err)
	}
	forgetIsolationEvidence(executorID)
	executor.DefaultRegistry.Unregister(executorID)
	s.broadcastExecutorUpdate("retired", executorID)
}

// retireRunnerHere ends a runner's connection if this member holds it, and
// takes its executor out of this process's registry. Its credential is revoked
// either way, which every member can do.
func (s *Server) retireRunnerHere(executorID, reason string) {
	hub := activeRemoteHub()
	if hub == nil {
		return
	}
	if err := hub.Retire(executorID, reason); err != nil {
		fmt.Fprintf(os.Stderr, "ui: retire runner %s: %v\n", executorID, err)
	}
}

// retireReasonLabel is the metric label for a retirement reason.
func retireReasonLabel(reason string) string {
	switch {
	case strings.Contains(reason, "settled"):
		return "run_settled"
	case strings.Contains(reason, "before it was handed"):
		return "left_idle"
	case strings.Contains(reason, "idle for"):
		return "idle_timeout"
	case strings.Contains(reason, "credential that minted it was revoked"):
		return "credential_revoked"
	case strings.Contains(reason, "revoked"):
		return "pool_revoked"
	case strings.Contains(reason, "lost"):
		return "lost"
	case strings.Contains(reason, "could not be started"):
		return "start_failed"
	case strings.Contains(reason, "its controller"):
		return "scaled_down"
	}
	return "other"
}

// retireEphemeralAfterRun retires an executor pool's runner once its run has
// been settled (runEnded): it took its one run.
func (s *Server) retireEphemeralAfterRun(ex executor.Executor) {
	if ex == nil || !executor.IsEphemeral(ex) {
		return
	}
	s.retirePoolRunner(ex.ID(), "its run settled")
}

// retireLostPoolRunner retires a runner the failover found unreachable: its
// run was settled as lost, and the runner is not a device to wait for.
func (s *Server) retireLostPoolRunner(executorID string) {
	if s == nil {
		return
	}
	store, err := s.poolStore()
	if err != nil {
		return
	}
	if r, err := store.RunnerByExecutor(executorID); err != nil || r.State == statedb.PoolRunnerRetired {
		return
	}
	s.retirePoolRunner(executorID, "its run was lost with it")
}

// finishPoolRevocation does what a pool's revocation leaves to the hub: the
// live runners' connections end on whichever member holds them, their leases
// are taken back through the revocation push, and every cancelled run gives
// back its concurrency slot and is settled.
func (s *Server) finishPoolRevocation(rev statedb.ExecutorPoolRevocation, actor string) {
	reason := "executor pool " + rev.Pool.Name + " was revoked"
	s.takeBackRunners(rev.Pool.ID, rev.Runners, reason)
	for _, q := range rev.Cancelled {
		s.settleClosedPoolRun(q, "cancelled", reason, actor)
	}
	s.poolChanged(rev.Pool.ID)
}

// takeBackRunners ends runners whose credentials were just revoked — with
// their pool, or with the controller credential that minted them: the leases
// they hold go back through the revocation push while their connections are
// still up, so the material is scrubbed and the workload killed on the device
// rather than merely abandoned; then their connections end, on this member
// and, through the bus, on whichever member holds them; then their fleet
// records go.
func (s *Server) takeBackRunners(poolID string, runners []statedb.ExecutorPoolRunnerRow, reason string) {
	ids := make([]string, 0, len(runners))
	for _, r := range runners {
		if r.ExecutorID != "" {
			ids = append(ids, r.ExecutorID)
		}
	}
	store, _ := s.poolStore()
	for _, id := range ids {
		if hub := activeRemoteHub(); hub != nil {
			hub.RevokeExecutorLeases(context.Background(), id, reason, remote.RevokeKill)
		}
		s.retireRunnerHere(id, reason)
		if store != nil {
			store.AuditRunnerRetired(poolID, id, reason)
			s.forgetRunnerRecords(store.DB(), id)
		}
		hubmetrics.ExecutorPoolRunnersRetired.Inc(retireReasonLabel(reason))
	}
	if n := s.clusterNode(); n != nil && len(ids) > 0 {
		n.Publish(busTopicPool, poolID, poolBusNotice{Retire: ids, Reason: reason})
	}
}

// ── the dispatcher ─────────────────────────────────────────────────────────

// startPools starts this member's pool machinery: the dispatcher, on every
// member, and the janitor, on the leader.
func (s *Server) startPools(ctx context.Context) {
	s.pools.mu.Lock()
	if s.pools.kick == nil {
		s.pools.kick = make(chan string, 64)
	}
	kick := s.pools.kick
	s.pools.mu.Unlock()
	go s.poolDispatcher(ctx, kick)
	go s.runLeaderDuty(ctx, "executor-pool-janitor", s.poolJanitor)
}

// poolDispatcher hands queued runs to the idle runners this member holds.
func (s *Server) poolDispatcher(ctx context.Context, kick <-chan string) {
	defer recoverGoroutine("executor pool dispatcher")
	ticker := time.NewTicker(poolDispatchTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-kick:
			s.dispatchPool(id)
		case <-ticker.C:
			s.dispatchAllPools()
		}
	}
}

// dispatchAllPools runs a dispatch pass for every pool with an idle runner
// held here.
func (s *Server) dispatchAllPools() {
	defer recoverGoroutine("executor pool dispatch tick")
	store, err := s.poolStore()
	if err != nil {
		return
	}
	idle, err := store.DB().ListExecutorPoolRunners("", statedb.PoolRunnerIdle)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, r := range idle {
		if !seen[r.PoolID] && s.holdsRunner(r.ExecutorID) {
			seen[r.PoolID] = true
			s.dispatchPool(r.PoolID)
		}
	}
}

// holdsRunner reports whether this member holds the connection of the runner
// executorID.
func (s *Server) holdsRunner(executorID string) bool {
	hub := activeRemoteHub()
	if hub == nil || executorID == "" {
		return false
	}
	ex, ok := hub.Executor(executorID)
	return ok && ex.Ephemeral() && ex.HealthCheck(context.Background()) == nil && !ex.Spent()
}

// dispatchPool hands each idle runner of poolID this member holds the oldest
// queued run the pool may see, and takes out of the queue the runs it never
// will.
func (s *Server) dispatchPool(poolID string) {
	if poolID == "" {
		return
	}
	s.pools.mu.Lock()
	if s.pools.dispatching == nil {
		s.pools.dispatching = map[string]bool{}
	}
	if s.pools.dispatching[poolID] {
		s.pools.mu.Unlock()
		return
	}
	s.pools.dispatching[poolID] = true
	s.pools.mu.Unlock()
	defer func() {
		s.pools.mu.Lock()
		delete(s.pools.dispatching, poolID)
		s.pools.mu.Unlock()
	}()
	defer recoverGoroutine("executor pool dispatch")

	store, err := s.poolStore()
	if err != nil {
		return
	}
	pool, err := store.Get(poolID)
	if err != nil || pool.Revoked() {
		return
	}
	_, verdicts, err := store.Snapshot(pool, s.poolAccessFor(store))
	if err != nil {
		return
	}
	queue, err := store.DB().ListPoolQueue(poolID, statedb.PoolQueueWaiting)
	if err != nil {
		return
	}
	var visible []statedb.PoolQueueRow
	for _, q := range queue {
		v := verdicts[q.ID]
		switch {
		case v.Visible:
			visible = append(visible, q)
		case v.Final:
			// Waiting will not change it: the run leaves the queue and its
			// project says why, instead of waiting for a runner that will
			// never be handed it.
			if moved, err := store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueWaiting},
				statedb.PoolQueueFailed, v.Reason, time.Now()); err == nil && moved {
				s.settleClosedPoolRun(q, "failed", v.Reason, "system")
			}
		default:
			if q.Reason != v.Reason && v.Reason != "" {
				_ = store.DB().NotePoolQueueReason(q.ID, v.Reason)
			}
		}
	}
	if len(visible) == 0 {
		return
	}
	idle, err := store.DB().ListExecutorPoolRunners(poolID, statedb.PoolRunnerIdle)
	if err != nil {
		return
	}
	member := s.hubInstanceID()
	// Announced only when this pass handed something over: an announcement
	// wakes every member's dispatcher, and one that announced every pass
	// would have two members waking each other for ever.
	assigned := false
	defer func() {
		if assigned {
			s.poolChanged(poolID)
		}
	}()
	type heldRunner struct {
		row statedb.ExecutorPoolRunnerRow
		ex  executor.Executor
	}
	var held []heldRunner
	for _, r := range idle {
		if !s.holdsRunner(r.ExecutorID) {
			continue
		}
		ex, err := executor.Get(r.ExecutorID)
		if err != nil {
			continue
		}
		held = append(held, heldRunner{row: r, ex: ex})
	}
	access := s.poolAccessFor(store)
	// Oldest run first, each to the runner that suits it best (Task 20484):
	// one whose storage already holds its project's data — its workspace and
	// caches kept from the project's last run — and otherwise one whose
	// storage holds nothing. Never a runner holding another project's data:
	// a run no idle runner here may take waits for the next pass, and the
	// runs behind it are not held up by it. The assignment's UPDATE checks
	// the same rule again, so a runner another member just changed cannot
	// slip through.
	for _, q := range visible {
		if len(held) == 0 {
			break
		}
		project := s.runProjectFor(poolID, q, access)
		holds := make([]string, len(held))
		for i, h := range held {
			holds[i] = h.row.Holds
		}
		pick := pickPoolRunner(holds, project.Tenant, project.Tenant != "" && executorpool.RunMayUseHeld(q, access))
		if pick < 0 {
			continue
		}
		h := held[pick]
		ok, err := store.DB().AssignPoolQueueEntryTo(q.ID, h.row.ExecutorID, member, time.Now(), project)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: hand queued run %s to runner %s: %v\n", q.ID, h.row.ExecutorID, err)
			return
		}
		if !ok {
			// Another member took this run, or this runner. A runner that is
			// no longer idle here is dropped; the run is tried again next pass.
			if cur, err := store.RunnerByExecutor(h.row.ExecutorID); err != nil || cur.State != statedb.PoolRunnerIdle ||
				cur.Holds != h.row.Holds {
				held = append(held[:pick], held[pick+1:]...)
			}
			continue
		}
		held = append(held[:pick], held[pick+1:]...)
		q.State, q.ExecutorID, q.Member = statedb.PoolQueueAssigned, h.row.ExecutorID, member
		store.AuditQueue(q, "assigned", "system", "")
		assigned = true
		go s.startQueuedPoolRun(q, h.ex, project.Tenant)
	}
}

// poolJanitor expires runner tokens that lapsed unredeemed, retires runners
// that idled past poolRunnerMaxIdle, and prunes old rows. Leader only: one
// member's pass is the cluster's.
func (s *Server) poolJanitor(ctx context.Context) {
	ticker := time.NewTicker(poolJanitorTick)
	defer ticker.Stop()
	for {
		s.poolJanitorPass(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// poolJanitorPass is one janitor pass at now.
func (s *Server) poolJanitorPass(now time.Time) {
	defer recoverGoroutine("executor pool janitor")
	store, err := s.poolStore()
	if err != nil {
		return
	}
	db := store.DB()
	expired, err := db.ExpireExecutorPoolRunners(now)
	if err == nil {
		changed := map[string]bool{}
		for _, r := range expired {
			changed[r.PoolID] = true
			hubmetrics.ExecutorPoolRunnersRetired.Inc("token_expired")
		}
		for id := range changed {
			s.poolChanged(id)
		}
	}
	idle, err := db.ListExecutorPoolRunners("", statedb.PoolRunnerIdle)
	if err == nil {
		for _, r := range idle {
			if !r.EnrolledAt.IsZero() && now.Sub(r.EnrolledAt) > poolRunnerMaxIdle {
				s.retirePoolRunnerIf(r.ExecutorID, fmt.Sprintf("idle for longer than %s", poolRunnerMaxIdle),
					statedb.PoolRunnerIdle)
			}
		}
	}
	s.reclaimStuckPoolRuns(store, now)
	s.retireFinishedPoolRunners(store, now)
	if _, err := db.PrunePoolQueue(now.Add(-poolQueueRetention)); err != nil && !s.poolsClosed() {
		fmt.Fprintf(os.Stderr, "ui: prune executor pool rows: %v\n", err)
	}
}

// poolsClosed reports whether Shutdown closed the pool store.
func (s *Server) poolsClosed() bool {
	s.pools.mu.Lock()
	defer s.pools.mu.Unlock()
	return s.pools.closed
}

// poolStartDeadline is how long a queued run may stay "assigned" — handed to
// a runner whose member is starting it — before the janitor decides the
// start was lost. A start includes the runner fetching the workspace, so this
// is generous; a member that died is noticed at once instead.
var poolStartDeadline = 20 * time.Minute

// reclaimStuckPoolRuns finishes hand-overs nobody will finish: a run assigned
// to a runner by a member that died, or that has been starting for longer
// than poolStartDeadline. If the run did start — its runner has a session —
// it is recorded dispatched and left to the run's own settlement; otherwise
// it goes back to the queue (or fails, past MaxRunAttempts), and the runner,
// which may hold a half-started workload, is retired.
func (s *Server) reclaimStuckPoolRuns(store *executorpool.Store, now time.Time) {
	db := store.DB()
	assigned, err := db.ListPoolQueue("", statedb.PoolQueueAssigned)
	if err != nil {
		return
	}
	for _, q := range assigned {
		if s.poolMemberAlive(q.Member) && now.Sub(q.UpdatedAt) < poolStartDeadline {
			continue
		}
		if q.ExecutorID != "" {
			if sessions, err := db.ListExecutorSessions(q.ExecutorID, false); err == nil && len(sessions) > 0 {
				if moved, _ := db.MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
					statedb.PoolQueueDispatched, "", now); moved {
					store.AuditQueue(q, "dispatched", "system", "its runner's session was found after its member went away")
					s.poolChanged(q.PoolID)
				}
				continue
			}
		}
		reason := "the hub member starting it went away before it started"
		if s.poolMemberAlive(q.Member) {
			reason = fmt.Sprintf("it was not started within %s", poolStartDeadline)
		}
		if q.Attempts >= executorpool.MaxRunAttempts {
			if moved, _ := db.MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
				statedb.PoolQueueFailed, reason, now); moved {
				s.settleClosedPoolRun(q, "failed", reason, "system")
			}
		} else if moved, _ := db.MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned},
			statedb.PoolQueueWaiting, reason+"; queued again", now); moved {
			store.AuditQueue(q, "requeued", "system", reason)
		}
		if q.ExecutorID != "" {
			s.retirePoolRunnerIf(q.ExecutorID, "its run could not be started on it", statedb.PoolRunnerBusy)
		}
		s.poolChanged(q.PoolID)
	}
}

// retireFinishedPoolRunners retires busy runners whose run is over but that
// nobody retired — the member that settled the run died before it could:
// a runner busy for a while whose queued run left the queue, with no session
// still running on it.
func (s *Server) retireFinishedPoolRunners(store *executorpool.Store, now time.Time) {
	db := store.DB()
	busy, err := db.ListExecutorPoolRunners("", statedb.PoolRunnerBusy)
	if err != nil {
		return
	}
	for _, r := range busy {
		if r.ExecutorID == "" || r.BusyAt.IsZero() || now.Sub(r.BusyAt) < poolStartDeadline {
			continue
		}
		if q, err := db.GetPoolQueueEntry(r.QueueID); err == nil && q.Open() {
			continue // still being handed over: reclaimStuckPoolRuns' to decide
		}
		if n, err := db.CountRunningExecutorSessions(r.ExecutorID); err != nil || n > 0 {
			continue
		}
		s.retirePoolRunnerIf(r.ExecutorID, "its run settled", statedb.PoolRunnerBusy)
	}
}

// poolMemberAlive reports whether the hub member id still serves this control
// plane. A standalone hub is the only member there is: a row naming another
// is a previous process's.
func (s *Server) poolMemberAlive(id string) bool {
	if n := s.clusterNode(); n != nil {
		return n.IsAlive(id)
	}
	return id == s.hubInstanceID()
}

// poolOfProject returns the pool workDir is bound to, from the shared
// database; ok is false for a project bound to no pool.
func (s *Server) poolOfProject(workDir string) (poolID string, ok bool) {
	store, err := s.poolStore()
	if err != nil {
		return "", false
	}
	id, found, err := store.DB().ProjectExecutor(policyProjectPath(workDir))
	if err != nil || !found {
		return "", false
	}
	return executor.PoolOf(id)
}

// poolRefusal renders why a dispatch that is not a queued run cannot go to a
// pool-bound project's pool, as jsonWorkloadErr shows it.
func poolCapacityBody(e *executor.PoolCapacityError) map[string]any {
	return map[string]any{
		"error": e.Error(),
		"code":  "waiting_for_pool_capacity",
		"pool":  e.PoolID,
		"remediation": "this project runs on an executor pool, whose runners take queued runs only; start a run " +
			"to queue one, or bind the project to an executor to use this action",
	}
}

// marshalSlot encodes a held concurrency slot for its queue row.
func marshalSlot(h *heldSlot) string {
	if h == nil {
		return ""
	}
	b, err := json.Marshal(h.slot)
	if err != nil {
		return ""
	}
	return string(b)
}

// slotFromRow is the concurrency slot a queue row holds, as one this member
// may give back or hand to the run; nil for none.
func (s *Server) slotFromRow(raw string) *heldSlot {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var slot runQuotaSlot
	if err := json.Unmarshal([]byte(raw), &slot); err != nil || slot.Identity == "" || slot.N <= 0 {
		return nil
	}
	return &heldSlot{s: s, slot: slot}
}
