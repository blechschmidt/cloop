package ui

// failover_runs.go makes a failed-over run the project's run (Task 20396).
//
// When the supervisor declares an executor lost it claims the sessions
// stranded on it, settles their tasks (failover_settle.go) and, below the
// failover cap, starts the run again on another executor. Before this file
// the replacement was fire-and-forget: started and watched only for its
// session to close. Nothing streamed its output to a dashboard, nothing
// collected the result of a run sent out as a project seed, nothing settled
// the project when it ended — and the hub went on following the stranded run,
// whose driver could not say it was gone, so the project showed "running"
// for as long as the process lived.
//
// Three rules put that right:
//
//   - The replacement is dispatched the way any run is: through
//     startWorkloadAs, pinned to the executor placement chose. It gets a
//     fresh lease checked against the grants as they stand, a fresh project
//     seed from the plan the failover just settled, the sandbox, firewall,
//     egress and ceilings composed for its executor, and a placement record
//     its orchestrator attributes tasks and task.dispatch rows by. Then it is
//     followed the way handleRun follows a run: live log, owner row,
//     consumeRunOutput, runEnded.
//
//   - The stranded run is retired on the member that followed it: its
//     output stops being followed, its lease and egress session are closed,
//     and its driver is told to give it up (executor.Abandoner) — which for
//     an edge device means it is terminated if the device comes back,
//     instead of resuming beside its replacement.
//
//   - With no replacement — no executor left, the cap reached, a task it was
//     running quarantined, or the replacement refused — the project is
//     settled at once, paused with an executor_lost reason naming the
//     executor, instead of showing "running" until someone presses Stop.
//
// Which member does each part. The supervisor that claims a session runs in
// one process; the run may be followed by another (Task 20354). A replacement
// on an edge agent can only be started by the member holding that agent's
// socket, so it is started — and followed — there (agentOpRedispatch), and
// that member takes the run's owner row over. The member that followed the
// stranded run learns of it by a bus message (invalidateRunLost) and, should
// that be lost, from the session store on its own watcher tick
// (sweepLostRuns): the claim is recorded there whichever process made it.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/state"
)

// ── which Server follows a failover ─────────────────────────────────────────

// The supervisor is process-wide and has no Server to hand its failovers to
// (it is started by bootstrapExecutors, before the Server it serves exists),
// so every Server registers itself here. Weak pointers, because a Server
// built and dropped — every test builds hundreds — must not be kept alive by
// a registry nobody cleans.
var (
	runServersMu sync.Mutex
	runServers   []weak.Pointer[Server]
)

// registerRunServer records s as a hub that can follow a failed-over run.
func registerRunServer(s *Server) {
	if s == nil {
		return
	}
	runServersMu.Lock()
	defer runServersMu.Unlock()
	live := runServers[:0]
	for _, wp := range runServers {
		if v := wp.Value(); v != nil && v != s {
			live = append(live, wp)
		}
	}
	runServers = append(live, weak.Make(s))
}

// unregisterRunServer forgets s, as it shuts down.
func unregisterRunServer(s *Server) {
	runServersMu.Lock()
	defer runServersMu.Unlock()
	live := runServers[:0]
	for _, wp := range runServers {
		if v := wp.Value(); v != nil && v != s {
			live = append(live, wp)
		}
	}
	runServers = live
}

// failoverServer picks the Server in this process that settles a failover of
// the session handleID on executor from, for projectPath on the control plane
// at dir: the one following that run, or else the hub serving dir — the most
// recently built, should there be several. Nil when there is none, which only
// a process that bootstrapped executors without building a Server reaches.
func failoverServer(dir, from, handleID, projectPath string) *Server {
	runServersMu.Lock()
	servers := make([]*Server, 0, len(runServers))
	for _, wp := range runServers {
		if v := wp.Value(); v != nil {
			servers = append(servers, v)
		}
	}
	runServersMu.Unlock()
	for _, s := range servers {
		if run, ok := s.trackedRun(projectPath); ok && run.handleID == handleID && run.ex != nil && run.ex.ID() == from {
			return s
		}
	}
	for i := len(servers) - 1; i >= 0; i-- {
		if samePath(servers[i].WorkDir, dir) {
			return servers[i]
		}
	}
	return nil
}

// samePath is sameDir without its empty-path leniency: both must name the
// same directory.
func samePath(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	return sameDir(a, b)
}

// ── starting and following the replacement ──────────────────────────────────

// errProjectRunningAgain refuses a replacement for a project another run is
// already executing — started by a person, or by another member, while the
// stranded run was being failed over. Starting it would put two harnesses on
// one plan.
var errProjectRunningAgain = errors.New("the project is running again")

// redispatchArgs returns the arguments a claimed session's run is started
// again with, after the hub's own binary.
//
// Only a run is ever re-dispatched: every dispatch that records a session is
// a `cloop run`, and the session row is read back from a database. A row that
// asks for anything else — or for a flag a run is never dispatched with — is
// refused rather than started.
func redispatchArgs(spec executor.Spec) ([]string, error) {
	if len(spec.Argv) < 2 || spec.Argv[1] != "run" {
		return nil, fmt.Errorf("failover: the recorded workload is %q, not a run; only a run is re-dispatched",
			strings.Join(spec.Argv, " "))
	}
	args := []string{"run"}
	for _, a := range spec.Argv[2:] {
		switch a {
		case "--pm":
			args = append(args, a)
		default:
			return nil, fmt.Errorf("failover: the recorded run carries %q, which no dispatch passes; not re-dispatched", a)
		}
	}
	return args, nil
}

// startReplacement starts a claimed session's run again on ev.To, as the
// project's run, and follows it here. It is what the failover handler calls
// when the replacement can be started from this process, and what
// agentOpRedispatch calls on the member holding the replacement agent's
// socket.
func (s *Server) startReplacement(ctx context.Context, dir string, ev executor.FailoverEvent) error {
	if s == nil {
		return fmt.Errorf("failover: no hub server in this process follows runs, so session %s is not re-dispatched", ev.Session.ID)
	}
	// The claim's record decides (Task 20391), on this path too: an event
	// routed from another member is re-checked against the store here.
	if err := requireRequeued(dir, ev.Session.ID); err != nil {
		return err
	}
	if err := ev.Session.Spec.Validate(); err != nil {
		// A session with no recorded spec cannot be re-dispatched. Its tasks
		// are already back to pending, so the run is recoverable by hand.
		return fmt.Errorf("failover: session %s has no re-dispatchable spec: %w", ev.Session.ID, err)
	}
	args, err := redispatchArgs(ev.Session.Spec)
	if err != nil {
		return err
	}
	projectPath := executorstore.FailoverProjectPath(ev.Session)
	// A project removed from the hub since its run started is not brought
	// back by a failover, and a member is not steered into dispatching in a
	// directory that is not one of its projects.
	if !hasProjectDB(projectPath) || !s.isRegisteredProject(projectPath) {
		return fmt.Errorf("failover: session %s belongs to %s, which this hub no longer serves", ev.Session.ID, projectPath)
	}
	target, err := executor.Get(ev.To)
	if err != nil {
		return fmt.Errorf("failover: replacement executor %s: %w", ev.To, err)
	}
	// Placement already passes over a restricted executor; this is the
	// dispatch path's own copy of the rule, for an event routed from another
	// member or an access list added since.
	if !failoverPlaceable(target) {
		return fmt.Errorf("failover: replacement executor %s is restricted to an access list, which a failover "+
			"cannot check against the person who started the run", ev.To)
	}
	if other, ok := s.otherLiveRun(projectPath, ev.From, ev.Session.HandleID); ok {
		return fmt.Errorf("failover: %w (%s), so session %s is not re-dispatched", errProjectRunningAgain, other, ev.Session.ID)
	}

	labels := map[string]string{"handler": "failover"}
	if name := strings.TrimSpace(ev.Session.Spec.Labels["project_name"]); name != "" {
		labels["project_name"] = name
	}
	// Billed and credentialed as the automatic resume is (autoresume.go): a
	// machine restarting a run someone else started acts for whoever started
	// it, as the control plane recorded at that dispatch.
	payer := s.runIdentity(nil, projectPath)
	s.openSpendCursor(projectPath, payer)
	ex, handle, err := startWorkloadAs(nil, newHarnessClearance(projectPath, s.harnessWhoForResume(projectPath), ""), payer,
		projectPath, append([]string{s.selfExe()}, args...), labels, asReplacementFor(target, ev.Session))
	if err != nil {
		return fmt.Errorf("failover: start the replacement on %s: %w", ev.To, err)
	}
	if err := s.followReplacement(projectPath, ev, ex, handle); err != nil {
		return err
	}
	journalFailedOver(projectPath, ev, ex.ID())
	return nil
}

// failoverPlaceable reports whether a failover may move a run onto ex.
//
// Not onto an executor restricted to an access list (Task 20310): an audience
// is checked against the claims of the person starting a run, and a failover
// starts it on nobody's behalf — the claims are not there to check, and a
// recorded identity is not the claims. So a restricted executor is never a
// failover target, and an access list that cannot be read counts as one,
// exactly as admitExecutorAudience fails closed for a person.
func failoverPlaceable(ex executor.Executor) bool {
	if ex == nil {
		return false
	}
	entries, err := executorAudience(ex.ID())
	return err == nil && len(entries) == 0
}

// otherLiveRun reports a run executing projectPath that is not the stranded
// one (executor from, handle), and describes it.
func (s *Server) otherLiveRun(projectPath, from, handleID string) (string, bool) {
	if run, ok := s.trackedRun(projectPath); ok && !(run.handleID == handleID && run.ex != nil && run.ex.ID() == from) && !run.lost {
		return "this hub member follows another run of it", true
	}
	if o, meta, found := s.clusterRunOwner(projectPath); found && !o.Self &&
		hubcluster.RunClaimLive(o, time.Now(), orphanRunGrace) && meta.Handle != handleID && !meta.Dispatching {
		return "hub member " + o.InstanceID + " follows another run of it", true
	}
	return "", false
}

// followReplacement makes the replacement this project's run on this member:
// the stranded run swapped out for it, the owner row taken over, then the
// same following handleRun gives a run it dispatched.
//
// The swap is one critical section, so the project is never without a run
// here in between: the watcher's tick, seeing neither, would settle the
// project as a run that died. A conflict — this member follows some other
// run of the project, started while the stranded one was being failed over —
// withdraws the replacement instead.
func (s *Server) followReplacement(workDir string, ev executor.FailoverEvent, ex executor.Executor, handle executor.Handle) error {
	streamCtx, cancelStream := context.WithCancel(context.Background())
	old, outcome := s.swapInReplacement(workDir, ev.From, ev.Session.HandleID, ex, handle.ID, cancelStream)
	if outcome == swapConflict {
		cancelStream()
		abandonWorkload(ex, handle.ID, "withdrawn: another run of the project started while it was being failed over")
		return fmt.Errorf("failover: %w (this hub member follows another run of it), so the replacement on %s was withdrawn",
			errProjectRunningAgain, ex.ID())
	}
	reason := fmt.Sprintf("its executor %s stopped answering; the run failed over to %s", ev.From, ex.ID())
	if outcome == swapReplacedLost {
		s.letGoOfLostRun(old, reason)
	}

	prev, hadOwner := s.takeOverRunOwner(workDir, ex, handle.ID)
	// The stranded run on another live member: told so, and found in the
	// session store on its next sweep should the message be lost.
	if outcome != swapReplacedLost && hadOwner && !prev.Self && prev.Alive && prev.InstanceID != "" {
		s.noticeRunLost(prev.InstanceID, runLossNotice{
			Project: workDir, Executor: ev.From, Handle: ev.Session.HandleID, To: ex.ID(),
		})
	}

	// Followed as handleRun follows a run, except that the live log keeps
	// what the stranded run printed: the replacement continues it, and a
	// reader should see where one ended and the other began.
	s.liveLogSetRunning(workDir, true)
	s.broadcastLog(workDir, fmt.Sprintf("\n[cloop] executor %s stopped answering; the run failed over to %s (attempt %d)\n\n",
		ev.From, ex.ID(), ev.Session.Attempt+1))
	s.recordRunDispatch(workDir, "failover", ex, handle.ID)
	s.broadcastRunState(workDir, true, true)
	s.publishRunState(workDir, true)

	lines, err := ex.Stream(streamCtx, handle.ID)
	if err != nil {
		// Unobservable from the start: settle it now rather than show a run
		// nothing will ever say has ended (startAutoResumeRun does the same).
		fmt.Fprintf(os.Stderr, "ui: cannot stream the replacement run %s on %s: %v\n", handle.ID, ex.ID(), err)
		cancelStream()
		s.liveLogSetRunning(workDir, false)
		s.publishRunState(workDir, false)
		s.runEnded(workDir, ex, handle.ID)
		return nil
	}
	// No concurrency slot to return: like the automatic resume, a failover
	// restarts a run that was admitted when a person started it.
	go s.consumeRunOutput(workDir, ex, handle.ID, lines, nil)
	return nil
}

// swapOutcome is what swapInReplacement found tracked for the project.
type swapOutcome int

const (
	// swapFresh: nothing was tracked here; the replacement is now.
	swapFresh swapOutcome = iota
	// swapReplacedLost: the stranded run was tracked here and the
	// replacement took its place.
	swapReplacedLost
	// swapConflict: another live run is tracked here; nothing changed.
	swapConflict
)

// swapInReplacement tracks the replacement for workDir in place of the
// stranded run (executor lostEx, handle lostHandle), in one critical section,
// and returns what was tracked before. The stranded run is marked handed over
// in the same section, so its consumer — should its stream end — leaves it to
// the failover rather than settling the project under its replacement.
func (s *Server) swapInReplacement(workDir, lostEx, lostHandle string, ex executor.Executor, handleID string, cancel context.CancelFunc) (dispatchedRun, swapOutcome) {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	if s.runHandles == nil {
		s.runHandles = make(map[string]dispatchedRun)
	}
	old, had := s.runHandles[workDir]
	outcome := swapFresh
	switch {
	case had && old.handleID == lostHandle && old.ex != nil && old.ex.ID() == lostEx:
		outcome = swapReplacedLost
		s.markHandedOverLocked(old.handleID)
	case had && !old.lost:
		return old, swapConflict
	}
	s.runHandles[workDir] = dispatchedRun{ex: ex, handleID: handleID, cancel: cancel, tracked: time.Now()}
	return old, outcome
}

// markHandedOverLocked records that handleID's run is settled by someone else,
// for its consumer's takeHandedOver. The caller holds runHandleMu.
func (s *Server) markHandedOverLocked(handleID string) {
	if s.handedOverRuns == nil {
		s.handedOverRuns = make(map[string]bool)
	}
	s.handedOverRuns[handleID] = true
}

// letGoOfLostRun gives up a stranded run this member followed: its egress
// session and leases are closed — a workload out of reach keeps no credential
// — its driver is told to abandon it, and this member stops reading its
// output. Counted as a run that failed: whatever it did on the lost executor,
// nothing shows it succeeded.
func (s *Server) letGoOfLostRun(run dispatchedRun, reason string) {
	if run.ex == nil || run.handleID == "" {
		return
	}
	if reason == "" {
		reason = "its executor stopped answering and the run was failed over"
	}
	closeRunEgress(run.handleID, reason)
	closeRunLeases(run.ex.ID(), run.handleID)
	abandonWorkload(run.ex, run.handleID, reason)
	if run.cancel != nil {
		run.cancel()
	}
	// A seeded run's result would be merged when it ends; this one is not
	// going to be collected — its tasks were settled by the failover, and a
	// copy of the project it took is out of reach.
	_, _ = takeSeededDispatch(run.ex, run.handleID)
	countRunSettled(run.ex, executor.Status{State: executor.StateFailed}, nil, false, run.tracked)
	s.log().Info("executor", 0, "stopped following a run whose executor was lost",
		map[string]interface{}{"executor": run.ex.ID(), "handle": run.handleID, "reason": reason})
}

// takeOverRunOwner makes this member the owner of workDir's run, from
// whoever held the row — the member that followed the stranded run, alive or
// not — and returns the row it replaced, if there was one. The full meta is
// written by recordRunDispatch right after.
func (s *Server) takeOverRunOwner(workDir string, ex executor.Executor, handleID string) (hubcluster.Owner, bool) {
	n := s.clusterNode()
	if n == nil {
		return hubcluster.Owner{}, false
	}
	meta := runOwnerMeta{Executor: ex.ID(), Handle: handleID, Handler: "failover", Started: time.Now().UTC()}
	for attempt := 0; attempt < 3; attempt++ {
		o, found, err := n.Lookup(ownerRun, workDir)
		if err != nil {
			s.log().Warn("cluster", 0, "could not read the run's owner row for its replacement",
				map[string]interface{}{"project": workDir, "error": err.Error()})
			return hubcluster.Owner{}, false
		}
		if !found || o.Self {
			if _, _, err := n.Claim(ownerRun, workDir, meta); err != nil {
				s.log().Warn("cluster", 0, "could not record the replacement run's owner",
					map[string]interface{}{"project": workDir, "error": err.Error()})
			}
			return o, found
		}
		// Taken from the exact row read, so a member that changed it in the
		// meantime — released it, or started something — is re-read rather
		// than overwritten.
		if ok, err := n.Adopt(o, meta); err == nil && ok {
			return o, true
		}
	}
	s.log().Warn("cluster", 0, "the run's owner row kept changing; the replacement is followed without it",
		map[string]interface{}{"project": workDir})
	return hubcluster.Owner{}, false
}

// asReplacementFor pins a dispatch to target, the executor the failover
// placed the run on, and records its session as the next attempt of
// replaces, the session it continues — which is what the failover cap
// counts (Task 20391).
func asReplacementFor(target executor.Executor, replaces executor.Session) dispatchOption {
	return func(o *dispatchOptions) {
		o.target = target
		r := replaces
		o.replaces = &r
	}
}

// openReplacementSession records a replacement's session as the next attempt
// of prev's chain. Best-effort like openSessionFor, but loudly: a replacement
// whose session is not recorded is one the cap no longer counts, and one a
// later failover cannot find.
func openReplacementSession(dir string, ex executor.Executor, handle executor.Handle, spec executor.Spec, prev executor.Session) string {
	if dir == "" || ex == nil {
		return ""
	}
	sched, db, err := newScheduler(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: record the replacement of session %s: %v\n", prev.ID, err)
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
	next := executor.Session{
		ID:          sessionID,
		ExecutorID:  ex.ID(),
		HandleID:    handle.ID,
		ProjectPath: spec.WorkDir,
		TaskID:      prev.TaskID,
		ClaimToken:  token,
		Attempt:     prev.Attempt + 1,
		StartedAt:   handle.StartedAt,
		Spec:        spec,
	}
	if err := sched.OpenRequeuedSession(next, prev.ID); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record the replacement of session %s: %v\n", prev.ID, err)
		return ""
	}
	return sessionID
}

// ── the stranded run ────────────────────────────────────────────────────────

// retireLostRun stops following the run on executorID/handleID, whose session
// the failover claim took, if this member follows it — and reports whether
// it did.
//
// The run is given up rather than settled: its tasks were settled by the
// failover, and its output stream may never end. It is marked lost and handed
// over in one critical section (its consumer, should the stream end after
// all, leaves it alone), then let go of (letGoOfLostRun). With settle,
// nothing replaced it: the project is settled here, with verdict, while the
// run is still tracked, so the watcher's tick cannot settle it first with a
// verdict that knows nothing. Without, the replacement is followed elsewhere
// and owns the run's owner row.
func (s *Server) retireLostRun(workDir, executorID, handleID string, verdict runVerdict, settle bool) bool {
	s.runHandleMu.Lock()
	run, ok := s.runHandles[workDir]
	if !ok || run.lost || run.handleID != handleID || run.ex == nil || run.ex.ID() != executorID {
		s.runHandleMu.Unlock()
		return false
	}
	run.lost = true
	run.handedOver = true
	s.runHandles[workDir] = run
	s.markHandedOverLocked(handleID)
	s.runHandleMu.Unlock()

	s.letGoOfLostRun(run, verdict.Detail)
	if settle {
		s.reconcileDeadRun(workDir, verdict)
	}
	if s.untrackLostRun(workDir, handleID) && settle {
		s.releaseRunClaim(workDir)
	}
	// This member is no longer streaming it. A run another member relays
	// here keeps its flag: the replacement's member may have announced
	// itself before this retirement reached us.
	s.liveLogStopLocal(workDir)
	if settle {
		s.broadcastRunState(workDir, false, true)
		s.publishRunState(workDir, false)
		s.refreshProjectStatuses()
		s.broadcastProjectsUpdate()
	}
	return true
}

// untrackLostRun forgets workDir's run if it is still the lost one, and
// reports whether it was: a run started in the meantime is not forgotten in
// its place.
func (s *Server) untrackLostRun(workDir, handleID string) bool {
	s.runHandleMu.Lock()
	defer s.runHandleMu.Unlock()
	if cur, ok := s.runHandles[workDir]; ok && cur.handleID == handleID && cur.lost {
		delete(s.runHandles, workDir)
		return true
	}
	return false
}

// closeRunLeases closes the leases this process holds for a workload: its
// run's, and the workspace lease its driver kept. Idempotent, like Close.
func closeRunLeases(executorID, handleID string) {
	ids := liveLeases.forHandle(executorID, handleID)
	if ws := liveLeases.workspaceForHandle(executorID, handleID); ws != nil {
		ids = append(ids, ws.Lease)
	}
	for _, id := range ids {
		if sl := liveLeases.get(id); sl != nil {
			sl.Close()
		}
	}
}

// abandonTimeout bounds asking a lost executor to give a workload up: it is
// lost because it stopped answering.
const abandonTimeout = 5 * time.Second

// abandonWorkload tells ex to give the workload up (executor.Abandoner), or,
// for a driver that cannot, asks it to kill the workload — all the hub can do
// for one it cannot reach. Best-effort: the executor stopped answering.
func abandonWorkload(ex executor.Executor, handleID, reason string) {
	if ex == nil || handleID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), abandonTimeout)
	defer cancel()
	if a, ok := ex.(executor.Abandoner); ok {
		if err := a.Abandon(ctx, handleID, reason); err != nil {
			fmt.Fprintf(os.Stderr, "ui: %s could not be told to stop %s (it is given up all the same): %v\n", ex.ID(), handleID, err)
		}
		return
	}
	_ = ex.Signal(ctx, handleID, executor.SignalKill)
}

// ── a loss nothing replaced ─────────────────────────────────────────────────

// lostRunDetail renders why a lost executor's run stopped there, for the
// pause reason: the executor first, the cause after.
func lostRunDetail(ev executor.FailoverEvent, out failoverOutcome, cause error) string {
	switch {
	case ev.Exhausted:
		return exhaustedDetail(ev.From, redispatchCount(ev.Session))
	case len(out.Quarantined) > 0:
		return fmt.Sprintf("executor %s stopped answering; task %s is quarantined as a suspected node killer",
			ev.From, joinTaskIDs(out.Quarantined))
	case ev.To == "":
		return fmt.Sprintf("executor %s stopped answering and no executor could take the run", ev.From)
	case errors.Is(cause, errProjectRunningAgain):
		return fmt.Sprintf("executor %s stopped answering; another run of the project took over", ev.From)
	default:
		return fmt.Sprintf("executor %s stopped answering and the replacement on %s could not start", ev.From, ev.To)
	}
}

// exhaustedDetail is the pause reason's detail for a run whose executor was
// lost after n re-dispatches, the most executors.failover.max_attempts allows.
func exhaustedDetail(executorID string, n int) string {
	switch n {
	case 0:
		return fmt.Sprintf("executor %s stopped answering; executors.failover.max_attempts allows no re-dispatch", executorID)
	case 1:
		return fmt.Sprintf("executor %s stopped answering; failover gave up after 1 re-dispatch (executors.failover.max_attempts)", executorID)
	}
	return fmt.Sprintf("executor %s stopped answering; failover gave up after %d re-dispatches (executors.failover.max_attempts)", executorID, n)
}

// redispatchCount is how many times the session's run was started again.
func redispatchCount(sess executor.Session) int {
	if sess.Attempt <= 1 {
		return 0
	}
	return sess.Attempt - 1
}

func joinTaskIDs(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	return strings.Join(parts, ", ")
}

// failoverStopCause says why a claimed session is not re-dispatched, or nil
// when it may be.
//
// Past the cap, or with nowhere to go, the claim and placement already said
// so. A task this failover quarantined stops the run too: two executors have
// gone down under it, and carrying the run to a third — whose gate would hold
// that task anyway — risks another node on the strength of attribution a
// device itself reported, to run work a person can restart in one click.
func failoverStopCause(ev executor.FailoverEvent, out failoverOutcome) error {
	switch {
	case ev.Exhausted:
		return errors.New(exhaustedReason(ev, out.Lost))
	case ev.To == "":
		if ev.Err != nil {
			return fmt.Errorf("no executor could take its run: %w", ev.Err)
		}
		return errors.New("no executor could take its run")
	case len(out.Quarantined) > 0:
		return fmt.Errorf("failover: not re-dispatched: task %s was quarantined as a suspected node killer",
			joinTaskIDs(out.Quarantined))
	}
	return nil
}

// settleLostRun ends a run the failover did not replace (Task 20396): the
// member following it gives it up and settles the project paused with an
// executor_lost reason, and the journal says which executor was lost and
// why the run stopped there. s is this process's hub, which may be nil.
func settleLostRun(s *Server, dir string, ev executor.FailoverEvent, out failoverOutcome, cause error) {
	projectPath := executorstore.FailoverProjectPath(ev.Session)
	if projectPath == "" {
		return
	}
	// A replacement this process could not see start — routed to another
	// member whose answer was lost — is recorded in the store. Then the run
	// was not lost, only moved, and the member that started it retired the
	// stranded one.
	if loss, ok := lossOfHandle(dir, ev.From, ev.Session.HandleID); ok && loss.Replaced() {
		return
	}
	verdict := runVerdict{Detail: lostRunDetail(ev, out, cause), Lost: true}
	running := errors.Is(cause, errProjectRunningAgain)
	journalLost(projectPath, ev, cause, running)
	if s == nil {
		return
	}
	if s.retireLostRun(projectPath, ev.From, ev.Session.HandleID, verdict, !running) {
		return
	}
	// Not followed here. The member that holds the run's owner row follows
	// it, if it is alive; otherwise nobody does, and the project is settled
	// here.
	if o, meta, found := s.clusterRunOwner(projectPath); found && !o.Self {
		if o.Alive {
			s.noticeRunLost(o.InstanceID, runLossNotice{
				Project: projectPath, Executor: ev.From, Handle: ev.Session.HandleID,
				Settle: !running, Detail: verdict.Detail,
			})
			return
		}
		if meta.Handle == ev.Session.HandleID {
			// A dead member's claim on the run it can no longer follow.
			// Dropped, so the orphan grace does not keep the project
			// "running" for a run that is gone.
			if n := s.clusterNode(); n != nil {
				_, _ = n.Drop(o)
			}
		}
	}
	if !running {
		s.reconcileDeadRun(projectPath, verdict)
	}
}

// ── the bus: telling the member that followed the stranded run ─────────────

// invalidateRunLost tells a member that the run it follows was taken off its
// executor by a failover (Task 20396).
const invalidateRunLost = "run_lost"

// runLossNotice is invalidateRunLost's payload.
type runLossNotice struct {
	Project  string `json:"project"`
	Executor string `json:"executor"`
	Handle   string `json:"handle"`
	// To is the replacement's executor, "" when nothing replaced the run.
	To string `json:"to,omitempty"`
	// Settle asks the member to settle the project: no replacement started.
	Settle bool `json:"settle,omitempty"`
	// Detail is the pause reason's detail when settling.
	Detail string `json:"detail,omitempty"`
}

// noticeRunLost sends a runLossNotice to one member.
func (s *Server) noticeRunLost(instanceID string, p runLossNotice) {
	n := s.clusterNode()
	if n == nil || instanceID == "" {
		return
	}
	n.PublishTo(instanceID, busTopicInvalidate, invalidateRunLost, p)
}

// applyRunLossNotice acts on a runLossNotice another member sent. The notice
// says what to look at; the session store says what is true: a run whose
// session the claim did not take is left alone, and a run that was replaced
// is never settled here, whatever the notice asks.
func (s *Server) applyRunLossNotice(p runLossNotice) {
	if p.Project == "" || p.Executor == "" || p.Handle == "" {
		return
	}
	loss, ok := lossOfHandle(controlPlaneDir(), p.Executor, p.Handle)
	if !ok || !loss.Claimed() {
		return
	}
	verdict := runVerdict{Detail: p.Detail, Lost: true}
	switch {
	case verdict.Detail != "":
	case p.To != "":
		verdict.Detail = fmt.Sprintf("its executor %s stopped answering; the run failed over to %s", p.Executor, p.To)
	default:
		verdict.Detail = fmt.Sprintf("executor %s stopped answering", p.Executor)
	}
	s.retireLostRun(p.Project, p.Executor, p.Handle, verdict, p.Settle && !loss.Replaced())
}

// ── the session store: the fallback that needs no message ──────────────────

// failoverReplacementWindow is how long after a claim a requeued session with
// no replacement yet is taken to have one on the way. A replacement is
// started by whichever process claimed the session, which may be another
// member, and starting one can take as long as pulling an image; within this
// window the stranded run still counts as executing, so nobody starts a
// second run beside a replacement about to begin. Past it — the failover
// decided against one, and the message saying so was lost — the run is given
// up. A variable so a test can shorten it.
var failoverReplacementWindow = 5 * time.Minute

// lostRunSweepInterval is how often the watcher checks the runs this member
// follows against the session store.
const lostRunSweepInterval = 10 * time.Second

// lossOfHandle reads what the session store recorded about a workload. ok is
// false when the store could not be read: no answer, which every caller
// treats as "nothing known".
func lossOfHandle(dir, executorID, handleID string) (executorstore.HandleLoss, bool) {
	if dir == "" || executorID == "" || handleID == "" {
		return executorstore.HandleLoss{}, false
	}
	if _, err := os.Stat(state.DBPath(dir)); err != nil {
		// statedb.Open creates and migrates; a liveness question must not
		// bring a control-plane database into existence.
		return executorstore.HandleLoss{}, false
	}
	sched, db, err := newScheduler(dir)
	if err != nil {
		return executorstore.HandleLoss{}, false
	}
	defer db.Close()
	loss, err := sched.LossOfHandle(executorID, handleID)
	if err != nil {
		return executorstore.HandleLoss{}, false
	}
	return loss, true
}

// lostRunState is how the session store reads for a run this member follows.
type lostRunState int

const (
	// runNotLost: the claim has not taken it (or nothing is known).
	runNotLost lostRunState = iota
	// runReplacementPending: claimed and requeued, no replacement yet, within
	// failoverReplacementWindow — one may still be starting.
	runReplacementPending
	// runReplaced: a failover started a replacement.
	runReplaced
	// runLostForGood: exhausted, or requeued long enough ago that no
	// replacement is coming.
	runLostForGood
)

// classifyLoss reads a HandleLoss at now.
func classifyLoss(loss executorstore.HandleLoss, now time.Time) lostRunState {
	switch {
	case !loss.Claimed():
		return runNotLost
	case loss.Replaced():
		return runReplaced
	case loss.Exhausted():
		return runLostForGood
	case !loss.ClaimedAt.IsZero() && now.Sub(loss.ClaimedAt) < failoverReplacementWindow:
		return runReplacementPending
	default:
		return runLostForGood
	}
}

// runLossState is classifyLoss for a run this member follows.
func (s *Server) runLossState(run dispatchedRun) lostRunState {
	if run.lost {
		return runLostForGood
	}
	if run.ex == nil || run.handleID == "" {
		return runNotLost
	}
	loss, ok := lossOfHandle(controlPlaneDir(), run.ex.ID(), run.handleID)
	if !ok {
		return runNotLost
	}
	return classifyLoss(loss, time.Now())
}

// maybeSweepLostRuns runs sweepLostRuns at most every lostRunSweepInterval.
func (s *Server) maybeSweepLostRuns(now time.Time) {
	s.clusterMu.Lock()
	due := now.Sub(s.lastLostRunSweep) >= lostRunSweepInterval
	if due {
		s.lastLostRunSweep = now
	}
	s.clusterMu.Unlock()
	if due {
		s.sweepLostRuns(now)
	}
}

// sweepLostRuns retires the runs this member follows whose sessions a
// failover claim took, by what the session store says — the path that needs
// no message from the process that made the claim.
func (s *Server) sweepLostRuns(now time.Time) {
	defer recoverGoroutine("sweep lost runs")
	s.runHandleMu.Lock()
	runs := make(map[string]dispatchedRun, len(s.runHandles))
	for workDir, run := range s.runHandles {
		if !run.lost && !run.handedOver {
			runs[workDir] = run
		}
	}
	s.runHandleMu.Unlock()
	for workDir, run := range runs {
		if run.ex == nil {
			continue
		}
		loss, ok := lossOfHandle(controlPlaneDir(), run.ex.ID(), run.handleID)
		if !ok {
			continue
		}
		switch classifyLoss(loss, now) {
		case runReplaced:
			// The replacement's member takes the owner row over right after
			// it records the replacement's session. Until it has, this member
			// still holds the row, and letting go here would leave the
			// project with no run anyone counts — the watcher would settle it
			// under its replacement. Unless that takeover never comes.
			if s.ownsRun(workDir) && now.Sub(loss.ClaimedAt) < failoverReplacementWindow {
				continue
			}
			s.retireLostRun(workDir, run.ex.ID(), run.handleID, runVerdict{
				Detail: fmt.Sprintf("its executor %s stopped answering; the run failed over to %s",
					run.ex.ID(), loss.SuccessorExecutor),
				Lost: true,
			}, false)
		case runLostForGood:
			detail := fmt.Sprintf("executor %s stopped answering and nothing replaced the run", run.ex.ID())
			if loss.Exhausted() {
				detail = exhaustedDetail(run.ex.ID(), max(loss.Attempt-1, 0))
			}
			s.retireLostRun(workDir, run.ex.ID(), run.handleID, runVerdict{Detail: detail, Lost: true}, true)
		}
	}
}

// ownsRun reports whether this member holds workDir's run owner row. A
// standalone hub — no cluster — always does.
func (s *Server) ownsRun(workDir string) bool {
	n := s.clusterNode()
	if n == nil {
		return true
	}
	return n.Owns(ownerRun, workDir)
}

// ── the journal ─────────────────────────────────────────────────────────────

// failoverDetails is the details a run-level failover row carries.
func failoverDetails(ev executor.FailoverEvent) map[string]any {
	d := map[string]any{
		"executor":     ev.From,
		"session_id":   ev.Session.ID,
		"attempt":      ev.Session.Attempt,
		"max_attempts": ev.MaxAttempts,
		"failover":     true,
	}
	if run := ev.Session.Spec.Labels[executor.LabelRunID]; run != "" {
		d["run_id"] = run
	}
	return d
}

// journalFailedOver records that the run continues on another executor.
func journalFailedOver(projectPath string, ev executor.FailoverEvent, to string) {
	d := failoverDetails(ev)
	d["to"] = to
	state.LogEventDetails(projectPath, state.EventRow{
		Type: state.EventFailover,
		Step: state.NoStep,
		Message: fmt.Sprintf("Run failed over from executor %s to %s: %s stopped answering, and the run continues on %s.",
			ev.From, to, ev.From, to),
	}, d)
}

// journalLost records that the run stopped with its executor, and why.
func journalLost(projectPath string, ev executor.FailoverEvent, cause error, runningAgain bool) {
	why := "it was not re-dispatched"
	if cause != nil {
		why = strings.TrimPrefix(cause.Error(), "failover: ")
	}
	msg := fmt.Sprintf("Executor %s was lost and the run was not re-dispatched: %s. The project is paused; "+
		"bring the executor back or bind the project to another, then press Run.", ev.From, why)
	if runningAgain {
		msg = fmt.Sprintf("Executor %s was lost; its run was not re-dispatched because another run of the project "+
			"is already executing it.", ev.From)
	}
	state.LogEventDetails(projectPath, state.EventRow{
		Type:    state.EventFailover,
		Step:    state.NoStep,
		Message: msg,
	}, failoverDetails(ev))
}
