package ui

// cluster_runs.go: a project's run, when several hub members could have
// started it (Task 20354).
//
// A dispatched run is a process-bound thing. The member that started it holds
// the handle, streams the output, keeps the secret lease alive and settles the
// run when the stream closes; none of that can be shared. What can be shared is
// the fact of it, and this file keeps that fact in hub_owners as
// ('run', project directory), so that every member can answer the questions a
// run raises:
//
//	may I start one?    Only if nobody live owns one. The claim is taken
//	                    *before* dispatch and is a compare-and-swap, so two
//	                    members pressed Start at the same instant produce one
//	                    run and one 409 — not two harnesses racing for the
//	                    same plan.
//
//	is one running?     A member that did not start the run cannot see it in
//	                    its process table or its handle map, and before this
//	                    file it concluded the run was dead: it paused the
//	                    project and reset its in-progress tasks under the live
//	                    run. A live owner row now answers "yes".
//
//	who can stop it?    The owner, so Stop is forwarded there.
//
//	what if the owner   Another member adopts the run from the row's meta —
//	dies, or its agent  the executor and handle to reattach to, and for a
//	moves?              seeded run the provenance its result is merged under.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

// runOwnerMeta is what the member streaming a run records for the others.
type runOwnerMeta struct {
	Executor string `json:"executor,omitempty"`
	Handle   string `json:"handle,omitempty"`
	// Handler is which entry point started the run (run, project-run,
	// auto_resume, new-project), for status output.
	Handler string `json:"handler,omitempty"`
	// Seeded and Provenance describe a run carried out as a seed: its result
	// comes back through the executor and is merged into the hub's copy under
	// this provenance, which an adopting member must have to do the merge.
	Seeded     bool                    `json:"seeded,omitempty"`
	Provenance *projectseed.Provenance `json:"provenance,omitempty"`
	// Feature is, for a feature's run on an isolating executor, what its
	// returned work is landed against (Task 20367).
	Feature *featureReturn `json:"feature,omitempty"`
	Started time.Time      `json:"started,omitzero"`
	// RunClaimMeta carries Dispatching, which every observer of the claim
	// judges by — members and, since Task 20374, processes that are not
	// members at all. It is embedded rather than restated so the field is
	// written here under the name pkg/hubcluster reads.
	hubcluster.RunClaimMeta
}

// orphanRunGrace is how long a run whose owner died keeps its project marked
// running while no member has adopted it; see hubcluster.DefaultOrphanRunGrace.
// A variable so a test can shorten it.
var orphanRunGrace = hubcluster.DefaultOrphanRunGrace

// errRunOwnedElsewhere is returned by claimRun when a live member owns the run.
var errRunOwnedElsewhere = errors.New("a run for this project is in progress on another hub member")

// claimRun takes the cluster-wide right to start workDir's run. It returns
// errRunOwnedElsewhere, carrying the owner, when a live member already holds
// it. A standalone hub always succeeds.
func (s *Server) claimRun(workDir, handler string) (hubcluster.Owner, error) {
	n := s.clusterNode()
	if n == nil || workDir == "" {
		return hubcluster.Owner{}, nil
	}
	o, ok, err := n.Claim(ownerRun, workDir, runOwnerMeta{
		Handler: handler, Started: time.Now().UTC(),
		RunClaimMeta: hubcluster.RunClaimMeta{Dispatching: true},
	})
	if err != nil {
		// A claim that could not be read or written is not evidence of a
		// conflict. Refusing would make a database hiccup an outage for Start;
		// proceeding costs, at worst, the race this claim exists to close —
		// which is where every hub was before it existed.
		s.log().Warn("cluster", 0, "could not claim the run; starting without the cluster-wide guard",
			map[string]interface{}{"project": workDir, "error": err.Error()})
		return hubcluster.Owner{}, nil
	}
	if !ok {
		return o, errRunOwnedElsewhere
	}
	return o, nil
}

// writeRunOwnedElsewhere answers a start that lost the claim: 409, as for a
// run this member knows about, naming where the run is.
func writeRunOwnedElsewhere(w http.ResponseWriter, o hubcluster.Owner) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	msg := "a run is already in progress for this project — stop it before starting another"
	body := map[string]interface{}{"error": msg, "running": true}
	if o.InstanceID != "" {
		body["member"] = o.InstanceID
	}
	_ = writeJSONBody(w, body)
}

// recordRunDispatch replaces the dispatching claim with what an adopter needs:
// which executor and handle to reattach to, and for a seeded run the
// provenance its result is merged under.
func (s *Server) recordRunDispatch(workDir, handler string, ex executor.Executor, handleID string) {
	n := s.clusterNode()
	if n == nil || workDir == "" || ex == nil {
		return
	}
	meta := runOwnerMeta{Executor: ex.ID(), Handle: handleID, Handler: handler, Started: time.Now().UTC()}
	if d, ok := peekSeededDispatch(ex, handleID); ok {
		prov := d.prov
		meta.Seeded, meta.Provenance = true, &prov
		meta.Feature = d.feature
	}
	if _, found, _ := n.Lookup(ownerRun, workDir); !found {
		// Standalone-era callers and adoption paths reach here without a
		// prior claim; take one now so the run is visible cluster-wide.
		if _, _, err := n.Claim(ownerRun, workDir, meta); err != nil {
			s.log().Warn("cluster", 0, "could not record the run's owner",
				map[string]interface{}{"project": workDir, "error": err.Error()})
		}
		return
	}
	if ok, err := n.UpdateMeta(ownerRun, workDir, meta); err != nil || !ok {
		s.log().Warn("cluster", 0, "could not record the run's executor for adoption",
			map[string]interface{}{"project": workDir, "still_owner": ok, "error": fmt.Sprint(err)})
	}
}

// releaseRunClaim gives up workDir's run. Fenced on this member, so a member
// whose run was adopted elsewhere releases nothing.
func (s *Server) releaseRunClaim(workDir string) {
	n := s.clusterNode()
	if n == nil || workDir == "" {
		return
	}
	if _, err := n.Release(ownerRun, workDir); err != nil {
		s.log().Warn("cluster", 0, "could not release the run's owner row",
			map[string]interface{}{"project": workDir, "error": err.Error()})
	}
}

// clusterRunOwner returns the owner row for workDir's run.
func (s *Server) clusterRunOwner(workDir string) (hubcluster.Owner, runOwnerMeta, bool) {
	n := s.clusterNode()
	if n == nil || workDir == "" {
		return hubcluster.Owner{}, runOwnerMeta{}, false
	}
	o, found, err := n.Lookup(ownerRun, workDir)
	if err != nil || !found {
		return hubcluster.Owner{}, runOwnerMeta{}, false
	}
	var meta runOwnerMeta
	_ = o.Meta(&meta)
	return o, meta, true
}

// peerRunExecuting reports whether another member is, or may still be,
// running workDir.
//
// A live owner is conclusive. A dead owner fails closed for orphanRunGrace —
// the run may be adopted by the member its agent reconnects to, and repairing
// the project in that window would reset tasks under a run that is about to
// resume. Past the grace, nobody picked it up, and stale-run recovery may do
// its work. The rule is hubcluster.RunClaimLive, which `cloop config validate
// --fix` applies to the same rows from outside the cluster (Task 20374).
func (s *Server) peerRunExecuting(workDir string) bool {
	o, _, found := s.clusterRunOwner(workDir)
	if !found || o.Self {
		return false
	}
	return hubcluster.RunClaimLive(o, time.Now(), orphanRunGrace)
}

// routeRunOwner forwards r to the member running workDir's run, and reports
// whether it did.
func (s *Server) routeRunOwner(w http.ResponseWriter, r *http.Request, workDir string) bool {
	o, _, found := s.clusterRunOwner(workDir)
	if !found || o.Self || !o.Alive {
		return false
	}
	return s.forwardProject(w, r, o.Member, workDir)
}

// ── dispatch routing ────────────────────────────────────────────────────────

// routeDispatch forwards r to the member able to dispatch workDir's workload,
// and reports whether it did.
//
// Only an edge agent pins dispatch to a member: its WebSocket is held by one
// member, and only that member can send it a start frame. Every other driver
// — the host, a container runtime, a Kubernetes API — is reachable from any
// member, so the member that received the request dispatches.
func (s *Server) routeDispatch(w http.ResponseWriter, r *http.Request, workDir string) bool {
	n := s.clusterNode()
	if n == nil {
		return false
	}
	if _, forwarded := peerCallFrom(r); forwarded {
		return false
	}
	m, ok := s.dispatchMember(workDir)
	if !ok {
		return false
	}
	return s.forwardProject(w, r, m, workDir)
}

// routeProjectAffinity forwards r to the member that must serve it: the one
// able to dispatch workDir's workload when that is an edge agent, else the
// member holding (or now claiming) the in-memory conversation kind names —
// a suggest job, a chat history. It reports whether r was forwarded.
func (s *Server) routeProjectAffinity(w http.ResponseWriter, r *http.Request, kind, workDir string) bool {
	if s.routeDispatch(w, r, workDir) {
		return true
	}
	return s.claimOrRoute(w, r, kind, workDir)
}

// routeNewProject forwards a project creation to the member able to dispatch
// its initialisation, which the request's executor_id — or the default
// executor, without one — decides. The body is read to find out and put back
// for whoever serves the request.
func (s *Server) routeNewProject(w http.ResponseWriter, r *http.Request) bool {
	n := s.clusterNode()
	if n == nil {
		return false
	}
	if _, forwarded := peerCallFrom(r); forwarded {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBodyBytes+1))
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var peek struct {
		ExecutorID string `json:"executor_id"`
	}
	_ = json.Unmarshal(body, &peek)
	var agent string
	if id := strings.TrimSpace(peek.ExecutorID); id != "" {
		agent = s.agentForExecutorID(id)
	} else {
		agent = s.agentForProject("")
	}
	if agent == "" {
		return false
	}
	o, found, err := n.Lookup(ownerAgent, agent)
	if err != nil || !found || o.Self || !o.Alive {
		return false
	}
	return s.forwardTo(w, r, o.Member)
}

// dispatchMember returns the live peer holding the session of the agent
// workDir's workload would be sent to, if that is not this member.
func (s *Server) dispatchMember(workDir string) (hubcluster.Member, bool) {
	n := s.clusterNode()
	if n == nil {
		return hubcluster.Member{}, false
	}
	agentID := s.agentForProject(workDir)
	if agentID == "" {
		return hubcluster.Member{}, false
	}
	o, found, err := n.Lookup(ownerAgent, agentID)
	if err != nil || !found || o.Self || !o.Alive {
		return hubcluster.Member{}, false
	}
	return o.Member, true
}

// agentForProject names the edge agent whose session a dispatch for workDir
// needs, or "" when the project's executor is not one (or is a sub-executor
// of none).
func (s *Server) agentForProject(workDir string) string {
	registerBuiltinExecutors()
	ex, err := executor.ResolveBinding(workDir)
	if err != nil || ex == nil {
		// Unresolvable here may still be an agent another member knows:
		// enrolled after this member restored its fleet. The binding row
		// names it either way.
		if id, ok := lookupProjectExecutor(controlPlaneDir(), workDir); ok {
			return s.agentForExecutorID(id)
		}
		return ""
	}
	return s.agentForExecutorID(ex.ID())
}

// agentForExecutorID maps an executor id to the agent whose session serves
// it: itself for an agent, its parent for a virtual executor, "" otherwise.
func (s *Server) agentForExecutorID(id string) string {
	return agentForExecutor(id, s.clusterNode())
}

// ── handover and adoption ───────────────────────────────────────────────────

// detachRun stops streaming a run this member no longer owns, without
// settling it: the member that took it over settles it. Returns whether this
// member was tracking a run for workDir.
func (s *Server) detachRun(workDir string) bool {
	run, ok := s.trackedRun(workDir)
	if !ok {
		return false
	}
	s.runHandleMu.Lock()
	if cur, still := s.runHandles[workDir]; still && cur.handleID == run.handleID {
		cur.handedOver = true
		s.runHandles[workDir] = cur
	}
	s.runHandleMu.Unlock()
	if run.cancel != nil {
		run.cancel()
	}
	s.untrackRunKeepClaim(workDir)
	s.liveLogSetRunning(workDir, false)
	s.log().Info("cluster", 0, "run handed over to another hub member; stopped streaming it here",
		map[string]interface{}{"project": workDir, "handle": run.handleID})
	return true
}

// verifyRunOwnership detaches from every run this member streams but no
// longer owns. Called on the watcher tick: the handover message may have been
// lost, and a member that keeps streaming a run another member adopted would
// settle it twice.
func (s *Server) verifyRunOwnership() {
	n := s.clusterNode()
	if n == nil {
		return
	}
	s.runHandleMu.Lock()
	dirs := make([]string, 0, len(s.runHandles))
	for workDir := range s.runHandles {
		dirs = append(dirs, workDir)
	}
	s.runHandleMu.Unlock()
	for _, workDir := range dirs {
		o, found, err := n.Lookup(ownerRun, workDir)
		if err != nil || !found || o.Self {
			continue
		}
		s.detachRun(workDir)
	}
}

// adoptOrphanedRuns takes over runs whose owner died, where this member can
// reach the workload.
//
// Who adopts is decided by reachability, not by a race: a run on an edge agent
// is adopted by the member holding that agent's session (only it can stream
// it), and every other run by the leader (every member can reach a container
// runtime or a cluster API; one must be chosen, and the leader already is).
// Adoption itself is a compare-and-swap, so a leader change mid-sweep cannot
// produce two adopters.
func (s *Server) adoptOrphanedRuns() {
	defer recoverGoroutine("adopt orphaned runs")
	n := s.clusterNode()
	if n == nil {
		return
	}
	orphans, err := n.Orphans(ownerRun)
	if err != nil {
		s.log().Warn("cluster", 0, "list orphaned runs", map[string]interface{}{"error": err.Error()})
		return
	}
	for _, o := range orphans {
		var meta runOwnerMeta
		_ = o.Meta(&meta)
		workDir := o.Key
		if meta.Dispatching || meta.Executor == "" || meta.Handle == "" {
			// The owner died between claim and dispatch. Nothing to reattach
			// to; the leader clears the claim so the project can start again.
			if n.IsLeader() {
				if ok, _ := n.Drop(o); ok {
					s.log().Info("cluster", 0, "cleared a run claim whose member died before dispatching",
						map[string]interface{}{"project": workDir, "member": o.InstanceID})
				}
			}
			continue
		}
		if agent := s.agentForExecutorID(meta.Executor); agent != "" {
			if !n.Owns(ownerAgent, agent) {
				continue // the member holding the agent adopts it
			}
		} else if !n.IsLeader() {
			continue
		}
		s.adoptRun(o, meta, "its hub member stopped")
	}
}

// adoptRunsForAgent takes over the runs on agentID (and its sub-executors)
// that another member was streaming. Called when the agent connects here: the
// member it left can no longer reach it, alive or not.
func (s *Server) adoptRunsForAgent(agentID string) {
	defer recoverGoroutine("adopt runs for agent " + agentID)
	n := s.clusterNode()
	if n == nil || agentID == "" {
		return
	}
	owned, err := n.Owned(ownerRun)
	if err != nil {
		return
	}
	for _, o := range owned {
		if o.Self {
			continue
		}
		var meta runOwnerMeta
		_ = o.Meta(&meta)
		if meta.Dispatching || meta.Handle == "" || s.agentForExecutorID(meta.Executor) != agentID {
			continue
		}
		s.adoptRun(o, meta, "its agent reconnected to this hub member")
	}
}

// adoptRun claims one run from its previous owner and resumes streaming and
// settling it here.
func (s *Server) adoptRun(o hubcluster.Owner, meta runOwnerMeta, why string) {
	n := s.clusterNode()
	workDir := o.Key
	ex, err := executor.Get(meta.Executor)
	if err != nil {
		// This member does not have the executor at all (removed from config,
		// or an agent enrolled after it restored its fleet). Leave the claim:
		// a member that does may adopt it, and peerRunExecuting stops holding
		// the project once the grace runs out.
		return
	}
	ok, err := n.Adopt(o, meta)
	if err != nil || !ok {
		return
	}
	s.log().Info("cluster", 0, "adopting a run from another hub member",
		map[string]interface{}{"project": workDir, "from": o.InstanceID, "executor": meta.Executor,
			"handle": meta.Handle, "reason": why})

	// A local driver learns of the dead member's handle by re-reading the
	// store, which now shows the rows of a member no longer alive. Idempotent
	// for handles already known.
	if att, ok := ex.(interface{ AttachHandleStore(executor.HandleStore) }); ok {
		if store := s.clusterHandleStoreFor(); store != nil && ex.Kind() != executor.KindRemoteAgent {
			att.AttachHandleStore(store)
		}
	}

	// The previous owner, if alive, must stop streaming it.
	if o.Alive && o.InstanceID != "" {
		n.PublishTo(o.InstanceID, busTopicInvalidate, invalidateRunMoved, map[string]string{"project": workDir})
	}

	ctx, cancel := context.WithTimeout(context.Background(), workloadStatusTimeout)
	st, stErr := ex.Status(ctx, meta.Handle)
	cancel()
	if errors.Is(stErr, executor.ErrHandleNotFound) || (stErr == nil && st.State.Terminal()) {
		// Gone, or already over: settle it now, as the owner would have.
		s.releaseRunClaim(workDir)
		verdict := workloadVerdict(ex, meta.Handle)
		if stErr != nil {
			verdict = runVerdict{Detail: "its hub member stopped and the workload could not be found on " + ex.ID()}
		}
		if meta.Seeded && meta.Provenance != nil {
			rememberSeededDispatch(ex, meta.Handle, *meta.Provenance)
			rememberFeatureReturn(ex, meta.Handle, meta.Feature)
			s.collectRunResult(workDir, ex, meta.Handle)
		}
		s.reconcileDeadRun(workDir, verdict)
		// Settled here, so counted here: the member that dispatched it, and
		// counted its start, is gone, and the cluster's sum needs the end.
		countRunSettled(ex, st, stErr, false, meta.Started)
		return
	}
	if meta.Seeded && meta.Provenance != nil {
		rememberSeededDispatch(ex, meta.Handle, *meta.Provenance)
		rememberFeatureReturn(ex, meta.Handle, meta.Feature)
	}
	s.resumeRun(workDir, ex, meta.Handle)
}

// resumeRun starts streaming and settling a run this member did not dispatch.
func (s *Server) resumeRun(workDir string, ex executor.Executor, handleID string) {
	streamCtx, cancel := context.WithCancel(context.Background())
	lines, err := ex.Stream(streamCtx, handleID)
	if err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "ui: adopted run %s on %s cannot be streamed: %v\n", handleID, ex.ID(), err)
		s.releaseRunClaim(workDir)
		s.runEnded(workDir, ex, handleID)
		return
	}
	s.liveLogSetRunning(workDir, true)
	s.trackRunWithCancel(workDir, ex, handleID, cancel)
	s.recordRunDispatch(workDir, "adopted", ex, handleID)
	s.broadcastRunState(workDir, true, true)
	s.publishRunState(workDir, true)
	go s.consumeRunOutput(workDir, ex, handleID, lines, nil)
}

// scanRunning is multiui.ScanRunningDirs plus the runs no walk of this
// process table can see: the ones another hub member streams (Task 20354), and
// the ones this member dispatched to an executor whose workload is not a local
// process — a container, a Pod, an edge device.
func (s *Server) scanRunning() multiui.RunningDirs {
	live := multiui.ScanRunningDirs()
	s.runHandleMu.Lock()
	for workDir := range s.runHandles {
		live.Add(workDir)
	}
	s.runHandleMu.Unlock()
	n := s.clusterNode()
	if n == nil {
		return live
	}
	owned, err := n.Owned(ownerRun)
	if err != nil {
		return live
	}
	for _, o := range owned {
		if o.Self {
			continue // counted above, from this member's own record
		}
		if o.Alive || s.peerRunExecuting(o.Key) {
			live.Add(o.Key)
		}
	}
	return live
}

// adoptSweepInterval is how often the project watcher looks for orphaned runs
// on top of the membership changes that normally trigger it: a member that
// could not adopt a run when its owner died (the agent had not reconnected
// yet) tries again.
const adoptSweepInterval = 10 * time.Second

// maybeAdoptOrphanedRuns runs adoptOrphanedRuns at most every
// adoptSweepInterval.
func (s *Server) maybeAdoptOrphanedRuns(now time.Time) {
	if s.clusterNode() == nil {
		return
	}
	s.clusterMu.Lock()
	due := now.Sub(s.lastAdoptSweep) >= adoptSweepInterval
	if due {
		s.lastAdoptSweep = now
	}
	s.clusterMu.Unlock()
	if due {
		go s.adoptOrphanedRuns()
	}
}

// invalidateRunMoved tells a member a run it streamed was adopted elsewhere.
const invalidateRunMoved = "run_moved"

// clusterHandleStoreFor returns the member-scoped handle store drivers use.
func (s *Server) clusterHandleStoreFor() executor.HandleStore {
	return scopeHandleStore(controlPlaneHandleStore(), s.clusterNode())
}

// logRunEvent writes a cluster event about a project to its journal.
func (s *Server) logClusterRunEvent(workDir, msg string) {
	s.log().Info(logger.EventCheckpoint, 0, msg, map[string]interface{}{"project": workDir})
}
