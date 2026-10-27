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
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
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
	// Leases are the secret leases the run holds, which the member adopting
	// it takes over: keeps alive while the run is live and releases when it
	// ends (Task 20382).
	Leases []string `json:"leases,omitempty"`
	// Egress are the egress proxy sessions the run holds, which the member
	// adopting it restores with their counters (Task 20383).
	Egress []string `json:"egress,omitempty"`
	// Workspace is the workspace lease and the pinned git proxy session a
	// driver keeps for the run's push write-back, which the member adopting
	// it takes over and restores (Task 20390).
	Workspace *runWorkspaceMeta `json:"workspace,omitempty"`
	// Slot is the tenant's concurrency slot the run holds, which whichever
	// member settles it gives back (Task 20452).
	Slot    *runQuotaSlot `json:"quota_slot,omitempty"`
	Started time.Time     `json:"started,omitzero"`
	// RunClaimMeta carries Dispatching, which every observer of the claim
	// judges by — members and, since Task 20374, processes that are not
	// members at all. It is embedded rather than restated so the field is
	// written here under the name pkg/hubcluster reads.
	hubcluster.RunClaimMeta
	// RunTakeoverMeta names the credentials above that the member adopting
	// the run could not take over yet and keeps trying (Task 20451), for
	// `cloop hub doctor` and Settings → Hub health. Embedded for the same
	// reason as RunClaimMeta.
	hubcluster.RunTakeoverMeta
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
// provenance its result is merged under. Once it has, the dispatch's intent is
// retired: the run's own record names the workload now (Task 20419).
//
// It reports a run it could not record. A dispatch treats that as a refusal
// (recordingRun): a run whose owner row does not name its workload is one no
// member would adopt after this one died.
func (s *Server) recordRunDispatch(workDir, handler string, ex executor.Executor, handleID string) error {
	n := s.clusterNode()
	if n == nil || workDir == "" || ex == nil {
		return nil
	}
	meta := runOwnerMeta{Executor: ex.ID(), Handle: handleID, Handler: handler, Started: time.Now().UTC()}
	if d, ok := peekSeededDispatch(ex, handleID); ok {
		prov := d.prov
		meta.Seeded, meta.Provenance = true, &prov
		meta.Feature = d.feature
	}
	// What this member holds for the workload, and what it keeps trying to
	// take over (Task 20451): an adopter merges rather than overwrites, so
	// an id an attempt could not decide stays on the row for whoever adopts
	// the run next.
	if err := s.writeRunRecord(n, workDir, ex, handleID, meta); err != nil {
		return err
	}
	if err := forgetDispatchIntentForHandle(ex.ID(), handleID); err != nil {
		// The run is on record, which is what an adopter reads; the intent is
		// retired by the reaper, which finds its run recorded.
		s.log().Warn("cluster", 0, "could not retire the dispatch intent of a recorded run",
			map[string]interface{}{"project": workDir, "handle": handleID, "error": err.Error()})
	}
	return nil
}

// writeRunRecord writes meta, with the credentials this member holds and keeps
// trying for the workload, as workDir's owner row — under the project's
// owner-row lock, which a takeover's refresh takes too.
func (s *Server) writeRunRecord(n *hubcluster.Node, workDir string, ex executor.Executor, handleID string,
	meta runOwnerMeta) error {
	defer lockRunMeta(workDir)()
	fillRunCredentials(&meta, ex.ID(), handleID)
	// And the tenant's concurrency slot the run holds here (Task 20452).
	meta.Slot = s.slots().get(ex.ID(), handleID)
	_, found, err := n.Lookup(ownerRun, workDir)
	if err != nil {
		s.log().Warn("cluster", 0, "could not read the run's owner row",
			map[string]interface{}{"project": workDir, "error": err.Error()})
		return fmt.Errorf("read the run's owner row: %w", err)
	}
	if !found {
		// Standalone-era callers and adoption paths reach here without a
		// prior claim; take one now so the run is visible cluster-wide.
		o, ok, err := n.Claim(ownerRun, workDir, meta)
		if err != nil {
			s.log().Warn("cluster", 0, "could not record the run's owner",
				map[string]interface{}{"project": workDir, "error": err.Error()})
			return fmt.Errorf("record the run's owner: %w", err)
		}
		if !ok {
			return fmt.Errorf("record the run's owner: hub member %s claimed the project's run meanwhile", o.InstanceID)
		}
	} else {
		ok, err := n.UpdateMeta(ownerRun, workDir, meta)
		if err != nil || !ok {
			s.log().Warn("cluster", 0, "could not record the run's executor for adoption",
				map[string]interface{}{"project": workDir, "still_owner": ok, "error": fmt.Sprint(err)})
			if err != nil {
				return fmt.Errorf("record the run's executor for adoption: %w", err)
			}
			return errors.New("record the run's executor for adoption: this hub member no longer holds the run's claim")
		}
	}
	return nil
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
	if cur, still := s.runHandles[workDir]; still && cur.handleID == run.handleID && cur.handedOver {
		// Let go of already — on the bus's word and the watcher's both, or
		// as a lost run — and by whoever did so.
		s.runHandleMu.Unlock()
		return true
	}
	if cur, still := s.runHandles[workDir]; still && cur.handleID == run.handleID {
		cur.handedOver = true
		s.runHandles[workDir] = cur
		// Marked before the stream is cancelled: its consumer, which the
		// cancel wakes, asks takeHandedOver whether to settle the run, and
		// a run settled here as well as by its adopter ends twice — its
		// egress session closed, its result merged and its credentials
		// retired under the member that took it over.
		s.markHandedOverLocked(cur.handleID)
	}
	s.runHandleMu.Unlock()
	// Its concurrency slot goes with it, before the stream's consumer wakes
	// and would give it back: the adopter, whose owner row names the slot,
	// gives it back when the run ends there (Task 20452).
	s.slots().moved(run.ex.ID(), run.handleID)
	if run.cancel != nil {
		run.cancel()
	}
	// What this member could not take over yet goes with the run first: the
	// adopter reads it off the owner row, which names it still, and an
	// attempt still running lets go of what it takes (Task 20451).
	s.handOverRunTakeovers(run.ex, run.handleID)
	// The run's credentials go with it (Task 20383): the leases its adopter
	// takes over hand over now rather than at their next extension, so the
	// sessions they feed stop being served here. The adopter announces itself
	// before it takes them (adoptRun), so a lease not taken yet is watched
	// until it is. The run's egress session stays: no proxy forwards egress,
	// and the workload's proxy address may well be this process's, so the
	// adopter restores it only from a process that is gone.
	ids := liveLeases.forHandle(run.ex.ID(), run.handleID)
	if ws := liveLeases.workspaceForHandle(run.ex.ID(), run.handleID); ws != nil {
		ids = append(ids, ws.Lease) // and its workspace lease (Task 20390)
	}
	for _, id := range ids {
		sl := liveLeases.get(id)
		if sl == nil || sl.broker == nil {
			continue
		}
		if sl.broker.HeldElsewhere(id) {
			sl.handOver()
			continue
		}
		go awaitLeaseTakeover(sl)
	}
	// The egress session stays, served from here until the run ends, which
	// this member learns from the run's owner row (Task 20451).
	if egr := liveEgress.byHandle(run.handleID); egr != nil {
		go s.followMovedRunEgress(workDir, egr, run.ex.ID(), run.handleID)
	}
	s.untrackRunKeepClaim(workDir)
	s.liveLogSetRunning(workDir, false)
	s.log().Info("cluster", 0, "run handed over to another hub member; stopped streaming it here",
		map[string]interface{}{"project": workDir, "handle": run.handleID})
	return true
}

// leaseTakeoverWait bounds how long a member that handed a run over watches
// for the adopter to take the run's lease, and leaseTakeoverPoll how often it
// looks. Variables so tests can shorten them.
var (
	leaseTakeoverWait = 2 * time.Minute
	leaseTakeoverPoll = time.Second
)

// awaitLeaseTakeover hands sl over once another process holds its lease, or
// gives up after leaseTakeoverWait — an adopter that has not taken it by then
// is not going to, and the lease's own keepalive learns the rest at its next
// extension.
func awaitLeaseTakeover(sl *secretLease) {
	defer recoverGoroutine("await lease takeover")
	deadline := time.Now().Add(leaseTakeoverWait)
	for time.Now().Before(deadline) {
		time.Sleep(leaseTakeoverPoll)
		if sl.isHandedOver() || sl.isClosing() {
			return
		}
		if sl.broker.HeldElsewhere(sl.lease.ID) {
			sl.handOver()
			return
		}
	}
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
		// A run taken off its executor by a failover is not handed over:
		// its replacement holds the row now, and the stranded run's leases
		// are closed rather than passed on to a run that has its own
		// (Task 20396).
		if run, ok := s.trackedRun(workDir); ok && run.ex != nil {
			if loss, ok := lossOfHandle(controlPlaneDir(), run.ex.ID(), run.handleID); ok && loss.Claimed() {
				s.retireLostRun(workDir, run.ex.ID(), run.handleID, runVerdict{
					Detail: fmt.Sprintf("its executor %s stopped answering; the run failed over", run.ex.ID()),
					Lost:   true,
				}, false)
				continue
			}
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
	// What a dead member's dispatches started without recording first: those
	// workloads have no run to adopt (Task 20419).
	s.reapOrphanedDispatches()
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
			// The owner died between claim and recording the run. Nothing to
			// reattach to — but a dispatch that got as far as its executor may
			// have started a workload, which is stopped, and its credentials
			// taken back, before the claim goes (Task 20419): clearing it
			// first let the project start again beside a workload whose lease
			// nobody kept or revoked. The leader clears the claim; the member
			// that would have adopted the run does the stopping.
			if !s.reapDispatchingClaim(o, meta) {
				continue
			}
			if n.LeadsAdoption() {
				if ok, _ := n.Drop(o); ok {
					s.log().Info("cluster", 0, "cleared a run claim whose member died before recording the run",
						map[string]interface{}{"project": workDir, "member": o.InstanceID, "run": meta.RunID})
				}
			}
			continue
		}
		// The member holding the agent adopts a run on an edge agent; the
		// leader every other.
		if !s.adoptsRun(meta) {
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
	// A run whose session a failover claim took is no run to resume (Task
	// 20396): its tasks went back to the plan, and a replacement may be
	// running them. Resuming it here is how a dead device's project used to
	// come back "running" with every adoption sweep.
	if loss, ok := lossOfHandle(controlPlaneDir(), meta.Executor, meta.Handle); ok && loss.Claimed() {
		s.settleOrphanedLostRun(o, meta, loss)
		return
	}
	ok, err := n.Adopt(o, meta)
	if err != nil || !ok {
		return
	}
	// The tenant's concurrency slot the run holds is this member's to give
	// back now (Task 20452).
	slot := s.adoptRunSlot(ex.ID(), meta.Handle, meta.Slot)
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

	// The previous owner, if it still heartbeats, must stop streaming it — a
	// member adopted from because it stopped answering may still read the
	// bus (Task 20419).
	if o.InstanceID != "" && n.IsAlive(o.InstanceID) {
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
		// What the owner would have ended with the run (Task 20382): its
		// leases, released, and its executor session, closed with how the
		// workload ended rather than left running for failover to find.
		s.retireRunLeases(meta.Leases, "its run ended while no hub process held the lease")
		if meta.Workspace != nil {
			s.retireRunLeases([]string{meta.Workspace.Lease}, "its run ended while no hub process held the lease")
		}
		retireRunEgressRecords(meta.Egress, "its run ended while no hub process held the session")
		closeAdoptedSessions(ex, meta.Handle, st, stErr)
		if stErr == nil {
			journalPushWriteBack(workDir, ex, st)
		}
		s.reconcileDeadRun(workDir, verdict)
		slot.giveBack()
		// Settled here, so counted here: the member that dispatched it, and
		// counted its start, is gone, and the cluster's sum needs the end.
		countRunSettled(ex, st, stErr, false, meta.Started)
		return
	}
	if meta.Seeded && meta.Provenance != nil {
		rememberSeededDispatch(ex, meta.Handle, *meta.Provenance)
		rememberFeatureReturn(ex, meta.Handle, meta.Feature)
	}
	// Before resumeRun, which rewrites the owner row from what this member
	// holds: the leases have to be held here by then to stay on it.
	s.takeOverRunLeases(workDir, ex, meta.Handle, meta.Leases)
	s.takeOverWorkspaceLease(workDir, ex, meta.Handle, meta.Workspace)
	s.restoreRunEgress(workDir, ex, meta.Handle, meta.Egress)
	// What its firewall refuses from here on is recorded on the run (Task
	// 20437). The levels are re-read: the dispatch's are gone with the
	// process that composed them.
	s.adoptRunDenials(workDir, ex, meta)
	go watchAdoptedSessions(ex, meta.Handle)
	s.resumeRun(workDir, ex, meta.Handle, slot)
}

// adoptRunDenials routes an adopted run's refusals to it.
func (s *Server) adoptRunDenials(workDir string, ex executor.Executor, meta runOwnerMeta) {
	runID := ""
	if meta.Provenance != nil {
		runID = meta.Provenance.RunID
	}
	if runID == "" {
		if store := s.clusterHandleStoreFor(); store != nil {
			if recs, err := store.ListHandles(ex.ID()); err == nil {
				for _, rec := range recs {
					if rec.HandleID == meta.Handle {
						runID = rec.Meta[executor.MetaRunID]
					}
				}
			}
		}
	}
	spec := executor.Spec{WorkDir: workDir}
	installFirewallSource()
	res, err := fwpolicy.Resolve(&spec, ex, workDir)
	if err != nil {
		res = fwpolicy.Resolution{}
	}
	// Ended where every run is settled: runEnded, once its stream closes.
	bindDenialRoute(ex, meta.Handle, runID, workDir, denialLevels(ex, res, spec))
}

// settleOrphanedLostRun deals with an orphaned owner row whose run a failover
// claimed: nothing is adopted. A replacement owns its own row, so a row still
// naming the stranded run is stale and goes; with no replacement, the project
// is settled here, once nothing more is expected — exhausted, or past the
// window a replacement takes to start.
func (s *Server) settleOrphanedLostRun(o hubcluster.Owner, meta runOwnerMeta, loss executorstore.HandleLoss) {
	n := s.clusterNode()
	workDir := o.Key
	switch classifyLoss(loss, time.Now()) {
	case runReplacementPending:
		return // look again on the next sweep
	case runReplaced:
		if ok, _ := n.Drop(o); ok {
			s.log().Info("cluster", 0, "cleared the owner row of a run that was failed over",
				map[string]interface{}{"project": workDir, "member": o.InstanceID})
			// Its replacement holds no slot, so this one comes back with the
			// row rather than never (Task 20452).
			s.releaseRecordedSlot(meta.Slot)
		}
		return
	}
	if ok, _ := n.Drop(o); !ok {
		return // another member got there first
	}
	s.releaseRecordedSlot(meta.Slot)
	detail := fmt.Sprintf("executor %s stopped answering and nothing replaced the run", meta.Executor)
	if loss.Exhausted() {
		detail = exhaustedDetail(meta.Executor, max(loss.Attempt-1, 0))
	}
	s.retireRunLeases(meta.Leases, "its run's executor was lost")
	if meta.Workspace != nil {
		s.retireRunLeases([]string{meta.Workspace.Lease}, "its run's executor was lost")
	}
	retireRunEgressRecords(meta.Egress, "its run's executor was lost")
	s.reconcileDeadRun(workDir, runVerdict{Detail: detail, Lost: true})
}

// resumeRun starts streaming and settling a run this member did not dispatch.
//
// slot is the concurrency slot the run holds, given back when it is settled
// here; nil when it holds none.
func (s *Server) resumeRun(workDir string, ex executor.Executor, handleID string, slot *heldSlot) {
	streamCtx, cancel := context.WithCancel(context.Background())
	lines, err := ex.Stream(streamCtx, handleID)
	if err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "ui: adopted run %s on %s cannot be streamed: %v\n", handleID, ex.ID(), err)
		s.releaseRunClaim(workDir)
		s.runEnded(workDir, ex, handleID)
		slot.giveBack()
		return
	}
	s.liveLogSetRunning(workDir, true)
	s.trackRunWithCancel(workDir, ex, handleID, cancel)
	// The adoption itself is on record — the owner row is this member's —
	// so a failure here leaves the dispatcher's account of the run, which
	// names the same workload. Logged, not refused: the run is not this
	// member's to stop over a write.
	_ = s.recordRunDispatch(workDir, "adopted", ex, handleID)
	s.broadcastRunState(workDir, true, true)
	s.publishRunState(workDir, true)
	go s.consumeRunOutput(workDir, ex, handleID, lines, slot.giveBack)
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
