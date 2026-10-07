package ui

// cluster_leases.go: secret leases and edge agents across hub members
// (Task 20354).
//
// A lease lives in the memory of the member that issued it — the broker's
// record, the keepalive that extends it while its run is live, the tmpfs
// directory its files were written to. An agent lives on whichever member it
// is connected to, and after a reconnect that is often a different one. So a
// revocation, a listing, or a cordon issued on one member has to reach the
// others: this file is how.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
)

// clusterRevokeRequest is what a member asks another to revoke.
type clusterRevokeRequest struct {
	LeaseID string              `json:"lease_id"`
	GrantID string              `json:"grant_id,omitempty"`
	Reason  string              `json:"reason,omitempty"`
	Action  remote.RevokeAction `json:"action,omitempty"`
	Actor   string              `json:"actor,omitempty"`
}

// mergePeerRevocations asks every other member to revoke leaseID on what it
// holds, and folds their answers into out.
func (s *Server) mergePeerRevocations(ctx context.Context, out *leaseRevocation, leaseID, grantID, reason string, action remote.RevokeAction, actor string) {
	if !s.clusterPeersAlive() {
		return
	}
	req := clusterRevokeRequest{LeaseID: leaseID, GrantID: grantID, Reason: reason, Action: action, Actor: actor}
	results, errs := s.fanOut(ctx, http.MethodPost, clusterAPIRevokeLease, req,
		func() any { return &leaseRevocation{} })
	for _, v := range results {
		lr, ok := v.(*leaseRevocation)
		if !ok || lr == nil {
			continue
		}
		out.WipedLocally = out.WipedLocally || lr.WipedLocally
		out.Remote = append(out.Remote, lr.Remote...)
		out.Local = append(out.Local, lr.Local...)
	}
	for member, err := range errs {
		// A member that could not be asked may hold a copy. Reported as an
		// unreachable holder, which aggregateState ranks worst: the operator
		// must not read "revoked" off a revocation that skipped a member.
		out.Remote = append(out.Remote, remote.RevokeResult{
			LeaseID:    leaseID,
			GrantID:    grantID,
			ExecutorID: "hub member " + member,
			State:      remote.RevokeStateUnreachable,
			SentAt:     time.Now(),
			Error:      err.Error(),
		})
	}
	out.State = aggregateState(out.holders(), out.WipedLocally)
}

// handleClusterRevokeLease is the peer side of mergePeerRevocations.
func (s *Server) handleClusterRevokeLease(w http.ResponseWriter, r *http.Request) {
	var req clusterRevokeRequest
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: 64 << 10}) {
		return
	}
	if strings.TrimSpace(req.LeaseID) == "" {
		jsonErr(w, "lease_id is required", http.StatusBadRequest)
		return
	}
	action := req.Action
	if action == "" {
		action = remote.RevokeScrub
	}
	ctx, cancel := context.WithTimeout(r.Context(), revokeFanoutTimeout)
	defer cancel()
	out := s.revokeLeaseHere(ctx, req.LeaseID, req.GrantID, req.Reason, action, req.Actor)
	if out.WipedLocally || len(out.holders()) > 0 {
		s.broadcastSecretsUpdate("lease_revoked", req.LeaseID)
	}
	jsonOK(w, out)
}

// revokeExpiredOnPeers scrubs expired leases off the agents other members
// hold. Asynchronous: the janitor tick must not wait on a round trip.
func (s *Server) revokeExpiredOnPeers(expired []remote.ExpiredLease) {
	if !s.clusterPeersAlive() || len(expired) == 0 {
		return
	}
	go func() {
		defer recoverGoroutine("scrub expired leases on hub members")
		ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
		defer cancel()
		for _, e := range expired {
			s.fanOut(ctx, http.MethodPost, clusterAPIRevokeLease, clusterRevokeRequest{
				LeaseID: e.LeaseID, Reason: e.Reason, Action: remote.RevokeScrub, Actor: "janitor",
			}, func() any { return &leaseRevocation{} })
		}
	}()
}

// peerLeaseViews lists the leases every other member issued.
func (s *Server) peerLeaseViews(ctx context.Context) []leaseView {
	if !s.clusterPeersAlive() {
		return nil
	}
	// A listing another member forwarded here is answered with this member's
	// leases only; that member does its own fan-out.
	if _, forwarded := hubcluster.PeerCallFrom(ctx); forwarded {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	results, errs := s.fanOut(ctx, http.MethodGet, clusterAPILeases, nil,
		func() any { return &[]leaseView{} })
	for member, err := range errs {
		fmt.Fprintf(os.Stderr, "ui: list leases on hub member %s: %v\n", member, err)
	}
	var out []leaseView
	for _, v := range results {
		if views, ok := v.(*[]leaseView); ok && views != nil {
			out = append(out, (*views)...)
		}
	}
	return out
}

// handleClusterLeases is the peer side of peerLeaseViews.
func (s *Server) handleClusterLeases(w http.ResponseWriter, r *http.Request) {
	names := map[string]string{}
	for _, entry := range s.allProjectEntries() {
		names[entry.Path] = entry.Name
	}
	jsonOK(w, s.localLeaseViews(names))
}

// ── agents ──────────────────────────────────────────────────────────────────

// clusterAgentOp is an operation on an agent that only the member holding its
// session can perform.
type clusterAgentOp struct {
	Op     string `json:"op"`
	Agent  string `json:"agent"`
	Reason string `json:"reason,omitempty"`
	Actor  string `json:"actor,omitempty"`
	// Failover is the claimed session to re-dispatch, for agentOpRedispatch.
	Failover *executor.FailoverEvent `json:"failover,omitempty"`
}

const (
	agentOpRevokeLeases = "revoke_leases"
	// agentOpRedispatch starts a failed-over session on an agent this member
	// holds; the supervisor that claimed it runs on another.
	agentOpRedispatch = "redispatch"
)

// revokeLeasesOnAgentOwner hands a cordon's lease revocation to the member
// holding executorID's session, and reports whether it did.
func (s *Server) revokeLeasesOnAgentOwner(executorID, reason, actor string) bool {
	n := s.clusterNode()
	if n == nil {
		return false
	}
	agent := s.agentForExecutorID(executorID)
	if agent == "" {
		return false
	}
	o, found, err := n.Lookup(ownerAgent, agent)
	if err != nil || !found || o.Self || !o.Alive {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
	defer cancel()
	if err := n.Call(ctx, o.Member, http.MethodPost, clusterAPIAgentOp, clusterAgentOp{
		Op: agentOpRevokeLeases, Agent: executorID, Reason: reason, Actor: actor,
	}, nil); err != nil {
		fmt.Fprintf(os.Stderr, "ui: revoke leases of %s on hub member %s: %v\n", executorID, o.InstanceID, err)
	}
	return true
}

// handleClusterAgentOp performs an agent operation another member routed here.
func (s *Server) handleClusterAgentOp(w http.ResponseWriter, r *http.Request) {
	var op clusterAgentOp
	if !jsonbody.Decode(w, r, &op, jsonbody.Options{Limit: 64 << 10}) {
		return
	}
	if strings.TrimSpace(op.Agent) == "" {
		jsonErr(w, "agent is required", http.StatusBadRequest)
		return
	}
	switch op.Op {
	case agentOpRevokeLeases:
		s.revokeLeasesForExecutor(op.Agent, op.Reason, op.Actor)
		jsonOK(w, map[string]any{"ok": true})
	case agentOpRedispatch:
		if op.Failover == nil {
			jsonErr(w, "failover event is required", http.StatusBadRequest)
			return
		}
		if err := redispatchSession(r.Context(), controlPlaneDir(), *op.Failover); err != nil {
			jsonErr(w, err.Error(), http.StatusConflict)
			return
		}
		jsonOK(w, map[string]any{"ok": true})
	default:
		jsonErr(w, "unknown agent operation", http.StatusBadRequest)
	}
}

// agentInvalidation tells other members that an agent changed in a way their
// registries must reflect.
type agentInvalidation struct {
	Agent string `json:"agent"`
	// Event is "deleted" (drop it: its credential is revoked) or "enrolled"
	// (a new device: register it so projects bound to it resolve here too).
	Event string `json:"event"`
}

const (
	agentEventDeleted  = "deleted"
	agentEventEnrolled = "enrolled"
)

// publishAgentChange tells other members about an agent change.
func (s *Server) publishAgentChange(agentID, event string) {
	s.publishInvalidate(invalidateAgent, agentInvalidation{Agent: agentID, Event: event})
}

// applyAgentInvalidation applies an agent change another member made.
func (s *Server) applyAgentInvalidation(p agentInvalidation) {
	hub, err := s.remoteHub()
	if err != nil || hub == nil || strings.TrimSpace(p.Agent) == "" {
		return
	}
	switch p.Event {
	case agentEventDeleted:
		// If the device is connected here, this drops it with a "do not
		// reconnect" goodbye; either way its executor leaves this member's
		// registry, with the virtual executors that ran through it.
		hub.Deregister(p.Agent)
		executor.DefaultRegistry.Unregister(p.Agent)
		for _, ex := range executor.List() {
			if v, ok := ex.(interface{ ParentID() string }); ok && v.ParentID() == p.Agent {
				executor.DefaultRegistry.Unregister(ex.ID())
			}
		}
	case agentEventEnrolled:
		if err := hub.Restore(); err != nil {
			fmt.Fprintf(os.Stderr, "ui: register agent %s enrolled on another hub member: %v\n", p.Agent, err)
		}
	}
	s.broadcastExecutorUpdateLocal(p.Event, p.Agent)
}

// clusterAgentStatus wraps an agent status mirror so that only the member
// actually holding an agent's socket speaks for it (Task 20354).
//
// Online is a fact about this member: the agent is here, now. Offline is only
// news if this member still held it — an agent that reconnected elsewhere is
// seen going offline by the member it left, up to a heartbeat deadline later,
// and letting that member write "offline" would overwrite the new holder's
// "online" and flap the Executors panel.
func (s *Server) clusterAgentStatus(inner func(string, string, time.Time)) func(string, string, time.Time) {
	return func(executorID, status string, at time.Time) {
		n := s.clusterNode()
		if n == nil {
			inner(executorID, status, at)
			return
		}
		if status == remote.StatusOnline {
			if err := n.Assert(ownerAgent, executorID, nil); err != nil {
				fmt.Fprintf(os.Stderr, "ui: record that agent %s is connected here: %v\n", executorID, err)
			}
			inner(executorID, status, at)
			// Runs another member was streaming for this agent can only be
			// streamed here now.
			go s.adoptRunsForAgent(executorID)
			return
		}
		if !n.Owns(ownerAgent, executorID) {
			return
		}
		_, _ = n.Release(ownerAgent, executorID)
		inner(executorID, status, at)
	}
}

// releaseAgentOwnership gives up every agent this member holds, as it shuts
// down: the agents are about to reconnect to another member, and requests for
// them must stop being forwarded to one that is leaving.
func (s *Server) releaseAgentOwnership() {
	n := s.clusterNode()
	if n == nil {
		return
	}
	owned, err := n.Owned(ownerAgent)
	if err != nil {
		return
	}
	for _, o := range owned {
		if o.Self {
			_, _ = n.Release(ownerAgent, o.Key)
		}
	}
}

// routeAgentRequest forwards r to the member holding executorID's agent
// session, and reports whether it did. For the handlers that talk to a device
// over its socket: upgrade, inventory refresh, attach.
func (s *Server) routeAgentRequest(w http.ResponseWriter, r *http.Request, executorID string) bool {
	agent := s.agentForExecutorID(executorID)
	if agent == "" {
		return false
	}
	return s.routeToOwner(w, r, ownerAgent, agent)
}

// agentHeldByPeer reports whether ex is an edge agent — or a sub-executor of
// one — whose socket another live hub member holds, and which member.
func (s *Server) agentHeldByPeer(ex executor.Executor) (string, bool) {
	n := s.clusterNode()
	if n == nil || ex == nil {
		return "", false
	}
	agent := s.agentForExecutorID(ex.ID())
	if agent == "" {
		return "", false
	}
	o, found, err := n.Lookup(ownerAgent, agent)
	if err != nil || !found || o.Self || !o.Alive {
		return "", false
	}
	return o.InstanceID, true
}

// redispatchOnAgentOwner hands a failed-over session to the member holding
// its replacement executor's agent, when that is not this member. routed
// reports whether it did; err is that member's answer.
func redispatchOnAgentOwner(ctx context.Context, ev executor.FailoverEvent) (routed bool, err error) {
	n := currentCluster()
	if n == nil || ev.To == "" {
		return false, nil
	}
	agent := agentForExecutor(ev.To, n)
	if agent == "" {
		return false, nil
	}
	o, found, lerr := n.Lookup(ownerAgent, agent)
	if lerr != nil || !found || o.Self || !o.Alive {
		return false, nil
	}
	ev.Err = nil
	return true, n.Call(ctx, o.Member, http.MethodPost, clusterAPIAgentOp, clusterAgentOp{
		Op: agentOpRedispatch, Agent: ev.To, Failover: &ev,
	}, nil)
}

// agentForExecutor is Server.agentForExecutorID for callers without a Server.
func agentForExecutor(id string, n *hubcluster.Node) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if parent := virtualParentOf(id); parent != "" {
		return parent
	}
	if ex, err := executor.Get(id); err == nil && ex != nil {
		if ex.Kind() == executor.KindRemoteAgent {
			return id
		}
		return ""
	}
	if n != nil {
		if _, found, _ := n.Lookup(ownerAgent, id); found {
			return id
		}
	}
	return ""
}
