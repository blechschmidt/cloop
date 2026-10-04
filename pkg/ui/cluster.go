package ui

// cluster.go wires pkg/hubcluster into the hub (Task 20354).
//
// Several `cloop ui` processes may now serve one control plane. Each is a full
// hub — any of them answers any request — and the database they share carries
// what used to be process memory. This file is the hub's side of that:
//
//   - which background work only the leader runs (runLeaderDuty);
//   - how a request that another member must answer gets there (the peer
//     middleware below, and forwardTo);
//   - how events one member produces reach the dashboards attached to the
//     others (publishers here, and startClusterBus).
//
// A Server with no Cluster is a standalone hub and behaves exactly as before:
// it leads, it owns everything, and nothing is published. Every helper here is
// written so that is the zero-cost path, which is also what lets the hundreds
// of existing pkg/ui tests run unchanged against struct-literal Servers.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
)

// Bus topics. Each is one kind of event a member produced that dashboards on
// other members must see; everything derived from the shared database (state
// diffs, the project list) is deliberately absent, because every member
// derives those itself from the same rows.
const (
	// busTopicWS carries a WebSocket message for one project's clients (key =
	// project directory) or, with an empty key, for every client.
	busTopicWS = "ws"
	// busTopicLog carries live harness output (key = project directory).
	busTopicLog = "log"
	// busTopicRunState carries a run starting or stopping.
	busTopicRunState = "run_state"
	// busTopicPresence carries the dashboard users one member has on a project.
	busTopicPresence = "presence"
	// busTopicEdit carries a task edit, for cross-member conflict detection.
	busTopicEdit = "edit"
	// busTopicInvalidate tells members to drop something they cache; the key
	// says what (see invalidate* below).
	busTopicInvalidate = "invalidate"
)

// Ownership kinds: things only one member can hold. See pkg/hubcluster/owners.go.
const (
	// ownerRun: the member streaming a project's dispatched run. Key: the
	// project directory. Defined by pkg/hubcluster, because processes that are
	// not members read these claims too (Task 20374).
	ownerRun = hubcluster.OwnerKindRun
	// ownerAgent: the member holding an edge agent's WebSocket. Key: executor
	// id.
	ownerAgent = "agent"
	// ownerSuggest / ownerChat: in-memory per-project conversations.
	ownerSuggest = "suggest"
	ownerChat    = "chat"
	// ownerCCAuth: a `claude auth login` child waiting for its code. Key: the
	// login's owner identity.
	ownerCCAuth = "ccauth"
	// ownerAutoPR: a feature pull request being opened. Key: feature dir.
	ownerAutoPR = "autopr"
	// ownerLock: a named cluster-wide mutex (clusterMutex).
	ownerLock = "lock"
)

// Invalidation keys.
const (
	invalidateQuota    = "quota"
	invalidateSession  = "session"
	invalidateAgent    = "agent"
	invalidateProjects = "projects"
)

// clusterNode returns this hub's cluster membership, or nil when standalone.
func (s *Server) clusterNode() *hubcluster.Node {
	if s == nil {
		return nil
	}
	return s.Cluster
}

// isLeader reports whether this hub runs the work that must happen once. A
// standalone hub always does.
func (s *Server) isLeader() bool {
	n := s.clusterNode()
	return n == nil || n.IsLeader()
}

// clusterPeersAlive reports whether any other member currently serves this
// control plane.
func (s *Server) clusterPeersAlive() bool {
	n := s.clusterNode()
	return n != nil && n.HasPeers()
}

// hubInstanceID names this process in rows other members read: the member id
// in a cluster, the exclusive lease's id otherwise.
func (s *Server) hubInstanceID() string {
	if n := s.clusterNode(); n != nil {
		return n.ID()
	}
	return s.Lease.InstanceID()
}

// runLeaderDuty runs fn for as long as this hub leads. Standalone, that is for
// as long as ctx lives; in a cluster, from each election to the matching
// demotion, so a sweep never runs on two members at once.
func (s *Server) runLeaderDuty(ctx context.Context, name string, fn func(context.Context)) {
	n := s.clusterNode()
	if n == nil {
		go fn(ctx)
		return
	}
	n.WhileLeader(name, fn)
}

// peerCallFrom reports whether r was forwarded by a verified peer.
func peerCallFrom(r *http.Request) (hubcluster.PeerCall, bool) {
	if r == nil {
		return hubcluster.PeerCall{}, false
	}
	return hubcluster.PeerCallFrom(r.Context())
}

// peerMiddleware verifies requests that claim to come from another member.
//
// A verified claim is recorded in the context — handlers then answer locally
// instead of forwarding again, and clientIP reports the caller the forwarding
// member saw rather than that member's address. A claim that does not verify
// is refused outright: treating it as an ordinary client would let anyone
// attach peer headers and see which ones a hub ignores.
func (s *Server) peerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hubcluster.IsPeerRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		n := s.clusterNode()
		if n == nil {
			jsonErr(w, "peer request refused: this hub is not a cluster member", http.StatusForbidden)
			return
		}
		pc, err := n.VerifyPeer(r)
		if err != nil {
			s.log().Warn("cluster", 0, "refused a request claiming to come from a hub member",
				map[string]interface{}{"remote": r.RemoteAddr, "path": r.URL.Path, "error": err.Error()})
			jsonErr(w, "peer request refused: "+err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set(hubcluster.HeaderServedBy, n.ID())
		next.ServeHTTP(w, r.WithContext(hubcluster.WithPeerCall(r.Context(), pc)))
	})
}

// servedByMiddleware names the answering member on every response, so an
// operator reading a HAR file — and a test — can see where a request landed.
func (s *Server) servedByMiddleware(next http.Handler) http.Handler {
	n := s.clusterNode()
	if n == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hubcluster.HeaderServedBy, n.ID())
		next.ServeHTTP(w, r)
	})
}

// forwardTo hands r to member m. It returns false only when r must be served
// here after all: it was itself forwarded (answering locally is the loop
// guard), or m is this member.
func (s *Server) forwardTo(w http.ResponseWriter, r *http.Request, m hubcluster.Member) bool {
	n := s.clusterNode()
	if n == nil || m.ID == "" || m.ID == n.ID() {
		return false
	}
	if _, forwarded := peerCallFrom(r); forwarded {
		return false
	}
	// The member that answers names itself; this one only passed it on.
	w.Header().Del(hubcluster.HeaderServedBy)
	if err := n.Forward(w, r, m, clientIP(r)); err != nil {
		s.log().Warn("cluster", 0, "forwarding to the owning hub member failed",
			map[string]interface{}{"member": m.ID, "path": r.URL.Path, "error": err.Error()})
	}
	return true
}

// routeToOwner forwards r to the live member that owns (kind, key), and
// reports whether it did. A key nobody owns, a key this member owns, a dead
// owner, and a request that was already forwarded are all served here.
func (s *Server) routeToOwner(w http.ResponseWriter, r *http.Request, kind, key string) bool {
	n := s.clusterNode()
	if n == nil || key == "" {
		return false
	}
	if _, forwarded := peerCallFrom(r); forwarded {
		return false
	}
	o, found, err := n.Lookup(kind, key)
	if err != nil || !found || o.Self || !o.Alive {
		return false
	}
	return s.forwardTo(w, r, o.Member)
}

// claimOrRoute makes this member the owner of (kind, key) unless a live peer
// already is, in which case r is forwarded there. It reports whether r was
// forwarded; when it was not, this member owns the key (or there is no
// cluster).
func (s *Server) claimOrRoute(w http.ResponseWriter, r *http.Request, kind, key string) bool {
	n := s.clusterNode()
	if n == nil || key == "" {
		return false
	}
	if _, forwarded := peerCallFrom(r); forwarded {
		// The forwarding member judged us the owner; make it so if nobody
		// else has claimed it meanwhile.
		_, _, _ = n.Claim(kind, key, nil)
		return false
	}
	o, ok, err := n.Claim(kind, key, nil)
	if err != nil || ok {
		return false
	}
	return s.forwardTo(w, r, o.Member)
}

// releaseClusterClaim gives up (kind, key) if this member holds it.
func (s *Server) releaseClusterClaim(kind, key string) {
	if n := s.clusterNode(); n != nil && key != "" {
		_, _ = n.Release(kind, key)
	}
}

// ── publishing ───────────────────────────────────────────────────────────────

// busWS is a WebSocket message relayed to other members' clients.
type busWS struct {
	Msg wsMessage `json:"msg"`
	// SSE names the SSE event to mirror the message to on the receiving side,
	// "" for none. Per-project messages only.
	SSE string `json:"sse,omitempty"`
}

// publishWS relays msg to the clients of workDir ("" for every client) on
// every other member.
func (s *Server) publishWS(workDir string, msg wsMessage, sse string) {
	n := s.clusterNode()
	if n == nil {
		return
	}
	n.Publish(busTopicWS, workDir, busWS{Msg: msg, SSE: sse})
}

// relayedWSTypes are the per-project messages that describe something only
// the producing member knows. The rest — state_diff above all — every member
// derives from the database itself, and relaying them would deliver each
// change twice, once in a form diffed against another member's cache.
var relayedWSTypes = map[string]bool{
	"task_added":    true,
	"task_deleted":  true,
	"task_mutation": true,
	"provider_call": true,
}

// publishInvalidate tells every other member to drop what key names.
func (s *Server) publishInvalidate(key string, payload any) {
	if n := s.clusterNode(); n != nil {
		n.Publish(busTopicInvalidate, key, payload)
	}
}

// logBatcher coalesces live output per project before it goes on the bus. A
// harness writes a line at a time; one bus event per line would be one write
// transaction per line on a database every member shares.
type logBatcher struct {
	s       *Server
	mu      sync.Mutex
	pending map[string]*strings.Builder
	timer   *time.Timer
}

// logBatchDelay is how long output waits to be batched: a fraction of the bus
// poll interval, so batching adds little to the latency the poll already has.
const logBatchDelay = 100 * time.Millisecond

// logBatchMax flushes a project's batch early once it is this large, so a
// burst does not become one enormous event.
const logBatchMax = 32 << 10

func (b *logBatcher) add(workDir, chunk string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		b.pending = map[string]*strings.Builder{}
	}
	sb := b.pending[workDir]
	if sb == nil {
		sb = &strings.Builder{}
		b.pending[workDir] = sb
	}
	sb.WriteString(chunk)
	if sb.Len() >= logBatchMax {
		b.publishLocked(workDir)
		return
	}
	if b.timer == nil {
		b.timer = time.AfterFunc(logBatchDelay, b.flush)
	}
}

func (b *logBatcher) flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.timer = nil
	for workDir := range b.pending {
		b.publishLocked(workDir)
	}
}

// flushProject publishes workDir's pending output now. Called before a
// run_state change so the last lines of a run reach other members before the
// message that says it ended.
func (b *logBatcher) flushProject(workDir string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.publishLocked(workDir)
}

func (b *logBatcher) publishLocked(workDir string) {
	sb := b.pending[workDir]
	if sb == nil || sb.Len() == 0 {
		delete(b.pending, workDir)
		return
	}
	chunk := sb.String()
	delete(b.pending, workDir)
	if n := b.s.clusterNode(); n != nil {
		n.Publish(busTopicLog, workDir, map[string]string{"chunk": chunk})
	}
}

// publishLog queues live output for other members.
func (s *Server) publishLog(workDir, chunk string) {
	n := s.clusterNode()
	if n == nil || !n.HasPeers() {
		return
	}
	s.clusterMu.Lock()
	if s.logBatch == nil {
		s.logBatch = &logBatcher{s: s}
	}
	b := s.logBatch
	s.clusterMu.Unlock()
	b.add(workDir, chunk)
}

// publishRunState tells other members a run started or stopped here.
func (s *Server) publishRunState(workDir string, running bool) {
	n := s.clusterNode()
	if n == nil {
		return
	}
	s.clusterMu.Lock()
	b := s.logBatch
	s.clusterMu.Unlock()
	if b != nil {
		b.flushProject(workDir)
	}
	n.Publish(busTopicRunState, workDir, map[string]bool{"running": running})
}

// ── receiving ────────────────────────────────────────────────────────────────

// startClusterBus subscribes this hub to what other members publish. Called
// once from Run.
func (s *Server) startClusterBus() {
	n := s.clusterNode()
	if n == nil {
		return
	}
	n.Subscribe(busTopicWS, s.onBusWS)
	n.Subscribe(busTopicLog, s.onBusLog)
	n.Subscribe(busTopicRunState, s.onBusRunState)
	n.Subscribe(busTopicPresence, s.onBusPresence)
	n.Subscribe(busTopicEdit, s.onBusEdit)
	n.Subscribe(busTopicInvalidate, s.onBusInvalidate)
	n.OnBusGap(s.onBusGap)
	n.OnMembership(s.onMembershipChange)
}

func (s *Server) onBusWS(ev hubcluster.Event) {
	var p busWS
	if err := ev.Decode(&p); err != nil || p.Msg.Type == "" {
		return
	}
	if ev.Key == "" {
		s.deliverToAll(p.Msg)
		return
	}
	s.deliverToProject(ev.Key, p.Msg)
	if p.SSE != "" {
		s.deliverSSE(ev.Key, sseEvent{Event: p.SSE, Data: string(p.Msg.Data)})
	}
}

// A log or run_state event's key is the project directory the publishing
// member resolved — the room key its own broadcastLog or publishRunState was
// called with — so it names exactly one project here too, and delivery goes
// only to that project's room, as a local broadcast would.

func (s *Server) onBusLog(ev hubcluster.Event) {
	var p struct {
		Chunk string `json:"chunk"`
	}
	workDir := ev.Key
	if err := ev.Decode(&p); err != nil || p.Chunk == "" || workDir == "" {
		return
	}
	s.deliverLog(workDir, p.Chunk)
}

func (s *Server) onBusRunState(ev hubcluster.Event) {
	var p struct {
		Running bool `json:"running"`
	}
	workDir := ev.Key
	if err := ev.Decode(&p); err != nil || workDir == "" {
		return
	}
	// The run belongs to the member that sent this. Recorded so the live-log
	// room reports it running to clients connecting here, and so this member
	// can forget it the moment that member dies (onMembershipChange) rather
	// than show a run nobody is streaming.
	s.clusterMu.Lock()
	if s.remoteRuns == nil {
		s.remoteRuns = map[string]string{}
	}
	if p.Running {
		s.remoteRuns[workDir] = ev.Origin
	} else if s.remoteRuns[workDir] == ev.Origin {
		delete(s.remoteRuns, workDir)
	}
	s.clusterMu.Unlock()
	if p.Running {
		s.liveLogStartRemoteRun(workDir)
	} else {
		s.liveLogSetRunning(workDir, false)
	}
	s.deliverRunState(workDir, p.Running, true)
	// The project list carries a running flag too.
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
}

func (s *Server) onBusGap() {
	// Events were lost; every local client may now be showing a view that
	// stopped matching. The resync directive makes them re-read.
	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			select {
			case hc.resync <- struct{}{}:
			default:
			}
		}
	}
	s.hubMu.Unlock()
}

// onMembershipChange forgets what dead members told us: runs they were
// streaming and users they had on a project. Without it a member that died
// mid-run would leave every other member's dashboards showing a run in
// progress and a colleague who left.
func (s *Server) onMembershipChange(live []hubcluster.Member) {
	alive := make(map[string]bool, len(live))
	for _, m := range live {
		alive[m.ID] = true
	}
	var stopped []string
	var presenceChanged []string
	s.clusterMu.Lock()
	for workDir, origin := range s.remoteRuns {
		if !alive[origin] {
			delete(s.remoteRuns, workDir)
			stopped = append(stopped, workDir)
		}
	}
	for workDir, byOrigin := range s.remotePresence {
		for origin := range byOrigin {
			if !alive[origin] {
				delete(byOrigin, origin)
				presenceChanged = append(presenceChanged, workDir)
			}
		}
		if len(byOrigin) == 0 {
			delete(s.remotePresence, workDir)
		}
	}
	s.clusterMu.Unlock()

	for _, workDir := range stopped {
		// Not a verdict that the run is over — only that nobody streams it
		// to us any more. Whether it is over is for adoption and stale-run
		// recovery to decide, from the run's owner row.
		s.liveLogSetRunning(workDir, false)
		s.deliverRunState(workDir, s.projectExecuting(workDir), true)
	}
	for _, workDir := range uniqueStrings(presenceChanged) {
		s.deliverPresence(workDir)
	}
	// A member that just joined knows nobody's presence; tell it ours.
	s.republishPresence()
	// Runs a dead member owned are up for adoption.
	go s.adoptOrphanedRuns()
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ── invalidation ─────────────────────────────────────────────────────────────

func (s *Server) onBusInvalidate(ev hubcluster.Event) {
	switch ev.Key {
	case invalidateQuota:
		s.reloadQuotaOverrides()
	case invalidateSession:
		var p struct {
			SessionHash string `json:"session_hash"`
			All         bool   `json:"all"`
		}
		if err := ev.Decode(&p); err == nil {
			s.evictSessionCache(p.SessionHash, p.All)
		}
	case invalidateAgent:
		var p agentInvalidation
		if err := ev.Decode(&p); err == nil {
			s.applyAgentInvalidation(p)
		}
	case invalidateProjects:
		s.refreshProjectStatuses()
		s.broadcastProjectsUpdate()
	case invalidateMembers:
		// Another member, or `cloop project members`, changed who may
		// reach a project (Task 20366). Reload now rather than at the TTL;
		// the reload closes this member's streams that lost access.
		s.onBusMembersInvalidate()
	case invalidateRunMoved:
		var p struct {
			Project string `json:"project"`
		}
		if err := ev.Decode(&p); err == nil && p.Project != "" {
			s.detachRun(p.Project)
		}
	}
}

// errNotClustered is returned by internal endpoints called on a standalone hub.
var errNotClustered = errors.New("this hub is not a cluster member")

// requirePeer refuses a request that did not come from a verified member. The
// internal endpoints act on another member's behalf and must never be
// reachable by a client, whatever its credentials.
func requirePeer(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := peerCallFrom(r); ok {
		return true
	}
	jsonErr(w, "this endpoint is only for hub cluster members", http.StatusForbidden)
	return false
}

// clusterLogf is the logger handed to pkg/hubcluster.
func clusterLogf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ui: "+format+"\n", args...)
}

// marshalBusPayload is json.Marshal for payloads that cannot fail to encode;
// a failure is a programming error and yields "null".
func marshalBusPayload(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
