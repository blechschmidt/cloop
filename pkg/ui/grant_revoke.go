package ui

// grant_revoke.go: revoking a grant takes its credential back from the
// workloads already holding it (Task 20403).
//
// A grant revocation used to stamp the grant and stop there. The keepalive then
// refused to extend a lease still carrying it, so the material inside a running
// workload stayed usable until that lease lapsed — and on a container or a Pod,
// until the workload exited. Now every revocation made in this process is
// announced by the broker (secretbroker.OnGrantRevoked), whoever made it — the
// Secrets panel, offboarding, a secret's deletion — and the hub serving the
// control plane cascades it:
//
//   - every live lease this member holds that carries the grant, or a
//     superseded grant standing on it, gives that grant's material back: the
//     hub's own copy, the git proxy and Kubernetes monitor sessions it fed, the
//     App tokens minted for it, and every holder's copy through
//     revokeLeaseHere — while the lease keeps its other grants;
//   - the leases other hub members hold are reached through the cluster;
//   - a revocation made by a process that is no member — `cloop secret revoke`
//     — arrives on the bus (AnnounceGrantRevoked), and each member answers it
//     for what it holds;
//   - and the lease janitor finds, once a minute, any grant a live lease still
//     carries that was revoked by anything that told no hub at all.
//
// A superseded grant is the exception the task names: an edited repository
// assignment, or a credential granted again for longer, revokes the old grant
// only after its successor exists, and the successor still authorises the run.
// Its leases are not touched — they stand on the successor (see
// secretbroker.Supersede) — except that an App token they hold is re-minted
// at once, held to the successor's constraints.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ── what a revocation did ────────────────────────────────────────────────────

// leaseWithdrawal is one lease's part in a grant revocation.
type leaseWithdrawal struct {
	LeaseID string `json:"lease_id"`
	// GrantID is the grant of the lease that was taken back: the revoked
	// grant, or a superseded one standing on it.
	GrantID     string `json:"grant_id"`
	ExecutorID  string `json:"executor_id,omitempty"`
	ProjectPath string `json:"project_path,omitempty"`
	// Member is the hub member that answered for it.
	Member string `json:"member,omitempty"`
	// Kept: the lease still carries other grants, and goes on without this
	// one. False when this was its only grant and the lease ended with it.
	Kept bool `json:"kept,omitempty"`
	leaseRevocation
}

// grantRevocationResult is what revoking one grant did to the workloads
// holding it, in the shape the lease revoke answers with — the worst state
// across every holder, the hub's own copy, each holder's report — plus the
// leases it was taken back from.
type grantRevocationResult struct {
	GrantID      string `json:"grant_id"`
	Superseded   bool   `json:"superseded,omitempty"`
	SupersededBy string `json:"superseded_by,omitempty"`
	// Leases are the leases that carried the grant.
	Leases []leaseWithdrawal `json:"leases"`
	// KeptLeases counts the leases a superseded grant's leases stand on its
	// successor in, untouched.
	KeptLeases int `json:"kept_leases,omitempty"`
	leaseRevocation
}

// merge folds other's leases into r.
func (r *grantRevocationResult) merge(other grantRevocationResult) {
	r.Leases = append(r.Leases, other.Leases...)
	r.KeptLeases += other.KeptLeases
}

// finish computes the aggregate fields from the leases.
func (r *grantRevocationResult) finish() {
	r.WipedLocally = false
	r.Remote, r.Local = nil, nil
	sort.SliceStable(r.Leases, func(i, j int) bool {
		if r.Leases[i].LeaseID != r.Leases[j].LeaseID {
			return r.Leases[i].LeaseID < r.Leases[j].LeaseID
		}
		return r.Leases[i].Member < r.Leases[j].Member
	})
	for _, l := range r.Leases {
		r.WipedLocally = r.WipedLocally || l.WipedLocally
		r.Remote = append(r.Remote, l.Remote...)
		r.Local = append(r.Local, l.Local...)
	}
	if r.Superseded || (len(r.Leases) == 0 && len(r.Remote) == 0) {
		// Nothing held it, or nothing was taken back: there is no holder
		// whose state could be weaker than revoked.
		r.State = remote.RevokeStateRevoked
		return
	}
	r.State = aggregateState(r.holders(), r.WipedLocally)
}

// grantCascadeKey carries a collector through a broker's revocation to the
// subscriber that cascades it, so the caller that revoked can report what the
// cascade did.
type grantCascadeKey struct{}

// grantCascade collects the cascade results of the revocations made under a
// context.
type grantCascade struct {
	// server is the hub that revoked: it cascades, rather than whichever
	// Server in the process serves the same control plane.
	server  *Server
	mu      sync.Mutex
	results map[string]grantRevocationResult
}

// withGrantCascade returns ctx carrying a fresh collector for s.
func withGrantCascade(ctx context.Context, s *Server) (context.Context, *grantCascade) {
	c := &grantCascade{server: s, results: map[string]grantRevocationResult{}}
	return context.WithValue(ctx, grantCascadeKey{}, c), c
}

func (c *grantCascade) put(r grantRevocationResult) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.results[r.GrantID] = r
	c.mu.Unlock()
}

// result returns what the cascade of grantID did, and whether one ran.
func (c *grantCascade) result(grantID string) (grantRevocationResult, bool) {
	if c == nil {
		return grantRevocationResult{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.results[grantID]
	return r, ok
}

// ── the subscription ─────────────────────────────────────────────────────────

var grantHookOnce sync.Once

// ensureGrantRevocationHook subscribes this process to the broker's
// revocations, once. Every Server registers itself (registerRunServer); the
// hook hands each revocation to the one serving the control plane the grant
// lives in, and does nothing in a process that serves none — a CLI.
func ensureGrantRevocationHook() {
	grantHookOnce.Do(func() {
		secretbroker.OnGrantRevoked(func(ctx context.Context, rev secretbroker.GrantRevocation) {
			c, _ := ctx.Value(grantCascadeKey{}).(*grantCascade)
			var s *Server
			if c != nil && c.server != nil && samePath(state.DBPath(c.server.WorkDir), rev.ControlPlane) {
				s = c.server
			} else {
				s = revocationServer(rev.ControlPlane)
			}
			if s == nil {
				return
			}
			c.put(s.cascadeGrantRevocation(ctx, rev))
		})
	})
}

// revocationServer picks the Server in this process serving the control plane
// whose database is dbPath: the most recently built, should there be several.
func revocationServer(dbPath string) *Server {
	if strings.TrimSpace(dbPath) == "" {
		return nil
	}
	runServersMu.Lock()
	servers := make([]*Server, 0, len(runServers))
	for _, wp := range runServers {
		if v := wp.Value(); v != nil {
			servers = append(servers, v)
		}
	}
	runServersMu.Unlock()
	for i := len(servers) - 1; i >= 0; i-- {
		if samePath(state.DBPath(servers[i].WorkDir), dbPath) {
			return servers[i]
		}
	}
	return nil
}

// grantRevokeReason is what the holders and the audit trail are told.
func grantRevokeReason(grantID, held, actor string) string {
	who := strings.TrimSpace(actor)
	if who == "" {
		who = "an operator"
	}
	if held != "" && held != grantID {
		return fmt.Sprintf("grant %s, which grant %s stood on, revoked by %s", grantID, held, who)
	}
	return fmt.Sprintf("grant %s revoked by %s", grantID, who)
}

// cascadeGrantRevocation takes a revoked grant's material back from every
// workload holding it, on this member and on every other one.
//
// It runs on the revoking goroutine and is bounded by revokeFanoutTimeout,
// detached from the caller's cancellation: the grant is already revoked, and an
// operator's browser closing must not leave the cascade half done.
func (s *Server) cascadeGrantRevocation(ctx context.Context, rev secretbroker.GrantRevocation) grantRevocationResult {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeFanoutTimeout)
	defer cancel()
	req := clusterGrantRequest{
		GrantID: rev.GrantID, Actor: rev.Actor, Superseded: rev.Superseded(), SupersededBy: rev.SupersededBy,
	}
	res := s.grantRevokedHere(ctx, req)
	if s.clusterPeersAlive() {
		results, errs := s.fanOut(ctx, http.MethodPost, clusterAPIGrantRevoked, req,
			func() any { return &grantRevocationResult{} })
		for _, v := range results {
			if peer, ok := v.(*grantRevocationResult); ok && peer != nil {
				res.merge(*peer)
			}
		}
		for member, err := range errs {
			// A member that could not be asked may hold the grant. Reported as
			// an unreachable holder, which the aggregate ranks worst: an
			// operator must not read "revoked" off a cascade that skipped one.
			res.Leases = append(res.Leases, leaseWithdrawal{
				GrantID: rev.GrantID, Member: member,
				leaseRevocation: leaseRevocation{
					State: remote.RevokeStateUnreachable,
					Remote: []remote.RevokeResult{{
						GrantID: rev.GrantID, ExecutorID: "hub member " + member,
						State: remote.RevokeStateUnreachable, SentAt: time.Now(), Error: err.Error(),
					}},
				},
			})
		}
	}
	res.finish()
	if len(res.Leases) > 0 || res.KeptLeases > 0 {
		s.broadcastSecretsUpdate("grant_revoked", rev.GrantID)
	}
	return res
}

// clusterGrantRequest is what a member asks the others to do about a grant.
type clusterGrantRequest struct {
	GrantID      string `json:"grant_id"`
	Actor        string `json:"actor,omitempty"`
	Superseded   bool   `json:"superseded,omitempty"`
	SupersededBy string `json:"superseded_by,omitempty"`
	// RequestID, on the bus, is what the announcing process matches the
	// answer to.
	RequestID string `json:"request_id,omitempty"`
}

// grantRevokedHere answers a grant revocation for what this member holds: the
// leases it issued or took over, and — for leases another process holds, or
// held — the holders connected here.
func (s *Server) grantRevokedHere(ctx context.Context, req clusterGrantRequest) grantRevocationResult {
	res := grantRevocationResult{GrantID: req.GrantID, Superseded: req.Superseded, SupersededBy: req.SupersededBy}
	member := s.hubInstanceID()
	broker, closeDB, err := openUIBroker(s.WorkDir)
	if err != nil {
		// Nothing can be checked, so nothing is taken back on the request's
		// word; the lease janitor finds the revocation once the store answers.
		fmt.Fprintf(os.Stderr, "ui: grant %s revoked, but its control plane cannot be read here: %v\n", req.GrantID, err)
		return res
	}
	defer closeDB()
	// The store, not the request, says whether the grant is revoked: a
	// member takes nothing back from a workload on the word of a bus event
	// or a peer call alone.
	g, err := broker.LookupGrant(req.GrantID)
	if err != nil || g.RevokedAt.IsZero() || (g.RevokedCause == secretbroker.RevokedSuperseded) != req.Superseded {
		return res
	}
	if req.Superseded {
		// The leases stand on the successor and keep their material, and an
		// App token one holds is re-minted, held to the successor — unless the
		// grant no longer stands for it after all, its own secret deleted
		// since, say. That lease gives the grant back as the janitor would
		// take it, from every holder: the agent holding it may be connected
		// to any member.
		for _, sl := range s.ownLeases() {
			held := sl.broker.HeldOn(sl.lease.ID, req.GrantID)
			if len(held) == 0 {
				continue
			}
			kept := true
			for _, wg := range sl.broker.WithdrawnGrants(sl.lease.ID) {
				if !slices.Contains(held, wg.GrantID) || sl.isWithdrawn(wg.GrantID) {
					continue
				}
				kept = false
				w := leaseWithdrawal{LeaseID: sl.lease.ID, GrantID: wg.GrantID, Member: member,
					ExecutorID: sl.lease.ExecutorID, ProjectPath: sl.lease.ProjectID}
				w.leaseRevocation = s.revokeLeaseEverywhere(ctx, sl.lease.ID, wg.GrantID,
					wg.Reason, remote.RevokeScrub, req.Actor)
				w.Kept = liveLeases.get(sl.lease.ID) != nil
				res.Leases = append(res.Leases, w)
			}
			if kept {
				sl.broker.ReconfirmSupersededSlots()
				res.KeptLeases++
			}
		}
		return res
	}

	targets := map[string][]string{}
	var order []string
	add := func(leaseID string, held []string) {
		if len(held) == 0 {
			return
		}
		if _, seen := targets[leaseID]; !seen {
			order = append(order, leaseID)
		}
		for _, h := range held {
			if !slices.Contains(targets[leaseID], h) {
				targets[leaseID] = append(targets[leaseID], h)
			}
		}
	}
	for _, sl := range s.ownLeases() {
		add(sl.lease.ID, sl.broker.HeldOn(sl.lease.ID, req.GrantID))
	}
	// Leases recorded by any member, for the holders connected here: an agent
	// is connected to whichever member it reached, which need not be the one
	// holding its lease.
	if recs, rerr := broker.LeaseRecords(); rerr == nil {
		for _, rec := range recs {
			add(rec.ID, broker.RecordHeldOn(rec, req.GrantID))
		}
	}

	for _, leaseID := range order {
		for _, held := range targets[leaseID] {
			w := leaseWithdrawal{LeaseID: leaseID, GrantID: held, Member: member}
			if sl := liveLeases.get(leaseID); sl != nil && sl.lease != nil {
				w.ExecutorID, w.ProjectPath = sl.lease.ExecutorID, sl.lease.ProjectID
			}
			w.leaseRevocation = s.revokeLeaseHere(ctx, leaseID, held,
				grantRevokeReason(req.GrantID, held, req.Actor), remote.RevokeScrub, req.Actor)
			if sl := liveLeases.get(leaseID); sl != nil {
				w.Kept = true
			}
			if !w.WipedLocally && len(w.holders()) == 0 {
				continue // recorded, held by nobody here
			}
			res.Leases = append(res.Leases, w)
		}
	}
	return res
}

// ownLeases are the live leases this process holds on its control plane.
func (s *Server) ownLeases() []*secretLease {
	var out []*secretLease
	for _, sl := range liveLeases.snapshot() {
		if sl == nil || sl.lease == nil || sl.broker == nil || sl.isHandedOver() {
			continue
		}
		if sl.controlPlane != "" && !samePath(sl.controlPlane, s.WorkDir) {
			continue
		}
		out = append(out, sl)
	}
	return out
}

// handleClusterGrantRevoked is the peer side of cascadeGrantRevocation.
func (s *Server) handleClusterGrantRevoked(w http.ResponseWriter, r *http.Request) {
	var req clusterGrantRequest
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: 64 << 10}) {
		return
	}
	if strings.TrimSpace(req.GrantID) == "" {
		jsonErr(w, "grant_id is required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), revokeFanoutTimeout)
	defer cancel()
	res := s.grantRevokedHere(ctx, req)
	if len(res.Leases) > 0 || res.KeptLeases > 0 {
		s.broadcastSecretsUpdate("grant_revoked", req.GrantID)
	}
	jsonOK(w, res)
}

// supersedeGrant revokes grantID as superseded by successorID, so the leases
// carrying it stand on the successor, and falls back to withdrawing it when the
// supersession cannot be recorded: an edit must never leave both grants live.
func (s *Server) supersedeGrant(ctx context.Context, bs *brokerSet, grantID, successorID, actor string) error {
	_, _, err := bs.secret.Supersede(ctx, grantID, successorID, actor)
	if err == nil {
		return nil
	}
	s.log().Warn("secret_supersede", 0, "could not record a supersession; withdrawing the grant instead",
		map[string]interface{}{"grant": grantID, "successor": successorID, "error": err.Error()})
	return bs.secret.Revoke(ctx, grantID, actor)
}

// replaceGrant retires old in favour of next, an edit's replacement for it.
//
// When next keeps old's credential and allows everything old did, old is
// superseded: a running task holding it goes on, standing on next. When next
// narrows anything, or delivers another credential, old is revoked, and what a
// running task holds under its terms is taken back at once. Standing on a
// narrower grant would leave the running task exactly the access the edit
// withdrew — its git proxy session enforces the scope and branches it was
// opened with, and a token already delivered cannot be narrowed — so an edit
// that narrows is a revocation, and the task's next lease carries next.
func (s *Server) replaceGrant(ctx context.Context, bs *brokerSet, old, next secretbroker.Grant, actor string) error {
	why := ""
	if old.SecretID != next.SecretID {
		why = "delivers a different credential"
	} else if ok, what := next.Constraints.Covers(old.Constraints); !ok {
		why = "allows less (" + what + ")"
	}
	if why == "" {
		return s.supersedeGrant(ctx, bs, old.ID, next.ID, actor)
	}
	_, _, err := bs.secret.RevokeGrant(ctx, secretbroker.RevokeGrantRequest{
		GrantID: old.ID, Actor: actor, Reason: "replaced by grant " + next.ID + ", which " + why,
	})
	return err
}

// ── one grant of a lease ─────────────────────────────────────────────────────

// carriesOthers reports whether the lease carries grantID and at least one
// other grant: whether taking grantID back leaves a lease to keep.
func (sl *secretLease) carriesOthers(grantID string) (carries, others bool) {
	if sl == nil || sl.lease == nil || sl.broker == nil {
		return false, false
	}
	held := sl.broker.HeldGrantIDs(sl.lease.ID)
	carries = slices.Contains(held, grantID)
	return carries, carries && len(held) > 1
}

// isWithdrawn reports whether grantID was already taken back from this lease.
func (sl *secretLease) isWithdrawn(grantID string) bool {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	_, ok := sl.withdrawn[grantID]
	return ok
}

// withdrawGrant takes one grant's material back from the hub's side of this
// lease, which keeps its other grants: the files the hub wrote for it (a host
// workload reads them where they are), the bytes it holds to re-deliver, the
// git proxy and Kubernetes monitor sessions it fed, and the App tokens minted
// for it — and drops the grant from the lease, so the keepalive extends the
// lease on the grants nobody revoked. Idempotent: a second call does nothing.
func (sl *secretLease) withdrawGrant(ctx context.Context, grantID, reason string) error {
	sl.mu.Lock()
	if sl.withdrawn == nil {
		sl.withdrawn = map[string]time.Time{}
	}
	if _, done := sl.withdrawn[grantID]; done {
		sl.mu.Unlock()
		return nil
	}
	sl.withdrawn[grantID] = time.Now()
	sl.mu.Unlock()

	var errs []error
	if sl.mount != nil {
		if _, err := sl.mount.Withdraw(grantID); err != nil {
			errs = append(errs, err)
		}
	}
	if sl.delivery != nil {
		sl.delivery.Withdraw(grantID)
	}
	closeGrantSessions(sl.lease, grantID, reason)
	if sl.broker != nil {
		if _, err := sl.broker.DropLeaseGrant(ctx, sl.lease.ID, grantID, reason); err != nil &&
			!errors.Is(err, secretbroker.ErrLeaseNotFound) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// closeGrantSessions ends the git proxy and Kubernetes monitor sessions one
// grant of a lease fed, leaving its other grants' sessions serving.
func closeGrantSessions(lease *secretbroker.Lease, grantID, reason string) {
	if lease == nil || strings.TrimSpace(grantID) == "" {
		return
	}
	if strings.TrimSpace(reason) == "" {
		reason = "grant " + grantID + " revoked"
	}
	if svc := activeGitProxy(); svc != nil && svc.reg != nil {
		for _, m := range lease.Materials {
			if m.GrantID != grantID {
				continue
			}
			if id := strings.TrimSpace(m.Env[gitProxySessionEnvKey]); id != "" {
				svc.reg.Close(id, reason)
			}
		}
		svc.reg.CloseForGrant(lease.ID, grantID, reason)
	}
	if svc := activeKubeGuard(); svc != nil && svc.reg != nil {
		for _, m := range lease.Materials {
			if m.GrantID != grantID {
				continue
			}
			if id := strings.TrimSpace(m.Env[secretbroker.KubeGuardSessionEnvKey]); id != "" {
				svc.reg.Close(id, reason)
			}
		}
		svc.reg.CloseForGrant(lease.ID, grantID, reason)
	}
}

// ── the janitor's half ───────────────────────────────────────────────────────

// reconcileWithdrawnGrants takes back, from every live lease this process
// holds, a grant that no longer authorises it and whose material it still
// carries: one revoked by a process that told no hub — `cloop secret revoke`
// against a hub that reads no bus, an older binary sharing the control plane —
// or whose successor was revoked while nobody was listening. It is the bound on
// a revocation that missed every announcement: one janitor pass.
func (s *Server) reconcileWithdrawnGrants(ctx context.Context) {
	for _, sl := range s.ownLeases() {
		for _, w := range sl.broker.WithdrawnGrants(sl.lease.ID) {
			if sl.isWithdrawn(w.GrantID) {
				continue
			}
			s.revokeLeaseEverywhere(ctx, sl.lease.ID, w.GrantID,
				w.Reason+" (found by the lease janitor)", remote.RevokeScrub, "janitor")
			s.broadcastSecretsUpdate("grant_revoked", w.GrantID)
		}
	}
}

// ── the bus: revocations made outside any hub ────────────────────────────────

// Bus keys for a grant revocation announced by a process that is no member.
const (
	invalidateGrant    = "grant"
	invalidateGrantAck = "grant_ack"
)

// grantRevocationAck is a member's answer to an announced revocation.
type grantRevocationAck struct {
	RequestID string `json:"request_id"`
	Member    string `json:"member"`
	Hostname  string `json:"hostname,omitempty"`
	grantRevocationResult
}

// onBusGrantRevoked answers a revocation another process announced: the
// member takes the grant back from what it holds, then tells the announcer
// what it did. On its own goroutine: the bus delivers in order and a cascade
// can wait on a device for most of a minute.
func (s *Server) onBusGrantRevoked(ev hubcluster.Event) {
	var req clusterGrantRequest
	if err := ev.Decode(&req); err != nil || strings.TrimSpace(req.GrantID) == "" {
		return
	}
	go func() {
		defer recoverGoroutine("cascade an announced grant revocation")
		ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
		defer cancel()
		res := s.grantRevokedHere(ctx, req)
		res.finish()
		if len(res.Leases) > 0 || res.KeptLeases > 0 {
			s.broadcastSecretsUpdate("grant_revoked", req.GrantID)
		}
		if n := s.clusterNode(); n != nil && req.RequestID != "" {
			host, _ := os.Hostname()
			n.PublishTo(ev.Origin, busTopicInvalidate, invalidateGrantAck, grantRevocationAck{
				RequestID: req.RequestID, Member: n.ID(), Hostname: host, grantRevocationResult: res,
			})
		}
	}()
}

// GrantRevocationAnnouncement is what a process that is no hub member — the
// CLI — tells running hubs about a grant it revoked.
type GrantRevocationAnnouncement struct {
	GrantID      string
	Actor        string
	Superseded   bool
	SupersededBy string
}

// GrantRevocationReport is what the running hubs answered.
type GrantRevocationReport struct {
	// Answered are the members that took the grant back from what they hold,
	// with what each did.
	Answered []GrantRevocationMemberReport
	// Silent are the members alive when it was announced that did not answer
	// within the wait.
	Silent []string
	// Exclusive names a hub holding the control plane alone, which reads no
	// bus; Detail says when it finds the revocation anyway.
	Exclusive       string
	ExclusiveDetail string
	// NoHub: no hub serves this control plane, so no workload holds a lease
	// from it.
	NoHub bool
}

// GrantRevocationMemberReport is one member's answer.
type GrantRevocationMemberReport struct {
	Member   string
	Hostname string
	// Leases is how many leases gave the grant back there, KeptLeases how many
	// a supersession left standing on the successor.
	Leases     int
	KeptLeases int
	// State is the weakest holder state across them.
	State remote.RevokeState
	// Holders summarises each holder's outcome, one line each.
	Holders []string
}

// AnnounceGrantRevoked tells every running hub member that a grant was
// revoked, waits up to wait for each member alive at the time to answer, and
// reports what they did — for `cloop secret revoke`, which revokes from a
// process that holds no lease and can reach no workload (Task 20403). The
// grant is already revoked in the store: a failure here leaves the material in
// the workloads until the hub's lease janitor finds the revocation, and is
// reported as such, not as a failure to revoke.
func AnnounceGrantRevoked(db *statedb.DB, origin string, ann GrantRevocationAnnouncement, wait time.Duration) (GrantRevocationReport, error) {
	return AnnounceGrantsRevoked(db, origin, []GrantRevocationAnnouncement{ann}, wait)
}

// AnnounceGrantsRevoked is AnnounceGrantRevoked for several grants at once —
// `cloop hub user offboard` revokes every grant over a departed person's
// secrets — with one wait for all of them.
func AnnounceGrantsRevoked(db *statedb.DB, origin string, anns []GrantRevocationAnnouncement, wait time.Duration) (GrantRevocationReport, error) {
	var rep GrantRevocationReport
	if db == nil {
		return rep, errors.New("no database")
	}
	if len(anns) == 0 {
		return rep, nil
	}
	rows, err := db.ListHubMembers()
	if err != nil {
		return rep, fmt.Errorf("read the hub members: %w", err)
	}
	now := time.Now()
	expect := map[string]bool{}
	for _, r := range rows {
		if hubcluster.RowAlive(r, now) {
			expect[r.InstanceID] = true
		}
	}
	if st, ierr := hublease.Inspect(hublease.Options{Store: db}); ierr == nil && st.Live && !expect[st.Row.InstanceID] {
		rep.Exclusive = st.Row.InstanceID
		rep.ExclusiveDetail = fmt.Sprintf("holds this control plane exclusively (pid %d on %s) and reads no "+
			"announcements; its lease janitor finds the revocation at its next pass, within %s, and takes the "+
			"grant back then", st.Row.PID, st.Row.Hostname, leaseJanitorBound)
	}
	if len(expect) == 0 {
		rep.NoHub = rep.Exclusive == ""
		return rep, nil
	}

	_, _, cursor, err := db.HubEventBounds()
	if err != nil {
		return rep, fmt.Errorf("read the bus: %w", err)
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return rep, err
	}
	requestID := hex.EncodeToString(idBytes)
	events := make([]statedb.HubEventRow, 0, len(anns))
	grants := map[string]bool{}
	for _, ann := range anns {
		payload, err := json.Marshal(clusterGrantRequest{
			GrantID: ann.GrantID, Actor: ann.Actor, Superseded: ann.Superseded, SupersededBy: ann.SupersededBy,
			RequestID: requestID,
		})
		if err != nil {
			return rep, err
		}
		grants[ann.GrantID] = true
		events = append(events, statedb.HubEventRow{
			Origin: origin, Topic: busTopicInvalidate, Key: invalidateGrant,
			Payload: string(payload), CreatedAt: time.Now(),
		})
	}
	if _, err := db.AppendHubEvents(events); err != nil {
		return rep, fmt.Errorf("write the announcement to the bus: %w", err)
	}

	// One answer per member and grant.
	got := map[string]map[string]grantRevocationAck{}
	complete := func() bool {
		for id := range expect {
			if len(got[id]) < len(grants) {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(wait)
	for !complete() && time.Now().Before(deadline) {
		evs, err := db.HubEventsAfter(cursor, 512)
		if err == nil {
			for _, ev := range evs {
				cursor = ev.Seq
				if ev.Topic != busTopicInvalidate || ev.Key != invalidateGrantAck || ev.Target != origin {
					continue
				}
				var ack grantRevocationAck
				if json.Unmarshal([]byte(ev.Payload), &ack) != nil || ack.RequestID != requestID || !grants[ack.GrantID] {
					continue
				}
				if ack.Member == "" {
					ack.Member = ev.Origin
				}
				if got[ev.Origin] == nil {
					got[ev.Origin] = map[string]grantRevocationAck{}
				}
				got[ev.Origin][ack.GrantID] = ack
			}
		}
		if !complete() {
			time.Sleep(150 * time.Millisecond)
		}
	}
	rank := map[remote.RevokeState]int{remote.RevokeStateRevoked: 0, remote.RevokeStatePending: 1,
		remote.RevokeStateFailed: 2, remote.RevokeStateUnreachable: 3}
	for id := range expect {
		acks := got[id]
		if len(acks) < len(grants) {
			rep.Silent = append(rep.Silent, id)
			if len(acks) == 0 {
				continue
			}
		}
		mr := GrantRevocationMemberReport{Member: id, State: remote.RevokeStateRevoked}
		for _, ack := range acks {
			if ack.Hostname != "" {
				mr.Hostname = ack.Hostname
			}
			mr.Leases += len(ack.Leases)
			mr.KeptLeases += ack.KeptLeases
			if rank[ack.State] > rank[mr.State] {
				mr.State = ack.State
			}
			for _, h := range ack.holders() {
				mr.Holders = append(mr.Holders, describeHolderOutcome(h))
			}
		}
		sort.Strings(mr.Holders)
		rep.Answered = append(rep.Answered, mr)
	}
	sort.Strings(rep.Silent)
	sort.Slice(rep.Answered, func(i, j int) bool { return rep.Answered[i].Member < rep.Answered[j].Member })
	return rep, nil
}

// leaseJanitorBound is how long a revocation no hub was told about can leave
// material in a workload: one janitor pass.
const leaseJanitorBound = remote.DefaultLeaseJanitorInterval

// describeHolderOutcome renders one holder's answer as a line for the CLI.
func describeHolderOutcome(o executor.RevokeOutcome) string {
	var parts []string
	if o.Ack != nil {
		if o.Ack.FilesRemoved > 0 {
			parts = append(parts, fmt.Sprintf("%d file(s) removed", o.Ack.FilesRemoved))
		}
		if len(o.Ack.EnvScrubbed) > 0 {
			parts = append(parts, "variables dropped from its copy: "+strings.Join(o.Ack.EnvScrubbed, ", "))
		}
		if len(o.Ack.Killed) > 0 {
			parts = append(parts, fmt.Sprintf("%d workload(s) terminated", len(o.Ack.Killed)))
		}
		if o.Ack.Eventual {
			parts = append(parts, "files empty in the Pod at the kubelet's next sync")
		}
		if !o.Ack.Known {
			parts = append(parts, "not held there")
		}
	}
	if o.Widened != "" {
		parts = append(parts, "the whole lease was taken back (agent too old to take back one grant)")
	}
	if o.Error != "" {
		parts = append(parts, o.Error)
	}
	line := fmt.Sprintf("%s: %s", o.ExecutorID, o.State)
	if len(parts) > 0 {
		line += " — " + strings.Join(parts, "; ")
	}
	return line
}
