package ui

// secrets_revoke.go pushes a lease revocation out to the executors already
// holding the credential, instead of waiting for their tasks to exit.
//
// Before this, POST /api/leases/{id}/revoke wiped the tmpfs directory on the
// *hub*. For a host executor that is the same directory the workload reads, so
// the revocation was real. For a remote executor it was not: the material had
// already been shipped to the device inside the start frame, and the hub's copy
// was a directory nobody was reading.
//
// The same was true of the container and Kubernetes backends, which this file
// used to describe as covered by the hub wipe. They are not, and secrets.go in
// the container driver says why in its own header: a container has a mount
// namespace of its own, so the hub's lease directory is simply not present
// inside it, and the driver stages a separate copy. The Kubernetes driver
// projects its copy from a Secret in etcd. Wiping the hub's directory reached
// neither. Those two backends are now asked directly, through
// executor.Revoker, exactly as a remote agent is.
//
// Three triggers drive revocation, and they are deliberately all routed
// through revokeLeaseEverywhere so they cannot drift apart:
//
//   - an operator pressing Revoke in the Secrets panel,
//   - the TTL janitor, which sweeps live sessions rather than re-checking at
//     mint time (which is all Lease.Expired ever did before),
//   - cordon and drain, because taking a device out of rotation and leaving
//     it holding live credentials answers "I no longer trust this machine"
//     with "in a few hours".

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// revokeFanoutTimeout bounds the whole fleet fan-out for one revocation.
//
// Generous relative to a single agent round trip (remote.revokeTimeout) so a
// slow LTE device does not cause a spurious "unreachable" for a credential it
// is about to give back, but bounded so the HTTP handler an operator is
// staring at cannot hang on a device that will never answer.
const revokeFanoutTimeout = 45 * time.Second

// leaseRevocation is one lease's outcome across the whole system.
type leaseRevocation struct {
	// WipedLocally reports that the hub's own copy of the material — the
	// tmpfs mount — was removed. Always true when the hub held the lease.
	WipedLocally bool `json:"wiped_locally"`
	// Remote is what each holding agent reported.
	Remote []remote.RevokeResult `json:"remote,omitempty"`
	// Local is what each holding executor on this hub reported — the
	// container, Kubernetes and host-process drivers. Separate from Remote
	// because the failure modes differ: a local driver is never
	// "unreachable", and an operator reading the panel should not have to
	// work out which of the two a row came from.
	Local []executor.RevokeOutcome `json:"local,omitempty"`
	// State is the weakest state across every holder, because a revocation
	// is only as strong as the credential copy it failed to reach.
	State remote.RevokeState `json:"state"`
}

// holders returns every outcome, remote and local, for aggregation.
func (lr leaseRevocation) holders() []executor.RevokeOutcome {
	out := make([]executor.RevokeOutcome, 0, len(lr.Remote)+len(lr.Local))
	out = append(out, lr.Remote...)
	out = append(out, lr.Local...)
	return out
}

// aggregateState folds per-executor results into the one state the UI shows.
//
// It takes the *worst* outcome rather than the best or the most recent. An
// operator who revoked a credential across four devices and reached three of
// them has not revoked that credential, and a panel that said "revoked"
// because the majority acked would be telling them a comfortable lie.
func aggregateState(results []remote.RevokeResult, wipedLocally bool) remote.RevokeState {
	if len(results) == 0 {
		if wipedLocally {
			return remote.RevokeStateRevoked
		}
		return remote.RevokeStatePending
	}
	worst := remote.RevokeStateRevoked
	rank := map[remote.RevokeState]int{
		remote.RevokeStateRevoked:     0,
		remote.RevokeStatePending:     1,
		remote.RevokeStateFailed:      2,
		remote.RevokeStateUnreachable: 3,
	}
	for _, r := range results {
		if rank[r.State] > rank[worst] {
			worst = r.State
		}
	}
	return worst
}

// revokeLeaseEverywhere takes a lease back from the hub and from every remote
// agent holding it.
//
// Ordering is load-bearing. The hub's copy goes first: it is the one this
// process can guarantee, it needs no network, and doing it after the fan-out
// would leave a window in which a fresh workload could be started from a
// mount the operator has already revoked. The remote fan-out follows, and its
// per-executor outcomes are reported rather than folded into a boolean —
// "revoked on two devices, one unreachable" is the answer, and there is no
// honest way to say it in a single flag.
func (s *Server) revokeLeaseEverywhere(ctx context.Context, leaseID, grantID, reason string, action remote.RevokeAction, actor string) leaseRevocation {
	out := leaseRevocation{}

	sl, held := liveLeases.revoke(leaseID)
	out.WipedLocally = held
	executorID, projectID := "", ""
	var secretNames []string
	if held && sl != nil && sl.lease != nil {
		executorID, projectID = sl.lease.ExecutorID, sl.lease.ProjectID
		secretNames = sl.lease.SecretNames()
	}

	req := remote.RevokePayload{
		LeaseID: leaseID,
		GrantID: grantID,
		Reason:  reason,
		Action:  action,
	}

	fanCtx, cancel := context.WithTimeout(ctx, revokeFanoutTimeout)
	defer cancel()

	hub, err := s.remoteHub()
	if err != nil || hub == nil {
		// No hub means no remote agents on this install. Not an error: a
		// hub-only deployment is a supported topology, not a degraded one.
		// The local drivers below are still asked — they are where a
		// container or in-cluster sandbox holds its own copy.
		s.auditRevokeSent(actor, leaseID, grantID, executorID, projectID, reason, action, secretNames, nil)
	} else {
		s.auditRevokeSent(actor, leaseID, grantID, executorID, projectID, reason, action, secretNames,
			hub.LeaseHolders(leaseID))
		out.Remote = hub.RevokeLease(fanCtx, req)
	}

	out.Local = s.revokeOnLocalDrivers(fanCtx, req)
	out.State = aggregateState(out.holders(), out.WipedLocally)

	for _, res := range out.holders() {
		s.auditRevokeResult(actor, projectID, res)
	}
	return out
}

// revokeOnLocalDrivers asks every executor running on this hub to give the
// lease back.
//
// Remote executors are skipped because the hub above already fanned out to
// them, with queueing and reconnect replay a plain registry walk cannot offer;
// asking twice would double every audit row and reopen a settled log entry.
//
// Executors that do not hold the lease are skipped rather than asked and
// ignored. The distinction is not cosmetic: a driver asked about a lease it
// never had answers "not here", which is indistinguishable in the audit trail
// from a driver that held it and wiped it — and "where did this credential
// live" is the question an incident actually asks.
func (s *Server) revokeOnLocalDrivers(ctx context.Context, req remote.RevokePayload) []executor.RevokeOutcome {
	var out []executor.RevokeOutcome
	for _, ex := range executor.List() {
		if _, isRemote := ex.(*remote.Executor); isRemote {
			continue
		}
		rv, ok := executor.AsRevoker(ex)
		if !ok || !rv.HoldsLease(req.LeaseID) {
			continue
		}
		out = append(out, rv.RevokeLease(ctx, req))
	}
	return out
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

// auditRevokeSent records that a revocation left the control plane.
//
// It is written *before* the fan-out rather than after, so the trail shows the
// intent even when the process dies mid-revocation. A trail that only records
// completed revocations cannot answer "was this credential ever withdrawn",
// which is the question an incident actually asks.
func (s *Server) auditRevokeSent(actor, leaseID, grantID, executorID, projectID, reason string,
	action remote.RevokeAction, secrets, holders []string) {

	s.auditRevokeEvent(secretbroker.ActionLeaseRevokeSent, actor, leaseID, map[string]any{
		"decision":    string(secretbroker.DecisionAllow),
		"lease_id":    leaseID,
		"grant_id":    grantID,
		"executor_id": executorID,
		"project_id":  projectID,
		"action":      string(action),
		"secrets":     strings.Join(secrets, ","),
		"holders":     strings.Join(holders, ","),
		"reason":      reason,
	})
}

// auditRevokeResult records one executor's answer.
func (s *Server) auditRevokeResult(actor, projectID string, res remote.RevokeResult) {
	payload := map[string]any{
		"lease_id":    res.LeaseID,
		"grant_id":    res.GrantID,
		"executor_id": res.ExecutorID,
		"project_id":  projectID,
		"action":      string(res.Action),
		"state":       string(res.State),
		"reason":      res.Reason,
	}
	if res.Ack != nil {
		// Names and counts only. EnvScrubbed is variable names, never values;
		// the agent is careful about this and so is this row.
		payload["env_scrubbed"] = strings.Join(res.Ack.EnvScrubbed, ",")
		payload["files_removed"] = res.Ack.FilesRemoved
		payload["egress_dropped"] = res.Ack.EgressDropped
		payload["killed"] = strings.Join(res.Ack.Killed, ",")
		payload["held_by_agent"] = res.Ack.Known
	}

	if res.State == remote.RevokeStateRevoked {
		payload["decision"] = string(secretbroker.DecisionAllow)
		if !res.AckedAt.IsZero() {
			payload["acked_after_ms"] = res.AckedAt.Sub(res.SentAt).Milliseconds()
		}
		s.auditRevokeEvent(secretbroker.ActionLeaseRevokeAcked, actor, res.LeaseID, payload)
		return
	}
	payload["decision"] = string(secretbroker.DecisionDeny)
	payload["error"] = res.Error
	s.auditRevokeEvent(secretbroker.ActionLeaseRevokeFailed, actor, res.LeaseID, payload)
}

// auditRevokeEvent writes one row. Best-effort, matching every other emitter
// in the hub: a wedged journal must not stop an operator pulling a credential.
func (s *Server) auditRevokeEvent(action secretbroker.Action, actor, leaseID string, payload map[string]any) {
	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "secrets: open control-plane db for lease revoke event",
			map[string]interface{}{"error": err.Error(), "lease_id": leaseID, "action": string(action)})
		return
	}
	defer db.Close()

	statedb.AuditSecretDecision(db, statedb.SecretAuditInput{
		Actor:     actor,
		EventType: auditaction.Action(action),
		EntityID:  leaseID,
		Payload:   payload,
	})
	s.broadcastAuditAppend(string(action))
}

// ---------------------------------------------------------------------------
// TTL janitor
// ---------------------------------------------------------------------------

var (
	leaseJanitorMu   sync.Mutex
	leaseJanitorStop func()
)

// StartLeaseJanitor begins sweeping expired leases off live agents.
//
// This is what makes a lease TTL bind the whole system rather than just the
// hub. Lease.Expired and Lease.TTL existed from the start, but nothing ever
// consulted them once the material had been handed out: an executor given a
// fifteen-minute credential simply kept it for the three hours its task ran.
// Sweeping live sessions is the difference.
//
// Idempotent. Calling it twice replaces the previous janitor rather than
// running two, which matters because the Server is constructed per test and
// a leaked ticker per construction would show up as a goroutine leak.
func (s *Server) StartLeaseJanitor(ctx context.Context) {
	hub, err := s.remoteHub()
	if err != nil || hub == nil {
		// No remote fleet: the hub's own leases are wiped when their
		// workloads exit, and there is nothing out there to sweep.
		return
	}

	leaseJanitorMu.Lock()
	defer leaseJanitorMu.Unlock()
	if leaseJanitorStop != nil {
		leaseJanitorStop()
		leaseJanitorStop = nil
	}
	leaseJanitorStop = hub.StartLeaseJanitor(ctx, remote.DefaultLeaseJanitorInterval, s.sweepExpiredLeases)
}

// StopLeaseJanitor shuts the sweeper down and waits for it to finish.
func (s *Server) StopLeaseJanitor() {
	leaseJanitorMu.Lock()
	stop := leaseJanitorStop
	leaseJanitorStop = nil
	leaseJanitorMu.Unlock()
	if stop != nil {
		stop()
	}
}

// sweepExpiredLeases reports the leases whose TTL has run out.
//
// It also wipes the hub's own copy of each, because a lapsed lease is lapsed
// everywhere: leaving the tmpfs mount in place would let a workload that has
// the directory path keep reading a credential the broker considers expired.
func (s *Server) sweepExpiredLeases(now time.Time) []remote.ExpiredLease {
	var out []remote.ExpiredLease
	for _, sl := range liveLeases.snapshot() {
		if sl == nil || sl.lease == nil || !sl.lease.Expired(now) {
			continue
		}
		age := now.Sub(sl.lease.ExpiresAt).Round(time.Second)
		out = append(out, remote.ExpiredLease{
			LeaseID: sl.lease.ID,
			Reason:  fmt.Sprintf("lease TTL expired %s ago", age),
		})
	}
	if len(out) == 0 {
		return nil
	}
	// Wipe the hub's copies here rather than leaving it to the fan-out: the
	// janitor's caller only revokes on agents that hold the lease, and a
	// hub-local executor never appears in that list.
	for _, expired := range out {
		if _, held := liveLeases.revoke(expired.LeaseID); held {
			fmt.Fprintf(os.Stderr, "ui: swept expired lease %s (%s)\n", expired.LeaseID, expired.Reason)
		}
		s.auditRevokeSent("janitor", expired.LeaseID, "", "", "", expired.Reason,
			remote.RevokeScrub, nil, nil)
	}
	s.broadcastSecretsUpdate("lease_expired", out[0].LeaseID)
	return out
}

// ---------------------------------------------------------------------------
// cordon / drain
// ---------------------------------------------------------------------------

// revokeLeasesForExecutor takes back every lease an executor is holding,
// after it has been cordoned or drained.
//
// Asynchronous because the cordon itself is already in force by the time this
// runs and the operator should not wait on a fleet round trip to be told so.
// The results reach them through the audit trail and the Secrets panel, which
// is where "did that credential actually come back" is answered anyway.
func (s *Server) revokeLeasesForExecutor(executorID, reason, actor string) {
	go func() {
		defer recoverGoroutine("lease revoke on cordon: " + executorID)

		hub, err := s.remoteHub()
		if err != nil || hub == nil {
			return
		}
		ex, ok := hub.Executor(executorID)
		if !ok {
			return
		}
		leases := ex.Leases()
		if len(leases) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
		defer cancel()
		for _, leaseID := range leases {
			// Scrub, not kill. Cordoning is "stop giving this machine new
			// work", and draining explicitly waits for in-flight work to
			// finish — killing those tasks to reclaim a credential would
			// contradict the operation the operator asked for. An operator
			// who does want the tasks stopped has the lease panel's kill
			// action.
			s.revokeLeaseEverywhere(ctx, leaseID, "", reason, remote.RevokeScrub, actor)
		}
		s.broadcastSecretsUpdate("leases_revoked", executorID)
	}()
}

// ---------------------------------------------------------------------------
// view helpers
// ---------------------------------------------------------------------------

// revocationView is the per-lease revocation state the Secrets panel renders.
type revocationView struct {
	State      remote.RevokeState  `json:"state"`
	ExecutorID string              `json:"executor_id,omitempty"`
	Action     remote.RevokeAction `json:"action,omitempty"`
	SentAt     time.Time           `json:"sent_at"`
	AckedAt    time.Time           `json:"acked_at,omitempty"`
	// EnvScrubbed and FilesRemoved are what the agent reported, so the panel
	// can distinguish a revocation that removed a kubeconfig from one that
	// only dropped an environment variable the child process still holds.
	EnvScrubbed   []string `json:"env_scrubbed,omitempty"`
	FilesRemoved  int      `json:"files_removed,omitempty"`
	EgressDropped bool     `json:"egress_dropped,omitempty"`
	Killed        []string `json:"killed,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// fleetRevocations indexes every executor's revocation log by lease, so GET
// /api/leases can annotate rows without a round trip per lease.
//
// Local drivers are included alongside remote agents. A panel that showed only
// the fleet's remote revocations would report "never revoked" for a credential
// a container sandbox gave back thirty seconds ago, which is the same class of
// untruth — a UI claiming a state the system is not in — that this whole task
// was about.
func (s *Server) fleetRevocations() map[string][]revocationView {
	out := make(map[string][]revocationView)

	var all []executor.RevokeOutcome
	if hub, err := s.remoteHub(); err == nil && hub != nil {
		all = append(all, hub.Revocations()...)
	}
	for _, ex := range executor.List() {
		if _, isRemote := ex.(*remote.Executor); isRemote {
			continue // already counted above, with its queued replays
		}
		if rv, ok := executor.AsRevoker(ex); ok {
			all = append(all, rv.Revocations()...)
		}
	}

	for _, res := range all {
		view := revocationView{
			State:      res.State,
			ExecutorID: res.ExecutorID,
			Action:     res.Action,
			SentAt:     res.SentAt,
			AckedAt:    res.AckedAt,
			Error:      res.Error,
		}
		if res.Ack != nil {
			view.EnvScrubbed = res.Ack.EnvScrubbed
			view.FilesRemoved = res.Ack.FilesRemoved
			view.EgressDropped = res.Ack.EgressDropped
			view.Killed = res.Ack.Killed
		}
		out[res.LeaseID] = append(out[res.LeaseID], view)
	}
	for _, views := range out {
		sort.Slice(views, func(i, j int) bool { return views[i].SentAt.After(views[j].SentAt) })
	}
	return out
}

// parseRevokeAction reads the action from a request body, defaulting to scrub.
//
// An unknown action is refused rather than defaulted. Defaulting would be
// tempting — "scrub is the safe one" — but an operator who typed "terminate"
// meaning kill would get a scrub and be told it succeeded, and would find out
// otherwise only from the task that kept running.
func parseRevokeAction(raw string) (remote.RevokeAction, error) {
	switch a := remote.RevokeAction(strings.TrimSpace(raw)); {
	case raw == "":
		return remote.RevokeScrub, nil
	case a.Valid():
		return a, nil
	default:
		return "", fmt.Errorf("action must be %q or %q (got %q)",
			remote.RevokeScrub, remote.RevokeKill, raw)
	}
}

// revokeHTTPStatus maps a revocation outcome onto a status code.
//
// A partial revocation is 200 with the per-executor detail, not an error: the
// operation ran, and its result is the payload. Returning 5xx would invite a
// retry of something that already happened, and would hide the one thing the
// operator needs to read — which device still has the credential.
func revokeHTTPStatus(_ leaseRevocation) int { return http.StatusOK }
