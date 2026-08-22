package remote

// revoke.go is the control plane's half of taking a secret lease back from a
// task that is already running.
//
// The problem it solves is a gap between two designs that were each correct
// on their own. Secret grants are TTL-leased, so a compromised executor's
// window is bounded — but the TTL was only ever consulted by the caller that
// minted the lease. And the session protocol could tear a whole agent down
// with a bye, but had no way to say "keep working, just give that one
// credential back". Between them, revoking a GitHub PAT or a kubeconfig had
// no effect on a run already in flight: it kept using the credential until it
// finished, which on a long autonomous run is hours.
//
// # What a revocation actually guarantees
//
// Three different things, with three different strengths, and the API reports
// which one you got rather than flattening them into "revoked":
//
//   - Files are genuinely gone. The agent wipes and unlinks them, so the next
//     read fails. This is the strong case, and it covers the two credentials
//     that matter most in practice — kubeconfigs and the git credential
//     helper's token file.
//   - Egress allowlist entries are genuinely gone: the next connection is
//     refused.
//   - Environment variables are dropped from the agent's own memory so they
//     are never re-injected, but the *running child process* already has its
//     own copy and no control plane can reach into another process's heap.
//     RevokeKill exists for exactly this case.
//
// # Ack state
//
// A revoke that was sent is not a revoke that landed. The tracker below keeps
// per-lease state so the Secrets panel can say "revoked" (the agent acked),
// "revoke pending" (sent, no ack yet), or "unreachable" (the agent is offline
// and the material is still out there). Anything that collapses those three
// into one would let the UI claim a guarantee the system did not deliver.
//
// Revocations for an offline agent are retained and replayed on reconnect, so
// a device that was unplugged during the revocation does not come back holding
// a credential the operator already took away.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// RevokeState is how far one lease's revocation has got.
type RevokeState string

const (
	// RevokeStatePending: the frame is on its way, or is queued for an agent
	// that is not currently connected but is expected back.
	RevokeStatePending RevokeState = "revoke_pending"
	// RevokeStateRevoked: the agent acked and reported what it scrubbed.
	RevokeStateRevoked RevokeState = "revoked"
	// RevokeStateUnreachable: the agent is offline, so the material is still
	// on the device. The revocation is queued and will be replayed, but until
	// then this is the honest state and the UI must show it as such.
	RevokeStateUnreachable RevokeState = "unreachable"
	// RevokeStateFailed: the agent answered, and the answer was an error.
	RevokeStateFailed RevokeState = "failed"
)

// Terminal reports whether the state can still change on its own. Only
// RevokeStateRevoked is final; a failure is retried on the next sweep and an
// unreachable agent is retried when it reconnects.
func (s RevokeState) Terminal() bool { return s == RevokeStateRevoked }

// RevokeResult is one executor's outcome for one lease revocation.
type RevokeResult struct {
	LeaseID    string      `json:"lease_id"`
	GrantID    string      `json:"grant_id,omitempty"`
	ExecutorID string      `json:"executor_id"`
	State      RevokeState `json:"state"`
	// Action is what was asked for, echoed so a caller reading only the
	// result knows whether a kill was requested.
	Action RevokeAction `json:"action,omitempty"`
	Reason string       `json:"reason,omitempty"`
	// SentAt / AckedAt bound how long the material was still live after the
	// operator pressed the button. Operators ask this after an incident.
	SentAt  time.Time `json:"sent_at"`
	AckedAt time.Time `json:"acked_at,omitempty"`
	// Ack is the agent's report, present once State is RevokeStateRevoked.
	Ack *RevokedPayload `json:"ack,omitempty"`
	// Error explains a failed or unreachable outcome.
	Error string `json:"error,omitempty"`
}

// Pending reports whether this result still needs to be delivered.
func (r RevokeResult) Pending() bool { return !r.State.Terminal() }

// revocationLog is an executor's record of the leases it has been told to
// take back, so they can be replayed on reconnect and reported to the UI.
type revocationLog struct {
	mu sync.Mutex
	// byLease is keyed by "leaseID\x00grantID" so a whole-lease revocation
	// and a single-grant one do not overwrite each other.
	byLease map[string]*RevokeResult
	order   []string
}

// maxRetainedRevocations bounds the log. A control plane runs for months and
// an operator can revoke as often as they like, so without a ceiling this
// would grow forever. Completed entries are evicted oldest-first; pending
// ones never are, because forgetting a pending revocation would silently drop
// the replay that is the whole point of retaining it.
const maxRetainedRevocations = 512

func newRevocationLog() *revocationLog {
	return &revocationLog{byLease: make(map[string]*RevokeResult)}
}

func revocationKey(leaseID, grantID string) string {
	return strings.TrimSpace(leaseID) + "\x00" + strings.TrimSpace(grantID)
}

// record inserts or refreshes an entry, returning the live pointer.
func (rl *revocationLog) record(res RevokeResult) *RevokeResult {
	key := revocationKey(res.LeaseID, res.GrantID)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if prev, ok := rl.byLease[key]; ok {
		// A repeat revocation of an already-acked lease is not an error and
		// must not reopen it: the material is gone, and flipping a settled
		// "revoked" back to "pending" would make the panel oscillate for an
		// operator who clicked twice.
		if prev.State.Terminal() {
			return prev
		}
		prev.State = res.State
		prev.Action = res.Action
		prev.SentAt = res.SentAt
		prev.Error = res.Error
		if res.Reason != "" {
			prev.Reason = res.Reason
		}
		return prev
	}

	entry := res
	rl.byLease[key] = &entry
	rl.order = append(rl.order, key)
	rl.pruneLocked()
	return &entry
}

// pruneLocked evicts the oldest settled entries. Callers hold rl.mu.
func (rl *revocationLog) pruneLocked() {
	if len(rl.order) <= maxRetainedRevocations {
		return
	}
	kept := rl.order[:0]
	for _, key := range rl.order {
		entry, ok := rl.byLease[key]
		if !ok {
			continue
		}
		if len(rl.byLease) > maxRetainedRevocations && entry.State.Terminal() {
			delete(rl.byLease, key)
			continue
		}
		kept = append(kept, key)
	}
	rl.order = kept
}

// settle applies an agent's ack.
func (rl *revocationLog) settle(leaseID, grantID string, ack RevokedPayload, at time.Time) {
	key := revocationKey(leaseID, grantID)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.byLease[key]
	if !ok {
		return
	}
	entry.AckedAt = at
	copied := ack
	entry.Ack = &copied
	if ack.Error != "" {
		entry.State = RevokeStateFailed
		entry.Error = ack.Error
		return
	}
	entry.State = RevokeStateRevoked
	entry.Error = ""
}

// fail marks an entry undelivered, without discarding it: it stays in the log
// so the next reconnect replays it.
func (rl *revocationLog) fail(leaseID, grantID string, state RevokeState, err error) {
	key := revocationKey(leaseID, grantID)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.byLease[key]
	if !ok {
		return
	}
	entry.State = state
	if err != nil {
		entry.Error = err.Error()
	}
}

// pending returns the revocations still owed to the agent, oldest first.
func (rl *revocationLog) pending() []RevokeResult {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := make([]RevokeResult, 0, len(rl.byLease))
	for _, entry := range rl.byLease {
		if entry.Pending() {
			out = append(out, *entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SentAt.Before(out[j].SentAt) })
	return out
}

// snapshot returns every entry, newest first.
func (rl *revocationLog) snapshot() []RevokeResult {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := make([]RevokeResult, 0, len(rl.byLease))
	for _, entry := range rl.byLease {
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SentAt.After(out[j].SentAt) })
	return out
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// revokeTimeout bounds one revoke round trip. It is short: the agent's work is
// unlinking a few files and dropping map entries, and a revocation that hangs
// is worse than one that fails, because the operator is waiting to find out
// whether a credential is still live.
const revokeTimeout = 15 * time.Second

// revokeLease sends a revoke frame and waits for the agent's ack.
//
// A session too old to understand the frame fails immediately with
// ErrRevocationUnsupported rather than writing a frame the peer will drop:
// silently "succeeding" against a v1 agent is the one outcome that would make
// the whole feature a lie.
func (s *Session) revokeLease(ctx context.Context, p RevokePayload) (RevokedPayload, error) {
	if !SupportsRevocation(s.version) {
		return RevokedPayload{}, fmt.Errorf(
			"%w: agent %s speaks protocol v%d; revocation needs v%d or newer",
			ErrRevocationUnsupported, s.agentID, s.version, MinRevocationVersion)
	}
	if strings.TrimSpace(p.LeaseID) == "" {
		return RevokedPayload{}, fmt.Errorf("%w: revoke with no lease id", ErrProtocol)
	}
	p.Action = p.Effective()

	frame, err := s.frame(TypeRevoke, newCorrelationID(), "", p)
	if err != nil {
		return RevokedPayload{}, err
	}
	reply, err := s.request(ctx, frame, TypeRevoked)
	if err != nil {
		return RevokedPayload{}, err
	}
	return DecodeRevoked(reply)
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

// SupportsRevocation reports whether the currently attached agent honours the
// revoke frame. False for a disconnected executor: with no session there is
// nothing that could honour anything.
func (e *Executor) SupportsRevocation() bool {
	sess := e.currentSession()
	return sess != nil && SupportsRevocation(sess.Version())
}

// ProtocolVersion reports the version the live session negotiated, or 0 when
// the agent is not connected. The Executors panel shows it so "this device is
// too old for revocable secrets" is visible before a run fails.
func (e *Executor) ProtocolVersion() int {
	sess := e.currentSession()
	if sess == nil {
		return 0
	}
	return sess.Version()
}

// HoldsLease reports whether any handle this executor tracks was started with
// material from leaseID.
func (e *Executor) HoldsLease(leaseID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.leaseHandles[strings.TrimSpace(leaseID)]
	return ok
}

// Leases lists the lease IDs this executor is holding material for.
func (e *Executor) Leases() []string {
	e.mu.RLock()
	out := make([]string, 0, len(e.leaseHandles))
	for id := range e.leaseHandles {
		out = append(out, id)
	}
	e.mu.RUnlock()
	sort.Strings(out)
	return out
}

// bindLease records that handleID was started with material from a lease, so
// a later revocation knows where to send the frame and which task to kill.
func (e *Executor) bindLease(handleID string, bindings []leaseBinding) {
	if len(bindings) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range bindings {
		id := strings.TrimSpace(b.leaseID)
		if id == "" {
			continue
		}
		if e.leaseHandles[id] == nil {
			e.leaseHandles[id] = make(map[string]struct{})
		}
		e.leaseHandles[id][handleID] = struct{}{}
	}
}

// releaseLeases forgets a handle's lease bindings once it is gone.
func (e *Executor) releaseLeases(handleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, handles := range e.leaseHandles {
		delete(handles, handleID)
		if len(handles) == 0 {
			delete(e.leaseHandles, id)
		}
	}
}

// leaseBinding is the executor's compact view of one Spec.SecretBinding.
type leaseBinding struct {
	leaseID string
	grantID string
}

// RevokeLease takes one lease's material back from this executor's agent.
//
// It always returns a result, even on failure: the caller's next move depends
// on *which* failure, and an error alone cannot say whether the material is
// gone, in doubt, or definitely still out there. The log entry is written
// before the frame goes out so a revocation is never lost to a crash between
// the two.
func (e *Executor) RevokeLease(ctx context.Context, p RevokePayload) RevokeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	now := e.opts.now()
	res := RevokeResult{
		LeaseID:    strings.TrimSpace(p.LeaseID),
		GrantID:    strings.TrimSpace(p.GrantID),
		ExecutorID: e.id,
		Action:     p.Effective(),
		Reason:     p.Reason,
		State:      RevokeStatePending,
		SentAt:     now,
	}
	if res.LeaseID == "" {
		res.State = RevokeStateFailed
		res.Error = "revoke requires a lease id"
		return res
	}
	e.revocations.record(res)

	sess := e.currentSession()
	if sess == nil {
		// Queued, not dropped: attach replays it the moment the device
		// returns. Until then "unreachable" is the truthful state, because
		// the credential is still sitting on a machine we cannot talk to.
		err := fmt.Errorf("%w: agent %s (%s) is not connected; the revocation is queued and will "+
			"be delivered when it reconnects", ErrAgentUnreachable, e.id, e.name)
		e.revocations.fail(res.LeaseID, res.GrantID, RevokeStateUnreachable, err)
		res.State, res.Error = RevokeStateUnreachable, err.Error()
		return res
	}

	rctx, cancel := context.WithTimeout(ctx, revokeTimeout)
	defer cancel()

	ack, err := sess.revokeLease(rctx, p)
	if err != nil {
		state := RevokeStateFailed
		if isUnreachable(err) {
			state = RevokeStateUnreachable
		}
		e.revocations.fail(res.LeaseID, res.GrantID, state, err)
		res.State, res.Error = state, err.Error()
		return res
	}

	acked := e.opts.now()
	e.revocations.settle(res.LeaseID, res.GrantID, ack, acked)
	res.State, res.AckedAt, res.Ack = RevokeStateRevoked, acked, &ack
	if ack.Error != "" {
		res.State, res.Error = RevokeStateFailed, ack.Error
	}
	if p.Effective() == RevokeKill {
		// The agent kills the workload; the terminal status arrives over the
		// normal status path. Forget the binding here so a second revoke does
		// not chase a handle that is on its way out.
		for _, id := range ack.Killed {
			e.releaseLeases(id)
		}
	}
	return res
}

// isUnreachable reports whether err means "the link is gone" rather than "the
// agent refused". The distinction drives the UI's state and whether the
// revocation is replayed on reconnect.
func isUnreachable(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrSessionClosed), errors.Is(err, ErrAgentUnreachable),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return true
	default:
		return false
	}
}

// Revocations reports this executor's revocation log for the UI.
func (e *Executor) Revocations() []RevokeResult { return e.revocations.snapshot() }

// replayRevocations re-sends every revocation still owed to a reconnecting
// agent.
//
// This closes the window the queue exists for. A device unplugged during a
// revocation would otherwise reconnect holding a credential the operator
// already took away, and — because the hub's own lease record was wiped when
// the operator pressed the button — nothing would ever ask for it back.
//
// It runs in its own goroutine because attach is called from the handshake
// path, which must not block on a round trip to the device it is still
// setting up.
func (e *Executor) replayRevocations(sess *Session) {
	owed := e.revocations.pending()
	if len(owed) == 0 {
		return
	}
	if !SupportsRevocation(sess.Version()) {
		err := fmt.Errorf("%w: agent %s reconnected speaking protocol v%d",
			ErrRevocationUnsupported, e.id, sess.Version())
		for _, r := range owed {
			e.revocations.fail(r.LeaseID, r.GrantID, RevokeStateFailed, err)
		}
		return
	}
	for _, r := range owed {
		ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
		ack, err := sess.revokeLease(ctx, RevokePayload{
			LeaseID: r.LeaseID,
			GrantID: r.GrantID,
			Reason:  r.Reason,
			Action:  r.Action,
		})
		cancel()
		if err != nil {
			state := RevokeStateFailed
			if isUnreachable(err) {
				state = RevokeStateUnreachable
			}
			e.revocations.fail(r.LeaseID, r.GrantID, state, err)
			continue
		}
		e.revocations.settle(r.LeaseID, r.GrantID, ack, e.opts.now())
		if e.opts.OnRevokeAck != nil {
			e.opts.OnRevokeAck(e.id, r.LeaseID, ack)
		}
	}
}
