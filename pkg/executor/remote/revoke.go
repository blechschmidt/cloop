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
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// The state machine, the result type and the retention rules are defined in
// pkg/executor and aliased here: every Revoker needs exactly these, and three
// copies of the eviction rule would eventually become three different rules —
// with the one that quietly dropped a pending entry losing a revocation rather
// than a log line.
type (
	// RevokeState is how far one lease's revocation has got.
	RevokeState = executor.RevokeState
	// RevokeResult is one executor's outcome for one lease revocation.
	RevokeResult = executor.RevokeOutcome
)

const (
	// RevokeStatePending: the frame is on its way, or is queued for an agent
	// that is not currently connected but is expected back.
	RevokeStatePending = executor.RevokeStatePending
	// RevokeStateRevoked: the agent acked and reported what it scrubbed.
	RevokeStateRevoked = executor.RevokeStateRevoked
	// RevokeStateUnreachable: the agent is offline, so the material is still
	// on the device. The revocation is queued and will be replayed, but until
	// then this is the honest state and the UI must show it as such.
	RevokeStateUnreachable = executor.RevokeStateUnreachable
	// RevokeStateFailed: the agent answered, and the answer was an error.
	RevokeStateFailed = executor.RevokeStateFailed
)

// This driver is a Revoker, and the assertion is what keeps it one. The
// interface's four methods are spread across this file and remote.go, so a
// refactor that changed one signature would otherwise surface not as a build
// failure but as a driver that silently stopped being placeable for leased
// work — the exact failure mode this task existed to remove.
var _ executor.Revoker = (*Executor)(nil)

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
//
// It answers true for an executor with any *unresolved* handle too, whatever
// the lease — a workload rehydrated from a row that did not record its
// bindings might be holding this one, and nothing here can tell. That routes
// the revocation to RevokeLease, which reports the doubt. See
// executor.LeaseIndex.Holds.
func (e *Executor) HoldsLease(leaseID string) bool { return e.leases.Holds(leaseID) }

// Leases lists the lease IDs this executor is holding material for.
func (e *Executor) Leases() []string { return e.leases.Leases() }

// releaseLeases forgets a handle's lease bindings once it is gone.
func (e *Executor) releaseLeases(handleID string) { e.leases.Release(handleID) }

// RevokeLease takes one lease's material back from this executor's agent.
//
// It always returns a result, even on failure: the caller's next move depends
// on *which* failure, and an error alone cannot say whether the material is
// gone, in doubt, or definitely still out there. The log entry is written
// before the frame goes out so a revocation is never lost to a crash between
// the two.
//
// Unlike the hub's own drivers this does *not* fail on an unresolved binding,
// and the asymmetry is deliberate. Those drivers' lease index is the only
// record that a workload was ever handed a credential, so doubt there is
// unresolvable. Here the device keeps an index of its own, in a process the
// hub's restart did not touch, and the frame reaches it either way — so the
// agent's ack is a *better* answer than anything the hub could reconstruct,
// and Known comes from the machine actually holding the material. What the
// unresolved mark still buys is the ask: HoldsLease answers true for it, so
// the frame is sent rather than the executor skipped.
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
	e.revocations.Record(res)

	sess := e.currentSession()
	if sess == nil {
		// Queued, not dropped: attach replays it the moment the device
		// returns. Until then "unreachable" is the truthful state, because
		// the credential is still sitting on a machine we cannot talk to.
		err := fmt.Errorf("%w: agent %s (%s) is not connected; the revocation is queued and will "+
			"be delivered when it reconnects", ErrAgentUnreachable, e.id, e.name)
		e.revocations.Fail(res.LeaseID, res.GrantID, RevokeStateUnreachable, err)
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
		e.revocations.Fail(res.LeaseID, res.GrantID, state, err)
		res.State, res.Error = state, err.Error()
		return res
	}

	acked := e.opts.now()
	e.revocations.Settle(res.LeaseID, res.GrantID, ack, acked)
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
func (e *Executor) Revocations() []RevokeResult { return e.revocations.Snapshot() }

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
	owed := e.revocations.Pending()
	if len(owed) == 0 {
		return
	}
	if !SupportsRevocation(sess.Version()) {
		err := fmt.Errorf("%w: agent %s reconnected speaking protocol v%d",
			ErrRevocationUnsupported, e.id, sess.Version())
		for _, r := range owed {
			e.revocations.Fail(r.LeaseID, r.GrantID, RevokeStateFailed, err)
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
			e.revocations.Fail(r.LeaseID, r.GrantID, state, err)
			continue
		}
		e.revocations.Settle(r.LeaseID, r.GrantID, ack, e.opts.now())
		if e.opts.OnRevokeAck != nil {
			e.opts.OnRevokeAck(e.id, r.LeaseID, ack)
		}
	}
}
