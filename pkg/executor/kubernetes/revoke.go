package kubernetes

// revoke.go implements executor.Revoker for the Kubernetes driver: taking a
// secret lease's material back from a Pod that is already running.
//
// # Why this needed writing at all
//
// Nothing in this driver had ever consulted Spec.RevocableSecrets, and the
// driver exposed no revocation entry point. A kubeconfig or a GitHub PAT leased
// to an in-cluster Pod could not be withdrawn until the task ended on its own,
// while the Executors panel reported the backend as revocable because it was
// not a remote agent. The TTL on the lease and the push revocation built on top
// of it were, on this backend, comments.
//
// # What a revocation can and cannot reach here
//
// Two objects hold brokered material for a run, and both are deleted:
//
//   - cloop-lease-<handle>, the Secret behind spec.SecretFiles, projected into
//     the workload as read-only volumes.
//   - cloop-ws-<handle>, the workspace git credential, referenced as an
//     environment variable through secretKeyRef.
//
// Deleting them is necessary and not sufficient, which is the part worth being
// precise about. The kubelet does not re-derive a projected volume from a
// Secret that no longer exists — it keeps serving the last content it
// synchronised, and a container that read the value into its own environment at
// start has a copy the API server cannot reach at all. So a Pod that is still
// running is deleted too. The task's own framing is the right one: evict the
// Pod when the material is already projected into a running container's volume
// or env.
//
// That escalation applies even to RevokeScrub. There is no weaker operation
// this backend can offer for material already inside a container, and reporting
// a scrub that did not happen is the failure this file exists to remove. The
// kill is reported, so the escalation is visible rather than surprising.
//
// # Why delete rather than patch
//
// client.go grants itself three verbs — create, delete, list — and the shipped
// RBAC matches. Emptying a Secret by PATCH would leave the volume projected and
// the Pod running, so it would buy nothing over deleting it, in exchange for a
// permission the hub does not currently need. Deleting the Secret and the Pod
// is the operation that actually takes the material back.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// This driver is a Revoker. The assertion is load-bearing: placement refuses
// any workload carrying revocable credentials on a driver that does not
// implement this interface, so a signature drift here would take the Kubernetes
// backend out of service for leased work rather than fail a build.
var _ executor.Revoker = (*Executor)(nil)

// SupportsRevocation reports whether a revocation issued now would be honoured.
//
// True whenever the executor is open. Unlike a remote agent, there is no peer
// whose protocol version or connectivity the guarantee depends on: the objects
// are in the API server, and the same client that created them deletes them. A
// closed executor answers false — its clients are shut and it can reach
// nothing.
func (e *Executor) SupportsRevocation() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed
}

// HoldsLease reports whether any Pod this executor tracks was started with
// material from leaseID.
func (e *Executor) HoldsLease(leaseID string) bool { return e.leases.Holds(leaseID) }

// Leases lists the lease IDs this executor is holding material for.
func (e *Executor) Leases() []string { return e.leases.Leases() }

// Revocations reports this executor's revocation log for the Secrets panel.
func (e *Executor) Revocations() []executor.RevokeOutcome { return e.revocations.Snapshot() }

// RevokeLease takes one lease's material back from every Pod holding it.
//
// It returns an outcome rather than an error for the reason the remote driver
// documents: the caller's next move depends on which failure, and an error
// alone cannot say whether the material is gone, in doubt, or still out there.
// The log entry is written before any deletion starts, so a revocation is never
// lost to a crash between the two.
func (e *Executor) RevokeLease(ctx context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	if ctx == nil {
		ctx = context.Background()
	}
	now := e.now()
	out := executor.RevokeOutcome{
		LeaseID:    strings.TrimSpace(req.LeaseID),
		GrantID:    strings.TrimSpace(req.GrantID),
		ExecutorID: e.id,
		Action:     req.Effective(),
		Reason:     req.Reason,
		State:      executor.RevokeStatePending,
		SentAt:     now,
	}
	if out.LeaseID == "" {
		out.State = executor.RevokeStateFailed
		out.Error = "revoke requires a lease id"
		return out
	}
	e.revocations.Record(out)

	ack := executor.RevokeReport{
		LeaseID: out.LeaseID,
		GrantID: out.GrantID,
		Action:  out.Action,
	}

	// Handles this driver adopted from a persisted row that did not record its
	// lease bindings. They might be holding the lease being revoked and there
	// is no second authority to ask — unlike the remote driver, whose agent
	// answers for its own device, the index below is the *only* record
	// that a Pod was ever given a credential. So the doubt
	// travels onto the report, which turns the outcome failed: an operator
	// reading "revoked" here has to be able to act on it.
	unresolved := e.leases.UnresolvedError()

	held := e.leases.Handles(req)
	if len(held) == 0 {
		// Not holding it is a success, not a failure: "the material is not
		// here" is the end state the revocation asked for. Known says which of
		// the two happened, so an operator can tell "deleted it" from "there
		// was nothing to delete" — the difference matters when the question is
		// where a leaked credential went.
		e.settle(&out, ack, unresolved)
		return out
	}
	ack.Known = true

	var errs []error
	for _, handleID := range executor.SortedHandles(held) {
		removed, killed, err := e.revokeHandle(ctx, handleID, held[handleID])
		ack.FilesRemoved += removed
		if killed {
			ack.Killed = append(ack.Killed, handleID)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	e.settle(&out, ack, errors.Join(append(errs, unresolved)...))
	return out
}

// settle finalises an outcome and its log entry from one report.
func (e *Executor) settle(out *executor.RevokeOutcome, ack executor.RevokeReport, err error) {
	if err != nil {
		ack.Error = err.Error()
	}
	at := e.now()
	e.revocations.Settle(out.LeaseID, out.GrantID, ack, at)
	out.AckedAt, out.Ack = at, &ack
	if ack.Error != "" {
		out.State, out.Error = executor.RevokeStateFailed, ack.Error
		return
	}
	out.State = executor.RevokeStateRevoked
}

// revokeHandle deletes one Pod's credential Secrets and, when the Pod is still
// running, the Pod itself.
//
// removed counts Secrets deleted rather than files, because a Secret is the
// unit this backend can actually destroy: the files inside it are projected
// copies the API server does not address individually.
func (e *Executor) revokeHandle(ctx context.Context, handleID string,
	bindings []executor.SecretBinding) (removed int, killed bool, err error) {

	rec, lookupErr := e.lookup(handleID)
	if lookupErr != nil {
		// The handle went away between the index read and here — the workload
		// finished, and finish() deleted its Secrets. Nothing to do and nothing
		// wrong; drop the stale index entry so a second revocation does not
		// chase it again.
		e.leases.Release(handleID)
		return 0, false, nil
	}

	// A record adopted after a hub restart has no *workspaceState and no
	// *secretFilesState — rehydrate rebuilds neither — but both Secret names
	// are pure functions of the handle ID, so they are derived rather than
	// read. That is what makes this function correct for an adopted record,
	// and it is why closing the restart gap (Task 20231) needed no change
	// here: adopt now restores the lease→handle index from the persisted
	// bindings, so an adopted Pod answers HoldsLease truthfully and arrives in
	// this function with its Secret names derivable exactly as a freshly
	// started one's are.
	cli := rec.client()
	if cli == nil {
		return 0, false, fmt.Errorf(
			"handle %s: no API client yet (the executor is still leasing a kubeconfig), so %s "+
				"could not be deleted; retry the revocation",
			handleID, executor.DescribeBindings(bindings))
	}

	// Whether each Secret was ever created, so the count reported back is what
	// was actually taken away. deleteSecret maps NotFound to success — correct
	// for an idempotent cleanup, useless as evidence — so counting every call
	// would report "2 credentials removed" for a run that had neither. An
	// operator reading that number after an incident is asking what was out
	// there, and an inflated answer is worse than a missing one.
	//
	// An adopted record has no bookkeeping to consult, so its deletes are
	// issued (the names are pure functions of the handle ID) but not counted.
	// Understating is the safe direction: Known is still true, and the
	// operator is not told a credential was destroyed on this evidence.
	existed := map[string]bool{}
	if st := rec.leaseFilesState(); st != nil {
		st.mu.Lock()
		existed[secretFilesSecretName(handleID)] = st.secretName != "" && !st.deleted
		st.mu.Unlock()
	}
	if st := rec.workspace(); st != nil {
		st.mu.Lock()
		existed[workspaceSecretName(handleID)] = st.secretName != "" && !st.deleted
		st.mu.Unlock()
	}

	var errs []error
	for _, name := range []string{secretFilesSecretName(handleID), workspaceSecretName(handleID)} {
		if err := cli.deleteSecret(ctx, rec.namespace, name); err != nil {
			errs = append(errs, fmt.Errorf("delete secret %s/%s: %w", rec.namespace, name, err))
			continue
		}
		if existed[name] {
			removed++
		}
	}
	// Mark the driver's own bookkeeping deleted so the cleanup paths do not
	// issue a second delete and log a spurious 404. Both are nil for an
	// adopted record, and both tolerate that.
	markSecretFilesDeleted(rec.leaseFilesState())
	markWorkspaceSecretDeleted(rec.workspace())

	// The Pod is the part the API server cannot reach into. A running
	// container holds the projected volume and its own environment, neither of
	// which a deleted Secret withdraws, so the Pod goes too.
	if rec.finished() {
		return removed, false, errors.Join(errs...)
	}
	if delErr := e.terminateForRevocation(ctx, rec, bindings); delErr != nil {
		errs = append(errs, delErr)
		return removed, false, errors.Join(errs...)
	}
	e.leases.Release(handleID)
	return removed, true, errors.Join(errs...)
}

// terminateForRevocation deletes the Pod, recording why.
//
// It mirrors Signal's shape rather than calling it: Signal is the operator's
// Stop button and records "stopped by a request", which would leave the run's
// own transcript unable to say that a withdrawn credential was the cause.
func (e *Executor) terminateForRevocation(ctx context.Context, rec *record,
	bindings []executor.SecretBinding) error {

	rec.mu.Lock()
	if rec.done || rec.state.Terminal() {
		rec.mu.Unlock()
		return nil
	}
	rec.killRequested = true
	if rec.errMsg == "" {
		rec.errMsg = fmt.Sprintf(
			"the workload was stopped because %s was revoked; the material was already projected "+
				"into a running container, which no API can take back", executor.DescribeBindings(bindings))
	}
	cli := rec.cli
	rec.mu.Unlock()
	if cli == nil {
		return fmt.Errorf("kubernetes: no API client for pod %s/%s", rec.namespace, rec.podName)
	}

	delCtx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	if err := cli.deletePod(delCtx, rec.namespace, rec.podName, e.opts.KillGracePeriod); err != nil {
		return fmt.Errorf("delete pod %s/%s: %w", rec.namespace, rec.podName, err)
	}
	// Force the watcher to re-list now, for the reason Signal does: a watch
	// that missed the DELETED event would leave the task showing "running"
	// until its own timeout expired, and an operator who just revoked a
	// credential is watching for exactly that transition.
	rec.interruptWatch()
	return nil
}

// markSecretFilesDeleted records that the credential-file Secret is gone, so
// the cleanup paths skip it. Nil-safe: an adopted record has no state.
func markSecretFilesDeleted(st *secretFilesState) {
	if st == nil {
		return
	}
	st.mu.Lock()
	st.deleted = true
	st.mu.Unlock()
}

// markWorkspaceSecretDeleted does the same for the workspace credential.
func markWorkspaceSecretDeleted(st *workspaceState) {
	if st == nil {
		return
	}
	st.mu.Lock()
	st.deleted = true
	st.mu.Unlock()
}
