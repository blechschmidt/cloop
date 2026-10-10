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
//   - cloop-lease-<handle>, the lease Secret: spec.SecretFiles, projected into
//     the workload as read-only volumes, and since Task 20401 every value of
//     the workload's environment, each read into the container through a
//     secretKeyRef when the kubelet created it.
//   - cloop-ws-<handle>, the workspace git credential, likewise referenced as
//     an environment variable through secretKeyRef.
//
// Deleting them is necessary and not sufficient, which is the part worth being
// precise about. The kubelet does not re-derive a projected volume from a
// Secret that no longer exists — it keeps serving the last content it
// synchronised, and a container that read a value into its own environment at
// start has a copy the API server cannot reach at all. So a Pod that is still
// running is deleted too. The task's own framing is the right one: evict the
// Pod when the material is already projected into a running container's volume
// or env.
//
// That escalation applies even to RevokeScrub, and moving the environment into
// the lease Secret changed none of it: an environment variable is still in the
// running process the moment the container exists, so env-borne material is
// kill-only exactly as it was when the value sat in the Pod spec. There is no
// weaker operation this backend can offer for material already inside a
// container, and reporting a scrub that did not happen is the failure this file
// exists to remove. The kill is reported, so the escalation is visible rather
// than surprising.
//
// # Why delete rather than patch
//
// The Role grants patch on Secrets (see rbac.go), but for one purpose: replacing
// a GitHub App token in a running Pod's files before it expires, which the
// kubelet syncs into the projected volume. Emptying the Secret by patch would
// reach the volume the same way and nothing else — the environment, and any
// copy the workload already made, stay — so it would buy nothing over deleting
// it. Deleting the Secret and the Pod is the operation that actually takes the
// material back.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// This driver is a Revoker. The assertion is load-bearing: placement refuses
// any workload carrying revocable credentials on a driver that does not
// implement this interface, so a signature drift here would take the Kubernetes
// backend out of service for leased work rather than fail a build.
var (
	_ executor.Revoker         = (*Executor)(nil)
	_ executor.SecretRefresher = (*Executor)(nil)
)

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

// RefreshSecretFiles implements executor.SecretRefresher: it replaces req's
// files in the lease Secret of every Pod holding the lease, and extends each
// Pod's output redaction to the new content (Task 20375).
//
// The Secret is mounted as a directory volume with no subPath, which is the one
// shape of Secret volume the kubelet keeps in sync with the object: it swaps
// the projected files atomically when the Secret changes. So the Pod reads the
// new content within the kubelet's sync period rather than at once, and the
// report says Eventual — the hub then leaves the superseded token to lapse on
// its own instead of destroying it while the Pod may still be reading it.
//
// The patch needs the "patch" verb on secrets, which the shipped RBAC grants;
// a Role from before Task 20375 refuses it, and the error says what to add.
func (e *Executor) RefreshSecretFiles(ctx context.Context, req executor.SecretRefreshRequest) executor.SecretRefreshReport {
	out := executor.SecretRefreshReport{LeaseID: strings.TrimSpace(req.LeaseID), Eventual: true}
	if err := req.Validate(); err != nil {
		out.Error = err.Error()
		return out
	}
	held := e.leases.Handles(executor.RevokeRequest{LeaseID: out.LeaseID})
	if len(held) == 0 {
		return out
	}
	out.Known = true
	values := req.Values()
	var errs []error
	for _, handleID := range executor.SortedHandles(held) {
		rec, err := e.lookup(handleID)
		if err != nil || rec.finished() {
			continue
		}
		st := rec.leaseSecretState()
		if st == nil {
			errs = append(errs, fmt.Errorf("pod for %s was adopted from a row written before this hub "+
				"process started, which does not record its lease Secret's keys", handleID))
			continue
		}
		cli := rec.client()
		if cli == nil {
			errs = append(errs, fmt.Errorf("pod for %s has no API client yet", handleID))
			continue
		}
		data := make(map[string][]byte, len(req.Files))
		for _, f := range req.Files {
			key, ok := st.keyFor(f.Path())
			if !ok {
				errs = append(errs, fmt.Errorf("%s was not delivered to the pod for %s", f.Path(), handleID))
				continue
			}
			data[key] = f.Content
		}
		if len(data) == 0 {
			continue
		}
		if rec.bus != nil {
			rec.bus.AddRedactions(values...)
		}
		name := leaseSecretName(handleID)
		if err := cli.patchSecretData(ctx, rec.namespace, name, data); err != nil {
			if ae, ok := asAPIError(err); ok && ae.Code == http.StatusForbidden {
				// The Role will refuse every later patch too: this executor
				// cannot take a refresh until an operator adds the verb.
				out.Unsupported = true
			}
			errs = append(errs, explainSecretFilePatchFailure(rec.namespace, name, err))
			continue
		}
		out.FilesRewritten += len(data)
		out.Handles = append(out.Handles, handleID)
	}
	if err := errors.Join(errs...); err != nil {
		out.Error = err.Error()
	}
	return out
}

// explainSecretFilePatchFailure turns a refused patch into an actionable error.
func explainSecretFilePatchFailure(namespace, name string, err error) error {
	if ae, ok := asAPIError(err); ok && ae.Code == http.StatusForbidden {
		return fmt.Errorf("kubernetes: not allowed to patch Secret %s/%s, which replacing a GitHub App "+
			"token before it expires needs: %w — add \"patch\" to the secrets rule of the executor's Role "+
			"(%s); until then the Pod keeps the token it was given, which GitHub stops honouring an hour "+
			"after dispatch", namespace, name, err, roleRuleFor("secrets").inline())
	}
	return fmt.Errorf("kubernetes: patch secret lease files %s/%s: %w", namespace, name, err)
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
	// *leaseSecretState — rehydrate rebuilds neither — but both Secret names
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
	if st := rec.leaseSecretState(); st != nil {
		st.mu.Lock()
		existed[leaseSecretName(handleID)] = st.secretName != "" && !st.deleted
		st.mu.Unlock()
	}
	if st := rec.workspace(); st != nil {
		st.mu.Lock()
		existed[workspaceSecretName(handleID)] = st.secretName != "" && !st.deleted
		st.mu.Unlock()
	}

	var errs []error
	for _, name := range []string{leaseSecretName(handleID), workspaceSecretName(handleID)} {
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
	markLeaseSecretDeleted(rec.leaseSecretState())
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

// markLeaseSecretDeleted records that the lease Secret is gone, so the cleanup
// paths skip it. Nil-safe: an adopted record has no state.
func markLeaseSecretDeleted(st *leaseSecretState) {
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

// Compile-time proof that a workload's output can be scrubbed of values
// learned after it started.
var _ executor.HandleRedactor = (*Executor)(nil)

// AddHandleRedactions implements executor.HandleRedactor: a handle adopted
// after a hub restart has no redaction set of its own, and the process that
// took its run's lease over hands the values here (Task 20382).
func (e *Executor) AddHandleRedactions(handleID string, values ...string) bool {
	rec, err := e.lookup(handleID)
	if err != nil {
		return false
	}
	if rec.bus != nil && len(values) > 0 {
		rec.bus.AddRedactions(values...)
	}
	return true
}
