package kubernetes

// rehydrate.go re-adopts the Pods this executor dispatched before the control
// plane restarted (Task 20191).
//
// # The failure it removes
//
// A Pod outlives the process that created it. That is the point of running
// work in a cluster, and it was also the hole: the handle map was the only
// record a Pod existed, so a hub that restarted came back with an empty map
// while the cluster kept scheduling, running and billing the Pods it had
// dispatched. Stream, Status and Signal all answered ErrHandleNotFound for
// them. The workload was simultaneously alive and unreachable — no output, no
// status, and no way to stop it short of `kubectl delete`.
//
// ReconcileOrphans did eventually clean up after that, but by killing: it
// deletes Pods this executor owns and no longer tracks, and after a restart
// that was every Pod in flight. For a Pod whose handle we persisted, killing
// is the wrong answer. The right one is to pick the handle back up, which is
// why adopt() inserts into the handle map *synchronously* — before New
// returns, before anything can call ReconcileOrphans — and only then does the
// cluster I/O on the adopted handle's own goroutine. A Pod that is tracked is
// never swept.
//
// # Why it works at all
//
// Nothing in the Kubernetes API cares which process created a Pod. A watch on
// metadata.name and a GET on .../log?follow=true attach to a Pod that has been
// running for an hour exactly as they attach to one created a moment ago, so
// an adopted record can run the *same* pump, the same log follower and the
// same lease renewer that Start runs, rather than a reduced "read-only"
// variant that would have to be kept in step with them forever. The log is
// re-read from the beginning, not tailed, so the reattached stream is the
// whole run and the write-back scanner sees a sentinel the previous process
// had already consumed.
//
// # What a row cannot carry
//
// Three things are gone with the process, and each is handled by saying so
// rather than by pretending:
//
//   - The kubeconfig lease. Leases are the broker's, not the row's, and a
//     persisted one would be a credential sitting in a table outliving the
//     grant that justified it. Adoption acquires a fresh lease through the
//     same Options.Credentials path Start uses, with the same project ID the
//     original dispatch used, so the grant is re-evaluated against current
//     policy — a run whose kubeconfig grant was revoked while the hub was down
//     is not silently resumed on authority that no longer exists. When the
//     acquisition fails the record is finished as failed, naming the cause;
//     claiming a Pod is fine while holding nothing that can observe or stop it
//     is the exact state this file exists to abolish.
//   - The Spec, deliberately (see pkg/executor/handles.go: it carries brokered
//     secret values in Env). The visible consequence is that an adopted record
//     does not know a write-back was *asked for*, so a run that produces no
//     report after a restart reads as "no write-back" instead of "a failed
//     one". A report that does arrive is still recorded, because the scanner
//     re-reads the log from the start.
//   - The workspace provisioning state. Its only job is to delete the
//     credential Secret once the init container has finished, and by the time
//     a hub has restarted the init container has either finished — in which
//     case the previous process deleted the Secret, or ReconcileOrphans will —
//     or the Pod is still Pending and the Secret is still needed.

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

// metaNetworkPolicy is the HandleRecord.Meta key under which a row carries the
// name of the egress NetworkPolicy created alongside its Pod.
//
// Unexported, matching the container driver's metaRuntime: the key is a
// persisted format, but the only code that has any business interpreting a
// driver's Meta map is that driver. A sweep outside this package needs to know
// a row exists, not what its extras mean. The value is a Kubernetes object
// name and never a secret — Meta is stored verbatim.
const metaNetworkPolicy = "network_policy"

// AttachHandleStore installs the durable handle store after construction and
// rehydrates from it immediately.
//
// It exists because of boot order, not convenience: the drivers are built from
// config before the state database is open, so the executor that most needs a
// store is constructed without one. Calling this later is equivalent to having
// passed Options.HandleStore, because rehydration is idempotent — a handle
// already in the map is left alone — so a caller that does both, or that
// re-attaches the same store on a config reload, adopts each Pod once.
//
// A nil store is ignored rather than clearing the current one: "forget how to
// find your Pods" is not something a caller should be able to ask for by
// passing a zero value.
func (e *Executor) AttachHandleStore(store executor.HandleStore) {
	if e == nil || store == nil {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.store = store
	e.mu.Unlock()
	e.rehydrate()
}

// handleStore returns the store, or nil when this executor persists nothing.
func (e *Executor) handleStore() executor.HandleStore {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store
}

// rehydrate adopts every persisted row this executor owns.
//
// Scoped to e.id by LoadHandles, which is what keeps two executors configured
// against the same cluster from stealing each other's Pods. A store that
// cannot be read yields nothing and logs, because a control plane that refused
// to boot over a stale row would leave the operator with no hub at all — the
// pre-Task-20191 behaviour is the floor, not a failure.
func (e *Executor) rehydrate() {
	store := e.handleStore()
	if store == nil {
		return
	}
	for _, persisted := range executor.LoadHandles(store, e.id) {
		e.adopt(persisted)
	}
}

// adopt rebuilds the live bookkeeping for one persisted row and puts the
// handle back in service.
//
// The split of work here is the load-bearing part. Everything that decides
// whether a Pod is *tracked* happens on the caller's goroutine, before this
// returns: parse the reference, build the record, insert it into the map. Only
// then does the goroutine start, because the first thing it does is lease a
// kubeconfig, and a hub with fifty adopted handles must not spend fifty broker
// round-trips inside New — nor leave fifty Pods swept as untracked while it
// does.
func (e *Executor) adopt(persisted executor.HandleRecord) {
	if d := strings.TrimSpace(persisted.Driver); d != "" && d != executor.KindKubernetes {
		// Rows are scoped by executor ID, and IDs are unique within a
		// registry, so this should be unreachable. It is checked anyway
		// because the one way to reach it — an operator renaming a container
		// executor onto a Kubernetes executor's old ID — would otherwise have
		// this driver treat a container name as a namespace/pod reference.
		fmt.Fprintf(os.Stderr, "kubernetes: executor %q ignoring handle %s: it belongs to the %s driver\n",
			e.id, persisted.HandleID, d)
		return
	}
	namespace, podName, ok := splitExternalID(persisted.ExternalID)
	if !ok {
		// Unusable identity: there is no Pod this row can be resolved to, so
		// it can never be adopted and would sit in the table forever. Dropping
		// it loses nothing — the Pod it referred to, if it exists, is still
		// labelled with this executor's ID and is collected by the orphan
		// sweep.
		fmt.Fprintf(os.Stderr, "kubernetes: executor %q dropping handle %s: %q is not a namespace/pod reference\n",
			e.id, persisted.HandleID, persisted.ExternalID)
		executor.ForgetHandle(e.handleStore(), persisted.HandleID)
		return
	}

	rec := &record{
		id:                persisted.HandleID,
		startedAt:         persisted.StartedAt,
		namespace:         namespace,
		podName:           podName,
		networkPolicyName: persisted.Meta[metaNetworkPolicy],
		// Running rather than pending, and the distinction is a claim about
		// what we know: a row only exists because Start created a Pod, so the
		// workload is at least dispatched. The first status update the watcher
		// delivers corrects it — including downwards, to pending, for a Pod
		// still pulling its image — and observePhase is written to allow that
		// because it refuses to move only *terminal* states backwards.
		state: executor.StateRunning,
		ready: make(chan struct{}),
	}
	// A fresh bus. The previous process's is gone with it, along with its
	// replay buffer, so a subscriber that attaches after adoption sees the
	// reattach banner and everything the re-opened log follower reads from the
	// start of the Pod's log — not a gap.
	rec.bus = logbus.New(rec.id, executor.StreamCombined, logbus.Options{})

	// Assigned before the record is published so nothing can observe a record
	// whose pump cannot be cancelled; Close reads this field to stop the
	// goroutines below.
	pumpCtx, cancelPump := context.WithCancel(context.Background())
	rec.cancelPump = cancelPump

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		cancelPump()
		return
	}
	if _, exists := e.handles[rec.id]; exists {
		// The idempotency guarantee AttachHandleStore documents. It also
		// covers the case that matters more: a handle this process already ran
		// to completion, whose row a failed delete left behind. Re-adopting it
		// would start a second pump against a Pod that is already gone and
		// walk a finished handle backwards into "running".
		e.mu.Unlock()
		cancelPump()
		return
	}
	e.handles[rec.id] = rec
	e.pruneLocked()
	e.mu.Unlock()

	rec.bus.Emit(fmt.Sprintf("[cloop] reattaching to pod %s/%s after a control-plane restart\n",
		namespace, podName))
	go e.resume(pumpCtx, rec, persisted.ProjectPath)
}

// resume is an adopted record's own goroutine: acquire the credential the
// record has none of, confirm the Pod is still there, then hand over to
// exactly the pump and renewer a fresh Start would have run.
func (e *Executor) resume(ctx context.Context, rec *record, projectPath string) {
	// markReady on every path out of the acquisition, including the panic
	// path, or a Signal that arrived mid-adoption waits until its caller's
	// context expires. It is idempotent, so the explicit call on the success
	// path below — which must not wait for the pump to return — is free.
	defer rec.markReady()
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "kubernetes: pod adoption panic recovered (handle %s): %v\n", rec.id, r)
			e.finish(rec, executor.StateFailed, -1, fmt.Sprintf("pod adoption panic: %v", r))
		}
	}()

	leaseCtx, cancelLease := context.WithTimeout(ctx, requestTimeout)
	creds, cli, err := e.connect(leaseCtx, projectPath)
	cancelLease()
	if err != nil {
		// No client means no watch, no logs and — the one that decides this —
		// no delete. A record left "running" here would be the pre-Task-20191
		// ghost with extra steps: visible in the UI, never advancing, never
		// stoppable. Failing it names the cause and hands the Pod to the
		// orphan sweep, which has its own credential path and its own grace
		// period. The row goes with it, so a revoked grant does not leave a
		// row that fails to adopt on every subsequent boot.
		msg := fmt.Sprintf("the control plane restarted and could not lease a kubeconfig to reattach to "+
			"pod %s/%s: %v — the Pod may still be running and will be collected by the next orphan sweep",
			rec.namespace, rec.podName, err)
		rec.bus.Emit("[cloop] " + msg + "\n")
		e.finish(rec, executor.StateFailed, -1, msg)
		return
	}
	if !rec.adoptClient(cli, creds.LeaseID, creds.ExpiresAt) {
		// Close raced the acquisition and already finished this record, so
		// finish has been past the point where it would have released either
		// of these. Undo by hand: a lease the broker still believes is held is
		// the leak this driver's whole credential contract is written against.
		cli.close()
		e.opts.Credentials.Release(creds.LeaseID)
		return
	}

	// One GET before handing over, purely to tell "gone" from "still there".
	// The pump would notice a missing Pod on its own, but it would classify it
	// through the eviction path — StateKilled, "deleted out from under this
	// run" — which describes a Pod that vanished while we were watching. This
	// one vanished while nobody was, and an operator reading the status
	// deserves the difference. Any *other* error is left to the pump, whose
	// list-then-watch loop already has the backoff and the failure budget for
	// a briefly unreachable API server; treating a timeout as a missing Pod
	// here would fail a healthy run over one slow request.
	if _, err := e.getPodWithClient(ctx, rec); err != nil {
		if ae, ok := asAPIError(err); ok && ae.NotFound() {
			msg := fmt.Sprintf("pod %s/%s no longer exists — it was deleted while the control plane "+
				"was down, so this run's outcome cannot be recovered", rec.namespace, rec.podName)
			rec.bus.Emit("[cloop] " + msg + "\n")
			// finish drops the row and, because the state is terminal, removes
			// the egress NetworkPolicy the row remembered — the reason its
			// name is persisted at all.
			e.finish(rec, executor.StateFailed, -1, msg)
			return
		}
	}

	// Released here and not one line earlier, which is the difference between
	// a correct status and a confusing one. markReady unblocks Signal, and
	// Signal's only lever is to delete the Pod; releasing it before the probe
	// let a Stop delete the Pod and the probe then report "no longer exists —
	// deleted while the control plane was down" for a Pod this process had
	// just deleted on the user's instruction. Waiting costs a stop request one
	// bounded GET and makes the probe mean what it says: what the cluster held
	// at the moment adoption looked, before this process touched anything.
	rec.markReady()

	// From here the adopted handle is indistinguishable from a started one.
	// A Pod that is already terminal simply makes the first pass through the
	// pump the last: watchToTerminal's initial list returns a terminal phase,
	// the log follower reads the Pod's log to EOF, and the record finishes
	// with the cluster's real exit status.
	go e.renewLoop(ctx, rec)
	e.pump(ctx, rec)
}

// --- adopted-record helpers -------------------------------------------

// adoptClient installs a freshly leased credential on an adopted record,
// reporting false when the record finished while the acquisition was in
// flight. The caller then owns the lease and the client and must release both:
// finish reads those fields once, and by then it had read nil.
func (r *record) adoptClient(cli *client, leaseID string, expiresAt time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return false
	}
	r.cli = cli
	r.leaseID = leaseID
	r.leaseExp = expiresAt
	return true
}

// markReady releases anything waiting for this record to have a client. Safe
// to call repeatedly and from several paths; only the first close happens.
func (r *record) markReady() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ready == nil {
		return
	}
	select {
	case <-r.ready:
	default:
		close(r.ready)
	}
}

// awaitClient blocks until an adopted record has been through adoption, or
// until ctx ends. Records created by Start hold a lease before they are
// published and carry no channel, so this returns immediately for them.
func (r *record) awaitClient(ctx context.Context) error {
	r.mu.Lock()
	ready := r.ready
	r.mu.Unlock()
	if ready == nil {
		return nil
	}
	select {
	case <-ready:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("kubernetes: handle %s is still reattaching to its Pod after a control-plane "+
			"restart: %w", r.id, ctx.Err())
	}
}

// --- row helpers ------------------------------------------------------

// externalIDFor renders the reference a Kubernetes row is found again by. A
// namespace and a Pod name each exclude "/", so the join is unambiguous and
// splitExternalID can recover both.
func externalIDFor(namespace, podName string) string {
	return namespace + "/" + podName
}

// splitExternalID parses that reference back. It reports false rather than
// guessing a namespace for a bare name: adopting into the wrong namespace
// would watch a Pod that is not this handle's, and deleting there would stop
// somebody else's.
func splitExternalID(external string) (namespace, podName string, ok bool) {
	ns, name, found := strings.Cut(strings.TrimSpace(external), "/")
	ns, name = strings.TrimSpace(ns), strings.TrimSpace(name)
	if !found || ns == "" || name == "" {
		return "", "", false
	}
	return ns, name, true
}

// handleMeta renders the driver extras a row carries. Nil when there is
// nothing to say, so an executor with no egress filter does not write "{}"
// worth of metadata for every Pod it starts.
func handleMeta(networkPolicyName string) map[string]string {
	if strings.TrimSpace(networkPolicyName) == "" {
		return nil
	}
	return map[string]string{metaNetworkPolicy: networkPolicyName}
}

// taskIDNumber renders the Spec's task label as HandleRecord's integer field.
//
// The two disagree by design: a Spec label is a string, and taskIDFrom returns
// the literal "none" for a workload with no task, while the row models the
// task as an int so a sweep can scope itself to one. Anything that is not a
// non-negative integer becomes 0, which the row's omitempty tag renders as
// absent — the honest reading of "this workload is not one of the numbered
// tasks", and never a claim about task 0.
func taskIDNumber(labels map[string]string) int {
	n, err := strconv.Atoi(taskIDFrom(labels))
	if err != nil || n < 0 {
		return 0
	}
	return n
}
