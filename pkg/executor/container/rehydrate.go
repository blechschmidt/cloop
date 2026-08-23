// Reattaching to containers a previous control plane started (Task 20191).
//
// The driver's handle map is in-memory, so before this file a hub that
// restarted came up believing it had dispatched nothing while its sandboxes
// kept running. Stream, Status and Signal all answered ErrHandleNotFound for
// containers that were alive and working: output nobody could read, CPU nobody
// could reclaim, and no way to stop them short of `podman kill` by hand.
//
// What makes reattachment possible at all is that the *runtime*, not this
// process, owns the workload. `docker logs --follow <name>` attaches to a
// container regardless of which process created it, and `docker wait <name>`
// returns its exit code to whoever asks. So rebuilding the live bookkeeping —
// a log bus and a pump goroutine — around a container name read back out of
// the handle store produces a handle indistinguishable from one Start
// returned, and does it without re-dispatching anything. Nothing here starts a
// container; that is the property that makes it safe to run unconditionally at
// construction.
//
// What cannot be rebuilt is anything that lived only in the Spec, because the
// Spec is deliberately not persisted (see pkg/executor/handles.go: it carries
// brokered secret values whose leases have usually expired by the time anyone
// reads the row).
//
// The one part of the Spec that had to survive is the timeout, and it does —
// as HandleRecord.Deadline, an absolute instant rather than the original
// duration. It gets a scalar of its own instead of riding along with a
// persisted Spec because it is the difference between an adopted workload that
// is bounded and one that is not, and an adopted container is *tracked*, so
// the orphan sweep will never collect it: without the deadline a runaway task
// that outlived a restart would run until the machine was rebooted, which is
// the failure mode this whole file exists to end.

package container

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

// metaRuntime is the HandleRecord.Meta key carrying the runtime that started
// the container ("podman" or "docker").
//
// It is recorded because ExternalID is only resolvable through the runtime
// that created it: podman and docker keep entirely separate container stores,
// so a hub reconfigured between restarts is reattaching against a namespace
// where its containers simply do not exist. Every call would fail, the run
// would be reported failed, and the operator would have no hint that the
// container is still alive under the other runtime. Storing the name turns
// that into one legible warning — see adopt.
const metaRuntime = "runtime"

// AttachHandleStore installs the durable handle store after construction and
// immediately reattaches to whatever it describes.
//
// It exists because of a construction-order problem with no tidy fix: the
// executor registry is built from configuration, early and synchronously,
// while the state database that backs the store is opened later by the process
// that needs it. Requiring the store at New would mean either opening the
// database before the config that names it has been validated, or leaving
// every executor that is legitimately storeless — `cloop executor test`,
// Preflight, the config validator — unable to construct at all.
//
// Calling it more than once is safe, including with a different store: see
// rehydrate for why re-adoption cannot produce a duplicate pump.
func (e *Executor) AttachHandleStore(store executor.HandleStore) {
	e.mu.Lock()
	e.store = store
	e.mu.Unlock()
	e.rehydrate()
}

// handleStore returns the durable store, or nil when the embedder gave none.
// Every caller must go through this rather than reading e.store directly:
// AttachHandleStore writes the field while the log pumps are running.
func (e *Executor) handleStore() executor.HandleStore {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store
}

// rehydrate rebuilds live bookkeeping for every persisted handle this executor
// is not already tracking.
//
// Idempotence is a requirement here rather than a nicety. New rehydrates,
// AttachHandleStore rehydrates, a caller may do both, and an operator swapping
// a store implementation may attach twice — and two adoptions of one row would
// mean two `logs --follow` followers duplicating every line into the same bus
// and two `wait` calls racing to finish the same record. The loser of that race
// is swallowed by finish's done guard, so it would go on to `rm` a name that no
// longer exists and log a spurious failure to remove it.
//
// Skipping by handle ID is what makes that safe: a row whose ID is already in
// e.handles is either being adopted a second time or belongs to a workload this
// process started, and both are already fully tracked.
//
// Failure to read the store is not propagated — LoadHandles reports it and
// returns nothing — because a hub that refuses to start over an unreadable
// handle table is strictly worse than one that starts having forgotten some
// containers. The forgotten ones are what ReapOrphans is for.
func (e *Executor) rehydrate() {
	store := e.handleStore()
	if store == nil {
		return
	}
	for _, saved := range executor.LoadHandles(store, e.id) {
		e.adopt(saved)
	}
}

// adopt rebuilds one record from its persisted identity and puts a log pump
// back on it.
//
// The record is created in the Running state, which is a claim rather than an
// observation: nothing has asked the runtime anything yet. The pump corrects it
// within milliseconds in every case, because all three possible worlds converge
// on finish —
//
//   - the container is still running: `logs --follow` streams until it exits
//     and `wait` then yields its real exit code, exactly as for a container
//     this process started.
//   - the container already exited but still exists: `logs --follow` returns
//     immediately with the backlog and `wait` returns the recorded exit code,
//     so the handle lands in its true terminal state and reap removes the
//     container.
//   - the container is gone entirely: `wait` fails, reap maps that to
//     StateFailed, and finish drops the row. That last part is the point — a
//     stale row that nothing can reattach to must be deleted rather than
//     re-adopted on every boot forever.
//
// The alternative of inspecting first and only adopting live containers was
// rejected because it puts a runtime round-trip per row into New, on the path
// that has to complete before the hub serves anything, for information the pump
// obtains anyway.
func (e *Executor) adopt(saved executor.HandleRecord) {
	if err := saved.Validate(); err != nil {
		// A row with no external ID names nothing the runtime can be asked
		// about. Adopting it would create a handle whose every operation fails
		// against the empty string; leaving it is harmless, since the sweep
		// works off container labels and not off this table.
		fmt.Fprintf(os.Stderr, "container: ignoring unusable persisted handle: %v\n", err)
		return
	}
	if saved.Driver != "" && saved.Driver != executor.KindContainer {
		// Rows are already scoped by executor ID and the registry forbids two
		// executors sharing one, so this should be unreachable. It is checked
		// anyway because the failure it prevents is silent and destructive:
		// adopting a Kubernetes row would spawn `docker logs --follow
		// namespace/pod`, which fails, which finishes a live Pod's handle as
		// failed and deletes the row that was the only way to find it again.
		fmt.Fprintf(os.Stderr, "container: ignoring persisted handle %s: it belongs to the %s driver\n",
			saved.HandleID, saved.Driver)
		return
	}
	if was := saved.Meta[metaRuntime]; was != "" && was != e.rt.Name {
		// Warn and adopt anyway. The adoption will fail and mark the handle
		// failed, which is the correct answer for *this* executor — it genuinely
		// cannot reach that container — and it clears the row. What the operator
		// needs to know is that a live sandbox has been left behind under a
		// runtime nothing is watching any more, and only this line can tell them.
		fmt.Fprintf(os.Stderr,
			"container: handle %s was started by %s but this executor runs %s; reattachment will fail — "+
				"the %s container %s may still be running and has to be stopped by hand\n",
			saved.HandleID, was, e.rt.Name, was, saved.ExternalID)
	}

	e.mu.Lock()
	if _, exists := e.handles[saved.HandleID]; exists {
		e.mu.Unlock()
		return
	}
	rec := &record{
		id:        saved.HandleID,
		name:      saved.ExternalID,
		startedAt: saved.StartedAt,
		state:     executor.StateRunning,
	}
	// The bus is built under the lock because it is pure allocation, and doing
	// it before the existence check would leave an orphaned bus on the
	// already-adopted path.
	rec.bus = logbus.New(rec.id, executor.StreamCombined, logbus.Options{})
	e.handles[rec.id] = rec
	// Adopted records are Running, and pruneLocked only ever drops terminal
	// ones, so this can trim the finished residue of an earlier adoption but
	// can never evict the workload we just reattached to.
	e.pruneLocked()
	e.mu.Unlock()

	// Re-arm the timeout. The deadline is persisted as an absolute instant, so
	// what resumes is the *remaining* time: a hub down for twenty minutes
	// gives a one-hour workload its last forty, rather than restarting the
	// hour — which a persisted duration would have done, silently extending
	// every timeout by the length of the outage.
	//
	// A deadline that already passed while the control plane was down arms at
	// zero and kills on the next tick. That is the point: the timeout expired,
	// and nobody having been there to enforce it is not a reprieve. This is
	// also the only thing standing between a restart and an unbounded runaway,
	// since an adopted container is *tracked* and therefore invisible to the
	// orphan sweep that would otherwise eventually collect it.
	if !saved.Deadline.IsZero() {
		e.armKillTimer(rec, time.Until(saved.Deadline),
			fmt.Sprintf("timeout expired at %s (deadline resumed after a control-plane restart)",
				saved.Deadline.UTC().Format(time.RFC3339)))
	}
	//
	// The pump is given a background context rather than a request one because
	// there is no request; it is stopped by cancelPump when the record
	// finishes, which is the same lifetime start() gives it. Every runtime call
	// reattachment makes happens on this goroutine, which is what keeps New
	// from blocking on a wedged runtime socket.
	pumpCtx, cancelPump := context.WithCancel(context.Background())
	rec.cancelPump = cancelPump
	go e.pump(pumpCtx, rec)
}
