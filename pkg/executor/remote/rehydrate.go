package remote

// rehydrate.go re-adopts the workloads this executor dispatched to its device
// before the control plane restarted (Task 20191).
//
// # The failure it removes
//
// A remote workload outlives the process that dispatched it more completely
// than any other driver's, because it is not even on the same machine. The
// handle map was the only record that it existed, and the map is in memory, so
// a hub that restarted came back believing it had dispatched nothing while the
// device kept running the harness.
//
// That would have been merely bad — Stream, Status and Signal answering
// ErrHandleNotFound for a live run — except that this driver has a reconnect
// protocol, and the reconnect protocol made it permanent. The agent offers its
// surviving handles in the hello; reconcileResume answered from the empty map
// and refused every one; the agent read the refusal as "stop reporting" and
// dropped its bookkeeping without stopping the process. The result was a
// harness running forever on an edge device, output discarded, invisible to the
// UI, with no reaper on either side. Nothing about it looked wrong from the
// control plane: the run had simply vanished.
//
// Adoption is what makes the offer matchable again, and it is the *only* thing
// that turns a restart back into the transient event the resume protocol was
// designed for. Its counterpart is in reconcileResume: an offer that still does
// not match is now answered with an explicit terminate rather than with
// silence, so the two halves together mean a workload is either picked back up
// or stopped, and never left orphaned.
//
// # Why it works at all
//
// Almost nothing has to be rebuilt. The device holds the process, its output
// buffer and its exit code; this side holds only a name, a log bus and a
// status. So adoption is a map insert and a fresh bus — no I/O, no round trip,
// nothing that can block — and the reconnecting agent supplies everything else
// over the session it was going to open anyway. That is why this runs
// synchronously inside NewExecutor: it must be finished before the hub's
// listener can accept the agent whose offer it exists to match.
//
// # What a row cannot carry
//
// The log offset, and that is the interesting one. HandleRecord has no offset
// field and adding a durable counter updated on every chunk would put a
// database write in the path of every 32 KiB of output, so an adopted handle
// starts at receivedOffset 0 and asks the device for everything it still has.
// See adopt for why that is safe, bounded, and honestly labelled.
//
// The Spec is gone too (see pkg/executor/handles.go: it carries brokered secret
// values in Env). For this driver that costs less than for the others, because
// the Spec was never executed here — the device holds its own copy. What is
// lost is Spec.WriteBack: an adopted handle does not know a work product was
// asked for. The device does, and sends it anyway; writeback.go accepts result
// frames on any tracked handle, so the bundle still lands.

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

// AttachHandleStore installs the durable handle store after construction and
// rehydrates from it immediately.
//
// It exists because of boot order rather than convenience: the hub builds an
// executor per enrolled agent from the enrollment store, which is open long
// before the state database that backs handle persistence. Calling this later
// is equivalent to having passed Options.HandleStore, because adoption is
// idempotent — a handle already in the map is left alone — so a caller that
// does both, or that re-attaches on a config reload, adopts each workload once.
//
// A nil store is ignored rather than clearing the current one. "Forget how to
// recognise your device's workloads" is not something a caller should be able
// to ask for by passing a zero value, and the consequence of granting it would
// be that the next reconnect terminates every run in flight.
func (e *Executor) AttachHandleStore(store executor.HandleStore) {
	if e == nil || store == nil {
		return
	}
	e.mu.Lock()
	e.store = store
	e.mu.Unlock()
	e.rehydrate()
}

// handleStore returns the durable store, or nil when this executor persists
// nothing. Every caller goes through here rather than reading e.store directly:
// AttachHandleStore writes the field while a session's read loop is already
// calling applyStatus.
func (e *Executor) handleStore() executor.HandleStore {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.store
}

// rehydrate adopts every persisted row this executor owns.
//
// Scoped to e.id by LoadHandles, which is what keeps two hubs sharing a state
// database from claiming each other's devices' work — and, more to the point
// here, what stops one agent's executor from accepting a resume offer for a
// handle another agent is running.
//
// A store that cannot be read yields nothing and logs, because a control plane
// that refused to boot over a stale row would leave the operator with no hub at
// all. The pre-Task-20191 behaviour is the floor, not a failure.
func (e *Executor) rehydrate() {
	store := e.handleStore()
	if store == nil {
		return
	}
	for _, persisted := range executor.LoadHandles(store, e.id) {
		e.adopt(persisted)
	}
}

// adopt rebuilds the live bookkeeping for one persisted row and puts the handle
// back in service.
//
// The record is created Running, which is a claim rather than an observation:
// nothing has spoken to the device yet. It is corrected by the first thing that
// does, and every path converges. The agent reconnects and offers the handle —
// reconcileResume matches it and streaming resumes. The agent reconnects
// without it, because the device rebooted and lost the process — the first
// heartbeat's handle list omits it and reconcileActive resolves it failed,
// which drops the row. The agent never reconnects — Status reports
// StateUnknown, which is this driver's documented answer for an unreachable
// device and was already what a caller saw.
//
// Pending was rejected as the initial state for the second of those: pending
// handles are exempt from reconcileActive, on the grounds that a start may
// still be in flight — so an adopted handle left pending would be the one thing
// that never resolves.
func (e *Executor) adopt(persisted executor.HandleRecord) {
	if err := persisted.Validate(); err != nil {
		// A row with no handle ID names nothing an agent could offer back, so
		// adopting it would create a handle nothing can ever reach. Left in
		// place rather than deleted: it identifies nothing this driver can act
		// on, but a cross-driver sweep reading the whole table may still make
		// sense of it.
		fmt.Fprintf(os.Stderr, "remote: executor %q ignoring unusable persisted handle: %v\n", e.id, err)
		return
	}
	if d := strings.TrimSpace(persisted.Driver); d != "" && d != executor.KindRemoteAgent {
		// Rows are scoped by executor ID and IDs are unique within a registry,
		// so this should be unreachable. It is checked anyway because the one
		// way to reach it — an operator enrolling an agent under an ID a
		// container executor used to hold — would otherwise have this driver
		// accept a resume offer for a container name, and answer a status
		// request about it with fabricated confidence.
		fmt.Fprintf(os.Stderr, "remote: executor %q ignoring handle %s: it belongs to the %s driver\n",
			e.id, persisted.HandleID, d)
		return
	}
	if ext := strings.TrimSpace(persisted.ExternalID); ext != "" && ext != persisted.HandleID {
		// For this driver the two are the same string by construction: the
		// control plane mints the handle and the agent offers that exact ID
		// back. A disagreement means the row was not written by Start, so warn
		// and adopt under the handle ID anyway — that is the key the agent will
		// use, and refusing would leave a live workload unmatchable for the sake
		// of a field nothing consults.
		fmt.Fprintf(os.Stderr,
			"remote: handle %s was persisted with external id %q; adopting under the handle id, "+
				"which is what agent %s offers on reconnect\n", persisted.HandleID, ext, e.id)
	}

	hs := &handleState{
		id:        persisted.HandleID,
		startedAt: persisted.StartedAt,
		bus:       logbus.New(persisted.HandleID, executor.StreamCombined, logbus.Options{Now: e.opts.now}),
		status: executor.Status{
			HandleID:   persisted.HandleID,
			ExecutorID: e.id,
			State:      executor.StateRunning,
			StartedAt:  persisted.StartedAt,
		},
		// receivedOffset stays 0, and that is a decision rather than an
		// omission. No offset was persisted — see the file header for why a
		// durable counter was rejected — so the choices are to ask the device
		// for everything it still holds, or to invent a number. Inventing one is
		// unsafe in the direction that matters: an ack above what this process
		// actually has tells the agent to discard those bytes from its retain
		// buffer, and they are then gone from both sides.
		//
		// Asking for 0 is bounded, not a replay of the whole run. The device's
		// buffer is capped (agent.DefaultRetainBytes, 1 MiB) and retainBuffer's
		// Slice clamps a request below its window up to the window's start, so
		// the agent resends at most what it retained and labels it with its true
		// offset. appendLog then sees a chunk starting above receivedOffset and
		// records the gap by itself.
		//
		// gapped is set here regardless, because the arithmetic cannot catch
		// every case: a workload that produced output before the restart and
		// none after resends nothing at all, and a device that never reconnects
		// sends nothing ever. Both would leave an empty log flagged complete.
		// The flag can only be conservative in the other direction — a run whose
		// entire output the device still holds and replays gets labelled partial
		// when it is not — and between "this log may be missing its start" and
		// "here is the whole run", only the first is safe to be wrong about.
		gapped: true,
	}

	e.mu.Lock()
	if _, exists := e.handles[hs.id]; exists {
		// The idempotency AttachHandleStore documents. It also covers the case
		// that matters more: a handle this process started, whose row a failed
		// delete left behind. Re-adopting it would walk a finished handle
		// backwards into "running" and hand its subscribers a second, empty bus.
		e.mu.Unlock()
		return
	}
	e.handles[hs.id] = hs
	// Adopted handles are Running and pruneLocked only evicts terminal ones, so
	// this can trim the finished residue of an earlier boot but can never evict
	// the workload just reattached to.
	e.pruneLocked()
	e.mu.Unlock()

	// A banner rather than silence: the log a subscriber is about to read
	// begins mid-run, and a transcript that starts abruptly in the middle of a
	// build is otherwise indistinguishable from a harness that produced
	// nonsense.
	hs.bus.Emit(fmt.Sprintf(
		"[cloop] the control plane restarted; reattaching to this workload on agent %s. "+
			"Output produced before the restart is not repeated here unless the device still holds it.\n",
		e.id))
}

// taskIDFromLabels extracts the cloop task ID a Spec was dispatched for.
//
// executor.Spec has no typed task field — task identity travels in Labels — so
// this is a parse, not a field read. The key list mirrors the container and
// Kubernetes drivers' so one driver's rows are not searchable by a key the
// others' are not.
//
// Zero means "not task-bound", which is the honest answer for a smoke test and
// is what HandleRecord.TaskID documents zero to mean. A label that is present
// but unparsable also yields zero rather than an error: a row that identifies
// the workload is worth storing even when the bookkeeping metadata on it is
// junk.
func taskIDFromLabels(labels map[string]string) int {
	for _, key := range []string{"task_id", "task", "taskid"} {
		if n, err := strconv.Atoi(strings.TrimSpace(labels[key])); err == nil && n > 0 {
			return n
		}
	}
	return 0
}
