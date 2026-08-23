// Durable handle identity (Task 20191).
//
// Every driver keeps its handle map in memory. That is the right place for
// the *live* bookkeeping — a log bus, a kill timer, a cancel func — but it
// made the map the only record that a workload exists at all. A control plane
// that restarts therefore came up believing it had dispatched nothing, while
// the containers, Pods and edge-device processes it had dispatched kept
// running. Stream, Status and Signal all answered ErrHandleNotFound for them,
// so the workload was simultaneously alive and unreachable: no output, no
// status, no way to stop it.
//
// The fix is to split identity from liveness. A HandleRecord carries only what
// is needed to *find* a workload again — which driver, which executor, and the
// external name the runtime knows it by — and that survives the process. The
// live bookkeeping is then rebuilt from it on the next start ("rehydration"),
// which is exactly what the runtime already lets us do: `docker logs -f` and
// `kubectl logs -f` attach to a container nobody started in this process just
// as happily as to one we did.
//
// What is deliberately *not* persisted: the Spec. It carries Spec.Env, which
// holds brokered secret values, and a handle record outlives the lease those
// values came from. Failover already persists a spec where it must
// (executor_sessions.spec_json, written by the control plane, not the driver);
// duplicating it here would widen the blast radius of a stolen state database
// for no gain, because rehydration reattaches to a *running* workload and
// never re-dispatches one.

package executor

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// HandleRecord is the durable identity of one dispatched workload: enough to
// find it again after the control plane restarts, and nothing more.
//
// It is a value type with no pointers so a driver can hand one to a store
// without worrying about the store retaining a reference into live state.
type HandleRecord struct {
	// HandleID is the driver-side handle, unique within ExecutorID. It is the
	// key callers hold, so it is the primary key here too.
	HandleID string `json:"handle_id"`
	// ExecutorID is the executor instance that owns the workload. Rehydration
	// is scoped by it: a driver adopts only its own rows, so two container
	// executors configured against the same runtime never steal each other's
	// containers.
	ExecutorID string `json:"executor_id"`
	// Driver is the Kind* constant of the owning driver, recorded so a sweep
	// can reason about rows whose executor is no longer registered (a
	// container executor removed from config still left containers behind).
	Driver string `json:"driver"`
	// ExternalID is the name the *runtime* knows the workload by, and is the
	// whole point of the record. Its shape is driver-specific:
	//
	//   localprocess  the OS process ID, rendered as decimal
	//   container     the container name
	//   kubernetes    "namespace/podname"
	//   remote        the agent-side handle ID (same as HandleID; the agent
	//                 offers it back on reconnect)
	//
	// It is a string rather than a typed union because nothing outside the
	// owning driver interprets it — the sweep only needs to know a row exists.
	ExternalID string `json:"external_id"`
	// ProjectPath and TaskID identify the work, so an operator reading the
	// table can tell what an orphan was doing and a sweep can scope itself to
	// one project.
	ProjectPath string `json:"project_path,omitempty"`
	TaskID      int    `json:"task_id,omitempty"`
	// PID is the OS process ID where one is meaningful (localprocess), 0
	// elsewhere. Duplicated from ExternalID for localprocess because a
	// typed field is what the liveness check wants.
	PID int `json:"pid,omitempty"`
	// Image is the resolved image reference, for drivers that have one.
	Image string `json:"image,omitempty"`
	// StartedAt is when the workload began, in the control plane's clock. The
	// orphan sweep compares it against a grace period, so it must be the
	// dispatch time and not the time the row was written.
	StartedAt time.Time `json:"started_at"`
	// Deadline is when Spec.TimeoutMinutes expires, or the zero time for an
	// unbounded workload.
	//
	// It is stored as an absolute instant rather than as the original
	// duration because the two disagree in exactly the case it exists for: a
	// hub down for twenty minutes must resume a one-hour timeout with forty
	// minutes left, not restart the hour. A duration would silently extend
	// every timeout by the length of the outage.
	//
	// Drivers whose backend enforces the deadline itself leave this zero and
	// say so — the Kubernetes driver hands the API server
	// activeDeadlineSeconds, which already survives a control-plane restart
	// and is the reason a client-side timer was the wrong mechanism there in
	// the first place. It is the drivers holding a time.AfterFunc in this
	// process (container, localprocess) that lose their timer on a restart
	// and need this to re-arm.
	Deadline time.Time `json:"deadline,omitempty"`
	// Meta carries driver-specific extras that do not deserve a column —
	// a Kubernetes NetworkPolicy name, a container's runtime. Never secrets:
	// this map is persisted verbatim.
	Meta map[string]string `json:"meta,omitempty"`
}

// Validate reports whether the record carries enough identity to be useful.
// A row with no external ID cannot be reattached to, so storing one would
// create an orphan that the sweep can see but never clean up.
func (r HandleRecord) Validate() error {
	if strings.TrimSpace(r.HandleID) == "" {
		return fmt.Errorf("executor: handle record needs a handle id")
	}
	if strings.TrimSpace(r.ExecutorID) == "" {
		return fmt.Errorf("executor: handle record %q needs an executor id", r.HandleID)
	}
	if strings.TrimSpace(r.ExternalID) == "" {
		return fmt.Errorf("executor: handle record %q needs an external id", r.HandleID)
	}
	return nil
}

// HandleStore persists handle identity across control-plane restarts.
//
// It is deliberately three methods. Drivers write one row when they dispatch,
// drop it when the workload reaches a terminal state, and read their own rows
// back at construction; anything richer would be a query surface for the UI,
// which reads executor_sessions instead.
//
// Implementations must be safe for concurrent use: Start is called from
// request goroutines and DeleteHandle from log-pump goroutines.
type HandleStore interface {
	// PutHandle inserts or replaces the row for rec.HandleID.
	PutHandle(rec HandleRecord) error
	// ListHandles returns the rows owned by executorID, oldest first.
	// Passing "" returns every row, which is what a cross-driver sweep wants.
	ListHandles(executorID string) ([]HandleRecord, error)
	// DeleteHandle forgets one row. Deleting a row that is not there is not
	// an error: a terminal transition can be recorded twice (once by the log
	// pump, once by an explicit reap) and neither call should fail.
	DeleteHandle(handleID string) error
}

// RecordHandle persists rec, reporting failure without propagating it.
//
// Persistence is best-effort by design. A workload that started successfully
// must not be reported as failed because the state database was momentarily
// locked: the caller would mark the task failed and retry it, producing the
// double execution the whole scheduling layer exists to prevent. A lost row
// degrades to exactly the behaviour that existed before this file — the
// workload becomes unobservable after a restart — which is strictly better
// than losing the workload now.
func RecordHandle(store HandleStore, rec HandleRecord) {
	if store == nil {
		return
	}
	if err := rec.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "executor: not persisting handle: %v\n", err)
		return
	}
	if err := store.PutHandle(rec); err != nil {
		fmt.Fprintf(os.Stderr, "executor: could not persist handle %s (%s): %v\n",
			rec.HandleID, rec.ExecutorID, err)
	}
}

// ForgetHandle drops rec's row once the workload is terminal. Same
// best-effort contract as RecordHandle: a row that outlives its workload is
// swept by the orphan reaper, so failing loudly here would buy nothing.
func ForgetHandle(store HandleStore, handleID string) {
	if store == nil || strings.TrimSpace(handleID) == "" {
		return
	}
	if err := store.DeleteHandle(handleID); err != nil {
		fmt.Fprintf(os.Stderr, "executor: could not forget handle %s: %v\n", handleID, err)
	}
}

// LoadHandles reads executorID's rows for rehydration, reporting failure
// without propagating it.
//
// A driver that cannot read its rows must still construct: refusing to would
// take down a control plane whose only real problem is a stale row, and leave
// the operator with no hub at all rather than a hub that has forgotten some
// workloads. The returned slice is empty in that case, which is the
// pre-existing behaviour.
func LoadHandles(store HandleStore, executorID string) []HandleRecord {
	if store == nil {
		return nil
	}
	recs, err := store.ListHandles(executorID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "executor: could not load persisted handles for %s: %v\n", executorID, err)
		return nil
	}
	return recs
}

// MemoryHandleStore is an in-memory HandleStore for tests and for embedders
// with no state database. It is concurrency-safe and, being a map, forgets
// everything on process exit — which makes it useful for asserting that a
// driver *writes* the right rows, and useless for surviving a restart.
type MemoryHandleStore struct {
	mu   sync.Mutex
	rows map[string]HandleRecord
}

// NewMemoryHandleStore returns an empty store.
func NewMemoryHandleStore() *MemoryHandleStore {
	return &MemoryHandleStore{rows: make(map[string]HandleRecord)}
}

// PutHandle implements HandleStore.
func (m *MemoryHandleStore) PutHandle(rec HandleRecord) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = make(map[string]HandleRecord)
	}
	// Copy the map so a caller mutating Meta after the write cannot reach
	// into stored state — the SQLite implementation marshals, and an
	// in-memory store that aliased would let tests pass where SQLite fails.
	cp := rec
	if len(rec.Meta) > 0 {
		cp.Meta = make(map[string]string, len(rec.Meta))
		for k, v := range rec.Meta {
			cp.Meta[k] = v
		}
	}
	m.rows[rec.HandleID] = cp
	return nil
}

// ListHandles implements HandleStore, returning rows oldest first.
func (m *MemoryHandleStore) ListHandles(executorID string) ([]HandleRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HandleRecord, 0, len(m.rows))
	for _, rec := range m.rows {
		if executorID != "" && rec.ExecutorID != executorID {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].HandleID < out[j].HandleID
		}
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out, nil
}

// DeleteHandle implements HandleStore.
func (m *MemoryHandleStore) DeleteHandle(handleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, handleID)
	return nil
}

// Len reports how many rows are stored, for test assertions.
func (m *MemoryHandleStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}
