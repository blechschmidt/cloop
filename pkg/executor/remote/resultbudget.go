package remote

// resultbudget.go bounds how much of this hub process's memory the work
// devices send back may occupy while it waits to be collected (Task 20399).
//
// A device returns two things the hub holds in memory until a consumer takes
// them: a write-back bundle, assembled from result chunks, and a seeded run's
// project-state document. Each is bounded per handle — the bundle by the cap
// its spec asked for, the document by executor.MaxProjectResultBytes — but a
// bound per handle is not a bound. The hub tracks every running handle and up
// to maxRetainedHandles finished ones per device, and before this file a
// compromised agent could pin the hard 128 MiB ceiling on each of them: 32 GiB
// per device per hub process, and nothing stopped a fleet adding that up.
//
// So the bytes are accounted twice, at the moment they are added and at the
// moment they are dropped: against the executor that sent them, which is the
// budget one device can exhaust, and against the process, which is the one
// that keeps the hub alive for every other tenant.
//
// Nothing else moves the counters. Not a reconnect, not a rehydration, not a
// session ending: the bytes outlive all three, and a counter reset by any of
// them would hand a device a fresh budget while its old bytes were still
// held. In a hub cluster each member holds what reached it and counts it
// itself, which is what a per-process bound means.

import (
	"fmt"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ResultBudget accounts the returned work one hub process holds, per executor
// and in total. The zero value is not usable; call NewResultBudget.
type ResultBudget struct {
	mu          sync.Mutex
	perExecutor int64
	total       int64
	used        int64
	byExecutor  map[string]int64
}

// NewResultBudget builds a budget with the given limits. A limit that is not
// positive takes its default (executor.DefaultPinnedWriteBackBytes and
// executor.DefaultPinnedWriteBackTotalBytes).
func NewResultBudget(perExecutor, total int64) *ResultBudget {
	b := &ResultBudget{byExecutor: make(map[string]int64)}
	b.SetLimits(perExecutor, total)
	return b
}

// defaultResultBudget is the process's budget: every remote executor built
// without Options.ResultBudget draws on it, because memory is a property of
// the process and not of any one executor.
var defaultResultBudget = NewResultBudget(0, 0)

// DefaultResultBudget returns the process-wide budget.
func DefaultResultBudget() *ResultBudget { return defaultResultBudget }

// SetLimits replaces both limits. A limit that is not positive takes its
// default. Bytes already held stay held: a lowered limit refuses new bytes
// until enough has been collected or released to fit under it.
func (b *ResultBudget) SetLimits(perExecutor, total int64) {
	if perExecutor <= 0 {
		perExecutor = executor.DefaultPinnedWriteBackBytes
	}
	if total <= 0 {
		total = executor.DefaultPinnedWriteBackTotalBytes
	}
	b.mu.Lock()
	b.perExecutor, b.total = perExecutor, total
	b.mu.Unlock()
}

// Limits reports the limits in force.
func (b *ResultBudget) Limits() (perExecutor, total int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.perExecutor, b.total
}

// ResultBudgetUsage is a snapshot of what a budget is holding.
type ResultBudgetUsage struct {
	// Pinned is every executor's bytes together.
	Pinned int64
	// MaxPerExecutor is the most any single executor holds.
	MaxPerExecutor int64
	// Executors is how many executors hold anything at all.
	Executors int
	// PerExecutorLimit and TotalLimit are the limits in force.
	PerExecutorLimit int64
	TotalLimit       int64
}

// Usage reports what the budget holds now.
func (b *ResultBudget) Usage() ResultBudgetUsage {
	b.mu.Lock()
	defer b.mu.Unlock()
	u := ResultBudgetUsage{
		Pinned:           b.used,
		Executors:        len(b.byExecutor),
		PerExecutorLimit: b.perExecutor,
		TotalLimit:       b.total,
	}
	for _, n := range b.byExecutor {
		if n > u.MaxPerExecutor {
			u.MaxPerExecutor = n
		}
	}
	return u
}

// Pinned reports what one executor holds.
func (b *ResultBudget) Pinned(executorID string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.byExecutor[executorID]
}

// budgetRefusal is a reservation a limit refused.
type budgetRefusal struct {
	// process is true when the process-wide ceiling refused it, false for
	// the executor's own budget.
	process bool
	// limit is the limit that refused, held what was already counted under
	// it, and want the bytes asked for.
	limit, held, want int64
}

// reserve counts n more bytes against executorID, or reports which limit
// they would cross.
func (b *ResultBudget) reserve(executorID string, n int64) *budgetRefusal {
	return b.swap(executorID, 0, n)
}

// swap replaces old bytes counted against executorID with n, in one step, or
// reports which limit n would cross — in which case nothing changes and the
// old bytes stay counted, because the caller keeps holding them. The
// executor's own budget is checked first: a device that exhausted its share is
// told so, rather than told the hub is full.
func (b *ResultBudget) swap(executorID string, old, n int64) *budgetRefusal {
	if n < 0 {
		n = 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	mine := b.byExecutor[executorID]
	old = min(max(old, 0), mine)
	if n > old {
		if mine-old+n > b.perExecutor {
			return &budgetRefusal{limit: b.perExecutor, held: mine - old, want: n}
		}
		if b.used-old+n > b.total {
			return &budgetRefusal{process: true, limit: b.total, held: b.used - old, want: n}
		}
	}
	if next := mine - old + n; next == 0 {
		delete(b.byExecutor, executorID)
	} else {
		b.byExecutor[executorID] = next
	}
	b.used += n - old
	return nil
}

// release gives n bytes back. It never takes an executor below zero, so a
// release that does not match a reservation cannot hand that executor — or
// the process — headroom it never paid for.
func (b *ResultBudget) release(executorID string, n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	mine := b.byExecutor[executorID]
	if n > mine {
		n = mine
	}
	if mine-n == 0 {
		delete(b.byExecutor, executorID)
	} else {
		b.byExecutor[executorID] = mine - n
	}
	b.used -= n
}

// reason renders a refusal for the write-back's error and the run's journal:
// which limit, how big, how much was already held, and the key that sets it.
func (r *budgetRefusal) reason(what, executorID string) string {
	if r.process {
		return fmt.Sprintf("holding %s would take the returned work this hub keeps in memory for every "+
			"executor past its ceiling of %s (executors.remote.max_pinned_writeback_total_bytes); %s is "+
			"already held, waiting to be collected", what, formatBytes(r.limit), formatBytes(r.held))
	}
	return fmt.Sprintf("holding %s would take the returned work executor %s may keep in this hub's "+
		"memory past its budget of %s (executors.remote.max_pinned_writeback_bytes); %s is already "+
		"held for its other workloads, waiting to be collected", what, executorID,
		formatBytes(r.limit), formatBytes(r.held))
}

// formatBytes renders a byte count the way the limits are usually written:
// exactly when it is a whole number of units, to a tenth otherwise.
func formatBytes(n int64) string {
	for _, u := range []struct {
		size int64
		name string
	}{{1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		switch {
		case n >= u.size && n%u.size == 0:
			return fmt.Sprintf("%d %s", n/u.size, u.name)
		case n >= u.size:
			return fmt.Sprintf("%.1f %s", float64(n)/float64(u.size), u.name)
		}
	}
	return fmt.Sprintf("%d bytes", n)
}
