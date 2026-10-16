package executor

import (
	"sync"

	"github.com/blechschmidt/cloop/pkg/denylog"
)

// denials.go is where a sandbox's firewall refusals meet the hub (Task 20437).
//
// They arrive two ways: from the hub's own container executor, whose packet
// log this process reads (pkg/denylog), and from an edge device's agent, which
// reads its own and sends each batch over its session (pkg/executor/remote).
// Both report here, by the executor that ran the workload and the handle the
// hub knows it by, and the process that installed a sink — the hub's UI
// server — decides what they mean: which run, which task, which rule.

// DenialSink receives one workload's batch of refusals.
type DenialSink func(executorID, handleID string, b denylog.Batch)

var (
	denialMu   sync.RWMutex
	denialSink DenialSink
)

// SetDenialSink installs where refusals go, returning the function that
// restores the previous sink. With none installed they are discarded: a
// process that is not a hub has nobody to tell.
func SetDenialSink(s DenialSink) (restore func()) {
	denialMu.Lock()
	prev := denialSink
	denialSink = s
	denialMu.Unlock()
	return func() {
		denialMu.Lock()
		denialSink = prev
		denialMu.Unlock()
	}
}

// ReportDenials hands one workload's batch to the sink, and reports whether
// there was one.
func ReportDenials(executorID, handleID string, b denylog.Batch) bool {
	denialMu.RLock()
	s := denialSink
	denialMu.RUnlock()
	if s == nil {
		return false
	}
	s(executorID, handleID, b)
	return true
}
