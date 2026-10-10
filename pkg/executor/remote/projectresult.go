package remote

// projectresult.go holds what a device sent back of a seeded run until the hub
// collects it (Task 20339).
//
// This layer does not parse the document. It is the transport: it bounds the
// frame, keeps the bytes on the handle they belong to, and hands them — with
// the handle's redaction set — to whoever settles the run. What the hub accepts
// from the document is pkg/executor/projectseed's decision, made with the hub's
// own copy of the project in hand, which this package never has.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// projectResultState is a device's report for one handle.
type projectResultState struct {
	data []byte
	err  string
}

// applyProjectResult records a project_result frame on its handle.
//
// A second frame for the same handle replaces the first rather than being
// refused: the agent re-reads and re-sends after a reconnect, and the later
// reading of the same finished workload's directory is the better one.
//
// The document is held until the hub collects it, so it is counted against the
// executor's ResultBudget like a bundle (Task 20399). One the budget cannot
// hold is not kept. A replacement that does not fit leaves the earlier reading
// in place, still counted — it is as true as it was a moment ago — and a first
// document that does not fit leaves the reason instead, so the run's journal
// names the limit rather than reporting a run that sent nothing back.
func (e *Executor) applyProjectResult(handleID string, p ProjectResultPayload) error {
	hs, err := e.lookup(handleID)
	if err != nil {
		return err
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.closed {
		// The terminal status has already closed the stream, which means the
		// run has been — or is being — settled without this. Accepting it now
		// would hold bytes nobody will collect; saying so tells a device that
		// is out of order that it is.
		refuseFrame(hubmetrics.WriteBackRefusedLate)
		return fmt.Errorf("%w: handle %s already reported its final status", ErrProtocol, handleID)
	}
	if !hs.returns.acceptsProjectResult() {
		// The run was dispatched without a project seed, so the device was
		// given no project to read back. A document anyway is bytes nothing
		// would ever collect.
		refuseFrame(hubmetrics.WriteBackRefusedNotRequested)
		return fmt.Errorf("%w: handle %s was dispatched with no project seed, so it has no project "+
			"state to return", ErrProtocol, handleID)
	}
	var held int64
	if hs.projectResult != nil {
		held = int64(len(hs.projectResult.data))
	}
	if refused := e.budget.swap(e.id, held, int64(len(p.Data))); refused != nil {
		refuseFrame(refused.metricReason())
		reason := refused.reason("the run's project state", e.id)
		if hs.projectResult == nil {
			hs.projectResult = &projectResultState{err: "the hub refused to hold it: " + reason}
		}
		return fmt.Errorf("%w: %s", ErrWriteBackBudget, reason)
	}
	hs.projectResult = &projectResultState{data: append([]byte(nil), p.Data...), err: p.Err}
	return nil
}

// ProjectResult implements executor.ProjectResultFetcher.
//
// Released once: the bytes go to the caller and are dropped here, because a
// second merge of the same run would book its spend twice.
func (e *Executor) ProjectResult(handleID string) (executor.ProjectResult, error) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return executor.ProjectResult{}, err
	}
	hs.mu.Lock()
	pr := hs.projectResult
	hs.projectResult = nil
	hs.mu.Unlock()
	if pr == nil {
		return executor.ProjectResult{}, fmt.Errorf("%w: handle %s on agent %s",
			executor.ErrProjectResultUnavailable, handleID, e.id)
	}
	// Given back as the bytes leave: from here they are the caller's.
	e.budget.release(e.id, int64(len(pr.data)))
	// The set the hub installed on this handle's log bus from the Spec it
	// dispatched — the same one that scrubs the live log. A rehydrated handle
	// has none (the Spec's secrets are not persisted), and scrubs nothing,
	// which is no worse than its log.
	redactor := hs.bus.Redactor()
	return executor.ProjectResult{
		Data:   pr.data,
		Err:    pr.err,
		Redact: redactor.String,
	}, nil
}
