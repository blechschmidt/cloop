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
		return fmt.Errorf("%w: handle %s already reported its final status", ErrProtocol, handleID)
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
