// handles.go adapts executor.HandleStore onto statedb (Task 20191).
//
// Same separation as the rest of this package: pkg/executor declares the
// interface because it is linked into the agent binary that runs on edge
// devices and must not carry a SQLite engine, and everything that knows about
// rows lives here.
//
// The only judgement in this file is what a driver's Meta map is allowed to
// be. It is marshalled verbatim into a text column, so it must never carry
// secret material — see MarshalHandleMeta's contract in statedb.

package executorstore

import (
	"errors"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Handles implements executor.HandleStore over a *statedb.DB.
//
// It is a separate type from Scheduler rather than more methods on it because
// the two have different owners: a Scheduler is the control plane's view and
// is constructed by the supervisor, while a Handles is handed to a *driver*,
// which is the one thing in this system that may also run outside the hub.
// Keeping them apart means a driver holds a store that can do exactly three
// things and cannot, say, close a session it does not own.
type Handles struct {
	db *statedb.DB
}

// Compile-time proof the adapter satisfies the interface drivers are written
// against; a signature drift in pkg/executor should be a build error here and
// not a nil-interface panic at wiring time.
var _ executor.HandleStore = (*Handles)(nil)

// NewHandles wraps a database handle.
func NewHandles(db *statedb.DB) (*Handles, error) {
	if db == nil {
		return nil, fmt.Errorf("executorstore: nil database")
	}
	return &Handles{db: db}, nil
}

// PutHandle implements executor.HandleStore.
func (h *Handles) PutHandle(rec executor.HandleRecord) error {
	if h == nil || h.db == nil {
		return fmt.Errorf("executorstore: nil handle store")
	}
	if err := rec.Validate(); err != nil {
		return err
	}
	return h.db.PutExecutorHandle(statedb.ExecutorHandleRow{
		HandleID:    rec.HandleID,
		ExecutorID:  rec.ExecutorID,
		Driver:      rec.Driver,
		ExternalID:  rec.ExternalID,
		ProjectPath: rec.ProjectPath,
		TaskID:      rec.TaskID,
		PID:         rec.PID,
		Image:       rec.Image,
		MetaJSON:    statedb.MarshalHandleMeta(rec.Meta),
		StartedAt:   rec.StartedAt,
		Deadline:    rec.Deadline,
	})
}

// ListHandles implements executor.HandleStore.
func (h *Handles) ListHandles(executorID string) ([]executor.HandleRecord, error) {
	if h == nil || h.db == nil {
		return nil, fmt.Errorf("executorstore: nil handle store")
	}
	rows, err := h.db.ListExecutorHandles(executorID)
	if err != nil {
		return nil, err
	}
	out := make([]executor.HandleRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, executor.HandleRecord{
			HandleID:    row.HandleID,
			ExecutorID:  row.ExecutorID,
			Driver:      row.Driver,
			ExternalID:  row.ExternalID,
			ProjectPath: row.ProjectPath,
			TaskID:      row.TaskID,
			PID:         row.PID,
			Image:       row.Image,
			StartedAt:   row.StartedAt,
			Deadline:    row.Deadline,
			Meta:        statedb.UnmarshalHandleMeta(row.MetaJSON),
		})
	}
	return out, nil
}

// DeleteHandle implements executor.HandleStore.
func (h *Handles) DeleteHandle(handleID string) error {
	if h == nil || h.db == nil {
		return fmt.Errorf("executorstore: nil handle store")
	}
	if err := h.db.DeleteExecutorHandle(handleID); err != nil && !errors.Is(err, statedb.ErrExecutorHandleNotFound) {
		return err
	}
	return nil
}
