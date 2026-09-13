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
//
// This package also owns the marshalling of a handle's secret-lease bindings
// (Task 20231), for the same layering reason: pkg/statedb stores the column as
// opaque text and never learns the type, so the agent binary keeps its
// SQLite-free build while the hub gets a typed round trip.

package executorstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

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
		SecretsJSON: marshalHandleSecrets(rec),
		StartedAt:   rec.StartedAt,
		Deadline:    rec.Deadline,
	})
}

// marshalHandleSecrets renders a record's lease bindings for the
// secrets_json column.
//
// The three cases the column distinguishes (see migration 0031) are produced
// here: "" when the caller did not record bindings, "[]" when it recorded that
// there were none, and a JSON array otherwise. A marshal failure degrades to
// "" — unknown — rather than to "[]", because the two are read differently and
// only one of them is safe to be wrong about: unknown costs an over-cautious
// revocation report, while a wrong "[]" loses a holder.
func marshalHandleSecrets(rec executor.HandleRecord) string {
	if !rec.SecretsRecorded {
		return ""
	}
	bindings := rec.Secrets
	if bindings == nil {
		bindings = []executor.SecretBinding{}
	}
	b, err := json.Marshal(bindings)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"executorstore: could not marshal secret bindings for handle %s (%v); "+
				"recording them as unknown so a later revocation reports the doubt\n",
			rec.HandleID, err)
		return ""
	}
	return string(b)
}

// unmarshalHandleSecrets parses the secrets_json column, reporting whether the
// answer is authoritative.
//
// Unparsable JSON yields (nil, false) — the same as an unrecorded row, and
// deliberately so. Dropping a corrupt value to "no bindings" is how a
// revocation would come to report success against a workload whose credentials
// nobody can enumerate; this is the one field in the table where a decode
// failure must not degrade to the empty case. Contrast UnmarshalHandleMeta,
// which drops corrupt metadata precisely because the extras are advisory.
func unmarshalHandleSecrets(s string) ([]executor.SecretBinding, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	var out []executor.SecretBinding
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, false
	}
	return out, true
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
		secrets, recorded := unmarshalHandleSecrets(row.SecretsJSON)
		out = append(out, executor.HandleRecord{
			HandleID:        row.HandleID,
			ExecutorID:      row.ExecutorID,
			Driver:          row.Driver,
			ExternalID:      row.ExternalID,
			ProjectPath:     row.ProjectPath,
			TaskID:          row.TaskID,
			PID:             row.PID,
			Image:           row.Image,
			StartedAt:       row.StartedAt,
			Deadline:        row.Deadline,
			Meta:            statedb.UnmarshalHandleMeta(row.MetaJSON),
			Secrets:         secrets,
			SecretsRecorded: recorded,
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
