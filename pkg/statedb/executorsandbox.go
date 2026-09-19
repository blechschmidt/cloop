// executorsandbox.go stores the per-executor sandbox configuration an admin
// sets from the UI: whether payloads run on the executor's host or in a
// container on it, and which engine, runtime and image that container uses.
//
// The sibling of projectlimits.go and executors.go's project_executors. All
// three record an operator's policy about something rather than a fact
// belonging to it, which is why all three live in the control plane and none is
// readable — or writable — from the thing they constrain.
package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ExecutorSandbox is one executor's sandbox configuration plus its provenance.
//
// Settings is the part that travels to the device in a start frame; SetAt and
// SetBy never leave the control plane. See executor.SandboxSettings for why
// that split is in the types rather than in a convention.
type ExecutorSandbox struct {
	ExecutorID string                   `json:"executor_id"`
	Settings   executor.SandboxSettings `json:"settings"`
	SetAt      time.Time                `json:"set_at,omitempty"`
	SetBy      string                   `json:"set_by,omitempty"`
}

// SetExecutorSandbox records sandbox settings for executorID, replacing any
// previous ones. setBy is the identity that set them, for the audit trail.
//
// Settings that configure nothing are stored rather than rejected, for the
// reason SetProjectResourceLimit stores a zero ceiling: "no row" and "a row
// that asserts nothing" mean the same thing at dispatch and different things to
// the admin reading the panel, who wants to see that someone looked at this
// executor. Callers meaning "remove the policy" call ClearExecutorSandbox.
func (d *DB) SetExecutorSandbox(executorID string, s executor.SandboxSettings, setBy string) error {
	if strings.TrimSpace(executorID) == "" {
		return errors.New("statedb: executor id is required")
	}
	// Normalized then validated, in that order and here as well as at the HTTP
	// boundary, because this is the last point before the value becomes durable
	// and the durable value is what a dispatch reads. An engine name that
	// reached this table unchecked would be a program an executor runs, chosen
	// by whoever last wrote the row.
	s = s.Normalize()
	if err := s.Validate(); err != nil {
		return fmt.Errorf("statedb: executor sandbox for %q: %w", executorID, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(
		`INSERT INTO executor_sandbox(
		     executor_id, mode, engine, runtime, image, set_at, set_by)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(executor_id) DO UPDATE SET
		   mode    = excluded.mode,
		   engine  = excluded.engine,
		   runtime = excluded.runtime,
		   image   = excluded.image,
		   set_at  = excluded.set_at,
		   set_by  = excluded.set_by`,
		executorID, string(s.Mode), s.Engine, s.Runtime, s.Image,
		time.Now().UTC().Format(time.RFC3339Nano), setBy)
	if err != nil {
		return fmt.Errorf("statedb: set executor sandbox for %q: %w", executorID, classifyDriverErr(err))
	}
	return nil
}

// ClearExecutorSandbox removes the configuration for executorID, returning it
// to the executor's own default. Clearing an executor that was never configured
// is not an error.
func (d *DB) ClearExecutorSandbox(executorID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`DELETE FROM executor_sandbox WHERE executor_id = ?`, executorID)
	if err != nil {
		return fmt.Errorf("statedb: clear executor sandbox for %q: %w", executorID, classifyDriverErr(err))
	}
	return nil
}

// ExecutorSandboxSettings returns the settings for executorID.
//
// The boolean is false when the executor has no row, which the dispatch path
// reads as "this executor keeps its own default" — deliberately distinct from
// an error, which means the lookup failed. The distinction matters in one
// direction especially: a storage fault that silently became "unset" would
// downgrade a container-mode executor to host execution exactly when the hub is
// least healthy, which is the failure this whole feature exists to prevent. See
// SandboxSettingsFor for the caller that has to choose what to do about it.
func (d *DB) ExecutorSandboxSettings(executorID string) (executor.SandboxSettings, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var (
		mode, engine, runtime, image string
	)
	err := d.conn.QueryRow(
		`SELECT mode, engine, runtime, image
		   FROM executor_sandbox WHERE executor_id = ?`, executorID,
	).Scan(&mode, &engine, &runtime, &image)
	if errors.Is(err, sql.ErrNoRows) {
		return executor.SandboxSettings{}, false, nil
	}
	if err != nil {
		return executor.SandboxSettings{}, false, fmt.Errorf(
			"statedb: executor sandbox for %q: %w", executorID, classifyDriverErr(err))
	}
	return executor.SandboxSettings{
		Mode:    executor.SandboxMode(mode),
		Engine:  engine,
		Runtime: runtime,
		Image:   image,
	}, true, nil
}

// ExecutorSandboxRecord returns the settings for executorID together with their
// provenance, for the fleet view that shows who chose an executor's containment.
func (d *DB) ExecutorSandboxRecord(executorID string) (ExecutorSandbox, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rec := ExecutorSandbox{ExecutorID: executorID}
	var (
		mode, engine, runtime, image, setAt string
	)
	err := d.conn.QueryRow(
		`SELECT mode, engine, runtime, image, set_at, set_by
		   FROM executor_sandbox WHERE executor_id = ?`, executorID,
	).Scan(&mode, &engine, &runtime, &image, &setAt, &rec.SetBy)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorSandbox{ExecutorID: executorID}, false, nil
	}
	if err != nil {
		return ExecutorSandbox{}, false, fmt.Errorf(
			"statedb: executor sandbox record for %q: %w", executorID, classifyDriverErr(err))
	}
	rec.Settings = executor.SandboxSettings{
		Mode:    executor.SandboxMode(mode),
		Engine:  engine,
		Runtime: runtime,
		Image:   image,
	}
	if t, err := time.Parse(time.RFC3339Nano, setAt); err == nil {
		rec.SetAt = t
	}
	return rec, true, nil
}

// ListExecutorSandboxes returns every recorded configuration, newest first, so
// the fleet view can render each card's containment in one query rather than
// one per executor.
func (d *DB) ListExecutorSandboxes() ([]ExecutorSandbox, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT executor_id, mode, engine, runtime, image, set_at, set_by
		   FROM executor_sandbox ORDER BY set_at DESC, executor_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor sandboxes: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ExecutorSandbox
	for rows.Next() {
		var (
			rec                          ExecutorSandbox
			mode, engine, runtime, image string
			setAt                        string
		)
		if err := rows.Scan(&rec.ExecutorID, &mode, &engine, &runtime, &image, &setAt, &rec.SetBy); err != nil {
			return nil, fmt.Errorf("statedb: scan executor sandbox: %w", classifyDriverErr(err))
		}
		rec.Settings = executor.SandboxSettings{
			Mode:    executor.SandboxMode(mode),
			Engine:  engine,
			Runtime: runtime,
			Image:   image,
		}
		if t, err := time.Parse(time.RFC3339Nano, setAt); err == nil {
			rec.SetAt = t
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor sandboxes: %w", classifyDriverErr(err))
	}
	return out, nil
}

// SandboxSettingsFor resolves an executor's settings for a dispatch, collapsing
// "no row" and "lookup failed" onto the same answer the caller can act on.
//
// The two are not the same, and the difference is the reason this helper exists
// rather than every caller deciding for itself. A missing row is a fact: this
// executor was never configured, and it should run what it always ran. A failed
// lookup is not a fact about the executor at all, and answering it with the
// zero value would silently unconfigure a container-mode executor for the
// duration of a database fault — a downgrade from containment to host
// execution, arrived at by no one's decision, at the moment the hub is least
// able to notice.
//
// So a failed lookup returns the error and the caller refuses the dispatch. The
// run fails loudly and is retried; it does not quietly run somewhere weaker
// than the admin asked for. That is the same trade the container driver makes
// when it refuses to construct without a runtime.
//
// A nil DB means no control plane — the single-user, no-database path — and
// yields unset settings with no error, because there is no policy to fail to
// read.
func SandboxSettingsFor(d *DB, executorID string) (executor.SandboxSettings, error) {
	if d == nil {
		return executor.SandboxSettings{}, nil
	}
	s, _, err := d.ExecutorSandboxSettings(executorID)
	if err != nil {
		return executor.SandboxSettings{}, err
	}
	return s, nil
}
