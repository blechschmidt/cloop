package statedb

// isolation_evidence.go records what each executor's runtime was found to be
// by the isolation probe (Task 20439; migration 0082). See the migration for
// the columns.
//
// Two writes, because a probe has two outcomes and only one of them is
// evidence. A probe that ran records its verdict and everything it rests on. A
// probe that could not run — no image, a device gone mid-request, an agent too
// old to be asked — records only that it was attempted and why it failed, and
// leaves the verdict the last probe reached where it is: a broken probe says
// nothing about the runtime, and letting it clear a contradiction would make
// breaking the probe the way to escape one.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// IsolationEvidenceRow is one executor's record for one runtime.
type IsolationEvidenceRow struct {
	executor.IsolationRecord
	// Engine is the container engine the probe ran through, when it ran on
	// one.
	Engine string
	// Image is the image whose root filesystem the probe ran in.
	Image string
	// Evidence and Reference are what the probe read and the host kernel it
	// was compared with, as the JSON the probe wrote.
	Evidence  string
	Reference string
	// ProbedBy is the hub member that made the latest attempt.
	ProbedBy string
}

// isolationTime renders a time for the table: RFC 3339 UTC, ” for zero.
func isolationTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseIsolationTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// RecordIsolationProbe records a probe that ran: its verdict replaces any
// earlier one for the executor and runtime, and the attempt's error is
// cleared.
func (d *DB) RecordIsolationProbe(row IsolationEvidenceRow) error {
	id := strings.TrimSpace(row.ExecutorID)
	if id == "" {
		return errors.New("statedb: isolation evidence needs an executor id")
	}
	if row.ProbedAt.IsZero() {
		return fmt.Errorf("statedb: isolation evidence for %q has no probe time, so it is not a probe result", id)
	}
	if !row.Verdict.Valid() {
		return fmt.Errorf("statedb: isolation evidence for %q has no verdict (%q)", id, row.Verdict)
	}
	if row.AttemptedAt.IsZero() {
		row.AttemptedAt = row.ProbedAt
	}
	evidence, reference := jsonOr(row.Evidence), jsonOr(row.Reference)

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO isolation_evidence(
		     executor_id, runtime, engine, claim, verdict, detail, evidence, reference,
		     image, probed_at, attempted_at, error, point, probed_by)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,'',?,?)
		 ON CONFLICT(executor_id, runtime) DO UPDATE SET
		   engine       = excluded.engine,
		   claim        = excluded.claim,
		   verdict      = excluded.verdict,
		   detail       = excluded.detail,
		   evidence     = excluded.evidence,
		   reference    = excluded.reference,
		   image        = excluded.image,
		   probed_at    = excluded.probed_at,
		   attempted_at = excluded.attempted_at,
		   error        = '',
		   point        = excluded.point,
		   probed_by    = excluded.probed_by`,
		id, strings.TrimSpace(row.Runtime), row.Engine, string(row.Claim), string(row.Verdict),
		row.Detail, evidence, reference, row.Image, isolationTime(row.ProbedAt),
		isolationTime(row.AttemptedAt), row.Point, row.ProbedBy)
	if err != nil {
		return fmt.Errorf("statedb: record isolation evidence for %q: %w", id, classifyDriverErr(err))
	}
	return nil
}

// RecordIsolationProbeFailure records an attempt that could not run. The
// verdict and the evidence it rests on are kept; a row that did not exist is
// created with the unknown verdict.
func (d *DB) RecordIsolationProbeFailure(row IsolationEvidenceRow) error {
	id := strings.TrimSpace(row.ExecutorID)
	if id == "" {
		return errors.New("statedb: isolation evidence needs an executor id")
	}
	if row.AttemptedAt.IsZero() {
		return fmt.Errorf("statedb: a failed isolation probe of %q has no attempt time", id)
	}
	reason := strings.TrimSpace(row.Error)
	if reason == "" {
		reason = "the probe failed without saying why"
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO isolation_evidence(
		     executor_id, runtime, engine, claim, verdict, image, attempted_at, error, point, probed_by)
		 VALUES(?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(executor_id, runtime) DO UPDATE SET
		   claim        = excluded.claim,
		   attempted_at = excluded.attempted_at,
		   error        = excluded.error,
		   point        = excluded.point,
		   probed_by    = excluded.probed_by`,
		id, strings.TrimSpace(row.Runtime), row.Engine, string(row.Claim),
		string(isolationprobe.KindUnknown), row.Image, isolationTime(row.AttemptedAt), reason,
		row.Point, row.ProbedBy)
	if err != nil {
		return fmt.Errorf("statedb: record a failed isolation probe of %q: %w", id, classifyDriverErr(err))
	}
	return nil
}

// IsolationEvidence returns the record for executorID and runtime, and false
// when there is none.
func (d *DB) IsolationEvidence(executorID, runtime string) (IsolationEvidenceRow, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(isolationSelect+` WHERE executor_id = ? AND runtime = ?`,
		strings.TrimSpace(executorID), strings.TrimSpace(runtime))
	if err != nil {
		return IsolationEvidenceRow{}, false, fmt.Errorf("statedb: isolation evidence for %q: %w",
			executorID, classifyDriverErr(err))
	}
	out, err := scanIsolationRows(rows)
	if err != nil || len(out) == 0 {
		return IsolationEvidenceRow{}, false, err
	}
	return out[0], true, nil
}

// ListIsolationEvidence returns every record, by executor and runtime.
func (d *DB) ListIsolationEvidence() ([]IsolationEvidenceRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(isolationSelect + ` ORDER BY executor_id, runtime`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list isolation evidence: %w", classifyDriverErr(err))
	}
	return scanIsolationRows(rows)
}

// ForgetIsolationEvidence removes every record for executorID — an executor
// revoked or deleted, or one whose engine changed under the same runtime name,
// so that nothing verified about the old one is read as true of the new.
func (d *DB) ForgetIsolationEvidence(executorID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM isolation_evidence WHERE executor_id = ?`,
		strings.TrimSpace(executorID)); err != nil {
		return fmt.Errorf("statedb: forget isolation evidence for %q: %w", executorID, classifyDriverErr(err))
	}
	return nil
}

const isolationSelect = `SELECT executor_id, runtime, engine, claim, verdict, detail, evidence,
	reference, image, probed_at, attempted_at, error, point, probed_by FROM isolation_evidence`

func scanIsolationRows(rows *sql.Rows) ([]IsolationEvidenceRow, error) {
	defer rows.Close()
	var out []IsolationEvidenceRow
	for rows.Next() {
		var (
			r                               IsolationEvidenceRow
			claim, verdict, probed, attempt string
		)
		if err := rows.Scan(&r.ExecutorID, &r.Runtime, &r.Engine, &claim, &verdict, &r.Detail,
			&r.Evidence, &r.Reference, &r.Image, &probed, &attempt, &r.Error, &r.Point, &r.ProbedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan isolation evidence: %w", classifyDriverErr(err))
		}
		r.Claim, r.Verdict = isolationprobe.Kind(claim), isolationprobe.Kind(verdict)
		if !r.Verdict.Valid() {
			// A row this build cannot read is no evidence at all.
			r.Verdict = isolationprobe.KindUnknown
		}
		r.ProbedAt, r.AttemptedAt = parseIsolationTime(probed), parseIsolationTime(attempt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read isolation evidence: %w", classifyDriverErr(err))
	}
	return out, nil
}

// jsonOr returns s, or an empty object for an empty string.
func jsonOr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
}
