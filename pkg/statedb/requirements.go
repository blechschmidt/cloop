package statedb

// requirements.go stores what a project must keep doing and what its checks
// found (Task 20458; migration 0085). See pkg/requirements for the model, and
// the migration for the columns.
//
// Three tables, three kinds of writer. requirements is written by a person —
// the dashboard or `cloop requirements` — and by nothing a run does on its
// own. requirement_checks is written when a check ends, by whoever ran it:
// the hub, for a check it dispatched to the project's executor, or `cloop
// requirements check` run by hand. requirement_runs is the hub's record of a
// check in progress, which is what lets any member see one and refuse a second.
//
// What is read back is bounded again on the way out (requirements.Normalize
// is not re-run, but every JSON column is decoded leniently and every text
// clipped): on an executor that shares the project's directory the database
// is writable from inside the sandbox, and a row is not to be trusted for
// having been read from here.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

const (
	// requirementTimeFormat is how every time here is stored: fixed width,
	// so the columns order and compare as text.
	requirementTimeFormat = "2006-01-02T15:04:05.000000Z"

	// requirementChecksKept is how many checks a requirement keeps.
	requirementChecksKept = 50
	// requirementRunsKept is how many check runs a project keeps.
	requirementRunsKept = 200

	// maxCheckDetailBytes bounds a stored check's detail: its tests' outputs
	// are each bounded by the report, and this bounds them together.
	maxCheckDetailBytes = 512 << 10

	// RequirementRunHeartbeat is how often the member running a check says
	// so (TouchRequirementRun); a run silent for requirementRunSilence has
	// lost its member — the process died, or was killed by a deploy — and
	// lapses then rather than at its deadline, hours on.
	RequirementRunHeartbeat = 2 * time.Second
	requirementRunSilence   = 30 * time.Second
)

// Check run states.
const (
	RequirementRunRunning   = "running"
	RequirementRunDone      = "done"
	RequirementRunFailed    = "failed"
	RequirementRunCancelled = "cancelled"
	// RequirementRunLapsed is how a run still recorded as running past its
	// deadline reads: whoever ran it died without finishing it.
	RequirementRunLapsed = "lapsed"
)

// RequirementCheck is one recorded verdict about a requirement.
type RequirementCheck struct {
	ID            int64                     `json:"id"`
	RequirementID int                       `json:"requirement_id"`
	RunID         string                    `json:"run_id,omitempty"`
	Method        string                    `json:"method"`
	Verdict       string                    `json:"verdict"`
	Summary       string                    `json:"summary,omitempty"`
	Tests         []requirements.TestResult `json:"tests,omitempty"`
	Evidence      []string                  `json:"evidence,omitempty"`
	Fingerprint   string                    `json:"fingerprint,omitempty"`
	Commit        string                    `json:"commit,omitempty"`
	Dirty         bool                      `json:"dirty,omitempty"`
	ExecutorID    string                    `json:"executor_id,omitempty"`
	CheckedBy     string                    `json:"checked_by,omitempty"`
	CheckedAt     time.Time                 `json:"checked_at"`
	DurationMS    int64                     `json:"duration_ms"`
}

// checkDetail is the JSON a check's detail column holds.
type checkDetail struct {
	Tests    []requirements.TestResult `json:"tests,omitempty"`
	Evidence []string                  `json:"evidence,omitempty"`
}

// RequirementRun is one check run.
type RequirementRun struct {
	RunID           string              `json:"run_id"`
	State           string              `json:"state"`
	Source          string              `json:"source,omitempty"`
	StartedBy       string              `json:"started_by,omitempty"`
	StartedAt       time.Time           `json:"started_at"`
	Deadline        time.Time           `json:"deadline"`
	FinishedAt      time.Time           `json:"finished_at,omitzero"`
	ExecutorID      string              `json:"executor_id,omitempty"`
	Assess          bool                `json:"assess,omitempty"`
	RequirementIDs  []int               `json:"requirement_ids"`
	Counts          requirements.Counts `json:"counts"`
	Error           string              `json:"error,omitempty"`
	CancelRequested bool                `json:"cancel_requested,omitempty"`
}

// CheckRecord is what recording one check run's results needs besides the
// results themselves.
type CheckRecord struct {
	RunID      string
	Commit     string
	Dirty      bool
	ExecutorID string
	CheckedBy  string
}

func formatReqTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(requirementTimeFormat)
}

func parseReqTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(requirementTimeFormat, s); err == nil {
		return t
	}
	return parseOptionalTime(s)
}

const requirementColumns = `id, title, description, priority, tags, tests, created_at, updated_at, created_by, updated_by`

type requirementQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func queryRequirements(q requirementQuerier, where string, args ...any) ([]requirements.Requirement, error) {
	rows, err := q.Query(`SELECT `+requirementColumns+` FROM requirements `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: read requirements: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []requirements.Requirement
	for rows.Next() {
		var (
			r                    requirements.Requirement
			tags, tests          string
			created, updated     string
			createdBy, updatedBy string
		)
		if err := rows.Scan(&r.ID, &r.Title, &r.Description, &r.Priority, &tags, &tests, &created, &updated,
			&createdBy, &updatedBy); err != nil {
			return nil, fmt.Errorf("statedb: read requirements: %w", classifyDriverErr(err))
		}
		r.Title = clipText(r.Title, 4*requirements.MaxTitleRunes)
		r.Description = clipText(r.Description, 4*requirements.MaxDescriptionRunes)
		r.Priority = clipText(r.Priority, 16)
		_ = json.Unmarshal([]byte(tags), &r.Tags)
		if len(r.Tags) > requirements.MaxTags {
			r.Tags = r.Tags[:requirements.MaxTags]
		}
		_ = json.Unmarshal([]byte(tests), &r.Tests)
		if len(r.Tests) > requirements.MaxTests {
			r.Tests = r.Tests[:requirements.MaxTests]
		}
		for i := range r.Tests {
			r.Tests[i].Command = clipText(r.Tests[i].Command, requirements.MaxCommandBytes)
			r.Tests[i].Name = clipText(r.Tests[i].Name, 4*requirements.MaxTestNameRunes)
		}
		r.CreatedAt, r.UpdatedAt = parseReqTime(created), parseReqTime(updated)
		r.CreatedBy, r.UpdatedBy = clipText(createdBy, 4*requirements.MaxActorRunes), clipText(updatedBy, 4*requirements.MaxActorRunes)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read requirements: %w", classifyDriverErr(err))
	}
	return out, nil
}

// Requirements lists the project's requirements in id order.
func (d *DB) Requirements() ([]requirements.Requirement, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryRequirements(d.conn, `ORDER BY id LIMIT ?`, requirements.MaxRequirements)
}

// Requirement reads one requirement, or ErrRequirementNotFound.
func (d *DB) Requirement(id int) (requirements.Requirement, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rs, err := queryRequirements(d.conn, `WHERE id = ?`, id)
	if err != nil {
		return requirements.Requirement{}, err
	}
	if len(rs) == 0 {
		return requirements.Requirement{}, fmt.Errorf("%w: %s", ErrRequirementNotFound, requirements.Key(id))
	}
	return rs[0], nil
}

func marshalJSONColumn(v any, empty string) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return empty
	}
	return string(b)
}

// AddRequirement stores r, which the caller has normalised, as a new
// requirement and returns it with its id, recording who added it.
func (d *DB) AddRequirement(r requirements.Requirement, actor string) (requirements.Requirement, error) {
	if err := r.Normalize(); err != nil {
		return requirements.Requirement{}, err
	}
	now := time.Now().UTC()
	r.ID, r.CreatedAt, r.UpdatedAt = 0, now, now
	r.CreatedBy, r.UpdatedBy = clipActor(actor), clipActor(actor)

	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return r, fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
	}
	err = func() error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM requirements`).Scan(&n); err != nil {
			return fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
		}
		if n >= requirements.MaxRequirements {
			return fmt.Errorf("%w: a project holds at most %d requirements", requirements.ErrInvalid, requirements.MaxRequirements)
		}
		res, err := tx.Exec(`INSERT INTO requirements
			(title, description, priority, tags, tests, created_at, updated_at, created_by, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Title, r.Description, r.Priority, marshalJSONColumn(r.Tags, "[]"), marshalJSONColumn(r.Tests, "[]"),
			formatReqTime(now), formatReqTime(now), r.CreatedBy, r.UpdatedBy)
		if err != nil {
			return fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
		}
		r.ID = int(id)
		return tx.Commit()
	}()
	if err != nil {
		_ = tx.Rollback()
	}
	d.mu.Unlock()
	if err != nil {
		return r, classifyDriverErr(err)
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementCreate),
		EntityType: "requirement", EntityID: fmt.Sprint(r.ID),
		Payload: MarshalAuditPayload(map[string]any{
			"id": r.ID, "title": r.Title, "priority": r.Priority, "tests": testCommands(r.Tests),
			"fingerprint": r.Fingerprint(),
		}),
	})
	return r, nil
}

// UpdateRequirement replaces the definition of the requirement r.ID names with
// r's, keeping when and by whom it was created, and returns it as stored.
func (d *DB) UpdateRequirement(r requirements.Requirement, actor string) (requirements.Requirement, error) {
	if err := r.Normalize(); err != nil {
		return requirements.Requirement{}, err
	}
	now := time.Now().UTC()
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return r, fmt.Errorf("statedb: update requirement: %w", classifyDriverErr(err))
	}
	var before requirements.Requirement
	err = func() error {
		rs, err := queryRequirements(tx, `WHERE id = ?`, r.ID)
		if err != nil {
			return err
		}
		if len(rs) == 0 {
			return fmt.Errorf("%w: %s", ErrRequirementNotFound, requirements.Key(r.ID))
		}
		before = rs[0]
		if _, err := tx.Exec(`UPDATE requirements SET title = ?, description = ?, priority = ?, tags = ?, tests = ?,
			updated_at = ?, updated_by = ? WHERE id = ?`,
			r.Title, r.Description, r.Priority, marshalJSONColumn(r.Tags, "[]"), marshalJSONColumn(r.Tests, "[]"),
			formatReqTime(now), clipActor(actor), r.ID); err != nil {
			return fmt.Errorf("statedb: update requirement: %w", classifyDriverErr(err))
		}
		return tx.Commit()
	}()
	if err != nil {
		_ = tx.Rollback()
	}
	d.mu.Unlock()
	if err != nil {
		return r, classifyDriverErr(err)
	}
	r.CreatedAt, r.CreatedBy = before.CreatedAt, before.CreatedBy
	r.UpdatedAt, r.UpdatedBy = now, clipActor(actor)
	if changed := changedRequirementFields(before, r); len(changed) > 0 {
		emit(d, &AuditEvent{
			Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementUpdate),
			EntityType: "requirement", EntityID: fmt.Sprint(r.ID),
			Payload: MarshalAuditPayload(map[string]any{
				"id": r.ID, "title": r.Title, "changed": changed, "tests": testCommands(r.Tests),
				"fingerprint": r.Fingerprint(), "previous_fingerprint": before.Fingerprint(),
			}),
		})
	}
	return r, nil
}

func changedRequirementFields(a, b requirements.Requirement) []string {
	var out []string
	if a.Title != b.Title {
		out = append(out, "title")
	}
	if a.Description != b.Description {
		out = append(out, "description")
	}
	if a.Priority != b.Priority {
		out = append(out, "priority")
	}
	if strings.Join(a.Tags, "\x00") != strings.Join(b.Tags, "\x00") {
		out = append(out, "tags")
	}
	if marshalJSONColumn(a.Tests, "[]") != marshalJSONColumn(b.Tests, "[]") {
		out = append(out, "tests")
	}
	return out
}

// DeleteRequirement deletes a requirement and the history of its checks, and
// returns the requirement as it was.
func (d *DB) DeleteRequirement(id int, actor string) (requirements.Requirement, error) {
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return requirements.Requirement{}, fmt.Errorf("statedb: delete requirement: %w", classifyDriverErr(err))
	}
	var (
		gone   requirements.Requirement
		checks int64
	)
	err = func() error {
		rs, err := queryRequirements(tx, `WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if len(rs) == 0 {
			return fmt.Errorf("%w: %s", ErrRequirementNotFound, requirements.Key(id))
		}
		gone = rs[0]
		if _, err := tx.Exec(`DELETE FROM requirements WHERE id = ?`, id); err != nil {
			return fmt.Errorf("statedb: delete requirement: %w", classifyDriverErr(err))
		}
		res, err := tx.Exec(`DELETE FROM requirement_checks WHERE requirement_id = ?`, id)
		if err != nil {
			return fmt.Errorf("statedb: delete requirement checks: %w", classifyDriverErr(err))
		}
		checks, _ = res.RowsAffected()
		return tx.Commit()
	}()
	if err != nil {
		_ = tx.Rollback()
	}
	d.mu.Unlock()
	if err != nil {
		return gone, classifyDriverErr(err)
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementDelete),
		EntityType: "requirement", EntityID: fmt.Sprint(id),
		Payload: MarshalAuditPayload(map[string]any{"id": id, "title": gone.Title, "checks": checks}),
	})
	return gone, nil
}

// RecordRequirementChecks stores one check run's results. A result about a
// requirement deleted while it was checked is dropped, as is one whose
// requirement's definition changed meanwhile: it is a verdict about something
// the project no longer requires. It returns the results it stored.
func (d *DB) RecordRequirementChecks(rec CheckRecord, results []requirements.Result) ([]RequirementCheck, error) {
	if len(results) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: record requirement checks: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit

	current, err := queryRequirements(tx, `ORDER BY id`)
	if err != nil {
		return nil, err
	}
	prints := make(map[int]string, len(current))
	for _, r := range current {
		prints[r.ID] = r.Fingerprint()
	}
	var stored []RequirementCheck
	touched := map[int]bool{}
	for _, res := range results {
		fp, ok := prints[res.RequirementID]
		if !ok || (res.Fingerprint != "" && res.Fingerprint != fp) || !requirements.ValidVerdict(res.Verdict) {
			continue
		}
		c := RequirementCheck{
			RequirementID: res.RequirementID, RunID: clipText(rec.RunID, 64), Method: clipText(res.Method, 16),
			Verdict: res.Verdict, Summary: clipText(res.Summary, 4*requirements.MaxRationaleRunes),
			Tests: append([]requirements.TestResult(nil), res.Tests...), Evidence: res.Evidence, Fingerprint: fp, Commit: clipText(rec.Commit, 64), Dirty: rec.Dirty,
			ExecutorID: clipText(rec.ExecutorID, 256), CheckedBy: clipActor(rec.CheckedBy),
			CheckedAt: res.StartedAt.UTC(), DurationMS: res.DurationMS,
		}
		if c.CheckedAt.IsZero() {
			c.CheckedAt = now
		}
		detail := marshalJSONColumn(checkDetail{Tests: c.Tests, Evidence: c.Evidence}, "{}")
		if len(detail) > maxCheckDetailBytes {
			for i := range c.Tests {
				c.Tests[i].Output, c.Tests[i].Truncated = "", true
			}
			detail = marshalJSONColumn(checkDetail{Tests: c.Tests, Evidence: c.Evidence}, "{}")
		}
		r, err := tx.Exec(`INSERT INTO requirement_checks
			(requirement_id, run_id, method, verdict, summary, detail, fingerprint, git_commit, dirty,
			 executor_id, checked_by, checked_at, duration_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.RequirementID, c.RunID, c.Method, c.Verdict, c.Summary, detail, c.Fingerprint, c.Commit, boolInt(c.Dirty),
			c.ExecutorID, c.CheckedBy, formatReqTime(c.CheckedAt), c.DurationMS)
		if err != nil {
			return nil, fmt.Errorf("statedb: record requirement check: %w", classifyDriverErr(err))
		}
		c.ID, _ = r.LastInsertId()
		stored = append(stored, c)
		touched[c.RequirementID] = true
	}
	for id := range touched {
		if _, err := tx.Exec(`DELETE FROM requirement_checks WHERE requirement_id = ? AND id <= (
			SELECT id FROM requirement_checks WHERE requirement_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`,
			id, id, requirementChecksKept); err != nil {
			return nil, fmt.Errorf("statedb: trim requirement checks: %w", classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: record requirement checks: %w", classifyDriverErr(err))
	}
	return stored, nil
}

// RecordRequirementVerdict stores a verdict a person reached by hand about the
// requirement id names, as it is now.
func (d *DB) RecordRequirementVerdict(id int, verdict, note, actor string) (RequirementCheck, error) {
	if verdict != requirements.VerdictFulfilled && verdict != requirements.VerdictUnfulfilled {
		return RequirementCheck{}, fmt.Errorf("%w: a recorded verdict is fulfilled or unfulfilled, not %q",
			requirements.ErrInvalid, clipText(verdict, 32))
	}
	note = strings.TrimSpace(note)
	if len([]rune(note)) > requirements.MaxSummaryRunes {
		return RequirementCheck{}, fmt.Errorf("%w: the note is longer than %d characters", requirements.ErrInvalid, requirements.MaxSummaryRunes)
	}
	req, err := d.Requirement(id)
	if err != nil {
		return RequirementCheck{}, err
	}
	summary := "recorded by hand"
	if note != "" {
		summary = note
	}
	stored, err := d.RecordRequirementChecks(CheckRecord{CheckedBy: actor}, []requirements.Result{{
		RequirementID: id, Fingerprint: req.Fingerprint(), Method: requirements.MethodManual,
		Verdict: verdict, Summary: summary, StartedAt: time.Now().UTC(),
	}})
	if err != nil {
		return RequirementCheck{}, err
	}
	if len(stored) == 0 {
		return RequirementCheck{}, fmt.Errorf("%w: %s changed while the verdict was recorded", ErrRequirementNotFound, requirements.Key(id))
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementVerdict),
		EntityType: "requirement", EntityID: fmt.Sprint(id),
		Payload: MarshalAuditPayload(map[string]any{
			"id": id, "verdict": verdict, "note": note, "fingerprint": req.Fingerprint(),
		}),
	})
	return stored[0], nil
}

const requirementCheckColumns = `id, requirement_id, run_id, method, verdict, summary, detail, fingerprint, git_commit,
	dirty, executor_id, checked_by, checked_at, duration_ms`

func scanRequirementChecks(rows *sql.Rows) ([]RequirementCheck, error) {
	defer rows.Close()
	var out []RequirementCheck
	for rows.Next() {
		var (
			c              RequirementCheck
			detail, at     string
			dirty          int
			summary, runID string
		)
		if err := rows.Scan(&c.ID, &c.RequirementID, &runID, &c.Method, &c.Verdict, &summary, &detail, &c.Fingerprint,
			&c.Commit, &dirty, &c.ExecutorID, &c.CheckedBy, &at, &c.DurationMS); err != nil {
			return nil, fmt.Errorf("statedb: read requirement checks: %w", classifyDriverErr(err))
		}
		c.RunID, c.Summary = clipText(runID, 64), clipText(summary, 4*requirements.MaxRationaleRunes)
		if !requirements.ValidVerdict(c.Verdict) {
			c.Verdict = requirements.VerdictError
		}
		var dt checkDetail
		if len(detail) <= maxCheckDetailBytes {
			_ = json.Unmarshal([]byte(detail), &dt)
		}
		if len(dt.Tests) > requirements.MaxTests {
			dt.Tests = dt.Tests[:requirements.MaxTests]
		}
		if len(dt.Evidence) > requirements.MaxEvidence {
			dt.Evidence = dt.Evidence[:requirements.MaxEvidence]
		}
		c.Tests, c.Evidence = dt.Tests, dt.Evidence
		c.Dirty = dirty != 0
		c.CheckedAt = parseReqTime(at)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read requirement checks: %w", classifyDriverErr(err))
	}
	return out, nil
}

// LatestRequirementChecks returns each requirement's newest check, by
// requirement id.
func (d *DB) LatestRequirementChecks() (map[int]RequirementCheck, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + requirementCheckColumns + ` FROM requirement_checks
		WHERE id IN (SELECT MAX(id) FROM requirement_checks GROUP BY requirement_id)`)
	if err != nil {
		return nil, fmt.Errorf("statedb: read requirement checks: %w", classifyDriverErr(err))
	}
	checks, err := scanRequirementChecks(rows)
	if err != nil {
		return nil, err
	}
	out := make(map[int]RequirementCheck, len(checks))
	for _, c := range checks {
		out[c.RequirementID] = c
	}
	return out, nil
}

// RequirementChecks returns a requirement's checks, newest first, at most
// limit of them.
func (d *DB) RequirementChecks(id, limit int) ([]RequirementCheck, error) {
	if limit <= 0 || limit > requirementChecksKept {
		limit = requirementChecksKept
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+requirementCheckColumns+` FROM requirement_checks
		WHERE requirement_id = ? ORDER BY id DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: read requirement checks: %w", classifyDriverErr(err))
	}
	return scanRequirementChecks(rows)
}

// ── check runs ──────────────────────────────────────────────────────────────

const requirementRunColumns = `run_id, state, source, started_by, started_at, deadline, finished_at, executor_id,
	assess, requirement_ids, fulfilled, unfulfilled, unverified, errored, error, cancel_requested, heartbeat`

// liveRunSQL selects the runs still holding their project's one check: running,
// inside their deadline, and heard from lately. Its two arguments are now and
// the oldest heartbeat that still counts.
const liveRunSQL = `state = '` + RequirementRunRunning + `' AND deadline > ? AND heartbeat > ?`

func liveRunArgs(now time.Time) []any {
	return []any{formatReqTime(now), formatReqTime(now.Add(-requirementRunSilence))}
}

func scanRequirementRuns(rows *sql.Rows, now time.Time) ([]RequirementRun, error) {
	defer rows.Close()
	var out []RequirementRun
	for rows.Next() {
		var (
			r                          RequirementRun
			started, deadline, finish  string
			assess, cancel             int
			ids, heartbeat             string
			startedBy, executor, errTx string
		)
		if err := rows.Scan(&r.RunID, &r.State, &r.Source, &startedBy, &started, &deadline, &finish, &executor,
			&assess, &ids, &r.Counts.Fulfilled, &r.Counts.Unfulfilled, &r.Counts.Unverified, &r.Counts.Error,
			&errTx, &cancel, &heartbeat); err != nil {
			return nil, fmt.Errorf("statedb: read requirement runs: %w", classifyDriverErr(err))
		}
		r.StartedBy, r.ExecutorID, r.Error = clipText(startedBy, 4*requirements.MaxActorRunes), clipText(executor, 256), clipText(errTx, 2048)
		r.StartedAt, r.Deadline, r.FinishedAt = parseReqTime(started), parseReqTime(deadline), parseReqTime(finish)
		r.Assess, r.CancelRequested = assess != 0, cancel != 0
		if len(ids) <= 64<<10 {
			_ = json.Unmarshal([]byte(ids), &r.RequirementIDs)
		}
		if len(r.RequirementIDs) > requirements.MaxRequirements {
			r.RequirementIDs = r.RequirementIDs[:requirements.MaxRequirements]
		}
		if r.State == RequirementRunRunning && (now.After(r.Deadline) || now.Sub(parseReqTime(heartbeat)) > requirementRunSilence) {
			r.State = RequirementRunLapsed
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read requirement runs: %w", classifyDriverErr(err))
	}
	return out, nil
}

// StartRequirementRun records run as running, unless another run of this
// project still is — then it returns that run and ErrRequirementCheckRunning.
// One check at a time per project, across every hub member: two would run the
// same tests in the same tree at once.
func (d *DB) StartRequirementRun(run RequirementRun) (RequirementRun, error) {
	now := time.Now().UTC()
	if run.StartedAt.IsZero() {
		run.StartedAt = now
	}
	run.State = RequirementRunRunning
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return RequirementRun{}, fmt.Errorf("statedb: start requirement check: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit
	rows, err := tx.Query(`SELECT `+requirementRunColumns+` FROM requirement_runs
		WHERE `+liveRunSQL+` ORDER BY started_at DESC LIMIT 1`, liveRunArgs(now)...)
	if err != nil {
		return RequirementRun{}, fmt.Errorf("statedb: start requirement check: %w", classifyDriverErr(err))
	}
	busy, err := scanRequirementRuns(rows, now)
	if err != nil {
		return RequirementRun{}, err
	}
	if len(busy) > 0 {
		return busy[0], fmt.Errorf("%w: %s started by %s at %s", ErrRequirementCheckRunning, busy[0].RunID,
			busy[0].StartedBy, busy[0].StartedAt.Format(time.RFC3339))
	}
	ids := run.RequirementIDs
	if ids == nil {
		ids = []int{}
	}
	if _, err := tx.Exec(`INSERT INTO requirement_runs
		(run_id, state, source, started_by, started_at, deadline, executor_id, assess, requirement_ids, heartbeat)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.RunID, run.State, clipText(run.Source, 32), clipActor(run.StartedBy), formatReqTime(run.StartedAt),
		formatReqTime(run.Deadline), clipText(run.ExecutorID, 256), boolInt(run.Assess), marshalJSONColumn(ids, "[]"),
		formatReqTime(now)); err != nil {
		return RequirementRun{}, fmt.Errorf("statedb: start requirement check: %w", classifyDriverErr(err))
	}
	if err := trimRequirementRunsTx(tx); err != nil {
		return RequirementRun{}, err
	}
	if err := tx.Commit(); err != nil {
		return RequirementRun{}, fmt.Errorf("statedb: start requirement check: %w", classifyDriverErr(err))
	}
	return run, nil
}

// RecordFinishedRequirementRun records a run that is already over: a check
// `cloop requirements check` ran by hand, which takes no place in the queue —
// it holds nothing the hub could be refused by if it died half way.
func (d *DB) RecordFinishedRequirementRun(run RequirementRun) error {
	switch run.State {
	case RequirementRunDone, RequirementRunFailed, RequirementRunCancelled:
	default:
		return fmt.Errorf("statedb: a finished check run cannot be %q", run.State)
	}
	now := time.Now().UTC()
	if run.StartedAt.IsZero() {
		run.StartedAt = now
	}
	if run.FinishedAt.IsZero() {
		run.FinishedAt = now
	}
	ids := run.RequirementIDs
	if ids == nil {
		ids = []int{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: record requirement check: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit
	if _, err := tx.Exec(`INSERT INTO requirement_runs
		(run_id, state, source, started_by, started_at, deadline, finished_at, executor_id, assess, requirement_ids,
		 fulfilled, unfulfilled, unverified, errored, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.RunID, run.State, clipText(run.Source, 32), clipActor(run.StartedBy), formatReqTime(run.StartedAt),
		formatReqTime(run.FinishedAt), formatReqTime(run.FinishedAt), clipText(run.ExecutorID, 256), boolInt(run.Assess),
		marshalJSONColumn(ids, "[]"), run.Counts.Fulfilled, run.Counts.Unfulfilled, run.Counts.Unverified,
		run.Counts.Error, clipText(run.Error, 2048)); err != nil {
		return fmt.Errorf("statedb: record requirement check: %w", classifyDriverErr(err))
	}
	if err := trimRequirementRunsTx(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: record requirement check: %w", classifyDriverErr(err))
	}
	return nil
}

// trimRequirementRunsTx keeps the newest requirementRunsKept runs that have
// ended; one still running is never trimmed.
func trimRequirementRunsTx(tx *sql.Tx) error {
	if _, err := tx.Exec(`DELETE FROM requirement_runs WHERE state != ? AND started_at <= (
		SELECT started_at FROM requirement_runs ORDER BY started_at DESC LIMIT 1 OFFSET ?)`,
		RequirementRunRunning, requirementRunsKept); err != nil {
		return fmt.Errorf("statedb: trim requirement runs: %w", classifyDriverErr(err))
	}
	return nil
}

// FinishRequirementRun records how a run ended, unless it already has. It
// reports whether this call was the one that ended it.
func (d *DB) FinishRequirementRun(runID, state string, counts requirements.Counts, executorID, reason string) (bool, error) {
	switch state {
	case RequirementRunDone, RequirementRunFailed, RequirementRunCancelled:
	default:
		return false, fmt.Errorf("statedb: a check run cannot end %q", state)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`UPDATE requirement_runs SET state = ?, finished_at = ?, fulfilled = ?, unfulfilled = ?,
		unverified = ?, errored = ?, error = ?, executor_id = CASE WHEN ? != '' THEN ? ELSE executor_id END
		WHERE run_id = ? AND state = ?`,
		state, formatReqTime(time.Now()), counts.Fulfilled, counts.Unfulfilled, counts.Unverified, counts.Error,
		clipText(reason, 2048), executorID, clipText(executorID, 256), runID, RequirementRunRunning)
	if err != nil {
		return false, fmt.Errorf("statedb: finish requirement check %s: %w", runID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RequirementRunByID reads one run, or ErrRequirementNotFound.
func (d *DB) RequirementRunByID(runID string) (RequirementRun, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+requirementRunColumns+` FROM requirement_runs WHERE run_id = ?`, runID)
	if err != nil {
		return RequirementRun{}, fmt.Errorf("statedb: read requirement run: %w", classifyDriverErr(err))
	}
	runs, err := scanRequirementRuns(rows, time.Now())
	if err != nil {
		return RequirementRun{}, err
	}
	if len(runs) == 0 {
		return RequirementRun{}, fmt.Errorf("%w: check run %s", ErrRequirementNotFound, clipText(runID, 64))
	}
	return runs[0], nil
}

// RecentRequirementRuns returns the newest runs first, at most limit. A run
// still recorded as running past its deadline reads as lapsed.
func (d *DB) RecentRequirementRuns(limit int) ([]RequirementRun, error) {
	if limit <= 0 || limit > requirementRunsKept {
		limit = requirementRunsKept
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+requirementRunColumns+` FROM requirement_runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: read requirement runs: %w", classifyDriverErr(err))
	}
	return scanRequirementRuns(rows, time.Now())
}

// ActiveRequirementRun returns the run in progress, if there is one.
func (d *DB) ActiveRequirementRun() (RequirementRun, bool, error) {
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+requirementRunColumns+` FROM requirement_runs
		WHERE `+liveRunSQL+` ORDER BY started_at DESC LIMIT 1`, liveRunArgs(now)...)
	if err != nil {
		return RequirementRun{}, false, fmt.Errorf("statedb: read requirement runs: %w", classifyDriverErr(err))
	}
	runs, err := scanRequirementRuns(rows, now)
	if err != nil || len(runs) == 0 {
		return RequirementRun{}, false, err
	}
	return runs[0], true, nil
}

// RequestRequirementRunCancel asks the member running a check to stop it. It
// reports whether the run was still running to be asked.
func (d *DB) RequestRequirementRunCancel(runID string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`UPDATE requirement_runs SET cancel_requested = 1 WHERE run_id = ? AND state = ?`,
		runID, RequirementRunRunning)
	if err != nil {
		return false, fmt.Errorf("statedb: cancel requirement check %s: %w", runID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// TouchRequirementRun is the running member's heartbeat for runID, every
// RequirementRunHeartbeat: it records that the check is still running, and
// reports whether somebody asked to stop it.
func (d *DB) TouchRequirementRun(runID string) (cancelRequested bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE requirement_runs SET heartbeat = ? WHERE run_id = ? AND state = ?`,
		formatReqTime(time.Now()), runID, RequirementRunRunning); err != nil {
		return false, fmt.Errorf("statedb: touch requirement run %s: %w", runID, classifyDriverErr(err))
	}
	var n int
	err = d.conn.QueryRow(`SELECT cancel_requested FROM requirement_runs WHERE run_id = ?`, runID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("statedb: read requirement run %s: %w", runID, classifyDriverErr(err))
	}
	return n != 0, nil
}

// AuditRequirementCheck records a check run's end in the project's trail.
// Best effort, like every emit helper; d must be the project's handle.
func AuditRequirementCheck(d *DB, run RequirementRun, commit string, dirty bool, actor string) {
	ids := append([]int(nil), run.RequirementIDs...)
	sort.Ints(ids)
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementCheck),
		EntityType: "requirement", EntityID: run.RunID,
		Payload: MarshalAuditPayload(map[string]any{
			"run_id": run.RunID, "state": run.State, "source": run.Source, "requirement_ids": ids,
			"assess": run.Assess, "executor_id": run.ExecutorID, "commit": commit, "dirty": dirty,
			"fulfilled": run.Counts.Fulfilled, "unfulfilled": run.Counts.Unfulfilled,
			"unverified": run.Counts.Unverified, "error": run.Counts.Error, "reason": run.Error,
		}),
	})
}

func testCommands(ts []requirements.Test) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Command)
	}
	return out
}

func clipActor(a string) string {
	return clipText(strings.TrimSpace(a), 4*requirements.MaxActorRunes)
}

func actorOrSystem(a string) string {
	if a = clipActor(a); a == "" {
		return "system"
	}
	return a
}
