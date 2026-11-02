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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/pm"
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
	// TaskID is the task whose completion the check gated (Task 20461); 0
	// for a check that gated none.
	TaskID int `json:"task_id,omitempty"`
	// Regression reports that the requirement was fulfilled at its previous
	// check of the same definition, and is unfulfilled at this one.
	Regression bool `json:"regression,omitempty"`
	// Persisting reports a regression carried over from the same task's
	// previous check: the requirement broke at an earlier attempt and still
	// fails. The journal and the notifier report a regression once, at the
	// check where it happened.
	Persisting bool `json:"persisting,omitempty"`
	// Was is that previous check, on the checks RecordRequirementChecks
	// returns for a regression. Not stored: the previous check is the row
	// before this one.
	Was *PriorCheck `json:"was,omitempty"`
}

// PriorCheck is the check a regression is measured against.
type PriorCheck struct {
	ID        int64     `json:"id"`
	Verdict   string    `json:"verdict"`
	Commit    string    `json:"commit,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	TaskID    int       `json:"task_id,omitempty"`
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
	// TaskID is the task whose completion the run gated (Task 20461); 0 for
	// a run that gated none.
	TaskID int `json:"task_id,omitempty"`
	// Kind is check, or prove for a run of red-green proofs (Task 20464):
	// both take the project's one check slot. Empty reads as check.
	Kind string `json:"kind,omitempty"`
}

// CheckRecord is what recording one check run's results needs besides the
// results themselves.
type CheckRecord struct {
	RunID      string
	Commit     string
	Dirty      bool
	ExecutorID string
	CheckedBy  string
	// TaskID is the task whose completion the check gates (Task 20461).
	TaskID int
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

const requirementColumns = `id, title, description, priority, tags, tests, created_at, updated_at, created_by, updated_by, status,
	approved_by, approved_at`

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
			approvedBy, approved string
		)
		if err := rows.Scan(&r.ID, &r.Title, &r.Description, &r.Priority, &tags, &tests, &created, &updated,
			&createdBy, &updatedBy, &r.Status, &approvedBy, &approved); err != nil {
			return nil, fmt.Errorf("statedb: read requirements: %w", classifyDriverErr(err))
		}
		boundRequirementRow(&r, tags, tests, created, updated)
		r.CreatedBy, r.UpdatedBy = clipText(createdBy, 4*requirements.MaxActorRunes), clipText(updatedBy, 4*requirements.MaxActorRunes)
		// Who approved it, for an approved requirement only: whatever else
		// says so has since stopped being approved.
		if r.Status == requirements.StatusApproved {
			r.ApprovedBy, r.ApprovedAt = clipText(approvedBy, 4*requirements.MaxActorRunes), parseReqTime(approved)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read requirements: %w", classifyDriverErr(err))
	}
	return out, nil
}

// boundRequirementRow finishes a requirement read from a row: its texts
// clipped, its JSON columns decoded leniently and bounded, its times parsed.
// The row may have been written by something other than this package.
func boundRequirementRow(r *requirements.Requirement, tags, tests, created, updated string) {
	r.Title = clipText(r.Title, 4*requirements.MaxTitleRunes)
	r.Description = clipText(r.Description, 4*requirements.MaxDescriptionRunes)
	r.Priority = clipText(r.Priority, 16)
	if !requirements.ValidStatus(r.Status) {
		// Written by something other than this package: whatever it meant,
		// it is not approved, so no check runs it unasked.
		r.Status = requirements.StatusDraft
	}
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
	r.Status = r.CurrentStatus()
	// Added approved, it was approved by whoever added it.
	r.ApprovedBy, r.ApprovedAt = "", time.Time{}
	if r.Status == requirements.StatusApproved {
		r.ApprovedBy, r.ApprovedAt = r.CreatedBy, now
	}

	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return r, fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
	}
	err = func() error {
		if err := roomForRequirementsTx(tx, 1); err != nil {
			return err
		}
		if err := insertRequirementTx(tx, &r, now); err != nil {
			return err
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
	auditRequirementCreate(d, r, actor, "")
	return r, nil
}

// roomForRequirementsTx refuses n more requirements in a project that has no
// room for them.
func roomForRequirementsTx(tx *sql.Tx, n int) error {
	var held int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM requirements`).Scan(&held); err != nil {
		return fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
	}
	if held+n > requirements.MaxRequirements {
		if n == 1 {
			return fmt.Errorf("%w: a project holds at most %d requirements", requirements.ErrInvalid, requirements.MaxRequirements)
		}
		return fmt.Errorf("%w: a project holds at most %d requirements, and this one holds %d: there is no room for %d more",
			requirements.ErrInvalid, requirements.MaxRequirements, held, n)
	}
	return nil
}

// insertRequirementTx stores r, as AddRequirement prepared it, and gives it
// its id.
func insertRequirementTx(tx *sql.Tx, r *requirements.Requirement, now time.Time) error {
	res, err := tx.Exec(`INSERT INTO requirements
		(title, description, priority, tags, tests, created_at, updated_at, created_by, updated_by, status,
		 approved_by, approved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Title, r.Description, r.Priority, marshalJSONColumn(r.Tags, "[]"), marshalJSONColumn(r.Tests, "[]"),
		formatReqTime(now), formatReqTime(now), r.CreatedBy, r.UpdatedBy, r.Status, r.ApprovedBy, formatReqTime(r.ApprovedAt))
	if err != nil {
		return fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("statedb: add requirement: %w", classifyDriverErr(err))
	}
	r.ID = int(id)
	return nil
}

// auditRequirementCreate records r added by actor; drafted, when the model
// drafted it, says from what (Task 20462).
func auditRequirementCreate(d *DB, r requirements.Requirement, actor, drafted string) {
	payload := map[string]any{
		"id": r.ID, "title": r.Title, "priority": r.Priority, "status": r.Status, "tests": testCommands(r.Tests),
		"fingerprint": r.Fingerprint(),
	}
	if drafted != "" {
		payload["drafted"] = drafted
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementCreate),
		EntityType: "requirement", EntityID: fmt.Sprint(r.ID), Payload: MarshalAuditPayload(payload),
	})
}

// DraftOrigin says where a set of drafted requirements came from: what the
// model drafted from, a digest of the text, and where it ran.
type DraftOrigin struct {
	// Source is goal, text (pasted in the dashboard), file or stdin.
	Source string
	// SHA256 and Bytes describe the text drafted from.
	SHA256 string
	Bytes  int
	// ExecutorID is where the model ran; Via is dashboard or cli.
	ExecutorID string
	Via        string
	// Refused counts the proposals that did not become drafts.
	Refused int
}

// AddDraftRequirements stores drafts — requirements the model drafted, which
// the caller has passed through requirements.CheckDraftResult — as new
// requirements with the status draft, all of them or none, and returns them
// with their ids. actor is the person who asked for them. Each is audited as
// a requirement.create naming where it was drafted from, and the set as one
// requirement.draft (Task 20462).
func (d *DB) AddDraftRequirements(drafts []requirements.Requirement, actor string, origin DraftOrigin) ([]requirements.Requirement, error) {
	if len(drafts) > requirements.MaxDrafts {
		return nil, fmt.Errorf("%w: at most %d drafts at once, not %d", requirements.ErrInvalid, requirements.MaxDrafts, len(drafts))
	}
	now := time.Now().UTC()
	out := make([]requirements.Requirement, 0, len(drafts))
	for i, r := range drafts {
		// A draft, whatever it says: only a person approves.
		r.Status = requirements.StatusDraft
		if err := r.Normalize(); err != nil {
			return nil, fmt.Errorf("draft %d: %w", i+1, err)
		}
		r.ID, r.CreatedAt, r.UpdatedAt = 0, now, now
		r.CreatedBy, r.UpdatedBy = clipActor(actor), clipActor(actor)
		r.ApprovedBy, r.ApprovedAt = "", time.Time{}
		out = append(out, r)
	}
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return nil, fmt.Errorf("statedb: add drafts: %w", classifyDriverErr(err))
	}
	err = func() error {
		if err := roomForRequirementsTx(tx, len(out)); err != nil {
			return err
		}
		for i := range out {
			if err := insertRequirementTx(tx, &out[i], now); err != nil {
				return err
			}
		}
		return tx.Commit()
	}()
	if err != nil {
		_ = tx.Rollback()
	}
	d.mu.Unlock()
	if err != nil {
		return nil, classifyDriverErr(err)
	}
	ids := make([]int, len(out))
	for i, r := range out {
		ids[i] = r.ID
		auditRequirementCreate(d, r, actor, origin.Source)
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementDraft),
		EntityType: "requirement", EntityID: "draft",
		Payload: MarshalAuditPayload(map[string]any{
			"source": origin.Source, "sha256": origin.SHA256, "bytes": origin.Bytes, "ids": ids,
			"refused": origin.Refused, "executor_id": origin.ExecutorID, "via": origin.Via,
		}),
	})
	return out, nil
}

// ApproveRequirements approves the drafts ids names, in one transaction:
// each must be a draft, or already approved, which it stays — so approving
// "all" twice, or a draft somebody else approved a moment before, is not an
// error. A deprecated requirement is reinstated by editing it, not here.
// actor is recorded as each one's approver, and each approval is audited as a
// requirement.approve. It returns the requirements approved now, and the ids
// of those that already were.
func (d *DB) ApproveRequirements(ids []int, actor string) (approved []requirements.Requirement, already []int, err error) {
	if len(ids) == 0 {
		return nil, nil, fmt.Errorf("%w: name the drafts to approve", requirements.ErrInvalid)
	}
	if len(ids) > requirements.MaxRequirements {
		return nil, nil, fmt.Errorf("%w: at most %d requirements at once", requirements.ErrInvalid, requirements.MaxRequirements)
	}
	now := time.Now().UTC()
	who := clipActor(actor)
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return nil, nil, fmt.Errorf("statedb: approve requirements: %w", classifyDriverErr(err))
	}
	err = func() error {
		seen := map[int]bool{}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			rs, err := queryRequirements(tx, `WHERE id = ?`, id)
			if err != nil {
				return err
			}
			if len(rs) == 0 {
				return fmt.Errorf("%w: %s", ErrRequirementNotFound, requirements.Key(id))
			}
			r := rs[0]
			switch r.CurrentStatus() {
			case requirements.StatusApproved:
				already = append(already, id)
				continue
			case requirements.StatusDeprecated:
				return fmt.Errorf("%w: %s is deprecated, not a draft: edit its status to reinstate it",
					requirements.ErrInvalid, requirements.Key(id))
			}
			if _, err := tx.Exec(`UPDATE requirements SET status = ?, approved_by = ?, approved_at = ?, updated_at = ?,
				updated_by = ? WHERE id = ?`, requirements.StatusApproved, who, formatReqTime(now), formatReqTime(now), who, id); err != nil {
				return fmt.Errorf("statedb: approve %s: %w", requirements.Key(id), classifyDriverErr(err))
			}
			r.Status, r.ApprovedBy, r.ApprovedAt, r.UpdatedAt, r.UpdatedBy = requirements.StatusApproved, who, now, now, who
			approved = append(approved, r)
		}
		return tx.Commit()
	}()
	if err != nil {
		_ = tx.Rollback()
	}
	d.mu.Unlock()
	if err != nil {
		return nil, nil, classifyDriverErr(err)
	}
	for _, r := range approved {
		auditRequirementApprove(d, r, requirements.StatusDraft, actor, "approve")
	}
	return approved, already, nil
}

// auditRequirementApprove records r becoming approved from the status was,
// by actor; how is the way it was done — approve, edit or import.
func auditRequirementApprove(d *DB, r requirements.Requirement, was, actor, how string) {
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementApprove),
		EntityType: "requirement", EntityID: fmt.Sprint(r.ID),
		Payload: MarshalAuditPayload(map[string]any{
			"id": r.ID, "title": r.Title, "previous_status": was, "via": how, "priority": r.Priority,
			"tests": testCommands(r.Tests), "fingerprint": r.Fingerprint(), "approved_by": r.ApprovedBy,
		}),
	})
}

// SeedRequirements stores reqs under their own ids, as a project seed carries
// them to an executor that does not share the hub's database (Task 20460): the
// requirements the plan's unfinished tasks implement, which the run there
// gives its agent as each task's contract. A requirement already stored under
// an id is replaced in its definition. Nothing is audited — the hub recorded
// these requirements when they were written; this is its copy for one run.
func (d *DB) SeedRequirements(reqs []requirements.Requirement) error {
	if len(reqs) == 0 {
		return nil
	}
	if len(reqs) > requirements.MaxRequirements {
		return fmt.Errorf("%w: a seed carries at most %d requirements", requirements.ErrInvalid, requirements.MaxRequirements)
	}
	now := formatReqTime(time.Now())
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: seed requirements: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit
	for _, r := range reqs {
		id := r.ID
		if id <= 0 {
			return fmt.Errorf("%w: a seeded requirement has no id", requirements.ErrInvalid)
		}
		if err := r.Normalize(); err != nil {
			return fmt.Errorf("%s: %w", requirements.Key(id), err)
		}
		if _, err := tx.Exec(`INSERT INTO requirements
			(id, title, description, priority, tags, tests, created_at, updated_at, created_by, updated_by, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)
			ON CONFLICT(id) DO UPDATE SET title = excluded.title, description = excluded.description,
				priority = excluded.priority, tags = excluded.tags, tests = excluded.tests,
				updated_at = excluded.updated_at, status = excluded.status`,
			id, r.Title, r.Description, r.Priority, marshalJSONColumn(r.Tags, "[]"), marshalJSONColumn(r.Tests, "[]"),
			now, now, r.CurrentStatus()); err != nil {
			return fmt.Errorf("statedb: seed requirement %s: %w", requirements.Key(id), classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: seed requirements: %w", classifyDriverErr(err))
	}
	return nil
}

// UpdateRequirement replaces the definition of the requirement r.ID names with
// r's, keeping when and by whom it was created, and returns it as stored. A
// requirement given no status keeps the one it has.
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
		if r.Status == "" {
			r.Status = before.Status
		}
		// Becoming approved is an approval, recorded with who made it
		// (Task 20462); leaving approved takes the approval back.
		r.ApprovedBy, r.ApprovedAt = before.ApprovedBy, before.ApprovedAt
		switch {
		case r.CurrentStatus() == requirements.StatusApproved && before.CurrentStatus() != requirements.StatusApproved:
			r.ApprovedBy, r.ApprovedAt = clipActor(actor), now
		case r.CurrentStatus() != requirements.StatusApproved:
			r.ApprovedBy, r.ApprovedAt = "", time.Time{}
		}
		if _, err := tx.Exec(`UPDATE requirements SET title = ?, description = ?, priority = ?, tags = ?, tests = ?,
			status = ?, updated_at = ?, updated_by = ?, approved_by = ?, approved_at = ? WHERE id = ?`,
			r.Title, r.Description, r.Priority, marshalJSONColumn(r.Tags, "[]"), marshalJSONColumn(r.Tests, "[]"),
			r.Status, formatReqTime(now), clipActor(actor), r.ApprovedBy, formatReqTime(r.ApprovedAt), r.ID); err != nil {
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
	changed := changedRequirementFields(before, r)
	approval := r.CurrentStatus() == requirements.StatusApproved && before.CurrentStatus() != requirements.StatusApproved
	// An approval is its own row; the update row is for what else changed.
	if approval && len(changed) == 1 {
		changed = nil
	}
	if len(changed) > 0 {
		emit(d, &AuditEvent{
			Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementUpdate),
			EntityType: "requirement", EntityID: fmt.Sprint(r.ID),
			Payload: MarshalAuditPayload(map[string]any{
				"id": r.ID, "title": r.Title, "changed": changed, "status": r.Status, "tests": testCommands(r.Tests),
				"fingerprint": r.Fingerprint(), "previous_fingerprint": before.Fingerprint(),
			}),
		})
	}
	if approval {
		auditRequirementApprove(d, r, before.CurrentStatus(), actor, "edit")
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
	if a.CurrentStatus() != b.CurrentStatus() {
		out = append(out, "status")
	}
	return out
}

// DeleteRequirement deletes a requirement and the history of its checks,
// takes it out of every task that implements it (Task 20460), and returns the
// requirement as it was and the ids of those tasks. The tasks change in the
// transaction that deletes it, so no task is ever left linked to a requirement
// that is gone; the requirement.delete row names them, and each gets its
// task.upsert row under the same actor.
func (d *DB) DeleteRequirement(id int, actor string) (requirements.Requirement, []int, error) {
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return requirements.Requirement{}, nil, fmt.Errorf("statedb: delete requirement: %w", classifyDriverErr(err))
	}
	var (
		gone     requirements.Requirement
		checks   int64
		proofs   int64
		unlinked []*pm.Task
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
		if proofs, err = deleteRequirementProofsTx(tx, id); err != nil {
			return err
		}
		if unlinked, err = unlinkRequirementTx(tx, id); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if err != nil {
		_ = tx.Rollback()
	}
	d.mu.Unlock()
	if err != nil {
		return gone, nil, classifyDriverErr(err)
	}
	taskIDs := make([]int, 0, len(unlinked))
	for _, t := range unlinked {
		taskIDs = append(taskIDs, t.ID)
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementDelete),
		EntityType: "requirement", EntityID: fmt.Sprint(id),
		Payload: MarshalAuditPayload(map[string]any{"id": id, "title": gone.Title, "checks": checks,
			"proofs": proofs, "unlinked_tasks": taskIDs}),
	})
	for _, t := range unlinked {
		auditTaskUpsert(d, t, actorOrSystem(actor))
	}
	return gone, taskIDs, nil
}

// unlinkRequirementTx takes requirement id out of every task that implements
// it and returns those tasks as they now are.
//
// Each task's audit fingerprint moves with its row, as UpsertTask's does: the
// change is recorded once, by DeleteRequirement under its actor, instead of
// again by whichever save comes next as the system's.
//
// A row whose list cannot be read is left alone. It already keeps the project
// from loading (decodeTaskColumns), and the error that says so names the row;
// rewriting it here would destroy what the repair needs to see.
func unlinkRequirementTx(tx *sql.Tx, id int) ([]*pm.Task, error) {
	rows, err := tx.Query(`SELECT id, requirements FROM plan_tasks WHERE requirements NOT IN ('[]', 'null', '')`)
	if err != nil {
		return nil, fmt.Errorf("statedb: read task requirements: %w", classifyDriverErr(err))
	}
	type relink struct {
		task int
		keep []int
	}
	var todo []relink
	for rows.Next() {
		var (
			task int
			raw  string
		)
		if err := rows.Scan(&task, &raw); err != nil {
			rows.Close()
			return nil, fmt.Errorf("statedb: read task requirements: %w", classifyDriverErr(err))
		}
		ids, err := decodeList[int](raw)
		if err != nil || !slices.Contains(ids, id) {
			continue
		}
		todo = append(todo, relink{task: task, keep: slices.DeleteFunc(ids, func(x int) bool { return x == id })})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("statedb: read task requirements: %w", classifyDriverErr(err))
	}
	rows.Close()

	out := make([]*pm.Task, 0, len(todo))
	for _, r := range todo {
		if _, err := tx.Exec(`UPDATE plan_tasks SET requirements = ? WHERE id = ?`, listText(r.keep), r.task); err != nil {
			return nil, fmt.Errorf("statedb: unlink %s from task %d: %w", requirements.Key(id), r.task, classifyDriverErr(err))
		}
		trows, err := tx.Query(taskSelect+` WHERE id = ?`, r.task)
		if err != nil {
			return nil, fmt.Errorf("statedb: read task %d: %w", r.task, classifyDriverErr(err))
		}
		var t *pm.Task
		if trows.Next() {
			t, err = newTaskScanner().scan(trows)
		}
		if err == nil {
			err = trows.Err()
		}
		trows.Close()
		if err != nil {
			return nil, fmt.Errorf("statedb: read task %d: %w", r.task, classifyDriverErr(err))
		}
		if t == nil {
			continue
		}
		if err := recordTaskFingerprintTx(tx, t.ID, MarshalAuditPayload(t)); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
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
		// A regression is measured against the requirement's previous check
		// of the same definition: a verdict about what it used to require
		// says nothing about what the project does now (Task 20461).
		var (
			was        *PriorCheck
			persisting bool
		)
		if res.Verdict == requirements.VerdictUnfulfilled {
			if was, persisting, err = priorCheckTx(tx, res.RequirementID, fp, rec.TaskID); err != nil {
				return nil, err
			}
			if was != nil && was.Verdict != requirements.VerdictFulfilled {
				was, persisting = nil, false
			}
		}
		c := RequirementCheck{
			RequirementID: res.RequirementID, RunID: clipText(rec.RunID, 64), Method: clipText(res.Method, 16),
			Verdict: res.Verdict, Summary: clipText(res.Summary, 4*requirements.MaxRationaleRunes),
			Tests: append([]requirements.TestResult(nil), res.Tests...), Evidence: res.Evidence, Fingerprint: fp, Commit: clipText(rec.Commit, 64), Dirty: rec.Dirty,
			ExecutorID: clipText(rec.ExecutorID, 256), CheckedBy: clipActor(rec.CheckedBy),
			CheckedAt: res.StartedAt.UTC(), DurationMS: res.DurationMS,
			TaskID: max(rec.TaskID, 0), Regression: was != nil, Persisting: persisting, Was: was,
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
			 executor_id, checked_by, checked_at, duration_ms, task_id, regression)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.RequirementID, c.RunID, c.Method, c.Verdict, c.Summary, detail, c.Fingerprint, c.Commit, boolInt(c.Dirty),
			c.ExecutorID, c.CheckedBy, formatReqTime(c.CheckedAt), c.DurationMS, c.TaskID, regressionColumn(c))
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
	if req.CurrentStatus() == requirements.StatusDraft {
		return RequirementCheck{}, fmt.Errorf("%w: %s is a draft: approve it before it is given a verdict",
			requirements.ErrInvalid, requirements.Key(id))
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
	dirty, executor_id, checked_by, checked_at, duration_ms, task_id, regression`

// priorCheckTx is what a new check of requirement id, whose definition is fp,
// is measured against: its newest earlier check of that definition that
// reached a verdict about it — fulfilled or unfulfilled; a check that could
// not run, or that nothing could verify, says nothing about the project. For a
// check that gates task (task > 0), that task's own unfulfilled checks are
// passed over too: they are its earlier attempts at the work, and the
// requirement it broke on the first is still a regression on the next —
// persisting reports that one was passed over. Nil when there is none.
func priorCheckTx(tx *sql.Tx, id int, fp string, task int) (prior *PriorCheck, persisting bool, err error) {
	rows, err := tx.Query(`SELECT id, verdict, git_commit, checked_at, task_id FROM requirement_checks
		WHERE requirement_id = ? AND fingerprint = ? ORDER BY id DESC LIMIT ?`, id, fp, requirementChecksKept)
	if err != nil {
		return nil, false, fmt.Errorf("statedb: read the previous checks of %s: %w", requirements.Key(id), classifyDriverErr(err))
	}
	defer rows.Close()
	for rows.Next() {
		var (
			p      PriorCheck
			at     string
			commit string
		)
		if err := rows.Scan(&p.ID, &p.Verdict, &commit, &at, &p.TaskID); err != nil {
			return nil, false, fmt.Errorf("statedb: read the previous checks of %s: %w", requirements.Key(id), classifyDriverErr(err))
		}
		switch {
		case p.Verdict != requirements.VerdictFulfilled && p.Verdict != requirements.VerdictUnfulfilled:
			continue
		case task > 0 && p.TaskID == task && p.Verdict == requirements.VerdictUnfulfilled:
			persisting = true
			continue
		}
		p.Commit, p.CheckedAt = requirements.CleanCommit(commit), parseReqTime(at)
		return &p, persisting, nil
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("statedb: read the previous checks of %s: %w", requirements.Key(id), classifyDriverErr(err))
	}
	return nil, false, nil
}

// regressionColumn is a check's requirement_checks.regression: 0 for none, 1
// for a regression that happened at this check, 2 for one carried over from
// the same task's earlier check.
func regressionColumn(c RequirementCheck) int {
	switch {
	case c.Persisting:
		return 2
	case c.Regression:
		return 1
	}
	return 0
}

func scanRequirementChecks(rows *sql.Rows) ([]RequirementCheck, error) {
	defer rows.Close()
	var out []RequirementCheck
	for rows.Next() {
		var (
			c              RequirementCheck
			detail, at     string
			dirty          int
			summary, runID string
			regression     int
		)
		if err := rows.Scan(&c.ID, &c.RequirementID, &runID, &c.Method, &c.Verdict, &summary, &detail, &c.Fingerprint,
			&c.Commit, &dirty, &c.ExecutorID, &c.CheckedBy, &at, &c.DurationMS, &c.TaskID, &regression); err != nil {
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
		c.Regression, c.Persisting = regression != 0, regression == 2
		if c.TaskID < 0 {
			c.TaskID = 0
		}
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

// RequirementRegressionsSince returns the checks at which a regression
// happened at or after since — not the later checks it persisted through —
// newest first, at most limit of them (Task 20461). The hub's notifier reads
// them from every project it serves, so the query rides the regression index
// and reads no detail column.
func (d *DB) RequirementRegressionsSince(since time.Time, limit int) ([]RequirementCheck, error) {
	if limit <= 0 || limit > requirementChecksKept {
		limit = requirementChecksKept
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT id, requirement_id, run_id, verdict, summary, fingerprint, git_commit,
			checked_at, task_id FROM requirement_checks
		WHERE regression = 1 AND checked_at >= ? ORDER BY id DESC LIMIT ?`, formatReqTime(since), limit)
	// regression = 2 is a persisting one: see regressionColumn.
	if err != nil {
		return nil, fmt.Errorf("statedb: read requirement regressions: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []RequirementCheck
	for rows.Next() {
		var (
			c                   RequirementCheck
			runID, summary, at  string
			commit, fingerprint string
		)
		if err := rows.Scan(&c.ID, &c.RequirementID, &runID, &c.Verdict, &summary, &fingerprint, &commit, &at,
			&c.TaskID); err != nil {
			return nil, fmt.Errorf("statedb: read requirement regressions: %w", classifyDriverErr(err))
		}
		c.RunID, c.Summary = clipText(runID, 64), clipText(summary, requirements.MaxSummaryRunes)
		c.Fingerprint, c.Commit = clipText(fingerprint, 128), requirements.CleanCommit(commit)
		if !requirements.ValidVerdict(c.Verdict) {
			c.Verdict = requirements.VerdictError
		}
		if c.TaskID < 0 {
			c.TaskID = 0
		}
		c.Regression, c.CheckedAt = true, parseReqTime(at)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read requirement regressions: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ── check runs ──────────────────────────────────────────────────────────────

const requirementRunColumns = `run_id, state, source, started_by, started_at, deadline, finished_at, executor_id,
	assess, requirement_ids, fulfilled, unfulfilled, unverified, errored, error, cancel_requested, heartbeat, task_id, kind`

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
			&errTx, &cancel, &heartbeat, &r.TaskID, &r.Kind); err != nil {
			return nil, fmt.Errorf("statedb: read requirement runs: %w", classifyDriverErr(err))
		}
		r.Kind = runKind(r.Kind)
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
	run.Kind = runKind(run.Kind)
	if _, err := tx.Exec(`INSERT INTO requirement_runs
		(run_id, state, source, started_by, started_at, deadline, executor_id, assess, requirement_ids, heartbeat, kind)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.RunID, run.State, clipText(run.Source, 32), clipActor(run.StartedBy), formatReqTime(run.StartedAt),
		formatReqTime(run.Deadline), clipText(run.ExecutorID, 256), boolInt(run.Assess), marshalJSONColumn(ids, "[]"),
		formatReqTime(now), run.Kind); err != nil {
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
		 fulfilled, unfulfilled, unverified, errored, error, task_id, kind)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.RunID, run.State, clipText(run.Source, 32), clipActor(run.StartedBy), formatReqTime(run.StartedAt),
		formatReqTime(run.FinishedAt), formatReqTime(run.FinishedAt), clipText(run.ExecutorID, 256), boolInt(run.Assess),
		marshalJSONColumn(ids, "[]"), run.Counts.Fulfilled, run.Counts.Unfulfilled, run.Counts.Unverified,
		run.Counts.Error, clipText(run.Error, 2048), max(run.TaskID, 0), runKind(run.Kind)); err != nil {
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
			"task_id": run.TaskID,
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

// runKind is a run's kind as stored: prove, or check for anything else.
func runKind(k string) string {
	if k == RequirementRunKindProve {
		return k
	}
	return RequirementRunKindCheck
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
