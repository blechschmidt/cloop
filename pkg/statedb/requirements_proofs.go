package statedb

// requirements_proofs.go stores red-green proofs of requirements' tests
// (Task 20464; migration 0090). See pkg/requirements/proof.go for the model.
//
// requirement_proofs is written when a proof ends, by whoever ran it: the hub,
// for one it dispatched to the project's executor; the requirements gate, for
// the tests a task added or changed; `cloop requirements prove` run by hand.
// Like requirement_checks it is bounded by its writer, and read back bounded
// again: on an executor that shares the project's directory the database is
// writable from inside the sandbox.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// requirementProofsKept is how many proofs a requirement keeps. A proof holds
// two runs' output where a check holds one, so fewer than checks.
const requirementProofsKept = 20

// Kinds of requirement run.
const (
	RequirementRunKindCheck = "check"
	RequirementRunKindProve = "prove"
)

// RequirementProof is one recorded proof of a requirement's tests.
type RequirementProof struct {
	ID int64 `json:"id"`
	requirements.Proof
	RunID      string    `json:"run_id,omitempty"`
	ExecutorID string    `json:"executor_id,omitempty"`
	ProvedBy   string    `json:"proved_by,omitempty"`
	ProvedAt   time.Time `json:"proved_at"`
	// TaskID is the task whose tests the proof was of; 0 for one asked for by
	// hand.
	TaskID int `json:"task_id,omitempty"`
}

// ProofRecord is what recording one run's proofs needs besides the proofs.
type ProofRecord struct {
	RunID      string
	ExecutorID string
	ProvedBy   string
	TaskID     int
}

// proofDetail is the JSON a proof's detail column holds.
type proofDetail struct {
	Before      requirements.ProofSide   `json:"before"`
	After       requirements.ProofSide   `json:"after"`
	TestFiles   []requirements.ProofFile `json:"test_files,omitempty"`
	CodeChanged bool                     `json:"code_changed,omitempty"`
}

const requirementProofColumns = `id, requirement_id, run_id, outcome, summary, detail, fingerprint, base_commit, base_from,
	git_commit, dirty, fallback, new_tests, executor_id, proved_by, proved_at, duration_ms, task_id`

// RecordRequirementProofs stores one run's proofs. A proof of a requirement
// deleted meanwhile is dropped, as is one whose requirement's definition
// changed while it ran: it is about tests the requirement no longer has. It
// returns the proofs it stored.
func (d *DB) RecordRequirementProofs(rec ProofRecord, proofs []requirements.Proof) ([]RequirementProof, error) {
	if len(proofs) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: record requirement proofs: %w", classifyDriverErr(err))
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
	var stored []RequirementProof
	touched := map[int]bool{}
	for _, p := range proofs {
		fp, ok := prints[p.RequirementID]
		if !ok || (p.Fingerprint != "" && p.Fingerprint != fp) || !requirements.ValidProofOutcome(p.Outcome) {
			continue
		}
		c := RequirementProof{Proof: p.Clone(), RunID: clipText(rec.RunID, 64), ExecutorID: clipText(rec.ExecutorID, 256),
			ProvedBy: clipActor(rec.ProvedBy), ProvedAt: p.StartedAt.UTC(), TaskID: max(rec.TaskID, 0)}
		c.Fingerprint = fp
		requirements.BoundProof(&c.Proof, requirements.MaxOutputBytes)
		if c.ProvedAt.IsZero() {
			c.ProvedAt = now
		}
		c.StartedAt = c.ProvedAt
		detail := marshalJSONColumn(proofDetail{Before: c.Before, After: c.After, TestFiles: c.TestFiles,
			CodeChanged: c.CodeChanged}, "{}")
		if len(detail) > maxCheckDetailBytes {
			for _, s := range []*requirements.ProofSide{&c.Before, &c.After} {
				for i := range s.Tests {
					s.Tests[i].Output, s.Tests[i].Truncated = "", true
				}
			}
			detail = marshalJSONColumn(proofDetail{Before: c.Before, After: c.After, TestFiles: c.TestFiles,
				CodeChanged: c.CodeChanged}, "{}")
		}
		r, err := tx.Exec(`INSERT INTO requirement_proofs
			(requirement_id, run_id, outcome, summary, detail, fingerprint, base_commit, base_from, git_commit, dirty,
			 fallback, new_tests, executor_id, proved_by, proved_at, duration_ms, task_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.RequirementID, c.RunID, c.Outcome, clipText(c.Summary, 4*requirements.MaxRationaleRunes), detail,
			c.Fingerprint, requirements.CleanCommit(c.Before.Commit), c.BaseFrom, requirements.CleanCommit(c.After.Commit),
			boolInt(c.After.Dirty), boolInt(c.Fallback), boolInt(c.NewTests), c.ExecutorID, c.ProvedBy,
			formatReqTime(c.ProvedAt), c.DurationMS, c.TaskID)
		if err != nil {
			return nil, fmt.Errorf("statedb: record requirement proof: %w", classifyDriverErr(err))
		}
		c.ID, _ = r.LastInsertId()
		stored = append(stored, c)
		touched[c.RequirementID] = true
	}
	for id := range touched {
		if _, err := tx.Exec(`DELETE FROM requirement_proofs WHERE requirement_id = ? AND id <= (
			SELECT id FROM requirement_proofs WHERE requirement_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`,
			id, id, requirementProofsKept); err != nil {
			return nil, fmt.Errorf("statedb: trim requirement proofs: %w", classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: record requirement proofs: %w", classifyDriverErr(err))
	}
	return stored, nil
}

func scanRequirementProofs(rows *sql.Rows) ([]RequirementProof, error) {
	defer rows.Close()
	var out []RequirementProof
	for rows.Next() {
		var (
			p                         RequirementProof
			detail, at, base, commit  string
			summary, runID            string
			dirty, fallback, newTests int
		)
		if err := rows.Scan(&p.ID, &p.RequirementID, &runID, &p.Outcome, &summary, &detail, &p.Fingerprint, &base,
			&p.BaseFrom, &commit, &dirty, &fallback, &newTests, &p.ExecutorID, &p.ProvedBy, &at, &p.DurationMS,
			&p.TaskID); err != nil {
			return nil, fmt.Errorf("statedb: read requirement proofs: %w", classifyDriverErr(err))
		}
		p.RunID, p.Summary = clipText(runID, 64), clipText(summary, 4*requirements.MaxRationaleRunes)
		if !requirements.ValidProofOutcome(p.Outcome) {
			p.Outcome = requirements.ProofError
		}
		var dt proofDetail
		if len(detail) <= maxCheckDetailBytes {
			_ = json.Unmarshal([]byte(detail), &dt)
		}
		p.Before, p.After, p.TestFiles, p.CodeChanged = dt.Before, dt.After, dt.TestFiles, dt.CodeChanged
		p.Before.Commit, p.After.Commit = requirements.CleanCommit(base), requirements.CleanCommit(commit)
		p.After.Dirty, p.Fallback, p.NewTests = dirty != 0, fallback != 0, newTests != 0
		p.ExecutorID, p.ProvedBy = clipText(p.ExecutorID, 256), clipText(p.ProvedBy, 4*requirements.MaxActorRunes)
		p.ProvedAt = parseReqTime(at)
		p.StartedAt = p.ProvedAt
		if p.TaskID < 0 {
			p.TaskID = 0
		}
		requirements.BoundProof(&p.Proof, requirements.MaxOutputBytes)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read requirement proofs: %w", classifyDriverErr(err))
	}
	return out, nil
}

// LatestRequirementProofs returns each requirement's newest proof, by
// requirement id.
func (d *DB) LatestRequirementProofs() (map[int]RequirementProof, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + requirementProofColumns + ` FROM requirement_proofs
		WHERE id IN (SELECT MAX(id) FROM requirement_proofs GROUP BY requirement_id)`)
	if err != nil {
		return nil, fmt.Errorf("statedb: read requirement proofs: %w", classifyDriverErr(err))
	}
	proofs, err := scanRequirementProofs(rows)
	if err != nil {
		return nil, err
	}
	out := make(map[int]RequirementProof, len(proofs))
	for _, p := range proofs {
		out[p.RequirementID] = p
	}
	return out, nil
}

// RequirementProofs returns a requirement's proofs, newest first, at most
// limit of them.
func (d *DB) RequirementProofs(id, limit int) ([]RequirementProof, error) {
	if limit <= 0 || limit > requirementProofsKept {
		limit = requirementProofsKept
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+requirementProofColumns+` FROM requirement_proofs
		WHERE requirement_id = ? ORDER BY id DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: read requirement proofs: %w", classifyDriverErr(err))
	}
	return scanRequirementProofs(rows)
}

// deleteRequirementProofsTx removes a deleted requirement's proofs with it.
func deleteRequirementProofsTx(tx *sql.Tx, id int) (int64, error) {
	res, err := tx.Exec(`DELETE FROM requirement_proofs WHERE requirement_id = ?`, id)
	if err != nil {
		return 0, fmt.Errorf("statedb: delete requirement proofs: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// AuditRequirementProof records a proof run's end in the project's audit
// trail: one row per run, each requirement's outcome in it.
func AuditRequirementProof(d *DB, run RequirementRun, proofs []requirements.Proof, actor string) {
	outcomes := make(map[string]string, len(proofs))
	var base, commit string
	for _, p := range proofs {
		outcomes[requirements.Key(p.RequirementID)] = p.Outcome
		if base == "" {
			base, commit = p.Before.Commit, p.After.Commit
		}
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionRequirementProve),
		EntityType: "requirement", EntityID: run.RunID,
		Payload: MarshalAuditPayload(map[string]any{
			"run_id": run.RunID, "state": run.State, "source": run.Source, "requirement_ids": run.RequirementIDs,
			"executor_id": run.ExecutorID, "base": base, "commit": commit, "outcomes": outcomes,
			"reason": run.Error, "task_id": run.TaskID,
		}),
	})
}
