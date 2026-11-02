package statedb

// requirements_trace.go reads the traceability matrix's facts (Task 20465;
// pkg/requirements/trace.go, migration 0091): each approved requirement a page
// selects, with its latest check and its latest proof, a keyset page at a time.
//
// Every query here is bounded by an index. The page seeks its first row
// through requirements_status or requirements_status_priority — an index ends
// in the row id, so the same index serves `id > ?` and ORDER BY id with no
// sort — and stops at its LIMIT; each row's latest check and latest proof are
// one seek each into requirement_checks(requirement_id, id) and
// requirement_proofs(requirement_id, id). The keyset is the id alone: a
// row-value comparison makes SQLite scan an index from its top
// (TestHistory_PagesSeekTheIndex), and one column needs none.
// TestTraceFacts_SeekTheIndexes holds the plans to that.
//
// Only lean columns are read: no check's detail (its tests' output, up to
// 512 KiB a row) and no proof's — a matrix row shows a verdict and a summary.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// traceFactsSQL selects the approved requirements after a cursor, each with
// its latest check and latest proof; traceFactsWhere adds the filters a query
// asks for, and the ORDER BY and LIMIT close it.
const traceFactsSQL = `SELECT r.id, r.title, r.description, r.priority, r.tags, r.tests, r.created_at, r.updated_at,
	c.id, c.method, c.verdict, c.summary, c.fingerprint, c.git_commit, c.dirty, c.checked_at, c.task_id, c.regression,
	p.id, p.outcome, p.summary, p.fingerprint, p.proved_at, p.task_id
FROM requirements r
LEFT JOIN requirement_checks c ON c.id = (SELECT MAX(id) FROM requirement_checks WHERE requirement_id = r.id)
LEFT JOIN requirement_proofs p ON p.id = (SELECT MAX(id) FROM requirement_proofs WHERE requirement_id = r.id)
WHERE r.status = 'approved' AND r.id > ?`

// traceFactsQuery is the statement and its arguments for q.
func traceFactsQuery(q requirements.TraceQuery) (string, []any) {
	var b strings.Builder
	b.WriteString(traceFactsSQL)
	args := []any{max(q.After, 0)}
	switch q.Priority {
	case "":
	case requirements.FilterNone:
		b.WriteString(` AND r.priority = ''`)
	default:
		b.WriteString(` AND r.priority = ?`)
		args = append(args, q.Priority)
	}
	if q.Tag != "" {
		// json_valid first: json_each refuses malformed JSON with an error
		// that would fail the whole page, and a row written by something
		// else may hold anything. AND short-circuits.
		b.WriteString(` AND json_valid(r.tags) AND EXISTS (SELECT 1 FROM json_each(r.tags) WHERE json_each.value = ?)`)
		args = append(args, q.Tag)
	}
	limit := q.Limit
	if limit <= 0 || limit > requirements.MaxRequirements {
		limit = requirements.MaxRequirements
	}
	b.WriteString(` ORDER BY r.id LIMIT ?`)
	return b.String(), append(args, limit)
}

// traceHeldSQL reads when each of a page's requirements, as each definition
// it has had, was last found fulfilled: a seek per id into
// requirement_checks(requirement_id, id).
const traceHeldSQL = `SELECT requirement_id, fingerprint, MAX(checked_at) FROM requirement_checks
	WHERE requirement_id IN (SELECT value FROM json_each(?)) AND verdict = ?
	GROUP BY requirement_id, fingerprint`

// TraceFacts reads the approved requirements q selects, in id order, each with
// its latest check, when its current definition last held, and its latest
// proof. It is the project database's requirements.TraceSource.
func (d *DB) TraceFacts(q requirements.TraceQuery) ([]requirements.TraceFacts, error) {
	query, args := traceFactsQuery(q)
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: read the traceability matrix: %w", classifyDriverErr(err))
	}
	out, err := scanTraceFacts(rows)
	if err != nil || len(out) == 0 {
		return out, err
	}
	ids := make([]int, len(out))
	for i, f := range out {
		ids[i] = f.Requirement.ID
	}
	raw, _ := json.Marshal(ids)
	held, err := d.conn.Query(traceHeldSQL, string(raw), requirements.VerdictFulfilled)
	if err != nil {
		return nil, fmt.Errorf("statedb: read when requirements last held: %w", classifyDriverErr(err))
	}
	defer held.Close()
	at := map[heldKey]string{}
	for held.Next() {
		var (
			id       int
			fp, last string
		)
		if err := held.Scan(&id, &fp, &last); err != nil {
			return nil, fmt.Errorf("statedb: read when requirements last held: %w", classifyDriverErr(err))
		}
		at[heldKey{id, fp}] = last
	}
	if err := held.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read when requirements last held: %w", classifyDriverErr(err))
	}
	for i := range out {
		r := out[i].Requirement
		out[i].HeldAt = parseReqTime(at[heldKey{r.ID, r.Fingerprint()}])
	}
	return out, nil
}

func scanTraceFacts(rows *sql.Rows) ([]requirements.TraceFacts, error) {
	defer rows.Close()
	var out []requirements.TraceFacts
	for rows.Next() {
		var (
			f                                requirements.TraceFacts
			r                                requirements.Requirement
			tags, tests, created, updated    string
			cID, cDirty, cTask, cRegression  sql.NullInt64
			cMethod, cVerdict, cSummary, cFP sql.NullString
			cCommit, cAt                     sql.NullString
			pID, pTask                       sql.NullInt64
			pOutcome, pSummary, pFP, pAt     sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.Title, &r.Description, &r.Priority, &tags, &tests, &created, &updated,
			&cID, &cMethod, &cVerdict, &cSummary, &cFP, &cCommit, &cDirty, &cAt, &cTask, &cRegression,
			&pID, &pOutcome, &pSummary, &pFP, &pAt, &pTask); err != nil {
			return nil, fmt.Errorf("statedb: read the traceability matrix: %w", classifyDriverErr(err))
		}
		r.Status = requirements.StatusApproved
		boundRequirementRow(&r, tags, tests, created, updated)
		f.Requirement = r
		if cID.Valid {
			c := &requirements.TraceCheckFact{Method: clipText(cMethod.String, 16), Verdict: cVerdict.String,
				Summary: clipText(cSummary.String, 4*requirements.MaxRationaleRunes), Fingerprint: clipText(cFP.String, 128),
				Commit: requirements.CleanCommit(cCommit.String), Dirty: cDirty.Int64 != 0, CheckedAt: parseReqTime(cAt.String),
				TaskID: max(int(cTask.Int64), 0), Regression: cRegression.Int64 != 0}
			if !requirements.ValidVerdict(c.Verdict) {
				c.Verdict = requirements.VerdictError
			}
			f.Check = c
		}
		if pID.Valid {
			p := &requirements.TraceProofFact{Outcome: pOutcome.String,
				Summary: clipText(pSummary.String, 4*requirements.MaxSummaryRunes), Fingerprint: clipText(pFP.String, 128),
				ProvedAt: parseReqTime(pAt.String), TaskID: max(int(pTask.Int64), 0)}
			if !requirements.ValidProofOutcome(p.Outcome) {
				p.Outcome = requirements.ProofError
			}
			f.Proof = p
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read the traceability matrix: %w", classifyDriverErr(err))
	}
	return out, nil
}
