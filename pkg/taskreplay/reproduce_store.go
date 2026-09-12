package taskreplay

// reproduce_store.go persists reproduction verdicts.
//
// Separate from store.go, which persists replay_runs, because the two tables
// answer different questions and share no column. See migration 0028.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrReproductionNotFound is returned by GetReproduction for an unknown id.
var ErrReproductionNotFound = errors.New("reproduction not found")

// SaveReproduction appends rep to the reproductions table and sets rep.ID.
//
// Persisting is the caller's decision, not Reproduce's: a CLI invocation that
// only wants to print a verdict should not grow the project's database, and a
// dry run must be able to reach a verdict without leaving a record that looks
// like evidence.
func SaveReproduction(workDir string, rep *Reproduction) error {
	if rep == nil {
		return errors.New("nil reproduction")
	}
	conn, err := openStateDB(workDir)
	if err != nil {
		return err
	}
	defer conn.Close()

	cmp := rep.Comparison
	if cmp == nil {
		cmp = &Comparison{}
	}

	res, err := conn.Exec(`
		INSERT INTO reproductions(
			created_at, task_id, task_title,
			verdict, reason,
			base_sha, base_source, original_commit, replay_commit,
			original_tree, replay_tree,
			executor_id, executor_kind, isolation, pinned_image,
			diff_stat, diff_of_diffs,
			provenance, original_test, replay_test,
			agent_exit_code, duration_ms, error
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rep.CreatedAt.UTC().Format(time.RFC3339Nano), rep.TaskID, rep.TaskTitle,
		string(rep.Verdict), rep.Reason,
		cmp.BaseSHA, baseSourceOf(rep), cmp.OriginalCommit, cmp.ReplayCommit,
		cmp.OriginalTree, cmp.ReplayTree,
		rep.ExecutorID, rep.ExecutorKind, rep.Isolation, rep.PinnedImage,
		cmp.DiffStat, cmp.DiffOfDiffs,
		encodeJSON(rep.Provenance), encodeJSON(rep.OriginalTest), encodeJSON(rep.ReplayTest),
		rep.AgentExitCode, rep.Duration.Milliseconds(), rep.Err,
	)
	if err != nil {
		return fmt.Errorf("insert reproduction: %w", err)
	}
	if id, idErr := res.LastInsertId(); idErr == nil {
		rep.ID = id
	}
	return nil
}

// baseSourceOf reads the base source off the provenance, tolerating a
// reproduction that never got one.
func baseSourceOf(rep *Reproduction) string {
	if rep.Provenance == nil {
		return ""
	}
	return string(rep.Provenance.BaseSource)
}

// encodeJSON marshals v, returning "" rather than an error: a record that could
// not serialize its detail blob is still worth keeping for its verdict.
func encodeJSON(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// reproductionColumns is the select list, shared so a column added to one query
// cannot be forgotten in the other.
const reproductionColumns = `
	id, created_at, task_id, task_title,
	verdict, reason,
	base_sha, base_source, original_commit, replay_commit,
	original_tree, replay_tree,
	executor_id, executor_kind, isolation, pinned_image,
	diff_stat, diff_of_diffs,
	provenance, original_test, replay_test,
	agent_exit_code, duration_ms, error`

// ListReproductions returns reproductions newest first. taskID == 0 means all
// tasks; limit <= 0 defaults to 50.
//
// The diff-of-diffs is dropped from every row: a list of fifty verdicts each
// carrying up to a megabyte of patch is the artifact-read amplification Task
// 20220 bounded elsewhere. GetReproduction returns it for the one row a
// reviewer opened.
func ListReproductions(workDir string, taskID, limit int) ([]*Reproduction, error) {
	if limit <= 0 {
		limit = 50
	}
	conn, err := openStateDB(workDir)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var rows *sql.Rows
	if taskID > 0 {
		rows, err = conn.Query(`SELECT `+reproductionColumns+`
			FROM reproductions WHERE task_id = ? ORDER BY id DESC LIMIT ?`, taskID, limit)
	} else {
		rows, err = conn.Query(`SELECT `+reproductionColumns+`
			FROM reproductions ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("select reproductions: %w", err)
	}
	defer rows.Close()

	out := []*Reproduction{}
	for rows.Next() {
		rep, scanErr := scanReproduction(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if rep.Comparison != nil {
			rep.Comparison.DiffOfDiffs = ""
		}
		out = append(out, rep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reproductions: %w", err)
	}
	return out, nil
}

// GetReproduction returns one reproduction by id, diff included.
func GetReproduction(workDir string, id int64) (*Reproduction, error) {
	conn, err := openStateDB(workDir)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	row := conn.QueryRow(`SELECT `+reproductionColumns+` FROM reproductions WHERE id = ?`, id)
	rep, err := scanReproduction(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("reproduction %d: %w", id, ErrReproductionNotFound)
		}
		return nil, err
	}
	return rep, nil
}

// rowScanner is the shared shape of *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanReproduction(row rowScanner) (*Reproduction, error) {
	var (
		rep        Reproduction
		cmp        Comparison
		createdAt  string
		baseSource string
		provJSON   string
		origTest   string
		replTest   string
		verdict    string
		durationMS int64
	)
	err := row.Scan(
		&rep.ID, &createdAt, &rep.TaskID, &rep.TaskTitle,
		&verdict, &rep.Reason,
		&cmp.BaseSHA, &baseSource, &cmp.OriginalCommit, &cmp.ReplayCommit,
		&cmp.OriginalTree, &cmp.ReplayTree,
		&rep.ExecutorID, &rep.ExecutorKind, &rep.Isolation, &rep.PinnedImage,
		&cmp.DiffStat, &cmp.DiffOfDiffs,
		&provJSON, &origTest, &replTest,
		&rep.AgentExitCode, &durationMS, &rep.Err,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan reproduction: %w", err)
	}

	rep.Verdict = Verdict(verdict)
	if !rep.Verdict.Valid() {
		// A row written by a newer binary, or a corrupted one. Reading it back
		// as a verdict this binary does not understand would let it be counted
		// as a reproducible result; inconclusive is the safe direction.
		rep.Verdict = VerdictInconclusive
	}
	if t, perr := time.Parse(time.RFC3339Nano, createdAt); perr == nil {
		rep.CreatedAt = t
	}
	rep.Duration = time.Duration(durationMS) * time.Millisecond
	cmp.Identical = cmp.OriginalTree != "" && cmp.OriginalTree == cmp.ReplayTree
	rep.Comparison = &cmp

	if provJSON != "" {
		var p Provenance
		if json.Unmarshal([]byte(provJSON), &p) == nil {
			p.BaseSource = BaseSource(baseSource)
			rep.Provenance = &p
		}
	}
	rep.OriginalTest = decodeTestOutcome(origTest)
	rep.ReplayTest = decodeTestOutcome(replTest)
	return &rep, nil
}

func decodeTestOutcome(s string) *TestOutcome {
	if s == "" {
		return nil
	}
	var t TestOutcome
	if err := json.Unmarshal([]byte(s), &t); err != nil {
		return nil
	}
	return &t
}

// VerdictCounts summarizes reproductions by verdict, for a dashboard that wants
// "how much of this project's history has been proven to reproduce?".
func VerdictCounts(workDir string) (map[Verdict]int, error) {
	conn, err := openStateDB(workDir)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rows, err := conn.Query(`SELECT verdict, COUNT(*) FROM reproductions GROUP BY verdict`)
	if err != nil {
		return nil, fmt.Errorf("count verdicts: %w", err)
	}
	defer rows.Close()

	counts := make(map[Verdict]int, len(AllVerdicts))
	for _, v := range AllVerdicts {
		counts[v] = 0
	}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, fmt.Errorf("scan verdict count: %w", err)
		}
		if verdict := Verdict(v); verdict.Valid() {
			counts[verdict] += n
		} else {
			counts[VerdictInconclusive] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate verdict counts: %w", err)
	}
	return counts, nil
}
