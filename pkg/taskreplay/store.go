package taskreplay

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Run is the on-disk shape of a replay_runs row. Mirrors Result but uses
// scalar fields suitable for SQL bind/scan.
type Run struct {
	ID                   int64
	CreatedAt            time.Time
	TaskID               int
	TaskTitle            string
	OriginalProvider     string
	OriginalModel        string
	TargetProvider       string
	TargetModel          string
	Prompt               string
	OriginalOutput       string
	ReplayedOutput       string
	SimilarityScore      float64
	EquivalenceScore     int
	EquivalenceRationale string
	DurationMS           int64
	InputTokens          int
	OutputTokens         int
	Error                string
}

// persistReplay opens the project's state.db, runs schema migrations if
// needed (defensive — they should already be applied), and inserts a row.
func persistReplay(workDir string, r *Result) error {
	if r == nil {
		return errors.New("nil result")
	}
	dbPath := state.StateDBPath(state.ActiveDir(workDir))
	db, err := statedb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open state db: %w", err)
	}
	defer db.Close()

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open replay writer conn: %w", err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return fmt.Errorf("busy_timeout: %w", err)
	}

	_, err = conn.Exec(`
		INSERT INTO replay_runs(
			created_at, task_id, task_title,
			original_provider, original_model,
			target_provider, target_model,
			prompt, original_output, replayed_output,
			similarity_score, equivalence_score, equivalence_rationale,
			duration_ms, input_tokens, output_tokens, error
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.CreatedAt.UTC().Format(time.RFC3339Nano),
		r.TaskID, r.TaskTitle,
		r.OriginalProvider, r.OriginalModel,
		r.TargetProvider, r.TargetModel,
		r.Prompt, r.OriginalOutput, r.ReplayedOutput,
		r.SimilarityScore, r.EquivalenceScore, r.EquivalenceRationale,
		r.Duration.Milliseconds(), r.InputTokens, r.OutputTokens, r.Err,
	)
	if err != nil {
		return fmt.Errorf("insert replay_runs: %w", err)
	}
	return nil
}

// ListRuns returns the most recent replays for the given workDir, newest
// first. taskID == 0 means "all tasks". limit <= 0 defaults to 100.
func ListRuns(workDir string, taskID int, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 100
	}
	dbPath := state.StateDBPath(state.ActiveDir(workDir))

	// Ensure schema exists by opening through statedb (which migrates).
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	db.Close()

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open replay reader: %w", err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return nil, fmt.Errorf("busy_timeout: %w", err)
	}

	var rows *sql.Rows
	if taskID > 0 {
		rows, err = conn.Query(`
			SELECT id, created_at, task_id, task_title,
				original_provider, original_model, target_provider, target_model,
				prompt, original_output, replayed_output,
				similarity_score, equivalence_score, equivalence_rationale,
				duration_ms, input_tokens, output_tokens, error
			FROM replay_runs
			WHERE task_id = ?
			ORDER BY id DESC
			LIMIT ?`, taskID, limit)
	} else {
		rows, err = conn.Query(`
			SELECT id, created_at, task_id, task_title,
				original_provider, original_model, target_provider, target_model,
				prompt, original_output, replayed_output,
				similarity_score, equivalence_score, equivalence_rationale,
				duration_ms, input_tokens, output_tokens, error
			FROM replay_runs
			ORDER BY id DESC
			LIMIT ?`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("select replay_runs: %w", err)
	}
	defer rows.Close()

	var out []Run
	for rows.Next() {
		var run Run
		var ts string
		if err := rows.Scan(
			&run.ID, &ts, &run.TaskID, &run.TaskTitle,
			&run.OriginalProvider, &run.OriginalModel, &run.TargetProvider, &run.TargetModel,
			&run.Prompt, &run.OriginalOutput, &run.ReplayedOutput,
			&run.SimilarityScore, &run.EquivalenceScore, &run.EquivalenceRationale,
			&run.DurationMS, &run.InputTokens, &run.OutputTokens, &run.Error,
		); err != nil {
			return nil, fmt.Errorf("scan replay row: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			run.CreatedAt = t
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate replay rows: %w", err)
	}
	return out, nil
}

// GetRun returns a single replay_runs row by id, or sql.ErrNoRows wrapped
// when not found.
func GetRun(workDir string, id int64) (*Run, error) {
	dbPath := state.StateDBPath(state.ActiveDir(workDir))
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	db.Close()

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open replay reader: %w", err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return nil, fmt.Errorf("busy_timeout: %w", err)
	}

	var run Run
	var ts string
	err = conn.QueryRow(`
		SELECT id, created_at, task_id, task_title,
			original_provider, original_model, target_provider, target_model,
			prompt, original_output, replayed_output,
			similarity_score, equivalence_score, equivalence_rationale,
			duration_ms, input_tokens, output_tokens, error
		FROM replay_runs WHERE id = ?`, id).Scan(
		&run.ID, &ts, &run.TaskID, &run.TaskTitle,
		&run.OriginalProvider, &run.OriginalModel, &run.TargetProvider, &run.TargetModel,
		&run.Prompt, &run.OriginalOutput, &run.ReplayedOutput,
		&run.SimilarityScore, &run.EquivalenceScore, &run.EquivalenceRationale,
		&run.DurationMS, &run.InputTokens, &run.OutputTokens, &run.Error,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("replay %d not found", id)
		}
		return nil, fmt.Errorf("select replay row: %w", err)
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		run.CreatedAt = t
	}
	return &run, nil
}
