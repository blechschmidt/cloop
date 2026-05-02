// Package eval scores completed task output against a configurable rubric by
// calling the AI provider once per criterion and aggregating weighted scores.
// Results are stored as JSON under .cloop/evals/<task-id>.json.
package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Criterion is a single evaluation dimension with a weight and description.
type Criterion struct {
	Name        string  `yaml:"name"        json:"name"`
	Weight      float64 `yaml:"weight"      json:"weight"`
	Description string  `yaml:"description" json:"description"`
}

// Rubric is an ordered list of criteria used to evaluate task output.
type Rubric struct {
	Criteria []Criterion `yaml:"criteria" json:"criteria"`
}

// DefaultRubric returns the built-in four-criterion rubric.
func DefaultRubric() Rubric {
	return Rubric{Criteria: []Criterion{
		{
			Name:        "Correctness",
			Weight:      0.35,
			Description: "Does the output correctly fulfill the task requirements? Are there bugs, logic errors, or factual mistakes?",
		},
		{
			Name:        "Completeness",
			Weight:      0.30,
			Description: "Does the output address all parts of the task? Are any required pieces missing or left TODO?",
		},
		{
			Name:        "Code Quality",
			Weight:      0.20,
			Description: "Is the code well-structured, readable, idiomatic, and maintainable? Are error paths handled?",
		},
		{
			Name:        "Conciseness",
			Weight:      0.15,
			Description: "Is the output focused and free of unnecessary verbosity, dead code, or redundant explanations?",
		},
	}}
}

// Score holds the evaluation result for a single criterion.
type Score struct {
	Criterion Criterion `json:"criterion"`
	// Value is the 1-10 score given by the AI judge.
	Value     int    `json:"score"`
	Rationale string `json:"rationale"`
}

// EvalResult is the full evaluation output for one task.
type EvalResult struct {
	TaskID    int       `json:"task_id"`
	TaskTitle string    `json:"task_title"`
	Scores    []Score   `json:"scores"`
	// Weighted is the overall weighted average (1-10).
	Weighted  float64   `json:"weighted_average"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// Evaluate calls the AI provider to score each criterion in the rubric for the
// given task and its output. Returns a populated EvalResult and saves it to
// .cloop/evals/<task-id>.json under workDir.
func Evaluate(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, workDir string, task *pm.Task, output string, rubric Rubric) (*EvalResult, error) {
	if len(rubric.Criteria) == 0 {
		rubric = DefaultRubric()
	}

	scores := make([]Score, 0, len(rubric.Criteria))
	for _, c := range rubric.Criteria {
		s, err := scoreOneCriterion(ctx, prov, model, timeout, task, output, c)
		if err != nil {
			return nil, fmt.Errorf("eval criterion %q: %w", c.Name, err)
		}
		scores = append(scores, s)
	}

	weighted := computeWeighted(scores)

	result := &EvalResult{
		TaskID:      task.ID,
		TaskTitle:   task.Title,
		Scores:      scores,
		Weighted:    weighted,
		EvaluatedAt: time.Now().UTC(),
	}

	if err := save(workDir, result); err != nil {
		return result, fmt.Errorf("saving eval result: %w", err)
	}

	return result, nil
}

// Load reads a previously saved EvalResult for the given task ID.
// Returns nil, nil if no result exists yet.
func Load(workDir string, taskID int) (*EvalResult, error) {
	path := evalPath(workDir, taskID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r EvalResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse eval result: %w", err)
	}
	return &r, nil
}

// evalPath returns the storage path for a task's eval result.
func evalPath(workDir string, taskID int) string {
	return filepath.Join(workDir, ".cloop", "evals", fmt.Sprintf("%d.json", taskID))
}

// save writes result to .cloop/evals/<taskID>.json.
func save(workDir string, r *EvalResult) error {
	dir := filepath.Join(workDir, ".cloop", "evals")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(evalPath(workDir, r.TaskID), data, 0o644)
}

// computeWeighted computes the weighted average score normalising weights to 1.
func computeWeighted(scores []Score) float64 {
	totalWeight := 0.0
	for _, s := range scores {
		totalWeight += s.Criterion.Weight
	}
	if totalWeight == 0 {
		return 0
	}
	sum := 0.0
	for _, s := range scores {
		sum += float64(s.Value) * (s.Criterion.Weight / totalWeight)
	}
	return sum
}

// aiScore is the minimal JSON structure returned by the AI for one criterion.
type aiScore struct {
	Score     int    `json:"score"`
	Rationale string `json:"rationale"`
}

// scoreOneCriterion asks the AI to rate the task output on a single criterion.
func scoreOneCriterion(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, task *pm.Task, output string, c Criterion) (Score, error) {
	prompt := buildCriterionPrompt(task, output, c)

	opts := provider.Options{
		Model:   model,
		Timeout: timeout,
	}

	res, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return Score{}, err
	}

	raw, err := parseCriterionResponse(res.Output)
	if err != nil {
		// Fallback: return a mid-score with the raw text as rationale.
		return Score{
			Criterion: c,
			Value:     5,
			Rationale: fmt.Sprintf("parse error: %v\n\nRaw: %s", err, res.Output),
		}, nil
	}

	// Clamp to 1-10.
	if raw.Score < 1 {
		raw.Score = 1
	}
	if raw.Score > 10 {
		raw.Score = 10
	}

	return Score{
		Criterion: c,
		Value:     raw.Score,
		Rationale: raw.Rationale,
	}, nil
}

// buildCriterionPrompt builds the AI prompt for a single rubric criterion.
func buildCriterionPrompt(task *pm.Task, output string, c Criterion) string {
	var sb strings.Builder

	sb.WriteString("You are an expert code reviewer evaluating AI-generated task output.\n")
	sb.WriteString("Score the output on a single criterion using an integer from 1 (worst) to 10 (best).\n\n")

	sb.WriteString(fmt.Sprintf("TASK TITLE: %s\n", task.Title))
	if task.Description != "" {
		sb.WriteString(fmt.Sprintf("TASK DESCRIPTION: %s\n", task.Description))
	}
	sb.WriteString("\n")

	// Truncate output to avoid context overflow (~6000 chars ≈ ~1500 tokens).
	outputTrunc := output
	const maxOutputChars = 6000
	if len(outputTrunc) > maxOutputChars {
		outputTrunc = outputTrunc[:maxOutputChars] + "\n...(truncated)"
	}
	sb.WriteString("TASK OUTPUT:\n")
	sb.WriteString("---\n")
	sb.WriteString(outputTrunc)
	sb.WriteString("\n---\n\n")

	sb.WriteString(fmt.Sprintf("CRITERION: %s\n", c.Name))
	sb.WriteString(fmt.Sprintf("DEFINITION: %s\n\n", c.Description))

	sb.WriteString(`Respond ONLY with a JSON object — no markdown fences, no extra text:
{
  "score": 7,
  "rationale": "One or two sentences explaining the score with specific evidence from the output."
}

Rules:
- score must be an integer 1-10 (1=very poor, 5=adequate, 10=excellent).
- rationale must be specific and reference concrete details from the output.
- Do not reference any criterion other than the one above.
`)

	return sb.String()
}

// parseCriterionResponse extracts an aiScore from raw provider output.
func parseCriterionResponse(output string) (aiScore, error) {
	cleaned := strings.TrimSpace(output)
	if idx := strings.Index(cleaned, "{"); idx > 0 {
		cleaned = cleaned[idx:]
	}
	if idx := strings.LastIndex(cleaned, "}"); idx >= 0 && idx < len(cleaned)-1 {
		cleaned = cleaned[:idx+1]
	}
	var s aiScore
	if err := json.Unmarshal([]byte(cleaned), &s); err != nil {
		return s, fmt.Errorf("unmarshal: %w (raw: %q)", err, output)
	}
	return s, nil
}
