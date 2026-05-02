// Package simulate provides AI-powered "what-if" scenario analysis for cloop PM projects.
// It lets PMs ask counterfactual questions — "What if we cut scope?", "What if deadline moves
// up 2 weeks?", "What if we add an engineer?" — and get structured impact projections.
package simulate

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/insights"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TaskChange describes a recommended change to a specific task.
type TaskChange struct {
	TaskID     int    `json:"task_id"`
	TaskTitle  string `json:"task_title"`
	Action     string `json:"action"`     // "cut", "defer", "reprioritize", "add", "split"
	NewPrio    int    `json:"new_prio,omitempty"`
	Rationale  string `json:"rationale"`
}

// SimResult is the structured output of a scenario simulation.
type SimResult struct {
	Scenario       string       `json:"scenario"`
	Summary        string       `json:"summary"`
	TimelineDelta  int          `json:"timeline_delta_days"` // +days = delayed, -days = faster
	BaselineDays   float64      `json:"baseline_days"`
	SimulatedDays  float64      `json:"simulated_days"`
	RiskBefore     string       `json:"risk_before"`         // "low" | "medium" | "high" | "critical"
	RiskAfter      string       `json:"risk_after"`
	Confidence     string       `json:"confidence"`          // "low" | "medium" | "high"
	Recommendations []string    `json:"recommendations"`
	TaskChanges    []TaskChange `json:"task_changes,omitempty"`
	TradeOffs      []string     `json:"trade_offs,omitempty"`
	Warnings       []string     `json:"warnings,omitempty"`
}

// ProjectSnapshot builds a concise text summary of current project state for AI context.
func ProjectSnapshot(s *state.ProjectState) string {
	m := insights.Analyze(s)
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Project Goal: %s\n", s.Goal))
	sb.WriteString(fmt.Sprintf("Project Age: %s\n", time.Since(s.CreatedAt).Round(time.Hour)))
	sb.WriteString(fmt.Sprintf("Status: %s\n", s.Status))

	if s.Plan != nil {
		sb.WriteString(fmt.Sprintf("\nTask Summary:\n"))
		sb.WriteString(fmt.Sprintf("  Total: %d | Done: %d | In-Progress: %d | Pending: %d | Failed: %d | Skipped: %d | Blocked: %d\n",
			m.TotalTasks, m.DoneTasks, m.InProgressTasks, m.PendingTasks, m.FailedTasks, m.SkippedTasks, m.BlockedTasks))

		pct := 0.0
		if m.TotalTasks > 0 {
			pct = float64(m.DoneTasks) / float64(m.TotalTasks) * 100
		}
		sb.WriteString(fmt.Sprintf("  Completion: %.0f%%\n", pct))

		if m.VelocityPerDay > 0 {
			sb.WriteString(fmt.Sprintf("  Velocity: %.2f tasks/day\n", m.VelocityPerDay))
		}
		if m.EstimatedDaysRemaining > 0 {
			sb.WriteString(fmt.Sprintf("  Est. Days Remaining: %.1f\n", m.EstimatedDaysRemaining))
		}
		sb.WriteString(fmt.Sprintf("  Risk Score: %d/100 (%s)\n", m.RiskScore, riskLabel(m.RiskScore)))
		if len(m.RiskFactors) > 0 {
			sb.WriteString(fmt.Sprintf("  Risk Factors: %s\n", strings.Join(m.RiskFactors, "; ")))
		}

		if len(m.RoleBreakdown) > 0 {
			sb.WriteString("\nRole Breakdown:\n")
			roles := make([]string, 0, len(m.RoleBreakdown))
			for r := range m.RoleBreakdown {
				roles = append(roles, r)
			}
			sort.Strings(roles)
			for _, r := range roles {
				rb := m.RoleBreakdown[r]
				sb.WriteString(fmt.Sprintf("  %s: %d/%d done\n", r, rb[0], rb[1]))
			}
		}

		// Task list (pending + in-progress for "what can be changed")
		sb.WriteString("\nPending/Active Tasks:\n")
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
				deps := ""
				if len(t.DependsOn) > 0 {
					depStrs := make([]string, len(t.DependsOn))
					for i, d := range t.DependsOn {
						depStrs[i] = fmt.Sprintf("#%d", d)
					}
					deps = fmt.Sprintf(" [deps: %s]", strings.Join(depStrs, ","))
				}
				sb.WriteString(fmt.Sprintf("  [%d] P%d (%s) %s%s\n", t.ID, t.Priority, t.Status, t.Title, deps))
			}
		}

		// Recent failures
		hasFailures := false
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskFailed {
				if !hasFailures {
					sb.WriteString("\nFailed Tasks:\n")
					hasFailures = true
				}
				sb.WriteString(fmt.Sprintf("  [%d] %s\n", t.ID, t.Title))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nToken Usage: %d in / %d out\n", s.TotalInputTokens, s.TotalOutputTokens))
	return sb.String()
}

func riskLabel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// buildPrompt constructs the AI prompt for scenario simulation.
func buildPrompt(snapshot, scenario string) string {
	return fmt.Sprintf(`You are a senior AI product manager performing a "what-if" scenario analysis.

CURRENT PROJECT STATE:
%s

SCENARIO TO SIMULATE:
%s

Analyze the impact of this scenario on the project. Consider:
- Timeline: will it speed up or delay delivery?
- Risk: does this increase or reduce risk?
- Scope: which tasks should be cut, deferred, reprioritized, or added?
- Trade-offs: what is gained and what is lost?
- Dependencies: are there cascading effects?

Respond with a JSON object matching this exact schema (no markdown, just raw JSON):
{
  "scenario": "<one-line summary of the scenario>",
  "summary": "<2-3 sentence executive summary of the impact>",
  "timeline_delta_days": <integer, positive = delayed, negative = faster, 0 = no change>,
  "baseline_days": <float, current estimated days to completion>,
  "simulated_days": <float, new estimated days after scenario>,
  "risk_before": "<low|medium|high|critical>",
  "risk_after": "<low|medium|high|critical>",
  "confidence": "<low|medium|high>",
  "recommendations": ["<action item 1>", "<action item 2>", ...],
  "task_changes": [
    {"task_id": <id>, "task_title": "<title>", "action": "<cut|defer|reprioritize|add|split>", "new_prio": <1-10 or omit>, "rationale": "<why>"}
  ],
  "trade_offs": ["<trade-off 1>", "<trade-off 2>"],
  "warnings": ["<warning if any>"]
}`, snapshot, scenario)
}

// Run performs the AI scenario simulation.
// Returns a SimResult and the raw AI response text.
func Run(ctx context.Context, s *state.ProjectState, scenario string, prov provider.Provider, model string, onToken func(string)) (*SimResult, string, error) {
	snapshot := ProjectSnapshot(s)
	prompt := buildPrompt(snapshot, scenario)

	opts := provider.Options{Model: model, OnToken: onToken}
	res, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, "", fmt.Errorf("AI simulation failed: %w", err)
	}
	raw := res.Output

	// Extract JSON from response
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return nil, raw, fmt.Errorf("AI did not return valid JSON — raw response saved")
	}

	var result SimResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, raw, fmt.Errorf("parsing simulation JSON: %w (raw: %s)", err, jsonStr[:min(200, len(jsonStr))])
	}

	// Fill in missing derived fields
	if result.BaselineDays == 0 && s.Plan != nil {
		m := insights.Analyze(s)
		if m.EstimatedDaysRemaining > 0 {
			result.BaselineDays = m.EstimatedDaysRemaining
		}
	}
	if result.SimulatedDays == 0 && result.BaselineDays > 0 {
		result.SimulatedDays = math.Max(0, result.BaselineDays+float64(result.TimelineDelta))
	}

	return &result, raw, nil
}

// extractJSON finds the first complete {...} block in the AI response.
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	if start == -1 {
		return ""
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-task dry-run simulation (Task 101)
// ─────────────────────────────────────────────────────────────────────────────

// TaskPrediction holds the AI-predicted outcome for a single pending task.
type TaskPrediction struct {
	TaskID          int      `json:"task_id"`
	TaskTitle       string   `json:"task_title"`
	SuccessProb     int      `json:"success_probability"` // 0-100
	ExpectedOutput  string   `json:"expected_output"`
	Risks           []string `json:"risks"`
	PreConditions   []string `json:"pre_conditions"`
}

// SimulationReport aggregates per-task predictions into an overall assessment.
type SimulationReport struct {
	Goal            string           `json:"goal"`
	GeneratedAt     time.Time        `json:"generated_at"`
	Predictions     []TaskPrediction `json:"predictions"`
	OverallConfidence int            `json:"overall_confidence"` // 0-100 average success prob
}

// predictionPrompt builds the AI prompt for a single pending task.
func predictionPrompt(goal string, task *pm.Task, codebaseCtx string) string {
	var sb strings.Builder
	sb.WriteString("You are an AI product manager performing a dry-run simulation of a task.\n")
	sb.WriteString("Do NOT execute anything. Predict the likely outcome based on the task description and any codebase context.\n\n")

	sb.WriteString("## PROJECT GOAL\n")
	sb.WriteString(goal)
	sb.WriteString("\n\n")

	sb.WriteString("## TASK\n")
	sb.WriteString(fmt.Sprintf("ID: %d\nTitle: %s\n", task.ID, task.Title))
	if task.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	sb.WriteString(fmt.Sprintf("Priority: %d | Role: %s\n", task.Priority, task.Role))
	if len(task.Tags) > 0 {
		sb.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(task.Tags, ", ")))
	}

	if codebaseCtx != "" {
		sb.WriteString("\n## CODEBASE CONTEXT\n")
		sb.WriteString(codebaseCtx)
		sb.WriteString("\n")
	}

	sb.WriteString(`
## INSTRUCTIONS
Predict the likely outcome if this task were executed now.

Return ONLY a JSON object matching this exact schema (no prose, no markdown fences):
{
  "success_probability": <integer 0-100>,
  "expected_output": "<1-3 sentence summary of what the task would produce>",
  "risks": ["<risk 1>", "<risk 2>"],
  "pre_conditions": ["<condition to check before running>"]
}

Rules:
- success_probability: 0=certain failure, 100=certain success
- expected_output: describe the artifact or outcome, not the process
- risks: 0-4 items; only genuine risks, not hypotheticals
- pre_conditions: 0-4 practical checks the executor should verify first
`)
	return sb.String()
}

// gatherCodebaseContext returns a brief summary of the working directory for AI context.
func gatherCodebaseContext(workDir string) string {
	var sb strings.Builder

	// Try to read README
	readmePaths := []string{
		workDir + "/README.md",
		workDir + "/readme.md",
		workDir + "/README.txt",
	}
	for _, p := range readmePaths {
		// Use a simple read approach
		data, err := readFileTruncated(p, 800)
		if err == nil && data != "" {
			sb.WriteString("README (excerpt):\n")
			sb.WriteString(data)
			sb.WriteString("\n\n")
			break
		}
	}

	// Try go.mod for Go projects
	if data, err := readFileTruncated(workDir+"/go.mod", 300); err == nil {
		sb.WriteString("go.mod:\n")
		sb.WriteString(data)
		sb.WriteString("\n\n")
	}

	// Try package.json for Node projects
	if data, err := readFileTruncated(workDir+"/package.json", 300); err == nil {
		sb.WriteString("package.json:\n")
		sb.WriteString(data)
		sb.WriteString("\n\n")
	}

	return strings.TrimSpace(sb.String())
}

// readFileTruncated reads a file and truncates it to maxBytes.
func readFileTruncated(path string, maxBytes int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := string(data)
	if len(s) > maxBytes {
		s = s[:maxBytes] + "..."
	}
	return s, nil
}

// parsePrediction parses the AI JSON output into a TaskPrediction.
func parsePrediction(task *pm.Task, raw string) TaskPrediction {
	pred := TaskPrediction{
		TaskID:    task.ID,
		TaskTitle: task.Title,
	}

	// Extract first {...} block
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || end < start {
		pred.ExpectedOutput = "Unable to parse AI response."
		pred.SuccessProb = 50
		return pred
	}

	var tmp struct {
		SuccessProb    int      `json:"success_probability"`
		ExpectedOutput string   `json:"expected_output"`
		Risks          []string `json:"risks"`
		PreConditions  []string `json:"pre_conditions"`
	}
	if err := json.Unmarshal([]byte(raw[start:end+1]), &tmp); err != nil {
		pred.ExpectedOutput = "Unable to parse AI response."
		pred.SuccessProb = 50
		return pred
	}

	pred.SuccessProb = tmp.SuccessProb
	pred.ExpectedOutput = tmp.ExpectedOutput
	pred.Risks = tmp.Risks
	pred.PreConditions = tmp.PreConditions
	return pred
}

// Simulate runs a dry-run simulation of all pending tasks in the plan.
// It calls the AI provider once per pending task to predict the outcome
// and returns a SimulationReport. The report is also saved to
// .cloop/simulation-<timestamp>.json.
func Simulate(ctx context.Context, prov provider.Provider, model string, plan *pm.Plan, workDir string) (*SimulationReport, error) {
	if plan == nil {
		return nil, fmt.Errorf("no plan loaded")
	}

	codeCtx := gatherCodebaseContext(workDir)

	report := &SimulationReport{
		Goal:        plan.Goal,
		GeneratedAt: time.Now(),
	}

	for _, task := range plan.Tasks {
		if task.Status != pm.TaskPending && task.Status != pm.TaskInProgress {
			continue
		}

		prompt := predictionPrompt(plan.Goal, task, codeCtx)
		res, err := prov.Complete(ctx, prompt, provider.Options{
			Model:   model,
			Timeout: 90 * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("predicting task #%d: %w", task.ID, err)
		}

		pred := parsePrediction(task, res.Output)
		report.Predictions = append(report.Predictions, pred)
	}

	// Compute overall confidence as average success probability
	if len(report.Predictions) > 0 {
		total := 0
		for _, p := range report.Predictions {
			total += p.SuccessProb
		}
		report.OverallConfidence = total / len(report.Predictions)
	}

	// Save report to .cloop/simulation-<timestamp>.json
	if err := saveSimulationReport(workDir, report); err != nil {
		// Non-fatal: log to stderr but continue
		fmt.Fprintf(os.Stderr, "warning: could not save simulation report: %v\n", err)
	}

	return report, nil
}

// saveSimulationReport persists the report as JSON in .cloop/.
func saveSimulationReport(workDir string, report *SimulationReport) error {
	dir := workDir + "/.cloop"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ts := report.GeneratedAt.Format("20060102-150405")
	path := fmt.Sprintf("%s/simulation-%s.json", dir, ts)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
