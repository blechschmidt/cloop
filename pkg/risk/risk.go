// Package risk provides AI-powered pre-execution risk assessment for cloop tasks.
// For each task (or the full plan) it asks the provider to output a structured JSON
// list of findings, each with a severity level, category, rationale, and mitigation.
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Level is the risk severity.
type Level string

const (
	LevelLow      Level = "LOW"
	LevelMedium   Level = "MEDIUM"
	LevelHigh     Level = "HIGH"
	LevelCritical Level = "CRITICAL"
)

// Category describes the type of risk.
type Category string

const (
	CategoryDataLoss           Category = "data-loss"
	CategorySecurity           Category = "security"
	CategoryIrreversible       Category = "irreversible"
	CategoryBreakingChange     Category = "breaking-change"
	CategoryExternalDependency Category = "external-dependency"
)

// Finding is a single risk finding for a task.
type Finding struct {
	// Level is the severity: LOW, MEDIUM, HIGH, or CRITICAL.
	Level Level `json:"level"`

	// Category classifies the risk type.
	Category Category `json:"category"`

	// Rationale explains why this is a risk.
	Rationale string `json:"rationale"`

	// Mitigation suggests how to reduce or eliminate the risk.
	Mitigation string `json:"mitigation"`
}

// RiskReport is the result of assessing a single task or the full plan.
type RiskReport struct {
	// TaskID is the numeric task ID (0 if this is a plan-level report).
	TaskID int `json:"task_id,omitempty"`

	// TaskTitle is the title of the assessed task ("(plan)" for plan-level).
	TaskTitle string `json:"task_title"`

	// Findings is the ordered list of risk findings (highest severity first).
	Findings []Finding `json:"findings"`

	// OverallLevel is the highest severity level across all findings.
	OverallLevel Level `json:"overall_level"`
}

// HasCritical reports whether the report contains at least one CRITICAL finding.
func (r *RiskReport) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Level == LevelCritical {
			return true
		}
	}
	return false
}

// Assess runs a risk assessment for the given tasks using the AI provider.
//
// If taskID is non-empty it must be a numeric task ID; only that task is assessed.
// If taskID is empty, all pending tasks are assessed and one RiskReport is returned per task.
// model may be empty (the provider will use its default).
func Assess(ctx context.Context, p provider.Provider, model string, plan *pm.Plan, taskID string) ([]*RiskReport, error) {
	if plan == nil {
		return nil, fmt.Errorf("no plan loaded")
	}

	tasks, err := selectTasks(plan, taskID)
	if err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, nil
	}

	var reports []*RiskReport
	for _, task := range tasks {
		deps := depsFor(plan, task)
		prompt := buildPrompt(plan, task, deps)

		result, err := p.Complete(ctx, prompt, provider.Options{
			Model:   model,
			Timeout: 2 * time.Minute,
		})
		if err != nil {
			return nil, fmt.Errorf("risk assessment for task #%d: %w", task.ID, err)
		}

		report, err := parseReport(task, result.Output)
		if err != nil {
			return nil, fmt.Errorf("parsing risk report for task #%d: %w", task.ID, err)
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// AssessTask assesses a single task by value (used by the orchestrator pre-execution check).
func AssessTask(ctx context.Context, p provider.Provider, model string, plan *pm.Plan, task *pm.Task) (*RiskReport, error) {
	deps := depsFor(plan, task)
	prompt := buildPrompt(plan, task, deps)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("risk assessment for task #%d: %w", task.ID, err)
	}
	return parseReport(task, result.Output)
}

// selectTasks resolves which tasks to assess.
func selectTasks(plan *pm.Plan, taskID string) ([]*pm.Task, error) {
	if taskID != "" {
		id, err := strconv.Atoi(taskID)
		if err != nil {
			return nil, fmt.Errorf("invalid task ID %q: must be a number", taskID)
		}
		for _, t := range plan.Tasks {
			if t.ID == id {
				return []*pm.Task{t}, nil
			}
		}
		return nil, fmt.Errorf("task #%d not found", id)
	}

	var pending []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			pending = append(pending, t)
		}
	}
	return pending, nil
}

// depsFor returns the dependency tasks for a given task.
func depsFor(plan *pm.Plan, task *pm.Task) []*pm.Task {
	if len(task.DependsOn) == 0 {
		return nil
	}
	byID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}
	var deps []*pm.Task
	for _, depID := range task.DependsOn {
		if t, ok := byID[depID]; ok {
			deps = append(deps, t)
		}
	}
	return deps
}

// buildPrompt builds the risk-assessment prompt for a single task.
func buildPrompt(plan *pm.Plan, task *pm.Task, deps []*pm.Task) string {
	var b strings.Builder

	b.WriteString("You are a senior software engineer and security auditor performing a pre-execution risk assessment.\n")
	b.WriteString("Analyze the task below for execution risks BEFORE it runs.\n\n")

	b.WriteString("## PROJECT GOAL\n")
	b.WriteString(plan.Goal)
	b.WriteString("\n\n")

	b.WriteString("## TASK TO ASSESS\n")
	b.WriteString(fmt.Sprintf("ID: %d\nTitle: %s\n", task.ID, task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	b.WriteString(fmt.Sprintf("Priority: %d | Status: %s", task.Priority, task.Status))
	if task.Role != "" {
		b.WriteString(fmt.Sprintf(" | Role: %s", task.Role))
	}
	if task.Condition != "" {
		b.WriteString(fmt.Sprintf("\nCondition: %s", task.Condition))
	}
	if len(task.Tags) > 0 {
		b.WriteString(fmt.Sprintf("\nTags: %s", strings.Join(task.Tags, ", ")))
	}
	b.WriteString("\n")

	if len(deps) > 0 {
		b.WriteString("\n## DEPENDENCY TASKS (already completed or in progress)\n")
		for _, d := range deps {
			b.WriteString(fmt.Sprintf("- #%d [%s]: %s\n", d.ID, d.Status, d.Title))
			if d.Description != "" {
				b.WriteString(fmt.Sprintf("  %s\n", truncate(d.Description, 120)))
			}
		}
	}

	b.WriteString(`
## RISK CATEGORIES
Use exactly one of these category values per finding:
- "data-loss"           — risk of permanent data deletion or corruption
- "security"            — secrets exposure, injection, auth bypass, privilege escalation
- "irreversible"        — actions that cannot be undone (dropping tables, deleting branches, etc.)
- "breaking-change"     — API/interface changes that break existing consumers or contracts
- "external-dependency" — reliance on third-party services, APIs, or network resources

## SEVERITY LEVELS
- "LOW"      — minor, easily reversible or negligible impact
- "MEDIUM"   — noticeable impact but recoverable with effort
- "HIGH"     — significant impact; recovery is difficult or time-consuming
- "CRITICAL" — severe, likely unrecoverable impact; should block execution unless explicitly overridden

## INSTRUCTIONS
Return ONLY a JSON array of risk findings (no prose, no markdown fences):
[
  {
    "level": "HIGH",
    "category": "irreversible",
    "rationale": "The task drops the users table which cannot be recovered without a backup.",
    "mitigation": "Take a database snapshot before executing. Confirm DROP is intentional."
  }
]

If there are no meaningful risks, return an empty array: []

Rules:
- Include only genuine, task-specific risks. Do not invent risks that do not apply.
- Be concise. Each rationale and mitigation should be 1-3 sentences.
- Order findings from highest to lowest severity.
- Use exactly the level and category strings specified above.
`)

	return b.String()
}

// parseReport parses the AI JSON output into a RiskReport.
func parseReport(task *pm.Task, output string) (*RiskReport, error) {
	// Extract the JSON array — the AI may include surrounding text.
	start := strings.Index(output, "[")
	end := strings.LastIndex(output, "]")
	if start == -1 || end == -1 || end < start {
		// Treat as zero findings if the output doesn't contain a JSON array.
		return &RiskReport{
			TaskID:       task.ID,
			TaskTitle:    task.Title,
			Findings:     nil,
			OverallLevel: LevelLow,
		}, nil
	}
	raw := output[start : end+1]

	var findings []Finding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		return nil, fmt.Errorf("invalid JSON from provider: %w (raw: %s)", err, truncate(raw, 200))
	}

	overall := overallLevel(findings)
	return &RiskReport{
		TaskID:       task.ID,
		TaskTitle:    task.Title,
		Findings:     findings,
		OverallLevel: overall,
	}, nil
}

// overallLevel returns the highest severity level in the findings.
func overallLevel(findings []Finding) Level {
	order := map[Level]int{
		LevelLow:      0,
		LevelMedium:   1,
		LevelHigh:     2,
		LevelCritical: 3,
	}
	best := LevelLow
	for _, f := range findings {
		if order[f.Level] > order[best] {
			best = f.Level
		}
	}
	return best
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
