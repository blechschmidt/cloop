// Package calibrate computes effort-estimate calibration metrics from historical
// task actuals and asks the AI to suggest updated estimates for pending tasks.
package calibrate

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// RoleStat holds accuracy metrics for one agent role (or "all" for the aggregate).
type RoleStat struct {
	Role        string
	TaskCount   int
	EstTotal    int     // sum of EstimatedMinutes
	ActualTotal int     // sum of ActualMinutes
	MAE         float64 // mean absolute error in minutes
	Bias        float64 // mean(actual - estimated); positive = underestimated
	Factor      float64 // ActualTotal / EstTotal; 1.0 = perfect, >1 = underestimate
}

// CalibrationReport contains the full calibration result.
type CalibrationReport struct {
	OverallFactor float64              // recommended global calibration factor
	ByRole        []RoleStat           // per-role breakdown (first entry is "all")
	Suggestions   []EstimateSuggestion // AI suggestions for pending tasks
}

// EstimateSuggestion is an AI-suggested new estimate for a pending task.
type EstimateSuggestion struct {
	TaskID     int    `json:"task_id"`
	Title      string `json:"title"`
	OldMinutes int    `json:"old_minutes"`
	NewMinutes int    `json:"new_minutes"`
	Reasoning  string `json:"reasoning"`
}

// calibratedTaskIn is the shape the AI returns for each task suggestion.
type calibratedTaskIn struct {
	TaskID     int    `json:"task_id"`
	NewMinutes int    `json:"new_minutes"`
	Reasoning  string `json:"reasoning"`
}

// Run computes calibration metrics from the plan and optionally calls the AI
// to generate per-task suggestions for all pending tasks.
//
// If prov is nil the AI call is skipped and only the statistical report is returned.
func Run(ctx context.Context, prov provider.Provider, opts provider.Options, plan *pm.Plan) (*CalibrationReport, error) {
	// ── 1. Gather completed tasks that have both estimates and actuals ──────────
	var history []*pm.Task
	for _, t := range plan.Tasks {
		if (t.Status == pm.TaskDone || t.Status == pm.TaskSkipped) &&
			t.EstimatedMinutes > 0 && t.ActualMinutes > 0 {
			history = append(history, t)
		}
	}

	// ── 2. Compute statistics ──────────────────────────────────────────────────
	report := &CalibrationReport{OverallFactor: 1.0}

	if len(history) == 0 {
		report.ByRole = []RoleStat{{Role: "all", Factor: 1.0}}
		return report, nil
	}

	agg := computeRoleStat("all", history)
	report.OverallFactor = agg.Factor

	roleMap := make(map[string][]*pm.Task)
	for _, t := range history {
		role := string(t.Role)
		if role == "" {
			role = "general"
		}
		roleMap[role] = append(roleMap[role], t)
	}
	report.ByRole = []RoleStat{agg}
	for role, tasks := range roleMap {
		report.ByRole = append(report.ByRole, computeRoleStat(role, tasks))
	}

	// ── 3. AI suggestions for pending tasks ───────────────────────────────────
	if prov == nil {
		return report, nil
	}

	var pending []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending {
			pending = append(pending, t)
		}
	}
	if len(pending) == 0 {
		return report, nil
	}

	prompt := buildCalibratePrompt(plan, history, report.ByRole, pending)
	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return report, fmt.Errorf("AI calibration call: %w", err)
	}

	suggestions, err := parseCalibrationResponse(result.Output, pending)
	if err != nil {
		// Non-fatal: return statistics without suggestions.
		return report, nil
	}
	report.Suggestions = suggestions
	return report, nil
}

// computeRoleStat builds a RoleStat from a slice of tasks for a named role.
func computeRoleStat(role string, tasks []*pm.Task) RoleStat {
	if len(tasks) == 0 {
		return RoleStat{Role: role, Factor: 1.0}
	}
	var estSum, actSum int
	var absErrSum, biasSum float64
	for _, t := range tasks {
		est := t.EstimatedMinutes
		act := t.ActualMinutes
		estSum += est
		actSum += act
		diff := float64(act - est)
		biasSum += diff
		absErrSum += math.Abs(diff)
	}
	n := float64(len(tasks))
	factor := 1.0
	if estSum > 0 {
		factor = float64(actSum) / float64(estSum)
	}
	return RoleStat{
		Role:        role,
		TaskCount:   len(tasks),
		EstTotal:    estSum,
		ActualTotal: actSum,
		MAE:         absErrSum / n,
		Bias:        biasSum / n,
		Factor:      factor,
	}
}

// buildCalibratePrompt constructs the AI prompt for per-task estimate calibration.
func buildCalibratePrompt(plan *pm.Plan, history []*pm.Task, stats []RoleStat, pending []*pm.Task) string {
	var b strings.Builder

	b.WriteString("You are a senior engineering estimator calibrating task effort estimates.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", plan.Goal))

	b.WriteString("## HISTORICAL ESTIMATION ACCURACY\n")
	b.WriteString("The following completed tasks have known estimated vs actual durations:\n\n")
	b.WriteString("| # | Title | Role | Estimated(min) | Actual(min) | Error |\n")
	b.WriteString("|---|-------|------|---------------|-------------|-------|\n")
	for _, t := range history {
		role := string(t.Role)
		if role == "" {
			role = "general"
		}
		errVal := t.ActualMinutes - t.EstimatedMinutes
		sign := "+"
		if errVal < 0 {
			sign = ""
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %d | %d | %s%d |\n",
			t.ID, t.Title, role, t.EstimatedMinutes, t.ActualMinutes, sign, errVal))
	}
	b.WriteString("\n")

	b.WriteString("## CALIBRATION STATISTICS BY ROLE\n")
	b.WriteString("| Role | Tasks | Factor | Bias(min) | MAE(min) |\n")
	b.WriteString("|------|-------|--------|-----------|----------|\n")
	for _, s := range stats {
		b.WriteString(fmt.Sprintf("| %s | %d | %.2fx | %+.1f | %.1f |\n",
			s.Role, s.TaskCount, s.Factor, s.Bias, s.MAE))
	}
	b.WriteString("\nFactor > 1.0 means tasks took longer than estimated (underestimation).\n")
	b.WriteString("Factor < 1.0 means tasks completed faster than estimated (overestimation).\n\n")

	b.WriteString("## PENDING TASKS TO RE-ESTIMATE\n")
	b.WriteString("Using the historical calibration data above, suggest revised estimates for these pending tasks:\n\n")
	for _, t := range pending {
		role := string(t.Role)
		if role == "" {
			role = "general"
		}
		b.WriteString(fmt.Sprintf("- Task %d [%s]: %s (current estimate: %d min)\n",
			t.ID, role, t.Title, t.EstimatedMinutes))
		if t.Description != "" {
			desc := t.Description
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}
			b.WriteString(fmt.Sprintf("  Description: %s\n", desc))
		}
	}

	b.WriteString("\n## INSTRUCTIONS\n")
	b.WriteString("For each pending task, provide a calibrated estimate considering:\n")
	b.WriteString("1. The historical calibration factor for the task's role\n")
	b.WriteString("2. The task's complexity relative to completed tasks\n")
	b.WriteString("3. Any patterns in over/under-estimation for similar work\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown code blocks):\n")
	b.WriteString(`{"suggestions":[{"task_id":1,"new_minutes":45,"reasoning":"Backend tasks ran 1.4x over; adjusted for similar complexity"},{"task_id":2,"new_minutes":30,"reasoning":"Testing tasks were accurate; minor adjustment for scope"}]}`)
	b.WriteString("\n\nIf a task has no current estimate (0 min), provide one based on its description and role calibration data.")
	return b.String()
}

// parseCalibrationResponse parses the AI JSON output into EstimateSuggestion slice.
func parseCalibrationResponse(raw string, pending []*pm.Task) ([]EstimateSuggestion, error) {
	byID := make(map[int]*pm.Task, len(pending))
	for _, t := range pending {
		byID[t.ID] = t
	}

	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	jsonStr := raw[start : end+1]

	var result struct {
		Suggestions []calibratedTaskIn `json:"suggestions"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("unmarshal calibration response: %w", err)
	}

	out := make([]EstimateSuggestion, 0, len(result.Suggestions))
	for _, s := range result.Suggestions {
		t, ok := byID[s.TaskID]
		if !ok {
			continue
		}
		out = append(out, EstimateSuggestion{
			TaskID:     s.TaskID,
			Title:      t.Title,
			OldMinutes: t.EstimatedMinutes,
			NewMinutes: s.NewMinutes,
			Reasoning:  s.Reasoning,
		})
	}
	return out, nil
}
