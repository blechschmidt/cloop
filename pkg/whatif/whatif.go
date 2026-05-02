// Package whatif implements scenario-based what-if planning for cloop.
// It applies a natural-language mutation to an in-memory copy of the plan,
// re-runs velocity forecasting and health scoring, and feeds the before/after
// diff to the AI to narrate timeline, risk, and mitigation consequences.
package whatif

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/forecast"
	"github.com/blechschmidt/cloop/pkg/health"
	"github.com/blechschmidt/cloop/pkg/planedit"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TaskChange describes a single field-level change between the original and mutated plan.
type TaskChange struct {
	TaskID    int    `json:"task_id"`
	TaskTitle string `json:"task_title"`
	Field     string `json:"field"`
	Before    string `json:"before"`
	After     string `json:"after"`
}

// Report holds the full what-if analysis — before/after forecasts, health
// scores, structural diff, and the AI narrative.
type Report struct {
	Scenario string `json:"scenario"`

	// Before state
	BeforeForecast *forecast.Forecast  `json:"before_forecast"`
	BeforeHealth   health.HealthReport `json:"before_health"`

	// After (mutated) state
	MutatedPlan  *pm.Plan            `json:"mutated_plan"`
	AfterForecast *forecast.Forecast `json:"after_forecast"`
	AfterHealth  health.HealthReport `json:"after_health"`

	// Structural diff
	TasksAdded   []*pm.Task   `json:"tasks_added,omitempty"`
	TasksRemoved []*pm.Task   `json:"tasks_removed,omitempty"`
	TasksChanged []TaskChange `json:"tasks_changed,omitempty"`

	// AI narrative
	Narrative string `json:"narrative"`

	// Removed tasks flagged by planedit
	RemovedTaskWarnings []*pm.Task `json:"removed_task_warnings,omitempty"`
}

// clonePlan deep-copies a plan via JSON round-trip so mutations are fully isolated.
func clonePlan(plan *pm.Plan) (*pm.Plan, error) {
	data, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("whatif: marshal plan: %w", err)
	}
	var clone pm.Plan
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, fmt.Errorf("whatif: unmarshal plan clone: %w", err)
	}
	return &clone, nil
}

// cloneStateWithPlan creates a lightweight state.ProjectState copy that uses
// the provided plan. Only the fields consumed by forecast.Build are copied.
func cloneStateWithPlan(s *state.ProjectState, plan *pm.Plan) *state.ProjectState {
	return &state.ProjectState{
		Goal:      s.Goal,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
		Plan:      plan,
	}
}

// diffPlans computes the structural differences between two plans.
func diffPlans(before, after *pm.Plan) (added []*pm.Task, removed []*pm.Task, changed []TaskChange) {
	beforeByID := make(map[int]*pm.Task, len(before.Tasks))
	for _, t := range before.Tasks {
		beforeByID[t.ID] = t
	}
	afterByID := make(map[int]*pm.Task, len(after.Tasks))
	for _, t := range after.Tasks {
		afterByID[t.ID] = t
	}

	// Added
	for _, t := range after.Tasks {
		if _, exists := beforeByID[t.ID]; !exists {
			added = append(added, t)
		}
	}

	// Removed
	for _, t := range before.Tasks {
		if _, exists := afterByID[t.ID]; !exists {
			removed = append(removed, t)
		}
	}

	// Changed (field-level diff for tasks present in both)
	for _, bt := range before.Tasks {
		at, exists := afterByID[bt.ID]
		if !exists {
			continue
		}
		title := at.Title
		if title == "" {
			title = bt.Title
		}

		checkField := func(field, bVal, aVal string) {
			if bVal != aVal {
				changed = append(changed, TaskChange{
					TaskID:    bt.ID,
					TaskTitle: title,
					Field:     field,
					Before:    bVal,
					After:     aVal,
				})
			}
		}

		checkField("title", bt.Title, at.Title)
		checkField("description", bt.Description, at.Description)
		checkField("status", string(bt.Status), string(at.Status))
		checkField("priority", fmt.Sprintf("%d", bt.Priority), fmt.Sprintf("%d", at.Priority))
		checkField("estimated_minutes", fmt.Sprintf("%d", bt.EstimatedMinutes), fmt.Sprintf("%d", at.EstimatedMinutes))
		checkField("assignee", bt.Assignee, at.Assignee)
		checkField("role", string(bt.Role), string(at.Role))
	}

	return added, removed, changed
}

// BuildNarrativePrompt constructs the AI prompt for narrating what-if consequences.
func BuildNarrativePrompt(report *Report) string {
	var sb strings.Builder

	sb.WriteString("You are an expert AI project manager specialising in scenario analysis and risk narration.\n")
	sb.WriteString("A user has asked a what-if question about their project plan.\n\n")

	sb.WriteString(fmt.Sprintf("## SCENARIO\n%s\n\n", report.Scenario))

	// Goal
	if report.BeforeForecast != nil {
		sb.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", report.BeforeForecast.Goal))
	}

	// Structural diff
	sb.WriteString("## PLAN MUTATION (what changed)\n")
	if len(report.TasksAdded) == 0 && len(report.TasksRemoved) == 0 && len(report.TasksChanged) == 0 {
		sb.WriteString("No structural changes detected.\n")
	}
	for _, t := range report.TasksAdded {
		sb.WriteString(fmt.Sprintf("  + ADDED   Task #%d [P%d]: %s\n", t.ID, t.Priority, t.Title))
		if t.EstimatedMinutes > 0 {
			sb.WriteString(fmt.Sprintf("             estimated %d min\n", t.EstimatedMinutes))
		}
	}
	for _, t := range report.TasksRemoved {
		sb.WriteString(fmt.Sprintf("  - REMOVED Task #%d: %s\n", t.ID, t.Title))
	}
	for _, c := range report.TasksChanged {
		sb.WriteString(fmt.Sprintf("  ~ CHANGED Task #%d (%s): %s  %q → %q\n",
			c.TaskID, c.TaskTitle, c.Field, c.Before, c.After))
	}
	sb.WriteString("\n")

	// Before forecast
	if f := report.BeforeForecast; f != nil {
		sb.WriteString("## BEFORE — Velocity & Forecast\n")
		sb.WriteString(fmt.Sprintf("  Tasks: %d total, %d done, %d pending, %d blocked\n",
			f.TotalTasks, f.DoneTasks, f.PendingTasks, f.BlockedTasks))
		if f.Expected.DaysRemaining >= 0 {
			sb.WriteString(fmt.Sprintf("  Expected completion: %.1f days → %s\n",
				f.Expected.DaysRemaining,
				f.Expected.CompletionDate.Format("Mon Jan 2, 2006")))
		} else {
			sb.WriteString("  Expected completion: unknown (no velocity data)\n")
		}
		if f.MinuteDataPoints > 0 {
			sb.WriteString(fmt.Sprintf("  Velocity ratio: %.2f (1.0 = on-estimate)\n", f.VelocityRatio))
		}
	}

	// After forecast
	if f := report.AfterForecast; f != nil {
		sb.WriteString("## AFTER — Velocity & Forecast\n")
		sb.WriteString(fmt.Sprintf("  Tasks: %d total, %d done, %d pending, %d blocked\n",
			f.TotalTasks, f.DoneTasks, f.PendingTasks, f.BlockedTasks))
		if f.Expected.DaysRemaining >= 0 {
			sb.WriteString(fmt.Sprintf("  Expected completion: %.1f days → %s\n",
				f.Expected.DaysRemaining,
				f.Expected.CompletionDate.Format("Mon Jan 2, 2006")))
		} else {
			sb.WriteString("  Expected completion: unknown (no velocity data)\n")
		}
	}

	// Health scores
	sb.WriteString(fmt.Sprintf("\n## HEALTH SCORE\n  Before: %d/100 (%s) — %s\n  After:  %d/100 (%s) — %s\n\n",
		report.BeforeHealth.Score, report.BeforeHealth.Grade(), report.BeforeHealth.Summary,
		report.AfterHealth.Score, report.AfterHealth.Grade(), report.AfterHealth.Summary,
	))

	// Newly blocked tasks
	if report.AfterForecast != nil && report.BeforeForecast != nil {
		newlyBlocked := report.AfterForecast.BlockedTasks - report.BeforeForecast.BlockedTasks
		if newlyBlocked > 0 {
			sb.WriteString(fmt.Sprintf("  NOTE: This scenario introduces %d newly blocked task(s).\n\n", newlyBlocked))
		}
	}

	// Narration request
	sb.WriteString("## NARRATION REQUEST\n")
	sb.WriteString("Write a concise Markdown scenario analysis with these sections:\n\n")
	sb.WriteString("### Timeline Impact\nHow does this scenario shift the expected delivery date? Quantify if possible.\n\n")
	sb.WriteString("### Risk Changes\nWhich risks increase, decrease, or emerge as a result of this scenario?\n\n")
	sb.WriteString("### Newly Blocked Tasks\nList any tasks that would become blocked or unblockable in this scenario.\n\n")
	sb.WriteString("### Recommended Mitigations\n3 concrete actions to reduce the downside of this scenario.\n\n")
	sb.WriteString("### Verdict\nOne clear sentence: should the team proceed with this change, prepare contingencies, or avoid it?\n\n")
	sb.WriteString("Be specific, use numbers and dates where available. Do not hedge excessively.\n")

	return sb.String()
}

// Run executes the full what-if pipeline:
//  1. Clone plan.
//  2. Apply mutation via AI (using planedit).
//  3. Build before/after forecasts (no AI).
//  4. Score before/after health (AI calls, run in parallel goroutines).
//  5. Build diff.
//  6. Generate AI narrative (streamed via streamFn).
func Run(ctx context.Context, prov provider.Provider, opts provider.Options, s *state.ProjectState, scenario string, streamFn func(string)) (*Report, error) {
	if s.Plan == nil {
		return nil, fmt.Errorf("whatif: no task plan found — run 'cloop run --pm' to create one")
	}

	// 1. Clone original plan so the mutation is isolated.
	originalPlan, err := clonePlan(s.Plan)
	if err != nil {
		return nil, err
	}

	// 2. Apply mutation via planedit AI call.
	editOpts := opts
	editOpts.OnToken = nil // no streaming for the mutation call
	editResult, err := planedit.EditPlan(ctx, prov, editOpts, originalPlan, scenario)
	if err != nil {
		return nil, fmt.Errorf("whatif: mutation failed: %w", err)
	}
	mutatedPlan := editResult.ModifiedPlan

	// 3. Build forecasts (pure computation, no AI).
	beforeState := cloneStateWithPlan(s, originalPlan)
	afterState := cloneStateWithPlan(s, mutatedPlan)
	beforeForecast := forecast.Build(beforeState)
	afterForecast := forecast.Build(afterState)

	// 4. Score health in parallel (two AI calls).
	type healthResult struct {
		report health.HealthReport
		err    error
	}
	beforeCh := make(chan healthResult, 1)
	afterCh := make(chan healthResult, 1)

	healthTimeout := opts.Timeout
	if healthTimeout <= 0 {
		healthTimeout = 90 * time.Second
	}

	go func() {
		hCtx, cancel := context.WithTimeout(ctx, healthTimeout)
		defer cancel()
		r, e := health.Score(hCtx, prov, opts.Model, healthTimeout, originalPlan)
		beforeCh <- healthResult{r, e}
	}()
	go func() {
		hCtx, cancel := context.WithTimeout(ctx, healthTimeout)
		defer cancel()
		r, e := health.Score(hCtx, prov, opts.Model, healthTimeout, mutatedPlan)
		afterCh <- healthResult{r, e}
	}()

	bh := <-beforeCh
	ah := <-afterCh

	// Health errors are non-fatal: use degraded report.
	beforeHealth := bh.report
	afterHealth := ah.report

	// 5. Diff.
	added, removed, changed := diffPlans(originalPlan, mutatedPlan)

	report := &Report{
		Scenario:            scenario,
		BeforeForecast:      beforeForecast,
		BeforeHealth:        beforeHealth,
		MutatedPlan:         mutatedPlan,
		AfterForecast:       afterForecast,
		AfterHealth:         afterHealth,
		TasksAdded:          added,
		TasksRemoved:        removed,
		TasksChanged:        changed,
		RemovedTaskWarnings: editResult.RemovedTasks,
	}

	// 6. Generate AI narrative (streamed).
	narrativePrompt := BuildNarrativePrompt(report)
	narrativeOpts := opts
	narrativeOpts.OnToken = streamFn
	result, err := prov.Complete(ctx, narrativePrompt, narrativeOpts)
	if err != nil {
		return nil, fmt.Errorf("whatif: narrative generation failed: %w", err)
	}
	report.Narrative = result.Output

	return report, nil
}

// FormatMarkdown renders a complete Markdown what-if report suitable for stdout.
func FormatMarkdown(r *Report) string {
	var sb strings.Builder

	sb.WriteString("# What-If Scenario Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Scenario:** %s\n\n", r.Scenario))

	// Before/After comparison table
	sb.WriteString("## Before / After Comparison\n\n")
	sb.WriteString("| Metric | Before | After | Delta |\n")
	sb.WriteString("|--------|--------|-------|-------|\n")

	if r.BeforeForecast != nil && r.AfterForecast != nil {
		bf, af := r.BeforeForecast, r.AfterForecast
		deltaTasks := af.TotalTasks - bf.TotalTasks
		deltaSign := ""
		if deltaTasks > 0 {
			deltaSign = "+"
		}
		sb.WriteString(fmt.Sprintf("| Total tasks | %d | %d | %s%d |\n",
			bf.TotalTasks, af.TotalTasks, deltaSign, deltaTasks))
		sb.WriteString(fmt.Sprintf("| Done | %d | %d | %s%d |\n",
			bf.DoneTasks, af.DoneTasks, deltaSign, af.DoneTasks-bf.DoneTasks))
		sb.WriteString(fmt.Sprintf("| Pending | %d | %d | %s%d |\n",
			bf.PendingTasks, af.PendingTasks, "", af.PendingTasks-bf.PendingTasks))
		sb.WriteString(fmt.Sprintf("| Blocked | %d | %d | %s%d |\n",
			bf.BlockedTasks, af.BlockedTasks, "", af.BlockedTasks-bf.BlockedTasks))

		bETA := "unknown"
		aETA := "unknown"
		if bf.Expected.DaysRemaining >= 0 {
			bETA = bf.Expected.CompletionDate.Format("Jan 2, 2006")
		}
		if af.Expected.DaysRemaining >= 0 {
			aETA = af.Expected.CompletionDate.Format("Jan 2, 2006")
		}
		sb.WriteString(fmt.Sprintf("| Expected completion | %s | %s | — |\n", bETA, aETA))
	}

	sb.WriteString(fmt.Sprintf("| Health score | %d/100 (%s) | %d/100 (%s) | %+d |\n\n",
		r.BeforeHealth.Score, r.BeforeHealth.Grade(),
		r.AfterHealth.Score, r.AfterHealth.Grade(),
		r.AfterHealth.Score-r.BeforeHealth.Score,
	))

	// Mutation summary
	if len(r.TasksAdded)+len(r.TasksRemoved)+len(r.TasksChanged) > 0 {
		sb.WriteString("## Mutation Applied\n\n")
		for _, t := range r.TasksAdded {
			sb.WriteString(fmt.Sprintf("- **Added** Task #%d [P%d]: %s\n", t.ID, t.Priority, t.Title))
		}
		for _, t := range r.TasksRemoved {
			sb.WriteString(fmt.Sprintf("- **Removed** Task #%d: %s\n", t.ID, t.Title))
		}
		for _, c := range r.TasksChanged {
			sb.WriteString(fmt.Sprintf("- **Changed** Task #%d (%s): `%s` %q → %q\n",
				c.TaskID, c.TaskTitle, c.Field, c.Before, c.After))
		}
		sb.WriteString("\n")
	}

	// AI narrative
	sb.WriteString("## AI Analysis\n\n")
	sb.WriteString(r.Narrative)
	sb.WriteString("\n")

	// Removed task warnings
	if len(r.RemovedTaskWarnings) > 0 {
		sb.WriteString("\n> **Warning:** The mutation would remove the following tasks. Use `--apply` only if intentional:\n")
		for _, t := range r.RemovedTaskWarnings {
			sb.WriteString(fmt.Sprintf("> - Task #%d: %s\n", t.ID, t.Title))
		}
	}

	return sb.String()
}
