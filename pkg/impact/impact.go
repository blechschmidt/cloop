// Package impact implements AI-powered strategic impact scoring for PM tasks.
// It rates every pending/in-progress task on a 1-10 scale based on how much
// it advances the overall project goal. Multiplier tasks (those that unblock
// many others) are identified separately from leaf tasks (independent, low leverage).
package impact

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// TaskImpact holds the AI-generated impact assessment for one task.
type TaskImpact struct {
	TaskID        int    `json:"task_id"`
	TaskTitle     string `json:"task_title"`
	ImpactScore   int    `json:"impact_score"`   // 1-10
	Rationale     string `json:"rationale"`      // brief explanation
	IsMultiplier  bool   `json:"is_multiplier"`  // unblocks many downstream tasks
	UnblocksCount int    `json:"unblocks_count"` // number of tasks that depend on this one
}

// aiResponse is the JSON structure we expect back from the AI.
type aiResponse struct {
	Scores []aiTaskScore `json:"scores"`
}

type aiTaskScore struct {
	ID           int    `json:"id"`
	ImpactScore  int    `json:"impact_score"`
	Rationale    string `json:"rationale"`
	IsMultiplier bool   `json:"is_multiplier"`
}

// buildPrompt constructs the AI prompt for impact scoring.
func buildPrompt(plan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are a strategic AI product manager. Your job is to rate each pending/in-progress task by its strategic impact toward the overall project goal.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", plan.Goal))

	// Completed tasks for context
	var done []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			done = append(done, t)
		}
	}
	if len(done) > 0 {
		b.WriteString("## COMPLETED TASKS (context only)\n")
		for _, t := range done {
			b.WriteString(fmt.Sprintf("- #%d %s\n", t.ID, t.Title))
		}
		b.WriteString("\n")
	}

	// Active tasks to score
	var active []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			active = append(active, t)
		}
	}

	b.WriteString("## TASKS TO SCORE\n")
	for _, t := range active {
		b.WriteString(fmt.Sprintf("- ID %d: %s", t.ID, t.Title))
		if t.Description != "" {
			desc := t.Description
			if len([]rune(desc)) > 200 {
				desc = string([]rune(desc)[:200]) + "..."
			}
			b.WriteString(fmt.Sprintf("\n  Description: %s", desc))
		}
		if t.Role != "" {
			b.WriteString(fmt.Sprintf("\n  Role: %s", t.Role))
		}
		if len(t.DependsOn) > 0 {
			deps := make([]string, len(t.DependsOn))
			for i, d := range t.DependsOn {
				deps[i] = fmt.Sprintf("#%d", d)
			}
			b.WriteString(fmt.Sprintf("\n  Depends on: %s", strings.Join(deps, ", ")))
		}
		if len(t.Tags) > 0 {
			b.WriteString(fmt.Sprintf("\n  Tags: %s", strings.Join(t.Tags, ", ")))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Dependency graph so AI can reason about multipliers
	hasDeps := false
	for _, t := range plan.Tasks {
		if len(t.DependsOn) > 0 {
			hasDeps = true
			break
		}
	}
	if hasDeps {
		b.WriteString("## DEPENDENCY GRAPH\n")
		for _, t := range plan.Tasks {
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, d := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", d)
				}
				b.WriteString(fmt.Sprintf("  #%d depends on: %s\n", t.ID, strings.Join(deps, ", ")))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## SCORING INSTRUCTIONS\n")
	b.WriteString("For each task in 'TASKS TO SCORE', assign:\n")
	b.WriteString("1. impact_score (1-10): how much this task advances the project goal\n")
	b.WriteString("   - 1-3: low impact (nice-to-have, cosmetic, minor edge case)\n")
	b.WriteString("   - 4-6: medium impact (useful feature or fix, moderate value)\n")
	b.WriteString("   - 7-10: high impact (core capability, unblocks progress, multiplies value)\n")
	b.WriteString("2. rationale: 1-2 sentence strategic justification for the score\n")
	b.WriteString("3. is_multiplier: true if this task unblocks 2 or more other pending tasks once complete\n\n")
	b.WriteString("Return ONLY a JSON object with this exact structure (no markdown fences, no extra text):\n")
	b.WriteString(`{"scores": [{"id": <task-id>, "impact_score": <1-10>, "rationale": "<text>", "is_multiplier": <bool>}, ...]}`)
	b.WriteString("\n\nInclude ALL tasks from 'TASKS TO SCORE'. Every id must appear exactly once.\n")

	return b.String()
}

// countUnblocks counts how many pending/in-progress tasks depend on the given task ID.
func countUnblocks(plan *pm.Plan, taskID int) int {
	count := 0
	for _, t := range plan.Tasks {
		if t.Status != pm.TaskPending && t.Status != pm.TaskInProgress {
			continue
		}
		for _, dep := range t.DependsOn {
			if dep == taskID {
				count++
				break
			}
		}
	}
	return count
}

// Score calls the AI to rate every pending/in-progress task by strategic impact.
// Returns a slice of TaskImpact sorted by descending impact score.
func Score(ctx context.Context, prov provider.Provider, opts provider.Options, plan *pm.Plan) ([]TaskImpact, error) {
	// Collect active tasks
	var active []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			active = append(active, t)
		}
	}
	if len(active) == 0 {
		return nil, nil
	}

	prompt := buildPrompt(plan)

	var buf strings.Builder
	callOpts := opts
	callOpts.OnToken = func(tok string) {
		buf.WriteString(tok)
	}

	if _, err := prov.Complete(ctx, prompt, callOpts); err != nil {
		return nil, fmt.Errorf("AI call failed: %w", err)
	}

	raw := strings.TrimSpace(buf.String())
	// Strip markdown fences if present
	if strings.HasPrefix(raw, "```") {
		lines := strings.SplitN(raw, "\n", 2)
		if len(lines) == 2 {
			raw = lines[1]
		}
		if idx := strings.LastIndex(raw, "```"); idx != -1 {
			raw = raw[:idx]
		}
		raw = strings.TrimSpace(raw)
	}

	var result aiResponse
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w\nraw: %s", err, truncate(raw, 500))
	}
	if len(result.Scores) == 0 {
		return nil, fmt.Errorf("AI returned empty scores")
	}

	// Build a lookup by ID for quick title retrieval
	byID := make(map[int]*pm.Task, len(active))
	for _, t := range active {
		byID[t.ID] = t
	}

	impacts := make([]TaskImpact, 0, len(result.Scores))
	for _, s := range result.Scores {
		score := s.ImpactScore
		if score < 1 {
			score = 1
		}
		if score > 10 {
			score = 10
		}
		title := ""
		if t, ok := byID[s.ID]; ok {
			title = t.Title
		}
		unblocksCount := countUnblocks(plan, s.ID)
		impacts = append(impacts, TaskImpact{
			TaskID:        s.ID,
			TaskTitle:     title,
			ImpactScore:   score,
			Rationale:     s.Rationale,
			IsMultiplier:  s.IsMultiplier,
			UnblocksCount: unblocksCount,
		})
	}

	// Sort by descending impact score
	for i := 0; i < len(impacts)-1; i++ {
		for j := i + 1; j < len(impacts); j++ {
			if impacts[j].ImpactScore > impacts[i].ImpactScore {
				impacts[i], impacts[j] = impacts[j], impacts[i]
			}
		}
	}

	return impacts, nil
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
