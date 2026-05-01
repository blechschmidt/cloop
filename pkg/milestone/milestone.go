// Package milestone implements sprint/release planning for cloop PM mode.
// Milestones group tasks into named releases or sprints with optional deadlines
// and provide AI-powered velocity forecasting.
package milestone

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Milestone groups PM tasks into a named sprint or release.
type Milestone struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Deadline    *time.Time `json:"deadline,omitempty"`
	TaskIDs     []int      `json:"task_ids"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Progress holds computed stats for a milestone against a plan.
type Progress struct {
	Total      int
	Done       int
	InProgress int
	Failed     int
	Pending    int
	Skipped    int
	PctDone    float64 // 0.0-100.0
}

// ForecastResult holds an AI-powered completion prediction.
type ForecastResult struct {
	EstimatedDate   *time.Time
	DaysRemaining   int
	TasksPerDay     float64
	IsOnTrack       bool
	RiskLevel       string // "low" | "medium" | "high"
	Notes           string
}

// Progress computes task completion stats for the milestone against the given plan.
// Tasks not found in the plan are ignored.
func (m *Milestone) Progress(plan *pm.Plan) Progress {
	if plan == nil {
		return Progress{}
	}
	// Build a lookup by task ID
	byID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}

	p := Progress{}
	for _, id := range m.TaskIDs {
		t, ok := byID[id]
		if !ok {
			continue
		}
		p.Total++
		switch t.Status {
		case pm.TaskDone:
			p.Done++
		case pm.TaskInProgress:
			p.InProgress++
		case pm.TaskFailed:
			p.Failed++
		case pm.TaskSkipped:
			p.Skipped++
		default:
			p.Pending++
		}
	}
	if p.Total > 0 {
		p.PctDone = float64(p.Done+p.Skipped) / float64(p.Total) * 100.0
	}
	return p
}

// StatusLabel returns a human-readable status considering deadline and progress.
func (m *Milestone) StatusLabel(plan *pm.Plan) string {
	if m.CompletedAt != nil {
		return "complete"
	}
	p := m.Progress(plan)
	if p.Total == 0 {
		return "empty"
	}
	if p.Done+p.Skipped == p.Total {
		return "complete"
	}
	if m.Deadline == nil {
		return "in_progress"
	}
	remaining := time.Until(*m.Deadline)
	// Estimate: if we need >0 tasks per day but have plenty of time
	tasksLeft := p.Total - p.Done - p.Skipped
	daysLeft := remaining.Hours() / 24
	if daysLeft <= 0 {
		return "overdue"
	}
	// Rough velocity: need at least 1 task per 2 days
	requiredRate := float64(tasksLeft) / daysLeft
	if requiredRate > 3 {
		return "at_risk"
	}
	if requiredRate > 1 {
		return "needs_attention"
	}
	return "on_track"
}

// Forecast computes a completion forecast based on historical task velocity.
// createdAt is the session start time used to calculate elapsed time.
func (m *Milestone) Forecast(plan *pm.Plan, sessionStart time.Time) ForecastResult {
	p := m.Progress(plan)
	result := ForecastResult{}

	completedCount := p.Done + p.Skipped
	tasksLeft := p.Total - completedCount

	if tasksLeft == 0 {
		now := time.Now()
		result.EstimatedDate = &now
		result.DaysRemaining = 0
		result.IsOnTrack = true
		result.RiskLevel = "low"
		result.Notes = "All tasks complete."
		return result
	}

	elapsed := time.Since(sessionStart)
	elapsedDays := elapsed.Hours() / 24
	if elapsedDays < 0.01 {
		elapsedDays = 0.01
	}

	if completedCount == 0 {
		result.RiskLevel = "medium"
		result.Notes = "No tasks completed yet — cannot forecast velocity."
		return result
	}

	result.TasksPerDay = float64(completedCount) / elapsedDays
	daysNeeded := float64(tasksLeft) / result.TasksPerDay
	estimated := time.Now().Add(time.Duration(daysNeeded * float64(24*time.Hour)))
	result.EstimatedDate = &estimated
	result.DaysRemaining = int(math.Ceil(daysNeeded))

	if m.Deadline != nil {
		daysUntilDeadline := time.Until(*m.Deadline).Hours() / 24
		slack := daysUntilDeadline - daysNeeded
		switch {
		case slack < 0:
			result.IsOnTrack = false
			result.RiskLevel = "high"
			result.Notes = fmt.Sprintf("Behind schedule by ~%.0f days at current velocity.", -slack)
		case slack < daysNeeded*0.2:
			result.IsOnTrack = true
			result.RiskLevel = "medium"
			result.Notes = fmt.Sprintf("Only %.0f days of slack — any slowdown risks the deadline.", slack)
		default:
			result.IsOnTrack = true
			result.RiskLevel = "low"
			result.Notes = fmt.Sprintf("On track with ~%.0f days of slack.", slack)
		}
	} else {
		result.IsOnTrack = true
		result.RiskLevel = "low"
		result.Notes = fmt.Sprintf("Estimated %.0f days to complete at current velocity (%.2f tasks/day).", daysNeeded, result.TasksPerDay)
	}

	return result
}

// aiMilestone is the shape the AI returns for milestone planning.
type aiMilestone struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	TaskIDs     []int  `json:"task_ids"`
	Deadline    string `json:"deadline,omitempty"` // "YYYY-MM-DD" or ""
	Rationale   string `json:"rationale,omitempty"`
}

// BuildPlanPrompt creates a prompt asking the AI to organize tasks into milestones.
func BuildPlanPrompt(goal string, plan *pm.Plan, existing []*Milestone) string {
	var sb strings.Builder
	sb.WriteString("You are an expert product manager.\n\n")
	sb.WriteString("## Project Goal\n")
	sb.WriteString(goal + "\n\n")

	if plan != nil && len(plan.Tasks) > 0 {
		sb.WriteString("## Current Task Plan\n")
		for _, t := range plan.Tasks {
			status := string(t.Status)
			role := ""
			if t.Role != "" {
				role = fmt.Sprintf(" [%s]", t.Role)
			}
			sb.WriteString(fmt.Sprintf("- Task #%d%s [%s]: %s\n", t.ID, role, status, t.Title))
			if t.Description != "" {
				sb.WriteString(fmt.Sprintf("  %s\n", t.Description))
			}
		}
		sb.WriteString("\n")
	}

	if len(existing) > 0 {
		sb.WriteString("## Existing Milestones\n")
		for _, ms := range existing {
			deadline := ""
			if ms.Deadline != nil {
				deadline = " (deadline: " + ms.Deadline.Format("2006-01-02") + ")"
			}
			sb.WriteString(fmt.Sprintf("- %s%s: tasks %v\n", ms.Name, deadline, ms.TaskIDs))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(`## Instructions

Organize ALL tasks into logical milestones (sprints or releases). Each milestone should:
- Have a clear, meaningful name (e.g. "Foundation", "v0.1 MVP", "v1.0 Launch")
- Group related, sequentially-dependent tasks together
- Be achievable within 1-2 weeks of focused work
- Have at most 8-10 tasks

Respond with ONLY valid JSON — an array of milestone objects with these fields:
- "name": milestone name (string)
- "description": one-sentence purpose (string)
- "task_ids": array of task IDs assigned to this milestone (integers)
- "deadline": suggested deadline as "YYYY-MM-DD", or "" if none (string)
- "rationale": brief justification for the grouping (string)

Every task must appear in exactly one milestone. Do not skip tasks.

Example:
[
  {
    "name": "Foundation",
    "description": "Core infrastructure and project scaffolding.",
    "task_ids": [1, 2, 3],
    "deadline": "",
    "rationale": "These tasks have no dependencies and should ship first."
  }
]
`)
	return sb.String()
}

// ParsePlan parses the AI output into a slice of Milestone structs.
// It handles JSON embedded in markdown code fences.
func ParsePlan(output string, startID int) ([]*Milestone, error) {
	// Strip markdown fences
	raw := output
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
		if end := strings.Index(raw, "```"); end != -1 {
			raw = raw[:end]
		}
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
		if end := strings.Index(raw, "```"); end != -1 {
			raw = raw[:end]
		}
	}
	raw = strings.TrimSpace(raw)

	// Find JSON array
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start == -1 || end == -1 || end < start {
		return nil, fmt.Errorf("no JSON array found in AI response")
	}
	raw = raw[start : end+1]

	var items []aiMilestone
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, fmt.Errorf("parsing AI milestone JSON: %w", err)
	}

	milestones := make([]*Milestone, 0, len(items))
	for i, item := range items {
		ms := &Milestone{
			ID:          startID + i,
			Name:        item.Name,
			Description: item.Description,
			TaskIDs:     item.TaskIDs,
			CreatedAt:   time.Now(),
		}
		if item.Deadline != "" {
			t, err := time.Parse("2006-01-02", item.Deadline)
			if err == nil {
				ms.Deadline = &t
			}
		}
		milestones = append(milestones, ms)
	}
	return milestones, nil
}

// Plan calls the AI provider to generate a milestone plan from the current task list.
func Plan(ctx context.Context, prov provider.Provider, goal string, plan *pm.Plan, existing []*Milestone, opts provider.Options) ([]*Milestone, error) {
	prompt := BuildPlanPrompt(goal, plan, existing)
	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("AI milestone planning: %w", err)
	}

	// Determine next ID
	nextID := 1
	for _, ms := range existing {
		if ms.ID >= nextID {
			nextID = ms.ID + 1
		}
	}

	milestones, err := ParsePlan(result.Output, nextID)
	if err != nil {
		return nil, fmt.Errorf("parsing milestone plan: %w\n\nRaw output:\n%s", err, result.Output)
	}
	return milestones, nil
}

// FindByName returns the first milestone matching name (case-insensitive prefix match).
func FindByName(milestones []*Milestone, name string) *Milestone {
	lower := strings.ToLower(name)
	for _, ms := range milestones {
		if strings.ToLower(ms.Name) == lower {
			return ms
		}
	}
	// Prefix match
	for _, ms := range milestones {
		if strings.HasPrefix(strings.ToLower(ms.Name), lower) {
			return ms
		}
	}
	return nil
}

// SortByID sorts milestones by ID ascending.
func SortByID(milestones []*Milestone) {
	sort.Slice(milestones, func(i, j int) bool {
		return milestones[i].ID < milestones[j].ID
	})
}

// NextID returns one more than the highest existing milestone ID (minimum 1).
func NextID(milestones []*Milestone) int {
	max := 0
	for _, ms := range milestones {
		if ms.ID > max {
			max = ms.ID
		}
	}
	return max + 1
}
