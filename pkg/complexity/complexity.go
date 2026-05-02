// Package complexity implements AI-powered T-shirt size complexity estimation for PM tasks.
// It rates each task with a T-shirt size (XS/S/M/L/XL) and corresponding Fibonacci story
// points (1/2/3/5/8/13) based on description, dependencies, codebase context, and similar
// completed tasks from history.
package complexity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Valid T-shirt sizes in ascending order.
var validSizes = []string{"XS", "S", "M", "L", "XL"}

// sizeToPoints maps T-shirt size to Fibonacci story points.
var sizeToPoints = map[string]int{
	"XS": 1,
	"S":  2,
	"M":  3,
	"L":  5,
	"XL": 8,
}

// ComplexityEstimate holds the AI-generated complexity assessment for a single task.
type ComplexityEstimate struct {
	TaskID       int      `json:"task_id"`
	TaskTitle    string   `json:"task_title"`
	Size         string   `json:"size"`          // XS/S/M/L/XL
	StoryPoints  int      `json:"story_points"`  // 1/2/3/5/8/13 Fibonacci
	Rationale    string   `json:"rationale"`     // 2-3 sentence explanation
	Confidence   string   `json:"confidence"`    // low/medium/high
	SimilarTasks []string `json:"similar_tasks"` // completed task titles used as calibration
}

// IsValidSize returns true if s is a known T-shirt size.
func IsValidSize(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	for _, v := range validSizes {
		if v == s {
			return true
		}
	}
	return false;
}

// PointsForSize returns the Fibonacci story points for a given T-shirt size.
// Returns 0 for unknown sizes.
func PointsForSize(size string) int {
	return sizeToPoints[strings.ToUpper(strings.TrimSpace(size))]
}

// aiResponse is the JSON envelope expected back from the AI.
type aiResponse struct {
	Size         string   `json:"size"`
	StoryPoints  int      `json:"story_points"`
	Rationale    string   `json:"rationale"`
	Confidence   string   `json:"confidence"`
	SimilarTasks []string `json:"similar_tasks"`
}

// buildPrompt constructs the AI prompt for a single-task complexity estimation.
// completedSamples are up to 5 completed tasks used as calibration examples.
func buildPrompt(task *pm.Task, plan *pm.Plan, completedSamples []pm.Task) string {
	var b strings.Builder

	b.WriteString("You are an expert AI engineering manager performing story point estimation.\n")
	b.WriteString("Your job is to assign a T-shirt complexity size and Fibonacci story points to a single task.\n\n")

	if plan != nil && plan.Goal != "" {
		b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", plan.Goal))
	}

	// Task to estimate
	b.WriteString("## TASK TO ESTIMATE\n")
	b.WriteString(fmt.Sprintf("ID: %d\n", task.ID))
	b.WriteString(fmt.Sprintf("Title: %s\n", task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("Role: %s\n", task.Role))
	}
	if len(task.Tags) > 0 {
		b.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(task.Tags, ", ")))
	}
	if len(task.DependsOn) > 0 && plan != nil {
		b.WriteString("Dependencies:\n")
		for _, depID := range task.DependsOn {
			dep := plan.TaskByID(depID)
			if dep != nil {
				b.WriteString(fmt.Sprintf("  - #%d %s\n", dep.ID, dep.Title))
			} else {
				b.WriteString(fmt.Sprintf("  - #%d\n", depID))
			}
		}
	}
	b.WriteString("\n")

	// Calibration examples from completed tasks with known actuals
	if len(completedSamples) > 0 {
		b.WriteString("## COMPLETED TASKS (calibration examples)\n")
		b.WriteString("Use these as reference points to calibrate your estimate.\n")
		for _, sample := range completedSamples {
			line := fmt.Sprintf("- \"%s\"", sample.Title)
			if sample.ComplexitySize != "" {
				line += fmt.Sprintf("  [size=%s, points=%d]", sample.ComplexitySize, sample.StoryPoints)
			}
			if sample.ActualMinutes > 0 {
				line += fmt.Sprintf("  [actual=%dm]", sample.ActualMinutes)
			} else if sample.EstimatedMinutes > 0 {
				line += fmt.Sprintf("  [est=%dm]", sample.EstimatedMinutes)
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	// Complexity scale definition
	b.WriteString("## T-SHIRT SIZE SCALE\n")
	b.WriteString("XS (1 pt)  — Trivial: well-understood change, < 30 min, minimal risk\n")
	b.WriteString("S  (2 pts) — Small: 30-90 min, clear scope, straightforward implementation\n")
	b.WriteString("M  (3 pts) — Medium: 2-4 hours, some unknowns, requires design decisions\n")
	b.WriteString("L  (5 pts) — Large: 4-8 hours or multi-file/multi-system, significant unknowns\n")
	b.WriteString("XL (8 pts) — Extra-large: > 1 day, high uncertainty, consider splitting\n\n")

	b.WriteString("## CONFIDENCE LEVELS\n")
	b.WriteString("high   — requirements are clear, similar work done before, low ambiguity\n")
	b.WriteString("medium — some unknowns but generally understood; reasonable estimate\n")
	b.WriteString("low    — high uncertainty, significant unknowns, estimate may drift\n\n")

	b.WriteString("## ESTIMATION INSTRUCTIONS\n")
	b.WriteString("Consider:\n")
	b.WriteString("1. Task scope and description breadth\n")
	b.WriteString("2. Number and complexity of dependencies\n")
	b.WriteString("3. Technical uncertainty and risk\n")
	b.WriteString("4. How this task compares to the calibration examples above\n")
	b.WriteString("5. The role/expertise required (e.g. security work is riskier than docs)\n\n")

	b.WriteString("Respond with ONLY a JSON object (no markdown, no prose):\n")
	b.WriteString(`{
  "size": "<XS|S|M|L|XL>",
  "story_points": <1|2|3|5|8>,
  "rationale": "<2-3 sentence explanation>",
  "confidence": "<low|medium|high>",
  "similar_tasks": ["<title of similar calibration task>", ...]
}`)
	b.WriteString("\n\nsimilar_tasks should list 0-3 titles from the calibration examples that are most similar to this task. Use [] if none are relevant.\n")

	return b.String()
}

// SelectCalibrationSamples picks up to maxN completed tasks that are most relevant as calibration
// examples. It prefers tasks with known story points, then tasks with actuals, then by recency.
func SelectCalibrationSamples(plan *pm.Plan, maxN int) []pm.Task {
	if plan == nil {
		return nil
	}

	// Collect completed tasks
	var completed []pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			completed = append(completed, *t)
		}
	}
	if len(completed) == 0 {
		return nil
	}

	// Sort: tasks with story points first, then tasks with actual minutes, then by completedAt recency
	type scored struct {
		task  pm.Task
		score int
	}
	var ss []scored
	for _, t := range completed {
		s := 0
		if t.StoryPoints > 0 {
			s += 100
		}
		if t.ActualMinutes > 0 {
			s += 50
		}
		if t.EstimatedMinutes > 0 {
			s += 10
		}
		if t.CompletedAt != nil {
			// More recent = higher score; normalize to days-ago within 30 days
			daysAgo := int(time.Since(*t.CompletedAt).Hours() / 24)
			if daysAgo < 30 {
				s += 30 - daysAgo
			}
		}
		ss = append(ss, scored{t, s})
	}
	// Simple sort by descending score
	for i := 0; i < len(ss)-1; i++ {
		for j := i + 1; j < len(ss); j++ {
			if ss[j].score > ss[i].score {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}

	n := maxN
	if len(ss) < n {
		n = len(ss)
	}
	out := make([]pm.Task, n)
	for i := 0; i < n; i++ {
		out[i] = ss[i].task
	}
	return out
}

// Estimate calls the AI to produce a complexity estimate for the given task.
// completedSamples are used as calibration anchors (pass SelectCalibrationSamples result).
func Estimate(ctx context.Context, prov provider.Provider, model string, task *pm.Task, plan *pm.Plan, completedSamples []pm.Task) (*ComplexityEstimate, error) {
	prompt := buildPrompt(task, plan, completedSamples)

	opts := provider.Options{
		Model:   model,
		Timeout: 60 * time.Second,
	}

	var buf strings.Builder
	opts.OnToken = func(tok string) {
		buf.WriteString(tok)
	}

	if _, err := prov.Complete(ctx, prompt, opts); err != nil {
		return nil, fmt.Errorf("AI call failed: %w", err)
	}

	raw := strings.TrimSpace(buf.String())
	raw = stripMarkdownFence(raw)

	var resp aiResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w\nraw: %s", err, truncate(raw, 500))
	}

	// Normalise size
	resp.Size = strings.ToUpper(strings.TrimSpace(resp.Size))
	if !IsValidSize(resp.Size) {
		return nil, fmt.Errorf("AI returned invalid size %q (expected XS/S/M/L/XL)", resp.Size)
	}

	// Ensure story_points is a valid Fibonacci value, or derive from size
	validPoints := map[int]bool{1: true, 2: true, 3: true, 5: true, 8: true, 13: true}
	if !validPoints[resp.StoryPoints] {
		resp.StoryPoints = sizeToPoints[resp.Size]
	}

	// Normalise confidence
	resp.Confidence = strings.ToLower(strings.TrimSpace(resp.Confidence))
	switch resp.Confidence {
	case "low", "medium", "high":
	default:
		resp.Confidence = "medium"
	}

	return &ComplexityEstimate{
		TaskID:       task.ID,
		TaskTitle:    task.Title,
		Size:         resp.Size,
		StoryPoints:  resp.StoryPoints,
		Rationale:    resp.Rationale,
		Confidence:   resp.Confidence,
		SimilarTasks: resp.SimilarTasks,
	}, nil
}

func stripMarkdownFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	lines := strings.SplitN(s, "\n", 2)
	if len(lines) == 2 {
		s = lines[1]
	}
	if idx := strings.LastIndex(s, "```"); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
