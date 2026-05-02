// Package sprint implements AI-powered sprint planning with velocity-based grouping.
// It groups pending tasks into time-boxed sprints using velocity data from the
// forecast package, deadlines, priorities, and task dependencies.
package sprint

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/forecast"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

const sprintsFile = ".cloop/sprints.json"

// Sprint represents a time-boxed unit of work.
type Sprint struct {
	ID             int       `json:"id"`
	Name           string    `json:"name"`
	Goal           string    `json:"goal"`
	TaskIDs        []int     `json:"task_ids"`
	EstimatedHours float64   `json:"estimated_hours"`
	StartDate      time.Time `json:"start_date"`
	EndDate        time.Time `json:"end_date"`
	CreatedAt      time.Time `json:"created_at"`
}

// SprintFile is the on-disk format for .cloop/sprints.json.
type SprintFile struct {
	Sprints   []*Sprint `json:"sprints"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CompletionPct returns the percentage of sprint tasks that are done or skipped.
func (s *Sprint) CompletionPct(plan *pm.Plan) int {
	if len(s.TaskIDs) == 0 {
		return 0
	}
	done := 0
	for _, id := range s.TaskIDs {
		t := plan.TaskByID(id)
		if t != nil && (t.Status == pm.TaskDone || t.Status == pm.TaskSkipped) {
			done++
		}
	}
	return done * 100 / len(s.TaskIDs)
}

// Load reads sprints from .cloop/sprints.json. Returns an empty SprintFile if the file
// does not exist.
func Load(workDir string) (*SprintFile, error) {
	path := filepath.Join(workDir, sprintsFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &SprintFile{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sprint: read %s: %w", path, err)
	}
	var sf SprintFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("sprint: parse %s: %w", path, err)
	}
	return &sf, nil
}

// Save writes the SprintFile to .cloop/sprints.json.
func Save(workDir string, sf *SprintFile) error {
	sf.UpdatedAt = time.Now()
	dir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sprint: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("sprint: marshal: %w", err)
	}
	path := filepath.Join(workDir, sprintsFile)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("sprint: write: %w", err)
	}
	return nil
}

// aiSprint is the shape expected in the AI JSON response.
type aiSprint struct {
	Name           string  `json:"name"`
	Goal           string  `json:"goal"`
	TaskIDs        []int   `json:"task_ids"`
	EstimatedHours float64 `json:"estimated_hours"`
	DurationDays   int     `json:"duration_days"`
}

// aiResponse is the top-level JSON envelope expected from the AI.
type aiResponse struct {
	Sprints []aiSprint `json:"sprints"`
}

// PlanPrompt builds the AI prompt for sprint planning.
// It embeds velocity metrics, task list, deadlines, and dependencies.
func PlanPrompt(s *state.ProjectState, f *forecast.Forecast, sprintDays int) string {
	var b strings.Builder

	b.WriteString("You are an expert AI Scrum master performing sprint planning.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", s.Goal))

	b.WriteString("## VELOCITY METRICS\n")
	if f.MinuteDataPoints > 0 {
		b.WriteString(fmt.Sprintf("- Actual/estimated time ratio: %.2f (%d data points)\n", f.VelocityRatio, f.MinuteDataPoints))
		b.WriteString(fmt.Sprintf("- Average estimated minutes per task: %.0f\n", f.AvgEstimatedMinutes))
	} else {
		b.WriteString("- No historical velocity data; assume 1-hour per task\n")
		b.WriteString("- Average estimated minutes per task: 60 (default)\n")
	}
	if f.BaseVelocityPerDay > 0 {
		b.WriteString(fmt.Sprintf("- Velocity: %.2f tasks/day\n", f.BaseVelocityPerDay))
	}
	b.WriteString(fmt.Sprintf("- Sprint duration: %d days\n\n", sprintDays))

	// Check if any tasks have story points set (from ai-complexity)
	hasStoryPoints := false
	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			if (t.Status == pm.TaskPending || t.Status == pm.TaskInProgress) && t.StoryPoints > 0 {
				hasStoryPoints = true
				break
			}
		}
	}

	b.WriteString("## PENDING TASKS (to be assigned to sprints)\n")
	if hasStoryPoints {
		b.WriteString("Format: [ID] Priority | Title | StoryPoints | Estimated (adjusted) minutes | Deadline | DependsOn\n")
		b.WriteString("Note: Story points are available — use them as the primary sizing signal for sprint capacity.\n\n")
	} else {
		b.WriteString("Format: [ID] Priority | Title | Estimated (adjusted) minutes | Deadline | DependsOn\n\n")
	}

	now := time.Now()
	// Collect pending/in-progress tasks sorted by priority.
	var tasks []*pm.Task
	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
				tasks = append(tasks, t)
			}
		}
	}
	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].Priority != tasks[j].Priority {
			return tasks[i].Priority < tasks[j].Priority
		}
		return tasks[i].ID < tasks[j].ID
	})

	avgEst := f.AvgEstimatedMinutes
	if avgEst <= 0 {
		avgEst = 60
	}

	for _, t := range tasks {
		est := float64(t.EstimatedMinutes)
		if est <= 0 {
			est = avgEst
		}
		adjusted := est * f.VelocityRatio
		if adjusted < 1 {
			adjusted = 1
		}

		deadlineStr := "none"
		if t.Deadline != nil {
			d := t.Deadline.Sub(now)
			if d < 0 {
				deadlineStr = fmt.Sprintf("OVERDUE (%s)", t.Deadline.Format("2006-01-02"))
			} else {
				deadlineStr = fmt.Sprintf("%s (in %.0f days)", t.Deadline.Format("2006-01-02"), d.Hours()/24)
			}
		}

		depsStr := "none"
		if len(t.DependsOn) > 0 {
			parts := make([]string, len(t.DependsOn))
			for i, d := range t.DependsOn {
				parts[i] = fmt.Sprintf("#%d", d)
			}
			depsStr = strings.Join(parts, ", ")
		}

		if hasStoryPoints && t.StoryPoints > 0 {
			b.WriteString(fmt.Sprintf("[%d] P%d | %s | %dpts(%s) | est=%.0fm adj=%.0fm | deadline=%s | deps=%s\n",
				t.ID, t.Priority, t.Title, t.StoryPoints, t.ComplexitySize, est, adjusted, deadlineStr, depsStr))
		} else {
			b.WriteString(fmt.Sprintf("[%d] P%d | %s | est=%.0fm adj=%.0fm | deadline=%s | deps=%s\n",
				t.ID, t.Priority, t.Title, est, adjusted, deadlineStr, depsStr))
		}
	}

	b.WriteString(fmt.Sprintf("\nTotal pending tasks: %d\n", len(tasks)))

	b.WriteString("\n## SPRINT PLANNING REQUEST\n")
	planNote := `Group ALL the pending tasks above into sprints of %d days each.
Use adjusted minutes (velocity-corrected) when computing hours per sprint.`
	if hasStoryPoints {
		planNote += `
When story points are available, also use them to balance sprint capacity:
  a typical sprint velocity is 20-30 story points per week for a single developer.`
	}
	planNote += `
Respect dependencies: a task cannot be in an earlier sprint than its dependencies.
Respect deadlines: urgent/overdue tasks must appear in Sprint 1.
Keep each sprint focused with a clear, concise goal (1 sentence).
Give each sprint a memorable name (e.g. "Foundation Sprint", "Core Features", "Polish & Ship").`
	b.WriteString(fmt.Sprintf(planNote+`

Respond with ONLY valid JSON in this exact schema (no markdown, no prose):
{
  "sprints": [
    {
      "name": "Sprint name",
      "goal": "One-sentence sprint goal",
      "task_ids": [1, 2, 3],
      "estimated_hours": 12.5,
      "duration_days": %d
    }
  ]
}
`, sprintDays, sprintDays))

	return b.String()
}

// Plan calls the AI provider to decompose pending tasks into sprints.
// It saves the result to .cloop/sprints.json and updates SprintID on each task.
func Plan(ctx context.Context, p provider.Provider, s *state.ProjectState, f *forecast.Forecast, model string, sprintDays int, streamFn func(string)) ([]*Sprint, error) {
	prompt := PlanPrompt(s, f, sprintDays)

	opts := provider.Options{
		Model:   model,
		Timeout: 120 * time.Second,
		OnToken: streamFn,
	}

	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("sprint plan: AI call: %w", err)
	}

	raw := extractJSON(result.Output)
	var resp aiResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("sprint plan: parse AI response: %w\nraw: %s", err, raw)
	}

	// Build Sprint objects with sequential dates.
	now := time.Now().Truncate(24 * time.Hour)
	var sprints []*Sprint
	cursor := now

	for i, ai := range resp.Sprints {
		days := ai.DurationDays
		if days <= 0 {
			days = sprintDays
		}
		end := cursor.Add(time.Duration(days) * 24 * time.Hour)

		sp := &Sprint{
			ID:             i + 1,
			Name:           ai.Name,
			Goal:           ai.Goal,
			TaskIDs:        ai.TaskIDs,
			EstimatedHours: ai.EstimatedHours,
			StartDate:      cursor,
			EndDate:        end,
			CreatedAt:      time.Now(),
		}
		if sp.Name == "" {
			sp.Name = fmt.Sprintf("Sprint %d", i+1)
		}
		// Recompute estimated hours from tasks if AI didn't provide.
		if sp.EstimatedHours <= 0 && s.Plan != nil {
			var totalMins float64
			avgEst := f.AvgEstimatedMinutes
			if avgEst <= 0 {
				avgEst = 60
			}
			for _, id := range sp.TaskIDs {
				t := s.Plan.TaskByID(id)
				if t == nil {
					continue
				}
				est := float64(t.EstimatedMinutes)
				if est <= 0 {
					est = avgEst
				}
				totalMins += est * f.VelocityRatio
			}
			sp.EstimatedHours = math.Round(totalMins/60*10) / 10
		}

		sprints = append(sprints, sp)
		cursor = end
	}

	// Update SprintID on tasks in the plan.
	if s.Plan != nil {
		for _, sp := range sprints {
			for _, id := range sp.TaskIDs {
				t := s.Plan.TaskByID(id)
				if t != nil {
					t.SprintID = sp.ID
				}
			}
		}
	}

	return sprints, nil
}

// extractJSON extracts the first JSON object from a string (strips markdown fences etc.).
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start == -1 || end == -1 || end < start {
		return s
	}
	return s[start : end+1]
}
