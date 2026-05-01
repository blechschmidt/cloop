// Package pm implements the AI product manager mode.
// In PM mode, the goal is first decomposed into concrete tasks,
// then each task is executed and verified one at a time.
package pm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// TaskStatus represents the state of a task.
type TaskStatus string

const (
	TaskPending    TaskStatus = "pending"
	TaskInProgress TaskStatus = "in_progress"
	TaskDone       TaskStatus = "done"
	TaskFailed     TaskStatus = "failed"
	TaskSkipped    TaskStatus = "skipped"
)

// Task is a single unit of work derived from the project goal.
type Task struct {
	ID          int        `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Priority    int        `json:"priority"` // 1 = highest
	Status      TaskStatus `json:"status"`
	DependsOn   []int      `json:"depends_on,omitempty"` // IDs of tasks that must complete before this one
	Result      string     `json:"result,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Plan is the full task plan for a goal.
type Plan struct {
	Goal    string  `json:"goal"`
	Tasks   []*Task `json:"tasks"`
	Version int     `json:"version"`
}

// NewPlan creates an empty plan for a goal.
func NewPlan(goal string) *Plan {
	return &Plan{Goal: goal, Tasks: []*Task{}, Version: 1}
}

// DepsReady returns true when all of this task's dependencies are done or skipped.
func (p *Plan) DepsReady(t *Task) bool {
	for _, depID := range t.DependsOn {
		for _, dep := range p.Tasks {
			if dep.ID == depID {
				if dep.Status != TaskDone && dep.Status != TaskSkipped {
					return false
				}
				break
			}
		}
	}
	return true
}

// NextTask returns the highest-priority pending task whose dependencies are all satisfied.
func (p *Plan) NextTask() *Task {
	var best *Task
	for _, t := range p.Tasks {
		if t.Status != TaskPending {
			continue
		}
		if !p.DepsReady(t) {
			continue
		}
		if best == nil || t.Priority < best.Priority {
			best = t
		}
	}
	return best
}

// IsComplete returns true if all tasks are done or skipped, or if remaining
// pending tasks are permanently blocked (all their deps include a failed task).
func (p *Plan) IsComplete() bool {
	if len(p.Tasks) == 0 {
		return false
	}
	for _, t := range p.Tasks {
		if t.Status == TaskInProgress {
			return false
		}
		if t.Status == TaskPending {
			// Check if this task is permanently blocked
			if !p.PermanentlyBlocked(t) {
				return false
			}
		}
	}
	return true
}

// PermanentlyBlocked returns true if a task can never run because one of its
// dependencies has failed (and is not retried).
func (p *Plan) PermanentlyBlocked(t *Task) bool {
	for _, depID := range t.DependsOn {
		for _, dep := range p.Tasks {
			if dep.ID == depID && dep.Status == TaskFailed {
				return true
			}
		}
	}
	return false
}

// Summary returns a short summary of task completion.
func (p *Plan) Summary() string {
	done, total := 0, len(p.Tasks)
	for _, t := range p.Tasks {
		if t.Status == TaskDone || t.Status == TaskSkipped {
			done++
		}
	}
	return fmt.Sprintf("%d/%d tasks complete", done, total)
}

// DecomposePrompt builds the prompt for decomposing a goal into tasks.
func DecomposePrompt(goal, instructions string) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager. Your job is to decompose a project goal into a prioritized list of concrete, executable tasks.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}
	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Analyze the goal and produce a JSON task plan. Each task must be:\n")
	b.WriteString("- Concrete and independently executable\n")
	b.WriteString("- Ordered by priority (1 = must do first, higher = can do later)\n")
	b.WriteString("- Specific enough that an AI agent can implement it without clarification\n")
	b.WriteString("- Linked to prerequisite tasks via depends_on (list of task IDs that must complete first)\n\n")
	b.WriteString("Output ONLY valid JSON in this exact format (no explanation, no markdown):\n")
	b.WriteString(`{"tasks":[{"id":1,"title":"short title","description":"detailed description of what to do","priority":1,"depends_on":[]},{"id":2,"title":"another task","description":"details","priority":2,"depends_on":[1]}]}`)
	b.WriteString("\n\nAim for 5-15 tasks. Break large tasks into smaller ones. Use depends_on to express real prerequisites (not just ordering preferences). An empty depends_on array means no prerequisites.")
	return b.String()
}

// ExecuteTaskPrompt builds the prompt for executing a specific task.
func ExecuteTaskPrompt(goal, instructions string, plan *Plan, task *Task) string {
	var b strings.Builder
	b.WriteString("You are an AI agent executing a task as part of a larger project goal.\n")
	b.WriteString("You have full file system access and can run commands.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}

	b.WriteString("## CURRENT TASK\n")
	b.WriteString(fmt.Sprintf("**Task %d: %s**\n", task.ID, task.Title))
	b.WriteString(fmt.Sprintf("%s\n", task.Description))
	if len(task.DependsOn) > 0 {
		depTitles := []string{}
		for _, depID := range task.DependsOn {
			for _, t := range plan.Tasks {
				if t.ID == depID {
					depTitles = append(depTitles, fmt.Sprintf("#%d %s", t.ID, t.Title))
					break
				}
			}
		}
		b.WriteString(fmt.Sprintf("*Depends on: %s*\n", strings.Join(depTitles, ", ")))
	}
	b.WriteString("\n")

	// Show completed tasks for context
	done := []*Task{}
	for _, t := range plan.Tasks {
		if t.Status == TaskDone || t.Status == TaskSkipped {
			done = append(done, t)
		}
	}
	if len(done) > 0 {
		b.WriteString("## COMPLETED TASKS (for context)\n")
		for _, t := range done {
			marker := "[x]"
			if t.Status == TaskSkipped {
				marker = "[-]"
			}
			b.WriteString(fmt.Sprintf("- %s Task %d: %s\n", marker, t.ID, t.Title))
			if t.Result != "" {
				summary := t.Result
				if len(summary) > 200 {
					summary = summary[:200] + "..."
				}
				// Indent result lines for readability
				b.WriteString(fmt.Sprintf("  Summary: %s\n", strings.ReplaceAll(summary, "\n", " ")))
			}
		}
		b.WriteString("\n")
	}

	// Show remaining tasks
	pending := []*Task{}
	for _, t := range plan.Tasks {
		if t.Status == TaskPending && t.ID != task.ID {
			pending = append(pending, t)
		}
	}
	if len(pending) > 0 {
		b.WriteString("## UPCOMING TASKS (do not work on these now)\n")
		for _, t := range pending {
			b.WriteString(fmt.Sprintf("- [ ] Task %d: %s\n", t.ID, t.Title))
		}
		b.WriteString("\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("1. Focus ONLY on the current task\n")
	b.WriteString("2. Implement it fully and verify it works\n")
	b.WriteString("3. If the task is already done or not applicable, explain why\n")
	b.WriteString("4. Summarize what you did\n\n")
	b.WriteString("When the task is successfully completed, end with: TASK_DONE\n")
	b.WriteString("If the task is not applicable or already done, end with: TASK_SKIPPED\n")
	b.WriteString("If you cannot complete the task, end with: TASK_FAILED\n")

	return b.String()
}

// ParseTaskPlan extracts a Plan from the AI's JSON response.
func ParseTaskPlan(goal, output string) (*Plan, error) {
	// Find JSON in the output
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	jsonStr := output[start : end+1]

	var raw struct {
		Tasks []struct {
			ID          int    `json:"id"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Priority    int    `json:"priority"`
			DependsOn   []int  `json:"depends_on"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("parsing task plan: %w", err)
	}

	plan := NewPlan(goal)
	for i, t := range raw.Tasks {
		priority := t.Priority
		if priority == 0 {
			priority = i + 1
		}
		id := t.ID
		if id == 0 {
			id = i + 1
		}
		plan.Tasks = append(plan.Tasks, &Task{
			ID:          id,
			Title:       t.Title,
			Description: t.Description,
			Priority:    priority,
			DependsOn:   t.DependsOn,
			Status:      TaskPending,
		})
	}

	return plan, nil
}

// CheckTaskSignal looks for TASK_DONE, TASK_SKIPPED, TASK_FAILED in output.
func CheckTaskSignal(output string) TaskStatus {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	// Check last 5 lines
	check := lines
	if len(check) > 5 {
		check = check[len(check)-5:]
	}
	for _, line := range check {
		line = strings.TrimSpace(line)
		switch line {
		case "TASK_DONE":
			return TaskDone
		case "TASK_SKIPPED":
			return TaskSkipped
		case "TASK_FAILED":
			return TaskFailed
		}
	}
	return TaskInProgress
}

// Decompose calls the provider to decompose a goal into a task plan.
func Decompose(ctx context.Context, p provider.Provider, goal, instructions, model string, timeout time.Duration) (*Plan, error) {
	prompt := DecomposePrompt(goal, instructions)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("decompose: %w", err)
	}
	return ParseTaskPlan(goal, result.Output)
}
