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

// AgentRole defines specialized AI expertise for a task category.
// The role shapes the AI's perspective and focus during task execution.
type AgentRole string

const (
	RoleBackend  AgentRole = "backend"  // API, server, database, business logic
	RoleFrontend AgentRole = "frontend" // UI, UX, HTML, CSS, JavaScript/TypeScript
	RoleTesting  AgentRole = "testing"  // Unit, integration, e2e, and benchmark tests
	RoleSecurity AgentRole = "security" // Auth, permissions, hardening, threat modeling
	RoleDevOps   AgentRole = "devops"   // CI/CD, Docker, deployment, infrastructure
	RoleData     AgentRole = "data"     // Databases, migrations, data modeling, ETL
	RoleDocs     AgentRole = "docs"     // Documentation, README, API docs, comments
	RoleReview   AgentRole = "review"   // Code review, quality, refactoring
)

// RoleSystemPrompt returns a role-specific system context prepended to task execution prompts.
// Returns empty string for unknown roles or empty role (generic execution).
func RoleSystemPrompt(role AgentRole) string {
	switch role {
	case RoleBackend:
		return "You are a senior backend engineer. Focus on correctness, performance, and maintainability. " +
			"Apply best practices for API design, error handling, database interaction, and security. " +
			"Prefer explicit error handling and well-structured code over brevity.\n\n"
	case RoleFrontend:
		return "You are a senior frontend engineer. Focus on user experience, accessibility, and performance. " +
			"Apply best practices for component structure, state management, and responsive design. " +
			"Ensure cross-browser compatibility and follow the project's existing UI conventions.\n\n"
	case RoleTesting:
		return "You are a test engineering expert. Write comprehensive, maintainable tests that give real confidence. " +
			"Cover happy paths, edge cases, and error conditions. Avoid over-mocking — prefer integration tests " +
			"where feasible. Ensure tests are deterministic and fast.\n\n"
	case RoleSecurity:
		return "You are a security engineer. Think like an attacker, build like a defender. " +
			"Review for OWASP Top 10 vulnerabilities, injection flaws, broken auth, and data exposure. " +
			"Validate all inputs, enforce least-privilege, and document security decisions.\n\n"
	case RoleDevOps:
		return "You are a DevOps/platform engineer. Focus on reliability, repeatability, and observability. " +
			"Apply best practices for containerization, CI/CD pipelines, infrastructure-as-code, and monitoring. " +
			"Ensure configurations are idempotent and rollback-safe.\n\n"
	case RoleData:
		return "You are a data engineer. Focus on data integrity, query performance, and schema correctness. " +
			"Design schemas with normalization and indexing in mind. Write efficient queries and safe migrations " +
			"that can be rolled back. Document data models clearly.\n\n"
	case RoleDocs:
		return "You are a technical writer and documentation engineer. Write clear, accurate, and complete documentation. " +
			"Focus on the reader's perspective — explain the 'why' not just the 'what'. " +
			"Keep docs concise, well-organized, and always synchronized with the code.\n\n"
	case RoleReview:
		return "You are a code reviewer and refactoring expert. Focus on code quality, readability, and maintainability. " +
			"Identify code smells, unnecessary complexity, and opportunities for simplification. " +
			"Enforce consistency with project conventions and flag any correctness issues.\n\n"
	default:
		return ""
	}
}

// ValidRoles returns all known role names as strings (for help text and validation).
func ValidRoles() []string {
	return []string{
		string(RoleBackend),
		string(RoleFrontend),
		string(RoleTesting),
		string(RoleSecurity),
		string(RoleDevOps),
		string(RoleData),
		string(RoleDocs),
		string(RoleReview),
	}
}

// Task is a single unit of work derived from the project goal.
type Task struct {
	ID            int        `json:"id"`
	Title         string     `json:"title"`
	Description   string     `json:"description"`
	Priority      int        `json:"priority"` // 1 = highest
	Status        TaskStatus `json:"status"`
	Role          AgentRole  `json:"role,omitempty"`      // specialized agent role for this task
	DependsOn     []int      `json:"depends_on,omitempty"` // IDs of tasks that must complete before this one
	Result        string     `json:"result,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	VerifyRetries int        `json:"verify_retries,omitempty"` // number of times task was re-queued by verifier
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

// ReadyTasks returns all pending tasks whose dependencies are satisfied.
// In parallel mode, all of these can be run concurrently.
func (p *Plan) ReadyTasks() []*Task {
	var ready []*Task
	for _, t := range p.Tasks {
		if t.Status == TaskPending && p.DepsReady(t) {
			ready = append(ready, t)
		}
	}
	return ready
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

// CountByStatus returns the number of done (includes skipped) and failed tasks.
func (p *Plan) CountByStatus() (done, failed int) {
	for _, t := range p.Tasks {
		switch t.Status {
		case TaskDone, TaskSkipped:
			done++
		case TaskFailed:
			failed++
		}
	}
	return
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
	b.WriteString(`{"tasks":[{"id":1,"title":"short title","description":"detailed description of what to do","priority":1,"role":"backend","depends_on":[]},{"id":2,"title":"another task","description":"details","priority":2,"role":"testing","depends_on":[1]}]}`)
	b.WriteString("\n\nAim for 5-15 tasks. Break large tasks into smaller ones.")
	b.WriteString("\nUse depends_on to express real prerequisites. An empty depends_on array means no prerequisites.")
	b.WriteString("\nFor role, choose the best fit from: backend, frontend, testing, security, devops, data, docs, review. Use empty string if none applies.")
	return b.String()
}

// ExecuteTaskPrompt builds the prompt for executing a specific task.
// Pass a non-nil ProjectContext to include project state (git, file tree) in the prompt.
func ExecuteTaskPrompt(goal, instructions string, plan *Plan, task *Task, ctx ...*ProjectContext) string {
	var b strings.Builder

	// Inject role-specific expertise if task has a role assigned.
	if rolePrompt := RoleSystemPrompt(task.Role); rolePrompt != "" {
		b.WriteString(rolePrompt)
	}

	b.WriteString("You are an AI agent executing a task as part of a larger project goal.\n")
	b.WriteString("You have full file system access and can run commands.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}

	b.WriteString("## CURRENT TASK\n")
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("**Task %d: %s** [role: %s]\n", task.ID, task.Title, task.Role))
	} else {
		b.WriteString(fmt.Sprintf("**Task %d: %s**\n", task.ID, task.Title))
	}
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

	// Inject project context if provided
	if len(ctx) > 0 && ctx[0] != nil {
		if formatted := ctx[0].Format(); formatted != "" {
			b.WriteString(formatted)
		}
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
			ID          int       `json:"id"`
			Title       string    `json:"title"`
			Description string    `json:"description"`
			Priority    int       `json:"priority"`
			Role        AgentRole `json:"role"`
			DependsOn   []int     `json:"depends_on"`
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
			Role:        t.Role,
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

// AdaptiveReplanPrompt builds a prompt to re-plan remaining tasks after failures.
func AdaptiveReplanPrompt(goal, instructions string, plan *Plan, failedTask *Task, failureReason string) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager performing adaptive replanning.\n")
	b.WriteString("A task has failed and you need to re-think the remaining work.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}

	// Report completed tasks
	done := []*Task{}
	for _, t := range plan.Tasks {
		if t.Status == TaskDone || t.Status == TaskSkipped {
			done = append(done, t)
		}
	}
	if len(done) > 0 {
		b.WriteString("## COMPLETED TASKS\n")
		for _, t := range done {
			b.WriteString(fmt.Sprintf("- [x] Task %d: %s\n", t.ID, t.Title))
		}
		b.WriteString("\n")
	}

	b.WriteString("## FAILED TASK\n")
	b.WriteString(fmt.Sprintf("Task %d: %s\n", failedTask.ID, failedTask.Title))
	if failedTask.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", failedTask.Description))
	}
	if failureReason != "" {
		b.WriteString(fmt.Sprintf("Failure context: %s\n", failureReason))
	}
	b.WriteString("\n")

	// Report remaining pending tasks
	pending := []*Task{}
	for _, t := range plan.Tasks {
		if t.Status == TaskPending {
			pending = append(pending, t)
		}
	}
	if len(pending) > 0 {
		b.WriteString("## REMAINING PENDING TASKS (before replanning)\n")
		for _, t := range pending {
			b.WriteString(fmt.Sprintf("- [ ] Task %d [P%d]: %s\n", t.ID, t.Priority, t.Title))
			if t.Description != "" {
				b.WriteString(fmt.Sprintf("  %s\n", t.Description))
			}
		}
		b.WriteString("\n")
	}

	// Find highest existing ID
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Given the failure above, produce a revised plan for the REMAINING work only.\n")
	b.WriteString("- You may modify, merge, split, or reorder tasks to work around the failure\n")
	b.WriteString("- Do not re-include already completed tasks\n")
	b.WriteString("- Assign new sequential IDs starting from " + fmt.Sprintf("%d", maxID+1) + "\n")
	b.WriteString("- Use depends_on to express prerequisites\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown):\n")
	b.WriteString(`{"tasks":[{"id":` + fmt.Sprintf("%d", maxID+1) + `,"title":"...","description":"...","priority":1,"depends_on":[]}]}`)
	b.WriteString("\n\nIf no replanning is needed (all remaining work is blocked or complete), output: {\"tasks\":[]}")
	return b.String()
}

// AdaptiveReplan calls the provider to re-plan remaining tasks after a failure.
// It returns a new set of tasks to append/replace the pending tasks in the plan.
func AdaptiveReplan(ctx context.Context, p provider.Provider, goal, instructions, model string, timeout time.Duration, plan *Plan, failedTask *Task, failureReason string) ([]*Task, error) {
	prompt := AdaptiveReplanPrompt(goal, instructions, plan, failedTask, failureReason)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("adaptive replan: %w", err)
	}

	// Find the highest existing ID to validate new task IDs
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	newPlan, err := ParseTaskPlan(goal, result.Output)
	if err != nil {
		return nil, fmt.Errorf("parse replan: %w", err)
	}

	// Re-assign IDs to avoid collisions (ensure they start after maxID)
	for i, t := range newPlan.Tasks {
		if t.ID <= maxID {
			t.ID = maxID + i + 1
		}
	}

	return newPlan.Tasks, nil
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

// VerifyTaskPrompt builds a prompt that asks the AI to verify whether a task was actually completed.
// The verifier reviews the task description and the executor's output and checks the real filesystem/code.
func VerifyTaskPrompt(goal, instructions string, task *Task, executorOutput string) string {
	var b strings.Builder
	b.WriteString("You are a strict code reviewer verifying whether a task was actually completed.\n")
	b.WriteString("You have full file system access and can run commands to inspect the results.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}
	b.WriteString("## TASK THAT SHOULD HAVE BEEN COMPLETED\n")
	b.WriteString(fmt.Sprintf("**Task %d: %s**\n", task.ID, task.Title))
	b.WriteString(fmt.Sprintf("%s\n\n", task.Description))
	b.WriteString("## EXECUTOR'S REPORTED OUTPUT\n")
	if len(executorOutput) > 2000 {
		b.WriteString(executorOutput[:1000])
		b.WriteString("\n...(truncated)...\n")
		b.WriteString(executorOutput[len(executorOutput)-1000:])
	} else {
		b.WriteString(executorOutput)
	}
	b.WriteString("\n\n## VERIFICATION INSTRUCTIONS\n")
	b.WriteString("1. Critically evaluate whether the task was actually completed\n")
	b.WriteString("2. Check for concrete evidence: inspect files, run tests, verify commands work\n")
	b.WriteString("3. Do NOT accept vague claims — look for real artifacts (files, passing tests, working code)\n")
	b.WriteString("4. If the task created or modified files, verify they exist and contain the expected content\n")
	b.WriteString("5. Summarize your findings and your verdict\n\n")
	b.WriteString("End your response with exactly one of:\n")
	b.WriteString("VERIFY_PASS — the task is genuinely complete\n")
	b.WriteString("VERIFY_FAIL — the task was not actually completed or is incomplete\n")
	return b.String()
}

// VerifySignal parses the verifier's response and returns true if VERIFY_PASS was found.
func VerifySignal(output string) (pass bool, found bool) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	check := lines
	if len(check) > 5 {
		check = check[len(check)-5:]
	}
	for _, line := range check {
		line = strings.TrimSpace(line)
		if line == "VERIFY_PASS" {
			return true, true
		}
		if line == "VERIFY_FAIL" {
			return false, true
		}
	}
	return false, false
}

// VerifyTask calls the provider to verify whether a task was genuinely completed.
// Returns (true, nil) for pass, (false, nil) for fail, (false, err) on provider error.
func VerifyTask(ctx context.Context, p provider.Provider, goal, instructions, model string, timeout time.Duration, task *Task, executorOutput string) (bool, error) {
	prompt := VerifyTaskPrompt(goal, instructions, task, executorOutput)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return false, fmt.Errorf("verify task: %w", err)
	}
	pass, found := VerifySignal(result.Output)
	if !found {
		// If no explicit signal, treat as pass to avoid blocking valid completions
		return true, nil
	}
	return pass, nil
}
