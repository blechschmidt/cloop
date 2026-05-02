// Package linter performs static and AI-based quality analysis on cloop task plans.
// Static checks run without any AI call; AI checks are batched into a single provider call.
package linter

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Severity levels for lint issues.
type Severity string

const (
	SeverityError Severity = "ERROR"
	SeverityWarn  Severity = "WARN"
	SeverityInfo  Severity = "INFO"
)

// Issue is a single lint finding for a task plan.
type Issue struct {
	// TaskID is the task this issue applies to (0 = plan-level).
	TaskID int

	// Field is the task field that is affected (e.g. "title", "description", "priority").
	Field string

	// Severity indicates how serious the issue is.
	Severity Severity

	// Code is a short machine-readable identifier (e.g. "duplicate-title").
	Code string

	// Message is the human-readable description of the problem.
	Message string

	// Suggestion is an optional actionable improvement hint (may be empty for static checks).
	Suggestion string
}

// Options configure the Lint call.
type Options struct {
	// TaskID, when non-zero, restricts linting to a single task.
	TaskID int

	// SkipAI disables the AI-based checks (static checks still run).
	SkipAI bool

	// Provider and Model are used for the AI batch call.
	Provider provider.Provider
	Model    string

	// Timeout is forwarded to the provider call via context (set by caller).
}

// Lint analyses the plan and returns a slice of Issues ordered by severity (ERROR first).
// Static checks run without any AI call. AI checks are batched in a single provider call
// unless opts.SkipAI is true.
func Lint(ctx context.Context, plan *pm.Plan, opts Options) ([]Issue, error) {
	if plan == nil {
		return nil, nil
	}

	tasks := plan.Tasks
	if opts.TaskID != 0 {
		var filtered []*pm.Task
		for _, t := range plan.Tasks {
			if t.ID == opts.TaskID {
				filtered = append(filtered, t)
				break
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("task #%d not found", opts.TaskID)
		}
		tasks = filtered
	}

	var issues []Issue

	// --- Static checks ---
	issues = append(issues, checkDuplicateTitles(plan.Tasks, tasks)...)
	issues = append(issues, checkMissingDescriptions(tasks)...)
	issues = append(issues, checkZeroPriority(tasks)...)
	issues = append(issues, checkCircularDeps(plan.Tasks)...)
	issues = append(issues, checkDuplicateCompletedTitle(plan.Tasks, tasks)...)
	issues = append(issues, checkHighPriorityNoTimeBudget(tasks)...)
	issues = append(issues, checkPinInflation(plan.Tasks)...)

	// --- AI checks ---
	if !opts.SkipAI && opts.Provider != nil && len(tasks) > 0 {
		aiIssues, err := runAIChecks(ctx, opts.Provider, opts.Model, tasks)
		if err != nil {
			// AI failure is non-fatal: report as an INFO issue so the caller still gets static results.
			issues = append(issues, Issue{
				Severity: SeverityInfo,
				Code:     "ai-check-failed",
				Message:  fmt.Sprintf("AI checks could not run: %v", err),
			})
		} else {
			issues = append(issues, aiIssues...)
		}
	}

	sortBySeverity(issues)
	return issues, nil
}

// --- Static check implementations ---

func checkDuplicateTitles(allTasks, targetTasks []*pm.Task) []Issue {
	seen := map[string]int{} // normalised title → first task ID
	for _, t := range allTasks {
		key := normTitle(t.Title)
		if first, ok := seen[key]; ok && first != t.ID {
			// Only emit if one of the two is in targetTasks
			if inSet(targetTasks, t.ID) {
				return []Issue{{
					TaskID:   t.ID,
					Field:    "title",
					Severity: SeverityError,
					Code:     "duplicate-title",
					Message:  fmt.Sprintf("Task #%d has the same title as task #%d: %q", t.ID, first, t.Title),
				}}
			}
		} else {
			seen[key] = t.ID
		}
	}
	return nil
}

func checkMissingDescriptions(tasks []*pm.Task) []Issue {
	var issues []Issue
	for _, t := range tasks {
		if len(strings.TrimSpace(t.Description)) < 20 {
			issues = append(issues, Issue{
				TaskID:     t.ID,
				Field:      "description",
				Severity:   SeverityWarn,
				Code:       "missing-description",
				Message:    fmt.Sprintf("Task #%d %q has a very short description (%d chars)", t.ID, t.Title, len(strings.TrimSpace(t.Description))),
				Suggestion: "Add at least 20 characters describing what needs to be done and why.",
			})
		}
	}
	return issues
}

func checkZeroPriority(tasks []*pm.Task) []Issue {
	var issues []Issue
	for _, t := range tasks {
		if t.Priority == 0 {
			issues = append(issues, Issue{
				TaskID:     t.ID,
				Field:      "priority",
				Severity:   SeverityWarn,
				Code:       "zero-priority",
				Message:    fmt.Sprintf("Task #%d %q has priority 0 (unset)", t.ID, t.Title),
				Suggestion: "Set a priority ≥ 1 (lower number = higher priority).",
			})
		}
	}
	return issues
}

// checkHighPriorityNoTimeBudget warns when a high-priority task (priority ≤ 2)
// has no MaxMinutes set, which means it could run indefinitely and block the plan.
func checkHighPriorityNoTimeBudget(tasks []*pm.Task) []Issue {
	var issues []Issue
	for _, t := range tasks {
		if t.Priority > 0 && t.Priority <= 2 && t.MaxMinutes == 0 {
			issues = append(issues, Issue{
				TaskID:     t.ID,
				Field:      "max_minutes",
				Severity:   SeverityWarn,
				Code:       "no-time-budget",
				Message:    fmt.Sprintf("Task #%d %q is high-priority (P%d) but has no time budget set", t.ID, t.Title, t.Priority),
				Suggestion: "Set max_minutes (e.g. via 'cloop task add --max-minutes 30') to prevent runaway execution from blocking the plan.",
			})
		}
	}
	return issues
}

func checkCircularDeps(allTasks []*pm.Task) []Issue {
	// Build adjacency map
	adj := map[int][]int{}
	idSet := map[int]bool{}
	for _, t := range allTasks {
		idSet[t.ID] = true
		adj[t.ID] = t.DependsOn
	}

	// 3-colour DFS: 0=unvisited, 1=in-stack, 2=done
	colour := map[int]int{}
	var path []int
	var cycle []int

	var dfs func(id int) bool
	dfs = func(id int) bool {
		if colour[id] == 2 {
			return false
		}
		if colour[id] == 1 {
			cycle = make([]int, len(path))
			copy(cycle, path)
			return true
		}
		colour[id] = 1
		path = append(path, id)
		for _, dep := range adj[id] {
			if idSet[dep] && dfs(dep) {
				return true
			}
		}
		path = path[:len(path)-1]
		colour[id] = 2
		return false
	}

	for _, t := range allTasks {
		path = nil
		if dfs(t.ID) {
			ids := make([]string, len(cycle))
			for i, id := range cycle {
				ids[i] = strconv.Itoa(id)
			}
			return []Issue{{
				Field:    "depends_on",
				Severity: SeverityError,
				Code:     "circular-dependency",
				Message:  fmt.Sprintf("Circular dependency detected among tasks: %s", strings.Join(ids, " → ")),
			}}
		}
	}
	return nil
}

func checkDuplicateCompletedTitle(allTasks, targetTasks []*pm.Task) []Issue {
	doneSet := map[string]bool{}
	for _, t := range allTasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			doneSet[normTitle(t.Title)] = true
		}
	}
	var issues []Issue
	for _, t := range targetTasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			if doneSet[normTitle(t.Title)] {
				issues = append(issues, Issue{
					TaskID:     t.ID,
					Field:      "title",
					Severity:   SeverityWarn,
					Code:       "title-matches-done-task",
					Message:    fmt.Sprintf("Task #%d %q has the same title as a completed/skipped task — may be a duplicate", t.ID, t.Title),
					Suggestion: "Review if this task is truly distinct from the completed one.",
				})
			}
		}
	}
	return issues
}

// checkPinInflation warns when more than 5 tasks are pinned simultaneously,
// since the usefulness of pinning diminishes when everything is pinned.
func checkPinInflation(allTasks []*pm.Task) []Issue {
	count := pm.PinnedCount(allTasks)
	if count <= 5 {
		return nil
	}
	return []Issue{{
		Field:      "pinned",
		Severity:   SeverityWarn,
		Code:       "pin-inflation",
		Message:    fmt.Sprintf("%d tasks are currently pinned — consider reducing to ≤5 to keep the pin indicator meaningful", count),
		Suggestion: "Run 'cloop task unpin <id>' on lower-priority pinned tasks to avoid pin inflation.",
	}}
}

// --- AI check ---

// aiIssueJSON is the shape expected back from the AI.
type aiIssueJSON struct {
	TaskID     int    `json:"task_id"`
	Field      string `json:"field"`
	Severity   string `json:"severity"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

func runAIChecks(ctx context.Context, prov provider.Provider, model string, tasks []*pm.Task) ([]Issue, error) {
	prompt := buildAIPrompt(tasks)
	result, err := prov.Complete(ctx, prompt, provider.Options{Model: model})
	if err != nil {
		return nil, err
	}

	// Extract JSON array from response (strip markdown fences if present)
	raw := extractJSON(result.Output)
	if raw == "" {
		return nil, fmt.Errorf("no JSON array in AI response")
	}

	var items []aiIssueJSON
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w", err)
	}

	var issues []Issue
	for _, item := range items {
		sev := normSeverity(item.Severity)
		if sev == "" {
			sev = SeverityInfo
		}
		issues = append(issues, Issue{
			TaskID:     item.TaskID,
			Field:      item.Field,
			Severity:   sev,
			Code:       item.Code,
			Message:    item.Message,
			Suggestion: item.Suggestion,
		})
	}
	return issues, nil
}

func buildAIPrompt(tasks []*pm.Task) string {
	var sb strings.Builder
	sb.WriteString(`You are a task plan quality reviewer. Analyze the tasks below and return ONLY a JSON array of issues.

Each issue must be a JSON object with these fields:
  task_id   (int)    — task ID (0 for plan-level issues)
  field     (string) — "title", "description", or "scope"
  severity  (string) — "ERROR", "WARN", or "INFO"
  code      (string) — one of: "vague-verb", "missing-acceptance-criteria", "unrealistic-scope"
  message   (string) — concise explanation of the problem
  suggestion (string) — specific rewrite or actionable fix

Rules:
1. "vague-verb": Title starts with a vague verb ('fix', 'update', 'improve', 'refactor', 'change', 'modify') with no specific detail about what exactly changes. Only flag if genuinely vague.
2. "missing-acceptance-criteria": Description has no measurable success condition (no "should", "must", "returns", "passes", specific file/function/endpoint mentioned).
3. "unrealistic-scope": Task appears to encompass multiple distinct subsystems or would take >1 sprint to complete based on scope described.

Only output issues you are confident about. If no issues, return [].

Tasks:
`)
	for _, t := range tasks {
		sb.WriteString(fmt.Sprintf("[Task #%d]\nTitle: %s\nDescription: %s\nPriority: %d\nStatus: %s\n\n",
			t.ID, t.Title, t.Description, t.Priority, t.Status))
	}
	sb.WriteString("\nReturn ONLY the JSON array, no other text.")
	return sb.String()
}

// --- Fix / rewrite ---

// FixSuggestion holds an AI-generated field rewrite for a single task.
type FixSuggestion struct {
	TaskID      int
	TitleFix    string
	DescFix     string
}

// GenerateFixes asks the provider to rewrite titles/descriptions for the given issues.
func GenerateFixes(ctx context.Context, prov provider.Provider, model string, plan *pm.Plan, issues []Issue) ([]FixSuggestion, error) {
	// Collect tasks that need fixing
	type fixTarget struct {
		task        *pm.Task
		fixTitle    bool
		fixDesc     bool
	}
	targets := map[int]*fixTarget{}
	for _, issue := range issues {
		if issue.TaskID == 0 {
			continue
		}
		if issue.Field != "title" && issue.Field != "description" {
			continue
		}
		if _, ok := targets[issue.TaskID]; !ok {
			for _, t := range plan.Tasks {
				if t.ID == issue.TaskID {
					targets[issue.TaskID] = &fixTarget{task: t}
					break
				}
			}
		}
		if ft, ok := targets[issue.TaskID]; ok {
			if issue.Field == "title" {
				ft.fixTitle = true
			} else {
				ft.fixDesc = true
			}
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	var sb strings.Builder
	sb.WriteString(`You are rewriting task titles and descriptions to fix quality issues.
For each task below return ONLY a JSON array where each object has:
  task_id      (int)    — the task ID
  title_fix    (string) — improved title (empty string if no change needed)
  desc_fix     (string) — improved description (empty string if no change needed)

Make fixes specific, measurable, and concise. Return ONLY the JSON array.

Tasks to fix:
`)
	for _, ft := range targets {
		t := ft.task
		sb.WriteString(fmt.Sprintf("[Task #%d]\nTitle: %s\nDescription: %s\nFix title: %v\nFix description: %v\n\n",
			t.ID, t.Title, t.Description, ft.fixTitle, ft.fixDesc))
	}

	result, err := prov.Complete(ctx, sb.String(), provider.Options{Model: model})
	if err != nil {
		return nil, err
	}

	raw := extractJSON(result.Output)
	if raw == "" {
		return nil, fmt.Errorf("no JSON in AI fix response")
	}

	type fixJSON struct {
		TaskID   int    `json:"task_id"`
		TitleFix string `json:"title_fix"`
		DescFix  string `json:"desc_fix"`
	}
	var fixes []fixJSON
	if err := json.Unmarshal([]byte(raw), &fixes); err != nil {
		return nil, fmt.Errorf("parsing fix response: %w", err)
	}

	var out []FixSuggestion
	for _, f := range fixes {
		if f.TitleFix != "" || f.DescFix != "" {
			out = append(out, FixSuggestion{
				TaskID:   f.TaskID,
				TitleFix: f.TitleFix,
				DescFix:  f.DescFix,
			})
		}
	}
	return out, nil
}

// ApplyFixes updates the plan in-place with the generated fixes.
func ApplyFixes(plan *pm.Plan, fixes []FixSuggestion) int {
	changed := 0
	for _, fix := range fixes {
		for _, t := range plan.Tasks {
			if t.ID == fix.TaskID {
				if fix.TitleFix != "" {
					t.Title = fix.TitleFix
					changed++
				}
				if fix.DescFix != "" {
					t.Description = fix.DescFix
					changed++
				}
			}
		}
	}
	return changed
}

// --- Helpers ---

func normTitle(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func inSet(tasks []*pm.Task, id int) bool {
	for _, t := range tasks {
		if t.ID == id {
			return true
		}
	}
	return false
}

func normSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return SeverityError
	case "WARN", "WARNING":
		return SeverityWarn
	case "INFO":
		return SeverityInfo
	}
	return ""
}

func sortBySeverity(issues []Issue) {
	// Simple insertion sort: ERROR < WARN < INFO
	rank := func(s Severity) int {
		switch s {
		case SeverityError:
			return 0
		case SeverityWarn:
			return 1
		default:
			return 2
		}
	}
	for i := 1; i < len(issues); i++ {
		for j := i; j > 0 && rank(issues[j].Severity) < rank(issues[j-1].Severity); j-- {
			issues[j], issues[j-1] = issues[j-1], issues[j]
		}
	}
}

// extractJSON pulls the first JSON array out of a potentially markdown-fenced response.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Strip markdown fences
	if strings.HasPrefix(s, "```") {
		end := strings.LastIndex(s, "```")
		if end > 3 {
			s = strings.TrimSpace(s[strings.Index(s, "\n")+1 : end])
		}
	}
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start < 0 || end < start {
		return ""
	}
	return s[start : end+1]
}
