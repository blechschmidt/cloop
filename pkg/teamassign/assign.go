// Package teamassign provides AI-powered automatic task assignment based on
// inferred skill match between task descriptions and team member history.
package teamassign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Member represents a team member available for assignment.
type Member struct {
	Name   string   // display name / login
	Role   string   // optional job role (e.g. "backend engineer")
	Skills []string // inferred skill tags derived from completed task history
}

// AssignmentResult is the AI's decision for a single task.
type AssignmentResult struct {
	TaskID    int    `json:"task_id"`
	Assignee  string `json:"assignee"`
	Reasoning string `json:"reasoning"`
}

// AssignPrompt builds the prompt that asks the AI to assign unassigned tasks
// to team members based on skill match, workload, and overdue priority.
func AssignPrompt(tasks []*pm.Task, members []Member) string {
	var sb strings.Builder

	sb.WriteString("You are an AI project manager performing skill-based task assignment.\n")
	sb.WriteString("Assign each listed task to the most suitable team member based on:\n")
	sb.WriteString("  1. Skill match between the task description and the member's demonstrated skills\n")
	sb.WriteString("  2. Current workload (prefer less-loaded members, especially for overdue tasks)\n")
	sb.WriteString("  3. Task role/type alignment with member role\n\n")

	sb.WriteString("## Team Members\n\n")
	for _, m := range members {
		sb.WriteString(fmt.Sprintf("- **%s**", m.Name))
		if m.Role != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", m.Role))
		}
		if len(m.Skills) > 0 {
			sb.WriteString(fmt.Sprintf(" | skills: %s", strings.Join(m.Skills, ", ")))
		}
		sb.WriteByte('\n')
	}
	sb.WriteByte('\n')

	sb.WriteString("## Tasks to Assign\n\n")
	for _, t := range tasks {
		overdue := pm.IsOverdue(t)
		sb.WriteString(fmt.Sprintf("### Task #%d: %s\n", t.ID, t.Title))
		if t.Description != "" {
			sb.WriteString(fmt.Sprintf("Description: %s\n", t.Description))
		}
		if t.Role != "" {
			sb.WriteString(fmt.Sprintf("Required role: %s\n", t.Role))
		}
		if len(t.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(t.Tags, ", ")))
		}
		if t.Priority > 0 {
			sb.WriteString(fmt.Sprintf("Priority: P%d\n", t.Priority))
		}
		if overdue {
			sb.WriteString("**OVERDUE** — assign to the least-loaded available member\n")
		}
		if t.EstimatedMinutes > 0 {
			sb.WriteString(fmt.Sprintf("Estimated: %dm\n", t.EstimatedMinutes))
		}
		sb.WriteByte('\n')
	}

	sb.WriteString("## Output\n\n")
	sb.WriteString("Respond with a JSON array. One entry per task. Do not wrap in markdown:\n")
	sb.WriteString("[\n")
	sb.WriteString("  {\"task_id\": 1, \"assignee\": \"alice\", \"reasoning\": \"Alice has backend skills matching this API task\"},\n")
	sb.WriteString("  ...\n")
	sb.WriteString("]\n")
	sb.WriteString("Use only member names from the list above. Every task must have exactly one assignee.\n")

	return sb.String()
}

// ParseAssignments extracts the JSON assignment array from raw AI output.
func ParseAssignments(raw string) ([]AssignmentResult, error) {
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array found in AI response")
	}
	jsonPart := raw[start : end+1]
	var results []AssignmentResult
	if err := json.Unmarshal([]byte(jsonPart), &results); err != nil {
		return nil, fmt.Errorf("parsing assignments: %w", err)
	}
	return results, nil
}

// ApplyAssignments writes the AI-proposed assignments back into the plan.
// Only assignments whose task_id exists in the plan are applied.
// Returns the number of tasks actually updated.
func ApplyAssignments(plan *pm.Plan, assignments []AssignmentResult) int {
	applied := 0
	for _, a := range assignments {
		t := plan.TaskByID(a.TaskID)
		if t == nil {
			continue
		}
		t.Assignee = a.Assignee
		applied++
	}
	return applied
}

// SkillTagsFromHistory derives skill tags for a team member by analysing
// the titles, descriptions, roles, and tags of their completed tasks.
// Returns deduplicated lowercase skill tokens.
func SkillTagsFromHistory(plan *pm.Plan, memberName string) []string {
	seen := make(map[string]struct{})
	var skills []string

	add := func(token string) {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			return
		}
		if _, ok := seen[token]; !ok {
			seen[token] = struct{}{}
			skills = append(skills, token)
		}
	}

	for _, t := range plan.Tasks {
		if t.Assignee != memberName {
			continue
		}
		if t.Status != pm.TaskDone && t.Status != pm.TaskSkipped {
			continue
		}

		// Explicit tags are the strongest signal.
		for _, tag := range t.Tags {
			add(tag)
		}

		// Role maps directly to a skill.
		if t.Role != "" {
			add(string(t.Role))
		}

		// Extract meaningful keywords from the title (skip stop words).
		for _, word := range tokenise(t.Title) {
			add(word)
		}
	}
	return skills
}

// MembersWithSkills builds a []Member list from the current plan, enriching
// each known assignee with skill tags derived from their completed task history.
// If onlyMember is non-empty, only that member is included.
func MembersWithSkills(plan *pm.Plan, onlyMember string) []Member {
	// Collect unique assignees.
	seen := make(map[string]struct{})
	for _, t := range plan.Tasks {
		if t.Assignee != "" {
			seen[t.Assignee] = struct{}{}
		}
	}
	// If --member flag is set, restrict to that member (may be new to the plan).
	if onlyMember != "" {
		seen = map[string]struct{}{onlyMember: {}}
	}

	members := make([]Member, 0, len(seen))
	for name := range seen {
		members = append(members, Member{
			Name:   name,
			Skills: SkillTagsFromHistory(plan, name),
		})
	}
	return members
}

// WorkloadCount returns the number of pending/in-progress tasks assigned to
// each member. Used for least-loaded selection for overdue tasks.
func WorkloadCount(plan *pm.Plan) map[string]int {
	counts := make(map[string]int)
	for _, t := range plan.Tasks {
		if t.Assignee == "" {
			continue
		}
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			counts[t.Assignee]++
		}
	}
	return counts
}

// LeastLoadedMember returns the member from the list with the fewest active
// tasks. Ties are broken alphabetically for determinism.
func LeastLoadedMember(members []Member, counts map[string]int) string {
	if len(members) == 0 {
		return ""
	}
	best := members[0].Name
	bestCount := counts[best]
	for _, m := range members[1:] {
		c := counts[m.Name]
		if c < bestCount || (c == bestCount && m.Name < best) {
			best = m.Name
			bestCount = c
		}
	}
	return best
}

// Run calls the provider with the assignment prompt and returns the parsed results.
func Run(ctx context.Context, p provider.Provider, model string, tasks []*pm.Task, members []Member) ([]AssignmentResult, error) {
	if len(tasks) == 0 {
		return nil, nil
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("no team members available for assignment; assign at least one task manually first or use --member")
	}

	prompt := AssignPrompt(tasks, members)

	var buf strings.Builder
	opts := provider.Options{
		Model: model,
		OnToken: func(tok string) {
			buf.WriteString(tok)
		},
	}
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("provider error: %w", err)
	}
	if result != nil && result.Output != "" {
		buf.Reset()
		buf.WriteString(result.Output)
	}

	return ParseAssignments(buf.String())
}

// stop words to skip when extracting skill keywords from task titles.
var stopWords = map[string]struct{}{
	"a": {}, "an": {}, "the": {}, "and": {}, "or": {}, "of": {}, "for": {},
	"to": {}, "in": {}, "on": {}, "at": {}, "by": {}, "with": {}, "from": {},
	"add": {}, "create": {}, "implement": {}, "build": {}, "update": {},
	"fix": {}, "make": {}, "use": {}, "new": {}, "via": {}, "as": {},
	"is": {}, "be": {}, "are": {}, "was": {}, "were": {}, "has": {}, "have": {},
}

// tokenise splits a string into lowercase alphanumeric tokens, filtering stop
// words and very short tokens.
func tokenise(s string) []string {
	var tokens []string
	words := strings.Fields(s)
	for _, w := range words {
		// Strip punctuation.
		w = strings.TrimFunc(w, func(r rune) bool {
			return r < 'a' || r > 'z' && r < 'A' || r > 'Z' && (r < '0' || r > '9')
		})
		w = strings.ToLower(w)
		if len(w) < 3 {
			continue
		}
		if _, skip := stopWords[w]; skip {
			continue
		}
		tokens = append(tokens, w)
	}
	return tokens
}
