// Package epic clusters a task plan into named epics/themes using AI.
// Each epic groups semantically related tasks by business value and domain.
package epic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Epic is a named theme grouping related tasks.
type Epic struct {
	Name        string `json:"name"`
	Description string `json:"description"` // one-sentence summary
	TaskIDs     []int  `json:"task_ids"`
}

// EpicProgress augments Epic with live completion statistics.
type EpicProgress struct {
	Epic
	Total    int `json:"total"`
	Done     int `json:"done"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Pending  int `json:"pending"`
}

// aiResponse is the JSON envelope returned by the AI provider.
type aiResponse struct {
	Epics []*Epic `json:"epics"`
}

// ClusterPrompt builds the prompt sent to the AI provider.
func ClusterPrompt(plan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are an expert technical product manager. Your job is to cluster a task plan into named epics.\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("- Group the tasks below into 3-7 named epics/themes.\n")
	b.WriteString("- Base groupings on semantic similarity and business value.\n")
	b.WriteString("- Each epic must have:\n")
	b.WriteString("  - \"name\": a short, clear name (2-4 words, title-case, no punctuation)\n")
	b.WriteString("  - \"description\": exactly one sentence describing the epic's purpose and value\n")
	b.WriteString("  - \"task_ids\": array of task ID integers belonging to this epic\n")
	b.WriteString("- Every task must appear in exactly one epic.\n")
	b.WriteString("- Aim for cohesive groupings — related work should share an epic.\n")
	b.WriteString("- Return ONLY valid JSON. No markdown fences, no commentary.\n\n")

	b.WriteString("## SCHEMA\n")
	b.WriteString(`{"epics":[{"name":"Epic Name","description":"One sentence.","task_ids":[1,2,3]}]}`)
	b.WriteString("\n\n")

	b.WriteString("## PROJECT GOAL\n")
	b.WriteString(plan.Goal)
	b.WriteString("\n\n")

	b.WriteString("## TASKS\n")
	for _, t := range plan.Tasks {
		role := string(t.Role)
		if role == "" {
			role = "general"
		}
		tags := ""
		if len(t.Tags) > 0 {
			tags = " [tags:" + strings.Join(t.Tags, ",") + "]"
		}
		fmt.Fprintf(&b, "- id:%d [P%d][%s][%s]%s %s\n",
			t.ID, t.Priority, t.Status, role, tags, t.Title)
		if t.Description != "" {
			short := t.Description
			if len(short) > 100 {
				short = short[:100] + "..."
			}
			fmt.Fprintf(&b, "  %s\n", short)
		}
	}

	return b.String()
}

// ParseResponse parses the AI's JSON response into a slice of Epics.
func ParseResponse(raw string) ([]*Epic, error) {
	raw = strings.TrimSpace(raw)
	// Strip markdown code fences if present.
	raw = stripFences(raw)

	var resp aiResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("parsing epic JSON: %w\nraw output (first 400 chars): %s", err, truncate(raw, 400))
	}
	if len(resp.Epics) == 0 {
		return nil, fmt.Errorf("AI returned no epics")
	}
	return resp.Epics, nil
}

// Cluster calls the provider and returns a structured list of epics.
func Cluster(ctx context.Context, p provider.Provider, model string, plan *pm.Plan) ([]*Epic, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil, fmt.Errorf("plan has no tasks")
	}

	prompt := ClusterPrompt(plan)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model: model,
	})
	if err != nil {
		return nil, fmt.Errorf("epic clustering: %w", err)
	}

	return ParseResponse(result.Output)
}

// ApplyTags writes an "epic:<name>" tag to each task referenced by an epic.
// Existing epic: tags are removed before applying the new assignment.
func ApplyTags(plan *pm.Plan, epics []*Epic) int {
	// Build task-id → epic-name lookup.
	idToEpic := make(map[int]string)
	for _, e := range epics {
		for _, id := range e.TaskIDs {
			idToEpic[id] = e.Name
		}
	}

	changed := 0
	for _, t := range plan.Tasks {
		epicName, hasEpic := idToEpic[t.ID]

		// Strip any existing epic: tags.
		filtered := t.Tags[:0]
		hadEpic := false
		for _, tag := range t.Tags {
			if strings.HasPrefix(tag, "epic:") {
				hadEpic = true
				continue
			}
			filtered = append(filtered, tag)
		}
		t.Tags = filtered

		if hasEpic {
			t.Tags = append(t.Tags, "epic:"+epicName)
			if !hadEpic || !containsTag(filtered, "epic:"+epicName) {
				changed++
			}
		}
	}
	return changed
}

// Progress computes EpicProgress for each epic based on current task statuses.
func Progress(plan *pm.Plan, epics []*Epic) []*EpicProgress {
	// Build task-id → task lookup.
	idToTask := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		idToTask[t.ID] = t
	}

	result := make([]*EpicProgress, 0, len(epics))
	for _, e := range epics {
		ep := &EpicProgress{Epic: *e, Total: len(e.TaskIDs)}
		for _, id := range e.TaskIDs {
			t, ok := idToTask[id]
			if !ok {
				continue
			}
			switch t.Status {
			case pm.TaskDone:
				ep.Done++
			case pm.TaskFailed:
				ep.Failed++
			case pm.TaskSkipped:
				ep.Skipped++
			default:
				ep.Pending++
			}
		}
		result = append(result, ep)
	}
	return result
}

// EpicsFromTags rebuilds epics from existing "epic:<name>" tags in the plan.
// Returns nil if no tasks have epic tags.
func EpicsFromTags(plan *pm.Plan) []*Epic {
	epicTasks := map[string][]int{}
	for _, t := range plan.Tasks {
		for _, tag := range t.Tags {
			if strings.HasPrefix(tag, "epic:") {
				name := strings.TrimPrefix(tag, "epic:")
				epicTasks[name] = append(epicTasks[name], t.ID)
			}
		}
	}
	if len(epicTasks) == 0 {
		return nil
	}
	result := make([]*Epic, 0, len(epicTasks))
	for name, ids := range epicTasks {
		result = append(result, &Epic{Name: name, TaskIDs: ids})
	}
	return result
}

// ── helpers ──────────────────────────────────────────────────────────────────

func stripFences(s string) string {
	if idx := strings.Index(s, "```"); idx != -1 {
		s = s[idx:]
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		if end := strings.LastIndex(s, "```"); end > 0 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
