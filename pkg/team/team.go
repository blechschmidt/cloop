// Package team implements multi-user task assignment and workload management.
package team

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Assign sets the assignee for a task and persists the updated state.
// taskID is matched against Task.ID; user may be empty to unassign.
func Assign(workDir string, taskID int, user string) error {
	s, err := state.Load(workDir)
	if err != nil {
		return err
	}
	if !s.PMMode || s.Plan == nil {
		return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
	}
	t := s.Plan.TaskByID(taskID)
	if t == nil {
		return fmt.Errorf("task %d not found", taskID)
	}
	t.Assignee = user
	return s.Save()
}

// Workload groups tasks by assignee. Tasks with no assignee are grouped under
// the empty string key "". The returned map is never nil.
func Workload(plan *pm.Plan) map[string][]*pm.Task {
	result := make(map[string][]*pm.Task)
	for _, t := range plan.Tasks {
		result[t.Assignee] = append(result[t.Assignee], t)
	}
	return result
}

// Members returns an alphabetically sorted list of all distinct non-empty
// assignees in the plan.
func Members(plan *pm.Plan) []string {
	seen := make(map[string]struct{})
	for _, t := range plan.Tasks {
		if t.Assignee != "" {
			seen[t.Assignee] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// workloadLine returns a short human-readable summary for a task entry.
func workloadLine(t *pm.Task) string {
	est := ""
	if t.EstimatedMinutes > 0 {
		h := t.EstimatedMinutes / 60
		m := t.EstimatedMinutes % 60
		if h > 0 {
			est = fmt.Sprintf(" (~%dh%dm)", h, m)
		} else {
			est = fmt.Sprintf(" (~%dm)", m)
		}
	}
	return fmt.Sprintf("  [%s] #%d %s%s", t.Status, t.ID, t.Title, est)
}

// WorkloadSummary returns a formatted text block showing each member's task
// list with statuses and estimated hours. Unassigned tasks are listed last
// under "(unassigned)".
func WorkloadSummary(plan *pm.Plan) string {
	wl := Workload(plan)
	members := Members(plan)

	var sb strings.Builder

	for _, member := range members {
		tasks := wl[member]
		totalEst := 0
		done := 0
		for _, t := range tasks {
			totalEst += t.EstimatedMinutes
			if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
				done++
			}
		}
		h := totalEst / 60
		m := totalEst % 60
		estStr := ""
		if totalEst > 0 {
			if h > 0 {
				estStr = fmt.Sprintf(", ~%dh%dm estimated", h, m)
			} else {
				estStr = fmt.Sprintf(", ~%dm estimated", m)
			}
		}
		fmt.Fprintf(&sb, "%s — %d tasks (%d done%s)\n", member, len(tasks), done, estStr)
		for _, t := range tasks {
			sb.WriteString(workloadLine(t))
			sb.WriteByte('\n')
		}
		sb.WriteByte('\n')
	}

	// Unassigned tasks.
	if unassigned := wl[""]; len(unassigned) > 0 {
		fmt.Fprintf(&sb, "(unassigned) — %d tasks\n", len(unassigned))
		for _, t := range unassigned {
			sb.WriteString(workloadLine(t))
			sb.WriteByte('\n')
		}
	}

	return strings.TrimRight(sb.String(), "\n")
}

// BalancePrompt builds a prompt asking the AI to suggest workload rebalancing
// across the current team members.
func BalancePrompt(plan *pm.Plan) string {
	members := Members(plan)
	wl := Workload(plan)

	var sb strings.Builder
	sb.WriteString("You are an AI project manager. Below is the current task assignment for a project.\n")
	sb.WriteString("Suggest concrete reassignments to better balance the workload across team members.\n")
	sb.WriteString("Consider task status, estimated hours, and overall fairness.\n\n")

	sb.WriteString("## Goal\n")
	sb.WriteString(plan.Goal)
	sb.WriteString("\n\n")

	sb.WriteString("## Team Workload\n\n")
	for _, member := range members {
		tasks := wl[member]
		totalEst := 0
		for _, t := range tasks {
			totalEst += t.EstimatedMinutes
		}
		fmt.Fprintf(&sb, "### %s (%d tasks", member, len(tasks))
		if totalEst > 0 {
			fmt.Fprintf(&sb, ", ~%dm estimated", totalEst)
		}
		sb.WriteString(")\n")
		for _, t := range tasks {
			fmt.Fprintf(&sb, "- #%d [%s] P%d %s", t.ID, t.Status, t.Priority, t.Title)
			if t.EstimatedMinutes > 0 {
				fmt.Fprintf(&sb, " (~%dm)", t.EstimatedMinutes)
			}
			sb.WriteByte('\n')
		}
		sb.WriteByte('\n')
	}

	if unassigned := wl[""]; len(unassigned) > 0 {
		fmt.Fprintf(&sb, "### Unassigned (%d tasks)\n", len(unassigned))
		for _, t := range unassigned {
			fmt.Fprintf(&sb, "- #%d [%s] P%d %s", t.ID, t.Status, t.Priority, t.Title)
			if t.EstimatedMinutes > 0 {
				fmt.Fprintf(&sb, " (~%dm)", t.EstimatedMinutes)
			}
			sb.WriteByte('\n')
		}
		sb.WriteByte('\n')
	}

	sb.WriteString("## Output format\n")
	sb.WriteString("Respond with a JSON array of reassignment suggestions:\n")
	sb.WriteString("[\n")
	sb.WriteString("  {\"task_id\": 3, \"from\": \"alice\", \"to\": \"bob\", \"reason\": \"Bob has fewer pending tasks\"},\n")
	sb.WriteString("  ...\n")
	sb.WriteString("]\n")
	sb.WriteString("If the workload is already balanced, return an empty array [].\n")
	sb.WriteString("Only suggest reassignments for pending or in_progress tasks.\n")

	return sb.String()
}
