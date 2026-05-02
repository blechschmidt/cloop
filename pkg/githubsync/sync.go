// Package githubsync implements two-way synchronization between cloop PM tasks
// and GitHub Issues. It maintains a persistent mapping in .cloop/github-sync.json
// so that each pull or push only processes new/changed items.
package githubsync

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gh "github.com/blechschmidt/cloop/pkg/github"
	"github.com/blechschmidt/cloop/pkg/pm"
)

const mappingFile = ".cloop/github-sync.json"

// Mapping persists the task↔issue relationship across runs.
type Mapping struct {
	// TaskToIssue maps cloop task ID → GitHub issue number.
	TaskToIssue map[int]int `json:"task_to_issue"`
	// IssueToTask maps GitHub issue number → cloop task ID.
	IssueToTask map[int]int `json:"issue_to_task"`
}

// LoadMapping reads the persisted mapping file. Returns an empty mapping when the
// file does not exist yet.
func LoadMapping(workDir string) (*Mapping, error) {
	path := filepath.Join(workDir, mappingFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Mapping{
			TaskToIssue: make(map[int]int),
			IssueToTask: make(map[int]int),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", mappingFile, err)
	}
	var m Mapping
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", mappingFile, err)
	}
	if m.TaskToIssue == nil {
		m.TaskToIssue = make(map[int]int)
	}
	if m.IssueToTask == nil {
		m.IssueToTask = make(map[int]int)
	}
	// Rebuild IssueToTask from TaskToIssue as the canonical source.
	m.IssueToTask = make(map[int]int, len(m.TaskToIssue))
	for tid, inum := range m.TaskToIssue {
		m.IssueToTask[inum] = tid
	}
	return &m, nil
}

// Save writes the mapping to disk.
func (m *Mapping) Save(workDir string) error {
	path := filepath.Join(workDir, mappingFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Link records a task↔issue relationship in both maps.
func (m *Mapping) Link(taskID, issueNumber int) {
	m.TaskToIssue[taskID] = issueNumber
	m.IssueToTask[issueNumber] = taskID
}

// Unlink removes the mapping for a task ID (also removes the reverse entry).
func (m *Mapping) Unlink(taskID int) {
	if inum, ok := m.TaskToIssue[taskID]; ok {
		delete(m.IssueToTask, inum)
	}
	delete(m.TaskToIssue, taskID)
}

// PullResult contains the outcome of a Pull operation.
type PullResult struct {
	Imported int
	Updated  int
	Skipped  int
}

// Pull fetches open GitHub issues and creates PM tasks for those not yet in
// the plan. If force is true, already-linked tasks are also updated from GitHub.
// The mapping and plan are mutated in place; callers must save state and mapping.
func Pull(workDir string, client *gh.Client, plan *pm.Plan, mapping *Mapping, labelFilter []string, force bool) (*PullResult, error) {
	issues, err := client.ListIssues("open", labelFilter)
	if err != nil {
		return nil, fmt.Errorf("fetching issues: %w", err)
	}

	result := &PullResult{}

	for _, issue := range issues {
		if taskID, linked := mapping.IssueToTask[issue.Number]; linked {
			if force && plan != nil {
				// Update the existing task's metadata from GitHub.
				for _, t := range plan.Tasks {
					if t.ID == taskID {
						t.Title = issue.Title
						if issue.Body != "" {
							t.Description = buildTaskDescription(issue)
						}
						result.Updated++
						break
					}
				}
			} else {
				result.Skipped++
			}
			continue
		}

		// Also skip issues that are already linked via the Task.GitHubIssue field
		// (legacy direct link, not in the mapping yet — reconcile it).
		if plan != nil {
			reconciled := false
			for _, t := range plan.Tasks {
				if t.GitHubIssue == issue.Number {
					mapping.Link(t.ID, issue.Number)
					result.Skipped++
					reconciled = true
					break
				}
			}
			if reconciled {
				continue
			}
		}

		// New issue — create a task.
		newTask := &pm.Task{
			ID:          nextTaskID(plan),
			Title:       issue.Title,
			Description: buildTaskDescription(issue),
			Priority:    nextPriority(plan),
			Status:      pm.TaskPending,
			Role:        roleFromLabels(issue.Labels),
			GitHubIssue: issue.Number,
		}

		if plan == nil {
			// Cannot add tasks without a plan; caller must initialize one first.
			return nil, fmt.Errorf("no PM plan found — run 'cloop init --pm' first")
		}
		plan.Tasks = append(plan.Tasks, newTask)
		mapping.Link(newTask.ID, issue.Number)
		result.Imported++
	}

	return result, nil
}

// PushResult contains the outcome of a Push operation.
type PushResult struct {
	Created int
	Updated int
	Closed  int
	Skipped int
}

// Push creates or updates GitHub issues for each PM task.
// If closeDone is true, issues linked to done/skipped tasks are closed.
// The mapping is mutated in place; callers must save state and mapping.
func Push(workDir string, client *gh.Client, plan *pm.Plan, mapping *Mapping, defaultLabels []string, dryRun, closeDone, addComment bool) (*PushResult, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil, fmt.Errorf("no PM tasks found")
	}

	result := &PushResult{}

	for _, t := range plan.Tasks {
		issueNum, alreadyLinked := mapping.TaskToIssue[t.ID]
		// Also honour legacy Task.GitHubIssue field.
		if !alreadyLinked && t.GitHubIssue > 0 {
			issueNum = t.GitHubIssue
			alreadyLinked = true
			mapping.Link(t.ID, issueNum)
		}

		if !alreadyLinked {
			// Create a new issue.
			body := buildIssueBody(t, plan.Goal)
			if dryRun {
				result.Created++
				continue
			}
			labels := buildLabels(t, defaultLabels)
			issue, err := client.CreateIssue(t.Title, body, labels)
			if err != nil {
				return result, fmt.Errorf("creating issue for task #%d: %w", t.ID, err)
			}
			t.GitHubIssue = issue.Number
			mapping.Link(t.ID, issue.Number)
			result.Created++
			continue
		}

		// Issue is already linked.
		if closeDone && (t.Status == pm.TaskDone || t.Status == pm.TaskSkipped) {
			issue, err := client.GetIssue(issueNum)
			if err != nil {
				return result, fmt.Errorf("fetching issue #%d: %w", issueNum, err)
			}
			if issue.State == "closed" {
				result.Skipped++
				continue
			}
			if dryRun {
				result.Closed++
				continue
			}
			if addComment && t.Result != "" {
				comment := fmt.Sprintf("**Task completed by cloop**\n\n%s", truncate(t.Result, 1000))
				_ = client.AddComment(issueNum, comment)
			}
			if err := client.CloseIssue(issueNum); err != nil {
				return result, fmt.Errorf("closing issue #%d: %w", issueNum, err)
			}
			result.Closed++
			continue
		}

		// Issue exists and task is not done — update title/body to reflect current state.
		if dryRun {
			result.Updated++
			continue
		}
		updates := map[string]interface{}{
			"title": t.Title,
			"body":  buildIssueBody(t, plan.Goal),
		}
		if err := client.UpdateIssue(issueNum, updates); err != nil {
			// Non-fatal: log but continue.
			_ = err
		}
		result.Updated++
	}

	return result, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func buildTaskDescription(issue gh.Issue) string {
	var b strings.Builder
	if issue.Body != "" {
		b.WriteString(issue.Body)
		b.WriteString("\n\n")
	}
	if issue.LabelNames() != "" {
		b.WriteString("Labels: " + issue.LabelNames() + "\n")
	}
	b.WriteString(fmt.Sprintf("Source: %s", issue.HTMLURL))
	return b.String()
}

func buildIssueBody(t *pm.Task, goal string) string {
	var b strings.Builder
	if t.Description != "" {
		b.WriteString(t.Description)
		b.WriteString("\n\n")
	}
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("*Created by [cloop](https://github.com/blechschmidt/cloop) — task #%d*\n", t.ID))
	if goal != "" {
		b.WriteString(fmt.Sprintf("*Goal: %s*\n", truncate(goal, 120)))
	}
	if t.Role != "" {
		b.WriteString(fmt.Sprintf("*Role: %s*\n", string(t.Role)))
	}
	return b.String()
}

func buildLabels(t *pm.Task, defaults []string) []string {
	labels := make([]string, len(defaults))
	copy(labels, defaults)
	labels = append(labels, t.Tags...)
	return labels
}

func roleFromLabels(labels []gh.Label) pm.AgentRole {
	for _, l := range labels {
		switch strings.ToLower(l.Name) {
		case "backend", "api", "server":
			return pm.RoleBackend
		case "frontend", "ui", "ux":
			return pm.RoleFrontend
		case "test", "testing", "tests":
			return pm.RoleTesting
		case "security", "auth":
			return pm.RoleSecurity
		case "devops", "ci", "cd", "infra":
			return pm.RoleDevOps
		case "database", "data", "db":
			return pm.RoleData
		case "docs", "documentation":
			return pm.RoleDocs
		case "review", "refactor", "cleanup":
			return pm.RoleReview
		}
	}
	return ""
}

func nextTaskID(plan *pm.Plan) int {
	if plan == nil {
		return 1
	}
	max := 0
	for _, t := range plan.Tasks {
		if t.ID > max {
			max = t.ID
		}
	}
	return max + 1
}

func nextPriority(plan *pm.Plan) int {
	if plan == nil {
		return 1
	}
	max := 0
	for _, t := range plan.Tasks {
		if t.Priority > max {
			max = t.Priority
		}
	}
	return max + 1
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
