// Package ctxedit builds, annotates, persists, and loads context overrides for PM tasks.
// It gives power users surgical control over what context is sent to the AI before a task runs.
package ctxedit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// OverrideDir is the subdirectory under workDir where override files are stored.
const OverrideDir = ".cloop"

// overrideName returns the filename for a task context override.
func overrideName(taskID int) string {
	return fmt.Sprintf("context_override_%d.txt", taskID)
}

// OverridePath returns the absolute path for the context override file of a given task.
func OverridePath(workDir string, taskID int) string {
	return filepath.Join(workDir, OverrideDir, overrideName(taskID))
}

// Build constructs the exact prompt string the orchestrator would send for task,
// mirroring the logic in pkg/pm.ExecuteTaskPrompt.
// workDir is used to load adaptive prompt hints; pass "" to skip.
// pruneTokenBudget mirrors the orchestrator's context-pruning budget (0 = no pruning).
func Build(plan *pm.Plan, task *pm.Task, workDir string, injectCtx bool, pruneTokenBudget int) string {
	var promptPlan *pm.Plan
	if pruneTokenBudget > 0 && plan != nil {
		promptPlan = prunePlan(plan, pruneTokenBudget)
	} else {
		promptPlan = plan
	}

	var projCtx *pm.ProjectContext
	if injectCtx && workDir != "" {
		projCtx = pm.BuildProjectContext(workDir)
	}

	return pm.ExecuteTaskPrompt(plan.Goal, "", workDir, promptPlan, task, false, projCtx)
}

// prunePlan returns a shallow copy of plan where each task's Result is pruned so
// the total tokens stay within budget. This matches what prunePlanForPrompt does
// in the orchestrator.
func prunePlan(plan *pm.Plan, budgetTokens int) *pm.Plan {
	results := make([]string, len(plan.Tasks))
	for i, t := range plan.Tasks {
		results[i] = t.Result
	}
	pruned := pm.PruneToTokenBudget(results, budgetTokens)

	// Build a shallow copy with pruned results.
	tasks := make([]*pm.Task, len(plan.Tasks))
	for i, t := range plan.Tasks {
		cp := *t
		cp.Result = pruned[i]
		tasks[i] = &cp
	}
	return &pm.Plan{Goal: plan.Goal, Tasks: tasks, Version: plan.Version}
}

// Section represents a named section of the prompt with its content.
type Section struct {
	Header  string // e.g. "## PROJECT GOAL"
	Content string // text under the header (excluding next header)
	Tokens  int    // estimated token count for this section
}

// Annotate splits prompt into sections by "## " headers and annotates each
// with an estimated token count. Returns the annotated string and section metadata.
func Annotate(prompt string) (annotated string, sections []Section) {
	lines := strings.Split(prompt, "\n")
	type chunk struct {
		header string
		lines  []string
	}
	var chunks []chunk
	cur := chunk{header: "(preamble)"}

	for _, line := range lines {
		if strings.HasPrefix(line, "## ") {
			chunks = append(chunks, cur)
			cur = chunk{header: line}
		} else {
			cur.lines = append(cur.lines, line)
		}
	}
	chunks = append(chunks, cur)

	var sb strings.Builder
	for _, ch := range chunks {
		body := strings.Join(ch.lines, "\n")
		toks := pm.EstimateTokens(ch.header + "\n" + body)
		sec := Section{
			Header:  ch.header,
			Content: body,
			Tokens:  toks,
		}
		sections = append(sections, sec)

		if ch.header != "(preamble)" {
			sb.WriteString(fmt.Sprintf("<!-- section: %q | ~%d tokens -->\n", ch.header, toks))
			sb.WriteString(ch.header)
			sb.WriteString("\n")
		} else if strings.TrimSpace(body) != "" {
			sb.WriteString(fmt.Sprintf("<!-- section: preamble | ~%d tokens -->\n", toks))
		}
		sb.WriteString(body)
	}

	total := pm.EstimateTokens(prompt)
	summary := fmt.Sprintf("\n<!-- TOTAL: ~%d tokens across %d sections -->\n", total, len(chunks))
	return sb.String() + summary, sections
}

// LoadOverride reads the context override file for taskID from workDir.
// Returns ("", nil) if no override exists.
func LoadOverride(workDir string, taskID int) (string, error) {
	path := OverridePath(workDir, taskID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading context override for task %d: %w", taskID, err)
	}
	return string(data), nil
}

// SaveOverride writes content as the context override for taskID.
func SaveOverride(workDir string, taskID int, content string) error {
	path := OverridePath(workDir, taskID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// ClearOverride removes the context override for taskID.
// Returns nil if the file does not exist.
func ClearOverride(workDir string, taskID int) error {
	path := OverridePath(workDir, taskID)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ClearAllOverrides removes all context_override_*.txt files in workDir/.cloop/.
func ClearAllOverrides(workDir string) (int, error) {
	dir := filepath.Join(workDir, OverrideDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "context_override_") && strings.HasSuffix(e.Name(), ".txt") {
			if rmErr := os.Remove(filepath.Join(dir, e.Name())); rmErr == nil {
				count++
			}
		}
	}
	return count, nil
}
