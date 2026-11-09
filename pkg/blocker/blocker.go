// Package blocker detects blocked tasks and generates AI-powered resolution suggestions.
// A task is considered blocked if any of the following heuristics fire:
//   - It is in_progress and nothing is executing its project, so nothing will
//     advance it ("stalled"). How long it has been in progress plays no part:
//     a task a run is working on is never stalled, however long it takes.
//   - It has at least one failed dependency
//   - Any of its annotations contains the word "blocked"
package blocker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// BlockReason describes why a task was classified as blocked.
type BlockReason string

const (
	BlockReasonStalled    BlockReason = "stalled"    // in_progress, but nothing is executing it
	BlockReasonFailedDep  BlockReason = "failed_dep" // a dependency task has failed
	BlockReasonAnnotation BlockReason = "annotation" // annotation explicitly mentions "blocked"
)

// Run is what the caller knows about whether a run is executing the project a
// task belongs to. Only the caller can say: a run may be a local process, a
// container, or a workload on an edge device, and which of those can be seen
// depends on where the question is asked.
//
// It is the stalled heuristic's only input besides the task's status. That
// heuristic used to fire on a task in progress with no checkpoint or artifact
// written for thirty minutes, which is every long task: the agent's turn on a
// task is one provider call with no deadline by default (Task 20148), and it
// can work for hours without writing either (Task 20479).
type Run string

const (
	// RunUnknown: the caller cannot tell. A task is never called stalled on
	// this, however long it has been in progress.
	RunUnknown Run = ""
	// RunLive: a run is executing the project. Its task in progress is being
	// worked on, however long that takes.
	RunLive Run = "live"
	// RunGone: nothing is executing the project. A task in progress is then
	// stranded: nothing will advance it until a run starts and recovers it.
	RunGone Run = "gone"
)

// BlockerInfo holds the detection results for a single task.
type BlockerInfo struct {
	TaskID    int           `json:"task_id"`
	TaskTitle string        `json:"task_title"`
	Blocked   bool          `json:"blocked"`
	Reasons   []BlockReason `json:"reasons,omitempty"`
	// Run is what the detection was told about a run executing the project,
	// and so why a task in progress was or was not called stalled. Omitted
	// when the caller could not tell.
	Run Run `json:"run,omitempty"`
	// StalledSince is set when BlockReasonStalled is detected: the task's last
	// recorded activity — its newest checkpoint or artifact write, else when
	// it started — after which nothing advanced it.
	StalledSince *time.Time `json:"stalled_since,omitempty"`
	// FailedDeps contains the IDs of failed dependency tasks.
	FailedDeps []int `json:"failed_deps,omitempty"`
}

// BlockerReport is the full AI-generated analysis for a blocked task.
type BlockerReport struct {
	TaskID         int          `json:"task_id"`
	TaskTitle      string       `json:"task_title"`
	Detection      *BlockerInfo `json:"detection"`
	RootCause      string       `json:"root_cause"`
	Actions        []string     `json:"actions"`        // exactly 3 concrete unblocking steps
	Recommendation string       `json:"recommendation"` // "retry", "skip", or "reassign"
}

// Detect checks whether a task is blocked without calling the AI. run is what
// the caller knows about a run executing the project (see Run); workDir is
// used to date a stalled task's last activity from its checkpoint and artifact
// files.
func Detect(workDir string, task *pm.Task, plan *pm.Plan, run Run) *BlockerInfo {
	info := &BlockerInfo{
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Run:       run,
	}

	// Heuristic 1: in progress with nothing executing it. Never a matter of
	// how long the task has been in progress — see Run.
	if task.Status == pm.TaskInProgress && run == RunGone {
		info.Reasons = append(info.Reasons, BlockReasonStalled)
		if last := latestActivityTime(workDir, task); !last.IsZero() {
			info.StalledSince = &last
		} else if task.StartedAt != nil {
			since := *task.StartedAt
			info.StalledSince = &since
		}
	}

	// Heuristic 2: has failed dependencies
	if plan != nil {
		byID := make(map[int]*pm.Task, len(plan.Tasks))
		for _, t := range plan.Tasks {
			byID[t.ID] = t
		}
		for _, depID := range task.DependsOn {
			dep, ok := byID[depID]
			if ok && dep.Status == pm.TaskFailed {
				info.FailedDeps = append(info.FailedDeps, depID)
			}
		}
		if len(info.FailedDeps) > 0 {
			info.Reasons = append(info.Reasons, BlockReasonFailedDep)
		}
	}

	// Heuristic 3: annotation explicitly mentions "blocked"
	for _, a := range task.Annotations {
		if strings.Contains(strings.ToLower(a.Text), "blocked") {
			info.Reasons = append(info.Reasons, BlockReasonAnnotation)
			break
		}
	}

	info.Blocked = len(info.Reasons) > 0
	return info
}

// DetectAll scans every task in the plan and returns blocked tasks only.
func DetectAll(workDir string, plan *pm.Plan, run Run) []*BlockerInfo {
	var blocked []*BlockerInfo
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			continue
		}
		info := Detect(workDir, t, plan, run)
		if info.Blocked {
			blocked = append(blocked, info)
		}
	}
	return blocked
}

// Analyze calls the AI provider to produce a BlockerReport for the given task.
// The AI receives the task spec, detection reasons, failure/timeout history,
// and dependency statuses, then outputs root-cause + 3 unblocking actions +
// a retry/skip/reassign recommendation.
func Analyze(ctx context.Context, p provider.Provider, model string, timeout time.Duration, task *pm.Task, plan *pm.Plan, workDir string, run Run) (*BlockerReport, error) {
	info := Detect(workDir, task, plan, run)
	prompt := buildPrompt(task, plan, info, workDir)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		WorkDir: workDir,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("blocker analyze: %w", err)
	}

	report, err := parseResponse(result.Output)
	if err != nil {
		return nil, fmt.Errorf("blocker analyze: parsing response: %w", err)
	}
	report.TaskID = task.ID
	report.TaskTitle = task.Title
	report.Detection = info
	return report, nil
}

// buildPrompt constructs the AI prompt for blocker analysis.
func buildPrompt(task *pm.Task, plan *pm.Plan, info *BlockerInfo, workDir string) string {
	var b strings.Builder

	b.WriteString("You are a senior project manager and technical lead diagnosing why a software task is stuck.\n")
	b.WriteString("Analyse the information below and produce a structured blocker analysis.\n\n")

	if plan != nil {
		b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", plan.Goal))
	}

	b.WriteString("## BLOCKED TASK\n")
	b.WriteString(fmt.Sprintf("ID: #%d\n", task.ID))
	b.WriteString(fmt.Sprintf("Title: %s\n", task.Title))
	b.WriteString(fmt.Sprintf("Status: %s\n", task.Status))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("Role: %s\n", task.Role))
	}
	if task.Priority > 0 {
		b.WriteString(fmt.Sprintf("Priority: %d\n", task.Priority))
	}
	if task.FailCount > 0 {
		b.WriteString(fmt.Sprintf("Fail count: %d\n", task.FailCount))
	}
	if task.HealAttempts > 0 {
		b.WriteString(fmt.Sprintf("Auto-heal attempts: %d\n", task.HealAttempts))
	}
	if task.FailureDiagnosis != "" {
		b.WriteString(fmt.Sprintf("Previous failure diagnosis: %s\n", task.FailureDiagnosis))
	}
	if task.StartedAt != nil {
		b.WriteString(fmt.Sprintf("Started at: %s\n", task.StartedAt.Format(time.RFC3339)))
	}
	b.WriteString("\n")

	// Why it was flagged as blocked
	b.WriteString("## BLOCKER DETECTION\n")
	if task.Status == pm.TaskInProgress && info.Run == RunLive {
		// Said outright, because the framing above presumes a stuck task and
		// a model told only "in_progress since 09:00" reads the hours as the
		// problem — and recommends retrying or skipping work that is simply
		// still being done (Task 20479).
		b.WriteString("- IN PROGRESS: a run is executing this task right now. However long it has taken, " +
			"that is not by itself a sign the task is stuck.\n")
	}
	if len(info.Reasons) == 0 {
		b.WriteString("- none of the heuristics (stalled, failed dependencies, a \"blocked\" annotation) fired\n")
	}
	for _, r := range info.Reasons {
		switch r {
		case BlockReasonStalled:
			line := "- STALLED: the task is in_progress but no run is executing it, so nothing will advance it " +
				"until a run starts and recovers it"
			if info.StalledSince != nil {
				line += fmt.Sprintf(" (last activity %s ago)", time.Since(*info.StalledSince).Round(time.Minute))
			}
			b.WriteString(line + "\n")
		case BlockReasonFailedDep:
			depStrs := make([]string, len(info.FailedDeps))
			for i, d := range info.FailedDeps {
				depStrs[i] = fmt.Sprintf("#%d", d)
			}
			b.WriteString(fmt.Sprintf("- FAILED DEPS: dependency tasks %s have failed\n", strings.Join(depStrs, ", ")))
		case BlockReasonAnnotation:
			b.WriteString("- ANNOTATED BLOCKED: a user annotation explicitly flags this task as blocked\n")
		}
	}
	b.WriteString("\n")

	// Annotations
	if len(task.Annotations) > 0 {
		b.WriteString("## ANNOTATIONS\n")
		for _, a := range task.Annotations {
			b.WriteString(fmt.Sprintf("- [%s] %s: %s\n", a.Timestamp.Format("2006-01-02 15:04"), a.Author, a.Text))
		}
		b.WriteString("\n")
	}

	// Dependency statuses
	if plan != nil && len(task.DependsOn) > 0 {
		b.WriteString("## DEPENDENCY STATUS\n")
		byID := make(map[int]*pm.Task, len(plan.Tasks))
		for _, t := range plan.Tasks {
			byID[t.ID] = t
		}
		for _, depID := range task.DependsOn {
			dep, ok := byID[depID]
			if ok {
				result := ""
				if dep.Result != "" && len(dep.Result) < 200 {
					result = fmt.Sprintf(" — %s", dep.Result)
				}
				b.WriteString(fmt.Sprintf("- #%d %s [%s]%s\n", dep.ID, dep.Title, dep.Status, result))
				if dep.FailureDiagnosis != "" {
					b.WriteString(fmt.Sprintf("  failure: %s\n", truncate(dep.FailureDiagnosis, 200)))
				}
			} else {
				b.WriteString(fmt.Sprintf("- #%d (not found in plan)\n", depID))
			}
		}
		b.WriteString("\n")
	}

	// Recent checkpoint/artifact summary
	if checkpointSummary := readLatestCheckpointSummary(workDir, task.ID); checkpointSummary != "" {
		b.WriteString("## LATEST CHECKPOINT\n")
		b.WriteString(checkpointSummary)
		b.WriteString("\n\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Respond with ONLY a JSON object (no markdown fences, no extra text) in this exact schema:\n\n")
	b.WriteString(`{
  "root_cause": "<1-2 sentence hypothesis about the most likely root cause of the block>",
  "actions": [
    "<concrete step 1 to unblock — be specific, not generic>",
    "<concrete step 2 to unblock>",
    "<concrete step 3 to unblock>"
  ],
  "recommendation": "<exactly one of: retry, skip, reassign>"
}`)
	b.WriteString("\n\nRules:\n")
	b.WriteString("- actions: exactly 3 items, each actionable and specific to THIS task\n")
	b.WriteString("- recommendation must be exactly one of: retry, skip, reassign\n")
	b.WriteString("  retry = reset and re-attempt with the suggested actions applied\n")
	b.WriteString("  skip = bypass this task (document reason in annotation)\n")
	b.WriteString("  reassign = this task needs a different owner or specialist\n")
	b.WriteString("- Output valid JSON only — no markdown, no explanations outside the JSON\n")

	return b.String()
}

// readLatestCheckpointSummary returns a brief summary of the most recent checkpoint for
// the given task, or empty string if none exists.
func readLatestCheckpointSummary(workDir string, taskID int) string {
	entries, err := checkpoint.ListHistory(workDir, taskID)
	if err != nil || len(entries) == 0 {
		return ""
	}
	cp := entries[len(entries)-1].Checkpoint
	var parts []string
	parts = append(parts, fmt.Sprintf("step=%d event=%s status=%s", cp.StepNumber, cp.Event, cp.Status))
	if cp.ElapsedSec > 0 {
		parts = append(parts, fmt.Sprintf("elapsed=%.0fs", cp.ElapsedSec))
	}
	if cp.TokenCount > 0 {
		parts = append(parts, fmt.Sprintf("tokens=%d", cp.TokenCount))
	}
	if !cp.Timestamp.IsZero() {
		ago := time.Since(cp.Timestamp).Round(time.Second)
		parts = append(parts, fmt.Sprintf("recorded=%s ago", ago))
	}
	return strings.Join(parts, " ")
}

// latestActivityTime returns the most recent mtime among checkpoint history files
// and the artifact file for the given task. Returns zero time if none found.
func latestActivityTime(workDir string, task *pm.Task) time.Time {
	var latest time.Time

	// Check task artifact file
	if task.ArtifactPath != "" {
		if fi, err := os.Stat(filepath.Join(workDir, task.ArtifactPath)); err == nil {
			if fi.ModTime().After(latest) {
				latest = fi.ModTime()
			}
		}
	}

	// Check checkpoint history directory
	histDir := filepath.Join(workDir, ".cloop", "task-checkpoints", fmt.Sprintf("task-%d", task.ID))
	if entries, err := os.ReadDir(histDir); err == nil {
		for _, e := range entries {
			if fi, err2 := e.Info(); err2 == nil {
				if fi.ModTime().After(latest) {
					latest = fi.ModTime()
				}
			}
		}
	}

	// Also check the live checkpoint.json for this task
	cpFile := filepath.Join(workDir, ".cloop", "checkpoint.json")
	if data, err := os.ReadFile(cpFile); err == nil {
		var cp struct {
			TaskID    int       `json:"task_id"`
			Timestamp time.Time `json:"timestamp"`
		}
		if json.Unmarshal(data, &cp) == nil && cp.TaskID == task.ID {
			if cp.Timestamp.After(latest) {
				latest = cp.Timestamp
			}
		}
	}

	return latest
}

// parseResponse parses the AI JSON response into a BlockerReport.
func parseResponse(raw string) (*BlockerReport, error) {
	raw = strings.TrimSpace(raw)

	// Strip markdown fences
	if strings.HasPrefix(raw, "```") {
		lines := strings.Split(raw, "\n")
		if len(lines) >= 2 {
			end := len(lines) - 1
			for end > 0 && strings.TrimSpace(lines[end]) == "```" {
				end--
			}
			raw = strings.Join(lines[1:end+1], "\n")
		}
	}

	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}
	raw = raw[start : end+1]

	var payload struct {
		RootCause      string   `json:"root_cause"`
		Actions        []string `json:"actions"`
		Recommendation string   `json:"recommendation"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	if payload.RootCause == "" {
		return nil, fmt.Errorf("response missing root_cause")
	}
	if len(payload.Actions) == 0 {
		return nil, fmt.Errorf("response missing actions")
	}

	rec := strings.ToLower(strings.TrimSpace(payload.Recommendation))
	if rec != "retry" && rec != "skip" && rec != "reassign" {
		rec = "retry" // safe default
	}

	return &BlockerReport{
		RootCause:      payload.RootCause,
		Actions:        payload.Actions,
		Recommendation: rec,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
