// Package taskstats aggregates per-task execution analytics from all available
// cloop data sources: task state, step log tokens, artifact files, and verification
// results.
package taskstats

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Phase is a named point on the task execution timeline.
type Phase struct {
	Name string
	At   time.Time
}

// TaskStats holds collected analytics for a single task.
type TaskStats struct {
	TaskID    int
	TaskTitle string
	Status    pm.TaskStatus

	// Timing
	StartedAt   *time.Time
	CompletedAt *time.Time
	WallTime    time.Duration // CompletedAt - StartedAt when both set

	// Estimate accuracy
	EstimatedMinutes int
	ActualMinutes    int // measured (or derived from StartedAt/CompletedAt)

	// Resilience
	HealAttempts  int
	VerifyRetries int
	FailCount     int

	// Verification
	VerifyPasses int
	VerifyFails  int

	// Tokens & cost (aggregated from step log)
	InputTokens  int
	OutputTokens int
	CostUSD      float64
	HasCostData  bool

	// Mini timeline
	Phases []Phase
}

// AggregateStats summarises analytics across all tasks in a plan.
type AggregateStats struct {
	TotalTasks     int
	DoneTasks      int
	SkippedTasks   int
	FailedTasks    int
	PendingTasks   int
	InProgressTasks int

	CompletionRate float64 // (done+skipped) / total
	SuccessRate    float64 // done / (done+failed) when done+failed > 0

	TotalEstimatedMinutes int
	TotalActualMinutes    int

	TotalInputTokens  int
	TotalOutputTokens int
	TotalCostUSD      float64

	TotalHealAttempts int
	TotalVerifyPasses int
	TotalVerifyFails  int

	// Ranked sub-lists
	SlowestTasks    []*TaskStats // top 5 by actual minutes (desc)
	MostHealedTasks []*TaskStats // top 5 by HealAttempts (desc)

	All []*TaskStats
}

// Collect gathers analytics for all tasks in the plan.
// workDir is the project root (.cloop is a sub-directory of workDir).
// model is used for cost estimation and may be empty.
func Collect(s *state.ProjectState, workDir, model string) *AggregateStats {
	agg := &AggregateStats{}
	if s == nil || s.Plan == nil {
		return agg
	}

	agg.TotalTasks = len(s.Plan.Tasks)
	for _, t := range s.Plan.Tasks {
		ts := collectTask(t, s, workDir, model)
		agg.All = append(agg.All, ts)

		// Accumulate counters
		switch t.Status {
		case pm.TaskDone:
			agg.DoneTasks++
		case pm.TaskSkipped:
			agg.SkippedTasks++
		case pm.TaskFailed, pm.TaskTimedOut:
			agg.FailedTasks++
		case pm.TaskPending:
			agg.PendingTasks++
		case pm.TaskInProgress:
			agg.InProgressTasks++
		}
		agg.TotalEstimatedMinutes += ts.EstimatedMinutes
		agg.TotalActualMinutes += ts.ActualMinutes
		agg.TotalInputTokens += ts.InputTokens
		agg.TotalOutputTokens += ts.OutputTokens
		agg.TotalCostUSD += ts.CostUSD
		agg.TotalHealAttempts += ts.HealAttempts
		agg.TotalVerifyPasses += ts.VerifyPasses
		agg.TotalVerifyFails += ts.VerifyFails
	}

	if agg.TotalTasks > 0 {
		agg.CompletionRate = float64(agg.DoneTasks+agg.SkippedTasks) / float64(agg.TotalTasks) * 100
	}
	if doneAndFailed := agg.DoneTasks + agg.FailedTasks; doneAndFailed > 0 {
		agg.SuccessRate = float64(agg.DoneTasks) / float64(doneAndFailed) * 100
	}

	// Build ranked lists (copy and sort)
	sorted := make([]*TaskStats, len(agg.All))
	copy(sorted, agg.All)

	// Top 5 slowest by actual minutes
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ActualMinutes > sorted[j].ActualMinutes
	})
	n := 5
	if len(sorted) < n {
		n = len(sorted)
	}
	for i := 0; i < n; i++ {
		if sorted[i].ActualMinutes > 0 {
			agg.SlowestTasks = append(agg.SlowestTasks, sorted[i])
		}
	}

	// Top 5 most healed
	sorted2 := make([]*TaskStats, len(agg.All))
	copy(sorted2, agg.All)
	sort.Slice(sorted2, func(i, j int) bool {
		return sorted2[i].HealAttempts > sorted2[j].HealAttempts
	})
	n2 := 5
	if len(sorted2) < n2 {
		n2 = len(sorted2)
	}
	for i := 0; i < n2; i++ {
		if sorted2[i].HealAttempts > 0 {
			agg.MostHealedTasks = append(agg.MostHealedTasks, sorted2[i])
		}
	}

	return agg
}

// CollectOne gathers analytics for the single task with the given ID.
// Returns (nil, error) if not found.
func CollectOne(s *state.ProjectState, workDir, model string, taskID int) (*TaskStats, error) {
	if s == nil || s.Plan == nil {
		return nil, fmt.Errorf("no task plan found")
	}
	var task *pm.Task
	for _, t := range s.Plan.Tasks {
		if t.ID == taskID {
			task = t
			break
		}
	}
	if task == nil {
		return nil, fmt.Errorf("task %d not found", taskID)
	}
	return collectTask(task, s, workDir, model), nil
}

// collectTask builds TaskStats for a single task.
func collectTask(t *pm.Task, s *state.ProjectState, workDir, model string) *TaskStats {
	ts := &TaskStats{
		TaskID:        t.ID,
		TaskTitle:     t.Title,
		Status:        t.Status,
		StartedAt:     t.StartedAt,
		CompletedAt:   t.CompletedAt,
		HealAttempts:  t.HealAttempts,
		VerifyRetries: t.VerifyRetries,
		FailCount:     t.FailCount,
		EstimatedMinutes: t.EstimatedMinutes,
		ActualMinutes:    t.ActualMinutes,
	}

	// Derive wall time
	if t.StartedAt != nil && t.CompletedAt != nil {
		ts.WallTime = t.CompletedAt.Sub(*t.StartedAt)
	}

	// Derive actual minutes from wall time if not set
	if ts.ActualMinutes == 0 && ts.WallTime > 0 {
		ts.ActualMinutes = int(math.Round(ts.WallTime.Minutes()))
		if ts.ActualMinutes == 0 && ts.WallTime > 0 {
			ts.ActualMinutes = 1 // minimum 1 minute for very fast tasks
		}
	}

	// Build mini timeline
	ts.Phases = buildTimeline(t)

	// Aggregate tokens from step log by matching task title
	ts.InputTokens, ts.OutputTokens = aggregateTokens(s, t.Title)

	// Cost estimate
	if ts.InputTokens > 0 || ts.OutputTokens > 0 {
		if model != "" {
			usd, ok := cost.Estimate(strings.ToLower(model), ts.InputTokens, ts.OutputTokens)
			if ok {
				ts.CostUSD = usd
				ts.HasCostData = true
			}
		}
	}

	// Verification pass/fail from artifact files
	ts.VerifyPasses, ts.VerifyFails = readVerifyResults(workDir, t.ID)

	return ts
}

// buildTimeline constructs a minimal ordered timeline of named phases for a task.
func buildTimeline(t *pm.Task) []Phase {
	var phases []Phase
	if t.StartedAt != nil {
		phases = append(phases, Phase{Name: "started", At: *t.StartedAt})
	}
	if t.CompletedAt != nil {
		label := string(t.Status) // "done", "failed", "skipped", "timed_out"
		phases = append(phases, Phase{Name: label, At: *t.CompletedAt})
	}
	return phases
}

// aggregateTokens sums input/output tokens from step results whose Task field
// contains (case-insensitive) the task title.
func aggregateTokens(s *state.ProjectState, taskTitle string) (input, output int) {
	if s == nil || taskTitle == "" {
		return
	}
	lower := strings.ToLower(taskTitle)
	for _, step := range s.Steps {
		if strings.Contains(strings.ToLower(step.Task), lower) {
			input += step.InputTokens
			output += step.OutputTokens
		}
	}
	return
}

// readVerifyResults scans .cloop/tasks/ for verification artifact files
// belonging to taskID (pattern: <id>-*-verify.md) and counts PASS/FAIL verdicts.
func readVerifyResults(workDir string, taskID int) (passes, fails int) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	pattern := filepath.Join(dir, fmt.Sprintf("%d-*-verify.md", taskID))
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return
	}
	for _, path := range matches {
		verdict := readVerificationFrontmatter(path)
		switch verdict {
		case "PASS":
			passes++
		case "FAIL":
			fails++
		}
	}
	return
}

// readVerificationFrontmatter opens a verification artifact Markdown file and
// extracts the "verification:" field from its YAML frontmatter.
// Returns "PASS", "FAIL", or "" if not found.
func readVerificationFrontmatter(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inFrontmatter := false
	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++
		if lineNum == 1 {
			if line == "---" {
				inFrontmatter = true
			}
			continue
		}
		if !inFrontmatter {
			break
		}
		if line == "---" {
			break // end of frontmatter
		}
		if strings.HasPrefix(line, "verification:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "verification:"))
			return val
		}
	}
	return ""
}

// FormatDuration renders a duration in a human-readable form: "2h 3m 15s", "45m 2s", "12s".
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm %ds", h, m, sec)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, sec)
	default:
		return fmt.Sprintf("%ds", sec)
	}
}

// VariancePct returns the percentage variance of actual vs estimated minutes.
// Returns (0, false) when either is zero.
func VariancePct(estimated, actual int) (float64, bool) {
	if estimated == 0 || actual == 0 {
		return 0, false
	}
	return float64(actual-estimated) / float64(estimated) * 100, true
}
