// Package insights provides AI-powered project analytics and recommendations.
// It analyzes task completion patterns, velocity, risk, and generates actionable insights.
package insights

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Metrics holds computed project health metrics.
type Metrics struct {
	TotalTasks     int
	DoneTasks      int
	FailedTasks    int
	SkippedTasks   int
	InProgressTasks int
	PendingTasks   int
	BlockedTasks   int // permanently blocked by failed deps

	// Velocity: tasks completed per day (based on CompletedAt timestamps)
	VelocityPerDay float64

	// AvgTaskDuration is the mean duration of completed tasks.
	AvgTaskDuration time.Duration

	// EstimatedDaysRemaining is a rough forecast based on velocity.
	// -1 means not enough data.
	EstimatedDaysRemaining float64

	// RiskScore is 0-100 (0 = low risk, 100 = critical).
	RiskScore int

	// RiskFactors lists what contributed to the risk score.
	RiskFactors []string

	// RoleBreakdown maps role name to counts {done, total}.
	RoleBreakdown map[string][2]int

	// TokenCost tracks session token usage.
	InputTokens  int
	OutputTokens int
}

// Analyze computes metrics from the current project state.
func Analyze(s *state.ProjectState) *Metrics {
	m := &Metrics{
		EstimatedDaysRemaining: -1,
		RoleBreakdown:          make(map[string][2]int),
		InputTokens:            s.TotalInputTokens,
		OutputTokens:           s.TotalOutputTokens,
	}

	if s.Plan == nil {
		return m
	}

	// Count task statuses and build role breakdown.
	var completedTimes []time.Time
	var durations []time.Duration
	for _, t := range s.Plan.Tasks {
		m.TotalTasks++
		role := string(t.Role)
		if role == "" {
			role = "general"
		}
		rb := m.RoleBreakdown[role]
		rb[1]++ // total for this role

		switch t.Status {
		case pm.TaskDone:
			m.DoneTasks++
			rb[0]++ // done for this role
			if t.CompletedAt != nil {
				completedTimes = append(completedTimes, *t.CompletedAt)
			}
			if t.StartedAt != nil && t.CompletedAt != nil {
				durations = append(durations, t.CompletedAt.Sub(*t.StartedAt))
			}
		case pm.TaskFailed:
			m.FailedTasks++
		case pm.TaskSkipped:
			m.SkippedTasks++
		case pm.TaskInProgress:
			m.InProgressTasks++
		case pm.TaskPending:
			m.PendingTasks++
			if s.Plan.PermanentlyBlocked(t) {
				m.BlockedTasks++
			}
		}
		m.RoleBreakdown[role] = rb
	}

	// Velocity: tasks/day over the window of completed tasks.
	if len(completedTimes) >= 2 {
		sort.Slice(completedTimes, func(i, j int) bool { return completedTimes[i].Before(completedTimes[j]) })
		span := completedTimes[len(completedTimes)-1].Sub(completedTimes[0])
		days := span.Hours() / 24
		if days > 0 {
			m.VelocityPerDay = float64(len(completedTimes)) / days
		}
	} else if len(completedTimes) == 1 {
		// Assume 1 task/day as baseline
		m.VelocityPerDay = 1.0
	}

	// Average task duration.
	if len(durations) > 0 {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		m.AvgTaskDuration = total / time.Duration(len(durations))
	}

	// Estimated days remaining.
	remainingExecutable := m.PendingTasks - m.BlockedTasks
	if remainingExecutable > 0 && m.VelocityPerDay > 0 {
		m.EstimatedDaysRemaining = float64(remainingExecutable) / m.VelocityPerDay
	}

	// Risk score.
	m.RiskScore, m.RiskFactors = computeRisk(m, s.Plan)

	return m
}

func computeRisk(m *Metrics, plan *pm.Plan) (int, []string) {
	score := 0
	var factors []string

	if m.TotalTasks == 0 {
		return 0, nil
	}

	// Failed task ratio (up to 40 points)
	failRatio := float64(m.FailedTasks) / float64(m.TotalTasks)
	if failRatio > 0 {
		failScore := int(math.Min(40, failRatio*100))
		score += failScore
		factors = append(factors, fmt.Sprintf("%d failed task(s) (%.0f%% failure rate)", m.FailedTasks, failRatio*100))
	}

	// Blocked tasks (up to 20 points)
	if m.BlockedTasks > 0 {
		blockScore := int(math.Min(20, float64(m.BlockedTasks)*5))
		score += blockScore
		factors = append(factors, fmt.Sprintf("%d task(s) permanently blocked by failed dependencies", m.BlockedTasks))
	}

	// High in-progress count relative to total (stalled work, up to 15 points)
	if m.InProgressTasks > 2 {
		score += 15
		factors = append(factors, fmt.Sprintf("%d tasks stuck in-progress (may indicate stalled execution)", m.InProgressTasks))
	}

	// Very low velocity on large plans (up to 15 points)
	if m.TotalTasks > 5 && m.VelocityPerDay > 0 && m.VelocityPerDay < 0.5 {
		score += 15
		factors = append(factors, fmt.Sprintf("slow velocity (%.1f tasks/day)", m.VelocityPerDay))
	}

	// No progress yet on non-trivial plans (up to 10 points)
	if m.DoneTasks == 0 && m.TotalTasks > 3 {
		score += 10
		factors = append(factors, "no tasks completed yet")
	}

	// Unresolved dependency chains (up to 10 points)
	if plan != nil {
		deepChains := countDependencyDepth(plan)
		if deepChains > 3 {
			score += 10
			factors = append(factors, fmt.Sprintf("deep dependency chains (max depth: %d)", deepChains))
		}
	}

	if score > 100 {
		score = 100
	}

	return score, factors
}

// countDependencyDepth returns the maximum dependency chain depth in the plan.
func countDependencyDepth(plan *pm.Plan) int {
	idToTask := make(map[int]*pm.Task)
	for _, t := range plan.Tasks {
		idToTask[t.ID] = t
	}

	var depth func(id int, visited map[int]bool) int
	depth = func(id int, visited map[int]bool) int {
		if visited[id] {
			return 0
		}
		visited[id] = true
		t, ok := idToTask[id]
		if !ok || len(t.DependsOn) == 0 {
			return 1
		}
		max := 0
		for _, dep := range t.DependsOn {
			d := depth(dep, visited)
			if d > max {
				max = d
			}
		}
		return max + 1
	}

	maxDepth := 0
	for _, t := range plan.Tasks {
		d := depth(t.ID, make(map[int]bool))
		if d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth
}

// RiskLabel returns a human-readable risk level.
func (m *Metrics) RiskLabel() string {
	switch {
	case m.RiskScore >= 70:
		return "CRITICAL"
	case m.RiskScore >= 40:
		return "HIGH"
	case m.RiskScore >= 20:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// CompletionPct returns percentage of tasks done or skipped.
func (m *Metrics) CompletionPct() int {
	if m.TotalTasks == 0 {
		return 0
	}
	return (m.DoneTasks + m.SkippedTasks) * 100 / m.TotalTasks
}

// InsightReport is the full AI-generated analysis.
type InsightReport struct {
	Metrics     *Metrics
	AIAnalysis  string
	GeneratedAt time.Time
}

// InsightPrompt builds the prompt for AI-powered project analysis.
func InsightPrompt(goal, instructions string, plan *pm.Plan, m *Metrics) string {
	var b strings.Builder

	b.WriteString("You are an expert AI project manager performing a deep project health analysis.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}

	b.WriteString("## CURRENT METRICS\n")
	b.WriteString(fmt.Sprintf("- Total tasks: %d\n", m.TotalTasks))
	b.WriteString(fmt.Sprintf("- Completed: %d (%.0f%%)\n", m.DoneTasks, float64(m.DoneTasks)*100/math.Max(1, float64(m.TotalTasks))))
	b.WriteString(fmt.Sprintf("- Failed: %d\n", m.FailedTasks))
	b.WriteString(fmt.Sprintf("- Skipped: %d\n", m.SkippedTasks))
	b.WriteString(fmt.Sprintf("- Pending: %d (%d blocked)\n", m.PendingTasks, m.BlockedTasks))
	if m.VelocityPerDay > 0 {
		b.WriteString(fmt.Sprintf("- Velocity: %.1f tasks/day\n", m.VelocityPerDay))
	}
	if m.EstimatedDaysRemaining >= 0 {
		b.WriteString(fmt.Sprintf("- Estimated days remaining: %.1f\n", m.EstimatedDaysRemaining))
	}
	b.WriteString(fmt.Sprintf("- Risk score: %d/100 (%s)\n", m.RiskScore, m.RiskLabel()))
	if len(m.RiskFactors) > 0 {
		b.WriteString("- Risk factors:\n")
		for _, f := range m.RiskFactors {
			b.WriteString(fmt.Sprintf("  • %s\n", f))
		}
	}

	if plan != nil && len(plan.Tasks) > 0 {
		b.WriteString("\n## TASK DETAILS\n")
		for _, t := range plan.Tasks {
			status := string(t.Status)
			roleStr := ""
			if t.Role != "" {
				roleStr = fmt.Sprintf(" [%s]", t.Role)
			}
			depsStr := ""
			if len(t.DependsOn) > 0 {
				depsStr = fmt.Sprintf(" (deps: %v)", t.DependsOn)
			}
			b.WriteString(fmt.Sprintf("- Task %d [%s]%s%s: %s\n", t.ID, status, roleStr, depsStr, t.Title))
			if t.Result != "" && (t.Status == pm.TaskFailed || t.Status == pm.TaskDone) {
				summary := t.Result
				if len(summary) > 100 {
					summary = summary[:100] + "..."
				}
				b.WriteString(fmt.Sprintf("  Result: %s\n", strings.ReplaceAll(summary, "\n", " ")))
			}
		}
	}

	b.WriteString("\n## ANALYSIS REQUEST\n")
	b.WriteString("Provide a concise, actionable project health report with these sections:\n\n")
	b.WriteString("**1. Executive Summary** (2-3 sentences on overall project health)\n\n")
	b.WriteString("**2. Key Risks** (top 3 risks with specific mitigations)\n\n")
	b.WriteString("**3. Bottlenecks** (what is slowing progress and why)\n\n")
	b.WriteString("**4. Recommendations** (3-5 concrete next actions, ordered by impact)\n\n")
	b.WriteString("**5. Completion Forecast** (honest assessment of when this might finish)\n\n")
	b.WriteString("Be direct and specific. Skip generic advice. Focus on THIS project's actual situation.\n")

	return b.String()
}

// Generate calls the AI provider to produce a full insight report.
func Generate(ctx context.Context, p provider.Provider, s *state.ProjectState, model string, timeout time.Duration) (*InsightReport, error) {
	m := Analyze(s)

	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		return &InsightReport{
			Metrics:     m,
			AIAnalysis:  "No task plan found. Run `cloop run --pm --plan-only` to generate a plan first.",
			GeneratedAt: time.Now(),
		}, nil
	}

	prompt := InsightPrompt(s.Goal, s.Instructions, s.Plan, m)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("insights: %w", err)
	}

	return &InsightReport{
		Metrics:     m,
		AIAnalysis:  result.Output,
		GeneratedAt: time.Now(),
	}, nil
}
