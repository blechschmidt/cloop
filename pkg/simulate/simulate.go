// Package simulate provides AI-powered "what-if" scenario analysis for cloop PM projects.
// It lets PMs ask counterfactual questions — "What if we cut scope?", "What if deadline moves
// up 2 weeks?", "What if we add an engineer?" — and get structured impact projections.
package simulate

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/insights"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TaskChange describes a recommended change to a specific task.
type TaskChange struct {
	TaskID     int    `json:"task_id"`
	TaskTitle  string `json:"task_title"`
	Action     string `json:"action"`     // "cut", "defer", "reprioritize", "add", "split"
	NewPrio    int    `json:"new_prio,omitempty"`
	Rationale  string `json:"rationale"`
}

// SimResult is the structured output of a scenario simulation.
type SimResult struct {
	Scenario       string       `json:"scenario"`
	Summary        string       `json:"summary"`
	TimelineDelta  int          `json:"timeline_delta_days"` // +days = delayed, -days = faster
	BaselineDays   float64      `json:"baseline_days"`
	SimulatedDays  float64      `json:"simulated_days"`
	RiskBefore     string       `json:"risk_before"`         // "low" | "medium" | "high" | "critical"
	RiskAfter      string       `json:"risk_after"`
	Confidence     string       `json:"confidence"`          // "low" | "medium" | "high"
	Recommendations []string    `json:"recommendations"`
	TaskChanges    []TaskChange `json:"task_changes,omitempty"`
	TradeOffs      []string     `json:"trade_offs,omitempty"`
	Warnings       []string     `json:"warnings,omitempty"`
}

// ProjectSnapshot builds a concise text summary of current project state for AI context.
func ProjectSnapshot(s *state.ProjectState) string {
	m := insights.Analyze(s)
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Project Goal: %s\n", s.Goal))
	sb.WriteString(fmt.Sprintf("Project Age: %s\n", time.Since(s.CreatedAt).Round(time.Hour)))
	sb.WriteString(fmt.Sprintf("Status: %s\n", s.Status))

	if s.Plan != nil {
		sb.WriteString(fmt.Sprintf("\nTask Summary:\n"))
		sb.WriteString(fmt.Sprintf("  Total: %d | Done: %d | In-Progress: %d | Pending: %d | Failed: %d | Skipped: %d | Blocked: %d\n",
			m.TotalTasks, m.DoneTasks, m.InProgressTasks, m.PendingTasks, m.FailedTasks, m.SkippedTasks, m.BlockedTasks))

		pct := 0.0
		if m.TotalTasks > 0 {
			pct = float64(m.DoneTasks) / float64(m.TotalTasks) * 100
		}
		sb.WriteString(fmt.Sprintf("  Completion: %.0f%%\n", pct))

		if m.VelocityPerDay > 0 {
			sb.WriteString(fmt.Sprintf("  Velocity: %.2f tasks/day\n", m.VelocityPerDay))
		}
		if m.EstimatedDaysRemaining > 0 {
			sb.WriteString(fmt.Sprintf("  Est. Days Remaining: %.1f\n", m.EstimatedDaysRemaining))
		}
		sb.WriteString(fmt.Sprintf("  Risk Score: %d/100 (%s)\n", m.RiskScore, riskLabel(m.RiskScore)))
		if len(m.RiskFactors) > 0 {
			sb.WriteString(fmt.Sprintf("  Risk Factors: %s\n", strings.Join(m.RiskFactors, "; ")))
		}

		if len(m.RoleBreakdown) > 0 {
			sb.WriteString("\nRole Breakdown:\n")
			roles := make([]string, 0, len(m.RoleBreakdown))
			for r := range m.RoleBreakdown {
				roles = append(roles, r)
			}
			sort.Strings(roles)
			for _, r := range roles {
				rb := m.RoleBreakdown[r]
				sb.WriteString(fmt.Sprintf("  %s: %d/%d done\n", r, rb[0], rb[1]))
			}
		}

		// Task list (pending + in-progress for "what can be changed")
		sb.WriteString("\nPending/Active Tasks:\n")
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
				deps := ""
				if len(t.DependsOn) > 0 {
					depStrs := make([]string, len(t.DependsOn))
					for i, d := range t.DependsOn {
						depStrs[i] = fmt.Sprintf("#%d", d)
					}
					deps = fmt.Sprintf(" [deps: %s]", strings.Join(depStrs, ","))
				}
				sb.WriteString(fmt.Sprintf("  [%d] P%d (%s) %s%s\n", t.ID, t.Priority, t.Status, t.Title, deps))
			}
		}

		// Recent failures
		hasFailures := false
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskFailed {
				if !hasFailures {
					sb.WriteString("\nFailed Tasks:\n")
					hasFailures = true
				}
				sb.WriteString(fmt.Sprintf("  [%d] %s\n", t.ID, t.Title))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nToken Usage: %d in / %d out\n", s.TotalInputTokens, s.TotalOutputTokens))
	return sb.String()
}

func riskLabel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// buildPrompt constructs the AI prompt for scenario simulation.
func buildPrompt(snapshot, scenario string) string {
	return fmt.Sprintf(`You are a senior AI product manager performing a "what-if" scenario analysis.

CURRENT PROJECT STATE:
%s

SCENARIO TO SIMULATE:
%s

Analyze the impact of this scenario on the project. Consider:
- Timeline: will it speed up or delay delivery?
- Risk: does this increase or reduce risk?
- Scope: which tasks should be cut, deferred, reprioritized, or added?
- Trade-offs: what is gained and what is lost?
- Dependencies: are there cascading effects?

Respond with a JSON object matching this exact schema (no markdown, just raw JSON):
{
  "scenario": "<one-line summary of the scenario>",
  "summary": "<2-3 sentence executive summary of the impact>",
  "timeline_delta_days": <integer, positive = delayed, negative = faster, 0 = no change>,
  "baseline_days": <float, current estimated days to completion>,
  "simulated_days": <float, new estimated days after scenario>,
  "risk_before": "<low|medium|high|critical>",
  "risk_after": "<low|medium|high|critical>",
  "confidence": "<low|medium|high>",
  "recommendations": ["<action item 1>", "<action item 2>", ...],
  "task_changes": [
    {"task_id": <id>, "task_title": "<title>", "action": "<cut|defer|reprioritize|add|split>", "new_prio": <1-10 or omit>, "rationale": "<why>"}
  ],
  "trade_offs": ["<trade-off 1>", "<trade-off 2>"],
  "warnings": ["<warning if any>"]
}`, snapshot, scenario)
}

// Run performs the AI scenario simulation.
// Returns a SimResult and the raw AI response text.
func Run(ctx context.Context, s *state.ProjectState, scenario string, prov provider.Provider, model string, onToken func(string)) (*SimResult, string, error) {
	snapshot := ProjectSnapshot(s)
	prompt := buildPrompt(snapshot, scenario)

	opts := provider.Options{Model: model, OnToken: onToken}
	res, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, "", fmt.Errorf("AI simulation failed: %w", err)
	}
	raw := res.Output

	// Extract JSON from response
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return nil, raw, fmt.Errorf("AI did not return valid JSON — raw response saved")
	}

	var result SimResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, raw, fmt.Errorf("parsing simulation JSON: %w (raw: %s)", err, jsonStr[:min(200, len(jsonStr))])
	}

	// Fill in missing derived fields
	if result.BaselineDays == 0 && s.Plan != nil {
		m := insights.Analyze(s)
		if m.EstimatedDaysRemaining > 0 {
			result.BaselineDays = m.EstimatedDaysRemaining
		}
	}
	if result.SimulatedDays == 0 && result.BaselineDays > 0 {
		result.SimulatedDays = math.Max(0, result.BaselineDays+float64(result.TimelineDelta))
	}

	return &result, raw, nil
}

// extractJSON finds the first complete {...} block in the AI response.
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	if start == -1 {
		return ""
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
