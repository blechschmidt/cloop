package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskstats"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var taskStatsJSON bool

var taskStatsCmd = &cobra.Command{
	Use:   "stats [task-id]",
	Short: "Show per-task execution analytics",
	Long: `Show execution analytics aggregated from state, artifact store, and
verification results.

Without a task ID:  display aggregate statistics across all tasks (completion
rate, slowest tasks, most-healed tasks, total cost, success rate).

With a task ID:  display detailed analytics for that task — wall time,
estimated vs actual duration, token/cost breakdown, retry/heal counts,
verification pass/fail ratio, and a mini execution timeline.

Examples:
  cloop task stats
  cloop task stats 3
  cloop task stats 3 --json
  cloop task stats --json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		model := s.Model

		if len(args) == 1 {
			// Single-task detailed view
			taskID, parseErr := strconv.Atoi(args[0])
			if parseErr != nil {
				return fmt.Errorf("invalid task ID %q: must be a number", args[0])
			}
			ts, collectErr := taskstats.CollectOne(s, workdir, model, taskID)
			if collectErr != nil {
				return collectErr
			}
			if taskStatsJSON {
				return printTaskStatsJSON(ts)
			}
			printSingleTaskStats(ts, s)
			return nil
		}

		// Aggregate view
		agg := taskstats.Collect(s, workdir, model)
		if taskStatsJSON {
			return printAggregateStatsJSON(agg, s)
		}
		printAggregateStats(agg, s)
		return nil
	},
}

// ──────────────────────────────────────────────
// Single-task output
// ──────────────────────────────────────────────

func printSingleTaskStats(ts *taskstats.TaskStats, s *state.ProjectState) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)

	sep := strings.Repeat("─", 64)
	bold.Printf("Task #%d Analytics: %s\n", ts.TaskID, ts.TaskTitle)
	fmt.Println(sep)

	// Status
	statusColor := statusColorFunc(ts.Status)
	fmt.Printf("  Status:      ")
	statusColor.Printf("%s\n", ts.Status)

	// Wall time
	fmt.Printf("  Wall time:   %s\n", taskstats.FormatDuration(ts.WallTime))

	// Estimated vs actual
	estStr := "-"
	actStr := "-"
	varStr := "-"
	if ts.EstimatedMinutes > 0 {
		estStr = fmt.Sprintf("%dm", ts.EstimatedMinutes)
	}
	if ts.ActualMinutes > 0 {
		actStr = fmt.Sprintf("%dm", ts.ActualMinutes)
	}
	if v, ok := taskstats.VariancePct(ts.EstimatedMinutes, ts.ActualMinutes); ok {
		varStr = fmt.Sprintf("%+.0f%%", v)
	}
	fmt.Printf("  Estimated:   %s\n", estStr)
	fmt.Printf("  Actual:      %s", actStr)
	if varStr != "-" {
		if v, ok := taskstats.VariancePct(ts.EstimatedMinutes, ts.ActualMinutes); ok {
			if v > 20 {
				red.Printf("  (%s)\n", varStr)
			} else if v < -20 {
				green.Printf("  (%s)\n", varStr)
			} else {
				green.Printf("  (%s)\n", varStr)
			}
		} else {
			fmt.Println()
		}
	} else {
		fmt.Println()
	}

	fmt.Println()

	// Tokens & cost
	bold.Printf("  Tokens & Cost\n")
	if ts.InputTokens == 0 && ts.OutputTokens == 0 {
		dim.Printf("    No per-task token data recorded.\n")
		dim.Printf("    (Token tracking requires Anthropic or OpenAI providers with streaming enabled.)\n")
	} else {
		fmt.Printf("    Input:    %d\n", ts.InputTokens)
		fmt.Printf("    Output:   %d\n", ts.OutputTokens)
		fmt.Printf("    Total:    %d\n", ts.InputTokens+ts.OutputTokens)
		if ts.HasCostData {
			green.Printf("    Est. cost: %s\n", cost.FormatCost(ts.CostUSD))
		} else if s.Model != "" {
			dim.Printf("    Cost:     n/a (unrecognized model)\n")
		}
	}

	fmt.Println()

	// Retries & heals
	bold.Printf("  Retries & Heals\n")
	healColor := dim
	if ts.HealAttempts > 0 {
		healColor = yellow
	}
	healColor.Printf("    Heal attempts:  %d\n", ts.HealAttempts)

	retryColor := dim
	if ts.VerifyRetries > 0 {
		retryColor = yellow
	}
	retryColor.Printf("    Verify retries: %d\n", ts.VerifyRetries)

	failColor := dim
	if ts.FailCount > 0 {
		failColor = red
	}
	failColor.Printf("    Fail count:     %d\n", ts.FailCount)

	fmt.Println()

	// Verification pass/fail ratio
	bold.Printf("  Verification\n")
	total := ts.VerifyPasses + ts.VerifyFails
	if total == 0 {
		dim.Printf("    No verification results found.\n")
	} else {
		green.Printf("    Pass: %d\n", ts.VerifyPasses)
		if ts.VerifyFails > 0 {
			red.Printf("    Fail: %d\n", ts.VerifyFails)
		} else {
			dim.Printf("    Fail: %d\n", ts.VerifyFails)
		}
		ratio := float64(ts.VerifyPasses) / float64(total) * 100
		fmt.Printf("    Rate: %.0f%% pass (%d of %d)\n", ratio, ts.VerifyPasses, total)
	}

	fmt.Println()

	// Mini timeline
	bold.Printf("  Timeline\n")
	if len(ts.Phases) == 0 {
		dim.Printf("    No timing data available.\n")
	} else {
		for i, p := range ts.Phases {
			ts := p.At.Format("2006-01-02 15:04:05")
			label := fmt.Sprintf("%-10s", p.Name)
			if i == 0 {
				cyan.Printf("    %s  %s\n", ts, label)
			} else {
				statusColorFunc(pm.TaskStatus(p.Name)).Printf("    %s  %s\n", ts, label)
			}
		}
	}

	fmt.Println(sep)
}

// ──────────────────────────────────────────────
// Aggregate output
// ──────────────────────────────────────────────

func printAggregateStats(agg *taskstats.AggregateStats, s *state.ProjectState) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)

	sep := strings.Repeat("─", 64)
	bold.Printf("Task Analytics — All Tasks\n")
	fmt.Println(sep)

	// Overview table
	bold.Printf("  Overview\n")
	fmt.Printf("    Total tasks:   %d\n", agg.TotalTasks)
	green.Printf("    Done:          %d\n", agg.DoneTasks)
	dim.Printf("    Skipped:       %d\n", agg.SkippedTasks)
	if agg.FailedTasks > 0 {
		red.Printf("    Failed:        %d\n", agg.FailedTasks)
	} else {
		dim.Printf("    Failed:        %d\n", agg.FailedTasks)
	}
	if agg.InProgressTasks > 0 {
		yellow.Printf("    In progress:   %d\n", agg.InProgressTasks)
	}
	dim.Printf("    Pending:       %d\n", agg.PendingTasks)
	// Pinned count
	pinnedCount := pm.PinnedCount(s.Plan.Tasks)
	if pinnedCount > 0 {
		cyan.Printf("    Pinned:        %d\n", pinnedCount)
	} else {
		dim.Printf("    Pinned:        0\n")
	}
	fmt.Println()

	// Rates
	bold.Printf("  Rates\n")
	crColor := dim
	if agg.CompletionRate >= 80 {
		crColor = green
	} else if agg.CompletionRate >= 50 {
		crColor = yellow
	} else if agg.TotalTasks > 0 {
		crColor = red
	}
	crColor.Printf("    Completion rate: %.1f%%\n", agg.CompletionRate)

	if agg.DoneTasks+agg.FailedTasks > 0 {
		srColor := dim
		if agg.SuccessRate >= 90 {
			srColor = green
		} else if agg.SuccessRate >= 70 {
			srColor = yellow
		} else {
			srColor = red
		}
		srColor.Printf("    Success rate:    %.1f%% (%d done / %d done+failed)\n",
			agg.SuccessRate, agg.DoneTasks, agg.DoneTasks+agg.FailedTasks)
	}
	fmt.Println()

	// Time
	bold.Printf("  Time\n")
	if agg.TotalActualMinutes > 0 {
		fmt.Printf("    Total actual:    %s\n", formatMinutes(agg.TotalActualMinutes))
	} else {
		dim.Printf("    Total actual:    -\n")
	}
	if agg.TotalEstimatedMinutes > 0 {
		fmt.Printf("    Total estimated: %s\n", formatMinutes(agg.TotalEstimatedMinutes))
		if agg.TotalActualMinutes > 0 {
			v, _ := taskstats.VariancePct(agg.TotalEstimatedMinutes, agg.TotalActualMinutes)
			vColor := green
			if v > 20 {
				vColor = red
			}
			vColor.Printf("    Overall variance: %+.0f%%\n", v)
		}
	} else {
		dim.Printf("    Total estimated: -\n")
	}
	fmt.Println()

	// Tokens & cost
	bold.Printf("  Tokens & Cost\n")
	if agg.TotalInputTokens == 0 && agg.TotalOutputTokens == 0 {
		// Fall back to session-wide totals from state
		if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
			fmt.Printf("    Input:  %d (session total)\n", s.TotalInputTokens)
			fmt.Printf("    Output: %d (session total)\n", s.TotalOutputTokens)
			dim.Printf("    (Per-task breakdown unavailable — shown as session total)\n")
		} else {
			dim.Printf("    No token data recorded.\n")
		}
	} else {
		fmt.Printf("    Input:  %d\n", agg.TotalInputTokens)
		fmt.Printf("    Output: %d\n", agg.TotalOutputTokens)
		fmt.Printf("    Total:  %d\n", agg.TotalInputTokens+agg.TotalOutputTokens)
	}
	if agg.TotalCostUSD > 0 {
		green.Printf("    Est. cost: %s\n", cost.FormatCost(agg.TotalCostUSD))
	} else {
		dim.Printf("    Est. cost: n/a\n")
	}
	fmt.Println()

	// Heal summary
	bold.Printf("  Heals & Retries\n")
	if agg.TotalHealAttempts > 0 {
		yellow.Printf("    Total heal attempts:  %d\n", agg.TotalHealAttempts)
	} else {
		dim.Printf("    Total heal attempts:  0\n")
	}
	vp := agg.TotalVerifyPasses
	vf := agg.TotalVerifyFails
	if vp+vf > 0 {
		ratio := float64(vp) / float64(vp+vf) * 100
		fmt.Printf("    Verify pass/fail:     %d/%d (%.0f%% pass)\n", vp, vf, ratio)
	} else {
		dim.Printf("    Verify pass/fail:     no data\n")
	}
	fmt.Println()

	// Slowest tasks
	if len(agg.SlowestTasks) > 0 {
		bold.Printf("  Slowest Tasks\n")
		fmt.Printf("    %-4s  %-35s  %8s\n", "ID", "Title", "Actual")
		fmt.Printf("    %-4s  %-35s  %8s\n", "----", strings.Repeat("-", 35), "--------")
		for _, ts := range agg.SlowestTasks {
			title := ts.TaskTitle
			if len(title) > 35 {
				title = title[:32] + "..."
			}
			cyan.Printf("    %-4d  %-35s  %8s\n", ts.TaskID, title, formatMinutes(ts.ActualMinutes))
		}
		fmt.Println()
	}

	// Most healed tasks
	if len(agg.MostHealedTasks) > 0 {
		bold.Printf("  Most-Healed Tasks\n")
		fmt.Printf("    %-4s  %-35s  %8s  %8s\n", "ID", "Title", "Heals", "Status")
		fmt.Printf("    %-4s  %-35s  %8s  %8s\n", "----", strings.Repeat("-", 35), "--------", "--------")
		for _, ts := range agg.MostHealedTasks {
			title := ts.TaskTitle
			if len(title) > 35 {
				title = title[:32] + "..."
			}
			healColor := yellow
			if ts.HealAttempts >= 3 {
				healColor = red
			}
			healColor.Printf("    %-4d  %-35s  %8d  %8s\n", ts.TaskID, title, ts.HealAttempts, ts.Status)
		}
		fmt.Println()
	}

	fmt.Println(sep)
	dim.Printf("  Use 'cloop task stats <id>' for per-task detail.\n")
}

// ──────────────────────────────────────────────
// JSON output
// ──────────────────────────────────────────────

func printTaskStatsJSON(ts *taskstats.TaskStats) error {
	type phaseJSON struct {
		Name string `json:"name"`
		At   string `json:"at"`
	}
	type out struct {
		TaskID           int         `json:"task_id"`
		TaskTitle        string      `json:"task_title"`
		Status           string      `json:"status"`
		WallTimeSec      float64     `json:"wall_time_sec,omitempty"`
		EstimatedMinutes int         `json:"estimated_minutes,omitempty"`
		ActualMinutes    int         `json:"actual_minutes,omitempty"`
		VariancePct      *float64    `json:"variance_pct,omitempty"`
		HealAttempts     int         `json:"heal_attempts"`
		VerifyRetries    int         `json:"verify_retries"`
		FailCount        int         `json:"fail_count"`
		VerifyPasses     int         `json:"verify_passes"`
		VerifyFails      int         `json:"verify_fails"`
		InputTokens      int         `json:"input_tokens,omitempty"`
		OutputTokens     int         `json:"output_tokens,omitempty"`
		CostUSD          float64     `json:"cost_usd,omitempty"`
		Phases           []phaseJSON `json:"phases,omitempty"`
	}
	o := out{
		TaskID:           ts.TaskID,
		TaskTitle:        ts.TaskTitle,
		Status:           string(ts.Status),
		EstimatedMinutes: ts.EstimatedMinutes,
		ActualMinutes:    ts.ActualMinutes,
		HealAttempts:     ts.HealAttempts,
		VerifyRetries:    ts.VerifyRetries,
		FailCount:        ts.FailCount,
		VerifyPasses:     ts.VerifyPasses,
		VerifyFails:      ts.VerifyFails,
		InputTokens:      ts.InputTokens,
		OutputTokens:     ts.OutputTokens,
		CostUSD:          ts.CostUSD,
	}
	if ts.WallTime > 0 {
		o.WallTimeSec = ts.WallTime.Seconds()
	}
	if v, ok := taskstats.VariancePct(ts.EstimatedMinutes, ts.ActualMinutes); ok {
		o.VariancePct = &v
	}
	for _, p := range ts.Phases {
		o.Phases = append(o.Phases, phaseJSON{Name: p.Name, At: p.At.Format("2006-01-02T15:04:05Z")})
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func printAggregateStatsJSON(agg *taskstats.AggregateStats, s *state.ProjectState) error {
	type taskSummary struct {
		TaskID        int     `json:"task_id"`
		TaskTitle     string  `json:"task_title"`
		Status        string  `json:"status"`
		ActualMinutes int     `json:"actual_minutes,omitempty"`
		HealAttempts  int     `json:"heal_attempts"`
		CostUSD       float64 `json:"cost_usd,omitempty"`
	}
	type out struct {
		TotalTasks            int           `json:"total_tasks"`
		DoneTasks             int           `json:"done_tasks"`
		SkippedTasks          int           `json:"skipped_tasks"`
		FailedTasks           int           `json:"failed_tasks"`
		PendingTasks          int           `json:"pending_tasks"`
		InProgressTasks       int           `json:"in_progress_tasks"`
		PinnedTasks           int           `json:"pinned_tasks"`
		CompletionRatePct     float64       `json:"completion_rate_pct"`
		SuccessRatePct        float64       `json:"success_rate_pct,omitempty"`
		TotalEstimatedMinutes int           `json:"total_estimated_minutes,omitempty"`
		TotalActualMinutes    int           `json:"total_actual_minutes,omitempty"`
		TotalInputTokens      int           `json:"total_input_tokens,omitempty"`
		TotalOutputTokens     int           `json:"total_output_tokens,omitempty"`
		TotalCostUSD          float64       `json:"total_cost_usd,omitempty"`
		TotalHealAttempts     int           `json:"total_heal_attempts"`
		TotalVerifyPasses     int           `json:"total_verify_passes"`
		TotalVerifyFails      int           `json:"total_verify_fails"`
		SlowestTasks          []taskSummary `json:"slowest_tasks,omitempty"`
		MostHealedTasks       []taskSummary `json:"most_healed_tasks,omitempty"`
	}
	o := out{
		TotalTasks:            agg.TotalTasks,
		DoneTasks:             agg.DoneTasks,
		SkippedTasks:          agg.SkippedTasks,
		FailedTasks:           agg.FailedTasks,
		PendingTasks:          agg.PendingTasks,
		InProgressTasks:       agg.InProgressTasks,
		PinnedTasks:           pm.PinnedCount(s.Plan.Tasks),
		CompletionRatePct:     agg.CompletionRate,
		SuccessRatePct:        agg.SuccessRate,
		TotalEstimatedMinutes: agg.TotalEstimatedMinutes,
		TotalActualMinutes:    agg.TotalActualMinutes,
		TotalInputTokens:      agg.TotalInputTokens,
		TotalOutputTokens:     agg.TotalOutputTokens,
		TotalCostUSD:          agg.TotalCostUSD,
		TotalHealAttempts:     agg.TotalHealAttempts,
		TotalVerifyPasses:     agg.TotalVerifyPasses,
		TotalVerifyFails:      agg.TotalVerifyFails,
	}
	// Use session totals when per-task tokens are unavailable
	if o.TotalInputTokens == 0 && o.TotalOutputTokens == 0 {
		o.TotalInputTokens = s.TotalInputTokens
		o.TotalOutputTokens = s.TotalOutputTokens
	}
	for _, ts := range agg.SlowestTasks {
		o.SlowestTasks = append(o.SlowestTasks, taskSummary{
			TaskID:        ts.TaskID,
			TaskTitle:     ts.TaskTitle,
			Status:        string(ts.Status),
			ActualMinutes: ts.ActualMinutes,
			HealAttempts:  ts.HealAttempts,
			CostUSD:       ts.CostUSD,
		})
	}
	for _, ts := range agg.MostHealedTasks {
		o.MostHealedTasks = append(o.MostHealedTasks, taskSummary{
			TaskID:        ts.TaskID,
			TaskTitle:     ts.TaskTitle,
			Status:        string(ts.Status),
			ActualMinutes: ts.ActualMinutes,
			HealAttempts:  ts.HealAttempts,
			CostUSD:       ts.CostUSD,
		})
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

// formatMinutes renders minutes as "2h 3m" or "45m" or "< 1m".
func formatMinutes(m int) string {
	if m <= 0 {
		return "-"
	}
	if m < 60 {
		return fmt.Sprintf("%dm", m)
	}
	h := m / 60
	rem := m % 60
	if rem == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh %dm", h, rem)
}

// statusColorFunc returns a color for a task status string.
func statusColorFunc(status pm.TaskStatus) *color.Color {
	switch status {
	case pm.TaskDone:
		return color.New(color.FgGreen)
	case pm.TaskFailed, pm.TaskTimedOut:
		return color.New(color.FgRed)
	case pm.TaskSkipped:
		return color.New(color.Faint)
	case pm.TaskInProgress:
		return color.New(color.FgYellow)
	default:
		return color.New(color.Reset)
	}
}

func init() {
	taskStatsCmd.Flags().BoolVar(&taskStatsJSON, "json", false, "Output as JSON")
	taskCmd.AddCommand(taskStatsCmd)
}
