package cmd

import (
	"fmt"
	"math"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var statsEstimates bool

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show session statistics",
	Long: `Show aggregated statistics for the current cloop session.

Includes step timing, token usage, and task completion breakdown (in PM mode).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		if statsEstimates {
			printEstimatesTable(s)
			return nil
		}
		printStats(s)
		return nil
	},
}

func printStats(s *state.ProjectState) {
	bold := color.New(color.Bold)
	dimColor := color.New(color.Faint)
	green := color.New(color.FgGreen)

	bold.Printf("Session Statistics\n\n")

	// Basic info
	prov := s.Provider
	if prov == "" {
		prov = "claudecode"
	}
	fmt.Printf("Goal:     %s\n", s.Goal)
	fmt.Printf("Status:   %s\n", s.Status)
	fmt.Printf("Provider: %s\n", prov)
	if s.Model != "" {
		fmt.Printf("Model:    %s\n", s.Model)
	}
	fmt.Println()

	// Step stats
	bold.Printf("Steps\n")
	if len(s.Steps) == 0 {
		dimColor.Printf("  No steps recorded yet.\n\n")
	} else {
		totalDur, minDur, maxDur, durCount := computeStepDurations(s.Steps)
		fmt.Printf("  Count:   %d\n", len(s.Steps))
		if durCount > 0 {
			avgDur := totalDur / time.Duration(durCount)
			fmt.Printf("  Total:   %s\n", totalDur.Round(time.Second))
			fmt.Printf("  Avg:     %s\n", avgDur.Round(time.Millisecond))
			fmt.Printf("  Min:     %s\n", minDur.Round(time.Millisecond))
			fmt.Printf("  Max:     %s\n", maxDur.Round(time.Millisecond))
		}
		fmt.Println()
	}

	// Token stats
	bold.Printf("Tokens\n")
	if s.TotalInputTokens == 0 && s.TotalOutputTokens == 0 {
		dimColor.Printf("  No token data recorded.\n\n")
	} else {
		fmt.Printf("  Input:   %d\n", s.TotalInputTokens)
		fmt.Printf("  Output:  %d\n", s.TotalOutputTokens)
		fmt.Printf("  Total:   %d\n", s.TotalInputTokens+s.TotalOutputTokens)
		if len(s.Steps) > 0 {
			avgIn := s.TotalInputTokens / len(s.Steps)
			avgOut := s.TotalOutputTokens / len(s.Steps)
			dimColor.Printf("  Avg/step: %d in / %d out\n", avgIn, avgOut)
		}
		// Cost estimate for known providers
		if cost, ok := estimateCost(s); ok {
			green.Printf("  Est. cost: $%.4f\n", cost)
		}
		fmt.Println()
	}

	// PM mode task stats
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		bold.Printf("Tasks\n")
		counts := map[pm.TaskStatus]int{}
		for _, t := range s.Plan.Tasks {
			counts[t.Status]++
		}
		total := len(s.Plan.Tasks)
		done := counts[pm.TaskDone]
		skipped := counts[pm.TaskSkipped]
		failed := counts[pm.TaskFailed]
		pending := counts[pm.TaskPending]
		inProgress := counts[pm.TaskInProgress]

		fmt.Printf("  Total:      %d\n", total)
		if done > 0 {
			green.Printf("  Done:       %d\n", done)
		}
		if skipped > 0 {
			dimColor.Printf("  Skipped:    %d\n", skipped)
		}
		if failed > 0 {
			color.New(color.FgRed).Printf("  Failed:     %d\n", failed)
		}
		if inProgress > 0 {
			color.New(color.FgYellow).Printf("  In progress:%d\n", inProgress)
		}
		if pending > 0 {
			fmt.Printf("  Pending:    %d\n", pending)
		}
		if total > 0 {
			pct := float64(done+skipped) / float64(total) * 100
			fmt.Printf("  Complete:   %.0f%%\n", pct)
		}
		fmt.Println()
	}

	// Timeline
	bold.Printf("Timeline\n")
	fmt.Printf("  Created:  %s\n", s.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Updated:  %s\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
	elapsed := s.UpdatedAt.Sub(s.CreatedAt).Round(time.Second)
	if elapsed > 0 {
		fmt.Printf("  Elapsed:  %s\n", elapsed)
	}
}

// computeStepDurations parses step duration strings and returns aggregate stats.
// Steps with unparseable durations are excluded from timing stats.
func computeStepDurations(steps []state.StepResult) (total, min, max time.Duration, count int) {
	first := true
	for _, step := range steps {
		d, err := time.ParseDuration(step.Duration)
		if err != nil {
			continue
		}
		total += d
		count++
		if first || d < min {
			min = d
		}
		if first || d > max {
			max = d
		}
		first = false
	}
	return
}

// estimateCost returns a rough dollar cost estimate based on provider and model.
// Returns (cost, true) if we can estimate, (0, false) if unknown.
func estimateCost(s *state.ProjectState) (float64, bool) {
	// Cost per million tokens (input, output) in USD.
	// Values approximate as of 2025.
	type pricing struct{ inPer1M, outPer1M float64 }
	prices := map[string]pricing{
		"claude-opus-4-6":        {15.0, 75.0},
		"claude-sonnet-4-6":      {3.0, 15.0},
		"claude-haiku-4-5":       {0.8, 4.0},
		"claude-opus-4-5":        {15.0, 75.0},
		"claude-sonnet-3-7":      {3.0, 15.0},
		"claude-3-haiku-20240307": {0.25, 1.25},
		"gpt-4o":                  {2.5, 10.0},
		"gpt-4o-mini":             {0.15, 0.6},
		"gpt-4-turbo":             {10.0, 30.0},
	}

	model := s.Model
	if model == "" {
		return 0, false
	}
	p, ok := prices[model]
	if !ok {
		return 0, false
	}
	cost := float64(s.TotalInputTokens)/1e6*p.inPer1M +
		float64(s.TotalOutputTokens)/1e6*p.outPer1M
	return cost, true
}

// printEstimatesTable prints a table comparing AI-estimated vs actual task durations.
func printEstimatesTable(s *state.ProjectState) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	dimColor := color.New(color.Faint)

	if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
		dimColor.Println("No PM task plan found. Run cloop in PM mode first.")
		return
	}

	bold.Printf("Task Time Estimates vs Actuals\n\n")

	// Header
	fmt.Printf("%-4s  %-30s  %8s  %8s  %8s\n", "ID", "Title", "Est(min)", "Act(min)", "Variance")
	fmt.Printf("%-4s  %-30s  %8s  %8s  %8s\n", "----", "------------------------------", "--------", "--------", "--------")

	var totalEst, totalAct int
	var withBoth int
	for _, t := range s.Plan.Tasks {
		title := t.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}

		estStr := "-"
		if t.EstimatedMinutes > 0 {
			estStr = fmt.Sprintf("%d", t.EstimatedMinutes)
		}

		actStr := "-"
		if t.ActualMinutes > 0 {
			actStr = fmt.Sprintf("%d", t.ActualMinutes)
		} else if t.StartedAt != nil && t.CompletedAt != nil {
			// Compute on the fly for backward compat (tasks completed before this field was added)
			act := int(t.CompletedAt.Sub(*t.StartedAt).Minutes())
			if act > 0 {
				actStr = fmt.Sprintf("%d", act)
				t.ActualMinutes = act
			}
		}

		varStr := "-"
		if t.EstimatedMinutes > 0 && t.ActualMinutes > 0 {
			variance := float64(t.ActualMinutes-t.EstimatedMinutes) / float64(t.EstimatedMinutes) * 100
			varStr = fmt.Sprintf("%+.0f%%", variance)
			totalEst += t.EstimatedMinutes
			totalAct += t.ActualMinutes
			withBoth++

			if math.Abs(variance) <= 20 {
				green.Printf("%-4d  %-30s  %8s  %8s  %8s\n", t.ID, title, estStr, actStr, varStr)
			} else if variance > 0 {
				red.Printf("%-4d  %-30s  %8s  %8s  %8s\n", t.ID, title, estStr, actStr, varStr)
			} else {
				green.Printf("%-4d  %-30s  %8s  %8s  %8s\n", t.ID, title, estStr, actStr, varStr)
			}
		} else {
			fmt.Printf("%-4d  %-30s  %8s  %8s  %8s\n", t.ID, title, estStr, actStr, varStr)
		}
	}

	fmt.Println()
	if withBoth > 0 {
		totalVariance := float64(totalAct-totalEst) / float64(totalEst) * 100
		bold.Printf("Totals: estimated=%dm, actual=%dm, overall variance=%+.0f%% (%d tasks)\n",
			totalEst, totalAct, totalVariance, withBoth)
	} else {
		dimColor.Printf("No tasks have both estimates and actuals yet.\n")
	}
}

func init() {
	statsCmd.Flags().BoolVar(&statsEstimates, "estimates", false, "Show estimated vs actual time table for PM tasks")
	rootCmd.AddCommand(statsCmd)
}
