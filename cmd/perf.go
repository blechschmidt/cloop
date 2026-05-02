package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/promptopt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var perfCmd = &cobra.Command{
	Use:   "perf",
	Short: "Show per-role prompt A/B testing performance stats",
	Long: `Reads .cloop/prompt-variants.jsonl and prints per-role prompt variant
performance: win rates, Wilson confidence scores, average latency, and
recommendations for switching to a better-performing variant.

The Wilson score (lower confidence bound) is used for ranking — it correctly
penalises variants with few data points, preferring battle-tested performers
over lucky newcomers.

Examples:
  cloop perf
  cloop perf --role backend
  cloop perf --min-trials 5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		roleFilter, _ := cmd.Flags().GetString("role")
		minTrials, _ := cmd.Flags().GetInt("min-trials")

		headerColor := color.New(color.FgCyan, color.Bold)
		boldColor := color.New(color.Bold)
		successColor := color.New(color.FgGreen)
		failColor := color.New(color.FgRed)
		dimColor := color.New(color.Faint)
		warnColor := color.New(color.FgYellow, color.Bold)
		recColor := color.New(color.FgMagenta)

		records, err := promptopt.LoadOutcomes(workDir)
		if err != nil {
			return fmt.Errorf("loading variant outcomes: %w", err)
		}

		// Determine which roles to display.
		var rolesToShow []pm.AgentRole
		if roleFilter != "" {
			rolesToShow = []pm.AgentRole{pm.AgentRole(roleFilter)}
		} else {
			rolesToShow = promptopt.AllRoles()
		}

		if len(records) == 0 {
			fmt.Println("No prompt variant data recorded yet.")
			fmt.Println("Run 'cloop run --pm' to generate A/B testing data.")
			fmt.Println()
			fmt.Println("Registered variants (no outcomes yet):")
			for _, role := range rolesToShow {
				variants := promptopt.LoadVariants(role)
				roleLabel := string(role)
				if roleLabel == "" {
					roleLabel = "generic"
				}
				boldColor.Printf("  [%s]\n", roleLabel)
				for _, v := range variants {
					dimColor.Printf("    %-30s  %s\n", v.ID, v.Name)
				}
			}
			return nil
		}

		headerColor.Println("=== Prompt A/B Testing Performance ===")
		fmt.Println()

		totalRecords := len(records)
		totalSuccess := 0
		for _, r := range records {
			if r.Success {
				totalSuccess++
			}
		}
		boldColor.Printf("Total observations: %d  (overall win rate: %.0f%%)\n", totalRecords, pct(totalSuccess, totalRecords))
		dimColor.Printf("Stats file: .cloop/prompt-variants.jsonl\n\n")

		anyData := false

		for _, role := range rolesToShow {
			stats, err := promptopt.RoleStats(workDir, role)
			if err != nil {
				continue
			}

			// Check if any variant has data
			hasData := false
			for _, s := range stats {
				if s.Trials > 0 {
					hasData = true
					break
				}
			}

			roleLabel := string(role)
			if roleLabel == "" {
				roleLabel = "generic"
			}

			headerColor.Printf("--- Role: %s ---\n", roleLabel)

			if !hasData {
				dimColor.Println("  No observations yet for this role.")
				fmt.Println()
				continue
			}
			anyData = true

			// Find current best variant (for recommendation)
			bestVariant := promptopt.BestVariant(workDir, role)

			fmt.Printf("  %-28s  %6s  %6s  %6s  %8s  %8s  %8s  %s\n",
				"VARIANT", "TRIALS", "WIN", "FAIL", "WIN%", "WILSON", "AVG-MS", "RANK")
			fmt.Printf("  %s\n", strings.Repeat("-", 90))

			for i, s := range stats {
				if minTrials > 0 && s.Trials < minTrials {
					continue
				}
				rank := fmt.Sprintf("#%d", i+1)
				winPct := s.WinRate * 100
				wilson := s.Wilson

				variantLabel := s.Variant.Name
				isBest := s.Variant.ID == bestVariant.ID

				line := fmt.Sprintf("  %-28s  %6d  %6d  %6d  %7.0f%%  %8.4f  %7dms  %s",
					truncateStr(s.Variant.ID, 28),
					s.Trials, s.Successes, s.Failures,
					winPct, wilson, s.AvgLatency, rank)

				switch {
				case s.Trials == 0:
					dimColor.Printf("  %-28s  %6s  %6s  %6s  %8s  %8s  %8s  %s\n",
						truncateStr(s.Variant.ID, 28), "-", "-", "-", "-", "-", "-", rank)
					continue
				case isBest && i == 0:
					successColor.Print(line)
					successColor.Printf("  ← BEST (%s)\n", variantLabel)
				case winPct < 33 && s.Trials >= 3:
					failColor.Println(line)
				default:
					fmt.Println(line)
				}
			}
			fmt.Println()

			// Recommendation
			defaultID := roleLabel + "-default"
			if bestVariant.ID != defaultID {
				recColor.Printf("  RECOMMENDATION: switch from '%s' to '%s' (Wilson: %.4f)\n",
					defaultID, bestVariant.ID, wilsonForID(workDir, role, bestVariant.ID))
				recColor.Printf("  To adopt: the orchestrator will use this variant on the next heal attempt.\n")
			} else {
				// Check if any non-default variant significantly outperforms
				for _, s := range stats {
					if s.Variant.ID == defaultID || s.Trials < 3 {
						continue
					}
					if s.WinRate > 0 {
						warnColor.Printf("  NOTE: '%s' shows promise (%.0f%% win rate, %d trials) — needs more data.\n",
							s.Variant.ID, s.WinRate*100, s.Trials)
					}
				}
				successColor.Printf("  Default variant '%s' is currently ranked #1.\n", defaultID)
			}
			fmt.Println()
		}

		if !anyData && len(records) > 0 {
			dimColor.Println("No data for the selected roles. Try 'cloop perf' without --role to see all roles.")
		}

		return nil
	},
}

// wilsonForID looks up the Wilson score for a specific variant ID.
func wilsonForID(workDir string, role pm.AgentRole, variantID string) float64 {
	stats, err := promptopt.RoleStats(workDir, role)
	if err != nil {
		return 0
	}
	for _, s := range stats {
		if s.Variant.ID == variantID {
			return s.Wilson
		}
	}
	return 0
}

func init() {
	perfCmd.Flags().String("role", "", "Filter to a specific role (backend, frontend, testing, security, devops, data, docs, review)")
	perfCmd.Flags().Int("min-trials", 0, "Minimum number of trials to show a variant")
	rootCmd.AddCommand(perfCmd)
}
