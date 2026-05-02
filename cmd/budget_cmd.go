package cmd

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/budget"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ── top-level "budget" command ────────────────────────────────────────────────

var budgetCmd = &cobra.Command{
	Use:   "budget",
	Short: "Daily token and cost budget enforcement",
	Long: `Manage and monitor daily spend and token budgets.

  cloop budget status             # show today's usage vs daily limit
  cloop budget set --daily-usd 5  # cap daily spend to $5.00
  cloop budget set --daily-tokens 500000  # cap daily token usage`,
}

// ── budget status ─────────────────────────────────────────────────────────────

var budgetStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show today's token and cost usage vs daily budget",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		stats, err := budget.DailyUsage(workdir)
		if err != nil {
			return fmt.Errorf("reading usage: %w", err)
		}

		bold := color.New(color.Bold)
		bold.Printf("\ncloop budget status — today (UTC)\n\n")

		// USD section
		if cfg.Budget.DailyUSDLimit > 0 {
			printDailyUSDBar(stats.TotalUSD, cfg.Budget.DailyUSDLimit, cfg.Budget.AlertThresholdPct)
		} else {
			fmt.Printf("  Daily USD spend : %s  (no limit set)\n", cost.FormatCost(stats.TotalUSD))
		}

		// Token section
		if cfg.Budget.DailyTokenLimit > 0 {
			printDailyTokenBar(stats.TotalTokens, cfg.Budget.DailyTokenLimit, cfg.Budget.AlertThresholdPct)
		} else {
			fmt.Printf("  Daily tokens    : %d  (no limit set)\n", stats.TotalTokens)
		}

		fmt.Printf("  Ledger entries  : %d\n", stats.EntryCount)

		if cfg.Budget.DailyUSDLimit == 0 && cfg.Budget.DailyTokenLimit == 0 {
			fmt.Println()
			color.New(color.Faint).Printf("No daily budget configured. Use 'cloop budget set' to add limits.\n")
		}
		fmt.Println()
		return nil
	},
}

// ── budget set ────────────────────────────────────────────────────────────────

var (
	budgetSetDailyUSD    float64
	budgetSetDailyTokens int
	budgetSetThreshold   int
)

var budgetSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure daily token and USD budget limits",
	Long: `Persist daily budget limits to .cloop/config.yaml.

  cloop budget set --daily-usd 5.00          # $5/day limit
  cloop budget set --daily-tokens 500000     # 500k tokens/day
  cloop budget set --daily-usd 5 --alert 90  # alert at 90% usage
  cloop budget set --daily-usd 0             # remove USD limit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		changed := false

		if cmd.Flags().Changed("daily-usd") {
			if budgetSetDailyUSD < 0 {
				return fmt.Errorf("--daily-usd must be >= 0")
			}
			cfg.Budget.DailyUSDLimit = budgetSetDailyUSD
			changed = true
		}

		if cmd.Flags().Changed("daily-tokens") {
			if budgetSetDailyTokens < 0 {
				return fmt.Errorf("--daily-tokens must be >= 0")
			}
			cfg.Budget.DailyTokenLimit = budgetSetDailyTokens
			changed = true
		}

		if cmd.Flags().Changed("alert") {
			if budgetSetThreshold < 1 || budgetSetThreshold > 100 {
				return fmt.Errorf("--alert must be between 1 and 100")
			}
			cfg.Budget.AlertThresholdPct = budgetSetThreshold
			changed = true
		}

		if !changed {
			return fmt.Errorf("specify at least one of --daily-usd, --daily-tokens, or --alert")
		}

		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Println("Budget configuration saved.")
		if cfg.Budget.DailyUSDLimit > 0 {
			fmt.Printf("  Daily USD limit    : %s\n", cost.FormatCost(cfg.Budget.DailyUSDLimit))
		} else {
			fmt.Println("  Daily USD limit    : (none)")
		}
		if cfg.Budget.DailyTokenLimit > 0 {
			fmt.Printf("  Daily token limit  : %d\n", cfg.Budget.DailyTokenLimit)
		} else {
			fmt.Println("  Daily token limit  : (none)")
		}
		threshold := cfg.Budget.AlertThresholdPct
		if threshold == 0 {
			threshold = 80
		}
		fmt.Printf("  Alert threshold    : %d%%\n", threshold)
		fmt.Println()

		// Show current usage vs the newly configured limits.
		stats, _ := budget.DailyUsage(workdir)
		if cfg.Budget.DailyUSDLimit > 0 {
			printDailyUSDBar(stats.TotalUSD, cfg.Budget.DailyUSDLimit, cfg.Budget.AlertThresholdPct)
		}
		if cfg.Budget.DailyTokenLimit > 0 {
			printDailyTokenBar(stats.TotalTokens, cfg.Budget.DailyTokenLimit, cfg.Budget.AlertThresholdPct)
		}
		fmt.Println()
		return nil
	},
}

// ── helpers ───────────────────────────────────────────────────────────────────

func printDailyUSDBar(spent, limit float64, alertPct int) {
	pct := spent / limit * 100
	if pct > 100 {
		pct = 100
	}
	bar := asciiBar(pct, 25)
	threshold := float64(alertPct)
	if threshold == 0 {
		threshold = 80
	}

	c := color.New(color.FgGreen)
	if spent >= limit {
		c = color.New(color.FgRed, color.Bold)
	} else if pct >= threshold {
		c = color.New(color.FgYellow)
	}
	c.Printf("  Daily USD   : %s / %s  [%s]  %.1f%%\n",
		cost.FormatCost(spent), cost.FormatCost(limit), bar, spent/limit*100)
}

func printDailyTokenBar(used, limit, alertPct int) {
	pct := float64(used) / float64(limit) * 100
	if pct > 100 {
		pct = 100
	}
	bar := asciiBar(pct, 25)
	threshold := float64(alertPct)
	if threshold == 0 {
		threshold = 80
	}

	c := color.New(color.FgGreen)
	if used >= limit {
		c = color.New(color.FgRed, color.Bold)
	} else if pct >= threshold {
		c = color.New(color.FgYellow)
	}
	c.Printf("  Daily tokens: %d / %d  [%s]  %.1f%%\n",
		used, limit, bar, float64(used)/float64(limit)*100)
}

func asciiBar(pct float64, width int) string {
	filled := int(math.Round(pct / 100 * float64(width)))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
}

func init() {
	budgetSetCmd.Flags().Float64Var(&budgetSetDailyUSD, "daily-usd", 0, "Daily USD spend cap (0 = remove limit)")
	budgetSetCmd.Flags().IntVar(&budgetSetDailyTokens, "daily-tokens", 0, "Daily token cap (0 = remove limit)")
	budgetSetCmd.Flags().IntVar(&budgetSetThreshold, "alert", 0, "Alert threshold percentage 1-100 (default 80)")

	budgetCmd.AddCommand(budgetStatusCmd, budgetSetCmd)
	rootCmd.AddCommand(budgetCmd)
}
