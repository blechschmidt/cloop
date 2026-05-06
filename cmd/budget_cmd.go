package cmd

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/budget"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/globalbudget"
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

var budgetStatusGlobal bool

var budgetStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show today's token and cost usage vs daily budget",
	Long: `Show today's (UTC) token and cost usage.

  cloop budget status           # per-project usage vs configured limits
  cloop budget status --global  # cross-project global usage vs global limits`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		bold := color.New(color.Bold)

		if budgetStatusGlobal {
			// ── Global view ───────────────────────────────────────────────
			globalCfg, err := globalbudget.Load()
			if err != nil {
				return fmt.Errorf("loading global budget config: %w", err)
			}
			globalStats, err := globalbudget.DailyUsage()
			if err != nil {
				return fmt.Errorf("reading global usage: %w", err)
			}

			bold.Printf("\ncloop budget status — global (all projects, today UTC)\n\n")

			if globalCfg.DailyUSDLimit > 0 {
				printDailyUSDBar(globalStats.TotalUSD, globalCfg.DailyUSDLimit, globalCfg.AlertThresholdPct)
			} else {
				fmt.Printf("  Global USD spend : %s  (no global limit set)\n", cost.FormatCost(globalStats.TotalUSD))
			}
			if globalCfg.DailyTokenLimit > 0 {
				printDailyTokenBar(globalStats.TotalTokens, globalCfg.DailyTokenLimit, globalCfg.AlertThresholdPct)
			} else {
				fmt.Printf("  Global tokens    : %d  (no global limit set)\n", globalStats.TotalTokens)
			}
			fmt.Printf("  Ledger entries   : %d\n", globalStats.EntryCount)

			if globalCfg.DailyUSDLimit == 0 && globalCfg.DailyTokenLimit == 0 {
				fmt.Println()
				color.New(color.Faint).Printf("No global budget configured. Use 'cloop budget set --global --daily-usd <n>' to add limits.\n")
			}
			fmt.Println()
			return nil
		}

		// ── Per-project view ──────────────────────────────────────────────
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		stats, err := budget.DailyUsage(workdir)
		if err != nil {
			return fmt.Errorf("reading usage: %w", err)
		}

		// Compute effective limits (incorporating global pct caps).
		globalCfg, _ := globalbudget.Load()
		effectiveUSDLimit := cfg.Budget.DailyUSDLimit
		effectiveTokenLimit := cfg.Budget.DailyTokenLimit
		if pct := globalbudget.EffectiveProjectUSDLimit(globalCfg, cfg.Budget.GlobalUSDPct); pct > 0 {
			if effectiveUSDLimit == 0 || pct < effectiveUSDLimit {
				effectiveUSDLimit = pct
			}
		}
		if pct := globalbudget.EffectiveProjectTokenLimit(globalCfg, cfg.Budget.GlobalTokenPct); pct > 0 {
			if effectiveTokenLimit == 0 || pct < effectiveTokenLimit {
				effectiveTokenLimit = pct
			}
		}

		bold.Printf("\ncloop budget status — today (UTC)\n\n")

		// USD section
		if effectiveUSDLimit > 0 {
			suffix := ""
			if cfg.Budget.GlobalUSDPct > 0 {
				suffix = fmt.Sprintf(" (%.0f%% of global $%.4f)", cfg.Budget.GlobalUSDPct, globalCfg.DailyUSDLimit)
			}
			fmt.Printf("  Effective USD limit : %s%s\n", cost.FormatCost(effectiveUSDLimit), suffix)
			printDailyUSDBar(stats.TotalUSD, effectiveUSDLimit, cfg.Budget.AlertThresholdPct)
		} else {
			fmt.Printf("  Daily USD spend : %s  (no limit set)\n", cost.FormatCost(stats.TotalUSD))
		}

		// Token section
		if effectiveTokenLimit > 0 {
			suffix := ""
			if cfg.Budget.GlobalTokenPct > 0 {
				suffix = fmt.Sprintf(" (%.0f%% of global %d tokens)", cfg.Budget.GlobalTokenPct, globalCfg.DailyTokenLimit)
			}
			fmt.Printf("  Effective token limit: %d%s\n", effectiveTokenLimit, suffix)
			printDailyTokenBar(stats.TotalTokens, effectiveTokenLimit, cfg.Budget.AlertThresholdPct)
		} else {
			fmt.Printf("  Daily tokens    : %d  (no limit set)\n", stats.TotalTokens)
		}

		fmt.Printf("  Ledger entries  : %d\n", stats.EntryCount)

		if effectiveUSDLimit == 0 && effectiveTokenLimit == 0 {
			fmt.Println()
			color.New(color.Faint).Printf("No daily budget configured. Use 'cloop budget set' to add limits.\n")
		}
		fmt.Println()
		return nil
	},
}

// ── budget set ────────────────────────────────────────────────────────────────

var (
	budgetSetDailyUSD      float64
	budgetSetDailyTokens   int
	budgetSetThreshold     int
	budgetSetGlobal        bool
	budgetSetGlobalUSDPct  float64
	budgetSetGlobalTokPct  float64
)

var budgetSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure daily token and USD budget limits",
	Long: `Persist daily budget limits to .cloop/config.yaml (per-project) or
~/.config/cloop/budget.yaml (global, with --global).

  cloop budget set --daily-usd 5.00           # $5/day per-project limit
  cloop budget set --daily-tokens 500000      # 500k tokens/day per-project
  cloop budget set --daily-usd 5 --alert 90   # alert at 90% usage
  cloop budget set --daily-usd 0              # remove per-project USD limit
  cloop budget set --global --daily-usd 20    # $20/day global limit (all projects)
  cloop budget set --global-usd-pct 80        # this project capped at 80% of global USD
  cloop budget set --global-token-pct 50      # this project capped at 50% of global tokens`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		changed := false

		if budgetSetGlobal {
			// ── Update global budget config ───────────────────────────────
			globalCfg, err := globalbudget.Load()
			if err != nil {
				return fmt.Errorf("loading global budget config: %w", err)
			}

			if cmd.Flags().Changed("daily-usd") {
				if budgetSetDailyUSD < 0 {
					return fmt.Errorf("--daily-usd must be >= 0")
				}
				globalCfg.DailyUSDLimit = budgetSetDailyUSD
				changed = true
			}
			if cmd.Flags().Changed("daily-tokens") {
				if budgetSetDailyTokens < 0 {
					return fmt.Errorf("--daily-tokens must be >= 0")
				}
				globalCfg.DailyTokenLimit = budgetSetDailyTokens
				changed = true
			}
			if cmd.Flags().Changed("alert") {
				if budgetSetThreshold < 1 || budgetSetThreshold > 100 {
					return fmt.Errorf("--alert must be between 1 and 100")
				}
				globalCfg.AlertThresholdPct = budgetSetThreshold
				changed = true
			}

			if !changed {
				return fmt.Errorf("specify at least one of --daily-usd, --daily-tokens, or --alert when using --global")
			}

			if err := globalbudget.Save(globalCfg); err != nil {
				return fmt.Errorf("saving global budget config: %w", err)
			}

			fmt.Println("Global budget configuration saved.")
			if globalCfg.DailyUSDLimit > 0 {
				fmt.Printf("  Global daily USD limit   : %s\n", cost.FormatCost(globalCfg.DailyUSDLimit))
			} else {
				fmt.Println("  Global daily USD limit   : (none)")
			}
			if globalCfg.DailyTokenLimit > 0 {
				fmt.Printf("  Global daily token limit : %d\n", globalCfg.DailyTokenLimit)
			} else {
				fmt.Println("  Global daily token limit : (none)")
			}
			threshold := globalCfg.AlertThresholdPct
			if threshold == 0 {
				threshold = 80
			}
			fmt.Printf("  Alert threshold          : %d%%\n", threshold)
			fmt.Println()
			return nil
		}

		// ── Update per-project budget config ──────────────────────────────
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

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

		if cmd.Flags().Changed("global-usd-pct") {
			if budgetSetGlobalUSDPct < 0 || budgetSetGlobalUSDPct > 100 {
				return fmt.Errorf("--global-usd-pct must be between 0 and 100")
			}
			cfg.Budget.GlobalUSDPct = budgetSetGlobalUSDPct
			changed = true
		}

		if cmd.Flags().Changed("global-token-pct") {
			if budgetSetGlobalTokPct < 0 || budgetSetGlobalTokPct > 100 {
				return fmt.Errorf("--global-token-pct must be between 0 and 100")
			}
			cfg.Budget.GlobalTokenPct = budgetSetGlobalTokPct
			changed = true
		}

		if !changed {
			return fmt.Errorf("specify at least one of --daily-usd, --daily-tokens, --alert, --global-usd-pct, or --global-token-pct")
		}

		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Println("Budget configuration saved.")
		if cfg.Budget.DailyUSDLimit > 0 {
			fmt.Printf("  Daily USD limit      : %s\n", cost.FormatCost(cfg.Budget.DailyUSDLimit))
		} else {
			fmt.Println("  Daily USD limit      : (none)")
		}
		if cfg.Budget.DailyTokenLimit > 0 {
			fmt.Printf("  Daily token limit    : %d\n", cfg.Budget.DailyTokenLimit)
		} else {
			fmt.Println("  Daily token limit    : (none)")
		}
		if cfg.Budget.GlobalUSDPct > 0 {
			fmt.Printf("  Global USD pct cap   : %.1f%%\n", cfg.Budget.GlobalUSDPct)
		}
		if cfg.Budget.GlobalTokenPct > 0 {
			fmt.Printf("  Global token pct cap : %.1f%%\n", cfg.Budget.GlobalTokenPct)
		}
		threshold := cfg.Budget.AlertThresholdPct
		if threshold == 0 {
			threshold = 80
		}
		fmt.Printf("  Alert threshold      : %d%%\n", threshold)
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
	// budget status flags
	budgetStatusCmd.Flags().BoolVar(&budgetStatusGlobal, "global", false, "Show global (cross-project) usage vs global limits")

	// budget set flags
	budgetSetCmd.Flags().Float64Var(&budgetSetDailyUSD, "daily-usd", 0, "Daily USD spend cap (0 = remove limit)")
	budgetSetCmd.Flags().IntVar(&budgetSetDailyTokens, "daily-tokens", 0, "Daily token cap (0 = remove limit)")
	budgetSetCmd.Flags().IntVar(&budgetSetThreshold, "alert", 0, "Alert threshold percentage 1-100 (default 80)")
	budgetSetCmd.Flags().BoolVar(&budgetSetGlobal, "global", false, "Set the global (cross-project) budget in ~/.config/cloop/budget.yaml")
	budgetSetCmd.Flags().Float64Var(&budgetSetGlobalUSDPct, "global-usd-pct", 0, "Cap this project at a % of the global daily USD limit (0-100)")
	budgetSetCmd.Flags().Float64Var(&budgetSetGlobalTokPct, "global-token-pct", 0, "Cap this project at a % of the global daily token limit (0-100)")

	budgetCmd.AddCommand(budgetStatusCmd, budgetSetCmd)
	rootCmd.AddCommand(budgetCmd)
}
