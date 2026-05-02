package cmd

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ── top-level "cost" command ──────────────────────────────────────────────────

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "API cost tracking and budget management",
}

// ── cost report ──────────────────────────────────────────────────────────────

var costReportSince string
var costReportBy string

var costReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show historical API cost dashboard",
	Long: `Read .cloop/costs.jsonl and render a cost breakdown table.

Group by task (default), provider, or day:

  cloop cost report
  cloop cost report --since 2024-01-01
  cloop cost report --by provider
  cloop cost report --by day`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		entries, err := cost.ReadLedger(workdir)
		if err != nil {
			return fmt.Errorf("reading cost ledger: %w", err)
		}

		// Apply --since filter
		var since time.Time
		if costReportSince != "" {
			since, err = parseSinceDate(costReportSince)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
		}

		if !since.IsZero() {
			filtered := entries[:0]
			for _, e := range entries {
				if !e.Timestamp.Before(since) {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}

		if len(entries) == 0 {
			fmt.Println("No cost records found. Records are written to .cloop/costs.jsonl when tasks execute.")
			return nil
		}

		// Budget warning
		cfg, _ := config.Load(workdir)
		if cfg != nil && cfg.Budget.MonthlyUSD > 0 {
			monthly, _ := cost.MonthlyTotal(workdir)
			printBudgetStatus(monthly, cfg.Budget.MonthlyUSD)
		}

		bold := color.New(color.Bold)
		bold.Printf("\ncloop cost report")
		if !since.IsZero() {
			fmt.Printf(" (since %s)", since.Format("2006-01-02"))
		}
		fmt.Println()

		var total float64
		for _, e := range entries {
			total += e.EstimatedUSD
		}
		fmt.Printf("Total entries : %d\n", len(entries))
		fmt.Printf("Total spend   : %s\n\n", cost.FormatCost(total))

		switch strings.ToLower(costReportBy) {
		case "provider":
			printByProvider(entries)
		case "day":
			printByDay(entries)
		default:
			printByTask(entries)
		}

		return nil
	},
}

// ── cost budget set ───────────────────────────────────────────────────────────

var costBudgetCmd = &cobra.Command{
	Use:   "budget",
	Short: "Manage monthly spend budget",
}

var costBudgetSetCmd = &cobra.Command{
	Use:   "set <usd>",
	Short: "Set the monthly budget cap in USD",
	Long: `Persist a monthly budget cap to .cloop/config.yaml.

  cloop cost budget set 10.00    # warn when monthly spend exceeds $10
  cloop cost budget set 0        # remove budget cap`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		usd, err := strconv.ParseFloat(args[0], 64)
		if err != nil || usd < 0 {
			return fmt.Errorf("budget must be a non-negative number, got: %s", args[0])
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return err
		}
		cfg.Budget.MonthlyUSD = usd
		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		if usd == 0 {
			fmt.Println("Monthly budget cap removed.")
		} else {
			fmt.Printf("Monthly budget cap set to %s.\n", cost.FormatCost(usd))
		}

		// Show current month spend vs budget
		monthly, err := cost.MonthlyTotal(workdir)
		if err == nil && usd > 0 {
			printBudgetStatus(monthly, usd)
		}
		return nil
	},
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseSinceDate(s string) (time.Time, error) {
	// Try RFC3339 first, then date-only
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognised date format %q (use YYYY-MM-DD or RFC3339)", s)
}

func printBudgetStatus(spent, budget float64) {
	pct := spent / budget * 100
	bar := budgetBar(pct, 20)
	status := color.New(color.FgGreen)
	if pct >= 100 {
		status = color.New(color.FgRed, color.Bold)
	} else if pct >= 80 {
		status = color.New(color.FgYellow)
	}
	status.Printf("Monthly budget: %s / %s  [%s]  %.1f%%\n",
		cost.FormatCost(spent), cost.FormatCost(budget), bar, pct)
}

func budgetBar(pct float64, width int) string {
	filled := int(math.Round(pct / 100 * float64(width)))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
}

// printByTask renders a table grouped by task ID+title.
func printByTask(entries []cost.LedgerEntry) {
	type row struct {
		id             int
		title          string
		inputTokens    int
		outputTokens   int
		thinkingTokens int
		usd            float64
		count          int
	}
	byTask := map[int]*row{}
	for _, e := range entries {
		r, ok := byTask[e.TaskID]
		if !ok {
			r = &row{id: e.TaskID, title: e.TaskTitle}
			byTask[e.TaskID] = r
		}
		r.inputTokens += e.InputTokens
		r.outputTokens += e.OutputTokens
		r.thinkingTokens += e.ThinkingTokens
		r.usd += e.EstimatedUSD
		r.count++
	}
	// Sort by task ID
	ids := make([]int, 0, len(byTask))
	for id := range byTask {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	// Check whether any entry has thinking tokens so we can add the column conditionally.
	var totalThinking int
	for _, r := range byTask {
		totalThinking += r.thinkingTokens
	}

	bold := color.New(color.Bold)
	if totalThinking > 0 {
		bold.Printf("%-5s  %-35s  %8s  %9s  %10s  %10s  %5s\n",
			"ID", "Task", "In-tok", "Out-tok", "Think-tok", "Cost", "Runs")
		fmt.Println(strings.Repeat("-", 90))
		for _, id := range ids {
			r := byTask[id]
			title := r.title
			if len(title) > 35 {
				title = title[:32] + "..."
			}
			fmt.Printf("%-5d  %-35s  %8d  %9d  %10d  %10s  %5d\n",
				r.id, title, r.inputTokens, r.outputTokens, r.thinkingTokens, cost.FormatCost(r.usd), r.count)
		}
	} else {
		bold.Printf("%-5s  %-35s  %8s  %9s  %10s  %5s\n",
			"ID", "Task", "In-tok", "Out-tok", "Cost", "Runs")
		fmt.Println(strings.Repeat("-", 80))
		for _, id := range ids {
			r := byTask[id]
			title := r.title
			if len(title) > 35 {
				title = title[:32] + "..."
			}
			fmt.Printf("%-5d  %-35s  %8d  %9d  %10s  %5d\n",
				r.id, title, r.inputTokens, r.outputTokens, cost.FormatCost(r.usd), r.count)
		}
	}
}

// printByProvider renders a table grouped by provider.
func printByProvider(entries []cost.LedgerEntry) {
	type row struct {
		provider       string
		inputTokens    int
		outputTokens   int
		thinkingTokens int
		usd            float64
		count          int
	}
	byProv := map[string]*row{}
	for _, e := range entries {
		key := e.Provider
		if key == "" {
			key = "(unknown)"
		}
		r, ok := byProv[key]
		if !ok {
			r = &row{provider: key}
			byProv[key] = r
		}
		r.inputTokens += e.InputTokens
		r.outputTokens += e.OutputTokens
		r.thinkingTokens += e.ThinkingTokens
		r.usd += e.EstimatedUSD
		r.count++
	}
	keys := make([]string, 0, len(byProv))
	for k := range byProv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var totalThinking int
	for _, r := range byProv {
		totalThinking += r.thinkingTokens
	}

	bold := color.New(color.Bold)
	if totalThinking > 0 {
		bold.Printf("%-20s  %8s  %9s  %10s  %10s  %5s\n",
			"Provider", "In-tok", "Out-tok", "Think-tok", "Cost", "Runs")
		fmt.Println(strings.Repeat("-", 70))
		for _, k := range keys {
			r := byProv[k]
			fmt.Printf("%-20s  %8d  %9d  %10d  %10s  %5d\n",
				r.provider, r.inputTokens, r.outputTokens, r.thinkingTokens, cost.FormatCost(r.usd), r.count)
		}
	} else {
		bold.Printf("%-20s  %8s  %9s  %10s  %5s\n",
			"Provider", "In-tok", "Out-tok", "Cost", "Runs")
		fmt.Println(strings.Repeat("-", 60))
		for _, k := range keys {
			r := byProv[k]
			fmt.Printf("%-20s  %8d  %9d  %10s  %5d\n",
				r.provider, r.inputTokens, r.outputTokens, cost.FormatCost(r.usd), r.count)
		}
	}
}

// printByDay renders a table grouped by calendar day with a simple ASCII trend.
func printByDay(entries []cost.LedgerEntry) {
	type row struct {
		day          string
		inputTokens  int
		outputTokens int
		usd          float64
		count        int
	}
	byDay := map[string]*row{}
	for _, e := range entries {
		key := e.Timestamp.UTC().Format("2006-01-02")
		r, ok := byDay[key]
		if !ok {
			r = &row{day: key}
			byDay[key] = r
		}
		r.inputTokens += e.InputTokens
		r.outputTokens += e.OutputTokens
		r.usd += e.EstimatedUSD
		r.count++
	}
	days := make([]string, 0, len(byDay))
	for d := range byDay {
		days = append(days, d)
	}
	sort.Strings(days)

	// Find max usd for bar scaling
	maxUSD := 0.0
	for _, d := range days {
		if byDay[d].usd > maxUSD {
			maxUSD = byDay[d].usd
		}
	}

	bold := color.New(color.Bold)
	bold.Printf("%-12s  %8s  %9s  %10s  %5s  %s\n",
		"Day", "In-tok", "Out-tok", "Cost", "Runs", "Burn")
	fmt.Println(strings.Repeat("-", 72))
	barWidth := 20
	for _, d := range days {
		r := byDay[d]
		bar := ""
		if maxUSD > 0 {
			filled := int(math.Round(r.usd / maxUSD * float64(barWidth)))
			bar = strings.Repeat("|", filled)
		}
		fmt.Printf("%-12s  %8d  %9d  %10s  %5d  %s\n",
			r.day, r.inputTokens, r.outputTokens, cost.FormatCost(r.usd), r.count, bar)
	}
}

func init() {
	costReportCmd.Flags().StringVar(&costReportSince, "since", "", "Only include records on or after this date (YYYY-MM-DD or RFC3339)")
	costReportCmd.Flags().StringVar(&costReportBy, "by", "task", "Group results by: task, provider, or day")

	costBudgetCmd.AddCommand(costBudgetSetCmd)
	costCmd.AddCommand(costReportCmd, costBudgetCmd)
	rootCmd.AddCommand(costCmd)
}
