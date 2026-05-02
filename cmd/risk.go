package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/risk"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	riskProvider string
	riskModel    string
	riskTimeout  string
	riskJSON     bool
)

var riskCmd = &cobra.Command{
	Use:   "risk [task-id]",
	Short: "AI pre-execution risk assessment for a task or the full plan",
	Long: `Analyze a task (or all pending tasks) for execution risks before running.

Each finding includes:
  • Severity level  — LOW / MEDIUM / HIGH / CRITICAL
  • Category        — data-loss, security, irreversible, breaking-change, external-dependency
  • Rationale       — why this is a risk
  • Mitigation      — how to reduce or eliminate the risk

CRITICAL findings should be reviewed carefully before proceeding.
Use 'cloop run --risk-check' to abort automatically on CRITICAL findings.

Examples:
  cloop risk                      # assess all pending tasks
  cloop risk 3                    # assess only task #3
  cloop risk --provider anthropic # use a specific provider
  cloop risk --json               # output raw JSON`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		taskID := ""
		if len(args) > 0 {
			taskID = args[0]
		}

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := riskProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := riskModel
		if model == "" {
			switch pName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}
		if model == "" {
			model = s.Model
		}

		timeout := 3 * time.Minute
		if riskTimeout != "" {
			timeout, err = time.ParseDuration(riskTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		provCfg := provider.ProviderConfig{
			Name:             pName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if !riskJSON {
			headerColor := color.New(color.FgCyan, color.Bold)
			headerColor.Printf("\ncloop risk — pre-execution AI risk assessment\n")
			fmt.Printf("  Provider: %s\n", prov.Name())
			fmt.Printf("  Goal: %s\n", truncate(s.Goal, 80))
			if taskID != "" {
				fmt.Printf("  Task: #%s\n", taskID)
			} else {
				fmt.Printf("  Scope: all pending tasks\n")
			}
			fmt.Println()
			color.New(color.Faint).Printf("Assessing risks...\n\n")
		}

		reports, err := risk.Assess(ctx, prov, model, s.Plan, taskID)
		if err != nil {
			return fmt.Errorf("risk: %w", err)
		}

		if len(reports) == 0 {
			if !riskJSON {
				color.New(color.FgGreen).Printf("No pending tasks to assess.\n")
			}
			return nil
		}

		if riskJSON {
			return printRiskJSON(reports)
		}

		printRiskReports(reports)
		return nil
	},
}

// printRiskReports renders risk reports with colored severity badges.
func printRiskReports(reports []*risk.RiskReport) {
	sep := strings.Repeat("─", 70)
	dimColor := color.New(color.Faint)

	criticalCount := 0
	for _, r := range reports {
		if r.HasCritical() {
			criticalCount++
		}
	}

	for _, r := range reports {
		taskHeader := color.New(color.FgWhite, color.Bold)
		fmt.Println(sep)
		taskHeader.Printf("Task #%d — %s\n", r.TaskID, r.TaskTitle)
		fmt.Printf("Overall risk: %s\n\n", levelBadge(r.OverallLevel))

		if len(r.Findings) == 0 {
			color.New(color.FgGreen).Printf("  ✓ No risks identified.\n\n")
			continue
		}

		for i, f := range r.Findings {
			fmt.Printf("  Finding %d: %s  [%s]\n", i+1, levelBadge(f.Level), categoryLabel(f.Category))
			fmt.Printf("  %-12s %s\n", "Rationale:", f.Rationale)
			fmt.Printf("  %-12s %s\n", "Mitigation:", f.Mitigation)
			fmt.Println()
		}
	}
	fmt.Println(sep)

	// Summary footer
	if criticalCount > 0 {
		color.New(color.FgRed, color.Bold).Printf(
			"\n⚠  %d task(s) have CRITICAL findings. Review carefully before running.\n",
			criticalCount,
		)
		color.New(color.FgRed).Printf("   Use 'cloop run --pm --risk-check' to automatically block on CRITICAL findings.\n")
		color.New(color.FgRed).Printf("   Add '--force' to override CRITICAL blocks if you accept the risk.\n\n")
	} else {
		dimColor.Printf("\nRun 'cloop run --pm' to execute the plan.\n\n")
	}
}

// printRiskJSON outputs a JSON array of all reports.
func printRiskJSON(reports []*risk.RiskReport) error {
	var sb strings.Builder
	sb.WriteString("[\n")
	for i, r := range reports {
		if i > 0 {
			sb.WriteString(",\n")
		}
		sb.WriteString(fmt.Sprintf(
			`  {"task_id":%d,"task_title":%q,"overall_level":%q,"findings":[`,
			r.TaskID, r.TaskTitle, r.OverallLevel,
		))
		for j, f := range r.Findings {
			if j > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(fmt.Sprintf(
				`{"level":%q,"category":%q,"rationale":%q,"mitigation":%q}`,
				f.Level, f.Category, f.Rationale, f.Mitigation,
			))
		}
		sb.WriteString("]}")
	}
	sb.WriteString("\n]\n")
	fmt.Print(sb.String())
	return nil
}

// levelBadge returns a colored text badge for a risk level.
func levelBadge(level risk.Level) string {
	switch level {
	case risk.LevelCritical:
		return color.New(color.FgRed, color.Bold).Sprint("[ CRITICAL ]")
	case risk.LevelHigh:
		return color.New(color.FgRed).Sprint("[   HIGH   ]")
	case risk.LevelMedium:
		return color.New(color.FgYellow).Sprint("[  MEDIUM  ]")
	default:
		return color.New(color.FgGreen).Sprint("[   LOW    ]")
	}
}

// categoryLabel returns a human-readable label with emoji for a risk category.
func categoryLabel(cat risk.Category) string {
	switch cat {
	case risk.CategoryDataLoss:
		return "data-loss"
	case risk.CategorySecurity:
		return "security"
	case risk.CategoryIrreversible:
		return "irreversible"
	case risk.CategoryBreakingChange:
		return "breaking-change"
	case risk.CategoryExternalDependency:
		return "external-dependency"
	default:
		return string(cat)
	}
}

func init() {
	riskCmd.Flags().StringVar(&riskProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	riskCmd.Flags().StringVar(&riskModel, "model", "", "Model override for the AI provider")
	riskCmd.Flags().StringVar(&riskTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 90s)")
	riskCmd.Flags().BoolVar(&riskJSON, "json", false, "Output findings as JSON")
	rootCmd.AddCommand(riskCmd)
}
