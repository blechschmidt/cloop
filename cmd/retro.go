package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/journal"
	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/retro"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	retroProvider   string
	retroModel      string
	retroFormat     string
	retroOutput     string
	retroSave       bool
	retroSaveMemory bool
	retroTimeout    string
)

var retroCmd = &cobra.Command{
	Use:   "retro",
	Short: "AI-powered sprint retrospective for the current project",
	Long: `Run an AI retrospective analysis on the current project session.

Analyzes task execution patterns, surfaces what went well and what failed,
computes velocity metrics, and provides concrete recommended next actions.

Examples:
  cloop retro                    # terminal retrospective
  cloop retro --format md        # markdown output
  cloop retro --format md -o retro.md  # save markdown to file
  cloop retro --save-memory      # persist insights to project memory
  cloop retro --provider anthropic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no project initialized — run 'cloop init' first")
		}
		if s.CurrentStep == 0 && (s.Plan == nil || len(s.Plan.Tasks) == 0) {
			return fmt.Errorf("no session data yet — run 'cloop run' first")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Resolve provider
		providerName := retroProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" {
			providerName = s.Provider
		}
		if providerName == "" {
			providerName = autoSelectProvider()
		}

		// Resolve model
		model := retroModel
		if model == "" {
			model = s.Model
		}
		if model == "" {
			switch providerName {
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

		provCfg := provider.ProviderConfig{
			Name:             providerName,
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

		timeout := 120 * time.Second
		if retroTimeout != "" {
			timeout, err = time.ParseDuration(retroTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		dimColor.Printf("Running retrospective analysis with %s...\n\n", prov.Name())

		// Build cost summary string if token data is available.
		costSummary := ""
		if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
			usd := cost.EstimateSessionCost(providerName, model, s.TotalInputTokens, s.TotalOutputTokens)
			costSummary = fmt.Sprintf("Input: %d tokens, Output: %d tokens, Estimated cost: %s",
				s.TotalInputTokens, s.TotalOutputTokens, cost.FormatCost(usd))
		}

		ctx := context.Background()
		var analysis *retro.Analysis
		if s.Plan != nil {
			// Use Generate() when a plan is available — richer per-task analysis.
			analysis, err = retro.Generate(ctx, prov, model, timeout, s.Plan, costSummary)
		} else {
			analysis, err = retro.Analyze(ctx, prov, model, timeout, s)
		}
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		goal := s.Goal
		var plan *pm.Plan
		if s.Plan != nil {
			plan = s.Plan
		}

		// Collect journal summaries for tasks that have entries.
		journalSummaries := collectJournalSummaries(ctx, workdir, plan, prov, model)

		switch retroFormat {
		case "md", "markdown":
			md := retro.FormatMarkdownFullWithJournal(analysis, goal, plan, costSummary, journalSummaries)
			dest := retroOutput
			if dest == "" && retroSave {
				dest = fmt.Sprintf(".cloop/retro-%s.md", time.Now().Format("20060102-150405"))
			}
			if dest != "" {
				if err := os.WriteFile(dest, []byte(md), 0o644); err != nil {
					return fmt.Errorf("writing output: %w", err)
				}
				color.New(color.FgGreen).Printf("Retrospective saved to %s\n", dest)
			} else {
				fmt.Print(md)
			}
		default:
			// Terminal format: print markdown to stdout by default, optionally save.
			md := retro.FormatMarkdownFullWithJournal(analysis, goal, plan, costSummary, journalSummaries)
			printRetroTerminal(analysis, s)
			if retroSave {
				dest := fmt.Sprintf(".cloop/retro-%s.md", time.Now().Format("20060102-150405"))
				if err := os.WriteFile(dest, []byte(md), 0o644); err != nil {
					dimColor.Printf("Warning: could not save retro file: %v\n", err)
				} else {
					color.New(color.FgGreen).Printf("\nRetrospective saved to %s\n", dest)
				}
			}
		}

		// Optionally save insights to project memory.
		if retroSaveMemory {
			mem, _ := memory.Load(workdir)
			if mem == nil {
				mem = &memory.Memory{}
			}
			saved := 0
			for _, insight := range analysis.Insights {
				mem.Add(insight, "retro", s.Goal, []string{"retro", "insight"})
				saved++
			}
			for _, action := range analysis.NextActions {
				mem.Add("Action item: "+action, "retro", s.Goal, []string{"retro", "action"})
				saved++
			}
			if err := mem.Save(workdir); err != nil {
				dimColor.Printf("Warning: could not save memory: %v\n", err)
			} else {
				dimColor.Printf("\nSaved %d insight(s) to project memory.\n", saved)
			}
		}

		return nil
	},
}

func printRetroTerminal(a *retro.Analysis, s *state.ProjectState) {
	header := color.New(color.FgCyan, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	warnColor := color.New(color.FgYellow, color.Bold)
	dimColor := color.New(color.Faint)
	boldColor := color.New(color.Bold)

	header.Printf("Sprint Retrospective\n")
	header.Printf("════════════════════\n\n")

	boldColor.Printf("Goal: ")
	fmt.Printf("%s\n\n", s.Goal)

	// Health score with color coding
	boldColor.Printf("Health Score: ")
	scoreColor := successColor
	if a.HealthScore < 5 {
		scoreColor = failColor
	} else if a.HealthScore < 7 {
		scoreColor = warnColor
	}
	scoreColor.Printf("%.1f/10\n\n", a.HealthScore)

	if a.Summary != "" {
		boldColor.Printf("Summary\n")
		dimColor.Printf("───────\n")
		fmt.Printf("%s\n\n", a.Summary)
	}

	// Session stats
	stats := retro.ComputeStats(s)
	boldColor.Printf("Session Stats\n")
	dimColor.Printf("─────────────\n")
	if s.Plan != nil && stats.TotalTasks > 0 {
		fmt.Printf("  Tasks:  %d total", stats.TotalTasks)
		if stats.DoneTasks > 0 {
			successColor.Printf("  %d done", stats.DoneTasks)
		}
		if stats.FailedTasks > 0 {
			failColor.Printf("  %d failed", stats.FailedTasks)
		}
		if stats.SkippedTasks > 0 {
			dimColor.Printf("  %d skipped", stats.SkippedTasks)
		}
		if stats.PendingTasks > 0 {
			warnColor.Printf("  %d pending", stats.PendingTasks)
		}
		fmt.Printf("\n")
		if stats.AvgTaskDur > 0 {
			fmt.Printf("  Avg task: %s\n", stats.AvgTaskDur.Round(time.Second))
		}
	}
	if stats.InputTokens > 0 || stats.OutputTokens > 0 {
		fmt.Printf("  Tokens: %d in / %d out", stats.InputTokens, stats.OutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, stats.InputTokens, stats.OutputTokens); ok {
				fmt.Printf(" ≈ %s", cost.FormatCost(usd))
			}
		}
		fmt.Printf("\n")
	}
	fmt.Printf("  Status: %s\n\n", s.Status)

	if a.VelocityNotes != "" {
		boldColor.Printf("Velocity\n")
		dimColor.Printf("────────\n")
		fmt.Printf("%s\n\n", a.VelocityNotes)
	}

	if len(a.WentWell) > 0 {
		successColor.Printf("What Went Well\n")
		dimColor.Printf("──────────────\n")
		for _, item := range a.WentWell {
			successColor.Printf("  ✓ ")
			fmt.Printf("%s\n", item)
		}
		fmt.Printf("\n")
	}

	if len(a.WentWrong) > 0 {
		failColor.Printf("What Went Wrong\n")
		dimColor.Printf("───────────────\n")
		for _, item := range a.WentWrong {
			failColor.Printf("  ✗ ")
			fmt.Printf("%s\n", item)
		}
		fmt.Printf("\n")
	}

	if len(a.Bottlenecks) > 0 {
		warnColor.Printf("Bottlenecks\n")
		dimColor.Printf("───────────\n")
		for _, item := range a.Bottlenecks {
			warnColor.Printf("  ⚠ ")
			fmt.Printf("%s\n", item)
		}
		fmt.Printf("\n")
	}

	if len(a.Insights) > 0 {
		boldColor.Printf("Key Insights\n")
		dimColor.Printf("────────────\n")
		for _, item := range a.Insights {
			dimColor.Printf("  • ")
			fmt.Printf("%s\n", item)
		}
		fmt.Printf("\n")
	}

	if len(a.NextActions) > 0 {
		header.Printf("Recommended Next Actions\n")
		dimColor.Printf("────────────────────────\n")
		for i, item := range a.NextActions {
			warnColor.Printf("  %d. ", i+1)
			fmt.Printf("%s\n", item)
		}
		fmt.Printf("\n")
	}

	// Task detail: show failed/skipped tasks for reference
	if s.Plan != nil {
		var failed []*pm.Task
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskFailed {
				failed = append(failed, t)
			}
		}
		if len(failed) > 0 {
			dimColor.Printf("Failed Tasks\n")
			dimColor.Printf("────────────\n")
			for _, t := range failed {
				failColor.Printf("  [!] Task %d: %s\n", t.ID, t.Title)
				if t.Result != "" {
					dimColor.Printf("      %s\n", truncateStr(t.Result, 120))
				}
			}
			fmt.Printf("\n")
		}
	}
}

// collectJournalSummaries fetches AI summaries for all tasks that have journal entries.
// Tasks without entries are skipped. Errors per task are silently dropped.
func collectJournalSummaries(ctx context.Context, workdir string, plan *pm.Plan, prov provider.Provider, model string) map[string]string {
	if plan == nil {
		return nil
	}
	summaries := make(map[string]string)
	for _, t := range plan.Tasks {
		taskID := fmt.Sprintf("%d", t.ID)
		entries, err := journal.List(workdir, taskID)
		if err != nil || len(entries) == 0 {
			continue
		}
		summary, err := journal.Summarize(ctx, prov, model, entries)
		if err != nil {
			continue
		}
		summaries[taskID] = summary
	}
	if len(summaries) == 0 {
		return nil
	}
	return summaries
}

func init() {
	retroCmd.Flags().StringVar(&retroProvider, "provider", "", "Provider to use for analysis")
	retroCmd.Flags().StringVar(&retroModel, "model", "", "Model to use for analysis")
	retroCmd.Flags().StringVar(&retroFormat, "format", "terminal", "Output format: terminal (default) or md")
	retroCmd.Flags().StringVarP(&retroOutput, "output", "o", "", "Write output to file (for --format md)")
	retroCmd.Flags().BoolVar(&retroSave, "save", false, "Save report to .cloop/retro-<timestamp>.md")
	retroCmd.Flags().BoolVar(&retroSaveMemory, "save-memory", false, "Save insights to project memory")
	retroCmd.Flags().StringVar(&retroTimeout, "timeout", "", "Analysis timeout (e.g. 120s, 2m)")
	rootCmd.AddCommand(retroCmd)
}
