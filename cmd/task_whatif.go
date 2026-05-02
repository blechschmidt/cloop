package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/whatif"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	whatifProvider string
	whatifModel    string
	whatifTimeout  string
	whatifApply    bool
	whatifJSON     bool
	whatifNoStream bool
)

var taskWhatIfCmd = &cobra.Command{
	Use:   "ai-what-if \"<scenario>\"",
	Short: "Scenario planning: simulate a plan mutation and narrate the consequences",
	Long: `Apply a hypothetical mutation to an in-memory copy of the plan, re-run the
velocity forecast and health score, then ask the AI to narrate the consequences:
timeline impact, risk changes, newly blocked tasks, and recommended mitigations.

The original plan is NEVER modified unless you pass --apply.

Example scenarios:
  cloop task ai-what-if "what if task 5 takes 3x longer?"
  cloop task ai-what-if "what if we skip all tasks tagged frontend?"
  cloop task ai-what-if "what if we add a new compliance requirement?"
  cloop task ai-what-if "what if the assignee for task 7 is changed to Alice?"

Output is a structured Markdown report with a before/after comparison table.

Use --apply to actually persist the mutation to the plan (with confirmation).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scenario := strings.TrimSpace(args[0])
		if scenario == "" {
			return fmt.Errorf("scenario must not be empty")
		}

		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := whatifProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := whatifModel
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

		timeout := 5 * time.Minute
		if whatifTimeout != "" {
			timeout, err = time.ParseDuration(whatifTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		cyan := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)

		if !whatifJSON {
			cyan.Printf("━━━ cloop task ai-what-if ━━━\n\n")
			dim.Printf("Scenario: %s\n", scenario)
			dim.Printf("Provider: %s", pName)
			if model != "" {
				dim.Printf(" (%s)", model)
			}
			dim.Printf("\n\n")
			dim.Printf("Step 1/3: Applying mutation to in-memory plan...\n")
		}

		var streamFn func(string)
		if !whatifJSON && !whatifNoStream {
			streamFn = func(token string) {
				fmt.Print(token)
			}
		}

		report, err := whatif.Run(ctx, prov, opts, s, scenario, streamFn)
		if err != nil {
			return fmt.Errorf("what-if analysis failed: %w", err)
		}

		if whatifJSON {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		// If streamed, narrative was already printed; otherwise print the full report.
		if whatifNoStream || streamFn == nil {
			fmt.Println(whatif.FormatMarkdown(report))
		} else {
			// Streaming already printed the narrative; print the comparison table header.
			fmt.Printf("\n\n")
			printWhatIfTable(report)
		}

		// --apply: persist the mutation
		if whatifApply {
			if len(report.RemovedTaskWarnings) > 0 {
				color.New(color.FgYellow, color.Bold).Printf("\nWarning: this mutation would remove %d task(s):\n", len(report.RemovedTaskWarnings))
				for _, t := range report.RemovedTaskWarnings {
					color.New(color.FgYellow).Printf("  - Task #%d: %s\n", t.ID, t.Title)
				}
				color.New(color.FgYellow).Printf("\nProceed? [y/N] ")
				var confirm string
				fmt.Scanln(&confirm) //nolint:errcheck
				if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			s.Plan = report.MutatedPlan
			if err := s.Save(); err != nil {
				return fmt.Errorf("saving mutated plan: %w", err)
			}
			color.New(color.FgGreen, color.Bold).Printf("\nMutation applied to plan. %d task(s) in plan.\n", len(s.Plan.Tasks))
		}

		return nil
	},
}

// printWhatIfTable renders the before/after comparison table to stdout.
func printWhatIfTable(r *whatif.Report) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	dim := color.New(color.Faint)

	sep := strings.Repeat("─", 72)
	bold.Printf("\n%s\n", sep)
	bold.Printf("  BEFORE / AFTER COMPARISON\n")
	bold.Printf("%s\n\n", sep)

	fmt.Printf("  %-28s  %-18s  %-18s  %s\n", "METRIC", "BEFORE", "AFTER", "DELTA")
	fmt.Printf("  %s\n", strings.Repeat("─", 68))

	printRow := func(metric, before, after, delta string, positive bool) {
		fmt.Printf("  %-28s  %-18s  %-18s  ", metric, before, after)
		if delta == "" || delta == "—" || delta == "+0" || delta == "0" {
			dim.Printf("%s\n", delta)
			return
		}
		if positive {
			green.Printf("%s\n", delta)
		} else {
			red.Printf("%s\n", delta)
		}
	}

	if r.BeforeForecast != nil && r.AfterForecast != nil {
		bf, af := r.BeforeForecast, r.AfterForecast

		deltaTasks := af.TotalTasks - bf.TotalTasks
		printRow("Total tasks", fmt.Sprintf("%d", bf.TotalTasks), fmt.Sprintf("%d", af.TotalTasks),
			fmt.Sprintf("%+d", deltaTasks), deltaTasks <= 0)

		deltaBlocked := af.BlockedTasks - bf.BlockedTasks
		printRow("Blocked tasks", fmt.Sprintf("%d", bf.BlockedTasks), fmt.Sprintf("%d", af.BlockedTasks),
			fmt.Sprintf("%+d", deltaBlocked), deltaBlocked <= 0)

		bETA := "unknown"
		aETA := "unknown"
		var deltaETA string
		if bf.Expected.DaysRemaining >= 0 {
			bETA = bf.Expected.CompletionDate.Format("Jan 2, 2006")
		}
		if af.Expected.DaysRemaining >= 0 {
			aETA = af.Expected.CompletionDate.Format("Jan 2, 2006")
		}
		if bf.Expected.DaysRemaining >= 0 && af.Expected.DaysRemaining >= 0 {
			dDelta := af.Expected.DaysRemaining - bf.Expected.DaysRemaining
			if dDelta == 0 {
				deltaETA = "no change"
			} else {
				deltaETA = fmt.Sprintf("%+.1f days", dDelta)
			}
			printRow("Expected completion", bETA, aETA, deltaETA, dDelta <= 0)
		} else {
			printRow("Expected completion", bETA, aETA, "—", true)
		}
	}

	deltaHealth := r.AfterHealth.Score - r.BeforeHealth.Score
	printRow("Health score",
		fmt.Sprintf("%d/100 (%s)", r.BeforeHealth.Score, r.BeforeHealth.Grade()),
		fmt.Sprintf("%d/100 (%s)", r.AfterHealth.Score, r.AfterHealth.Grade()),
		fmt.Sprintf("%+d", deltaHealth),
		deltaHealth >= 0,
	)

	fmt.Printf("  %s\n\n", strings.Repeat("─", 68))

	if len(r.TasksAdded) > 0 {
		green.Printf("  + %d task(s) added\n", len(r.TasksAdded))
	}
	if len(r.TasksRemoved) > 0 {
		red.Printf("  - %d task(s) removed\n", len(r.TasksRemoved))
	}
	if len(r.TasksChanged) > 0 {
		dim.Printf("  ~ %d field change(s) across existing tasks\n", len(r.TasksChanged))
	}
	fmt.Println()
}

func init() {
	taskWhatIfCmd.Flags().StringVar(&whatifProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskWhatIfCmd.Flags().StringVar(&whatifModel, "model", "", "Model override for the AI provider")
	taskWhatIfCmd.Flags().StringVar(&whatifTimeout, "timeout", "5m", "Timeout for all AI calls (e.g. 90s, 5m)")
	taskWhatIfCmd.Flags().BoolVar(&whatifApply, "apply", false, "Apply the mutation to the actual plan after analysis")
	taskWhatIfCmd.Flags().BoolVar(&whatifJSON, "json", false, "Output the full report as JSON")
	taskWhatIfCmd.Flags().BoolVar(&whatifNoStream, "no-stream", false, "Disable streaming output for the AI narrative")

	taskCmd.AddCommand(taskWhatIfCmd)
}
