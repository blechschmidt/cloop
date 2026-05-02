package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/brief"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/retro"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	briefFormat   string
	briefProvider string
	briefModel    string
	briefTimeout  string
	briefNoRetro  bool
)

var planBriefCmd = &cobra.Command{
	Use:   "ai-brief",
	Short: "Generate a one-page AI executive project brief",
	Long: `Generate a concise executive brief suitable for a stakeholder update.

The brief synthesizes:
  - Current project goal and task completion stats
  - Velocity trend (from forecast data)
  - Top 3 risks (derived from task risk scores)
  - Plan health score
  - Latest retrospective highlights (when available)

Output formats:
  --format markdown   Markdown (default) — saved to .cloop/briefs/
  --format html       Self-contained styled HTML
  --format slack      Slack Block Kit JSON payload

Examples:
  cloop plan ai-brief
  cloop plan ai-brief --format html > brief.html
  cloop plan ai-brief --format slack | curl -X POST -H 'Content-Type: application/json' -d @- $SLACK_WEBHOOK
  cloop plan brief list`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		pName := briefProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := briefModel
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
		if briefTimeout != "" {
			timeout, err = time.ParseDuration(briefTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		outputFormat := parseBriefFormat(briefFormat)

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

		// Print status to stderr so it doesn't pollute piped output.
		headerColor := color.New(color.FgCyan, color.Bold)
		headerColor.Fprintf(os.Stderr, "\ncloop plan ai-brief — executive project brief\n")
		color.New(color.Faint).Fprintf(os.Stderr, "  Provider: %s | Format: %s | Goal: %s\n\n",
			prov.Name(), briefFormat, truncateStr(s.Goal, 70))
		color.New(color.Faint).Fprintln(os.Stderr, "Generating executive brief...")

		// Optionally gather retro highlights (skip if --no-retro or no completed tasks).
		var retroWentWell, retroWentWrong, retroNextAction []string
		if !briefNoRetro {
			stats := retro.ComputeStats(s)
			if stats.DoneTasks > 0 {
				ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
				analysis, rerr := retro.Generate(ctx2, prov, model, timeout, s.Plan, "")
				cancel2()
				if rerr == nil && analysis != nil {
					const maxRetroItems = 3
					for i, w := range analysis.WentWell {
						if i >= maxRetroItems {
							break
						}
						retroWentWell = append(retroWentWell, w)
					}
					for i, w := range analysis.WentWrong {
						if i >= maxRetroItems {
							break
						}
						retroWentWrong = append(retroWentWrong, w)
					}
					for i, a := range analysis.NextActions {
						if i >= maxRetroItems {
							break
						}
						retroNextAction = append(retroNextAction, a)
					}
				}
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		b, err := brief.Generate(ctx, prov, model, timeout, s, outputFormat,
			retroWentWell, retroWentWrong, retroNextAction)
		if err != nil {
			return fmt.Errorf("generating brief: %w", err)
		}

		// Save the brief.
		savedPath, saveErr := brief.Save(workdir, b)
		if saveErr != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "warning: could not save brief: %v\n", saveErr)
		} else {
			color.New(color.Faint).Fprintf(os.Stderr, "Saved to: %s\n\n", savedPath)
		}

		// Print the brief to stdout.
		fmt.Print(b.Content)
		if !strings.HasSuffix(b.Content, "\n") {
			fmt.Println()
		}
		return nil
	},
}

var planBriefListCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved executive briefs",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		metas, err := brief.ListBriefs(workdir)
		if err != nil {
			return fmt.Errorf("listing briefs: %w", err)
		}
		if len(metas) == 0 {
			fmt.Println("No saved briefs found.")
			fmt.Println("Run 'cloop plan ai-brief' to generate one.")
			return nil
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("%-29s  %-10s  %s\n", "Timestamp", "Format", "Preview")
		fmt.Println(strings.Repeat("─", 78))
		for _, m := range metas {
			ts := m.CreatedAt.Local().Format("2006-01-02 15:04:05")
			fmt.Printf("%-29s  %-10s  ", ts, string(m.Format))
			dimColor.Printf("%s\n", m.Preview)
		}
		fmt.Println(strings.Repeat("─", 78))
		fmt.Printf("Total: %d brief(s)\n", len(metas))
		return nil
	},
}

func parseBriefFormat(s string) brief.Format {
	switch strings.ToLower(s) {
	case "html":
		return brief.FormatHTML
	case "slack":
		return brief.FormatSlack
	default:
		return brief.FormatMarkdown
	}
}

func briefMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	planBriefCmd.Flags().StringVar(&briefFormat, "format", "markdown", "Output format: markdown, html, or slack")
	planBriefCmd.Flags().StringVar(&briefProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	planBriefCmd.Flags().StringVar(&briefModel, "model", "", "Model override for the AI provider")
	planBriefCmd.Flags().StringVar(&briefTimeout, "timeout", "3m", "Timeout for AI call (e.g. 2m, 90s)")
	planBriefCmd.Flags().BoolVar(&briefNoRetro, "no-retro", false, "Skip retrospective highlights")

	planBriefCmd.AddCommand(planBriefListCmd)
	planCmd.AddCommand(planBriefCmd)
}
