package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/summarize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	summarizeProvider string
	summarizeModel    string
	summarizeFormat   string
	summarizeSince    string
	summarizeOutput   string
	summarizeCopy     bool
	summarizeTimeout  string
)

var taskSummarizeCmd = &cobra.Command{
	Use:   "summarize",
	Short: "AI executive summary of completed work for stakeholder communication",
	Long: `Generate a concise, stakeholder-ready executive summary of all completed
work in the current plan.

Unlike 'cloop retro' (process retrospective) or 'cloop report' (status overview),
this command targets non-technical stakeholders: product owners, executives, and
investors. It focuses on business value and outcomes.

The summary includes:
  (1) A one-paragraph high-level overview
  (2) Key accomplishments grouped by theme
  (3) Notable decisions made during execution
  (4) Remaining risks and open concerns

The result is saved to .cloop/summaries/<timestamp>.<ext> automatically.

Examples:
  cloop task summarize
  cloop task summarize --format html
  cloop task summarize --format json
  cloop task summarize --since 3              # only work done since snapshot v3
  cloop task summarize --copy                 # also copy to clipboard
  cloop task summarize --format md -o exec.md # write to specific file
  cloop task summarize --provider anthropic --model claude-opus-4-5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' first")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		// Resolve provider and model.
		pName := summarizeProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := summarizeModel
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

		timeout := 3 * time.Minute
		if summarizeTimeout != "" {
			timeout, err = time.ParseDuration(summarizeTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		// Parse --since snapshot version.
		sinceVersion := 0
		if summarizeSince != "" {
			if _, scanErr := fmt.Sscanf(summarizeSince, "%d", &sinceVersion); scanErr != nil {
				return fmt.Errorf("--since must be a snapshot version number (e.g. --since 3)")
			}
		}

		// Collect task contexts.
		tasks := summarize.CollectTaskContexts(workdir, s.Plan, sinceVersion)
		if len(tasks) == 0 {
			if sinceVersion > 0 {
				return fmt.Errorf("no completed tasks found since snapshot v%d", sinceVersion)
			}
			return fmt.Errorf("no completed tasks found — mark some tasks as done first")
		}

		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)

		sinceLabel := summarizeSince
		goal := s.Goal
		if s.Plan.Goal != "" {
			goal = s.Plan.Goal
		}

		headerColor.Printf("Generating executive summary for %d completed task(s)...\n\n", len(tasks))
		dimColor.Printf("Provider: %s\n\n", prov.Name())

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		summary, err := summarize.Generate(ctx, prov, model, timeout, goal, tasks, sinceLabel)
		if err != nil {
			return fmt.Errorf("summary generation failed: %w", err)
		}

		// Render in the requested format.
		format := summarizeFormat
		if format == "" {
			format = "markdown"
		}

		var content string
		var fileExt string
		switch format {
		case "html":
			content = summarize.FormatHTML(summary, goal, len(tasks), sinceLabel)
			fileExt = "html"
		case "json":
			content = summarize.FormatJSON(summary)
			fileExt = "json"
		default: // markdown / md
			content = summarize.FormatMarkdown(summary, goal, len(tasks), sinceLabel)
			fileExt = "md"
			format = "markdown"
		}

		// Always save to .cloop/summaries/.
		savedPath, saveErr := summarize.SaveToFile(workdir, content, fileExt)
		if saveErr != nil {
			dimColor.Printf("Warning: could not save summary file: %v\n", saveErr)
		}

		// Write to explicit --output file if provided.
		outputDest := summarizeOutput
		if outputDest != "" {
			if err := os.WriteFile(outputDest, []byte(content), 0o644); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
		}

		// Print to stdout (terminal output unless redirected).
		if outputDest == "" {
			if format == "markdown" {
				printSummaryTerminal(summary)
			} else {
				fmt.Print(content)
			}
		}

		// Copy to clipboard if requested.
		if summarizeCopy {
			if copyErr := summarize.CopyToClipboard(content); copyErr != nil {
				color.New(color.FgYellow).Printf("Warning: clipboard copy failed: %v\n", copyErr)
			} else {
				color.New(color.FgGreen).Printf("Copied to clipboard.\n")
			}
		}

		fmt.Println()
		if savedPath != "" {
			color.New(color.FgGreen).Printf("Summary saved: %s\n", savedPath)
		}
		if outputDest != "" {
			color.New(color.FgGreen).Printf("Summary written: %s\n", outputDest)
		}

		return nil
	},
}

// printSummaryTerminal renders a Summary for human-readable terminal output.
func printSummaryTerminal(s *summarize.Summary) {
	header := color.New(color.FgCyan, color.Bold)
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	accent := color.New(color.FgYellow)
	warn := color.New(color.FgRed)

	header.Printf("Executive Summary\n")
	header.Printf("═════════════════\n\n")

	if s.HighLevel != "" {
		bold.Printf("Overview\n")
		dim.Printf("────────\n")
		fmt.Printf("%s\n\n", s.HighLevel)
	}

	if len(s.Accomplishments) > 0 {
		bold.Printf("Key Accomplishments\n")
		dim.Printf("───────────────────\n")
		for _, group := range s.Accomplishments {
			accent.Printf("  %s\n", group.Theme)
			for _, item := range group.Items {
				dim.Printf("    • ")
				fmt.Printf("%s\n", item)
			}
		}
		fmt.Println()
	}

	if len(s.Decisions) > 0 {
		bold.Printf("Notable Decisions\n")
		dim.Printf("─────────────────\n")
		for i, d := range s.Decisions {
			accent.Printf("  %d. ", i+1)
			fmt.Printf("%s\n", d)
		}
		fmt.Println()
	}

	if len(s.Risks) > 0 {
		bold.Printf("Remaining Risks\n")
		dim.Printf("───────────────\n")
		for _, r := range s.Risks {
			warn.Printf("  ⚠ ")
			fmt.Printf("%s\n", r)
		}
		fmt.Println()
	}
}

func init() {
	taskSummarizeCmd.Flags().StringVar(&summarizeProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskSummarizeCmd.Flags().StringVar(&summarizeModel, "model", "", "Model override")
	taskSummarizeCmd.Flags().StringVar(&summarizeFormat, "format", "markdown", "Output format: markdown (default), html, json")
	taskSummarizeCmd.Flags().StringVar(&summarizeSince, "since", "", "Only summarize tasks completed after this snapshot version (e.g. --since 3)")
	taskSummarizeCmd.Flags().StringVarP(&summarizeOutput, "output", "o", "", "Write output to a specific file path")
	taskSummarizeCmd.Flags().BoolVar(&summarizeCopy, "copy", false, "Copy output to clipboard (requires xclip, xsel, or pbcopy)")
	taskSummarizeCmd.Flags().StringVar(&summarizeTimeout, "timeout", "3m", "Timeout for AI call (e.g. 2m, 180s)")

}
