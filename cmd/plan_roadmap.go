package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/roadmap"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	roadmapQuarters int
	roadmapFormat   string
	roadmapProvider string
	roadmapModel    string
	roadmapTimeout  string
	roadmapNoSave   bool
)

var planRoadmapCmd = &cobra.Command{
	Use:   "ai-roadmap",
	Short: "Generate a quarterly milestone roadmap from the task plan",
	Long: `Use AI to cluster the task plan into quarters with milestones and narratives.

Each quarter includes:
  - A short theme label summarizing the quarter's focus
  - A 2-3 sentence narrative explaining expected outcomes
  - Milestones grouping related tasks

Output formats:
  --format ascii      ASCII timeline (default, terminal-friendly)
  --format markdown   GitHub-flavored Markdown
  --format html       Self-contained styled HTML

Examples:
  cloop plan ai-roadmap
  cloop plan ai-roadmap --quarters 2
  cloop plan ai-roadmap --format markdown > ROADMAP.md
  cloop plan ai-roadmap --format html --no-save > roadmap.html`,
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

		pName := roadmapProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := roadmapModel
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
		if roadmapTimeout != "" {
			timeout, err = time.ParseDuration(roadmapTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		outputFormat := parseRoadmapFormat(roadmapFormat)

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

		quarters := roadmapQuarters
		if quarters < 1 {
			quarters = 4
		}

		// Status to stderr so it doesn't pollute piped output.
		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		headerColor.Fprintf(os.Stderr, "\ncloop plan ai-roadmap — quarterly milestone roadmap\n")
		dimColor.Fprintf(os.Stderr, "  Provider: %s | Quarters: %d | Format: %s | Tasks: %d\n\n",
			prov.Name(), quarters, roadmapFormat, len(s.Plan.Tasks))
		dimColor.Fprintln(os.Stderr, "Generating roadmap...")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		rm, err := roadmap.Build(ctx, prov, model, s.Plan, quarters)
		if err != nil {
			return fmt.Errorf("generating roadmap: %w", err)
		}

		// Save unless --no-save.
		if !roadmapNoSave {
			savedPath, saveErr := roadmap.Save(workdir, rm, outputFormat)
			if saveErr != nil {
				color.New(color.FgYellow).Fprintf(os.Stderr, "warning: could not save roadmap: %v\n", saveErr)
			} else {
				dimColor.Fprintf(os.Stderr, "Saved to: %s\n\n", savedPath)
			}
		}

		// Render and print to stdout.
		var content string
		switch outputFormat {
		case roadmap.FormatHTML:
			content = roadmap.RenderHTML(rm)
		case roadmap.FormatMarkdown:
			content = roadmap.RenderMarkdown(rm)
		default:
			content = roadmap.RenderASCII(rm)
		}

		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	},
}

func parseRoadmapFormat(s string) roadmap.Format {
	switch strings.ToLower(s) {
	case "html":
		return roadmap.FormatHTML
	case "markdown", "md":
		return roadmap.FormatMarkdown
	default:
		return roadmap.FormatASCII
	}
}

func init() {
	planRoadmapCmd.Flags().IntVar(&roadmapQuarters, "quarters", 4, "Number of quarters to generate (1-8)")
	planRoadmapCmd.Flags().StringVar(&roadmapFormat, "format", "ascii", "Output format: ascii, markdown, or html")
	planRoadmapCmd.Flags().StringVar(&roadmapProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	planRoadmapCmd.Flags().StringVar(&roadmapModel, "model", "", "Model override for the AI provider")
	planRoadmapCmd.Flags().StringVar(&roadmapTimeout, "timeout", "3m", "Timeout for AI call (e.g. 2m, 90s)")
	planRoadmapCmd.Flags().BoolVar(&roadmapNoSave, "no-save", false, "Do not save the roadmap to .cloop/roadmaps/")

	planCmd.AddCommand(planRoadmapCmd)
}
