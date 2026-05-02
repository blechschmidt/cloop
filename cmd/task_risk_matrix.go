package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/riskmatrix"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	riskMatrixProvider string
	riskMatrixModel    string
	riskMatrixTimeout  string
	riskMatrixFormat   string // "ascii" or "html"
	riskMatrixApply    bool
	riskMatrixOutput   string // output file for HTML format
	riskMatrixCached   bool   // use only cached scores, no AI call
)

var taskRiskMatrixCmd = &cobra.Command{
	Use:   "ai-risk-matrix",
	Short: "2D risk/impact quadrant visualization for pending tasks",
	Long: `Build a 2D risk/impact quadrant chart for all pending tasks.

Combines AI impact scoring (1-10) with AI risk assessment (LOW→CRITICAL)
to place each task in one of four quadrants:

  Critical  — high risk + high impact: address immediately
  Mitigate  — high risk + low impact:  high risk, low payoff; de-scope or mitigate
  Leverage  — low risk  + high impact: low risk, high value; pursue aggressively
  Defer     — low risk  + low impact:  low priority; defer or skip

Scores are cached in task metadata (risk_score / impact_score fields) so
re-renders with --cached are instant without any AI calls.

Examples:
  cloop task ai-risk-matrix
  cloop task ai-risk-matrix --apply
  cloop task ai-risk-matrix --format html --output matrix.html
  cloop task ai-risk-matrix --cached
  cloop task ai-risk-matrix --provider anthropic --model claude-opus-4-6`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Count scoreable tasks.
		activeCount := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
				activeCount++
			}
		}
		if activeCount == 0 {
			color.New(color.FgGreen).Println("No pending tasks — all tasks are complete.")
			return nil
		}

		// Validate format.
		riskMatrixFormat = strings.ToLower(riskMatrixFormat)
		if riskMatrixFormat != "ascii" && riskMatrixFormat != "html" {
			return fmt.Errorf("invalid --format %q: must be 'ascii' or 'html'", riskMatrixFormat)
		}

		var entries []riskmatrix.MatrixEntry

		if riskMatrixCached {
			// Use only cached scores — no AI call needed.
			entries = riskmatrix.BuildFromCache(s.Plan)
		} else {
			// Build provider.
			cfg, cfgErr := config.Load(workdir)
			if cfgErr != nil {
				return fmt.Errorf("loading config: %w", cfgErr)
			}
			applyEnvOverrides(cfg)

			pName := riskMatrixProvider
			if pName == "" {
				pName = cfg.Provider
			}
			if pName == "" && s.Provider != "" {
				pName = s.Provider
			}
			if pName == "" {
				pName = autoSelectProvider()
			}

			model := riskMatrixModel
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
			prov, provErr := provider.Build(provCfg)
			if provErr != nil {
				return fmt.Errorf("provider: %w", provErr)
			}

			timeout := riskmatrix.DefaultTimeout
			if riskMatrixTimeout != "" {
				timeout, err = time.ParseDuration(riskMatrixTimeout)
				if err != nil {
					return fmt.Errorf("invalid --timeout: %w", err)
				}
			}

			opts := provider.Options{
				Model:   model,
				Timeout: timeout,
			}

			headerColor := color.New(color.FgCyan, color.Bold)
			headerColor.Printf("Scoring %d pending tasks (risk + impact)...\n\n", activeCount)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			entries, err = riskmatrix.Build(ctx, prov, opts, s.Plan, riskMatrixApply)
			if err != nil {
				return fmt.Errorf("risk matrix scoring failed: %w", err)
			}

			if riskMatrixApply {
				if saveErr := s.Save(); saveErr != nil {
					return fmt.Errorf("saving state: %w", saveErr)
				}
				color.New(color.FgGreen).Printf("Scores cached on %d tasks.\n\n", len(entries))
			}
		}

		if len(entries) == 0 {
			color.New(color.Faint).Println("No entries to display.")
			return nil
		}

		switch riskMatrixFormat {
		case "html":
			html, renderErr := riskmatrix.RenderHTML(entries, s.Plan.Goal)
			if renderErr != nil {
				return fmt.Errorf("rendering HTML: %w", renderErr)
			}
			outPath := riskMatrixOutput
			if outPath == "" {
				outPath = "risk-matrix.html"
			}
			if writeErr := os.WriteFile(outPath, []byte(html), 0o644); writeErr != nil {
				return fmt.Errorf("writing HTML: %w", writeErr)
			}
			color.New(color.FgGreen).Printf("Risk matrix written to %s\n", outPath)
		default:
			fmt.Print(riskmatrix.RenderASCII(entries))
		}

		return nil
	},
}

func init() {
	taskRiskMatrixCmd.Flags().StringVar(&riskMatrixProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskRiskMatrixCmd.Flags().StringVar(&riskMatrixModel, "model", "", "Model override for the AI provider")
	taskRiskMatrixCmd.Flags().StringVar(&riskMatrixTimeout, "timeout", "", fmt.Sprintf("Timeout for AI calls (default %s)", riskmatrix.DefaultTimeout))
	taskRiskMatrixCmd.Flags().StringVar(&riskMatrixFormat, "format", "ascii", "Output format: ascii (default) or html")
	taskRiskMatrixCmd.Flags().StringVar(&riskMatrixOutput, "output", "", "Output file path for --format html (default: risk-matrix.html)")
	taskRiskMatrixCmd.Flags().BoolVar(&riskMatrixApply, "apply", false, "Cache risk/impact scores on each task in state")
	taskRiskMatrixCmd.Flags().BoolVar(&riskMatrixCached, "cached", false, "Use only cached scores; skip AI calls (instant re-render)")

	taskCmd.AddCommand(taskRiskMatrixCmd)
}
