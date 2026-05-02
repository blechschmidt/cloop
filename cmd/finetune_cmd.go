package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/finetune"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	finetuneOutput     string
	finetuneFormat     string
	finetuneMinQuality int
	finetuneAnonymize  bool
	finetuneProvider   string
	finetuneModel      string
	finetuneTimeout    string
)

var finetuneCmd = &cobra.Command{
	Use:   "finetune",
	Short: "Fine-tuning data utilities",
	Long:  `Commands for exporting task I/O pairs as JSONL suitable for LLM fine-tuning.`,
}

var finetuneExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export completed task I/O pairs as JSONL",
	Long: `Export completed PM task execution pairs as JSONL for LLM fine-tuning.

Each exported record pairs the reconstructed execution prompt with the full AI
output for a completed task. Records can be filtered by quality score and
optionally anonymized to remove project-specific file paths.

Formats:
  openai     {"messages":[{"role":"user","content":"..."},{"role":"assistant","content":"..."}]}
  anthropic  {"prompt":"...","completion":"..."}

Examples:
  cloop finetune export                         # write to .cloop/finetune.jsonl (OpenAI format)
  cloop finetune export --output pairs.jsonl    # custom output path
  cloop finetune export --format anthropic      # Anthropic format
  cloop finetune export --min-quality 70        # skip pairs with quality < 7/10
  cloop finetune export --anonymize             # strip file paths and project names`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no plan found — run 'cloop run --pm' first")
		}

		// Validate format.
		format := finetune.Format(finetuneFormat)
		if format != finetune.FormatOpenAI && format != finetune.FormatAnthropic {
			return fmt.Errorf("unknown format %q: use 'openai' or 'anthropic'", finetuneFormat)
		}

		// Validate quality range.
		if finetuneMinQuality < 0 || finetuneMinQuality > 100 {
			return fmt.Errorf("--min-quality must be 0-100")
		}

		cfg := finetune.ExportConfig{
			WorkDir:    workdir,
			OutputPath: finetuneOutput,
			Format:     format,
			MinQuality: finetuneMinQuality,
			Anonymize:  finetuneAnonymize,
		}

		// If quality filtering is requested, we need a provider.
		if finetuneMinQuality > 0 {
			appCfg, err := config.Load(workdir)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			providerName := finetuneProvider
			if providerName == "" {
				providerName = appCfg.Provider
			}
			if providerName == "" {
				providerName = s.Provider
			}
			if providerName == "" {
				providerName = autoSelectProvider()
			}

			model := finetuneModel
			if model == "" {
				model = s.Model
			}
			if model == "" {
				switch providerName {
				case "anthropic":
					model = appCfg.Anthropic.Model
				case "openai":
					model = appCfg.OpenAI.Model
				case "ollama":
					model = appCfg.Ollama.Model
				case "claudecode":
					model = appCfg.ClaudeCode.Model
				}
			}

			timeout := 60 * time.Second
			if finetuneTimeout != "" {
				timeout, err = time.ParseDuration(finetuneTimeout)
				if err != nil {
					return fmt.Errorf("invalid --timeout: %w", err)
				}
			}

			provCfg := provider.ProviderConfig{
				Name:             providerName,
				AnthropicAPIKey:  appCfg.Anthropic.APIKey,
				AnthropicBaseURL: appCfg.Anthropic.BaseURL,
				OpenAIAPIKey:     appCfg.OpenAI.APIKey,
				OpenAIBaseURL:    appCfg.OpenAI.BaseURL,
				OllamaBaseURL:    appCfg.Ollama.BaseURL,
			}
			prov, err := provider.Build(provCfg)
			if err != nil {
				return fmt.Errorf("provider: %w", err)
			}

			cfg.EvalProvider = prov
			cfg.EvalModel = model
			cfg.EvalTimeout = timeout
		}

		dim := color.New(color.Faint)
		dim.Printf("Scanning %d tasks for completed pairs...\n", len(s.Plan.Tasks))
		if finetuneMinQuality > 0 {
			dim.Printf("Quality filter: >= %d/100 (%.1f/10)\n", finetuneMinQuality, float64(finetuneMinQuality)/10.0)
		}
		if finetuneAnonymize {
			dim.Printf("Anonymization: enabled\n")
		}
		fmt.Println()

		ctx := context.Background()
		result, err := finetune.Export(ctx, s.Plan, s.Goal, s.Instructions, cfg)
		if err != nil {
			return fmt.Errorf("export failed: %w", err)
		}

		// Determine actual output path for display.
		outPath := finetuneOutput
		if outPath == "" {
			outPath = workdir + "/.cloop/finetune.jsonl"
		}

		// Print summary.
		bold := color.New(color.Bold)
		green := color.New(color.FgGreen)
		yellow := color.New(color.FgYellow)

		bold.Printf("Fine-tune Export Summary\n")
		dim.Printf("════════════════════════════════════\n")
		fmt.Printf("  Format:          %s\n", string(format))
		fmt.Printf("  Candidates:      %d\n", result.Total)
		green.Printf("  Exported:        %d\n", result.Exported)
		if result.Skipped > 0 {
			yellow.Printf("  Skipped:         %d\n", result.Skipped)
		}
		if result.AvgQuality > 0 {
			fmt.Printf("  Avg quality:     %.2f / 10\n", result.AvgQuality)
		}
		fmt.Printf("  Est. tokens:     ~%s\n", formatTokenCount(result.Tokens))
		fmt.Println()
		bold.Printf("Output: %s\n", outPath)

		return nil
	},
}

// formatTokenCount returns a human-readable token count (e.g. "12.3K").
func formatTokenCount(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%.1fK", float64(n)/1000.0)
}

func init() {
	finetuneExportCmd.Flags().StringVarP(&finetuneOutput, "output", "o", "", "Output JSONL file path (default: .cloop/finetune.jsonl)")
	finetuneExportCmd.Flags().StringVar(&finetuneFormat, "format", "openai", "JSONL format: openai or anthropic")
	finetuneExportCmd.Flags().IntVar(&finetuneMinQuality, "min-quality", 0, "Minimum quality score (0-100); pairs below this are skipped")
	finetuneExportCmd.Flags().BoolVar(&finetuneAnonymize, "anonymize", false, "Strip file paths and project names from exported pairs")
	finetuneExportCmd.Flags().StringVar(&finetuneProvider, "provider", "", "Provider for quality scoring (requires --min-quality)")
	finetuneExportCmd.Flags().StringVar(&finetuneModel, "model", "", "Model for quality scoring")
	finetuneExportCmd.Flags().StringVar(&finetuneTimeout, "timeout", "", "Timeout per quality-scoring call (e.g. 60s, 2m)")

	finetuneCmd.AddCommand(finetuneExportCmd)
	rootCmd.AddCommand(finetuneCmd)
}
