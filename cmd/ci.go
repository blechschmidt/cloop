package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/cipipe"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	ciPlatform string
	ciOutput   string
	ciProvider string
	ciModel    string
	ciTimeout  string
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "AI-generated CI/CD pipeline management",
}

var ciGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a CI pipeline config from the project tech stack and task plan",
	Long: `Detects the project's tech stack (Go, Node.js, Python, Docker, Makefile, etc.)
and generates a CI/CD pipeline YAML tailored to that stack.

The generated pipeline includes build, test, and lint stages plus a cloop-aware
step that installs cloop and runs 'cloop status'.

When --output - is given the YAML is printed to stdout instead of written to disk.

Examples:
  cloop ci generate                              # auto-detect; write to .github/workflows/cloop-ci.yml
  cloop ci generate --platform gitlab            # GitLab CI (.gitlab-ci.yml)
  cloop ci generate --platform circleci          # CircleCI (.circleci/config.yml)
  cloop ci generate --output ci.yml              # custom output path
  cloop ci generate --output -                   # print to stdout`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		// Resolve platform
		platform := cipipe.Platform(ciPlatform)
		switch platform {
		case cipipe.PlatformGitHub, cipipe.PlatformGitLab, cipipe.PlatformCircleCI:
			// valid
		default:
			return fmt.Errorf("unknown platform %q — choose github, gitlab, or circleci", ciPlatform)
		}

		// Resolve output path
		outputPath := ciOutput
		if outputPath == "" {
			outputPath = cipipe.DefaultOutputPath(platform)
		}
		toStdout := outputPath == "-"

		// Load config + state (optional — we still work without a plan)
		cfg, _ := config.Load(workDir)
		if cfg == nil {
			cfg = &config.Config{}
		}
		applyEnvOverrides(cfg)

		s, _ := state.Load(workDir)

		// Detect tech stack
		stack := cipipe.Detect(workDir)

		// Provider selection
		pName := ciProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s != nil && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		// Model selection
		model := ciModel
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
		if model == "" && s != nil {
			model = s.Model
		}

		timeout := 3 * time.Minute
		if ciTimeout != "" {
			var err error
			timeout, err = time.ParseDuration(ciTimeout)
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

		if !toStdout {
			headerColor := color.New(color.FgCyan, color.Bold)
			headerColor.Printf("\ncloop ci generate\n")
			fmt.Printf("  Platform : %s\n", platform)
			fmt.Printf("  Provider : %s\n", prov.Name())
			langs := stack.Languages()
			if len(langs) > 0 {
				fmt.Printf("  Stack    : %s", langs[0])
				for _, l := range langs[1:] {
					fmt.Printf(", %s", l)
				}
				fmt.Println()
			} else {
				fmt.Printf("  Stack    : (generic)\n")
			}
			if s != nil && s.PMMode && s.Plan != nil {
				fmt.Printf("  Plan     : %d tasks\n", len(s.Plan.Tasks))
			}
			fmt.Printf("  Output   : %s\n\n", outputPath)
			color.New(color.Faint).Printf("Generating pipeline...\n\n")
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Build the plan reference (nil if not in PM mode)
		var pmPlan *pm.Plan
		if s != nil && s.PMMode && s.Plan != nil {
			pmPlan = s.Plan
		}

		yaml, err := cipipe.Generate(ctx, prov, model, platform, stack, pmPlan)
		if err != nil {
			return err
		}

		if toStdout {
			fmt.Println(yaml)
			return nil
		}

		if err := cipipe.Write(outputPath, yaml+"\n"); err != nil {
			return err
		}

		color.New(color.FgGreen, color.Bold).Printf("Pipeline written to: %s\n\n", outputPath)
		color.New(color.Faint).Printf("Tip: commit %s and push to trigger your first CI run.\n\n", outputPath)
		return nil
	},
}

func init() {
	ciGenerateCmd.Flags().StringVar(&ciPlatform, "platform", "github", "CI platform: github, gitlab, or circleci")
	ciGenerateCmd.Flags().StringVar(&ciOutput, "output", "", "Output file path (use - for stdout; default: platform-specific)")
	ciGenerateCmd.Flags().StringVar(&ciProvider, "provider", "", "AI provider override")
	ciGenerateCmd.Flags().StringVar(&ciModel, "model", "", "Model override")
	ciGenerateCmd.Flags().StringVar(&ciTimeout, "timeout", "3m", "Timeout for the AI call")

	ciCmd.AddCommand(ciGenerateCmd)
	rootCmd.AddCommand(ciCmd)
}
