package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/ask"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	askProvider    string
	askModel       string
	askRecentSteps int
	askVerbose     bool
)

var askCmd = &cobra.Command{
	Use:   "ask <question>",
	Short: "Ask the AI a question about your project",
	Long: `Ask the AI anything about your project state, tasks, progress, or blockers.
The AI has full context: goal, task plan, recent activity, and project memory.

Examples:
  cloop ask "What are the remaining blockers?"
  cloop ask "Summarize what has been done so far"
  cloop ask "Which tasks failed and why?"
  cloop ask "What should I do next?"
  cloop ask "How long will the remaining tasks take?"
  cloop ask --provider anthropic "Are there any risks in the current plan?"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		question := strings.Join(args, " ")
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found — run 'cloop init' first: %w", err)
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := askProvider
		if pName == "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := askModel
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

		mem, _ := memory.Load(workdir)

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("\nAsking %s...\n\n", prov.Name())
		dimColor.Printf("Q: %s\n\n", question)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		answer, err := ask.Ask(ctx, prov, question, s, mem, model, 2*time.Minute, askRecentSteps)
		if err != nil {
			return fmt.Errorf("ask failed: %w", err)
		}

		answerColor := color.New(color.FgWhite)
		answerColor.Printf("A: %s\n\n", answer)

		return nil
	},
}

func init() {
	askCmd.Flags().StringVar(&askProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	askCmd.Flags().StringVar(&askModel, "model", "", "Model to use")
	askCmd.Flags().IntVar(&askRecentSteps, "recent-steps", 3, "Number of recent steps to include in context (0 = none)")
	askCmd.Flags().BoolVar(&askVerbose, "verbose", false, "Show the full prompt sent to the AI")
	rootCmd.AddCommand(askCmd)
}
