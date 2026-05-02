package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/query"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	queryProvider string
	queryModel    string
	queryTimeout  string
)

var taskQueryCmd = &cobra.Command{
	Use:   "query <question>",
	Short: "Answer a natural language question about the current plan",
	Long: `Use the configured AI provider to answer natural language questions
about the current plan. The plan context (titles, statuses, dependencies,
tags, annotations, and results) is included automatically.

Examples:
  cloop task query "which tasks are blocked?"
  cloop task query "what is the critical path?"
  cloop task query "summarize what failed and why"
  cloop task query "which tasks are in progress?"
  cloop task query "how many tasks remain?"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		question := strings.Join(args, " ")

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := queryProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := queryModel
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

		timeout := 2 * time.Minute
		if queryTimeout != "" {
			timeout, err = time.ParseDuration(queryTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		answer, err := query.Query(ctx, prov, model, s.Plan, question)
		if err != nil {
			return err
		}

		fmt.Println(answer)
		return nil
	},
}

func init() {
	taskQueryCmd.Flags().StringVar(&queryProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskQueryCmd.Flags().StringVar(&queryModel, "model", "", "Model override for the AI provider")
	taskQueryCmd.Flags().StringVar(&queryTimeout, "timeout", "2m", "Timeout for the AI call (e.g. 1m, 90s)")

	taskCmd.AddCommand(taskQueryCmd)
}
