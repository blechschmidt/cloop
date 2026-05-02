package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/aipair"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	aiPairProvider string
	aiPairModel    string
	aiPairTimeout  string
)

var aiPairCmd = &cobra.Command{
	Use:   "ai-pair [task-id]",
	Short: "Streaming AI coding assistant scoped to a task",
	Long: `Start an interactive streaming AI coding pair-programming session
scoped to a specific task in your plan.

Every message you send is enriched with:
  - The active task's title, description, and status
  - Relevant source files auto-detected from the task context
  - The most recent task output artifact (if any)
  - Matching knowledge base entries

Responses stream token-by-token to the terminal.

Slash commands:
  /task              Show current task details
  /files             Re-scan and refresh relevant file context
  /done              Mark active task as done and exit
  /switch <id>       Switch to a different task (clears history)
  /clear             Clear conversation history
  /quit              Exit the session

Each session is saved to .cloop/pair-sessions/<task-id>-<timestamp>.md
for later retrieval via 'cloop search'.

Examples:
  cloop ai-pair           # pair on first pending task
  cloop ai-pair 5         # pair on task #5
  cloop ai-pair --provider anthropic 3`,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		// Resolve provider name.
		pName := aiPairProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		// Resolve model.
		model := aiPairModel
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

		timeout := 120 * time.Second
		if aiPairTimeout != "" {
			timeout, err = time.ParseDuration(aiPairTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		// Resolve optional task-id argument.
		taskID := 0
		if len(args) > 0 {
			taskID, err = strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid task-id %q: must be a number", args[0])
			}
		}

		sess, err := aipair.New(s, prov, model, workdir, taskID)
		if err != nil {
			return err
		}
		sess.Timeout = timeout
		sess.OnSave = func() error {
			return s.Save()
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println()
			cancel()
		}()

		return sess.Run(ctx, os.Stdin, os.Stdout)
	},
}

func init() {
	aiPairCmd.Flags().StringVar(&aiPairProvider, "provider", "", "AI provider to use")
	aiPairCmd.Flags().StringVar(&aiPairModel, "model", "", "Model to use")
	aiPairCmd.Flags().StringVar(&aiPairTimeout, "timeout", "", "Response timeout per turn (e.g. 60s, 2m)")
	rootCmd.AddCommand(aiPairCmd)
}
