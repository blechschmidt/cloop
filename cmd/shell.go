package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/shell"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	shellProvider string
	shellModel    string
	shellTimeout  string
	shellStream   bool
)

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Interactive conversational REPL with plan awareness",
	Long: `Start an interactive cloop shell — a REPL that combines conversational AI
with direct plan management commands.

The shell maintains a multi-turn conversation history and injects the current
plan state as context before each AI call, making it an always-on PM assistant.

Built-in commands:
  /status              Show project and plan status
  /run <task-id>       Execute a specific task via the AI provider
  /add <title>         Add a new pending task to the plan
  /done <task-id>      Mark a task as done
  /clear               Clear conversation history
  /quit                Exit the shell

Any other input is forwarded to the AI provider as a conversational message.

Examples:
  cloop shell
  cloop shell --provider anthropic
  cloop shell --stream`,
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
		pName := shellProvider
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
		model := shellModel
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
		if shellTimeout != "" {
			timeout, err = time.ParseDuration(shellTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		sh := shell.New(s, prov, model)
		sh.Timeout = timeout

		if shellStream {
			sh.OnToken = func(token string) {
				fmt.Print(token)
			}
		}

		sh.OnSave = func() error {
			return s.Save()
		}

		// Propagate Ctrl+C as a clean shutdown.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println()
			cancel()
		}()

		return sh.Run(ctx, os.Stdin, os.Stdout)
	},
}

func init() {
	shellCmd.Flags().StringVar(&shellProvider, "provider", "", "AI provider to use")
	shellCmd.Flags().StringVar(&shellModel, "model", "", "Model to use")
	shellCmd.Flags().StringVar(&shellTimeout, "timeout", "", "Response timeout per turn (e.g. 60s, 2m)")
	shellCmd.Flags().BoolVar(&shellStream, "stream", false, "Stream tokens to the terminal as they are generated")
	rootCmd.AddCommand(shellCmd)
}
