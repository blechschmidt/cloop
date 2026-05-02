package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/mcp"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var mcpProvider string
var mcpModel string

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start an MCP server exposing cloop as a Model Context Protocol server",
	Long: `Start a JSON-RPC 2.0 server over stdio conforming to the Model Context Protocol (MCP).

This lets Claude Desktop, Cursor, and other MCP clients directly control and
query cloop through the following tools:

  get_status     Return current orchestrator state (goal, status, step counts)
  get_plan       Return the current PM-mode task plan as JSON
  add_task       Append a new task to the plan
  complete_task  Mark a task as done with an optional result
  run_task       Execute a one-shot AI prompt and return the response

The server reads newline-delimited JSON from stdin and writes responses to stdout.
All log output goes to stderr so it does not corrupt the MCP stream.

Claude Desktop configuration example (~/.claude/claude_desktop_config.json):

  {
    "mcpServers": {
      "cloop": {
        "command": "cloop",
        "args": ["mcp"],
        "cwd": "/path/to/your/project"
      }
    }
  }`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Load config
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Load state to check for persisted provider settings
		projectState, _ := state.Load(workdir)

		// Apply CLOOP_* environment variable overrides
		applyEnvOverrides(cfg)

		// Determine provider (flag > env > config > state > auto-detect)
		providerName := mcpProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" && projectState != nil {
			providerName = projectState.Provider
		}
		if providerName == "" {
			providerName = autoSelectProvider()
		}

		// Resolve model (flag > env > config)
		model := mcpModel
		if model == "" {
			model = os.Getenv("CLOOP_MODEL")
		}
		if model == "" {
			switch providerName {
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
			Name:             providerName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}

		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("building provider: %w", err)
		}
		_ = model // model passed via Options per-call if needed

		// Log startup info to stderr (not stdout — that's the MCP stream).
		fmt.Fprintf(os.Stderr, "cloop MCP server started (provider: %s, workdir: %s)\n",
			prov.Name(), workdir)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return mcp.RunStdio(ctx, workdir, prov)
	},
}

func init() {
	mcpCmd.Flags().StringVar(&mcpProvider, "provider", "", "AI provider to use for run_task (anthropic, openai, ollama, claudecode)")
	mcpCmd.Flags().StringVar(&mcpModel, "model", "", "Model to use for run_task")
	rootCmd.AddCommand(mcpCmd)
}
