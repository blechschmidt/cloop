package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/explain"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	explainProvider string
	explainModel    string
	explainTimeout  string
	explainConfirm  bool
)

var explainCmd = &cobra.Command{
	Use:   "explain [task-id]",
	Short: "AI narration of what each pending task will do before execution",
	Long: `Generate a human-readable walkthrough of what each task (or a specific task)
will do before any execution occurs.

For each task the AI narrates:
  • Files likely to be touched
  • Commands likely to run
  • Risks and potential side effects
  • Success criteria

With --confirm, you are prompted to approve the plan before being handed off to
'cloop run'.

Examples:
  cloop explain                      # narrate all pending tasks
  cloop explain 3                    # narrate only task #3
  cloop explain --confirm            # narrate then prompt before running
  cloop explain --provider anthropic # use a specific provider`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		taskID := ""
		if len(args) > 0 {
			taskID = args[0]
		}

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

		pName := explainProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := explainModel
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
		if explainTimeout != "" {
			timeout, err = time.ParseDuration(explainTimeout)
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

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("\ncloop explain — pre-execution task narration\n")
		fmt.Printf("  Provider: %s\n", prov.Name())
		fmt.Printf("  Goal: %s\n", truncate(s.Goal, 80))
		if taskID != "" {
			fmt.Printf("  Task: #%s\n", taskID)
		} else {
			fmt.Printf("  Scope: all pending tasks\n")
		}
		fmt.Println()
		dimColor.Printf("Generating narration...\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		narration, err := explain.Explain(ctx, prov, model, s.Plan, taskID)
		if err != nil {
			return fmt.Errorf("explain: %w", err)
		}

		sep := strings.Repeat("─", 70)
		fmt.Println(sep)
		fmt.Println(narration)
		fmt.Println(sep)
		fmt.Println()

		if explainConfirm {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Proceed with 'cloop run --pm'? [y/N] ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(strings.ToLower(line))
			if line != "y" && line != "yes" {
				dimColor.Printf("Execution cancelled.\n")
				return nil
			}
			// Hand off to run command.
			runCmd.Flags().Set("pm", "true") //nolint:errcheck
			return runCmd.RunE(runCmd, []string{})
		}

		dimColor.Printf("Run 'cloop run --pm' to execute the plan.\n")
		return nil
	},
}

func init() {
	explainCmd.Flags().StringVar(&explainProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	explainCmd.Flags().StringVar(&explainModel, "model", "", "Model override for the AI provider")
	explainCmd.Flags().StringVar(&explainTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 90s)")
	explainCmd.Flags().BoolVar(&explainConfirm, "confirm", false, "Prompt for approval and hand off to 'cloop run --pm' if approved")
	rootCmd.AddCommand(explainCmd)
}
