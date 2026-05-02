package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/nlcli"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	doProvider string
	doModel    string
	doYes      bool
	doTimeout  string
)

var doCmd = &cobra.Command{
	Use:   "do <natural language command>",
	Short: "Natural language CLI dispatcher — describe what you want, cloop figures out the command",
	Long: `Interpret a free-text instruction and dispatch it to the correct cloop sub-command.

The AI analyses your intent, picks the best matching cloop command with the
appropriate flags, shows you the resolved invocation, and executes it after a
confirmation step (skip with --yes).

Examples:
  cloop do "show me the current task list"
  cloop do "start a PM run with anthropic"
  cloop do "pivot the plan to focus on GraphQL"
  cloop do --yes "list all providers and test them"
  cloop do "generate a changelog"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := strings.TrimSpace(strings.Join(args, " "))
		if input == "" {
			return fmt.Errorf("instruction cannot be empty")
		}

		workdir, _ := os.Getwd()
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		s, _ := state.Load(workdir) // best-effort; state may not exist

		pName := doProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s != nil && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := doModel
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

		timeout := 30 * time.Second
		if doTimeout != "" {
			timeout, err = time.ParseDuration(doTimeout)
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

		// Collect the names of all registered top-level commands so the AI
		// knows what is available.
		available := collectCommandNames(rootCmd)

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("\ncloop do — natural language dispatcher\n")
		fmt.Printf("  Provider : %s\n", prov.Name())
		fmt.Printf("  Input    : %s\n", input)
		fmt.Println()

		dimColor.Printf("Interpreting...\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		result, err := nlcli.Interpret(ctx, prov, model, input, available)
		if err != nil {
			return fmt.Errorf("interpret: %w", err)
		}

		// Build the resolved command line for display.
		resolved := append([]string{"cloop", result.Command}, result.Args...)
		resolvedStr := strings.Join(resolved, " ")

		boldColor.Printf("Resolved command:\n")
		fmt.Printf("  %s\n\n", resolvedStr)

		if result.Explanation != "" {
			dimColor.Printf("What it does: %s\n\n", result.Explanation)
		}

		if !doYes {
			warnColor.Printf("Execute the command above? [y/N] ")
			var answer string
			fmt.Scanln(&answer) //nolint:errcheck
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				dimColor.Printf("Cancelled.\n")
				return nil
			}
			fmt.Println()
		}

		dimColor.Printf("Running: %s\n\n", resolvedStr)

		// Execute in-process: set cobra args and call Execute on the root command.
		// We build args as [command, ...flags] (without the binary name) since
		// cobra's Execute() already strips os.Args[0].
		cobraArgs := append([]string{result.Command}, result.Args...)
		rootCmd.SetArgs(cobraArgs)
		// Reset to default after execution so subsequent calls are clean.
		defer rootCmd.SetArgs(nil)

		return rootCmd.Execute()
	},
}

// collectCommandNames returns a descriptive list of all registered top-level
// commands so the AI prompt can reference them.
func collectCommandNames(root *cobra.Command) []string {
	var names []string
	for _, sub := range root.Commands() {
		if sub.Hidden {
			continue
		}
		line := sub.Use
		if sub.Short != "" {
			line += " — " + sub.Short
		}
		names = append(names, line)
	}
	return names
}

func init() {
	doCmd.Flags().StringVar(&doProvider, "provider", "", "AI provider to use for interpretation (anthropic, openai, ollama, claudecode)")
	doCmd.Flags().StringVar(&doModel, "model", "", "Model override for the AI provider")
	doCmd.Flags().StringVar(&doTimeout, "timeout", "30s", "Timeout for the AI interpretation call")
	doCmd.Flags().BoolVarP(&doYes, "yes", "y", false, "Skip confirmation prompt and execute immediately")
	rootCmd.AddCommand(doCmd)
}
