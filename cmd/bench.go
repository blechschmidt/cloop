package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/bench"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Benchmark prompt quality and speed across multiple providers",
	Long: `Send the same prompt to multiple providers concurrently and compare results.

Measures latency, token usage, cost estimate, and optional AI-rated quality.
Outputs a markdown comparison table to stdout and optionally saves to .cloop/bench-results/.

Examples:
  cloop bench --prompt "Explain how a B-tree index works"
  cloop bench --prompt "Write a Go HTTP handler" --providers anthropic,openai --runs 3
  cloop bench --prompt "Summarize REST vs GraphQL" --providers anthropic,openai,ollama --judge anthropic
  cloop bench --prompt "Design a cache layer" --output`,
	RunE: runBench,
}

func runBench(cmd *cobra.Command, args []string) error {
	prompt, _ := cmd.Flags().GetString("prompt")
	if prompt == "" && len(args) > 0 {
		prompt = strings.Join(args, " ")
	}
	if prompt == "" {
		return fmt.Errorf("--prompt is required (or pass the prompt as a positional argument)")
	}

	providersFlag, _ := cmd.Flags().GetString("providers")
	runs, _ := cmd.Flags().GetInt("runs")
	judgeProvider, _ := cmd.Flags().GetString("judge")
	outputFlag, _ := cmd.Flags().GetBool("output")
	timeoutSec, _ := cmd.Flags().GetInt("timeout")
	modelsFlag, _ := cmd.Flags().GetString("models")

	workDir, _ := os.Getwd()
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine which providers to benchmark.
	var providerNames []string
	if providersFlag != "" {
		for _, p := range strings.Split(providersFlag, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				providerNames = append(providerNames, p)
			}
		}
	} else {
		// Default: all four built-in providers.
		providerNames = []string{"anthropic", "openai", "ollama", "claudecode"}
	}

	// Parse per-provider model overrides: --models anthropic=claude-opus-4-6,openai=gpt-4o
	modelOverrides := map[string]string{}
	if modelsFlag != "" {
		for _, pair := range strings.Split(modelsFlag, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) == 2 {
				modelOverrides[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	// Build provider instances.
	providerBuilders := map[string]provider.Provider{}
	providerCfgs := map[string]provider.ProviderConfig{
		"anthropic": {
			Name:             "anthropic",
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
		},
		"openai": {
			Name:          "openai",
			OpenAIAPIKey:  cfg.OpenAI.APIKey,
			OpenAIBaseURL: cfg.OpenAI.BaseURL,
		},
		"ollama": {
			Name:          "ollama",
			OllamaBaseURL: cfg.Ollama.BaseURL,
		},
		"claudecode": {
			Name: "claudecode",
		},
	}

	headerColor := color.New(color.FgCyan, color.Bold)
	warnColor := color.New(color.FgYellow)
	dimColor := color.New(color.Faint)

	headerColor.Fprintf(os.Stderr, "\ncloop bench\n\n")
	dimColor.Fprintf(os.Stderr, "Prompt:    %s\n", prompt)
	dimColor.Fprintf(os.Stderr, "Providers: %s\n", strings.Join(providerNames, ", "))
	dimColor.Fprintf(os.Stderr, "Runs:      %d\n\n", runs)

	var skipped []string
	for _, name := range providerNames {
		pcfg, known := providerCfgs[name]
		if !known {
			// Accept unknown names and let provider.Build handle the error.
			pcfg = provider.ProviderConfig{Name: name}
		}
		p, buildErr := provider.Build(pcfg)
		if buildErr != nil {
			warnColor.Fprintf(os.Stderr, "  skip %s: %v\n", name, buildErr)
			skipped = append(skipped, name)
			continue
		}
		providerBuilders[name] = p
	}

	// Remove skipped providers from the list so the report stays clean.
	if len(skipped) > 0 {
		filtered := providerNames[:0]
		for _, n := range providerNames {
			skip := false
			for _, s := range skipped {
				if n == s {
					skip = true
					break
				}
			}
			if !skip {
				filtered = append(filtered, n)
			}
		}
		providerNames = filtered
	}

	if len(providerNames) == 0 {
		return fmt.Errorf("no providers could be built; check your configuration")
	}

	// Validate judge provider.
	if judgeProvider != "" {
		if _, ok := providerBuilders[judgeProvider]; !ok {
			// Try building it separately if not already in the bench list.
			if pcfg, known := providerCfgs[judgeProvider]; known {
				if p, buildErr := provider.Build(pcfg); buildErr == nil {
					providerBuilders[judgeProvider] = p
				} else {
					warnColor.Fprintf(os.Stderr, "warning: judge provider %q unavailable (%v); skipping quality scoring\n", judgeProvider, buildErr)
					judgeProvider = ""
				}
			} else {
				warnColor.Fprintf(os.Stderr, "warning: judge provider %q unknown; skipping quality scoring\n", judgeProvider)
				judgeProvider = ""
			}
		}
	}

	// Apply model defaults from config when not overridden by --models flag.
	if _, set := modelOverrides["anthropic"]; !set && cfg.Anthropic.Model != "" {
		modelOverrides["anthropic"] = cfg.Anthropic.Model
	}
	if _, set := modelOverrides["openai"]; !set && cfg.OpenAI.Model != "" {
		modelOverrides["openai"] = cfg.OpenAI.Model
	}
	if _, set := modelOverrides["ollama"]; !set && cfg.Ollama.Model != "" {
		modelOverrides["ollama"] = cfg.Ollama.Model
	}
	if _, set := modelOverrides["claudecode"]; !set && cfg.ClaudeCode.Model != "" {
		modelOverrides["claudecode"] = cfg.ClaudeCode.Model
	}

	fmt.Fprintf(os.Stderr, "Running benchmark")
	if judgeProvider != "" {
		fmt.Fprintf(os.Stderr, " with quality scoring by %s", judgeProvider)
	}
	fmt.Fprintln(os.Stderr, "...")

	runCfg := bench.RunConfig{
		Prompt:        prompt,
		Providers:     providerNames,
		Models:        modelOverrides,
		Runs:          runs,
		JudgeProvider: judgeProvider,
		Timeout:       time.Duration(timeoutSec) * time.Second,
	}

	ctx := cmd.Context()
	report, err := bench.Run(ctx, runCfg, providerBuilders)
	if err != nil {
		return fmt.Errorf("benchmark failed: %w", err)
	}

	// Print markdown table to stdout.
	fmt.Print(bench.FormatMarkdownTable(report))

	// Optionally save to disk.
	if outputFlag {
		path, saveErr := bench.SaveReport(workDir, report)
		if saveErr != nil {
			warnColor.Fprintf(os.Stderr, "warning: could not save report: %v\n", saveErr)
		} else {
			color.New(color.FgGreen).Fprintf(os.Stderr, "\nReport saved to %s\n", path)
		}
	}

	return nil
}

func init() {
	benchCmd.Flags().String("prompt", "", "Prompt to send to all providers (required)")
	benchCmd.Flags().String("providers", "", "Comma-separated provider list (default: anthropic,openai,ollama,claudecode)")
	benchCmd.Flags().String("models", "", "Per-provider model overrides, e.g. anthropic=claude-opus-4-6,openai=gpt-4o")
	benchCmd.Flags().Int("runs", 1, "Number of runs per provider (results are averaged)")
	benchCmd.Flags().String("judge", "", "Provider to use for quality scoring (1-10)")
	benchCmd.Flags().Bool("output", false, "Save results to .cloop/bench-results/<timestamp>.md")
	benchCmd.Flags().Int("timeout", 120, "Per-call timeout in seconds")
	rootCmd.AddCommand(benchCmd)
}
