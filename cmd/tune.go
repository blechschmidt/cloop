package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/spf13/cobra"
)

var tuneCmd = &cobra.Command{
	Use:   "tune [anthropic|openai|ollama|all]",
	Short: "Interactively configure model inference parameters per provider",
	Long: `Tune lets you set model inference parameters (temperature, top-p, max-tokens,
frequency-penalty) for each provider. Values are stored in .cloop/config.yaml
and used by default on every subsequent run.

Use --temperature / --top-p / --max-tokens on 'cloop run' for one-shot overrides
without changing the stored configuration.

Examples:
  cloop tune              # tune the active provider
  cloop tune anthropic    # tune Anthropic parameters only
  cloop tune openai       # tune OpenAI parameters
  cloop tune ollama       # tune Ollama parameters
  cloop tune all          # tune all providers`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		target := ""
		if len(args) > 0 {
			target = strings.ToLower(args[0])
		}
		if target == "" {
			// Default to the active provider
			target = cfg.Provider
			if target == "" {
				target = "all"
			}
		}

		scanner := bufio.NewScanner(os.Stdin)

		switch target {
		case "anthropic":
			tuneAnthropic(scanner, cfg)
		case "openai":
			tuneOpenAI(scanner, cfg)
		case "ollama":
			tuneOllama(scanner, cfg)
		case "all":
			tuneAnthropic(scanner, cfg)
			tuneOpenAI(scanner, cfg)
			tuneOllama(scanner, cfg)
		default:
			return fmt.Errorf("unknown provider %q — valid options: anthropic, openai, ollama, all", target)
		}

		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
		fmt.Println("\nConfiguration saved to .cloop/config.yaml")
		return nil
	},
}

func tuneAnthropic(scanner *bufio.Scanner, cfg *config.Config) {
	fmt.Println("\n=== Anthropic inference parameters ===")
	fmt.Println("These apply when using --provider anthropic.")
	fmt.Println()

	cfg.Anthropic.Temperature = promptFloatPtr(scanner, "temperature",
		cfg.Anthropic.Temperature, 0, 1,
		"Controls randomness. 0 = deterministic, 1 = most creative.")
	cfg.Anthropic.TopP = promptFloatPtr(scanner, "top-p",
		cfg.Anthropic.TopP, 0, 1,
		"Nucleus sampling. 1 = consider all tokens, 0.9 = top 90%.")
	cfg.Anthropic.MaxTokens = promptInt(scanner, "max-tokens",
		cfg.Anthropic.MaxTokens, 0, 32000,
		"Maximum output tokens per response. 0 = provider default (8192).")
}

func tuneOpenAI(scanner *bufio.Scanner, cfg *config.Config) {
	fmt.Println("\n=== OpenAI inference parameters ===")
	fmt.Println("These apply when using --provider openai.")
	fmt.Println()

	cfg.OpenAI.Temperature = promptFloatPtr(scanner, "temperature",
		cfg.OpenAI.Temperature, 0, 2,
		"Controls randomness. 0 = deterministic, 2 = most creative.")
	cfg.OpenAI.TopP = promptFloatPtr(scanner, "top-p",
		cfg.OpenAI.TopP, 0, 1,
		"Nucleus sampling. 1 = consider all tokens, 0.9 = top 90%.")
	cfg.OpenAI.FrequencyPenalty = promptFloatPtr(scanner, "frequency-penalty",
		cfg.OpenAI.FrequencyPenalty, -2, 2,
		"Reduces repetition. 0 = no penalty, 2 = strong penalty.")
	cfg.OpenAI.MaxTokens = promptInt(scanner, "max-tokens",
		cfg.OpenAI.MaxTokens, 0, 128000,
		"Maximum output tokens per response. 0 = provider default.")
}

func tuneOllama(scanner *bufio.Scanner, cfg *config.Config) {
	fmt.Println("\n=== Ollama inference parameters ===")
	fmt.Println("These apply when using --provider ollama.")
	fmt.Println()

	cfg.Ollama.Temperature = promptFloatPtr(scanner, "temperature",
		cfg.Ollama.Temperature, 0, 1,
		"Controls randomness. 0 = deterministic, 1 = most creative.")
	cfg.Ollama.TopP = promptFloatPtr(scanner, "top-p",
		cfg.Ollama.TopP, 0, 1,
		"Nucleus sampling. 1 = consider all tokens, 0.9 = top 90%.")
	cfg.Ollama.MaxTokens = promptInt(scanner, "max-tokens",
		cfg.Ollama.MaxTokens, 0, 128000,
		"Maximum output tokens (num_predict). 0 = provider default.")
}

// promptFloatPtr shows the current value for a float parameter and prompts for a new one.
// Returns nil to clear the value (use provider default), or a pointer to the entered value.
func promptFloatPtr(scanner *bufio.Scanner, name string, current *float64, min, max float64, hint string) *float64 {
	currentStr := "default"
	if current != nil {
		currentStr = strconv.FormatFloat(*current, 'f', -1, 64)
	}
	fmt.Printf("  %s [%g–%g, current: %s]\n", name, min, max, currentStr)
	fmt.Printf("    %s\n", hint)
	fmt.Printf("    Enter value, or press Enter to keep [%s], or 'clear' to reset to default: ", currentStr)

	if !scanner.Scan() {
		return current
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		return current
	}
	if strings.ToLower(input) == "clear" {
		fmt.Printf("    -> cleared (provider default)\n")
		return nil
	}

	v, err := strconv.ParseFloat(input, 64)
	if err != nil {
		fmt.Printf("    Invalid number %q — keeping current value.\n", input)
		return current
	}
	if v < min || v > max {
		fmt.Printf("    Value %g out of range [%g–%g] — keeping current value.\n", v, min, max)
		return current
	}
	fmt.Printf("    -> set to %g\n", v)
	return &v
}

// promptInt shows the current value for an integer parameter and prompts for a new one.
// Returns 0 to use provider default.
func promptInt(scanner *bufio.Scanner, name string, current, min, max int, hint string) int {
	currentStr := "default"
	if current > 0 {
		currentStr = strconv.Itoa(current)
	}
	fmt.Printf("  %s [%d–%d, current: %s]\n", name, min, max, currentStr)
	fmt.Printf("    %s\n", hint)
	fmt.Printf("    Enter value, or press Enter to keep [%s], or 0 to reset to default: ", currentStr)

	if !scanner.Scan() {
		return current
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		return current
	}

	v, err := strconv.Atoi(input)
	if err != nil {
		fmt.Printf("    Invalid integer %q — keeping current value.\n", input)
		return current
	}
	if v < min || v > max {
		fmt.Printf("    Value %d out of range [%d–%d] — keeping current value.\n", v, min, max)
		return current
	}
	if v == 0 {
		fmt.Printf("    -> reset to default\n")
	} else {
		fmt.Printf("    -> set to %d\n", v)
	}
	return v
}

func init() {
	rootCmd.AddCommand(tuneCmd)
}
