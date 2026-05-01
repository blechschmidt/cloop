package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage cloop configuration",
	Long: `Manage cloop configuration stored in .cloop/config.yaml.

Examples:
  cloop config show                          # show current config
  cloop config set provider anthropic        # set default provider
  cloop config set anthropic.api_key sk-...  # set Anthropic API key
  cloop config set anthropic.model claude-opus-4-6
  cloop config set openai.api_key sk-...
  cloop config set openai.base_url http://localhost:8080/v1
  cloop config set ollama.base_url http://localhost:11434
  cloop config set ollama.model llama3.2`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		cfg, err := config.Load(workdir)
		if err != nil {
			return err
		}

		// Mask API keys for display
		displayCfg := *cfg
		if displayCfg.Anthropic.APIKey != "" {
			displayCfg.Anthropic.APIKey = maskSecret(displayCfg.Anthropic.APIKey)
		}
		if displayCfg.OpenAI.APIKey != "" {
			displayCfg.OpenAI.APIKey = maskSecret(displayCfg.OpenAI.APIKey)
		}

		data, err := yaml.Marshal(&displayCfg)
		if err != nil {
			return err
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		headerColor.Printf("Configuration (%s)\n\n", config.ConfigPath(workdir))
		fmt.Printf("%s", string(data))
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := strings.ToLower(args[0])
		value := args[1]
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return err
		}

		if err := applyConfigKey(cfg, key, value); err != nil {
			return err
		}

		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		color.Green("Config updated: %s = %s", key, displayValue(key, value))
		return nil
	},
}

func applyConfigKey(cfg *config.Config, key, value string) error {
	switch key {
	case "provider":
		validProviders := map[string]bool{"anthropic": true, "openai": true, "ollama": true, "claudecode": true}
		if !validProviders[value] {
			return fmt.Errorf("unknown provider %q — valid: anthropic, openai, ollama, claudecode", value)
		}
		cfg.Provider = value

	case "anthropic.api_key":
		cfg.Anthropic.APIKey = value
	case "anthropic.model":
		cfg.Anthropic.Model = value
	case "anthropic.base_url":
		cfg.Anthropic.BaseURL = value

	case "openai.api_key":
		cfg.OpenAI.APIKey = value
	case "openai.model":
		cfg.OpenAI.Model = value
	case "openai.base_url":
		cfg.OpenAI.BaseURL = value

	case "ollama.base_url":
		cfg.Ollama.BaseURL = value
	case "ollama.model":
		cfg.Ollama.Model = value

	case "claudecode.model":
		cfg.ClaudeCode.Model = value

	default:
		return fmt.Errorf("unknown config key %q\n\nValid keys:\n  provider\n  anthropic.api_key, anthropic.model, anthropic.base_url\n  openai.api_key, openai.model, openai.base_url\n  ollama.base_url, ollama.model\n  claudecode.model", key)
	}
	return nil
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func displayValue(key, value string) string {
	if strings.Contains(key, "api_key") {
		return maskSecret(value)
	}
	return value
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}
