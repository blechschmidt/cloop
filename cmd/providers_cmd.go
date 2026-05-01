package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var providersCmd = &cobra.Command{
	Use:   "providers",
	Short: "List available AI providers and their configuration status",
	Long: `Show all registered AI providers, their configuration status, and
optionally test connectivity with --test.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		testConn, _ := cmd.Flags().GetBool("test")

		okColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow)
		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)

		headerColor.Printf("Available AI Providers\n\n")

		type providerInfo struct {
			name        string
			displayName string
			configured  bool
			details     string
			model       string
			provCfg     provider.ProviderConfig
		}

		providers := []providerInfo{
			{
				name:        "claudecode",
				displayName: "Claude Code (claude CLI)",
				configured:  true, // always available if claude binary exists
				details:     "uses local claude CLI binary",
				model:       cfg.ClaudeCode.Model,
				provCfg: provider.ProviderConfig{
					Name: "claudecode",
				},
			},
			{
				name:        "anthropic",
				displayName: "Anthropic API",
				configured:  cfg.Anthropic.APIKey != "" || os.Getenv("ANTHROPIC_API_KEY") != "",
				details:     fmt.Sprintf("endpoint: %s", coalesce(cfg.Anthropic.BaseURL, "https://api.anthropic.com/v1")),
				model:       coalesce(cfg.Anthropic.Model, "claude-opus-4-6"),
				provCfg: provider.ProviderConfig{
					Name:             "anthropic",
					AnthropicAPIKey:  cfg.Anthropic.APIKey,
					AnthropicBaseURL: cfg.Anthropic.BaseURL,
				},
			},
			{
				name:        "openai",
				displayName: "OpenAI API",
				configured:  cfg.OpenAI.APIKey != "" || os.Getenv("OPENAI_API_KEY") != "",
				details:     fmt.Sprintf("endpoint: %s", coalesce(cfg.OpenAI.BaseURL, "https://api.openai.com/v1")),
				model:       coalesce(cfg.OpenAI.Model, "gpt-4o"),
				provCfg: provider.ProviderConfig{
					Name:          "openai",
					OpenAIAPIKey:  cfg.OpenAI.APIKey,
					OpenAIBaseURL: cfg.OpenAI.BaseURL,
				},
			},
			{
				name:        "ollama",
				displayName: "Ollama (local models)",
				configured:  true, // no auth needed
				details:     fmt.Sprintf("endpoint: %s", coalesce(cfg.Ollama.BaseURL, "http://localhost:11434")),
				model:       coalesce(cfg.Ollama.Model, "llama3.2"),
				provCfg: provider.ProviderConfig{
					Name:          "ollama",
					OllamaBaseURL: cfg.Ollama.BaseURL,
				},
			},
		}

		defaultProvider := coalesce(cfg.Provider, "claudecode")

		for _, p := range providers {
			isDefault := p.name == defaultProvider
			prefix := "  "
			if isDefault {
				prefix = "* "
			}

			if p.configured {
				okColor.Printf("%s%-20s", prefix, p.name)
			} else {
				warnColor.Printf("%s%-20s", prefix, p.name)
			}

			fmt.Printf(" %-28s", p.displayName)

			if p.configured {
				okColor.Printf(" configured")
			} else {
				warnColor.Printf(" not configured")
			}
			if isDefault {
				dimColor.Printf(" (default)")
			}
			fmt.Println()

			dimColor.Printf("    model: %-20s  %s\n", p.model, p.details)

			if testConn {
				fmt.Printf("    testing... ")
				status := testProvider(p.provCfg)
				if status == "" {
					okColor.Printf("OK\n")
				} else {
					warnColor.Printf("FAIL: %s\n", status)
				}
			}
		}

		fmt.Println()
		dimColor.Printf("* = default provider (set in .cloop/config.yaml)\n")
		dimColor.Printf("Use 'cloop config set provider <name>' to change default.\n")
		dimColor.Printf("Use 'cloop providers --test' to test connectivity.\n")

		return nil
	},
}

func testProvider(cfg provider.ProviderConfig) string {
	prov, err := provider.Build(cfg)
	if err != nil {
		return err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = prov.Complete(ctx, "Say 'OK' and nothing else.", provider.Options{
		MaxTokens: 10,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		return err.Error()
	}
	return ""
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	providersCmd.Flags().Bool("test", false, "Test connectivity for each provider")
	rootCmd.AddCommand(providersCmd)
}
