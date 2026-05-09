package cmd

import (
	"fmt"
	"os"
	"strconv"
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
  cloop config set ollama.model llama3.2
  cloop config set notify.slack_webhook https://hooks.slack.com/services/...
  cloop config set notify.discord_webhook https://discord.com/api/webhooks/...
  cloop config set tracing.enabled true
  cloop config set tracing.endpoint http://localhost:4318
  cloop config set tracing.service_name my-project`,
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
		if displayCfg.GitHub.Token != "" {
			displayCfg.GitHub.Token = maskSecret(displayCfg.GitHub.Token)
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

		// Defence in depth: ensure the resulting config still passes the same
		// numeric bounds Load() would clamp. applyConfigKey already rejects
		// out-of-range values per-key, but a value imported earlier (or
		// hand-edited into config.yaml) could already be invalid; this catches
		// it before persistence.
		if err := cfg.ValidateNumeric(); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
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
		validProviders := map[string]bool{"anthropic": true, "openai": true, "ollama": true, "claudecode": true, "mock": true}
		if !validProviders[value] {
			return fmt.Errorf("unknown provider %q — valid: anthropic, openai, ollama, claudecode, mock", value)
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

	case "notify.slack_webhook":
		cfg.Notify.SlackWebhook = value
	case "notify.discord_webhook":
		cfg.Notify.DiscordWebhook = value

	case "webhook.url":
		cfg.Webhook.URL = value
	case "webhook.events":
		// Accept comma-separated list of event names
		if value == "" {
			cfg.Webhook.Events = nil
		} else {
			parts := strings.Split(value, ",")
			events := make([]string, 0, len(parts))
			for _, p := range parts {
				if e := strings.TrimSpace(p); e != "" {
					events = append(events, e)
				}
			}
			cfg.Webhook.Events = events
		}

	case "github.token":
		cfg.GitHub.Token = value
	case "github.repo":
		cfg.GitHub.Repo = value
	case "github.labels":
		if value == "" {
			cfg.GitHub.Labels = nil
		} else {
			parts := strings.Split(value, ",")
			labels := make([]string, 0, len(parts))
			for _, p := range parts {
				if l := strings.TrimSpace(p); l != "" {
					labels = append(labels, l)
				}
			}
			cfg.GitHub.Labels = labels
		}

	case "sync.remote":
		cfg.Sync.Remote = value
	case "sync.branch":
		cfg.Sync.Branch = value

	case "mock.responses_file":
		cfg.Mock.ResponsesFile = value
	case "mock.default":
		cfg.Mock.Default = value

	case "tracing.enabled":
		switch strings.ToLower(value) {
		case "true", "1", "yes", "on":
			cfg.Tracing.Enabled = true
		case "false", "0", "no", "off":
			cfg.Tracing.Enabled = false
		default:
			return fmt.Errorf("tracing.enabled: expected true/false, got %q", value)
		}
	case "tracing.endpoint":
		cfg.Tracing.Endpoint = value
	case "tracing.service_name":
		cfg.Tracing.ServiceName = value

	case "max_parallel":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("max_parallel: expected integer, got %q", value)
		}
		if n < config.MaxParallelLower || n > config.MaxParallelUpper {
			return fmt.Errorf("max_parallel must be between %d and %d (got %d) — use values in this range to bound the worker pool size", config.MaxParallelLower, config.MaxParallelUpper, n)
		}
		cfg.MaxParallel = n

	case "rate_limit.requests_per_second":
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("rate_limit.requests_per_second: expected number, got %q", value)
		}
		if f < config.RateLimitRPSLower {
			return fmt.Errorf("rate_limit.requests_per_second must be >= %.0f (got %.4f)", config.RateLimitRPSLower, f)
		}
		cfg.RateLimit.RequestsPerSecond = f
	case "rate_limit.burst":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("rate_limit.burst: expected integer, got %q", value)
		}
		if n < config.RateLimitBurstLower {
			return fmt.Errorf("rate_limit.burst must be >= %d (got %d)", config.RateLimitBurstLower, n)
		}
		cfg.RateLimit.Burst = n

	case "budget.monthly_usd":
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("budget.monthly_usd: expected number, got %q", value)
		}
		if f < 0 {
			return fmt.Errorf("budget.monthly_usd must be >= 0 (got %.4f) — use 0 for no monthly cap", f)
		}
		cfg.Budget.MonthlyUSD = f
	case "budget.daily_usd_limit":
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("budget.daily_usd_limit: expected number, got %q", value)
		}
		if f < 0 {
			return fmt.Errorf("budget.daily_usd_limit must be >= 0 (got %.4f) — use 0 for no daily cap", f)
		}
		cfg.Budget.DailyUSDLimit = f
	case "budget.daily_token_limit":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("budget.daily_token_limit: expected integer, got %q", value)
		}
		if n < 0 {
			return fmt.Errorf("budget.daily_token_limit must be >= 0 (got %d) — use 0 for no daily token cap", n)
		}
		cfg.Budget.DailyTokenLimit = n
	case "budget.alert_threshold_pct":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("budget.alert_threshold_pct: expected integer, got %q", value)
		}
		if n < config.AlertThresholdMin || n > config.AlertThresholdMax {
			return fmt.Errorf("budget.alert_threshold_pct must be between %d and %d (got %d)", config.AlertThresholdMin, config.AlertThresholdMax, n)
		}
		cfg.Budget.AlertThresholdPct = n
	case "budget.global_usd_pct":
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("budget.global_usd_pct: expected number, got %q", value)
		}
		if f < 0 || f > 100 {
			return fmt.Errorf("budget.global_usd_pct must be between 0 and 100 (got %.4f)", f)
		}
		cfg.Budget.GlobalUSDPct = f
	case "budget.global_token_pct":
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("budget.global_token_pct: expected number, got %q", value)
		}
		if f < 0 || f > 100 {
			return fmt.Errorf("budget.global_token_pct must be between 0 and 100 (got %.4f)", f)
		}
		cfg.Budget.GlobalTokenPct = f

	default:
		return fmt.Errorf("unknown config key %q\n\nValid keys:\n  provider\n  anthropic.api_key, anthropic.model, anthropic.base_url\n  openai.api_key, openai.model, openai.base_url\n  ollama.base_url, ollama.model\n  claudecode.model\n  mock.responses_file, mock.default\n  webhook.url, webhook.events\n  notify.slack_webhook, notify.discord_webhook\n  github.token, github.repo, github.labels\n  sync.remote, sync.branch\n  tracing.enabled, tracing.endpoint, tracing.service_name\n  max_parallel\n  rate_limit.requests_per_second, rate_limit.burst\n  budget.monthly_usd, budget.daily_usd_limit, budget.daily_token_limit\n  budget.alert_threshold_pct, budget.global_usd_pct, budget.global_token_pct", key)
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
	if strings.Contains(key, "api_key") || key == "github.token" {
		return maskSecret(value)
	}
	return value
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}
