package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/configdiff"
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

	case "ui.max_websocket_conns":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("ui.max_websocket_conns: expected integer, got %q", value)
		}
		if n != 0 && (n < config.WebSocketConnsLower || n > config.WebSocketConnsUpper) {
			return fmt.Errorf("ui.max_websocket_conns must be between %d and %d (or 0 to use the default %d) (got %d)",
				config.WebSocketConnsLower, config.WebSocketConnsUpper, config.WebSocketConnsDefault, n)
		}
		cfg.UI.MaxWebSocketConns = n
	case "ui.max_websocket_conns_per_ip":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("ui.max_websocket_conns_per_ip: expected integer, got %q", value)
		}
		if n != 0 && (n < config.WebSocketConnsPerIPLower || n > config.WebSocketConnsPerIPUpper) {
			return fmt.Errorf("ui.max_websocket_conns_per_ip must be between %d and %d (or 0 to use the default %d) (got %d)",
				config.WebSocketConnsPerIPLower, config.WebSocketConnsPerIPUpper, config.WebSocketConnsPerIPDefault, n)
		}
		cfg.UI.MaxWebSocketConnsPerIP = n

	default:
		return fmt.Errorf("unknown config key %q\n\nValid keys:\n  provider\n  anthropic.api_key, anthropic.model, anthropic.base_url\n  openai.api_key, openai.model, openai.base_url\n  ollama.base_url, ollama.model\n  claudecode.model\n  mock.responses_file, mock.default\n  webhook.url, webhook.events\n  notify.slack_webhook, notify.discord_webhook\n  github.token, github.repo, github.labels\n  sync.remote, sync.branch\n  tracing.enabled, tracing.endpoint, tracing.service_name\n  max_parallel\n  rate_limit.requests_per_second, rate_limit.burst\n  budget.monthly_usd, budget.daily_usd_limit, budget.daily_token_limit\n  budget.alert_threshold_pct, budget.global_usd_pct, budget.global_token_pct\n  ui.max_websocket_conns, ui.max_websocket_conns_per_ip", key)
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

// configDiffCmd compares the canonical YAML against the SQLite mirror so the
// operator can see exactly what's drifted before deciding which way to sync.
//
// Exit codes:
//
//	0 — sources are in sync (no drift).
//	1 — drift detected (or unexpected error). See stderr/stdout for details.
//
// We return a non-zero exit specifically on drift so this command can be
// used in CI / pre-commit hooks to fail-fast when an operator forgot to
// commit a `cloop config set` change.
var configDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare .cloop/config.yaml against the SQLite-mirrored copy",
	Long: `Show key-by-key differences between the canonical .cloop/config.yaml file
and the copy stored in .cloop/state.db (written by every 'cloop config set'
or programmatic config.Save). Drift here means a tool reading from one store
will see different values than a tool reading from the other.

Exit code is 0 when the two are in sync, 1 otherwise — suitable for CI gates.

To resolve drift, run 'cloop config sync' (default --from-yaml) or
'cloop config sync --from-db' to recover a missing or corrupted YAML.

Sensitive values (api keys, tokens, webhook secrets) are masked in the output.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// This is not a CLI-usage error class — silence Cobra's auto-help
		// dump on returned errors (matches the convention from Task 20076).
		cmd.SilenceUsage = true

		workdir, _ := os.Getwd()
		rep, err := configdiff.Compute(workdir)
		if err != nil {
			return err
		}
		fmt.Print(configdiff.Render(rep))
		if rep.HasDrift() {
			os.Exit(1)
		}
		return nil
	},
}

// configSyncCmd resolves drift by overwriting one source with the other.
// Default direction is from-yaml because YAML is the canonical, human-edited
// source — Load() already prefers it, so making the SQLite mirror agree is
// the natural recovery path.
var configSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Resolve drift between .cloop/config.yaml and the SQLite mirror",
	Long: `Resolve config drift by copying one source over the other.

By default, --from-yaml is used: the YAML file is the canonical store and
the SQLite mirror is rebuilt from it. Pass --from-db to recover the YAML
from the SQLite copy — useful when config.yaml has been accidentally
deleted or truncated.

Either direction passes the rehydrated config through validateAndClamp
before the destination store is rewritten, so a corrupt source can never
propagate silently.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		fromYAML, _ := cmd.Flags().GetBool("from-yaml")
		fromDB, _ := cmd.Flags().GetBool("from-db")
		if fromYAML && fromDB {
			return fmt.Errorf("--from-yaml and --from-db are mutually exclusive")
		}
		dir := configdiff.FromYAML
		if fromDB {
			dir = configdiff.FromDB
		}

		workdir, _ := os.Getwd()
		if err := configdiff.Sync(workdir, dir); err != nil {
			return err
		}

		// Re-compute and report the post-sync state so the user can confirm
		// the drift is gone. This costs one extra SQLite read but it's
		// cheap and the operator-facing reassurance is worth it.
		rep, err := configdiff.Compute(workdir)
		if err != nil {
			color.Yellow("Sync succeeded but post-check failed: %v", err)
			return nil
		}
		if rep.HasDrift() {
			color.Yellow("Sync ran but residual drift remains:")
			fmt.Print(configdiff.Render(rep))
			return nil
		}
		color.Green("Config is now in sync (%s).", dir)
		return nil
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configDiffCmd)
	configCmd.AddCommand(configSyncCmd)

	configSyncCmd.Flags().Bool("from-yaml", false, "overwrite SQLite mirror from .cloop/config.yaml (default)")
	configSyncCmd.Flags().Bool("from-db", false, "overwrite .cloop/config.yaml from SQLite mirror")

	rootCmd.AddCommand(configCmd)
}
