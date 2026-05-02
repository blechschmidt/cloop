// Package config manages the .cloop/config.yaml project configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

const configFile = ".cloop/config.yaml"

// Config is the project configuration loaded from .cloop/config.yaml.
type Config struct {
	// Default provider: anthropic, openai, ollama, claudecode, mock
	Provider string `yaml:"provider"`

	Anthropic  AnthropicConfig  `yaml:"anthropic"`
	OpenAI     OpenAIConfig     `yaml:"openai"`
	Ollama     OllamaConfig     `yaml:"ollama"`
	ClaudeCode ClaudeCodeConfig `yaml:"claudecode"`
	Mock       MockConfig       `yaml:"mock,omitempty"`
	Webhook    WebhookConfig    `yaml:"webhook,omitempty"`
	GitHub     GitHubConfig     `yaml:"github,omitempty"`
	// Router maps task roles to provider names for heterogeneous multi-agent execution.
	// Example: router.backend = "anthropic", router.frontend = "openai"
	Router RouterConfig `yaml:"router,omitempty"`
	// Hooks defines shell commands to run at task and plan lifecycle events.
	Hooks HooksConfig `yaml:"hooks,omitempty"`

	// MaxParallel sets the default worker pool size for parallel PM mode.
	// 0 means no limit (all ready tasks run concurrently).
	// Overridden by --max-parallel / -j on the command line.
	MaxParallel int `yaml:"max_parallel,omitempty"`

	// Watch configures the file-watch mode for `cloop watch --glob`.
	Watch WatchConfig `yaml:"watch,omitempty"`

	// Notify configures Slack and Discord incoming webhook notifications.
	Notify NotifyConfig `yaml:"notify,omitempty"`

	// Sync configures git-based team plan sharing and merging.
	Sync SyncConfig `yaml:"sync,omitempty"`

	// LogJSON switches all cloop output to newline-delimited JSON (NDJSON).
	// Equivalent to passing --log-json on the command line.
	// Each structured event is emitted as a JSON object with fields:
	//   time, level, event, task_id, message, data
	LogJSON bool `yaml:"log_json,omitempty"`

	// Budget configures monthly spend limits.
	Budget BudgetConfig `yaml:"budget,omitempty"`

	// CalibrationFactor is set by 'cloop task effort-calibrate --apply'.
	// When non-zero and != 1.0, Decompose() multiplies every AI-generated
	// time_estimate_minutes value by this factor before storing the task.
	// This closes the feedback loop between historical actuals and future plans.
	CalibrationFactor float64 `yaml:"calibration_factor,omitempty"`
}

// WatchConfig configures file-triggered plan re-evaluation.
type WatchConfig struct {
	// Globs are file patterns to monitor (e.g. "**/*.go").
	// Used as defaults when --glob is not specified on the command line.
	Globs []string `yaml:"globs,omitempty"`
	// Debounce is the duration to wait after the last change before triggering
	// (e.g. "2s", "500ms"). Defaults to 2s.
	Debounce string `yaml:"debounce,omitempty"`
}

// HooksConfig holds shell commands executed at task and plan lifecycle events.
// Commands run via "sh -c" with context passed as environment variables.
type HooksConfig struct {
	// PreTask runs before each task. Exit non-zero causes the task to be skipped.
	// Env: CLOOP_TASK_ID, CLOOP_TASK_TITLE, CLOOP_TASK_STATUS, CLOOP_TASK_ROLE
	PreTask string `yaml:"pre_task,omitempty"`
	// PostTask runs after each task completes (regardless of outcome).
	// Same env vars as PreTask, with CLOOP_TASK_STATUS set to the final status.
	PostTask string `yaml:"post_task,omitempty"`
	// PrePlan runs once before plan execution begins.
	// Env: CLOOP_PLAN_GOAL, CLOOP_PLAN_TOTAL
	PrePlan string `yaml:"pre_plan,omitempty"`
	// PostPlan runs once after the plan finishes.
	// Env: CLOOP_PLAN_GOAL, CLOOP_PLAN_TOTAL, CLOOP_PLAN_DONE, CLOOP_PLAN_FAILED, CLOOP_PLAN_SKIPPED
	PostPlan string `yaml:"post_plan,omitempty"`
	// PostTaskReview enables AI code review annotations after each successful task.
	// Equivalent to passing --post-review on the command line.
	PostTaskReview bool `yaml:"post_task_review,omitempty"`
}

// RouterConfig maps AgentRole names to provider names.
// Roles not listed here use the default provider.
type RouterConfig struct {
	// Routes maps role name (backend, frontend, testing, security, devops, data, docs, review)
	// to a provider name (anthropic, openai, ollama, claudecode).
	Routes map[string]string `yaml:"routes,omitempty"`
}

// WebhookConfig holds outbound notification settings.
type WebhookConfig struct {
	// URL to POST events to (empty = disabled).
	URL string `yaml:"url,omitempty"`
	// Events to fire (empty = all). Valid values:
	//   session_started, session_complete, session_failed,
	//   task_started, task_done, task_failed, task_skipped,
	//   plan_complete, evolve_discovered
	Events []string `yaml:"events,omitempty"`
	// Optional HTTP headers added to every request (e.g. Authorization).
	Headers map[string]string `yaml:"headers,omitempty"`
	// Secret, if set, signs every request with HMAC-SHA256 in the
	// X-Hub-Signature-256 header (GitHub-style webhook signing).
	Secret string `yaml:"secret,omitempty"`
}

type AnthropicConfig struct {
	// API key (falls back to ANTHROPIC_API_KEY env var)
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	BaseURL string `yaml:"base_url"`

	// Inference parameters (nil = use provider default)
	Temperature *float64 `yaml:"temperature,omitempty"`
	TopP        *float64 `yaml:"top_p,omitempty"`
	MaxTokens   int      `yaml:"max_tokens,omitempty"`
}

type OpenAIConfig struct {
	// API key (falls back to OPENAI_API_KEY env var)
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	// Optional: set for Azure OpenAI or OpenAI-compatible servers
	BaseURL string `yaml:"base_url"`

	// Inference parameters (nil = use provider default)
	Temperature      *float64 `yaml:"temperature,omitempty"`
	TopP             *float64 `yaml:"top_p,omitempty"`
	FrequencyPenalty *float64 `yaml:"frequency_penalty,omitempty"`
	MaxTokens        int      `yaml:"max_tokens,omitempty"`
}

type OllamaConfig struct {
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`

	// Inference parameters (nil = use provider default)
	Temperature *float64 `yaml:"temperature,omitempty"`
	TopP        *float64 `yaml:"top_p,omitempty"`
	MaxTokens   int      `yaml:"max_tokens,omitempty"`
}

type ClaudeCodeConfig struct {
	Model string `yaml:"model"`
}

// MockConfig holds settings for the deterministic offline mock provider.
type MockConfig struct {
	// ResponsesFile is the path (absolute or relative to workdir) to a YAML file
	// mapping prompt substrings/hashes to canned responses.
	// Defaults to .cloop/mock_responses.yaml when empty.
	ResponsesFile string `yaml:"responses_file,omitempty"`
	// Default is the response returned when no rule matches.
	// Defaults to "TASK_DONE".
	Default string `yaml:"default,omitempty"`
}

// NotifyConfig holds notification channel settings.
type NotifyConfig struct {
	// Desktop enables OS desktop notifications (notify-send on Linux, osascript on macOS).
	Desktop bool `yaml:"desktop,omitempty"`
	// SlackWebhook is the Slack incoming webhook URL.
	// Format: https://hooks.slack.com/services/...
	SlackWebhook string `yaml:"slack_webhook,omitempty"`
	// DiscordWebhook is the Discord webhook URL.
	// Format: https://discord.com/api/webhooks/...
	DiscordWebhook string `yaml:"discord_webhook,omitempty"`
	// CustomWebhook is a generic HTTP webhook URL for custom integrations.
	// cloop POSTs JSON: {"title":"...", "body":"...", "source":"cloop"}
	CustomWebhook string `yaml:"custom_webhook,omitempty"`
}

// SyncConfig configures git-based team plan sharing.
type SyncConfig struct {
	// Remote is the git remote name to sync with (default "origin").
	Remote string `yaml:"remote,omitempty"`
	// Branch is the branch name used to push/pull cloop state (default "cloop-state").
	Branch string `yaml:"branch,omitempty"`
}

// GitHubConfig holds GitHub integration settings.
type GitHubConfig struct {
	// Personal access token (falls back to GITHUB_TOKEN env var)
	Token string `yaml:"token,omitempty"`
	// Default repo in "owner/repo" format (falls back to git remote detection)
	Repo string `yaml:"repo,omitempty"`
	// Labels added to issues created by cloop push
	Labels []string `yaml:"labels,omitempty"`
}

// BudgetConfig holds spend limit settings.
type BudgetConfig struct {
	// MonthlyUSD is the maximum allowed API spend per calendar month.
	// 0 means no limit. When exceeded, cloop warns (or blocks) new task runs.
	MonthlyUSD float64 `yaml:"monthly_usd,omitempty"`

	// DailyUSDLimit is the maximum allowed API spend per calendar day (UTC).
	// 0 means no limit. When exceeded, cloop aborts task execution.
	DailyUSDLimit float64 `yaml:"daily_usd_limit,omitempty"`

	// DailyTokenLimit is the maximum total tokens (input + output) allowed per
	// calendar day (UTC). 0 means no limit.
	DailyTokenLimit int `yaml:"daily_token_limit,omitempty"`

	// AlertThresholdPct is the percentage of the daily budget at which cloop
	// fires a desktop/webhook alert. Default 80 (80%).
	AlertThresholdPct int `yaml:"alert_threshold_pct,omitempty"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Provider: "claudecode",
		Anthropic: AnthropicConfig{
			Model: "claude-opus-4-6",
		},
		OpenAI: OpenAIConfig{
			Model: "gpt-4o",
		},
		Ollama: OllamaConfig{
			BaseURL: "http://localhost:11434",
			Model:   "llama3.2",
		},
	}
}

// ConfigPath returns the path to the config file.
func ConfigPath(workdir string) string {
	return filepath.Join(workdir, configFile)
}

// Load reads config from .cloop/config.yaml. Returns defaults if missing.
// Environment variables override file values: ANTHROPIC_API_KEY, OPENAI_API_KEY,
// ANTHROPIC_BASE_URL, OPENAI_BASE_URL, OLLAMA_BASE_URL, CLOOP_PROVIDER.
// On Unix systems, Load prints a warning when the config file is world-readable
// (permissions wider than 0600) because it may contain API keys.
func Load(workdir string) (*Config, error) {
	cfg := Default()
	path := ConfigPath(workdir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg.applyEnvVars()
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	// Warn on Unix if the config file is world- or group-readable.
	if runtime.GOOS != "windows" {
		if fi, statErr := os.Stat(path); statErr == nil {
			if fi.Mode().Perm()&0o077 != 0 {
				fmt.Fprintf(os.Stderr, "warning: %s has permissions %o — it may contain API keys. Run: chmod 600 %s\n",
					path, fi.Mode().Perm(), path)
			}
		}
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.applyEnvVars()
	return cfg, nil
}

// applyEnvVars overlays environment variable values onto config fields.
// Env vars take precedence over file-based config values.
func (c *Config) applyEnvVars() {
	if v := os.Getenv("CLOOP_PROVIDER"); v != "" {
		c.Provider = v
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		c.Anthropic.APIKey = v
	}
	if v := os.Getenv("ANTHROPIC_BASE_URL"); v != "" {
		c.Anthropic.BaseURL = v
	}
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		c.OpenAI.APIKey = v
	}
	if v := os.Getenv("OPENAI_BASE_URL"); v != "" {
		c.OpenAI.BaseURL = v
	}
	if v := os.Getenv("OLLAMA_BASE_URL"); v != "" {
		c.Ollama.BaseURL = v
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		c.GitHub.Token = v
	}
}

// Save writes the config to .cloop/config.yaml.
func Save(workdir string, cfg *Config) error {
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// 0o600: owner read/write only — the file may contain API keys.
	return os.WriteFile(ConfigPath(workdir), data, 0o600)
}

// WriteDefault creates a default config.yaml if one doesn't exist.
func WriteDefault(workdir string) error {
	path := ConfigPath(workdir)
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	return Save(workdir, Default())
}
