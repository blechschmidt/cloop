// Package config manages the .cloop/config.yaml project configuration file.
//
// Storage model (Task 20075): the canonical source remains the human-readable
// .cloop/config.yaml file, but every Save() also mirrors the serialised YAML
// into a metadata row of the project's SQLite state.db (when one exists).
// This makes config queryable alongside cost and step data, and provides a
// recovery fallback if the YAML file is lost or quarantined for corruption.
// Load() prefers YAML when present; if YAML is missing, it transparently
// rehydrates from the SQLite mirror so the project keeps working.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

const configFile = ".cloop/config.yaml"

// permWarnedPaths tracks which config paths have already emitted the
// "wide permissions" warning. Long-running processes (the Web UI, daemon,
// auto-evolve loops) call Load() many times per second; without dedup the
// warning floods stderr and the journal. Each unique path warns at most once
// per process lifetime.
var (
	permWarnedMu    sync.Mutex
	permWarnedPaths = map[string]struct{}{}
)

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

	// RateLimit configures the per-IP token-bucket rate limiter for HTTP servers
	// (cloop serve and cloop ui). Zero values use built-in defaults.
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty"`

	// Tracing configures OTLP distributed trace export.
	// When Tracing.Enabled is true and Tracing.Endpoint is set, cloop exports
	// per-call spans to the specified OTLP HTTP endpoint (e.g. Jaeger, Tempo,
	// or an OTel Collector). Disabled by default (zero overhead when off).
	Tracing TracingConfig `yaml:"tracing,omitempty"`
}

// TracingConfig holds OpenTelemetry tracing settings.
type TracingConfig struct {
	// Enabled activates OTLP trace export. Default: false (no-op).
	Enabled bool `yaml:"enabled,omitempty"`
	// Endpoint is the OTLP HTTP receiver base URL, e.g. "http://localhost:4318".
	// The exporter appends /v1/traces automatically.
	Endpoint string `yaml:"endpoint,omitempty"`
	// ServiceName is reported as the OTel service.name resource attribute.
	// Defaults to "cloop".
	ServiceName string `yaml:"service_name,omitempty"`
}

// RateLimitConfig controls the per-IP token-bucket rate limiter applied to
// the REST API server (cloop serve) and the Web UI server (cloop ui).
type RateLimitConfig struct {
	// RequestsPerSecond is the sustained request rate allowed per remote IP.
	// Default: 20 requests/second.
	RequestsPerSecond float64 `yaml:"requests_per_second,omitempty"`
	// Burst is the maximum burst size (bucket capacity) per remote IP.
	// Default: 50 requests.
	Burst int `yaml:"burst,omitempty"`
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
	// Timeout caps the wall-clock duration of every hook invocation, parsed via
	// time.ParseDuration (e.g. "30s", "5m", "2h"). Empty defaults to 10 minutes.
	// Use "-1s" (or any negative duration) to disable the timeout for hooks
	// that legitimately exceed the default.
	Timeout string `yaml:"timeout,omitempty"`
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

	// MaxWeeklyPct, when > 0, blocks new runs once the global Anthropic weekly
	// (7-day) utilization reported by the OAuth usage API reaches this percent.
	// Example: 50 means "stop running this project once 50% of the weekly limit
	// has been consumed across all your Claude usage" — useful to reserve
	// headroom for other work.
	MaxWeeklyPct float64 `yaml:"max_weekly_pct,omitempty"`

	// MaxFiveHourPct, when > 0, blocks new runs once the global 5-hour window
	// utilization reaches this percent.
	MaxFiveHourPct float64 `yaml:"max_five_hour_pct,omitempty"`

	// MaxWeeklyOpusPct, when > 0, blocks new runs once the weekly Opus
	// utilization reaches this percent.
	MaxWeeklyOpusPct float64 `yaml:"max_weekly_opus_pct,omitempty"`

	// MaxWeeklySonnetPct, when > 0, blocks new runs once the weekly Sonnet
	// utilization reaches this percent.
	MaxWeeklySonnetPct float64 `yaml:"max_weekly_sonnet_pct,omitempty"`
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

	// GlobalUSDPct caps this project's daily USD spend to a percentage of the
	// global daily USD limit defined in ~/.config/cloop/budget.yaml.
	// E.g. 80 means this project may not exceed 80% of the global daily USD cap.
	// 0 means no percentage cap.
	GlobalUSDPct float64 `yaml:"global_usd_pct,omitempty"`

	// GlobalTokenPct caps this project's daily token usage to a percentage of
	// the global daily token limit defined in ~/.config/cloop/budget.yaml.
	// 0 means no percentage cap.
	GlobalTokenPct float64 `yaml:"global_token_pct,omitempty"`
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

// stateDBPath returns the SQLite state database path for the given workdir.
// Mirrors the location used by pkg/state.effectiveDBPath for the default
// (non-session) case, which is sufficient for Save/Load mirroring: sessions
// have their own state.db and load their own per-session config separately.
func stateDBPath(workdir string) string {
	return filepath.Join(workdir, ".cloop", "state.db")
}

// mirrorToSQLite stores the YAML-serialised config in the project's state.db.
// Best-effort: if state.db doesn't exist or can't be opened, returns nil
// silently — the YAML file is the authoritative store and the SQLite mirror
// is an enhancement, not a requirement. We deliberately do NOT create
// state.db here: that would make Save() a side-effecting init for every
// directory the user happens to pass in.
func mirrorToSQLite(workdir string, data []byte) {
	dbPath := stateDBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return
	}
	defer db.Close()
	_ = db.SetConfigBlob(string(data))
	// Tighten permissions defensively — config blob may include API keys.
	// state.db is created with the umask default (often 0644); on Unix we
	// shrink to 0600 once it carries credentials. Errors are ignored: this
	// is a hardening pass, not a precondition.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dbPath, 0o600)
	}
}

// loadFromSQLite returns the YAML-serialised config previously mirrored into
// state.db, or "" if no mirror exists. Used by Load() as a fallback when the
// .cloop/config.yaml file is missing — a config-set followed by a stray
// `rm config.yaml` no longer wipes the user's API keys, model picks, and
// budget caps. Errors are swallowed: the YAML-missing path must keep working
// even if the SQLite mirror is unreadable.
func loadFromSQLite(workdir string) string {
	dbPath := stateDBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return ""
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return ""
	}
	defer db.Close()
	blob, err := db.GetConfigBlob()
	if err != nil {
		return ""
	}
	return blob
}

// Load reads config from .cloop/config.yaml. Returns defaults if missing.
// Environment variables override file values: ANTHROPIC_API_KEY, OPENAI_API_KEY,
// ANTHROPIC_BASE_URL, OPENAI_BASE_URL, OLLAMA_BASE_URL, CLOOP_PROVIDER.
// On Unix systems, Load prints a warning when the config file is world-readable
// (permissions wider than 0600) because it may contain API keys.
//
// When the YAML file is missing, Load transparently falls back to the SQLite
// mirror written by Save() (see stateDBPath / mirrorToSQLite). The SQLite
// mirror is a recovery store, not the authoritative one — a present YAML
// file always wins so manual edits keep the expected semantics.
func Load(workdir string) (*Config, error) {
	cfg := Default()
	path := ConfigPath(workdir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Fall back to the SQLite mirror so a missing config.yaml doesn't
		// silently revert API keys and budget caps to defaults.
		if blob := loadFromSQLite(workdir); blob != "" {
			if err := yaml.Unmarshal([]byte(blob), cfg); err == nil {
				cfg.applyEnvVars()
				return cfg, nil
			}
		}
		cfg.applyEnvVars()
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	// Warn on Unix if the config file is world- or group-readable. The warning
	// fires once per path per process — Load() is hot in long-running processes
	// (UI, daemon, auto-evolve) and an unconditional Fprintf would flood stderr.
	if runtime.GOOS != "windows" {
		if fi, statErr := os.Stat(path); statErr == nil {
			if fi.Mode().Perm()&0o077 != 0 {
				permWarnedMu.Lock()
				_, already := permWarnedPaths[path]
				if !already {
					permWarnedPaths[path] = struct{}{}
				}
				permWarnedMu.Unlock()
				if !already {
					fmt.Fprintf(os.Stderr, "warning: %s has permissions %o — it may contain API keys. Run: chmod 600 %s\n",
						path, fi.Mode().Perm(), path)
				}
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
//
// The write is atomic — data is staged in a sibling .tmp file, fsynced, then
// renamed into place. A crash, ENOSPC, or `cloop config set` racing with a
// reader can no longer leave the file half-written and lose the user's API
// keys / provider settings.
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
	path := ConfigPath(workdir)
	tmp, err := os.CreateTemp(dir, ".config.yaml.*.tmp")
	if err != nil {
		return fmt.Errorf("config: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("config: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("config: rename tmp: %w", err)
	}
	// Mirror into SQLite (best-effort). Failure here doesn't roll back the
	// YAML write — YAML is the canonical store, SQLite is a queryable mirror.
	mirrorToSQLite(workdir, data)
	return nil
}

// WriteDefault creates a default config.yaml if one doesn't exist.
func WriteDefault(workdir string) error {
	path := ConfigPath(workdir)
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	return Save(workdir, Default())
}
