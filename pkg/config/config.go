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

// Bounds for numeric config values. Centralised here so both Load()'s
// warn-and-clamp path and `cloop config set`'s reject path agree on the
// same limits, and so pkg/configvalidate can import them without hard-coding
// constants in three places.
const (
	// MaxParallel: 1..MaxParallelUpper. Zero in YAML means "not set"
	// (omitempty zero value) and stays untouched — runtime treats 0 as
	// "use default". Anything else outside the range is pathological:
	// negative spawns no workers; an absurdly large value would create
	// thousands of goroutines per parallel tick.
	MaxParallelLower = 1
	MaxParallelUpper = 64

	// Rate limiter: zero means "use HTTP server default", but if the user
	// sets a value it must be a sane positive rate / burst.
	RateLimitRPSLower   = 1.0
	RateLimitBurstLower = 1

	// Budget alert threshold percent must be 0..100. 0 is allowed and
	// disables alerting; >100 is meaningless.
	AlertThresholdMin = 0
	AlertThresholdMax = 100

	// WebSocket connection caps for the cloop ui server (Task 20090).
	// Zero in YAML means "not set" — runtime substitutes the *Default*
	// values below. Non-zero values outside the allowed band are clamped
	// back to zero (validateAndClamp) and rejected by `cloop config set`
	// (ValidateNumeric) to keep the goroutine pool bounded.
	//
	// Upper bounds are intentionally generous: 4096 total connections is
	// far above any realistic single-tenant dashboard load (a browser
	// opens at most a handful of WebSocket peers per tab) but below the
	// default Linux open-file ulimit (1024 → 4096 with `ulimit -n`).
	// Per-IP cap of 1024 is similarly headroom-laden but stops a single
	// misbehaving client from monopolising the total budget.
	WebSocketConnsLower      = 1
	WebSocketConnsUpper      = 4096
	WebSocketConnsPerIPLower = 1
	WebSocketConnsPerIPUpper = 1024
	WebSocketConnsDefault      = 256
	WebSocketConnsPerIPDefault = 8

	// HTTP request body cap for the cloop ui and cloop serve servers
	// (Task 20102). The cap protects against memory-exhaustion DoS via
	// oversized POST/PUT/PATCH payloads on the long-running daemon. Zero
	// in YAML means "not set" — runtime substitutes MaxRequestBodyBytesDefault.
	// Non-zero values outside the allowed band are clamped back to zero
	// (validateAndClamp) and rejected by `cloop config set` (ValidateNumeric).
	//
	// Bounds: 1 KiB lower (anything smaller would reject normal task PATCHes)
	// and 1 GiB upper (anything larger defeats the protection while being
	// well above any legitimate JSON payload). Default 10 MiB covers chat
	// transcripts and large bulk-edit JSON arrays with comfortable headroom.
	MaxRequestBodyBytesLower   int64 = 1 << 10  // 1 KiB
	MaxRequestBodyBytesUpper   int64 = 1 << 30  // 1 GiB
	MaxRequestBodyBytesDefault int64 = 10 << 20 // 10 MiB

	// Orchestrator per-task wall-clock timeout (Task 20108). Bounds the
	// duration any single task may spend in the provider call before its
	// context is cancelled and the task is marked timed_out. Zero in YAML
	// means "use OrchestratorTaskTimeoutMinutesDefault" (30 minutes); a
	// non-zero value outside [Lower, Upper] is clamped to the default.
	//
	// Lower bound is 1 minute: anything smaller would race the AI's first
	// token on every call. Upper bound is one week (7*24*60), well above
	// any legitimate single-task budget but a hard ceiling against an
	// operator hand-editing nonsense like "1000000 minutes".
	OrchestratorTaskTimeoutMinutesLower   = 1
	OrchestratorTaskTimeoutMinutesUpper   = 7 * 24 * 60
	OrchestratorTaskTimeoutMinutesDefault = 30
)

// permWarnedPaths tracks which config paths have already emitted the
// "wide permissions" warning. Long-running processes (the Web UI, daemon,
// auto-evolve loops) call Load() many times per second; without dedup the
// warning floods stderr and the journal. Each unique path warns at most once
// per process lifetime.
var (
	permWarnedMu    sync.Mutex
	permWarnedPaths = map[string]struct{}{}
)

// clampWarnedMu serialises the once-per-(path,field) clamp warnings emitted by
// validateAndClamp. Same dedup rationale as permWarnedPaths: Load() runs hot
// and we don't want to flood stderr with the same "max_parallel out of range"
// line every second.
var (
	clampWarnedMu    sync.Mutex
	clampWarnedPairs = map[string]struct{}{}
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

	// Watchdog configures the stuck-task detector that runs alongside the
	// PM orchestrator. See WatchdogConfig for individual knobs; defaults
	// (Interval=30s, StuckThreshold=10m, ArtifactIdle=5m) are applied when
	// the relevant fields are zero.
	Watchdog WatchdogConfig `yaml:"watchdog,omitempty"`

	// Orchestrator configures the PM orchestrator's wall-clock execution
	// budgets. See OrchestratorConfig.TaskTimeoutMinutes for the default
	// per-task timeout applied when neither the task nor the project state
	// has a more specific budget set.
	Orchestrator OrchestratorConfig `yaml:"orchestrator,omitempty"`

	// UI configures the cloop ui Web dashboard server. See UIConfig.
	UI UIConfig `yaml:"ui,omitempty"`
}

// OrchestratorConfig holds wall-clock budgets and other knobs that bound the
// per-task execution of the PM orchestrator (Task 20108).
//
// The orchestrator already supported a per-task budget via Task.MaxMinutes
// (Task 99) and a per-project default via state.DefaultMaxMinutes. This
// config layer adds a process-wide default so operators get a safe upper
// bound on every cloop run without having to set the field on every project
// or task. The lookup order is:
//
//	task.MaxMinutes > state.DefaultMaxMinutes > config.Orchestrator.TaskTimeoutMinutes
//
// The first non-zero value wins; if all are zero the orchestrator falls back
// to OrchestratorTaskTimeoutMinutesDefault (30 minutes). This guarantees no
// task can run unbounded if the provider hangs or the LLM produces an
// infinite output stream — the deadline cancels the per-task context, which
// propagates into the provider HTTP call (Task 20081 made provider Complete()
// implementations honor ctx) and the task is marked timed_out.
type OrchestratorConfig struct {
	// TaskTimeoutMinutes is the default wall-clock budget for a single task
	// when neither Task.MaxMinutes nor state.DefaultMaxMinutes is set.
	// Zero substitutes OrchestratorTaskTimeoutMinutesDefault (30). Validated
	// to OrchestratorTaskTimeoutMinutesLower..OrchestratorTaskTimeoutMinutesUpper.
	TaskTimeoutMinutes int `yaml:"task_timeout_minutes,omitempty"`
}

// EffectiveTaskTimeoutMinutes returns the configured task timeout, substituting
// OrchestratorTaskTimeoutMinutesDefault when the field is zero. Out-of-band
// values are also coerced to the default (validateAndClamp catches them on
// load, but this call is the last line of defence for code paths that
// construct OrchestratorConfig{} directly without going through Load()).
func (o OrchestratorConfig) EffectiveTaskTimeoutMinutes() int {
	if o.TaskTimeoutMinutes < OrchestratorTaskTimeoutMinutesLower ||
		o.TaskTimeoutMinutes > OrchestratorTaskTimeoutMinutesUpper {
		return OrchestratorTaskTimeoutMinutesDefault
	}
	return o.TaskTimeoutMinutes
}

// UIConfig holds settings for the cloop ui Web dashboard server.
//
// WebSocket caps (Task 20090) protect the server from goroutine exhaustion
// caused by accidental browser tab storms or deliberate connection floods.
// Each accepted upgrade spawns at least three goroutines (handler, drain,
// writer-loop ticker) plus an entry in the per-project hub registry; without
// caps a single client can register thousands of simultaneous peers.
type UIConfig struct {
	// MaxWebSocketConns caps the total number of concurrent WebSocket
	// connections the UI server will accept across all remote IPs.
	// Zero substitutes WebSocketConnsDefault (256).
	// Validated to WebSocketConnsLower..WebSocketConnsUpper.
	MaxWebSocketConns int `yaml:"max_websocket_conns,omitempty"`

	// MaxWebSocketConnsPerIP caps the number of concurrent WebSocket
	// connections accepted from any single remote IP. A breached cap
	// returns HTTP 429 with a Retry-After header; the connection is
	// rejected before nhooyr.Accept hijacks the request.
	// Zero substitutes WebSocketConnsPerIPDefault (8).
	// Validated to WebSocketConnsPerIPLower..WebSocketConnsPerIPUpper.
	MaxWebSocketConnsPerIP int `yaml:"max_websocket_conns_per_ip,omitempty"`

	// MaxRequestBodyBytes caps the size of any incoming HTTP request body
	// the UI server will accept (POST/PUT/PATCH on every /api/* endpoint).
	// Zero substitutes MaxRequestBodyBytesDefault (10 MiB). Validated to
	// MaxRequestBodyBytesLower..MaxRequestBodyBytesUpper. A breached cap
	// returns HTTP 413 (Request Entity Too Large) before the handler runs,
	// so a malicious or buggy client cannot OOM the daemon by streaming
	// a multi-GB body. Applies to both cloop ui and cloop serve.
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes,omitempty"`
}

// EffectiveMaxWebSocketConns returns the configured total cap, substituting
// WebSocketConnsDefault when the field is zero (the YAML "not set" sentinel).
func (u UIConfig) EffectiveMaxWebSocketConns() int {
	if u.MaxWebSocketConns <= 0 {
		return WebSocketConnsDefault
	}
	return u.MaxWebSocketConns
}

// EffectiveMaxWebSocketConnsPerIP returns the configured per-IP cap,
// substituting WebSocketConnsPerIPDefault when the field is zero.
func (u UIConfig) EffectiveMaxWebSocketConnsPerIP() int {
	if u.MaxWebSocketConnsPerIP <= 0 {
		return WebSocketConnsPerIPDefault
	}
	return u.MaxWebSocketConnsPerIP
}

// EffectiveMaxRequestBodyBytes returns the configured request-body cap,
// substituting MaxRequestBodyBytesDefault (10 MiB) when the field is zero.
// Used by both pkg/ui and pkg/apiserver to size their http.MaxBytesReader
// wrappers.
func (u UIConfig) EffectiveMaxRequestBodyBytes() int64 {
	if u.MaxRequestBodyBytes <= 0 {
		return MaxRequestBodyBytesDefault
	}
	return u.MaxRequestBodyBytes
}

// WatchdogConfig configures the in-flight task stuck detector (Task 20088).
//
// The watchdog inspects every in-flight task on each Interval tick. A task
// is flagged as stuck when both:
//   - it has been running for at least StuckThreshold, AND
//   - its live artifact file has not been modified for at least ArtifactIdle.
//
// Suppressing the false-positive case where the artifact is actively
// growing is intentional: a long-running task that is still producing
// output is not stuck — it is merely slow.
type WatchdogConfig struct {
	// Enabled toggles the watchdog on/off. Default: true (zero value of
	// the YAML key omits it; we treat unset as enabled to make detection
	// the default safe behaviour for stability-focused PM runs).
	// Set Enabled=false explicitly to disable.
	Enabled *bool `yaml:"enabled,omitempty"`

	// IntervalSeconds is how often the watchdog inspects in-flight tasks.
	// Default: 30 seconds. Minimum enforced: 5 seconds (lower values
	// would burn CPU on the SQLite hot path without surfacing meaningful
	// signal — a stuck task does not become unstuck in 4 seconds).
	IntervalSeconds int `yaml:"interval_seconds,omitempty"`

	// StuckThresholdMinutes is the minimum task runtime before a task can
	// be flagged stuck. Default: 10 minutes.
	StuckThresholdMinutes int `yaml:"stuck_threshold_minutes,omitempty"`

	// ArtifactIdleMinutes is the minimum artifact-file inactivity required
	// to corroborate a stuck flag. A task whose artifact is still growing
	// is not stuck, even if its runtime exceeds StuckThresholdMinutes.
	// Default: 5 minutes.
	ArtifactIdleMinutes int `yaml:"artifact_idle_minutes,omitempty"`

	// AutoKillAfterMinutes, when > 0, cancels the task's context after
	// the task has been continuously stuck for this many minutes. Disabled
	// by default (0). Use sparingly: an aggressive auto-kill can mask
	// legitimately slow provider responses on cold paths.
	AutoKillAfterMinutes int `yaml:"auto_kill_after_minutes,omitempty"`
}

// WatchdogDefaults returns the effective watchdog configuration with all
// zero-value fields filled in from defaults. Returns Enabled=true unless
// the user explicitly set Enabled=false. Bounds:
//   - Interval: clamped to >= 5s.
//   - StuckThreshold: clamped to >= 1 minute (so misconfiguration does not
//     produce a runaway stream of "stuck" events for normal-running tasks).
//   - ArtifactIdle: clamped to >= 30 seconds.
//   - AutoKillAfter: zero means "off"; any positive value passes through.
func (w WatchdogConfig) WatchdogDefaults() WatchdogConfig {
	out := w
	if out.Enabled == nil {
		t := true
		out.Enabled = &t
	}
	if out.IntervalSeconds <= 0 {
		out.IntervalSeconds = 30
	}
	if out.IntervalSeconds < 5 {
		out.IntervalSeconds = 5
	}
	if out.StuckThresholdMinutes <= 0 {
		out.StuckThresholdMinutes = 10
	}
	if out.StuckThresholdMinutes < 1 {
		out.StuckThresholdMinutes = 1
	}
	if out.ArtifactIdleMinutes <= 0 {
		out.ArtifactIdleMinutes = 5
	}
	if out.ArtifactIdleMinutes*60 < 30 {
		out.ArtifactIdleMinutes = 1
	}
	if out.AutoKillAfterMinutes < 0 {
		out.AutoKillAfterMinutes = 0
	}
	return out
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

	// BlockExtraUsage, when true (default), prevents cloop from running tasks
	// when doing so would incur Claude Code extra usage (per-token billing
	// beyond the subscription). Set to false to allow extra usage.
	BlockExtraUsage *bool `yaml:"block_extra_usage,omitempty"`
}

// ShouldBlockExtraUsage returns true if extra usage should be blocked.
// Defaults to true when not explicitly set.
func (b BudgetConfig) ShouldBlockExtraUsage() bool {
	if b.BlockExtraUsage == nil {
		return true // default: block
	}
	return *b.BlockExtraUsage
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
				cfg.validateAndClamp(path)
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
	cfg.validateAndClamp(path)
	cfg.applyEnvVars()
	return cfg, nil
}

// validateAndClamp inspects user-supplied numeric values, warns once per
// (path, field) when a value is outside the safe range, and resets the field
// to its zero value (= "use default") so the runtime cannot be steered into
// pathological behaviour by a bad config. This is the *defensive* path —
// `cloop config set` rejects bad values up front; this function exists so a
// hand-edited or migrated YAML can never spawn 5000 goroutines, push
// negative budgets, or emit nonsensical alert thresholds.
func (c *Config) validateAndClamp(path string) {
	warn := func(field, msg string) {
		key := path + "::" + field
		clampWarnedMu.Lock()
		_, already := clampWarnedPairs[key]
		if !already {
			clampWarnedPairs[key] = struct{}{}
		}
		clampWarnedMu.Unlock()
		if !already {
			fmt.Fprintf(os.Stderr, "warning: config %s: %s — clamped to default\n", field, msg)
		}
	}
	// max_parallel: zero is "not set"; non-zero must be in [1, 64].
	if c.MaxParallel != 0 && (c.MaxParallel < MaxParallelLower || c.MaxParallel > MaxParallelUpper) {
		warn("max_parallel", fmt.Sprintf("value %d outside [%d, %d]", c.MaxParallel, MaxParallelLower, MaxParallelUpper))
		c.MaxParallel = 0
	}
	// rate_limit.requests_per_second: zero = use HTTP default; non-zero must be positive.
	if c.RateLimit.RequestsPerSecond < 0 || (c.RateLimit.RequestsPerSecond > 0 && c.RateLimit.RequestsPerSecond < RateLimitRPSLower) {
		warn("rate_limit.requests_per_second", fmt.Sprintf("value %.4f must be >= %.0f (or 0 for default)", c.RateLimit.RequestsPerSecond, RateLimitRPSLower))
		c.RateLimit.RequestsPerSecond = 0
	}
	// rate_limit.burst: zero = use HTTP default; non-zero must be positive.
	if c.RateLimit.Burst < 0 || (c.RateLimit.Burst > 0 && c.RateLimit.Burst < RateLimitBurstLower) {
		warn("rate_limit.burst", fmt.Sprintf("value %d must be >= %d (or 0 for default)", c.RateLimit.Burst, RateLimitBurstLower))
		c.RateLimit.Burst = 0
	}
	// Budget caps: must be >= 0. Zero means "no limit"; negative is meaningless.
	if c.Budget.MonthlyUSD < 0 {
		warn("budget.monthly_usd", fmt.Sprintf("value %.4f must be >= 0", c.Budget.MonthlyUSD))
		c.Budget.MonthlyUSD = 0
	}
	if c.Budget.DailyUSDLimit < 0 {
		warn("budget.daily_usd_limit", fmt.Sprintf("value %.4f must be >= 0", c.Budget.DailyUSDLimit))
		c.Budget.DailyUSDLimit = 0
	}
	if c.Budget.DailyTokenLimit < 0 {
		warn("budget.daily_token_limit", fmt.Sprintf("value %d must be >= 0", c.Budget.DailyTokenLimit))
		c.Budget.DailyTokenLimit = 0
	}
	if c.Budget.AlertThresholdPct < AlertThresholdMin || c.Budget.AlertThresholdPct > AlertThresholdMax {
		warn("budget.alert_threshold_pct", fmt.Sprintf("value %d outside [%d, %d]", c.Budget.AlertThresholdPct, AlertThresholdMin, AlertThresholdMax))
		c.Budget.AlertThresholdPct = 0
	}
	if c.Budget.GlobalUSDPct < 0 || c.Budget.GlobalUSDPct > 100 {
		warn("budget.global_usd_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.Budget.GlobalUSDPct))
		c.Budget.GlobalUSDPct = 0
	}
	if c.Budget.GlobalTokenPct < 0 || c.Budget.GlobalTokenPct > 100 {
		warn("budget.global_token_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.Budget.GlobalTokenPct))
		c.Budget.GlobalTokenPct = 0
	}
	// Claude Code subscription caps: 0..100 percent.
	if c.ClaudeCode.MaxWeeklyPct < 0 || c.ClaudeCode.MaxWeeklyPct > 100 {
		warn("claudecode.max_weekly_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxWeeklyPct))
		c.ClaudeCode.MaxWeeklyPct = 0
	}
	if c.ClaudeCode.MaxFiveHourPct < 0 || c.ClaudeCode.MaxFiveHourPct > 100 {
		warn("claudecode.max_five_hour_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxFiveHourPct))
		c.ClaudeCode.MaxFiveHourPct = 0
	}
	if c.ClaudeCode.MaxWeeklyOpusPct < 0 || c.ClaudeCode.MaxWeeklyOpusPct > 100 {
		warn("claudecode.max_weekly_opus_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxWeeklyOpusPct))
		c.ClaudeCode.MaxWeeklyOpusPct = 0
	}
	if c.ClaudeCode.MaxWeeklySonnetPct < 0 || c.ClaudeCode.MaxWeeklySonnetPct > 100 {
		warn("claudecode.max_weekly_sonnet_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxWeeklySonnetPct))
		c.ClaudeCode.MaxWeeklySonnetPct = 0
	}
	// UI WebSocket caps: zero means "use default"; non-zero must lie inside
	// the allowed band. Out-of-range values fall back to zero so the
	// runtime substitutes the sane default rather than honouring a
	// pathological "0 connections" or "10M per IP" hand-edit.
	if c.UI.MaxWebSocketConns != 0 && (c.UI.MaxWebSocketConns < WebSocketConnsLower || c.UI.MaxWebSocketConns > WebSocketConnsUpper) {
		warn("ui.max_websocket_conns", fmt.Sprintf("value %d outside [%d, %d]", c.UI.MaxWebSocketConns, WebSocketConnsLower, WebSocketConnsUpper))
		c.UI.MaxWebSocketConns = 0
	}
	if c.UI.MaxWebSocketConnsPerIP != 0 && (c.UI.MaxWebSocketConnsPerIP < WebSocketConnsPerIPLower || c.UI.MaxWebSocketConnsPerIP > WebSocketConnsPerIPUpper) {
		warn("ui.max_websocket_conns_per_ip", fmt.Sprintf("value %d outside [%d, %d]", c.UI.MaxWebSocketConnsPerIP, WebSocketConnsPerIPLower, WebSocketConnsPerIPUpper))
		c.UI.MaxWebSocketConnsPerIP = 0
	}
	// A per-IP cap larger than the total cap is meaningless: a single IP
	// could never reach it. Surface the misconfiguration and reset both
	// to defaults so the operator notices.
	if c.UI.MaxWebSocketConns != 0 && c.UI.MaxWebSocketConnsPerIP != 0 && c.UI.MaxWebSocketConnsPerIP > c.UI.MaxWebSocketConns {
		warn("ui.max_websocket_conns_per_ip", fmt.Sprintf("value %d exceeds ui.max_websocket_conns %d", c.UI.MaxWebSocketConnsPerIP, c.UI.MaxWebSocketConns))
		c.UI.MaxWebSocketConnsPerIP = 0
	}
	// Request body cap: zero means default; out-of-range falls back to zero
	// so the runtime substitutes MaxRequestBodyBytesDefault. Pathological
	// values (negative, microscopically small, or absurdly large) are
	// silently corrected rather than left in place.
	if c.UI.MaxRequestBodyBytes != 0 && (c.UI.MaxRequestBodyBytes < MaxRequestBodyBytesLower || c.UI.MaxRequestBodyBytes > MaxRequestBodyBytesUpper) {
		warn("ui.max_request_body_bytes", fmt.Sprintf("value %d outside [%d, %d]", c.UI.MaxRequestBodyBytes, MaxRequestBodyBytesLower, MaxRequestBodyBytesUpper))
		c.UI.MaxRequestBodyBytes = 0
	}
	// orchestrator.task_timeout_minutes: zero means "use default"; non-zero must
	// be in [1, 7*24*60]. Out-of-range falls back to zero so the runtime
	// substitutes OrchestratorTaskTimeoutMinutesDefault rather than honouring a
	// pathological 0-second or week-spanning budget.
	if c.Orchestrator.TaskTimeoutMinutes != 0 && (c.Orchestrator.TaskTimeoutMinutes < OrchestratorTaskTimeoutMinutesLower || c.Orchestrator.TaskTimeoutMinutes > OrchestratorTaskTimeoutMinutesUpper) {
		warn("orchestrator.task_timeout_minutes", fmt.Sprintf("value %d outside [%d, %d]", c.Orchestrator.TaskTimeoutMinutes, OrchestratorTaskTimeoutMinutesLower, OrchestratorTaskTimeoutMinutesUpper))
		c.Orchestrator.TaskTimeoutMinutes = 0
	}
}

// ValidateNumeric returns a non-nil error describing the first numeric range
// violation found in c, if any. Unlike validateAndClamp it does not mutate;
// callers (`cloop config set`, the Web UI options endpoints) use it to reject
// invalid inputs up front rather than silently clamping them. The returned
// error message is suitable for showing to a user.
func (c *Config) ValidateNumeric() error {
	if c.MaxParallel != 0 && (c.MaxParallel < MaxParallelLower || c.MaxParallel > MaxParallelUpper) {
		return fmt.Errorf("max_parallel must be between %d and %d (got %d)", MaxParallelLower, MaxParallelUpper, c.MaxParallel)
	}
	if c.RateLimit.RequestsPerSecond < 0 || (c.RateLimit.RequestsPerSecond > 0 && c.RateLimit.RequestsPerSecond < RateLimitRPSLower) {
		return fmt.Errorf("rate_limit.requests_per_second must be >= %.0f or 0 to use the default (got %.4f)", RateLimitRPSLower, c.RateLimit.RequestsPerSecond)
	}
	if c.RateLimit.Burst < 0 || (c.RateLimit.Burst > 0 && c.RateLimit.Burst < RateLimitBurstLower) {
		return fmt.Errorf("rate_limit.burst must be >= %d or 0 to use the default (got %d)", RateLimitBurstLower, c.RateLimit.Burst)
	}
	if c.Budget.MonthlyUSD < 0 {
		return fmt.Errorf("budget.monthly_usd must be >= 0 (got %.4f)", c.Budget.MonthlyUSD)
	}
	if c.Budget.DailyUSDLimit < 0 {
		return fmt.Errorf("budget.daily_usd_limit must be >= 0 (got %.4f)", c.Budget.DailyUSDLimit)
	}
	if c.Budget.DailyTokenLimit < 0 {
		return fmt.Errorf("budget.daily_token_limit must be >= 0 (got %d)", c.Budget.DailyTokenLimit)
	}
	if c.Budget.AlertThresholdPct < AlertThresholdMin || c.Budget.AlertThresholdPct > AlertThresholdMax {
		return fmt.Errorf("budget.alert_threshold_pct must be between %d and %d (got %d)", AlertThresholdMin, AlertThresholdMax, c.Budget.AlertThresholdPct)
	}
	if c.Budget.GlobalUSDPct < 0 || c.Budget.GlobalUSDPct > 100 {
		return fmt.Errorf("budget.global_usd_pct must be between 0 and 100 (got %.4f)", c.Budget.GlobalUSDPct)
	}
	if c.Budget.GlobalTokenPct < 0 || c.Budget.GlobalTokenPct > 100 {
		return fmt.Errorf("budget.global_token_pct must be between 0 and 100 (got %.4f)", c.Budget.GlobalTokenPct)
	}
	if c.ClaudeCode.MaxWeeklyPct < 0 || c.ClaudeCode.MaxWeeklyPct > 100 {
		return fmt.Errorf("claudecode.max_weekly_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxWeeklyPct)
	}
	if c.ClaudeCode.MaxFiveHourPct < 0 || c.ClaudeCode.MaxFiveHourPct > 100 {
		return fmt.Errorf("claudecode.max_five_hour_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxFiveHourPct)
	}
	if c.ClaudeCode.MaxWeeklyOpusPct < 0 || c.ClaudeCode.MaxWeeklyOpusPct > 100 {
		return fmt.Errorf("claudecode.max_weekly_opus_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxWeeklyOpusPct)
	}
	if c.ClaudeCode.MaxWeeklySonnetPct < 0 || c.ClaudeCode.MaxWeeklySonnetPct > 100 {
		return fmt.Errorf("claudecode.max_weekly_sonnet_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxWeeklySonnetPct)
	}
	if c.UI.MaxWebSocketConns != 0 && (c.UI.MaxWebSocketConns < WebSocketConnsLower || c.UI.MaxWebSocketConns > WebSocketConnsUpper) {
		return fmt.Errorf("ui.max_websocket_conns must be between %d and %d (or 0 for the default %d) (got %d)",
			WebSocketConnsLower, WebSocketConnsUpper, WebSocketConnsDefault, c.UI.MaxWebSocketConns)
	}
	if c.UI.MaxWebSocketConnsPerIP != 0 && (c.UI.MaxWebSocketConnsPerIP < WebSocketConnsPerIPLower || c.UI.MaxWebSocketConnsPerIP > WebSocketConnsPerIPUpper) {
		return fmt.Errorf("ui.max_websocket_conns_per_ip must be between %d and %d (or 0 for the default %d) (got %d)",
			WebSocketConnsPerIPLower, WebSocketConnsPerIPUpper, WebSocketConnsPerIPDefault, c.UI.MaxWebSocketConnsPerIP)
	}
	if c.UI.MaxWebSocketConns != 0 && c.UI.MaxWebSocketConnsPerIP != 0 && c.UI.MaxWebSocketConnsPerIP > c.UI.MaxWebSocketConns {
		return fmt.Errorf("ui.max_websocket_conns_per_ip (%d) must not exceed ui.max_websocket_conns (%d)",
			c.UI.MaxWebSocketConnsPerIP, c.UI.MaxWebSocketConns)
	}
	if c.UI.MaxRequestBodyBytes != 0 && (c.UI.MaxRequestBodyBytes < MaxRequestBodyBytesLower || c.UI.MaxRequestBodyBytes > MaxRequestBodyBytesUpper) {
		return fmt.Errorf("ui.max_request_body_bytes must be between %d and %d (or 0 for the default %d) (got %d)",
			MaxRequestBodyBytesLower, MaxRequestBodyBytesUpper, MaxRequestBodyBytesDefault, c.UI.MaxRequestBodyBytes)
	}
	if c.Orchestrator.TaskTimeoutMinutes != 0 && (c.Orchestrator.TaskTimeoutMinutes < OrchestratorTaskTimeoutMinutesLower || c.Orchestrator.TaskTimeoutMinutes > OrchestratorTaskTimeoutMinutesUpper) {
		return fmt.Errorf("orchestrator.task_timeout_minutes must be between %d and %d (or 0 for the default %d) (got %d)",
			OrchestratorTaskTimeoutMinutesLower, OrchestratorTaskTimeoutMinutesUpper, OrchestratorTaskTimeoutMinutesDefault, c.Orchestrator.TaskTimeoutMinutes)
	}
	return nil
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
