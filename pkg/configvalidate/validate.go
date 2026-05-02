// Package configvalidate implements schema and semantic validation for cloop config and state.
package configvalidate

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/config"
)

// Severity is the severity level of a validation finding.
type Severity string

const (
	SeverityError Severity = "ERROR"
	SeverityWarn  Severity = "WARN"
	SeverityInfo  Severity = "INFO"
)

// Finding is a single validation result.
type Finding struct {
	Severity Severity
	Field    string
	Message  string
	// FixNote describes what --fix will do. Empty means not auto-fixable.
	FixNote string
}

// Report holds all findings from a validation run.
type Report struct {
	Findings []Finding
	// Fixed lists human-readable descriptions of auto-corrections applied by --fix.
	Fixed []string
}

// HasErrors returns true if any ERROR-severity findings exist.
func (r *Report) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Counts returns counts by severity.
func (r *Report) Counts() (errors, warns, infos int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityError:
			errors++
		case SeverityWarn:
			warns++
		case SeverityInfo:
			infos++
		}
	}
	return
}

// knownTopLevelKeys is the set of valid top-level keys in config.yaml.
// These must match the yaml struct tags on config.Config.
var knownTopLevelKeys = map[string]bool{
	"provider":     true,
	"anthropic":    true,
	"openai":       true,
	"ollama":       true,
	"claudecode":   true,
	"mock":         true,
	"webhook":      true,
	"github":       true,
	"router":       true,
	"hooks":        true,
	"max_parallel": true,
	"watch":        true,
	"notify":       true,
	"sync":         true,
	"log_json":     true,
	"budget":       true,
}

// registeredProviders is the set of provider names cloop knows about.
var registeredProviders = map[string]bool{
	"anthropic":  true,
	"openai":     true,
	"ollama":     true,
	"claudecode": true,
	"mock":       true,
}

// validTaskStatuses is the full set of known task status values.
var validTaskStatuses = map[string]bool{
	"pending":     true,
	"in_progress": true,
	"done":        true,
	"failed":      true,
	"skipped":     true,
	"timed_out":   true,
}

// ValidateOptions controls optional behaviour.
type ValidateOptions struct {
	// Probe performs live HTTP reachability checks for notification URLs.
	Probe bool
	// Fix auto-corrects safe issues in place (unknown keys stripped, bad statuses reset).
	Fix bool
}

// Run executes all validation checks against the project at workdir.
func Run(ctx context.Context, workdir string, opts ValidateOptions) (*Report, error) {
	rep := &Report{}
	add := func(f Finding) { rep.Findings = append(rep.Findings, f) }

	configPath := config.ConfigPath(workdir)

	// ── 1. Read raw YAML to detect unknown top-level keys ──────────────────
	rawData, readErr := os.ReadFile(configPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			add(Finding{
				Severity: SeverityWarn,
				Field:    "config.yaml",
				Message:  "config file not found — using defaults",
			})
		} else {
			add(Finding{
				Severity: SeverityError,
				Field:    "config.yaml",
				Message:  fmt.Sprintf("cannot read config file: %v", readErr),
			})
		}
	} else {
		unknownKeys := checkUnknownKeys(rawData)
		for _, k := range unknownKeys {
			add(Finding{
				Severity: SeverityWarn,
				Field:    fmt.Sprintf("config.%s", k),
				Message:  fmt.Sprintf("unknown top-level key %q — will be ignored by cloop", k),
				FixNote:  "will be stripped from config.yaml",
			})
		}
		if opts.Fix && len(unknownKeys) > 0 {
			if err := stripUnknownKeys(configPath, rawData); err != nil {
				add(Finding{Severity: SeverityWarn, Field: "config.yaml", Message: fmt.Sprintf("--fix: could not strip unknown keys: %v", err)})
			} else {
				rep.Fixed = append(rep.Fixed, fmt.Sprintf("stripped unknown keys from config.yaml: %s", strings.Join(unknownKeys, ", ")))
				// Reload rawData after fix
				rawData, _ = os.ReadFile(configPath)
			}
		}
	}

	// ── 2. Load parsed config for semantic checks ───────────────────────────
	cfg, loadErr := config.Load(workdir)
	if loadErr != nil {
		add(Finding{
			Severity: SeverityError,
			Field:    "config.yaml",
			Message:  fmt.Sprintf("YAML parse error: %v", loadErr),
		})
		// Cannot continue without a valid config struct.
	} else {
		// 2a. Provider reference
		if cfg.Provider != "" && !registeredProviders[cfg.Provider] {
			add(Finding{
				Severity: SeverityError,
				Field:    "config.provider",
				Message:  fmt.Sprintf("unknown provider %q — valid: %s", cfg.Provider, knownProviderList()),
			})
		}

		// 2b. Router role-to-provider references
		for role, prov := range cfg.Router.Routes {
			if !registeredProviders[prov] {
				add(Finding{
					Severity: SeverityError,
					Field:    fmt.Sprintf("config.router.routes.%s", role),
					Message:  fmt.Sprintf("unknown provider %q in router route — valid: %s", prov, knownProviderList()),
				})
			}
		}

		// 2c. Model strings empty when provider is configured
		checkModelStrings(cfg, add)

		// 2d. URL fields malformed
		checkURLs(cfg, add)

		// 2e. Budget values negative
		checkBudgetValues(cfg, add)

		// 2f. Hooks referencing non-executable scripts
		checkHookScripts(cfg, add)

		// 2g. Optional notification URL reachability probe
		if opts.Probe {
			checkNotifyURLReachability(ctx, cfg, add)
		}
	}

	// ── 3. State DB: task status validity ───────────────────────────────────
	dbPath := filepath.Join(workdir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); err == nil {
		if err := checkStateDB(dbPath, opts.Fix, rep, add); err != nil {
			add(Finding{
				Severity: SeverityWarn,
				Field:    "state.db",
				Message:  fmt.Sprintf("cannot open state database: %v", err),
			})
		}
	}

	_ = rawData // used above
	return rep, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// checkUnknownKeys decodes YAML as a raw map and returns unknown top-level keys.
func checkUnknownKeys(data []byte) []string {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var unknown []string
	for k := range raw {
		if !knownTopLevelKeys[k] {
			unknown = append(unknown, k)
		}
	}
	return unknown
}

// stripUnknownKeys rewrites configPath keeping only known top-level keys.
func stripUnknownKeys(configPath string, data []byte) error {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k := range raw {
		if !knownTopLevelKeys[k] {
			delete(raw, k)
		}
	}
	out, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, out, 0o600)
}

func checkModelStrings(cfg *config.Config, add func(Finding)) {
	// Anthropic: warn if provider is anthropic but model is empty
	if cfg.Provider == "anthropic" && cfg.Anthropic.Model == "" {
		add(Finding{
			Severity: SeverityWarn,
			Field:    "config.anthropic.model",
			Message:  "anthropic provider is active but model string is empty — will use provider default",
		})
	}
	// OpenAI
	if cfg.Provider == "openai" && cfg.OpenAI.Model == "" {
		add(Finding{
			Severity: SeverityWarn,
			Field:    "config.openai.model",
			Message:  "openai provider is active but model string is empty — will use provider default",
		})
	}
	// Ollama
	if cfg.Provider == "ollama" && cfg.Ollama.Model == "" {
		add(Finding{
			Severity: SeverityWarn,
			Field:    "config.ollama.model",
			Message:  "ollama provider is active but model string is empty — will use provider default",
		})
	}
}

func checkURLs(cfg *config.Config, add func(Finding)) {
	type urlField struct {
		field string
		value string
	}
	fields := []urlField{
		{"config.anthropic.base_url", cfg.Anthropic.BaseURL},
		{"config.openai.base_url", cfg.OpenAI.BaseURL},
		{"config.ollama.base_url", cfg.Ollama.BaseURL},
		{"config.webhook.url", cfg.Webhook.URL},
		{"config.notify.slack_webhook", cfg.Notify.SlackWebhook},
		{"config.notify.discord_webhook", cfg.Notify.DiscordWebhook},
		{"config.notify.custom_webhook", cfg.Notify.CustomWebhook},
	}
	for _, f := range fields {
		if f.value == "" {
			continue
		}
		u, err := url.ParseRequestURI(f.value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			add(Finding{
				Severity: SeverityError,
				Field:    f.field,
				Message:  fmt.Sprintf("malformed URL %q: must be http:// or https://", f.value),
			})
		}
	}
}

func checkBudgetValues(cfg *config.Config, add func(Finding)) {
	if cfg.Budget.MonthlyUSD < 0 {
		add(Finding{
			Severity: SeverityError,
			Field:    "config.budget.monthly_usd",
			Message:  fmt.Sprintf("monthly_usd is negative (%.4f) — must be 0 (unlimited) or positive", cfg.Budget.MonthlyUSD),
		})
	}
	if cfg.Budget.DailyUSDLimit < 0 {
		add(Finding{
			Severity: SeverityError,
			Field:    "config.budget.daily_usd_limit",
			Message:  fmt.Sprintf("daily_usd_limit is negative (%.4f) — must be 0 (unlimited) or positive", cfg.Budget.DailyUSDLimit),
		})
	}
	if cfg.Budget.DailyTokenLimit < 0 {
		add(Finding{
			Severity: SeverityError,
			Field:    "config.budget.daily_token_limit",
			Message:  fmt.Sprintf("daily_token_limit is negative (%d) — must be 0 (unlimited) or positive", cfg.Budget.DailyTokenLimit),
		})
	}
	if cfg.Budget.AlertThresholdPct < 0 || cfg.Budget.AlertThresholdPct > 100 {
		add(Finding{
			Severity: SeverityWarn,
			Field:    "config.budget.alert_threshold_pct",
			Message:  fmt.Sprintf("alert_threshold_pct is %d — expected 0–100 (percent)", cfg.Budget.AlertThresholdPct),
		})
	}
}

func checkHookScripts(cfg *config.Config, add func(Finding)) {
	hooks := []struct {
		field string
		cmd   string
	}{
		{"config.hooks.pre_task", cfg.Hooks.PreTask},
		{"config.hooks.post_task", cfg.Hooks.PostTask},
		{"config.hooks.pre_plan", cfg.Hooks.PrePlan},
		{"config.hooks.post_plan", cfg.Hooks.PostPlan},
	}
	for _, h := range hooks {
		if h.cmd == "" {
			continue
		}
		parts := strings.Fields(h.cmd)
		if len(parts) == 0 {
			continue
		}
		script := parts[0]

		if !strings.Contains(script, "/") {
			// System command — check PATH
			if _, err := exec.LookPath(script); err != nil {
				add(Finding{
					Severity: SeverityWarn,
					Field:    h.field,
					Message:  fmt.Sprintf("hook command %q not found in PATH", script),
				})
			}
			continue
		}

		// Absolute or relative file path
		info, err := os.Stat(script)
		if err != nil {
			add(Finding{
				Severity: SeverityError,
				Field:    h.field,
				Message:  fmt.Sprintf("hook script %q does not exist", script),
			})
			continue
		}
		if info.Mode()&0o111 == 0 {
			add(Finding{
				Severity: SeverityError,
				Field:    h.field,
				Message:  fmt.Sprintf("hook script %q is not executable — run: chmod +x %s", script, script),
			})
		}
	}
}

func checkNotifyURLReachability(ctx context.Context, cfg *config.Config, add func(Finding)) {
	type entry struct {
		field string
		url   string
	}
	urls := []entry{
		{"config.webhook.url", cfg.Webhook.URL},
		{"config.notify.slack_webhook", cfg.Notify.SlackWebhook},
		{"config.notify.discord_webhook", cfg.Notify.DiscordWebhook},
		{"config.notify.custom_webhook", cfg.Notify.CustomWebhook},
	}
	client := &http.Client{Timeout: 8 * time.Second}
	for _, e := range urls {
		if e.url == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, e.url, nil)
		if err != nil {
			add(Finding{Severity: SeverityError, Field: e.field, Message: fmt.Sprintf("probe failed — cannot build request: %v", err)})
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			add(Finding{Severity: SeverityWarn, Field: e.field, Message: fmt.Sprintf("probe failed — unreachable: %v", err)})
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			add(Finding{Severity: SeverityWarn, Field: e.field, Message: fmt.Sprintf("probe returned HTTP %d — endpoint may be down", resp.StatusCode)})
		} else {
			add(Finding{Severity: SeverityInfo, Field: e.field, Message: fmt.Sprintf("probe OK (HTTP %d)", resp.StatusCode)})
		}
	}
}

// checkStateDB validates task statuses stored in state.db.
// If fix is true, tasks with invalid or stuck in_progress statuses are reset to pending.
func checkStateDB(dbPath string, fix bool, rep *Report, add func(Finding)) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, title, status FROM plan_tasks`)
	if err != nil {
		// Table might not exist yet
		return nil
	}
	defer rows.Close()

	type taskRow struct {
		id     int
		title  string
		status string
	}
	var invalid []taskRow
	var stuckInProgress []taskRow

	for rows.Next() {
		var t taskRow
		if err := rows.Scan(&t.id, &t.title, &t.status); err != nil {
			continue
		}
		if !validTaskStatuses[t.status] {
			invalid = append(invalid, t)
		} else if t.status == "in_progress" {
			stuckInProgress = append(stuckInProgress, t)
		}
	}
	rows.Close()

	for _, t := range invalid {
		add(Finding{
			Severity: SeverityError,
			Field:    fmt.Sprintf("state.db:plan_tasks[%d].status", t.id),
			Message:  fmt.Sprintf("task %q has invalid status %q — not a known status value", t.title, t.status),
			FixNote:  "will be reset to \"pending\"",
		})
	}

	for _, t := range stuckInProgress {
		add(Finding{
			Severity: SeverityWarn,
			Field:    fmt.Sprintf("state.db:plan_tasks[%d].status", t.id),
			Message:  fmt.Sprintf("task %q is stuck in \"in_progress\" — may indicate an interrupted run", t.title),
			FixNote:  "will be reset to \"pending\"",
		})
	}

	if fix {
		toReset := append(invalid, stuckInProgress...)
		for _, t := range toReset {
			if _, err := db.Exec(`UPDATE plan_tasks SET status='pending' WHERE id=?`, t.id); err != nil {
				add(Finding{Severity: SeverityWarn, Field: "state.db", Message: fmt.Sprintf("--fix: could not reset task %d: %v", t.id, err)})
				continue
			}
			rep.Fixed = append(rep.Fixed, fmt.Sprintf("reset task %d (%q) status from %q to \"pending\"", t.id, t.title, t.status))
		}
	}

	return nil
}

func knownProviderList() string {
	return "anthropic, openai, ollama, claudecode, mock"
}
