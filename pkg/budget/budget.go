// Package budget provides daily token and cost budget enforcement for cloop.
// It reads from the cost ledger (.cloop/costs.jsonl) to calculate today's usage
// and enforces configured limits before task execution.
package budget

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/notify"
)

// DailyStats holds today's aggregated usage figures.
type DailyStats struct {
	TotalTokens int
	TotalUSD    float64
	EntryCount  int
}

// DailyUsage reads the cost ledger and returns today's (UTC) aggregated usage.
// Returns an empty DailyStats (not an error) when no records exist.
func DailyUsage(workDir string) (DailyStats, error) {
	entries, err := cost.ReadLedger(workDir)
	if err != nil {
		return DailyStats{}, fmt.Errorf("budget: reading cost ledger: %w", err)
	}
	now := time.Now().UTC()
	var stats DailyStats
	for _, e := range entries {
		ts := e.Timestamp.UTC()
		if ts.Year() == now.Year() && ts.YearDay() == now.YearDay() {
			stats.TotalTokens += e.InputTokens + e.OutputTokens
			stats.TotalUSD += e.EstimatedUSD
			stats.EntryCount++
		}
	}
	return stats, nil
}

// CheckResult is returned by Check, summarising the budget state.
type CheckResult struct {
	// Stats is today's aggregated usage.
	Stats DailyStats

	// USDExceeded is true when DailyUSDLimit > 0 and today's USD spend >= limit.
	USDExceeded bool
	// TokensExceeded is true when DailyTokenLimit > 0 and today's tokens >= limit.
	TokensExceeded bool

	// USDRemaining is the remaining USD budget (negative when exceeded). 0 when no limit.
	USDRemaining float64
	// TokensRemaining is the remaining token budget (negative when exceeded). 0 when no limit.
	TokensRemaining int

	// ThresholdAlertUSD fires when USD spend crosses AlertThresholdPct but is not yet exceeded.
	ThresholdAlertUSD bool
	// ThresholdAlertTokens fires when token count crosses AlertThresholdPct but is not yet exceeded.
	ThresholdAlertTokens bool
}

// Exceeded reports whether any budget limit has been exceeded.
func (r CheckResult) Exceeded() bool {
	return r.USDExceeded || r.TokensExceeded
}

// alertThreshold returns the effective alert threshold percentage (default 80).
func alertThreshold(cfg config.BudgetConfig) float64 {
	if cfg.AlertThresholdPct > 0 {
		return float64(cfg.AlertThresholdPct)
	}
	return 80.0
}

// Check evaluates today's usage against the configured daily limits.
// It fires desktop/webhook alerts when the alert threshold is crossed.
// notifyCfg controls which notification channels are active (may be zero value to skip).
func Check(workDir string, cfg config.BudgetConfig, notifyCfg config.NotifyConfig) (CheckResult, error) {
	stats, err := DailyUsage(workDir)
	if err != nil {
		return CheckResult{}, err
	}

	result := CheckResult{Stats: stats}
	threshold := alertThreshold(cfg)

	if cfg.DailyUSDLimit > 0 {
		result.USDRemaining = cfg.DailyUSDLimit - stats.TotalUSD
		if stats.TotalUSD >= cfg.DailyUSDLimit {
			result.USDExceeded = true
		} else {
			pct := stats.TotalUSD / cfg.DailyUSDLimit * 100
			if pct >= threshold {
				result.ThresholdAlertUSD = true
				fireThresholdAlert(
					fmt.Sprintf("%.0f%% of daily USD budget used ($%.4f / $%.4f)", pct, stats.TotalUSD, cfg.DailyUSDLimit),
					notifyCfg,
				)
			}
		}
	}

	if cfg.DailyTokenLimit > 0 {
		result.TokensRemaining = cfg.DailyTokenLimit - stats.TotalTokens
		if stats.TotalTokens >= cfg.DailyTokenLimit {
			result.TokensExceeded = true
		} else {
			pct := float64(stats.TotalTokens) / float64(cfg.DailyTokenLimit) * 100
			if pct >= threshold {
				result.ThresholdAlertTokens = true
				fireThresholdAlert(
					fmt.Sprintf("%.0f%% of daily token budget used (%d / %d tokens)", pct, stats.TotalTokens, cfg.DailyTokenLimit),
					notifyCfg,
				)
			}
		}
	}

	return result, nil
}

// Enforce checks the daily budget and returns a non-nil error if any limit is
// exceeded, with a clear human-readable message. Use this before starting task
// execution to abort early rather than spending tokens on a blocked run.
func Enforce(workDir string, cfg config.BudgetConfig, notifyCfg config.NotifyConfig) error {
	if cfg.DailyUSDLimit == 0 && cfg.DailyTokenLimit == 0 {
		return nil // no limits configured
	}

	result, err := Check(workDir, cfg, notifyCfg)
	if err != nil {
		// Budget check errors are non-fatal: log them but don't block execution.
		return nil
	}

	if result.USDExceeded {
		return fmt.Errorf(
			"daily USD budget exceeded: spent $%.4f of $%.4f limit — run 'cloop budget status' for details or increase the limit with 'cloop budget set --daily-usd <n>'",
			result.Stats.TotalUSD,
			cfg.DailyUSDLimit,
		)
	}
	if result.TokensExceeded {
		return fmt.Errorf(
			"daily token budget exceeded: used %d of %d token limit — run 'cloop budget status' for details or increase the limit with 'cloop budget set --daily-tokens <n>'",
			result.Stats.TotalTokens,
			cfg.DailyTokenLimit,
		)
	}
	return nil
}

// fireThresholdAlert sends a desktop notification and (if configured) a webhook
// alert. Errors are silently discarded — alerts are best-effort.
func fireThresholdAlert(message string, notifyCfg config.NotifyConfig) {
	title := "cloop: Budget Alert"
	if notifyCfg.Desktop {
		notify.Send(title, message)
	}
	for _, u := range []string{notifyCfg.SlackWebhook, notifyCfg.DiscordWebhook, notifyCfg.CustomWebhook} {
		if u != "" {
			_ = notify.SendWebhook(u, title, message)
		}
	}
}
