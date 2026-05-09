// Package globalbudget manages a global (cross-project) daily token and cost
// budget stored in ~/.config/cloop/budget.yaml plus a global cost ledger at
// ~/.config/cloop/costs.jsonl.
package globalbudget

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// saveMu serialises Save's read-modify-write so two concurrent in-process
// callers can't both stage tmp files and race on the rename. The atomic write
// itself protects against torn reads from another process; this mutex protects
// against last-writer-wins within the same process.
var saveMu sync.Mutex

// ledgerMu serialises AppendLedger so two goroutines in the same process can't
// interleave JSON object writes on the shared costs.jsonl file. Cross-process
// concurrency is rare for the global ledger (one cloop daemon per host) and
// not worth the OS-specific flock complexity.
var ledgerMu sync.Mutex

const (
	configFileName = "budget.yaml"
	ledgerFileName = "costs.jsonl"
	configDir      = ".config/cloop"
)

// GlobalBudgetConfig holds the global (across all projects) daily budget limits.
type GlobalBudgetConfig struct {
	// DailyUSDLimit is the maximum daily USD spend across all projects.
	// 0 means no global USD limit.
	DailyUSDLimit float64 `yaml:"daily_usd_limit,omitempty"`

	// DailyTokenLimit is the maximum daily token count (input+output) across
	// all projects. 0 means no global token limit.
	DailyTokenLimit int `yaml:"daily_token_limit,omitempty"`

	// AlertThresholdPct is the percentage at which alerts fire. Default 80.
	AlertThresholdPct int `yaml:"alert_threshold_pct,omitempty"`
}

// GlobalLedgerEntry mirrors cost.LedgerEntry but adds a project path field so
// entries from different projects are distinguishable.
type GlobalLedgerEntry struct {
	Timestamp      time.Time `json:"timestamp"`
	ProjectPath    string    `json:"project_path,omitempty"`
	TaskID         int       `json:"task_id"`
	TaskTitle      string    `json:"task_title"`
	Provider       string    `json:"provider"`
	Model          string    `json:"model"`
	InputTokens    int       `json:"input_tokens"`
	OutputTokens   int       `json:"output_tokens"`
	ThinkingTokens int       `json:"thinking_tokens,omitempty"`
	EstimatedUSD   float64   `json:"estimated_usd"`
}

// DailyStats is the aggregated global usage for today.
type DailyStats struct {
	TotalTokens int
	TotalUSD    float64
	EntryCount  int
}

// configDir returns the path to the ~/.config/cloop directory.
func globalConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("globalbudget: resolving home dir: %w", err)
	}
	return filepath.Join(home, configDir), nil
}

// ConfigPath returns the path to ~/.config/cloop/budget.yaml.
func ConfigPath() (string, error) {
	d, err := globalConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, configFileName), nil
}

// LedgerPath returns the path to ~/.config/cloop/costs.jsonl.
func LedgerPath() (string, error) {
	d, err := globalConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, ledgerFileName), nil
}

// Load reads the global budget config. Returns an empty config (no limits) if
// the file does not exist.
func Load() (GlobalBudgetConfig, error) {
	path, err := ConfigPath()
	if err != nil {
		return GlobalBudgetConfig{}, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return GlobalBudgetConfig{}, nil
	}
	if err != nil {
		return GlobalBudgetConfig{}, fmt.Errorf("globalbudget: reading config: %w", err)
	}
	var cfg GlobalBudgetConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return GlobalBudgetConfig{}, fmt.Errorf("globalbudget: parsing config: %w", err)
	}
	return cfg, nil
}

// Save writes the global budget config to ~/.config/cloop/budget.yaml,
// creating the directory if needed. The write is atomic (tmp → fsync →
// rename), so a crash, ENOSPC, or concurrent reader during the write can
// never leave the file half-written or empty — readers see either the old
// valid file or the new valid file. Concurrent in-process callers are
// serialised via saveMu so two updates can't drop each other.
func Save(cfg GlobalBudgetConfig) error {
	saveMu.Lock()
	defer saveMu.Unlock()

	path, err := ConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("globalbudget: creating config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("globalbudget: marshaling config: %w", err)
	}
	return writeAtomic(path, data, 0o600)
}

// writeAtomic stages data to a sibling .tmp file in the same directory,
// fsyncs it, then renames it over path. Rename within a directory is atomic
// on POSIX/Linux, so any concurrent reader either sees the old file or the
// new file — never a half-written one.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("globalbudget: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("globalbudget: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("globalbudget: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("globalbudget: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("globalbudget: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("globalbudget: rename tmp: %w", err)
	}
	return nil
}

// AppendLedger appends a global ledger entry to ~/.config/cloop/costs.jsonl.
// Concurrent in-process callers are serialised via ledgerMu so JSON object
// writes can't interleave on the shared file (json.Encoder issues separate
// Write calls for the JSON body and the trailing newline). Cross-process
// races aren't guarded — only one cloop daemon is expected per host.
func AppendLedger(entry GlobalLedgerEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	path, err := LedgerPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("globalbudget: creating ledger dir: %w", err)
	}

	ledgerMu.Lock()
	defer ledgerMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("globalbudget: opening ledger: %w", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(entry)
}

// ReadLedger reads all entries from the global ledger. Returns nil (no error)
// when the file does not exist.
func ReadLedger() ([]GlobalLedgerEntry, error) {
	path, err := LedgerPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("globalbudget: opening ledger: %w", err)
	}
	defer f.Close()

	var entries []GlobalLedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e GlobalLedgerEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

// DailyUsage returns today's (UTC) aggregated usage across all projects from
// the global ledger.
func DailyUsage() (DailyStats, error) {
	entries, err := ReadLedger()
	if err != nil {
		return DailyStats{}, err
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

// EffectiveProjectUSDLimit returns the project-level effective daily USD cap
// derived from the global budget and the per-project percentage.
// Returns 0 when there is no global USD limit or no percentage configured.
func EffectiveProjectUSDLimit(globalCfg GlobalBudgetConfig, pct float64) float64 {
	if globalCfg.DailyUSDLimit <= 0 || pct <= 0 {
		return 0
	}
	return globalCfg.DailyUSDLimit * pct / 100.0
}

// EffectiveProjectTokenLimit returns the project-level effective daily token
// cap derived from the global budget and the per-project percentage.
// Returns 0 when there is no global token limit or no percentage configured.
func EffectiveProjectTokenLimit(globalCfg GlobalBudgetConfig, pct float64) int {
	if globalCfg.DailyTokenLimit <= 0 || pct <= 0 {
		return 0
	}
	return int(float64(globalCfg.DailyTokenLimit) * pct / 100.0)
}
