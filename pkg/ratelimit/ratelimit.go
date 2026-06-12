// Package ratelimit captures and exposes Anthropic API rate-limit information
// from anthropic-ratelimit-* response headers.
//
// On every Anthropic API call, callers invoke Record(model, headers). The
// package parses recognised headers (RPM, ITPM, OTPM, weekly/5h windows,
// priority tier) and stores a per-model snapshot in memory. Snapshots are
// also persisted to ~/.cloop/ratelimits.json so the Web UI can display the
// most recent values across cloop invocations.
package ratelimit

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
)

// Window is a single rate-limit dimension snapshot.
type Window struct {
	Limit     int64     `json:"limit"`
	Remaining int64     `json:"remaining"`
	Reset     time.Time `json:"reset,omitempty"`
}

// Used returns the consumed amount within the window.
func (w Window) Used() int64 {
	if w.Limit <= 0 {
		return 0
	}
	if w.Remaining < 0 {
		return w.Limit
	}
	if w.Remaining > w.Limit {
		return 0
	}
	return w.Limit - w.Remaining
}

// PercentUsed returns 0..100.
func (w Window) PercentUsed() int {
	if w.Limit <= 0 {
		return 0
	}
	pct := int(w.Used() * 100 / w.Limit)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

// ModelLimits is the full rate-limit snapshot for one model.
type ModelLimits struct {
	Model       string    `json:"model"`
	UpdatedAt   time.Time `json:"updated_at"`
	Tier        string    `json:"tier,omitempty"`         // anthropic-priority-tier or similar
	Requests    Window    `json:"requests"`               // RPM
	Tokens      Window    `json:"tokens"`                 // overall TPM (legacy, may be 0)
	InputTokens Window    `json:"input_tokens"`           // ITPM
	OutputTokens Window   `json:"output_tokens"`          // OTPM
	Weekly      Window    `json:"weekly,omitempty"`       // weekly window if present
	FiveHour    Window    `json:"five_hour,omitempty"`    // 5-hour rolling window
	MonthlySpendUSD float64 `json:"monthly_spend_usd,omitempty"` // x-spend-limit-monthly if present
	// Raw is the full set of anthropic-ratelimit-* headers as returned by the
	// API, for debugging / forward-compatibility.
	Raw map[string]string `json:"raw,omitempty"`
}

// store is the package-level in-memory state.
var (
	mu     sync.RWMutex
	models = map[string]*ModelLimits{}
	loaded bool
)

const persistFile = "ratelimits.json"

// configDir returns the directory used to persist snapshots.
func configDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cloop")
	}
	return ".cloop"
}

// persistPath returns the on-disk JSON path.
func persistPath() string {
	return filepath.Join(configDir(), persistFile)
}

// loadOnce reads the persisted snapshot file (if any) on first access.
func loadOnce() {
	if loaded {
		return
	}
	loaded = true
	data, err := os.ReadFile(persistPath())
	if err != nil {
		return
	}
	var on map[string]*ModelLimits
	if err := json.Unmarshal(data, &on); err != nil {
		return
	}
	for k, v := range on {
		models[k] = v
	}
}

// persist writes the current snapshot map atomically to disk.
//
// Uses atomicfile.Write (fsync + rename + parent-dir fsync) instead of the
// previous bare tmp-and-rename — the old path could lose the rename on power
// loss, and on next startup the Web UI would surface stale rate-limit data.
func persist() {
	dir := configDir()
	_ = os.MkdirAll(dir, 0o755)
	data, err := json.MarshalIndent(models, "", "  ")
	if err != nil {
		return
	}
	_ = atomicfile.Write(persistPath(), data, 0o600)
}

// parseInt is a tolerant int64 parser.
func parseInt(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// parseReset parses an RFC3339 timestamp; returns zero time on failure.
func parseReset(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// Record extracts anthropic-ratelimit-* headers from h and stores them under
// model. Safe to call from concurrent provider goroutines. Headers absent
// from the response are not zeroed; the previous values for those dimensions
// are preserved.
func Record(model string, h http.Header) {
	if model == "" || h == nil {
		return
	}

	mu.Lock()
	defer mu.Unlock()
	loadOnce()

	cur, ok := models[model]
	if !ok {
		cur = &ModelLimits{Model: model, Raw: map[string]string{}}
		models[model] = cur
	}
	if cur.Raw == nil {
		cur.Raw = map[string]string{}
	}

	updated := false

	// Iterate canonical header keys.
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		v := vs[0]
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "anthropic-ratelimit-") {
			cur.Raw[lk] = v
			updated = true
		}

		switch lk {
		case "anthropic-ratelimit-requests-limit":
			cur.Requests.Limit = parseInt(v)
		case "anthropic-ratelimit-requests-remaining":
			cur.Requests.Remaining = parseInt(v)
		case "anthropic-ratelimit-requests-reset":
			cur.Requests.Reset = parseReset(v)

		case "anthropic-ratelimit-tokens-limit":
			cur.Tokens.Limit = parseInt(v)
		case "anthropic-ratelimit-tokens-remaining":
			cur.Tokens.Remaining = parseInt(v)
		case "anthropic-ratelimit-tokens-reset":
			cur.Tokens.Reset = parseReset(v)

		case "anthropic-ratelimit-input-tokens-limit":
			cur.InputTokens.Limit = parseInt(v)
		case "anthropic-ratelimit-input-tokens-remaining":
			cur.InputTokens.Remaining = parseInt(v)
		case "anthropic-ratelimit-input-tokens-reset":
			cur.InputTokens.Reset = parseReset(v)

		case "anthropic-ratelimit-output-tokens-limit":
			cur.OutputTokens.Limit = parseInt(v)
		case "anthropic-ratelimit-output-tokens-remaining":
			cur.OutputTokens.Remaining = parseInt(v)
		case "anthropic-ratelimit-output-tokens-reset":
			cur.OutputTokens.Reset = parseReset(v)

		// Long windows (some Anthropic plans expose these).
		case "anthropic-ratelimit-weekly-limit", "anthropic-ratelimit-tokens-weekly-limit":
			cur.Weekly.Limit = parseInt(v)
		case "anthropic-ratelimit-weekly-remaining", "anthropic-ratelimit-tokens-weekly-remaining":
			cur.Weekly.Remaining = parseInt(v)
		case "anthropic-ratelimit-weekly-reset", "anthropic-ratelimit-tokens-weekly-reset":
			cur.Weekly.Reset = parseReset(v)

		case "anthropic-ratelimit-tokens-5h-limit", "anthropic-ratelimit-five-hour-limit":
			cur.FiveHour.Limit = parseInt(v)
		case "anthropic-ratelimit-tokens-5h-remaining", "anthropic-ratelimit-five-hour-remaining":
			cur.FiveHour.Remaining = parseInt(v)
		case "anthropic-ratelimit-tokens-5h-reset", "anthropic-ratelimit-five-hour-reset":
			cur.FiveHour.Reset = parseReset(v)

		// Tier / priority info.
		case "anthropic-priority-tier", "x-anthropic-tier", "anthropic-tier":
			cur.Tier = v
			updated = true

		// Spend limit (may not be standard; supported optimistically).
		case "x-spend-limit-monthly", "anthropic-spend-limit-monthly":
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				cur.MonthlySpendUSD = f
				updated = true
			}
		}
	}

	if !updated && cur.Requests.Limit == 0 && cur.InputTokens.Limit == 0 && cur.OutputTokens.Limit == 0 && cur.Tokens.Limit == 0 {
		// Nothing useful seen; do not overwrite timestamp/persist.
		return
	}
	cur.UpdatedAt = time.Now().UTC()
	persist()
}

// Snapshot returns a deep-ish copy of the current per-model rate-limit map.
// Map keys are model names. Caller may freely read from the result without
// locking.
func Snapshot() map[string]ModelLimits {
	mu.Lock()
	defer mu.Unlock()
	loadOnce()

	out := make(map[string]ModelLimits, len(models))
	for k, v := range models {
		c := *v
		if v.Raw != nil {
			c.Raw = make(map[string]string, len(v.Raw))
			for rk, rv := range v.Raw {
				c.Raw[rk] = rv
			}
		}
		out[k] = c
	}
	return out
}

// Clear wipes all stored snapshots (used by tests).
func Clear() {
	mu.Lock()
	defer mu.Unlock()
	models = map[string]*ModelLimits{}
	_ = os.Remove(persistPath())
}

// Probe makes a lightweight Anthropic API call (1 token max) to capture
// rate-limit headers for the given model. This is used when the claudecode
// CLI provider is active and no headers are available from direct API calls.
// apiKey can be an API key or OAuth token (sk-ant-oat01-*).
func Probe(apiKey, model string) error {
	if apiKey == "" || model == "" {
		return nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	body := `{"model":"` + model + `","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	// Support both API keys and OAuth tokens
	if strings.HasPrefix(apiKey, "sk-ant-oat") {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		req.Header.Set("x-api-key", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Record headers regardless of status code — even 429s have rate-limit headers
	Record(model, resp.Header)
	return nil
}

// ProbeAll probes rate limits for common Anthropic models.
func ProbeAll(apiKey string) {
	for _, model := range []string{
		"claude-sonnet-4-6",
		"claude-opus-4-8",
		"claude-opus-4-7",
		"claude-opus-4-6",
		"claude-fable-4-8",
		"claude-haiku-4-5",
	} {
		_ = Probe(apiKey, model)
	}
}
