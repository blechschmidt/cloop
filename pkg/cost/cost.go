// Package cost provides token-cost estimation for common AI model providers.
// Prices are per 1M tokens and are approximate — they may lag behind
// official pricing changes. Always verify with your provider's pricing page.
package cost

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/globalbudget"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const ledgerFile = ".cloop/costs.jsonl"
const stateDBFile = ".cloop/state.db"

// IdentityLocal is the sentinel for spend nobody authenticated: a bare
// `cloop run` from a terminal, or a hub with OIDC switched off.
//
// A sentinel rather than an empty string because the two mean different
// things and a report has to tell them apart. "local" is a positive claim —
// this ran outside any identity system, and on a single-user install that is
// every row. Empty means the row predates attribution entirely (migration
// 0035) and cloop genuinely does not know. Folding the second into the first
// would put historical spend under a name, which is a guess dressed as a fact.
//
// It cannot collide with a real identity: OwnerKey yields either a lowercased
// email (contains "@") or a "sub:"-prefixed subject, and "local" is neither.
const IdentityLocal = "local"

// IdentityUnattributed is how reports label rows with no identity at all.
const IdentityUnattributed = "(unattributed)"

// LedgerEntry records the cost of one task execution.
type LedgerEntry struct {
	Timestamp      time.Time `json:"timestamp"`
	TaskID         int       `json:"task_id"`
	TaskTitle      string    `json:"task_title"`
	Provider       string    `json:"provider"`
	Model          string    `json:"model"`
	InputTokens    int       `json:"input_tokens"`
	OutputTokens   int       `json:"output_tokens"`
	ThinkingTokens int       `json:"thinking_tokens,omitempty"`
	EstimatedUSD   float64   `json:"estimated_usd"`

	// Identity attributes this spend to whoever initiated the run: an
	// oidcauth OwnerKey (lowercased email, or "sub:<subject>"), or
	// IdentityLocal. Empty means unattributed — see migration 0035.
	Identity string `json:"identity,omitempty"`
}

// AppendLedger appends a cost entry to the project's SQLite database (primary)
// and to .cloop/costs.jsonl (legacy fallback for backward compatibility).
// It also mirrors to the global ledger at ~/.config/cloop/costs.jsonl.
func AppendLedger(workDir string, entry LedgerEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// ── Primary: write to SQLite state.db ──────────────────────────────
	dbPath := filepath.Join(workDir, stateDBFile)
	if _, err := os.Stat(dbPath); err == nil {
		if db, err := statedb.Open(dbPath); err == nil {
			_ = db.AppendCost(statedb.CostEntry{
				Timestamp:      entry.Timestamp,
				TaskID:         entry.TaskID,
				TaskTitle:      entry.TaskTitle,
				Provider:       entry.Provider,
				Model:          entry.Model,
				InputTokens:    entry.InputTokens,
				OutputTokens:   entry.OutputTokens,
				ThinkingTokens: entry.ThinkingTokens,
				EstimatedUSD:   entry.EstimatedUSD,
				Identity:       entry.Identity,
			})
			db.Close()
		}
	}

	// ── Legacy: also write to costs.jsonl for backward compatibility ───
	path := filepath.Join(workDir, ledgerFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(entry); err != nil {
		return err
	}

	// ── Mirror to global ledger (best-effort) ──────────────────────────
	_ = globalbudget.AppendLedger(globalbudget.GlobalLedgerEntry{
		Timestamp:      entry.Timestamp,
		ProjectPath:    workDir,
		TaskID:         entry.TaskID,
		TaskTitle:      entry.TaskTitle,
		Provider:       entry.Provider,
		Model:          entry.Model,
		InputTokens:    entry.InputTokens,
		OutputTokens:   entry.OutputTokens,
		ThinkingTokens: entry.ThinkingTokens,
		EstimatedUSD:   entry.EstimatedUSD,
		Identity:       entry.Identity,
	})
	return nil
}

// ReadLedger reads all cost entries. When a SQLite state.db exists it reads
// from the costs table (primary). It then merges any JSONL-only entries that
// are not yet in the database (legacy migration path). Returns an empty slice
// (not an error) when neither source has data.
func ReadLedger(workDir string) ([]LedgerEntry, error) {
	dbPath := filepath.Join(workDir, stateDBFile)
	if _, err := os.Stat(dbPath); err == nil {
		db, err := statedb.Open(dbPath)
		if err == nil {
			defer db.Close()
			rows, err := db.ReadCosts()
			if err == nil {
				// Also read the JSONL file and migrate any entries missing from DB.
				jsonlEntries := readJSONLCosts(workDir)
				migrated := migrateJSONLToDB(db, rows, jsonlEntries)
				if migrated > 0 {
					// Re-read after migration.
					rows, _ = db.ReadCosts()
				}
				return dbRowsToEntries(rows), nil
			}
		}
	}
	// Fallback: read from JSONL only.
	return readJSONLCosts(workDir), nil
}

// readJSONLCosts reads all entries from .cloop/costs.jsonl.
func readJSONLCosts(workDir string) []LedgerEntry {
	path := filepath.Join(workDir, ledgerFile)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []LedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e LedgerEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// migrateJSONLToDB inserts JSONL entries that are not already in the DB
// (matched by timestamp+task_id). Returns the number of entries inserted.
func migrateJSONLToDB(db *statedb.DB, existing []statedb.CostEntry, jsonl []LedgerEntry) int {
	if len(jsonl) == 0 {
		return 0
	}
	// Build a set of existing (timestamp, task_id) pairs.
	type key struct {
		ts     string
		taskID int
	}
	have := make(map[key]struct{}, len(existing))
	for _, e := range existing {
		have[key{e.Timestamp.UTC().Format(time.RFC3339), e.TaskID}] = struct{}{}
	}
	var inserted int
	for _, e := range jsonl {
		k := key{e.Timestamp.UTC().Format(time.RFC3339), e.TaskID}
		if _, ok := have[k]; ok {
			continue
		}
		_ = db.AppendCost(statedb.CostEntry{
			Timestamp:      e.Timestamp,
			TaskID:         e.TaskID,
			TaskTitle:      e.TaskTitle,
			Provider:       e.Provider,
			Model:          e.Model,
			InputTokens:    e.InputTokens,
			OutputTokens:   e.OutputTokens,
			ThinkingTokens: e.ThinkingTokens,
			EstimatedUSD:   e.EstimatedUSD,
			Identity:       e.Identity,
		})
		inserted++
	}
	return inserted
}

// dbRowsToEntries converts statedb.CostEntry slice to LedgerEntry slice.
func dbRowsToEntries(rows []statedb.CostEntry) []LedgerEntry {
	out := make([]LedgerEntry, len(rows))
	for i, r := range rows {
		out[i] = LedgerEntry{
			Timestamp:      r.Timestamp,
			TaskID:         r.TaskID,
			TaskTitle:      r.TaskTitle,
			Provider:       r.Provider,
			Model:          r.Model,
			InputTokens:    r.InputTokens,
			OutputTokens:   r.OutputTokens,
			ThinkingTokens: r.ThinkingTokens,
			EstimatedUSD:   r.EstimatedUSD,
			Identity:       r.Identity,
		}
	}
	return out
}

// MonthlyTotal returns the total estimated USD spent in the current calendar month.
func MonthlyTotal(workDir string) (float64, error) {
	now := time.Now().UTC()

	// Fast path: query SQLite directly for the current month.
	dbPath := filepath.Join(workDir, stateDBFile)
	if _, err := os.Stat(dbPath); err == nil {
		if db, err := statedb.Open(dbPath); err == nil {
			defer db.Close()
			rows, err := db.MonthlyCosts(now.Year(), int(now.Month()))
			if err == nil {
				var total float64
				for _, r := range rows {
					total += r.EstimatedUSD
				}
				return total, nil
			}
		}
	}

	// Fallback: scan JSONL.
	entries := readJSONLCosts(workDir)
	var total float64
	for _, e := range entries {
		if e.Timestamp.Year() == now.Year() && e.Timestamp.Month() == now.Month() {
			total += e.EstimatedUSD
		}
	}
	return total, nil
}

// ModelPricing holds the input and output cost in USD per 1M tokens.
type ModelPricing struct {
	InputPerM  float64
	OutputPerM float64
	// CacheReadFactor is the price of a prompt-cache read as a multiple of
	// InputPerM. Zero means the standard tenth (cacheReadPriceFactor). Claude
	// Fable 5.1 and 5.2 and Claude Mythos 5.1 and 5.2 bill a fortieth, Claude
	// Opus 5.5 and Claude Sonnet 5.5 a twentieth.
	CacheReadFactor float64
	// LongPromptOver and LongPromptFactor are Claude Haiku 5.5's long-prompt
	// price: a request whose prompt has more than LongPromptOver tokens,
	// counting every input token including cache reads and writes, pays
	// LongPromptFactor times every price. Zero means the model has one price
	// at any prompt length.
	LongPromptOver   int64
	LongPromptFactor float64
}

// prices is a lookup table of known model pricing (USD / 1M tokens).
// Keys are lowercase model IDs. Partial prefix matches are tried on miss.
var prices = map[string]ModelPricing{
	// Anthropic Claude 5 / 4.x, from Anthropic's pricing page (checked
	// 2026-11-10). The model relay enforces daily_cost_usd from this table
	// (Task 20435), so an unpriced model is a free one: lookup misses,
	// Estimate reports (0, false), EstimateSessionCost returns 0, and no
	// spend cap can stop what it measures as zero. Every model in
	// provider.ClaudeModels must have an exact entry here; cost_test.go
	// checks that. Lookup is exact-match first, so a key such as
	// claude-opus-5 never shadows claude-opus-5-5.
	"claude-fable-5-2":  {InputPerM: 8.00, OutputPerM: 40.00, CacheReadFactor: 0.025},
	"claude-fable-5-1":  {InputPerM: 10.00, OutputPerM: 50.00, CacheReadFactor: 0.025},
	"claude-fable-5":    {InputPerM: 10.00, OutputPerM: 50.00},
	"claude-opus-5-5":   {InputPerM: 4.00, OutputPerM: 20.00, CacheReadFactor: 0.05},
	"claude-opus-5":     {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-opus-4-8":   {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-opus-4-7":   {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-opus-4-6":   {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-opus-4-5":   {InputPerM: 5.00, OutputPerM: 25.00},
	"claude-sonnet-5-5": {InputPerM: 2.00, OutputPerM: 10.00, CacheReadFactor: 0.05},
	// Sonnet 5's launch price of $2/$10 became its standard price; the rise
	// to $3/$15 announced for 2026-09-01 did not happen.
	"claude-sonnet-5":   {InputPerM: 2.00, OutputPerM: 10.00},
	"claude-sonnet-4-6": {InputPerM: 3.00, OutputPerM: 15.00},
	"claude-sonnet-4-5": {InputPerM: 3.00, OutputPerM: 15.00},
	"claude-haiku-5-5":  {InputPerM: 0.10, OutputPerM: 0.50, LongPromptOver: 100_000, LongPromptFactor: 5},
	"claude-haiku-4-5":  {InputPerM: 1.00, OutputPerM: 5.00},
	// Claude Mythos is served only to organizations in Anthropic's
	// verification programs, at Fable's prices. No picker offers it, but a
	// relayed call to it must not book as free.
	"claude-mythos-5-2": {InputPerM: 8.00, OutputPerM: 40.00, CacheReadFactor: 0.025},
	"claude-mythos-5-1": {InputPerM: 10.00, OutputPerM: 50.00, CacheReadFactor: 0.025},
	"claude-mythos-5":   {InputPerM: 10.00, OutputPerM: 50.00},
	// Anthropic Claude 3.x
	"claude-3-opus-20240229":     {InputPerM: 15.00, OutputPerM: 75.00},
	"claude-3-5-sonnet-20241022": {InputPerM: 3.00, OutputPerM: 15.00},
	"claude-3-5-haiku-20241022":  {InputPerM: 0.80, OutputPerM: 4.00},
	"claude-3-haiku-20240307":    {InputPerM: 0.25, OutputPerM: 1.25},
	// OpenAI GPT-4o
	"gpt-4o":        {InputPerM: 2.50, OutputPerM: 10.00},
	"gpt-4o-mini":   {InputPerM: 0.15, OutputPerM: 0.60},
	"gpt-4-turbo":   {InputPerM: 10.00, OutputPerM: 30.00},
	"gpt-4":         {InputPerM: 30.00, OutputPerM: 60.00},
	"gpt-3.5-turbo": {InputPerM: 0.50, OutputPerM: 1.50},
	// OpenAI o-series
	"o1":      {InputPerM: 15.00, OutputPerM: 60.00},
	"o1-mini": {InputPerM: 3.00, OutputPerM: 12.00},
	"o3-mini": {InputPerM: 1.10, OutputPerM: 4.40},
	// Google (via OpenAI-compat)
	"gemini-1.5-pro":   {InputPerM: 1.25, OutputPerM: 5.00},
	"gemini-1.5-flash": {InputPerM: 0.075, OutputPerM: 0.30},
	// Ollama / local models — zero cost
	"llama3":   {InputPerM: 0, OutputPerM: 0},
	"llama3.2": {InputPerM: 0, OutputPerM: 0},
	"llama3.1": {InputPerM: 0, OutputPerM: 0},
	"mistral":  {InputPerM: 0, OutputPerM: 0},
	"mixtral":  {InputPerM: 0, OutputPerM: 0},
	"phi3":     {InputPerM: 0, OutputPerM: 0},
	"qwen":     {InputPerM: 0, OutputPerM: 0},
	"deepseek": {InputPerM: 0, OutputPerM: 0},
}

// Estimate returns the estimated cost in USD for the given token counts.
// model is matched case-insensitively; unrecognised models return (0, false).
// Totals do not say how long each request's prompt was, so a model with a
// long-prompt price (Claude Haiku 5.5) is priced at its standard rate here;
// EstimateCached, which prices one response, applies it.
func Estimate(model string, inputTokens, outputTokens int) (usd float64, ok bool) {
	p, ok := lookup(strings.ToLower(strings.TrimSpace(model)))
	if !ok {
		return 0, false
	}
	return (float64(inputTokens)/1_000_000)*p.InputPerM +
		(float64(outputTokens)/1_000_000)*p.OutputPerM, true
}

// CachedUsage is a Messages API response's token counts with prompt caching
// broken out: Input is the uncached input, CacheWrite5m and CacheWrite1h the
// input written to the five-minute and the one-hour cache, CacheRead the input
// served from it.
type CachedUsage struct {
	Input, Output, CacheRead, CacheWrite5m, CacheWrite1h int64
}

// Prompt-caching prices, as multiples of a model's input price: a cache read
// costs a tenth of an uncached input token unless the model says otherwise
// (ModelPricing.CacheReadFactor), a five-minute cache write a quarter more, a
// one-hour write twice as much.
const (
	cacheReadPriceFactor    = 0.1
	cacheWrite5mPriceFactor = 1.25
	cacheWrite1hPriceFactor = 2.0
)

// EstimateCached prices a response's usage with its cache reads and writes at
// their own rates (Task 20435). Estimate has no cache tokens to price; the
// hub's model relay meters them from the API's own responses, and an agent
// harness's input is mostly cache reads, so pricing them as uncached input
// would bill a run several times over. u is one response's usage, so a
// model's long-prompt price applies when that request's prompt was over its
// threshold. Unrecognised models return (0, false).
func EstimateCached(model string, u CachedUsage) (usd float64, ok bool) {
	p, ok := lookup(strings.ToLower(strings.TrimSpace(model)))
	if !ok {
		return 0, false
	}
	readFactor := p.CacheReadFactor
	if readFactor <= 0 {
		readFactor = cacheReadPriceFactor
	}
	scale := 1.0
	if p.LongPromptOver > 0 && p.LongPromptFactor > 0 &&
		u.Input+u.CacheRead+u.CacheWrite5m+u.CacheWrite1h > p.LongPromptOver {
		scale = p.LongPromptFactor
	}
	perIn := scale * p.InputPerM / 1_000_000
	return float64(u.Input)*perIn +
		float64(u.Output)*(scale*p.OutputPerM/1_000_000) +
		float64(u.CacheRead)*perIn*readFactor +
		float64(u.CacheWrite5m)*perIn*cacheWrite5mPriceFactor +
		float64(u.CacheWrite1h)*perIn*cacheWrite1hPriceFactor, true
}

// EstimateSessionCost returns the estimated cost in USD for the session.
// provider is used as a hint: "ollama" always returns 0 (local). For unknown
// models the function returns 0. Returns 0 when cost cannot be determined.
func EstimateSessionCost(provider, model string, inputTokens, outputTokens int) float64 {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "ollama" {
		return 0
	}
	// For claudecode without an explicit model, fall back to a safe default.
	m := strings.TrimSpace(model)
	if m == "" && p == "claudecode" {
		m = "claude-sonnet-4-6"
	}
	usd, ok := Estimate(strings.ToLower(m), inputTokens, outputTokens)
	if !ok {
		return 0
	}
	return usd
}

// FormatCost returns a human-readable cost string, e.g. "$0.0042" or "$1.23".
func FormatCost(usd float64) string {
	if usd == 0 {
		return "$0.00 (local)"
	}
	if usd < 0.0001 {
		return fmt.Sprintf("$%.6f", usd)
	}
	if usd < 0.01 {
		return fmt.Sprintf("$%.4f", usd)
	}
	return fmt.Sprintf("$%.2f", usd)
}

// FormatCostWithLimit returns a human-readable cost string with optional limit info.
// e.g. "$0.0042 / $1.00" when limit > 0.
func FormatCostWithLimit(usd, limit float64) string {
	base := FormatCost(usd)
	if limit <= 0 {
		return base
	}
	return fmt.Sprintf("%s / %s", base, FormatCost(limit))
}

// lookup performs an exact then prefix-based match.
func lookup(model string) (ModelPricing, bool) {
	// Exact match
	if p, ok := prices[model]; ok {
		return p, true
	}
	// Prefix match — find longest key that is a prefix of the model name
	var best string
	for k := range prices {
		if len(k) > len(best) && len(model) >= len(k) && model[:len(k)] == k {
			best = k
		}
	}
	if best != "" {
		return prices[best], true
	}
	return ModelPricing{}, false
}
