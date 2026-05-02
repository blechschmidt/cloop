// Package bench provides side-by-side provider benchmarking for cloop.
// It runs the same prompt against multiple providers concurrently and
// produces a comparison report with latency, token counts, cost estimates,
// and optional AI-rated quality scores.
package bench

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// RunConfig holds the configuration for a benchmark run.
type RunConfig struct {
	// Prompt is the text sent to all providers.
	Prompt string
	// Providers is the list of provider names to benchmark.
	Providers []string
	// Models maps provider name → model override (empty = use provider default).
	Models map[string]string
	// Runs is the number of times each provider is called (results are averaged).
	Runs int
	// JudgeProvider is the provider used to rate response quality (empty = skip).
	JudgeProvider string
	// Timeout per individual completion call.
	Timeout time.Duration
}

// ProviderResult holds aggregated results for a single provider.
type ProviderResult struct {
	ProviderName string
	Model        string
	// Averaged across runs.
	AvgLatencyMS float64
	MinLatencyMS float64
	MaxLatencyMS float64
	AvgInputTokens  float64
	AvgOutputTokens float64
	TotalCostUSD    float64
	// QualityScore is 1-10 as judged by the JudgeProvider. 0 means not rated.
	QualityScore float64
	// LastResponse is the last successful response (used for quality scoring).
	LastResponse string
	// Error is set when the provider failed on all runs.
	Error string
	// SuccessfulRuns counts how many runs succeeded.
	SuccessfulRuns int
}

// Report is the result of a full benchmark session.
type Report struct {
	Prompt    string
	Runs      int
	Timestamp time.Time
	Results   []*ProviderResult
}

// Run executes the benchmark and returns a Report.
// providerBuilders maps provider name → a built Provider instance.
func Run(ctx context.Context, cfg RunConfig, providerBuilders map[string]provider.Provider) (*Report, error) {
	if cfg.Runs < 1 {
		cfg.Runs = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}

	report := &Report{
		Prompt:    cfg.Prompt,
		Runs:      cfg.Runs,
		Timestamp: time.Now(),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, name := range cfg.Providers {
		prov, ok := providerBuilders[name]
		if !ok {
			r := &ProviderResult{
				ProviderName: name,
				Error:        fmt.Sprintf("provider %q not found or not built", name),
			}
			report.Results = append(report.Results, r)
			continue
		}

		model := cfg.Models[name]
		if model == "" {
			model = prov.DefaultModel()
		}

		wg.Add(1)
		go func(provName string, p provider.Provider, mdl string) {
			defer wg.Done()
			r := benchmarkProvider(ctx, cfg, provName, p, mdl)
			mu.Lock()
			report.Results = append(report.Results, r)
			mu.Unlock()
		}(name, prov, model)
	}

	wg.Wait()

	// Preserve original order from cfg.Providers.
	ordered := make([]*ProviderResult, 0, len(report.Results))
	for _, name := range cfg.Providers {
		for _, r := range report.Results {
			if r.ProviderName == name {
				ordered = append(ordered, r)
				break
			}
		}
	}
	report.Results = ordered

	// Quality scoring via judge provider.
	if cfg.JudgeProvider != "" {
		judge, ok := providerBuilders[cfg.JudgeProvider]
		if ok {
			rateResponses(ctx, cfg, judge, report)
		}
	}

	return report, nil
}

func benchmarkProvider(ctx context.Context, cfg RunConfig, name string, p provider.Provider, model string) *ProviderResult {
	r := &ProviderResult{
		ProviderName: name,
		Model:        model,
		MinLatencyMS: math.MaxFloat64,
	}

	var totalLatency, totalInput, totalOutput float64
	var totalCost float64

	for i := 0; i < cfg.Runs; i++ {
		runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		start := time.Now()
		result, err := p.Complete(runCtx, cfg.Prompt, provider.Options{
			Model:     model,
			MaxTokens: 2048,
			Timeout:   cfg.Timeout,
		})
		elapsed := time.Since(start)
		cancel()

		if err != nil {
			// Record the error but continue remaining runs.
			if r.Error == "" {
				r.Error = err.Error()
			}
			continue
		}

		r.SuccessfulRuns++
		latencyMS := float64(elapsed.Milliseconds())
		totalLatency += latencyMS
		if latencyMS < r.MinLatencyMS {
			r.MinLatencyMS = latencyMS
		}
		if latencyMS > r.MaxLatencyMS {
			r.MaxLatencyMS = latencyMS
		}
		totalInput += float64(result.InputTokens)
		totalOutput += float64(result.OutputTokens)

		usd, _ := cost.Estimate(strings.ToLower(model), result.InputTokens, result.OutputTokens)
		totalCost += usd

		r.LastResponse = result.Output
	}

	if r.SuccessfulRuns == 0 {
		r.MinLatencyMS = 0
		return r
	}

	n := float64(r.SuccessfulRuns)
	r.AvgLatencyMS = totalLatency / n
	r.AvgInputTokens = totalInput / n
	r.AvgOutputTokens = totalOutput / n
	r.TotalCostUSD = totalCost
	return r
}

// rateResponses asks the judge provider to score each successful response 1-10.
func rateResponses(ctx context.Context, cfg RunConfig, judge provider.Provider, report *Report) {
	for _, r := range report.Results {
		if r.SuccessfulRuns == 0 || r.LastResponse == "" {
			continue
		}

		ratePrompt := fmt.Sprintf(
			"You are evaluating AI assistant responses. "+
				"Rate the following response on a scale of 1 to 10 (10 = excellent), "+
				"considering accuracy, completeness, clarity, and usefulness. "+
				"Reply with ONLY a single integer between 1 and 10.\n\n"+
				"Original prompt: %s\n\n"+
				"Response to rate:\n%s",
			cfg.Prompt, r.LastResponse,
		)

		rateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		result, err := judge.Complete(rateCtx, ratePrompt, provider.Options{
			MaxTokens: 10,
			Timeout:   30 * time.Second,
		})
		cancel()

		if err != nil {
			continue
		}

		scoreStr := strings.TrimSpace(result.Output)
		// Handle cases like "8/10" or "8."
		scoreStr = strings.Split(scoreStr, "/")[0]
		scoreStr = strings.TrimRight(scoreStr, ".")
		if score, err := strconv.Atoi(scoreStr); err == nil && score >= 1 && score <= 10 {
			r.QualityScore = float64(score)
		}
	}
}

// FormatMarkdownTable formats the report as a markdown table.
func FormatMarkdownTable(r *Report) string {
	var sb strings.Builder

	sb.WriteString("## cloop bench results\n\n")
	sb.WriteString(fmt.Sprintf("**Prompt:** `%s`  \n", r.Prompt))
	sb.WriteString(fmt.Sprintf("**Runs per provider:** %d  \n", r.Runs))
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", r.Timestamp.Format(time.RFC3339)))

	// Determine whether to show quality score column.
	hasScores := false
	for _, res := range r.Results {
		if res.QualityScore > 0 {
			hasScores = true
			break
		}
	}

	// Header
	header := "| Provider | Model | Avg Latency | Min/Max (ms) | Avg Input Tokens | Avg Output Tokens | Est. Cost | Runs |"
	sep := "|----------|-------|-------------|--------------|------------------|-------------------|-----------|------|"
	if hasScores {
		header += " Quality (1-10) |"
		sep += "---------------|"
	}
	sb.WriteString(header + "\n")
	sb.WriteString(sep + "\n")

	for _, res := range r.Results {
		if res.Error != "" && res.SuccessfulRuns == 0 {
			row := fmt.Sprintf("| %s | %s | ERROR | — | — | — | — | 0/%d |",
				res.ProviderName, res.Model, r.Runs)
			if hasScores {
				row += " — |"
			}
			sb.WriteString(row + "\n")
			continue
		}

		latency := fmt.Sprintf("%.0f ms", res.AvgLatencyMS)
		minMax := fmt.Sprintf("%.0f / %.0f", res.MinLatencyMS, res.MaxLatencyMS)
		inputTok := fmt.Sprintf("%.0f", res.AvgInputTokens)
		outputTok := fmt.Sprintf("%.0f", res.AvgOutputTokens)
		costStr := cost.FormatCost(res.TotalCostUSD)
		runs := fmt.Sprintf("%d/%d", res.SuccessfulRuns, r.Runs)

		row := fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |",
			res.ProviderName, res.Model, latency, minMax,
			inputTok, outputTok, costStr, runs)

		if hasScores {
			if res.QualityScore > 0 {
				row += fmt.Sprintf(" %.0f |", res.QualityScore)
			} else {
				row += " — |"
			}
		}
		sb.WriteString(row + "\n")
	}

	sb.WriteString("\n")
	return sb.String()
}

// SaveReport writes the markdown report to .cloop/bench-results/<timestamp>.md.
// Returns the file path written.
func SaveReport(workDir string, r *Report) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "bench-results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating bench-results dir: %w", err)
	}

	filename := r.Timestamp.Format("2006-01-02T15-04-05") + ".md"
	path := filepath.Join(dir, filename)

	content := FormatMarkdownTable(r)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("writing bench report: %w", err)
	}
	return path, nil
}
