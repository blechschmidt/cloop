// Package selfimprove implements the cloop self-improve meta-command.
// It collects execution telemetry (metrics, task stats, prompt stats, checkpoint
// data) and the cloop source tree, then asks the AI to identify performance
// bottlenecks, missing error handling, and UX gaps with concrete file:line
// citations.
package selfimprove

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/metrics"
	"github.com/blechschmidt/cloop/pkg/promptstats"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskstats"
)

// Suggestion is a concrete improvement recommendation with a source location.
type Suggestion struct {
	Rank         int    `json:"rank"`
	Category     string `json:"category"`     // "performance"|"error_handling"|"ux"|"reliability"|"testing"
	Title        string `json:"title"`
	Description  string `json:"description"`
	FileCitation string `json:"file_citation"` // "pkg/foo/bar.go:42" or "pkg/foo/"
	Impact       string `json:"impact"`        // "high"|"medium"|"low"
	Effort       string `json:"effort"`        // "small"|"medium"|"large"
}

// Telemetry holds all gathered runtime signals used to build the prompt.
type Telemetry struct {
	MetricsSummary   *metrics.Summary
	AggStats         *taskstats.AggregateStats
	PromptStats      promptstats.Summary
	CheckpointExists bool
	CheckpointTaskID int
	SourceFileTree   string // compact listing of .go source files
}

// CollectTelemetry gathers runtime telemetry from the project working directory.
// The state is loaded by the caller and passed in. workDir is the project root.
// sourceDir is the root of the cloop source tree (may be empty to skip source scanning).
func CollectTelemetry(s *state.ProjectState, workDir, sourceDir, model string) *Telemetry {
	t := &Telemetry{}

	// Metrics JSON (may not exist)
	if ms, err := metrics.LoadJSON(workDir); err == nil {
		t.MetricsSummary = ms
	}

	// Task stats
	if s != nil {
		t.AggStats = taskstats.Collect(s, workDir, model)
	}

	// Prompt stats
	if records, err := promptstats.Load(workDir); err == nil {
		t.PromptStats = promptstats.Summarize(records)
	}

	// Checkpoint
	if cp, err := checkpoint.Load(workDir); err == nil && cp != nil {
		t.CheckpointExists = true
		t.CheckpointTaskID = cp.TaskID
	}

	// Source file tree
	if sourceDir != "" {
		t.SourceFileTree = buildSourceTree(sourceDir)
	}

	return t
}

// BuildPrompt constructs the AI prompt for self-improvement analysis.
func BuildPrompt(t *Telemetry, sourceDir string) string {
	var b strings.Builder

	b.WriteString("You are a senior Go engineer doing a performance and quality audit of the cloop CLI tool.\n")
	b.WriteString("cloop is an autonomous AI product manager CLI written in Go. It decomposes project goals\n")
	b.WriteString("into tasks, executes them via AI providers (Anthropic Claude, OpenAI, Ollama, Claude Code),\n")
	b.WriteString("tracks state, and closes a feedback loop to improve results.\n\n")

	b.WriteString("Your job: analyze the execution telemetry and source structure below to identify the top\n")
	b.WriteString("RANKED improvement opportunities. Focus on:\n")
	b.WriteString("  1. Performance bottlenecks (slow paths, unnecessary allocations, missing caching)\n")
	b.WriteString("  2. Missing or weak error handling (unchecked errors, silent failures)\n")
	b.WriteString("  3. UX gaps (confusing output, missing progress feedback, poor defaults)\n")
	b.WriteString("  4. Reliability issues (race conditions, incomplete retries, missing timeouts)\n")
	b.WriteString("  5. Testing gaps (untested critical paths, missing integration scenarios)\n\n")

	// Telemetry section
	b.WriteString("## EXECUTION TELEMETRY\n\n")

	if t.MetricsSummary != nil {
		ms := t.MetricsSummary
		b.WriteString("### Run Metrics (last recorded session)\n")
		b.WriteString(fmt.Sprintf("- Provider: %s / Model: %s\n", ms.Provider, ms.Model))
		b.WriteString(fmt.Sprintf("- Duration: %.1fs\n", ms.DurationSecs))
		b.WriteString(fmt.Sprintf("- Tasks: total=%d completed=%d failed=%d skipped=%d\n",
			ms.TasksTotal, ms.TasksCompleted, ms.TasksFailed, ms.TasksSkipped))
		b.WriteString(fmt.Sprintf("- Steps (AI completions): %d\n", ms.StepsTotal))
		if ms.TaskDuration.Count > 0 {
			avg := ms.TaskDuration.Sum / float64(ms.TaskDuration.Count)
			b.WriteString(fmt.Sprintf("- Average task duration: %.1fs (total=%.1fs, count=%d)\n",
				avg, ms.TaskDuration.Sum, ms.TaskDuration.Count))
		}
		// Token totals
		var totalIn, totalOut int64
		for k, v := range ms.TokensUsed {
			if strings.Contains(k, "input") {
				totalIn += v
			} else {
				totalOut += v
			}
		}
		if totalIn > 0 || totalOut > 0 {
			b.WriteString(fmt.Sprintf("- Tokens: input=%d output=%d\n", totalIn, totalOut))
		}
		b.WriteString("\n")
	} else {
		b.WriteString("### Run Metrics\n(no metrics.json found — session metrics not yet recorded)\n\n")
	}

	if t.AggStats != nil && t.AggStats.TotalTasks > 0 {
		agg := t.AggStats
		b.WriteString("### Task Execution Stats\n")
		b.WriteString(fmt.Sprintf("- Total tasks: %d  (done=%d  failed=%d  skipped=%d  pending=%d)\n",
			agg.TotalTasks, agg.DoneTasks, agg.FailedTasks, agg.SkippedTasks, agg.PendingTasks))
		if agg.DoneTasks+agg.FailedTasks > 0 {
			b.WriteString(fmt.Sprintf("- Success rate: %.1f%%\n", agg.SuccessRate))
		}
		if agg.TotalEstimatedMinutes > 0 && agg.TotalActualMinutes > 0 {
			v, _ := taskstats.VariancePct(agg.TotalEstimatedMinutes, agg.TotalActualMinutes)
			b.WriteString(fmt.Sprintf("- Estimate accuracy: est=%dm actual=%dm variance=%+.0f%%\n",
				agg.TotalEstimatedMinutes, agg.TotalActualMinutes, v))
		}
		if agg.TotalHealAttempts > 0 {
			b.WriteString(fmt.Sprintf("- Auto-heal attempts: %d (tasks needed multiple attempts to succeed)\n",
				agg.TotalHealAttempts))
		}
		if agg.TotalVerifyPasses+agg.TotalVerifyFails > 0 {
			b.WriteString(fmt.Sprintf("- Verification: %d passed / %d failed\n",
				agg.TotalVerifyPasses, agg.TotalVerifyFails))
		}
		if len(agg.SlowestTasks) > 0 {
			b.WriteString("- Slowest tasks:\n")
			for _, ts := range agg.SlowestTasks {
				b.WriteString(fmt.Sprintf("    [%d] %s → %dm\n", ts.TaskID, truncate(ts.TaskTitle, 60), ts.ActualMinutes))
			}
		}
		if len(agg.MostHealedTasks) > 0 {
			b.WriteString("- Most-healed tasks (required most retries):\n")
			for _, ts := range agg.MostHealedTasks {
				b.WriteString(fmt.Sprintf("    [%d] %s → %d heals\n", ts.TaskID, truncate(ts.TaskTitle, 60), ts.HealAttempts))
			}
		}
		b.WriteString("\n")
	}

	if t.PromptStats.Total > 0 {
		ps := t.PromptStats
		b.WriteString("### Prompt Statistics\n")
		b.WriteString(fmt.Sprintf("- Total prompt executions: %d  (done=%d  failed=%d  skipped=%d)\n",
			ps.Total, ps.Done, ps.Failed, ps.Skipped))
		if ps.Total > 0 {
			failRate := float64(ps.Failed) / float64(ps.Total) * 100
			b.WriteString(fmt.Sprintf("- Overall failure rate: %.1f%%\n", failRate))
		}
		// Highlight high-failure prompt hashes
		var badHashes []*promptstats.HashStats
		for _, hs := range ps.ByHash {
			if hs.Total >= 2 && hs.FailureRate() >= 0.5 {
				badHashes = append(badHashes, hs)
			}
		}
		if len(badHashes) > 0 {
			sort.Slice(badHashes, func(i, j int) bool {
				return badHashes[i].FailureRate() > badHashes[j].FailureRate()
			})
			b.WriteString("- High-failure prompt patterns (hashes with ≥50% failure):\n")
			for i, hs := range badHashes {
				if i >= 5 {
					break
				}
				b.WriteString(fmt.Sprintf("    hash=%s  failure=%.0f%%  runs=%d  avg_duration=%dms\n",
					hs.Hash, hs.FailureRate()*100, hs.Total, hs.AvgDurMs()))
			}
		}
		b.WriteString("\n")
	}

	if t.CheckpointExists {
		b.WriteString("### Checkpoint\n")
		b.WriteString(fmt.Sprintf("- An interrupted run checkpoint exists (task_id=%d). The tool was\n", t.CheckpointTaskID))
		b.WriteString("  interrupted mid-execution, indicating possible reliability or timeout issues.\n\n")
	}

	// Source structure
	b.WriteString("## SOURCE STRUCTURE\n\n")
	if t.SourceFileTree != "" {
		b.WriteString("### Go Source Files\n```\n")
		b.WriteString(t.SourceFileTree)
		b.WriteString("```\n\n")
	}

	// Sample key source files
	if sourceDir != "" {
		keyFiles := prioritySourceFiles(sourceDir)
		if len(keyFiles) > 0 {
			b.WriteString("### Key Source Excerpts\n\n")
			totalChars := 0
			const maxTotalChars = 12000
			for _, path := range keyFiles {
				if totalChars >= maxTotalChars {
					break
				}
				rel, _ := filepath.Rel(sourceDir, path)
				content, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				// Limit per-file to 2000 chars
				excerpt := string(content)
				if len(excerpt) > 2000 {
					excerpt = excerpt[:2000] + "\n// ... (truncated)\n"
				}
				b.WriteString(fmt.Sprintf("#### %s\n```go\n%s```\n\n", rel, excerpt))
				totalChars += len(excerpt)
			}
		}
	}

	// Instructions
	b.WriteString("## TASK\n\n")
	b.WriteString("Based on the telemetry and source above, identify the top 5-10 most impactful\n")
	b.WriteString("improvement opportunities. Be specific: cite exact files and line ranges where known.\n\n")
	b.WriteString("For each suggestion include:\n")
	b.WriteString("- rank: integer 1–10 (1 = highest priority)\n")
	b.WriteString("- category: one of performance|error_handling|ux|reliability|testing\n")
	b.WriteString("- title: short imperative description (max 80 chars)\n")
	b.WriteString("- description: 1-3 sentences explaining the issue and concrete fix\n")
	b.WriteString("- file_citation: file path (relative to repo root) with optional :line, e.g. pkg/orchestrator/orchestrator.go:145\n")
	b.WriteString("- impact: high|medium|low\n")
	b.WriteString("- effort: small|medium|large\n\n")
	b.WriteString("Respond with ONLY a JSON object in this exact format:\n")
	b.WriteString("```json\n")
	b.WriteString("{\n")
	b.WriteString("  \"suggestions\": [\n")
	b.WriteString("    {\n")
	b.WriteString("      \"rank\": 1,\n")
	b.WriteString("      \"category\": \"performance\",\n")
	b.WriteString("      \"title\": \"Cache repeated provider model lookups\",\n")
	b.WriteString("      \"description\": \"The factory.Build() is called on every task start without caching. Memoize the provider instance per config hash.\",\n")
	b.WriteString("      \"file_citation\": \"pkg/provider/factory.go:39\",\n")
	b.WriteString("      \"impact\": \"medium\",\n")
	b.WriteString("      \"effort\": \"small\"\n")
	b.WriteString("    }\n")
	b.WriteString("  ]\n")
	b.WriteString("}\n")
	b.WriteString("```\n")

	return b.String()
}

// analyzeResponse is the expected JSON structure from the AI.
type analyzeResponse struct {
	Suggestions []*Suggestion `json:"suggestions"`
}

// Analyze calls the provider and parses the ranked improvement suggestions.
func Analyze(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, prompt string) ([]*Suggestion, error) {
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	opts := provider.Options{
		Model:   model,
		Timeout: timeout,
	}

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("provider call failed: %w", err)
	}

	return parseResponse(result.Output)
}

// parseResponse extracts suggestions from the AI output, tolerating markdown fences.
func parseResponse(output string) ([]*Suggestion, error) {
	// Strip ```json ... ``` fences if present
	raw := output
	if idx := strings.Index(raw, "```json"); idx >= 0 {
		raw = raw[idx+7:]
		if end := strings.Index(raw, "```"); end >= 0 {
			raw = raw[:end]
		}
	} else if idx := strings.Index(raw, "```"); idx >= 0 {
		raw = raw[idx+3:]
		if end := strings.Index(raw, "```"); end >= 0 {
			raw = raw[:end]
		}
	}
	raw = strings.TrimSpace(raw)

	// Find the JSON object boundaries
	start := strings.Index(raw, "{")
	if start < 0 {
		return nil, fmt.Errorf("no JSON object found in AI response")
	}
	end := strings.LastIndex(raw, "}")
	if end < start {
		return nil, fmt.Errorf("malformed JSON in AI response")
	}
	raw = raw[start : end+1]

	var resp analyzeResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("parse AI response JSON: %w", err)
	}

	if len(resp.Suggestions) == 0 {
		return nil, fmt.Errorf("AI returned no suggestions")
	}

	// Sort by rank (ascending)
	sort.Slice(resp.Suggestions, func(i, j int) bool {
		return resp.Suggestions[i].Rank < resp.Suggestions[j].Rank
	})

	return resp.Suggestions, nil
}

// buildSourceTree returns a compact listing of Go source files under root,
// limited to 200 entries to keep prompt size manageable.
func buildSourceTree(root string) string {
	var lines []string
	const maxFiles = 200
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				name := d.Name()
				if name == "vendor" || name == ".git" || name == "node_modules" || name == "testdata" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		lines = append(lines, rel)
		if len(lines) >= maxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	return strings.Join(lines, "\n")
}

// prioritySourceFiles returns the most important source files for analysis,
// ordered by relevance. Limited to ensure the prompt stays manageable.
func prioritySourceFiles(root string) []string {
	priority := []string{
		"pkg/orchestrator/orchestrator.go",
		"pkg/pm/pm.go",
		"pkg/provider/provider.go",
		"pkg/provider/factory.go",
		"pkg/provider/retry.go",
		"pkg/state/state.go",
		"cmd/run.go",
		"cmd/root.go",
	}

	var result []string
	for _, rel := range priority {
		abs := filepath.Join(root, rel)
		if _, err := os.Stat(abs); err == nil {
			result = append(result, abs)
		}
	}

	// Also add any cmd files not already listed
	cmdDir := filepath.Join(root, "cmd")
	_ = filepath.WalkDir(cmdDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip test files and already-added
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, r := range result {
			if r == path {
				return nil
			}
		}
		result = append(result, path)
		return nil
	})

	return result
}

// truncate shortens a string to at most n runes.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-3]) + "..."
}
