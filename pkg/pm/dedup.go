package pm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// dedupPrompt builds the prompt asking the AI to filter candidates that duplicate existing tasks.
func dedupPrompt(existing, candidates []*Task) string {
	var b strings.Builder
	b.WriteString("You are a task deduplication assistant. Your job is to identify which candidate tasks\n")
	b.WriteString("are genuinely new and not already covered by the existing task list.\n\n")

	b.WriteString("## EXISTING TASKS (already done or in progress)\n")
	for _, t := range existing {
		b.WriteString(fmt.Sprintf("- [%d] %s: %s\n", t.ID, t.Title, t.Description))
	}
	b.WriteString("\n")

	b.WriteString("## CANDIDATE TASKS (newly proposed — may overlap with existing)\n")
	for i, t := range candidates {
		b.WriteString(fmt.Sprintf("- [%d] %s: %s\n", i, t.Title, t.Description))
	}
	b.WriteString("\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Analyze each candidate task and determine if it is:\n")
	b.WriteString("- NOVEL: genuinely new work not covered by any existing task\n")
	b.WriteString("- DUPLICATE: already handled, covered, or superseded by an existing task\n\n")
	b.WriteString("A candidate is a duplicate if an existing task already implements the same feature,\n")
	b.WriteString("test, fix, or improvement — even if the wording differs.\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown):\n")
	b.WriteString(`{"novel":[0,2],"reason":"Task 1 duplicates existing #5; task 3 duplicates existing #12"}`)
	b.WriteString("\n\nThe 'novel' array contains the 0-based indices of candidate tasks that are genuinely novel.\n")
	b.WriteString("If ALL candidates are novel, include all indices. If NONE are novel, use an empty array [].")
	return b.String()
}

// DeduplicateTasks calls the provider to filter out candidates that duplicate existing tasks.
// It returns only the candidates the AI considers genuinely new.
// If the provider call fails or the response can't be parsed, all candidates are returned unchanged
// (fail-open: better to inject a duplicate than to silently drop novel work).
func DeduplicateTasks(ctx context.Context, p provider.Provider, opts provider.Options, existing []*Task, candidates []*Task) ([]*Task, error) {
	if len(candidates) == 0 {
		return candidates, nil
	}
	if len(existing) == 0 {
		// Nothing to deduplicate against.
		return candidates, nil
	}

	prompt := dedupPrompt(existing, candidates)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		// Fail open: return all candidates so novel tasks are not dropped.
		return candidates, fmt.Errorf("dedup provider call failed (returning all candidates): %w", err)
	}

	novelIndices, reason, parseErr := parseDedupResponse(result.Output)
	if parseErr != nil {
		// Fail open.
		return candidates, fmt.Errorf("dedup parse failed (returning all candidates): %w", parseErr)
	}

	// Build the filtered list.
	indexSet := make(map[int]bool, len(novelIndices))
	for _, idx := range novelIndices {
		indexSet[idx] = true
	}

	var novel []*Task
	for i, t := range candidates {
		if indexSet[i] {
			novel = append(novel, t)
		}
	}

	dropped := len(candidates) - len(novel)
	if dropped > 0 && reason != "" {
		_ = reason // available for callers that want to log it; returned via the error field is not appropriate here
	}

	return novel, nil
}

// DedupReason returns the AI's stated reason for dropping tasks.
// It is a lightweight wrapper that re-runs parseDedupResponse on cached output — used for logging.
func DedupReason(output string) string {
	_, reason, _ := parseDedupResponse(output)
	return reason
}

func parseDedupResponse(output string) (novelIndices []int, reason string, err error) {
	// Find JSON in the output.
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, "", fmt.Errorf("no JSON found in dedup response")
	}
	jsonStr := output[start : end+1]

	var raw struct {
		Novel  []int  `json:"novel"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, "", fmt.Errorf("unmarshal dedup response: %w", err)
	}
	return raw.Novel, raw.Reason, nil
}
