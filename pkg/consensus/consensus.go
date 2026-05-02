// Package consensus implements multi-model voting for critical tasks.
// When enabled, a task prompt is fanned out to N providers in parallel.
// An AI judge then scores each response on correctness, safety, and
// completeness and returns the best response together with a decision report.
package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// CandidateResponse holds a single provider's output and metadata.
type CandidateResponse struct {
	ProviderName string
	Model        string
	Output       string
	Duration     time.Duration
	Err          error
}

// Score holds a judge's assessment of one candidate.
type Score struct {
	ProviderName string  `json:"provider"`
	Model        string  `json:"model"`
	Correctness  int     `json:"correctness"`  // 1–10
	Safety       int     `json:"safety"`       // 1–10
	Completeness int     `json:"completeness"` // 1–10
	Total        int     `json:"total"`        // sum of the three dimensions
	Rationale    string  `json:"rationale"`
}

// Report is the full consensus decision record attached to the task artifact.
type Report struct {
	TaskID    int              `json:"task_id"`
	TaskTitle string           `json:"task_title"`
	Scores    []Score          `json:"scores"`
	Winner    string           `json:"winner_provider"`
	Timestamp time.Time        `json:"timestamp"`
}

// isCritical returns true when the task should trigger consensus.
// A task is critical if its priority is 0 or 1 (P0/P1) or if it has the
// "critical" tag.
func IsCritical(priority int, tags []string) bool {
	if priority <= 1 {
		return true
	}
	for _, t := range tags {
		if strings.EqualFold(t, "critical") {
			return true
		}
	}
	return false
}

// RunConsensus fans the prompt out to all provided providers (up to n),
// collects their responses, and uses judgeProvider to score them.
// It returns the winning response text plus a full Report for logging.
//
// If only one provider is available (or n == 1), the single response is
// returned without calling the judge.
//
// providers must contain at least one entry; judgeProvider is used only for
// the scoring call and may be the same as one of the providers.
func RunConsensus(
	ctx context.Context,
	providers []provider.Provider,
	prompt string,
	opts provider.Options,
	judgeProvider provider.Provider,
	judgeModel string,
	n int,
	taskID int,
	taskTitle string,
) (string, *Report, error) {
	if len(providers) == 0 {
		return "", nil, fmt.Errorf("consensus: no providers supplied")
	}

	// Limit to n providers.
	ps := providers
	if n > 0 && n < len(ps) {
		ps = ps[:n]
	}

	// Fan out in parallel.
	candidates := make([]CandidateResponse, len(ps))
	var wg sync.WaitGroup
	for i, p := range ps {
		wg.Add(1)
		go func(idx int, prov provider.Provider) {
			defer wg.Done()
			start := time.Now()
			res, err := prov.Complete(ctx, prompt, opts)
			candidates[idx].ProviderName = prov.Name()
			candidates[idx].Duration = time.Since(start)
			if err != nil {
				candidates[idx].Err = err
				candidates[idx].Model = prov.DefaultModel()
				return
			}
			candidates[idx].Output = res.Output
			candidates[idx].Model = res.Model
		}(i, p)
	}
	wg.Wait()

	// Filter out errored responses.
	var valid []CandidateResponse
	for _, c := range candidates {
		if c.Err == nil && c.Output != "" {
			valid = append(valid, c)
		}
	}

	if len(valid) == 0 {
		// All providers failed — return error from first candidate.
		return "", nil, fmt.Errorf("consensus: all providers failed; first error: %v", candidates[0].Err)
	}

	if len(valid) == 1 {
		// No point judging a single response.
		report := &Report{
			TaskID:    taskID,
			TaskTitle: taskTitle,
			Winner:    valid[0].ProviderName,
			Timestamp: time.Now(),
		}
		return valid[0].Output, report, nil
	}

	// Ask the judge to score each candidate.
	scores, err := judge(ctx, judgeProvider, judgeModel, opts.Timeout, taskTitle, valid)
	if err != nil {
		// Fallback: return the first valid response without scoring.
		report := &Report{
			TaskID:    taskID,
			TaskTitle: taskTitle,
			Winner:    valid[0].ProviderName,
			Timestamp: time.Now(),
		}
		return valid[0].Output, report, nil
	}

	// Find the winner: highest total score.
	winnerIdx := 0
	for i := 1; i < len(scores); i++ {
		if scores[i].Total > scores[winnerIdx].Total {
			winnerIdx = i
		}
	}

	report := &Report{
		TaskID:    taskID,
		TaskTitle: taskTitle,
		Scores:    scores,
		Winner:    scores[winnerIdx].ProviderName,
		Timestamp: time.Now(),
	}

	// Find the winning output.
	winnerName := scores[winnerIdx].ProviderName
	for _, c := range valid {
		if c.ProviderName == winnerName {
			return c.Output, report, nil
		}
	}

	// Fallback (shouldn't happen).
	return valid[0].Output, report, nil
}

// judgePrompt builds the scoring prompt sent to the judge.
func judgePrompt(taskTitle string, candidates []CandidateResponse) string {
	var b strings.Builder
	b.WriteString("You are an impartial AI judge evaluating multiple AI responses to the same engineering task.\n\n")
	b.WriteString(fmt.Sprintf("## Task\n%s\n\n", taskTitle))
	b.WriteString("## Responses\n\n")

	for i, c := range candidates {
		b.WriteString(fmt.Sprintf("### Response %d (provider: %s)\n\n", i+1, c.ProviderName))
		// Truncate very long responses to avoid blowing the context.
		out := c.Output
		const maxChars = 4000
		if len(out) > maxChars {
			out = out[:maxChars] + "\n...[truncated]"
		}
		b.WriteString(out)
		b.WriteString("\n\n---\n\n")
	}

	b.WriteString("## Instructions\n\n")
	b.WriteString("Score each response on a scale of 1-10 for three dimensions:\n")
	b.WriteString("- **correctness**: Does it correctly solve the task? Are the facts and code accurate?\n")
	b.WriteString("- **safety**: Does it avoid dangerous patterns (security holes, data loss, etc.)?\n")
	b.WriteString("- **completeness**: Does it fully address all aspects of the task?\n\n")
	b.WriteString("Return ONLY a JSON array (no markdown fences, no extra text) with this exact structure:\n")
	b.WriteString(`[`)
	for i, c := range candidates {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf(`{"provider":%q,"correctness":<1-10>,"safety":<1-10>,"completeness":<1-10>,"rationale":"<one sentence>"}`, c.ProviderName))
	}
	b.WriteString("]\n")
	return b.String()
}

// judge calls judgeProvider to score the candidates and returns parsed scores.
func judge(
	ctx context.Context,
	judgeProvider provider.Provider,
	model string,
	timeout time.Duration,
	taskTitle string,
	candidates []CandidateResponse,
) ([]Score, error) {
	prompt := judgePrompt(taskTitle, candidates)
	opts := provider.Options{
		Model:   model,
		Timeout: timeout,
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}

	res, err := judgeProvider.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("judge call failed: %w", err)
	}

	// Parse the JSON array.
	raw := strings.TrimSpace(res.Output)
	// Strip optional markdown fences in case the model ignores our instruction.
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	type judgeEntry struct {
		Provider     string `json:"provider"`
		Correctness  int    `json:"correctness"`
		Safety       int    `json:"safety"`
		Completeness int    `json:"completeness"`
		Rationale    string `json:"rationale"`
	}
	var entries []judgeEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("parse judge output: %w", err)
	}

	// Build provider→model map for annotation.
	provModel := make(map[string]string, len(candidates))
	for _, c := range candidates {
		provModel[c.ProviderName] = c.Model
	}

	scores := make([]Score, 0, len(entries))
	for _, e := range entries {
		total := e.Correctness + e.Safety + e.Completeness
		scores = append(scores, Score{
			ProviderName: e.Provider,
			Model:        provModel[e.Provider],
			Correctness:  e.Correctness,
			Safety:       e.Safety,
			Completeness: e.Completeness,
			Total:        total,
			Rationale:    e.Rationale,
		})
	}
	return scores, nil
}

// FormatReport formats a consensus Report as a Markdown section suitable for
// appending to a task artifact.
func FormatReport(r *Report) string {
	var b strings.Builder
	b.WriteString("\n---\n\n## Consensus Decision\n\n")
	b.WriteString(fmt.Sprintf("**Winner:** `%s`  \n", r.Winner))
	b.WriteString(fmt.Sprintf("**Evaluated at:** %s\n\n", r.Timestamp.UTC().Format(time.RFC3339)))

	if len(r.Scores) == 0 {
		b.WriteString("_(single provider — no scoring needed)_\n")
		return b.String()
	}

	b.WriteString("| Provider | Model | Correctness | Safety | Completeness | Total | Rationale |\n")
	b.WriteString("|----------|-------|-------------|--------|--------------|-------|-----------|\n")
	for _, s := range r.Scores {
		marker := ""
		if s.ProviderName == r.Winner {
			marker = " ✓"
		}
		b.WriteString(fmt.Sprintf("| `%s`%s | %s | %d | %d | %d | **%d** | %s |\n",
			s.ProviderName, marker, s.Model, s.Correctness, s.Safety, s.Completeness, s.Total, s.Rationale))
	}
	b.WriteByte('\n')
	return b.String()
}
