// Package compare provides multi-provider benchmarking: run the same prompt
// against several AI providers simultaneously and compare results.
package compare

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// compareShutdownGracePeriod bounds how long Run will wait for in-flight
// provider goroutines to honour ctx.Done() after cancellation. A misbehaving
// provider that ignores ctx would otherwise pin the caller for the full
// per-provider timeout. Var (not const) so tests can shrink it.
var compareShutdownGracePeriod = 30 * time.Second

// Entry holds the result (or error) from a single provider.
type Entry struct {
	ProviderName string
	Model        string
	Output       string
	Duration     time.Duration
	InputTokens  int
	OutputTokens int
	CostUSD      float64
	CostKnown    bool
	Err          error

	// JudgeScore is 0–10, set only when a judge provider is used.
	JudgeScore    int
	JudgeFeedback string
}

// Run sends prompt to each provider in parallel and returns one Entry per provider.
// model is the model override (empty = use each provider's default).
func Run(ctx context.Context, prompt string, providers []provider.Provider, model string, timeout time.Duration) []*Entry {
	if timeout == 0 {
		timeout = 3 * time.Minute
	}

	results := make([]*Entry, len(providers))
	var wg sync.WaitGroup

	for i, prov := range providers {
		wg.Add(1)
		go func(idx int, p provider.Provider) {
			defer wg.Done()
			entry := &Entry{ProviderName: p.Name()}
			// Panic recovery: a provider implementation crashing must not
			// take down the whole compare run.
			defer func() {
				if rec := recover(); rec != nil {
					entry.Err = fmt.Errorf("provider panic: %v", rec)
					results[idx] = entry
				}
			}()

			m := model
			if m == "" {
				m = p.DefaultModel()
			}
			entry.Model = m

			opts := provider.Options{
				Model:   m,
				Timeout: timeout,
			}

			r, err := p.Complete(ctx, prompt, opts)
			if err != nil {
				entry.Err = err
				results[idx] = entry
				return
			}

			entry.Output = r.Output
			entry.Duration = r.Duration
			entry.InputTokens = r.InputTokens
			entry.OutputTokens = r.OutputTokens

			usd, ok := cost.Estimate(m, r.InputTokens, r.OutputTokens)
			entry.CostUSD = usd
			entry.CostKnown = ok

			results[idx] = entry
		}(i, prov)
	}

	// Bounded wait: if the parent ctx is cancelled and a misbehaving provider
	// ignores it, give workers up to the grace period to exit, then return
	// the partial results so the caller regains control. Any nil entries in
	// the returned slice represent providers that were still in-flight when
	// the watchdog fired; the caller can detect this by checking ctx.Err().
	// Leaked goroutines may still populate results[idx] afterward; safe
	// because each writes to a unique index and the caller has already
	// returned from this function.
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		// All providers exited; return full results.
	case <-ctx.Done():
		select {
		case <-waitDone:
			// Workers honored cancellation in time.
		case <-time.After(compareShutdownGracePeriod):
			// Watchdog fired — fill in placeholders for any unfinished
			// entries so callers can iterate the slice without nil checks.
			for i, entry := range results {
				if entry == nil {
					name := ""
					if i < len(providers) {
						name = providers[i].Name()
					}
					results[i] = &Entry{
						ProviderName: name,
						Err:          ctx.Err(),
					}
				}
			}
		}
	}
	return results
}

// JudgePrompt builds the evaluation prompt for an AI judge.
func JudgePrompt(originalPrompt string, entries []*Entry) string {
	var b strings.Builder
	b.WriteString("You are an impartial AI evaluator. Rate each response below on a scale of 0–10.\n")
	b.WriteString("Criteria: accuracy, completeness, clarity, conciseness, and helpfulness.\n\n")
	b.WriteString(fmt.Sprintf("## Original Prompt\n%s\n\n", originalPrompt))
	b.WriteString("## Responses\n\n")

	for i, e := range entries {
		if e == nil || e.Err != nil {
			continue
		}
		b.WriteString(fmt.Sprintf("### Response %d — %s (%s)\n", i+1, e.ProviderName, e.Model))
		b.WriteString(e.Output)
		b.WriteString("\n\n")
	}

	b.WriteString("## Instructions\n")
	b.WriteString("For EACH response, output exactly one line in this format:\n")
	b.WriteString("SCORE <N> <provider>: <one sentence feedback>\n")
	b.WriteString("Where N is an integer 0–10 and <provider> is the provider name from the response header.\n")
	b.WriteString("Do not add any other text.\n")
	return b.String()
}

// ParseJudgeOutput parses the judge's structured output and annotates entries.
// Expected format per line: SCORE <N> <provider>: <feedback>
func ParseJudgeOutput(output string, entries []*Entry) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SCORE ") {
			continue
		}
		rest := strings.TrimPrefix(line, "SCORE ")
		// rest = "N <provider>: <feedback>"
		parts := strings.SplitN(rest, " ", 3)
		if len(parts) < 2 {
			continue
		}
		var score int
		fmt.Sscanf(parts[0], "%d", &score)

		// provider name is everything up to the colon in parts[1]+parts[2]
		provPart := parts[1]
		if len(parts) == 3 {
			provPart = parts[1] + " " + parts[2]
		}
		colonIdx := strings.Index(provPart, ":")
		provName := provPart
		feedback := ""
		if colonIdx >= 0 {
			provName = strings.TrimSpace(provPart[:colonIdx])
			feedback = strings.TrimSpace(provPart[colonIdx+1:])
		}

		for _, e := range entries {
			if e != nil && strings.EqualFold(e.ProviderName, provName) {
				e.JudgeScore = score
				e.JudgeFeedback = feedback
			}
		}
	}
}

// Truncate shortens a string to maxRunes, appending "…" if cut.
func Truncate(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "…"
}
