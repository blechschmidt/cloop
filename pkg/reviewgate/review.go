package reviewgate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// DefaultTimeout bounds one review call when the project sets no step
// timeout. A reviewer reading files for context takes minutes; one that has
// not answered in half an hour is not going to.
const DefaultTimeout = 30 * time.Minute

// Reviewer is a project's configured review model.
type Reviewer struct {
	Provider provider.Provider
	// ProviderName and Model name it for the record. Model is passed to
	// the provider; empty means the provider's default.
	ProviderName string
	Model        string
	Effort       string
	Timeout      time.Duration
}

// Label names the reviewer for people: its model when set, else its provider.
func (r *Reviewer) Label() string {
	if r == nil {
		return ""
	}
	if r.Model != "" {
		return r.Model
	}
	return r.ProviderName
}

// Round is the outcome of one review call.
type Round struct {
	// Verdict is nil when Err is set.
	Verdict *Verdict
	Err     error
	// Tokens the reviewer spent, and the model the provider reports.
	InputTokens  int
	OutputTokens int
	Model        string
}

// Review runs one review round in workDir.
//
// A harness provider is given read-only tools (provider.Options.ReadOnly), so
// the reviewer can open files for context and cannot change the work it is
// judging. An answer with no verdict in it earns one more request for the
// format — in the same conversation where the provider keeps one — and a
// second such answer is an error, which the gate treats as no verdict.
func (r *Reviewer) Review(ctx context.Context, workDir string, in Input) Round {
	if r == nil || r.Provider == nil {
		return Round{Err: errors.New("no reviewer is configured")}
	}
	in.CanReadFiles = r.ProviderName == "claudecode"
	prompt := BuildPrompt(in)
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	opts := provider.Options{
		Model:    r.Model,
		Effort:   r.Effort,
		Timeout:  timeout,
		WorkDir:  workDir,
		ReadOnly: true,
	}
	var round Round
	res, err := r.Provider.Complete(ctx, prompt, opts)
	if err != nil {
		round.Err = fmt.Errorf("the reviewer failed: %w", err)
		return round
	}
	round.add(res)
	v, perr := ParseVerdict(res.Output)
	if perr == nil {
		round.Verdict = v
		return round
	}

	retry := opts
	var again string
	const formatNote = "Your answer could not be read as the verdict. Reply again with ONLY the JSON object the " +
		"ANSWER FORMAT section describes — no prose, no code fence."
	if res.SessionID != "" {
		retry.ResumeSession = res.SessionID
		again = formatNote
	} else {
		again = prompt + "\n\n" + formatNote
	}
	res2, err := r.Provider.Complete(ctx, again, retry)
	if err != nil {
		round.Err = fmt.Errorf("the reviewer failed: %w", err)
		return round
	}
	round.add(res2)
	if v, perr := ParseVerdict(res2.Output); perr == nil {
		round.Verdict = v
		return round
	}
	round.Err = fmt.Errorf("%w (it answered: %q)", ErrNoVerdict, clip(strings.TrimSpace(res2.Output), 160))
	return round
}

func (r *Round) add(res *provider.Result) {
	if res == nil {
		return
	}
	r.InputTokens += res.InputTokens
	r.OutputTokens += res.OutputTokens
	if res.Model != "" {
		r.Model = res.Model
	}
}
