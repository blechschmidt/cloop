package provider

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Options for a completion request.
type Options struct {
	Model        string
	MaxTokens    int
	Timeout      time.Duration
	SystemPrompt string
	WorkDir      string
	// OnToken, if set, is called for each token chunk as it streams in.
	// When set, the provider should use streaming mode.
	// The full output is still returned in Result.Output.
	OnToken func(token string)

	// OnBackgroundWait, if set, is called once when the provider starts
	// waiting for work an agent harness left running after it exited. The
	// activity passed in is provisional: Waited and Drained are not yet known.
	//
	// It exists so a caller can surface the wait as it happens. Without it a
	// task blocked for twenty minutes on a training run the agent forgot to
	// wait for is indistinguishable, from the outside, from a task that is
	// simply slow — which is the confusion this whole mechanism exists to end.
	OnBackgroundWait func(activity BackgroundActivity)

	// Inference parameters — nil means "use provider default".
	// Temperature controls randomness (0 = deterministic, higher = more creative).
	// TopP is nucleus sampling threshold (0–1).
	// FrequencyPenalty reduces repetition (OpenAI only, 0–2).
	Temperature      *float64
	TopP             *float64
	FrequencyPenalty *float64

	// ExtendedThinking enables reasoning/thinking mode.
	// For Anthropic: sends the "thinking" block with budget_tokens=ThinkingBudget.
	// For OpenAI o1/o3/o4-mini: sets reasoning_effort based on ThinkingBudget.
	ExtendedThinking bool

	// ThinkingBudget is the token budget for reasoning/thinking content.
	// Anthropic: budget_tokens for the thinking block (default 8000).
	// OpenAI: maps to reasoning_effort ("low"/<4000, "medium"/<12000, "high"/>=12000).
	ThinkingBudget int

	// Effort is the model reasoning-effort level for providers that support
	// it. Valid values: "low", "medium", "high", "xhigh", "max"; empty means
	// provider default. Currently honored by claudecode (passed as the claude
	// CLI's --effort flag); other providers ignore it.
	Effort string
}

// EffortLevels are the valid reasoning-effort levels accepted by
// Options.Effort, ordered from least to most effort. They mirror the claude
// CLI's --effort flag values.
var EffortLevels = []string{"low", "medium", "high", "xhigh", "max"}

// ValidEffort reports whether v is a valid Options.Effort value. The empty
// string is valid and means "provider default".
func ValidEffort(v string) bool {
	if v == "" {
		return true
	}
	for _, l := range EffortLevels {
		if v == l {
			return true
		}
	}
	return false
}

// Result from a completion request.
type Result struct {
	Output       string
	Duration     time.Duration
	Provider     string
	Model        string
	InputTokens  int // tokens in the prompt/input
	OutputTokens int // tokens in the completion/output
	// ThinkingTokens is the number of tokens used for reasoning/thinking content
	// (Anthropic extended thinking, OpenAI reasoning tokens). Estimated from output.
	ThinkingTokens int

	// Background reports work the harness left running after it exited, for
	// providers that spawn one. nil means none was detected — which is also
	// what the HTTP providers report, since they spawn no processes at all.
	//
	// A non-nil value with Drained false means the output above cannot be
	// trusted as a finished result: the harness described work it had only
	// started. Callers that gate other work on this one must treat that as
	// incomplete rather than as success.
	Background *BackgroundActivity
}

// BackgroundActivity describes processes an agent harness left running when it
// exited, and what cloop did about them.
//
// This exists because an agent that starts a long job in the background and
// then reports success is indistinguishable, from its output alone, from one
// that actually finished the job. The distinction matters whenever a later
// task consumes the result: a training run still writing its checkpoint looks
// exactly like a finished one to the task that reads the model file.
type BackgroundActivity struct {
	// Detected is how many processes were still running once the harness had
	// exited and a short grace window had passed.
	Detected int
	// Commands names what was running, for operator diagnosis. Bounded, and
	// truncated to the kernel's 15-character process names.
	Commands []string
	// Waited is how long cloop blocked waiting for the work to finish.
	Waited time.Duration
	// Drained is true when the background work finished on its own within the
	// budget. The task's output can then be trusted: the work it started is
	// genuinely complete.
	Drained bool
	// Terminated is how many processes were killed after outliving the
	// budget. Zero when Drained, or when the operator opted to keep orphans.
	Terminated int
}

// Incomplete reports whether background work outlived its budget, meaning the
// task that started it has not actually finished.
func (b *BackgroundActivity) Incomplete() bool {
	return b != nil && b.Detected > 0 && !b.Drained
}

// Summary renders the activity as one line for annotations, logs and the UI.
func (b *BackgroundActivity) Summary() string {
	if b == nil || b.Detected == 0 {
		return ""
	}
	what := "process"
	if b.Detected != 1 {
		what = "processes"
	}
	names := ""
	if len(b.Commands) > 0 {
		names = " (" + strings.Join(b.Commands, ", ") + ")"
	}
	waited := b.Waited.Round(time.Second)
	if b.Drained {
		return fmt.Sprintf("waited %s for %d background %s%s to finish", waited, b.Detected, what, names)
	}
	if b.Terminated > 0 {
		return fmt.Sprintf("%d background %s%s still running after %s; terminated %d",
			b.Detected, what, names, waited, b.Terminated)
	}
	return fmt.Sprintf("%d background %s%s still running after %s", b.Detected, what, names, waited)
}

// Provider is the interface all AI backends must implement.
type Provider interface {
	Complete(ctx context.Context, prompt string, opts Options) (*Result, error)
	Name() string
	DefaultModel() string
}
