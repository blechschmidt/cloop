package provider

import (
	"context"
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

	// Inference parameters — nil means "use provider default".
	// Temperature controls randomness (0 = deterministic, higher = more creative).
	// TopP is nucleus sampling threshold (0–1).
	// FrequencyPenalty reduces repetition (OpenAI only, 0–2).
	Temperature      *float64
	TopP             *float64
	FrequencyPenalty *float64
}

// Result from a completion request.
type Result struct {
	Output       string
	Duration     time.Duration
	Provider     string
	Model        string
	InputTokens  int // tokens in the prompt/input
	OutputTokens int // tokens in the completion/output
}

// Provider is the interface all AI backends must implement.
type Provider interface {
	Complete(ctx context.Context, prompt string, opts Options) (*Result, error)
	Name() string
	DefaultModel() string
}
