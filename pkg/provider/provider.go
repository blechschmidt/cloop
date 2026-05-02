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

	// ExtendedThinking enables reasoning/thinking mode.
	// For Anthropic: sends the "thinking" block with budget_tokens=ThinkingBudget.
	// For OpenAI o1/o3/o4-mini: sets reasoning_effort based on ThinkingBudget.
	ExtendedThinking bool

	// ThinkingBudget is the token budget for reasoning/thinking content.
	// Anthropic: budget_tokens for the thinking block (default 8000).
	// OpenAI: maps to reasoning_effort ("low"/<4000, "medium"/<12000, "high"/>=12000).
	ThinkingBudget int
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
}

// Provider is the interface all AI backends must implement.
type Provider interface {
	Complete(ctx context.Context, prompt string, opts Options) (*Result, error)
	Name() string
	DefaultModel() string
}
