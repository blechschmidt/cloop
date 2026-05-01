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
