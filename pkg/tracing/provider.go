package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// WrapProvider returns a provider.Provider that wraps inner and records one
// "provider_call" OTel span per Complete() invocation. The span captures:
//   - provider name and model as attributes
//   - input/output token counts after completion
//   - wall-clock duration (via span start/end)
//   - error status if the call fails
//
// When tracing is disabled (no-op tracer), the wrapper is zero-overhead.
func WrapProvider(inner provider.Provider) provider.Provider {
	return &tracingProvider{inner: inner}
}

type tracingProvider struct {
	inner provider.Provider
}

func (p *tracingProvider) Name() string {
	return p.inner.Name()
}

func (p *tracingProvider) DefaultModel() string {
	return p.inner.DefaultModel()
}

func (p *tracingProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	model := opts.Model
	if model == "" {
		model = p.inner.DefaultModel()
	}

	spanCtx, span := StartSpan(ctx, "provider_call",
		attribute.String("provider", p.inner.Name()),
		attribute.String("model", model),
	)
	defer span.End()

	result, err := p.inner.Complete(spanCtx, prompt, opts)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return nil, err
	}

	span.SetStatus(codes.Ok, "")
	span.SetAttributes(
		attribute.Int("input_tokens", result.InputTokens),
		attribute.Int("output_tokens", result.OutputTokens),
		attribute.String("duration_ms", fmt.Sprintf("%.0f", result.Duration.Seconds()*1000)),
	)
	return result, nil
}
