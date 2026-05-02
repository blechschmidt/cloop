// Package tracing provides OpenTelemetry distributed tracing for cloop.
//
// When tracing is enabled (config.Tracing.Enabled = true and Endpoint is set),
// the package initialises a global OTel TracerProvider that exports spans via
// OTLP over HTTP to the configured endpoint (e.g. a local Jaeger or OTEL
// Collector). When disabled, a no-op tracer is used so callers never need to
// guard on nil spans.
//
// Span hierarchy produced during a PM run:
//
//	plan_run                    (one per cloop run)
//	  └─ task_execute           (one per task)
//	       └─ provider_call     (one per Complete() invocation)
package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const tracerName = "cloop"

// globalTracer is the package-level tracer. It starts as a no-op and is
// replaced by Init() when tracing is enabled.
var globalTracer trace.Tracer = noop.NewTracerProvider().Tracer(tracerName)

// ShutdownFunc flushes and closes the TracerProvider. Always safe to call,
// even when tracing is disabled (it becomes a no-op).
type ShutdownFunc func(context.Context) error

// Init configures the global OTel TracerProvider using the given Config.
// When cfg.Enabled is false or cfg.Endpoint is empty, a no-op tracer is
// installed and shutdown is a harmless no-op. The caller must invoke the
// returned ShutdownFunc (e.g. via defer) to flush pending spans before exit.
func Init(cfg Config) (ShutdownFunc, error) {
	noopShutdown := func(context.Context) error { return nil }

	if !cfg.Enabled || cfg.Endpoint == "" {
		return noopShutdown, nil
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "cloop"
	}

	ctx := context.Background()

	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.Endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: create OTLP HTTP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: create OTel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	globalTracer = tp.Tracer(tracerName)

	shutdown := func(ctx context.Context) error {
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(ctx2)
	}
	return shutdown, nil
}

// StartSpan starts a new span named name as a child of the span already in ctx
// (if any). Extra span attributes can be provided via attrs.
// The returned context carries the new span; callers must call span.End().
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if len(attrs) > 0 {
		return globalTracer.Start(ctx, name, trace.WithAttributes(attrs...))
	}
	return globalTracer.Start(ctx, name)
}

// TraceIDFromContext returns the hex-encoded trace ID of the current span in
// ctx, or an empty string when no active span is present (tracing disabled or
// no span started).
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// SpanIDFromContext returns the hex-encoded span ID of the current span in
// ctx, or empty when no valid span is active.
func SpanIDFromContext(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.SpanID().String()
}
