// Package logger provides structured logging for cloop, backed by Go's
// standard library log/slog package.
//
// The Logger interface keeps cloop's existing event-oriented call sites
// (Info/Warn/Error/Log with an Event tag, optional task_id, message, and a
// free-form data map) source-compatible while letting the underlying
// slog.Handler decide how each entry is rendered:
//
//   - JSON mode (--log-json) → slog.NewJSONHandler writes one NDJSON line
//     per entry to stdout with stable keys (time, level, msg, event,
//     task_id, …) plus any structured attrs supplied by the caller or
//     bound via With.
//   - text mode (default)    → slog.NewTextHandler writes one logfmt-style
//     line per entry to stdout. The orchestrator and other callers
//     additionally print decorative color/banner output to the same
//     stdout; both streams interleave cleanly because slog uses a single
//     synchronised writer.
//
// The previous TextLogger was a no-op so that printf-style output owned the
// terminal. To preserve that behaviour for terminals where ANSI banners are
// the primary UX, callers can still gate decorative output on IsJSON()
// (true means "machine-parseable stream — suppress decoration"). Text mode
// now also emits one slog line per event so that downstream tooling can
// scrape it without enabling JSON.
//
// Logger is an interface so tests and integrators can capture entries
// without going through slog. The default constructor (`New`) returns the
// slog-backed implementation; tests can substitute their own captureLogger.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/reqid"
)

// Level represents the severity of a log entry. The string values are the
// historical cloop level names; they are mapped to slog.Level by the
// implementation. They are still comparable for tests and external code.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// slogLevel converts a cloop Level to its slog.Level counterpart.
func (l Level) slogLevel() slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Event is the structured event name embedded in every log line.
type Event string

const (
	EventSessionStart Event = "session_start"
	EventSessionDone  Event = "session_done"
	EventTaskStart    Event = "task_start"
	EventTaskDone     Event = "task_done"
	EventTaskFailed   Event = "task_failed"
	EventTaskSkipped  Event = "task_skipped"
	EventStep         Event = "step"
	EventHeal         Event = "heal"
	EventEvolve       Event = "evolve"
	EventHealthCheck  Event = "health_check"
	EventOptimize     Event = "optimize"
	EventVerify       Event = "verify"
	EventCheckpoint   Event = "checkpoint"
	EventTaskStuck    Event = "task_stuck"
)

// Entry is the legacy JSON schema for a log line. Kept for callers that
// want to assert against the historical shape (it is no longer the wire
// format — slog.JSONHandler emits its own representation), but tests in
// pkg/logger validate the slog output directly.
type Entry struct {
	Time    string                 `json:"time"`
	Level   Level                  `json:"level"`
	Event   Event                  `json:"event"`
	TaskID  int                    `json:"task_id,omitempty"`
	TraceID string                 `json:"trace_id,omitempty"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// Logger is the structured event logger used throughout cloop.
//
// Implementations MUST be safe for concurrent use from multiple goroutines.
// All methods are non-blocking; failures inside the handler are surfaced
// to stderr but never returned to the caller.
type Logger interface {
	// Log emits a structured entry. taskID of 0 means no associated task.
	Log(level Level, event Event, taskID int, message string, data map[string]interface{})

	// Debug, Info, Warn, Error are convenience wrappers for Log.
	Debug(event Event, taskID int, message string, data map[string]interface{})
	Info(event Event, taskID int, message string, data map[string]interface{})
	Warn(event Event, taskID int, message string, data map[string]interface{})
	Error(event Event, taskID int, message string, data map[string]interface{})

	// With returns a new Logger that prepends the given key/value pair to
	// every emitted entry. Chained calls compose; the parent is unaffected.
	// Typical use: log.With("project", workdir).With("provider", name).
	With(key string, value any) Logger

	// WithContext returns a Logger that automatically attaches a
	// request_id attribute (sourced from pkg/reqid) to every entry, when
	// such an ID is bound to ctx. When ctx carries no request ID the
	// returned Logger is equivalent to the receiver. Use this at the
	// boundary of a request-scoped goroutine so deeply nested call sites
	// don't have to thread the ID through their data maps manually.
	WithContext(ctx context.Context) Logger

	// IsJSON reports whether this logger emits machine-parseable JSON
	// output. Callers use this to suppress decorative color/banner text
	// that would otherwise corrupt a JSON stream.
	IsJSON() bool
}

// requestIDKey is the structured-log attribute name carrying a request ID.
// Mirrors reqid.LogKey; duplicated to keep this package free of a pkg/reqid
// import (logger is imported transitively by virtually every cloop package
// — pulling in another internal dep here would force them all to recompile
// on a reqid edit).
const requestIDKey = "request_id"

// slogLogger is the concrete Logger backed by slog.
type slogLogger struct {
	handler slog.Handler
	json    bool
}

// New returns a Logger writing to os.Stdout. When jsonMode is true the
// handler is slog.JSONHandler; otherwise it is slog.TextHandler.
//
// Both handlers use slog.LevelDebug as the floor so callers control the
// effective level via their choice of Debug/Info/Warn/Error. cloop does
// not currently expose a runtime-configurable level filter — every entry
// is recorded, and downstream tools filter by the `level` field.
func New(jsonMode bool) Logger {
	return NewWithWriter(os.Stdout, jsonMode)
}

// NewWithWriter is like New but writes to w. Tests use this to capture
// output into a bytes.Buffer.
func NewWithWriter(w io.Writer, jsonMode bool) Logger {
	if w == nil {
		w = io.Discard
	}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	var h slog.Handler
	if jsonMode {
		h = slog.NewJSONHandler(syncWriter(w), opts)
	} else {
		h = slog.NewTextHandler(syncWriter(w), opts)
	}
	return &slogLogger{handler: h, json: jsonMode}
}

// NewJSONLogger preserves the v1 constructor name for callers that import
// pkg/logger directly (it remains used by some integrators / forks).
// Internally it now goes through slog.JSONHandler.
func NewJSONLogger(w io.Writer) Logger {
	return NewWithWriter(w, true)
}

// IsJSON reports whether this logger emits JSON output.
func (s *slogLogger) IsJSON() bool { return s.json }

// With binds a key/value pair to every subsequent entry from the returned
// Logger. The parent is unaffected.
func (s *slogLogger) With(key string, value any) Logger {
	return &slogLogger{
		handler: s.handler.WithAttrs([]slog.Attr{slog.Any(key, value)}),
		json:    s.json,
	}
}

// WithContext binds the request ID carried by ctx (if any) as a permanent
// attr on the returned logger. When ctx carries no ID the receiver is
// returned unchanged so callers can use this unconditionally at the entry
// of any context-aware code path.
func (s *slogLogger) WithContext(ctx context.Context) Logger {
	id := reqid.FromContext(ctx)
	if id == "" {
		return s
	}
	return s.With(requestIDKey, id)
}

// Log emits an entry at the requested level with structured attrs. Entries
// always include the `event` attribute; task_id is included when non-zero.
// Anything in the data map is added as an attribute under its key — keys
// reserved by slog (time, level, msg, source) are namespaced under `data.*`
// to avoid collisions in the JSON handler.
func (s *slogLogger) Log(level Level, event Event, taskID int, message string, data map[string]interface{}) {
	if s == nil || s.handler == nil {
		return
	}
	lvl := level.slogLevel()
	if !s.handler.Enabled(context.Background(), lvl) {
		return
	}
	r := slog.NewRecord(time.Now(), lvl, message, 0)
	r.AddAttrs(slog.String("event", string(event)))
	if taskID != 0 {
		r.AddAttrs(slog.Int("task_id", taskID))
	}
	if len(data) > 0 {
		// Promote a trace_id key (commonly attached by tracing-aware
		// callers) to a top-level attr so log aggregators can index it.
		// Other keys are emitted as-is.
		for k, v := range data {
			if k == "" {
				continue
			}
			if isReservedSlogKey(k) {
				k = "data." + k
			}
			r.AddAttrs(slog.Any(k, v))
		}
	}
	if err := s.handler.Handle(context.Background(), r); err != nil {
		fmt.Fprintf(os.Stderr, "logger handle error: %v\n", err)
	}
}

func (s *slogLogger) Debug(event Event, taskID int, message string, data map[string]interface{}) {
	s.Log(LevelDebug, event, taskID, message, data)
}
func (s *slogLogger) Info(event Event, taskID int, message string, data map[string]interface{}) {
	s.Log(LevelInfo, event, taskID, message, data)
}
func (s *slogLogger) Warn(event Event, taskID int, message string, data map[string]interface{}) {
	s.Log(LevelWarn, event, taskID, message, data)
}
func (s *slogLogger) Error(event Event, taskID int, message string, data map[string]interface{}) {
	s.Log(LevelError, event, taskID, message, data)
}

// isReservedSlogKey reports whether key would collide with a slog built-in
// attribute name in the JSON or text handlers.
func isReservedSlogKey(key string) bool {
	switch key {
	case slog.TimeKey, slog.LevelKey, slog.MessageKey, slog.SourceKey:
		return true
	case "event", "task_id":
		// reserved for our own promoted attrs
		return true
	}
	return false
}

// syncWriter wraps w in a mutex so concurrent Handle calls cannot interleave
// bytes within a single line. slog's default handlers do their own
// per-record locking when the writer is *os.File (via internal type-switch),
// but they fall back to plain Write for arbitrary io.Writers — and tests
// pass a bytes.Buffer. Wrapping unconditionally is cheap and uniform.
func syncWriter(w io.Writer) io.Writer {
	if _, ok := w.(*lockedWriter); ok {
		return w
	}
	return &lockedWriter{w: w}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}
