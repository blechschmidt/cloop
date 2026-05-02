// Package logger provides structured logging for cloop with text and JSON output modes.
//
// In text mode (default) the Logger is a no-op wrapper — all output is handled by
// the existing fmt/color calls in the orchestrator. In JSON mode (--log-json) the
// Logger writes newline-delimited JSON (NDJSON) to stdout so that output can be
// piped into log aggregators such as Datadog, Splunk, or jq.
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Level represents the severity of a log entry.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Event is the structured event name embedded in every JSON log line.
type Event string

const (
	EventSessionStart  Event = "session_start"
	EventSessionDone   Event = "session_done"
	EventTaskStart     Event = "task_start"
	EventTaskDone      Event = "task_done"
	EventTaskFailed    Event = "task_failed"
	EventTaskSkipped   Event = "task_skipped"
	EventStep          Event = "step"
	EventHeal          Event = "heal"
	EventEvolve        Event = "evolve"
	EventHealthCheck   Event = "health_check"
	EventOptimize      Event = "optimize"
	EventVerify        Event = "verify"
	EventCheckpoint    Event = "checkpoint"
)

// Entry is the JSON schema for every log line emitted by JSONLogger.
type Entry struct {
	Time    string                 `json:"time"`
	Level   Level                  `json:"level"`
	Event   Event                  `json:"event"`
	TaskID  int                    `json:"task_id,omitempty"`
	// TraceID is the OpenTelemetry trace ID of the active span when this entry
	// was emitted. Present only when tracing is enabled and a span is active.
	TraceID string                 `json:"trace_id,omitempty"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// Logger defines the interface for structured event logging.
type Logger interface {
	// Log emits a structured entry. taskID of 0 means no associated task.
	Log(level Level, event Event, taskID int, message string, data map[string]interface{})

	// Info is a convenience wrapper for Log with LevelInfo.
	Info(event Event, taskID int, message string, data map[string]interface{})

	// Warn is a convenience wrapper for Log with LevelWarn.
	Warn(event Event, taskID int, message string, data map[string]interface{})

	// Error is a convenience wrapper for Log with LevelError.
	Error(event Event, taskID int, message string, data map[string]interface{})

	// IsJSON reports whether this logger emits JSON output.
	// When true the caller should suppress decorative color/fmt output.
	IsJSON() bool
}

// TextLogger is a no-op Logger — all output is handled by the caller's existing
// fmt/color calls. IsJSON() returns false.
type TextLogger struct{}

func (t *TextLogger) Log(_ Level, _ Event, _ int, _ string, _ map[string]interface{}) {}
func (t *TextLogger) Info(_ Event, _ int, _ string, _ map[string]interface{})          {}
func (t *TextLogger) Warn(_ Event, _ int, _ string, _ map[string]interface{})          {}
func (t *TextLogger) Error(_ Event, _ int, _ string, _ map[string]interface{})         {}
func (t *TextLogger) IsJSON() bool                                                      { return false }

// JSONLogger writes newline-delimited JSON to w (typically os.Stdout).
type JSONLogger struct {
	w   io.Writer
	enc *json.Encoder
}

// NewJSONLogger creates a JSONLogger that writes to w.
// Pass os.Stdout for normal operation.
func NewJSONLogger(w io.Writer) *JSONLogger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONLogger{w: w, enc: enc}
}

func (j *JSONLogger) Log(level Level, event Event, taskID int, message string, data map[string]interface{}) {
	entry := Entry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   level,
		Event:   event,
		TaskID:  taskID,
		Message: message,
		Data:    data,
	}
	// Promote trace_id from data map to top-level field for easy log correlation.
	// Callers that hold an OTel context can include {"trace_id": tracing.TraceIDFromContext(ctx)}.
	if data != nil {
		if tid, ok := data["trace_id"].(string); ok && tid != "" {
			entry.TraceID = tid
			// Remove from data to avoid duplication.
			filtered := make(map[string]interface{}, len(data)-1)
			for k, v := range data {
				if k != "trace_id" {
					filtered[k] = v
				}
			}
			if len(filtered) > 0 {
				entry.Data = filtered
			} else {
				entry.Data = nil
			}
		}
	}
	if err := j.enc.Encode(entry); err != nil {
		fmt.Fprintf(os.Stderr, "logger encode error: %v\n", err)
	}
}

func (j *JSONLogger) Info(event Event, taskID int, message string, data map[string]interface{}) {
	j.Log(LevelInfo, event, taskID, message, data)
}

func (j *JSONLogger) Warn(event Event, taskID int, message string, data map[string]interface{}) {
	j.Log(LevelWarn, event, taskID, message, data)
}

func (j *JSONLogger) Error(event Event, taskID int, message string, data map[string]interface{}) {
	j.Log(LevelError, event, taskID, message, data)
}

func (j *JSONLogger) IsJSON() bool { return true }

// New returns a Logger based on the jsonMode flag.
// When jsonMode is true a JSONLogger writing to os.Stdout is returned.
// When jsonMode is false a no-op TextLogger is returned.
func New(jsonMode bool) Logger {
	if jsonMode {
		return NewJSONLogger(os.Stdout)
	}
	return &TextLogger{}
}
