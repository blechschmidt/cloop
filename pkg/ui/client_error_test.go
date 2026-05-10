package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/logger"
)

// captureLogger is a Logger that records every entry into entries for
// later assertion. It is goroutine-safe so tests that exercise concurrent
// HTTP handlers can rely on it without external synchronisation.
type captureLogger struct {
	mu      sync.Mutex
	entries []captureEntry
}

type captureEntry struct {
	Level   logger.Level
	Event   logger.Event
	Message string
	Data    map[string]interface{}
}

func (c *captureLogger) Log(level logger.Level, event logger.Event, taskID int, message string, data map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, captureEntry{Level: level, Event: event, Message: message, Data: data})
}
func (c *captureLogger) Debug(event logger.Event, taskID int, message string, data map[string]interface{}) {
	c.Log(logger.LevelDebug, event, taskID, message, data)
}
func (c *captureLogger) Info(event logger.Event, taskID int, message string, data map[string]interface{}) {
	c.Log(logger.LevelInfo, event, taskID, message, data)
}
func (c *captureLogger) Warn(event logger.Event, taskID int, message string, data map[string]interface{}) {
	c.Log(logger.LevelWarn, event, taskID, message, data)
}
func (c *captureLogger) Error(event logger.Event, taskID int, message string, data map[string]interface{}) {
	c.Log(logger.LevelError, event, taskID, message, data)
}
func (c *captureLogger) With(_ string, _ any) logger.Logger          { return c }
func (c *captureLogger) WithContext(_ context.Context) logger.Logger { return c }
func (c *captureLogger) IsJSON() bool                                { return false }

func (c *captureLogger) snapshot() []captureEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]captureEntry, len(c.entries))
	copy(out, c.entries)
	return out
}

// TestClientError_LogsStructuredEntry verifies that POST /api/client-error
// decodes the JSON body, forwards every relevant field to the structured
// logger as a "client_error" event, and responds with 204 No Content.
func TestClientError_LogsStructuredEntry(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")
	cap := &captureLogger{}
	srv.Log = cap

	body := map[string]any{
		"message":   "TypeError: cannot read property 'foo' of null",
		"stack":     "at render (app.js:42:10)\nat init (app.js:7:3)",
		"url":       "http://localhost:8080/",
		"userAgent": "Mozilla/5.0 …",
		"tab":       "tasks",
		"kind":      "error",
		"line":      42,
		"col":       10,
	}
	buf, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/client-error", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleClientError(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body=%s)", w.Code, w.Body.String())
	}

	got := cap.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(got))
	}
	e := got[0]
	if e.Level != logger.LevelError {
		t.Errorf("level: want error, got %s", e.Level)
	}
	if e.Event != logger.Event("client_error") {
		t.Errorf("event: want client_error, got %s", e.Event)
	}
	if !strings.Contains(e.Message, "TypeError") {
		t.Errorf("message missing original error text: %q", e.Message)
	}
	if e.Data["kind"] != "error" {
		t.Errorf("data.kind = %v, want error", e.Data["kind"])
	}
	if e.Data["tab"] != "tasks" {
		t.Errorf("data.tab = %v, want tasks", e.Data["tab"])
	}
	if e.Data["line"] != 42 {
		t.Errorf("data.line = %v, want 42", e.Data["line"])
	}
	if !strings.Contains(e.Data["stack"].(string), "render") {
		t.Errorf("stack not preserved: %v", e.Data["stack"])
	}
}

// TestClientError_RejectsNonPOST asserts the handler refuses GET and the
// other read-only verbs with 405; client errors are never idempotent
// reads so any other method is a programming bug worth flagging.
func TestClientError_RejectsNonPOST(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/api/client-error", nil)
		w := httptest.NewRecorder()
		srv.handleClientError(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: want 405, got %d", m, w.Code)
		}
	}
}

// TestClientError_TruncatesOversizeFields confirms each long field is
// clipped to clientErrorMaxField bytes before reaching the logger so a
// runaway browser stack trace cannot inflate a single log line beyond
// safe processing limits. The body itself stays well under the global
// JSON cap; we test the per-field clamp specifically.
func TestClientError_TruncatesOversizeFields(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")
	cap := &captureLogger{}
	srv.Log = cap

	huge := strings.Repeat("X", clientErrorMaxField+512)
	body := map[string]any{
		"message":   huge,
		"stack":     huge,
		"url":       huge,
		"userAgent": huge,
		"tab":       strings.Repeat("t", 200),
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/client-error", bytes.NewReader(buf))
	w := httptest.NewRecorder()
	srv.handleClientError(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", w.Code)
	}
	got := cap.snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if len(got[0].Message) != clientErrorMaxField {
		t.Errorf("message len = %d, want %d", len(got[0].Message), clientErrorMaxField)
	}
	tab := got[0].Data["tab"].(string)
	if len(tab) != 64 || !strings.HasSuffix(tab, "...") {
		t.Errorf("tab not clipped to 64 bytes with ellipsis: %q", tab)
	}
	if !strings.HasSuffix(got[0].Message, "...") {
		t.Errorf("truncation marker missing: tail=%q", got[0].Message[len(got[0].Message)-5:])
	}
}

// TestClientError_RejectsInvalidJSON ensures malformed JSON yields HTTP
// 400 (matching the established respondToBodyError contract) rather than
// silently logging a junk entry.
func TestClientError_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")
	req := httptest.NewRequest(http.MethodPost, "/api/client-error", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.handleClientError(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// TestClientError_DefaultMessage covers the empty-message branch: the
// handler still records an entry but stamps a placeholder so log readers
// can recognise the case.
func TestClientError_DefaultMessage(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "")
	cap := &captureLogger{}
	srv.Log = cap

	req := httptest.NewRequest(http.MethodPost, "/api/client-error", strings.NewReader(`{"kind":"unhandledrejection"}`))
	w := httptest.NewRecorder()
	srv.handleClientError(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", w.Code)
	}
	got := cap.snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].Message != "(no message)" {
		t.Errorf("placeholder message missing: %q", got[0].Message)
	}
	if got[0].Data["kind"] != "unhandledrejection" {
		t.Errorf("kind not preserved: %v", got[0].Data["kind"])
	}
}
