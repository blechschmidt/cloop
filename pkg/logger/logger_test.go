package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// decodeLines splits captured slog JSON output into one decoded entry per
// line. Each entry is a generic map (slog has no public schema struct).
// Empty trailing lines are skipped so callers can iterate cleanly.
func decodeLines(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("non-JSON output line: %q (err=%v)", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestNew_ReturnsTextLoggerByDefault(t *testing.T) {
	l := New(false)
	if l.IsJSON() {
		t.Fatalf("expected text logger when jsonMode=false")
	}
}

func TestNew_ReturnsJSONLoggerWhenRequested(t *testing.T) {
	l := New(true)
	if !l.IsJSON() {
		t.Fatalf("expected JSON logger when jsonMode=true")
	}
}

func TestJSONHandler_EmitsLevelMsgAndEvent(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf, true)

	l.Info(EventTaskStart, 42, "starting task", map[string]interface{}{
		"role":     "backend",
		"priority": 1,
	})

	entries := decodeLines(t, buf.Bytes())
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]

	if e["msg"] != "starting task" {
		t.Errorf("msg: want %q, got %v", "starting task", e["msg"])
	}
	if e["level"] != "INFO" {
		t.Errorf("level: want INFO, got %v", e["level"])
	}
	if e["event"] != string(EventTaskStart) {
		t.Errorf("event: want %s, got %v", EventTaskStart, e["event"])
	}
	// task_id round-trips as float64 because encoding/json maps numbers to it.
	if id, ok := e["task_id"].(float64); !ok || id != 42 {
		t.Errorf("task_id: want 42, got %v (%T)", e["task_id"], e["task_id"])
	}
	if e["role"] != "backend" {
		t.Errorf("role attr missing or wrong: %v", e["role"])
	}
	if p, ok := e["priority"].(float64); !ok || p != 1 {
		t.Errorf("priority attr wrong: %v (%T)", e["priority"], e["priority"])
	}
	if _, ok := e["time"]; !ok {
		t.Errorf("expected time field on JSON entry, got: %v", e)
	}
}

func TestJSONHandler_OmitsTaskIDWhenZero(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf, true)
	l.Info(EventSessionStart, 0, "session", nil)

	entries := decodeLines(t, buf.Bytes())
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if _, ok := entries[0]["task_id"]; ok {
		t.Errorf("task_id should be omitted when zero, got: %v", entries[0])
	}
}

func TestJSONHandler_LevelMappings(t *testing.T) {
	cases := []struct {
		method string
		want   string
		fn     func(Logger, Event, int, string, map[string]interface{})
	}{
		{"Debug", "DEBUG", func(l Logger, e Event, id int, m string, d map[string]interface{}) { l.Debug(e, id, m, d) }},
		{"Info", "INFO", func(l Logger, e Event, id int, m string, d map[string]interface{}) { l.Info(e, id, m, d) }},
		{"Warn", "WARN", func(l Logger, e Event, id int, m string, d map[string]interface{}) { l.Warn(e, id, m, d) }},
		{"Error", "ERROR", func(l Logger, e Event, id int, m string, d map[string]interface{}) { l.Error(e, id, m, d) }},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			var buf bytes.Buffer
			l := NewWithWriter(&buf, true)
			tc.fn(l, EventStep, 1, "x", nil)
			entries := decodeLines(t, buf.Bytes())
			if len(entries) != 1 {
				t.Fatalf("expected 1 entry, got %d", len(entries))
			}
			if got := entries[0]["level"]; got != tc.want {
				t.Errorf("%s: level want %s, got %v", tc.method, tc.want, got)
			}
		})
	}
}

func TestWith_BindsAttributesToChild(t *testing.T) {
	var buf bytes.Buffer
	root := NewWithWriter(&buf, true)
	child := root.With("project", "/tmp/proj").With("provider", "anthropic")

	child.Info(EventTaskDone, 7, "done", map[string]interface{}{"duration_ms": int64(123)})

	entries := decodeLines(t, buf.Bytes())
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e["project"] != "/tmp/proj" {
		t.Errorf("project attr: want /tmp/proj, got %v", e["project"])
	}
	if e["provider"] != "anthropic" {
		t.Errorf("provider attr: want anthropic, got %v", e["provider"])
	}
	if d, ok := e["duration_ms"].(float64); !ok || d != 123 {
		t.Errorf("duration_ms: want 123, got %v", e["duration_ms"])
	}
}

func TestWith_DoesNotMutateParent(t *testing.T) {
	var buf bytes.Buffer
	root := NewWithWriter(&buf, true)
	_ = root.With("project", "/tmp/proj")

	root.Info(EventStep, 0, "no project here", nil)

	entries := decodeLines(t, buf.Bytes())
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if _, ok := entries[0]["project"]; ok {
		t.Errorf("parent logger must not inherit child attrs, got: %v", entries[0])
	}
}

func TestTextHandler_RendersKeyValuePairs(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf, false)
	l.With("project", "/tmp/p").Info(EventTaskStart, 5, "go", map[string]interface{}{"role": "backend"})

	out := buf.String()
	// slog text handler emits key=value pairs separated by spaces.
	for _, want := range []string{
		`level=INFO`,
		`msg=go`,
		`event=task_start`,
		`task_id=5`,
		`project=/tmp/p`,
		`role=backend`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\nfull output: %s", want, out)
		}
	}
}

func TestLog_SkipsCollidingKeys(t *testing.T) {
	// A caller passing a `time` key (slog reserved) must not be silently
	// dropped — the implementation namespaces it under data.time so the
	// real entry timestamp survives.
	var buf bytes.Buffer
	l := NewWithWriter(&buf, true)
	l.Info(EventStep, 0, "msg", map[string]interface{}{
		"time":  "user-supplied",
		"event": "user-event",
	})

	entries := decodeLines(t, buf.Bytes())
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e["data.time"] != "user-supplied" {
		t.Errorf("data.time should hold the user-supplied value, got %v", e["data.time"])
	}
	if e["data.event"] != "user-event" {
		t.Errorf("data.event should hold the user-supplied value, got %v", e["data.event"])
	}
	// The real `event` (top-level) must remain the EventStep tag, not the
	// caller-supplied one.
	if e["event"] != string(EventStep) {
		t.Errorf("top-level event must be the EventStep tag, got %v", e["event"])
	}
}

func TestLog_NilLogger_IsNoop(t *testing.T) {
	var l *slogLogger
	// must not panic
	l.Log(LevelInfo, EventStep, 0, "x", nil)
	l.Info(EventStep, 0, "x", nil)
	l.Warn(EventStep, 0, "x", nil)
	l.Error(EventStep, 0, "x", nil)
	l.Debug(EventStep, 0, "x", nil)
}

func TestLog_IgnoresEmptyKeys(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf, true)
	l.Info(EventStep, 0, "x", map[string]interface{}{"": "v", "kept": "y"})

	entries := decodeLines(t, buf.Bytes())
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if _, has := entries[0][""]; has {
		t.Errorf("empty key should not be emitted: %v", entries[0])
	}
	if entries[0]["kept"] != "y" {
		t.Errorf("non-empty key dropped: %v", entries[0])
	}
}

func TestNewJSONLogger_ProducesJSON(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLogger(&buf)
	if !l.IsJSON() {
		t.Fatalf("NewJSONLogger should yield IsJSON()=true")
	}
	l.Info(EventStep, 0, "hi", nil)
	if !bytes.Contains(buf.Bytes(), []byte(`"msg":"hi"`)) {
		t.Errorf("expected JSON output, got %q", buf.String())
	}
}

func TestNewWithWriter_NilWriter_DoesNotPanic(t *testing.T) {
	l := NewWithWriter(nil, true)
	// must not panic — entries are dropped onto io.Discard
	l.Info(EventStep, 0, "x", nil)
}

func TestConcurrentWrite_NoInterleave(t *testing.T) {
	// Stress: many goroutines writing — each line must remain a single,
	// parseable JSON object. If the underlying writer is not synchronised
	// this test may produce malformed lines.
	var buf bytes.Buffer
	l := NewWithWriter(&buf, true)
	var wg sync.WaitGroup
	const writers = 20
	const perWriter = 50
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				l.Info(EventStep, i, "concurrent",
					map[string]interface{}{"i": i, "j": j})
			}
		}(i)
	}
	wg.Wait()

	entries := decodeLines(t, buf.Bytes())
	if got, want := len(entries), writers*perWriter; got != want {
		t.Fatalf("expected %d entries, got %d", want, got)
	}
	for _, e := range entries {
		if e["msg"] != "concurrent" {
			t.Fatalf("malformed entry: %v", e)
		}
	}
}

func TestLevel_slogLevelMapping(t *testing.T) {
	// Sanity check that the cloop Level constants map onto the slog levels
	// the handler is configured to recognise. Asserts the integer values
	// because slog.Level is an int.
	cases := map[Level]int{
		LevelDebug: -4, // slog.LevelDebug
		LevelInfo:  0,  // slog.LevelInfo
		LevelWarn:  4,  // slog.LevelWarn
		LevelError: 8,  // slog.LevelError
	}
	for lvl, want := range cases {
		if got := int(lvl.slogLevel()); got != want {
			t.Errorf("Level %s: want slog level %d, got %d", lvl, want, got)
		}
	}
	// Unknown levels fall through to Info to avoid silently dropping
	// unrecognised input from external callers.
	if got := int(Level("bogus").slogLevel()); got != 0 {
		t.Errorf("unknown level should fall to Info (0), got %d", got)
	}
}
