package memory

import (
	"os"
	"strings"
	"testing"
	"time"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-mem-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestLoad_EmptyWhenMissing(t *testing.T) {
	dir := tempDir(t)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(m.Entries))
	}
}

func TestAdd_IncrementingIDs(t *testing.T) {
	m := &Memory{NextID: 1}
	e1 := m.Add("first", "ai", "goal", nil)
	e2 := m.Add("second", "user", "goal", nil)
	if e1.ID != 1 {
		t.Errorf("expected ID=1, got %d", e1.ID)
	}
	if e2.ID != 2 {
		t.Errorf("expected ID=2, got %d", e2.ID)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := tempDir(t)
	m := &Memory{NextID: 1}
	m.Add("learned to use bun", "ai", "build a web app", nil)
	m.Add("avoid nested callbacks", "user", "", nil)

	if err := m.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].Content != "learned to use bun" {
		t.Errorf("unexpected content: %q", loaded.Entries[0].Content)
	}
	if loaded.NextID != 3 {
		t.Errorf("expected NextID=3, got %d", loaded.NextID)
	}
}

func TestDelete_RemovesEntry(t *testing.T) {
	m := &Memory{NextID: 1}
	m.Add("first", "ai", "", nil)
	e2 := m.Add("second", "ai", "", nil)
	m.Add("third", "ai", "", nil)

	if !m.Delete(e2.ID) {
		t.Error("expected Delete to return true")
	}
	if len(m.Entries) != 2 {
		t.Errorf("expected 2 entries after delete, got %d", len(m.Entries))
	}
	if m.Delete(99) {
		t.Error("expected false for non-existent ID")
	}
}

func TestClear_RemovesAll(t *testing.T) {
	m := &Memory{NextID: 1}
	m.Add("a", "ai", "", nil)
	m.Add("b", "ai", "", nil)
	m.Clear()
	if len(m.Entries) != 0 {
		t.Errorf("expected 0 entries after clear, got %d", len(m.Entries))
	}
	if m.NextID != 1 {
		t.Errorf("expected NextID reset to 1, got %d", m.NextID)
	}
}

func TestFormatForPrompt_Empty(t *testing.T) {
	m := &Memory{}
	got := m.FormatForPrompt(10)
	if got != "" {
		t.Errorf("expected empty string for empty memory, got %q", got)
	}
}

func TestFormatForPrompt_ContainsEntries(t *testing.T) {
	m := &Memory{NextID: 1}
	m.Add("use composition over inheritance", "ai", "", nil)
	m.Add("tests must pass before PR", "user", "", nil)

	got := m.FormatForPrompt(10)
	if !strings.Contains(got, "use composition over inheritance") {
		t.Error("expected first entry in prompt")
	}
	if !strings.Contains(got, "tests must pass before PR") {
		t.Error("expected second entry in prompt")
	}
	if !strings.Contains(got, "PROJECT MEMORY") {
		t.Error("expected header in prompt")
	}
}

func TestFormatForPrompt_RespectsLimit(t *testing.T) {
	m := &Memory{NextID: 1}
	for i := 0; i < 10; i++ {
		m.Add("entry", "ai", "", nil)
	}
	got := m.FormatForPrompt(3)
	// Should contain at most 3 bullet entries
	count := strings.Count(got, "\n- ")
	if count != 3 {
		t.Errorf("expected 3 entries with limit=3, got %d", count)
	}
}

func TestParseLearnings_ValidJSON(t *testing.T) {
	output := `["Use bun not npm", "Tests pass with go test ./..."]`
	learnings, err := parseLearnings(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(learnings) != 2 {
		t.Errorf("expected 2 learnings, got %d", len(learnings))
	}
	if learnings[0] != "Use bun not npm" {
		t.Errorf("unexpected first learning: %q", learnings[0])
	}
}

func TestParseLearnings_EmptyArray(t *testing.T) {
	learnings, err := parseLearnings("[]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(learnings) != 0 {
		t.Errorf("expected 0 learnings, got %d", len(learnings))
	}
}

func TestParseLearnings_NoJSON(t *testing.T) {
	learnings, err := parseLearnings("nothing here")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(learnings) != 0 {
		t.Errorf("expected 0 learnings for no JSON, got %d", len(learnings))
	}
}

func TestParseLearnings_WithPreamble(t *testing.T) {
	// AI sometimes adds text before the JSON
	output := "Here are the learnings:\n[\"learned A\", \"learned B\"]"
	learnings, err := parseLearnings(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(learnings) != 2 {
		t.Errorf("expected 2, got %d", len(learnings))
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		age      time.Duration
		contains string
	}{
		{30 * time.Second, "just now"},
		{5 * time.Minute, "m"},
		{3 * time.Hour, "h"},
		{2 * 24 * time.Hour, "d"},
		{2 * 7 * 24 * time.Hour, "w"},
	}
	for _, tt := range tests {
		got := FormatAge(time.Now().Add(-tt.age))
		if !strings.Contains(got, tt.contains) {
			t.Errorf("FormatAge(%v): expected %q in %q", tt.age, tt.contains, got)
		}
	}
}
