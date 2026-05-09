package trace

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestWriteTraceJSON_AtomicNoTempFiles verifies that WriteTraceJSON leaves
// no .tmp stragglers in .cloop/ — the rename must clean up the staging file.
func TestWriteTraceJSON_AtomicNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	tm := &TraceMap{
		GeneratedAt: time.Now(),
		Entries: []TraceEntry{
			{Hash: "abc123", Subject: "subj", MatchedTaskID: 1, Confidence: ConfidenceHigh},
		},
	}
	if err := WriteTraceJSON(dir, tm); err != nil {
		t.Fatalf("WriteTraceJSON: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp file after WriteTraceJSON: %s", e.Name())
		}
	}
}

// TestWriteTraceJSON_RoundTrip verifies that LoadTraceJSON can read back what
// WriteTraceJSON wrote — i.e. the atomic write produces a valid JSON file,
// not a half-written one.
func TestWriteTraceJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	tm := &TraceMap{
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Entries: []TraceEntry{
			{Hash: "deadbeef", Subject: "fix bug", MatchedTaskID: 42, MatchedTaskTitle: "T", Confidence: ConfidenceMedium},
			{Hash: "feedface", Subject: "noise", MatchedTaskID: 0, Confidence: ConfidenceNone},
		},
	}
	if err := WriteTraceJSON(dir, tm); err != nil {
		t.Fatalf("WriteTraceJSON: %v", err)
	}
	got, err := LoadTraceJSON(dir)
	if err != nil {
		t.Fatalf("LoadTraceJSON: %v", err)
	}
	if got == nil || len(got.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %+v", got)
	}
	if got.Entries[0].Hash != "deadbeef" || got.Entries[0].MatchedTaskID != 42 {
		t.Fatalf("first entry mismatch: %+v", got.Entries[0])
	}
}

// TestWriteTraceJSON_ConcurrentNoCorruption hammers WriteTraceJSON from many
// goroutines. Every successful read must yield valid JSON, and no .tmp
// stragglers may remain. Atomic rename guarantees readers always see a
// fully-written file. Run under -race to catch shared-state bugs.
func TestWriteTraceJSON_ConcurrentNoCorruption(t *testing.T) {
	dir := t.TempDir()
	const writers = 6
	const iters = 25

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				tm := &TraceMap{
					GeneratedAt: time.Now(),
					Entries: []TraceEntry{
						{Hash: "h", Subject: "s", MatchedTaskID: w*100 + i, Confidence: ConfidenceLow},
					},
				}
				if err := WriteTraceJSON(dir, tm); err != nil {
					t.Errorf("WriteTraceJSON w=%d i=%d: %v", w, i, err)
					return
				}
				if _, err := LoadTraceJSON(dir); err != nil {
					t.Errorf("LoadTraceJSON during race w=%d i=%d: %v", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp file after concurrent writes: %s", e.Name())
		}
	}
}
