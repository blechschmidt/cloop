package metrics_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/metrics"
)

// TestWriteJSON_AtomicNoStaleTmpFiles ensures the writeAtomic cleanup defer
// fires — repeated WriteJSON calls should not accumulate ".metrics.json.*.tmp"
// staging files in .cloop/. A leftover would mean the temp-file lifecycle
// regressed (or the cleanup defer was removed) and would slowly leak inodes.
func TestWriteJSON_AtomicNoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	m := metrics.New("test-provider", "test-model")
	m.RecordTaskStarted()

	for i := 0; i < 10; i++ {
		if err := m.WriteJSON(dir); err != nil {
			t.Fatalf("WriteJSON %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if matched, _ := filepath.Match(".metrics.json.*.tmp", e.Name()); matched {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

// TestWriteJSON_ReaderNeverSeesTornJSON spawns a writer that calls WriteJSON
// in a tight loop and a reader that calls LoadJSON in parallel. With a direct
// os.WriteFile (the old path) the reader could observe a truncate-then-write
// race and decode an empty/partial file. The atomic-rename WriteJSON must
// always present a complete document to readers.
func TestWriteJSON_ReaderNeverSeesTornJSON(t *testing.T) {
	dir := t.TempDir()
	m := metrics.New("test-provider", "test-model")
	m.RecordTaskStarted()
	if err := m.WriteJSON(dir); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			m.RecordTaskStarted()
			if err := m.WriteJSON(dir); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			s, err := metrics.LoadJSON(dir)
			if err != nil {
				t.Errorf("reader saw torn JSON at iter %d: %v", i, err)
				return
			}
			if s == nil {
				t.Errorf("reader got nil summary at iter %d", i)
				return
			}
		}
	}()

	wg.Wait()
}

// TestWriteJSON_ConcurrentWritersStayValid drives N concurrent WriteJSON calls
// and confirms the final file on disk parses cleanly. Two non-atomic writers
// could interleave bytes; the writeMu + atomic-rename combo must serialise
// them so the resulting file is always a valid JSON document.
func TestWriteJSON_ConcurrentWritersStayValid(t *testing.T) {
	dir := t.TempDir()
	m := metrics.New("test-provider", "test-model")

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			m.RecordTaskStarted()
			if err := m.WriteJSON(dir); err != nil {
				t.Errorf("WriteJSON: %v", err)
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(filepath.Join(dir, ".cloop", "metrics.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON after concurrent writes: %v\n%s", err, data)
	}
	// Sanity-check: the snapshot mentions our provider name.
	if got, _ := raw["provider"].(string); got != "test-provider" {
		t.Fatalf("unexpected provider in snapshot: %q", got)
	}
}

// TestWriteJSON_SnapshotShape sanity-checks the JSON output structure so a
// future format change is caught explicitly.
func TestWriteJSON_SnapshotShape(t *testing.T) {
	dir := t.TempDir()
	m := metrics.New("p", "model")
	m.RecordTaskStarted()
	m.RecordTaskCompleted(1.0)
	if err := m.WriteJSON(dir); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	s, err := metrics.LoadJSON(dir)
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	if s.Provider != "p" || s.Model != "model" {
		t.Fatalf("provider/model not roundtripped: %+v", s)
	}
	if s.TasksTotal != 1 {
		t.Fatalf("expected TasksTotal=1, got %d", s.TasksTotal)
	}
	if s.TasksCompleted != 1 {
		t.Fatalf("expected TasksCompleted=1, got %d", s.TasksCompleted)
	}
	// Suppress unused-import warnings if the helpers below are stripped.
	_ = fmt.Sprintf("%v", s)
}
