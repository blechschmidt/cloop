package agent_test

// Regression tests for the atomic-write + serialised-write fix in agent.go.
//
// The daemon worker writes State via Save() on every status transition, run
// completion, and error path — and concurrently with cloop CLI invocations
// (e.g. `cloop agent status`) reading the same file. A torn write of
// agent.json or agent.pid would produce malformed JSON / a half-printed PID
// and a daemon would silently disagree with itself about whether it's alive.
//
// Pinned invariants:
//  1. Save and WritePID leave no .tmp files behind.
//  2. A reader running in parallel with a writer never sees a 0-byte JSON.
//  3. N concurrent Save() callers all complete without overwriting each
//     other's MarshalIndent buffer (race detector: no Marshal interleaving).

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/agent"
)

// TestSave_NoLeftoverTmpFiles asserts the atomic write path renames its
// staging tmp files instead of leaking them next to agent.json.
func TestSave_NoLeftoverTmpFiles(t *testing.T) {
	work := t.TempDir()

	s := &agent.State{
		PID:       1234,
		StartedAt: time.Now(),
		Status:    "idle",
		Interval:  "5m",
	}
	for i := 0; i < 8; i++ {
		s.RunCount = i
		if err := s.Save(work); err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(work, ".cloop"))
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after Save: %s", e.Name())
		}
	}
}

// TestWritePID_NoLeftoverTmpFiles same check for the PID file path.
func TestWritePID_NoLeftoverTmpFiles(t *testing.T) {
	work := t.TempDir()

	for i := 1000; i < 1008; i++ {
		if err := agent.WritePID(work, i); err != nil {
			t.Fatalf("write pid iter %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(work, ".cloop"))
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after WritePID: %s", e.Name())
		}
	}
	if got := agent.ReadPID(work); got != 1007 {
		t.Errorf("expected ReadPID=1007 after final write, got %d", got)
	}
}

// TestSave_ConcurrentReaderNeverSeesPartial pits a hot writer against a hot
// reader to expose torn writes. Without the atomic rename the reader would
// observe a 0-byte agent.json mid-write.
func TestSave_ConcurrentReaderNeverSeesPartial(t *testing.T) {
	work := t.TempDir()

	// Seed.
	s := &agent.State{
		PID:       1234,
		StartedAt: time.Now(),
		Status:    "idle",
		// Pad LastError to widen the write window so the race is more likely
		// to surface if the atomic rename regresses.
		LastError: strings.Repeat("e", 4096),
		Interval:  "5m",
	}
	if err := s.Save(work); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 300
	var stop atomic.Bool
	var wg sync.WaitGroup
	path := agent.StatePath(work)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			s.RunCount = i
			s.LastError = strings.Repeat("e", 4096+(i%256))
			if err := s.Save(work); err != nil {
				t.Errorf("save: %v", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					t.Errorf("reader saw missing agent.json mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				t.Errorf("reader saw 0-byte agent.json")
				return
			}
			var got agent.State
			if err := json.Unmarshal(data, &got); err != nil {
				t.Errorf("reader saw partial/invalid JSON: %v (len=%d)", err, len(data))
				return
			}
		}
	}()

	wg.Wait()
}

// TestSave_ConcurrentWritersNoCorruption fires N goroutines all calling
// Save() with different RunCount values. Under the race detector, the
// stateMu serialisation is what keeps the json.MarshalIndent buffer
// allocations from interleaving on the same shared State.
func TestSave_ConcurrentWritersNoCorruption(t *testing.T) {
	work := t.TempDir()

	const writers = 16
	const iters = 50
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := &agent.State{
				PID:       w,
				StartedAt: time.Now(),
				Status:    "idle",
			}
			for i := 0; i < iters; i++ {
				s.RunCount = i
				if err := s.Save(work); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("save: %v", err)
	}

	// Final file must parse cleanly.
	got, err := agent.Load(work)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil State after concurrent writers")
	}
}
