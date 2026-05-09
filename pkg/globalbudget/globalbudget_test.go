package globalbudget

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"
)

// withFakeHome redirects os.UserHomeDir() at a temp dir for the duration of
// the test. globalbudget reads HOME indirectly via os.UserHomeDir, which on
// Linux is just $HOME.
func withFakeHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestSave_RoundTrip(t *testing.T) {
	withFakeHome(t)
	in := GlobalBudgetConfig{
		DailyUSDLimit:     12.5,
		DailyTokenLimit:   1_000_000,
		AlertThresholdPct: 80,
	}
	if err := Save(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}
}

// TestSave_NoLeftoverTmpFiles guards against anyone reverting Save() to a
// direct os.WriteFile or breaking the cleanup defer in writeAtomic.
func TestSave_NoLeftoverTmpFiles(t *testing.T) {
	home := withFakeHome(t)
	for i := 0; i < 5; i++ {
		if err := Save(GlobalBudgetConfig{DailyUSDLimit: float64(i)}); err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
	}
	cfgDir := filepath.Join(home, ".config", "cloop")
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		t.Fatalf("read config dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after Save: %s", e.Name())
		}
	}
}

// TestSave_ConcurrentReaderNeverSeesEmptyOrPartialFile spins a hot writer and
// a hot reader. Without the atomic write, the reader could observe a 0-byte
// file or a yaml document missing trailing keys; with atomic rename, every
// observation must parse cleanly into a complete GlobalBudgetConfig.
func TestSave_ConcurrentReaderNeverSeesEmptyOrPartialFile(t *testing.T) {
	home := withFakeHome(t)
	path := filepath.Join(home, ".config", "cloop", "budget.yaml")

	// Seed a valid file.
	seed := GlobalBudgetConfig{
		DailyUSDLimit:     1,
		DailyTokenLimit:   100,
		AlertThresholdPct: 50,
	}
	if err := Save(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 200
	var stop atomic.Bool
	var bad atomic.Int64
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			cfg := GlobalBudgetConfig{
				DailyUSDLimit:     float64(i),
				DailyTokenLimit:   i * 1000,
				AlertThresholdPct: 80,
			}
			if err := Save(cfg); err != nil {
				t.Errorf("save: %v", err)
				return
			}
		}
	}()

	// Reader runs N iterations then signals the writer to stop. The previous
	// shape of this test signalled stop after wg.Wait, which deadlocked the
	// writer's infinite loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					bad.Add(1)
					t.Errorf("reader saw missing file mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				bad.Add(1)
				t.Errorf("reader saw 0-byte file")
				return
			}
			var got GlobalBudgetConfig
			if err := yaml.Unmarshal(data, &got); err != nil {
				bad.Add(1)
				t.Errorf("reader saw partial/invalid yaml: %v (len=%d)", err, len(data))
				return
			}
		}
	}()

	wg.Wait()
	if bad.Load() > 0 {
		t.Fatalf("reader observed %d bad states", bad.Load())
	}
}

// TestSave_PreservesMode ensures the atomic write keeps the 0o600 secret-grade
// permissions (config may live alongside API keys in budget context).
func TestSave_PreservesMode(t *testing.T) {
	home := withFakeHome(t)
	if err := Save(GlobalBudgetConfig{DailyUSDLimit: 1}); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(filepath.Join(home, ".config", "cloop", "budget.yaml"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("expected mode 0600, got %o", got)
	}
}

// TestAppendLedger_ConcurrentWritersNoInterleavedJSON spins multiple goroutines
// appending entries simultaneously. Every line in the resulting file must be
// a valid JSON object — proving ledgerMu prevents two json.Encoder.Encode
// calls from splicing each other's bytes together.
func TestAppendLedger_ConcurrentWritersNoInterleavedJSON(t *testing.T) {
	home := withFakeHome(t)

	const writers = 16
	const perWriter = 25
	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				e := GlobalLedgerEntry{
					TaskID:       w*1000 + i,
					TaskTitle:    fmt.Sprintf("writer-%d-task-%d", w, i),
					Provider:     "anthropic",
					Model:        "claude-opus-4-7",
					InputTokens:  1234,
					OutputTokens: 5678,
					EstimatedUSD: 0.0123,
				}
				if err := AppendLedger(e); err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	entries, err := ReadLedger()
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if got, want := len(entries), writers*perWriter; got != want {
		t.Fatalf("entry count: got %d, want %d (interleaved JSON would yield malformed lines that ReadLedger silently skips)", got, want)
	}

	// Verify every TaskID is present exactly once — proving the entries are
	// individually intact (no field-level interleaving).
	seen := make(map[int]int, writers*perWriter)
	for _, e := range entries {
		seen[e.TaskID]++
	}
	for w := 0; w < writers; w++ {
		for i := 0; i < perWriter; i++ {
			id := w*1000 + i
			if seen[id] != 1 {
				t.Errorf("entry id=%d seen %d times, expected 1", id, seen[id])
			}
		}
	}

	// Belt and braces: also verify the raw file has no malformed lines.
	path := filepath.Join(home, ".config", "cloop", "costs.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != writers*perWriter {
		t.Errorf("raw line count: got %d, want %d", len(lines), writers*perWriter)
	}
}
