package checkpoint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSaveHistoryEntry_AtomicNoTempFiles verifies writeAtomic cleans up after
// itself: only the final .json file should remain, no orphaned .tmp siblings.
func TestSaveHistoryEntry_AtomicNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	cp := &Checkpoint{
		TaskID:     42,
		TaskTitle:  "test",
		StepNumber: 1,
		Timestamp:  time.Now(),
	}
	if err := SaveHistoryEntry(dir, cp); err != nil {
		t.Fatalf("SaveHistoryEntry: %v", err)
	}
	hd := historyDir(dir, 42)
	entries, err := os.ReadDir(hd)
	if err != nil {
		t.Fatalf("read history dir: %v", err)
	}
	var jsonCount, tmpCount int
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".json"):
			jsonCount++
		case strings.Contains(e.Name(), ".tmp"):
			tmpCount++
		}
	}
	if jsonCount != 1 {
		t.Errorf("expected 1 .json history entry, got %d", jsonCount)
	}
	if tmpCount != 0 {
		t.Errorf("expected 0 .tmp files, got %d (atomic-write cleanup leaked)", tmpCount)
	}
}

// TestSaveHistoryEntry_ConcurrentNoCorruption stresses writeAtomic with many
// concurrent writers (each producing distinct unix-nano filenames) and a
// reader that lists+parses every entry. With a non-atomic os.WriteFile a
// reader interleaving between truncate and the JSON flush would observe a
// 0-byte file and ListHistory would silently drop it. With tmp+rename every
// listed file must parse.
func TestSaveHistoryEntry_ConcurrentNoCorruption(t *testing.T) {
	dir := t.TempDir()
	const writers = 8
	const iters = 25

	var wg sync.WaitGroup
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	var readerErr error

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				select {
				case <-stop:
					return
				default:
				}
				cp := &Checkpoint{
					TaskID:            7,
					TaskTitle:         "concurrent",
					StepNumber:        i,
					AccumulatedOutput: fmt.Sprintf("body-%d-%d", wid, i),
					Timestamp:         time.Now().Add(time.Duration(wid*1000+i) * time.Nanosecond),
				}
				if err := SaveHistoryEntry(dir, cp); err != nil {
					t.Errorf("writer %d iter %d: %v", wid, i, err)
					return
				}
			}
		}(w)
	}

	go func() {
		defer close(readerDone)
		// While writers are running, repeatedly list+parse every file. Any
		// torn write surfaces as a parse error inside ListHistory; the
		// outer loop simply re-lists. We instead audit the directory
		// directly so we don't rely on ListHistory's silent skip behaviour.
		for r := 0; r < 200; r++ {
			hd := historyDir(dir, 7)
			entries, err := os.ReadDir(hd)
			if err != nil {
				continue // dir not created yet
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				path := filepath.Join(hd, e.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					readerErr = fmt.Errorf("read %s: %w", e.Name(), err)
					return
				}
				if len(data) == 0 {
					readerErr = fmt.Errorf("zero-byte history entry %s — non-atomic write observed", e.Name())
					return
				}
			}
		}
	}()

	wg.Wait()
	close(stop)
	<-readerDone

	if readerErr != nil {
		t.Errorf("reader observed corruption: %v", readerErr)
	}

	// Every entry written must be loadable.
	hd := historyDir(dir, 7)
	entries, err := os.ReadDir(hd)
	if err != nil {
		t.Fatalf("final read: %v", err)
	}
	parsed := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if _, err := LoadHistoryEntry(dir, 7, id); err != nil {
			t.Errorf("LoadHistoryEntry(%s): %v", id, err)
		} else {
			parsed++
		}
	}
	if parsed == 0 {
		t.Errorf("no entries parsed; expected up to %d", writers*iters)
	}
}

// TestSave_AtomicNoTempFiles confirms the main checkpoint.json write also
// leaves no .tmp leftovers after a successful Save.
func TestSave_AtomicNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cp := &Checkpoint{TaskID: 1, TaskTitle: "save", Timestamp: time.Now()}
	if err := Save(dir, cp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("orphaned tmp file: %s", e.Name())
		}
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil || loaded.TaskID != 1 {
		t.Errorf("loaded checkpoint mismatch: %+v", loaded)
	}
}

// TestLoad_CorruptFileQuarantined ensures a malformed checkpoint.json no
// longer hard-errors a fresh run. The previous behaviour returned
// `parse checkpoint: ...` and the orchestrator refused to start until the
// user manually deleted the file. After the fix Load quarantines the bad
// bytes aside (preserved for forensics) and returns (nil, nil) so the run
// can proceed from scratch.
func TestLoad_CorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := Path(dir)
	if err := os.WriteFile(path, []byte(`{"task_id":42, "task_title": INVALID`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on corrupt file should return nil checkpoint, got: %+v", got)
	}

	// Original path freed up; corrupt bytes preserved under .corrupt-* sibling.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", path, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a .corrupt-* sibling preserving the bad bytes, dir contents: %v", entries)
	}
}

// TestLoad_ZeroByteFileQuarantined covers the most likely real-world cause of
// corruption: a process killed between os.Create and the first write left a
// 0-byte file behind. (atomicfile.Write avoids this on the happy path, but
// pre-atomicfile binaries didn't, and a `truncate -s 0` from outside cloop
// can produce the same shape.) An empty file fails json.Unmarshal with
// "unexpected end of JSON input" and previously bricked Load.
func TestLoad_ZeroByteFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := Path(dir)
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on zero-byte file should return nil, got: %+v", got)
	}
}

// TestLoad_OversizeFileQuarantined verifies an unreasonably large checkpoint
// file does not OOM the loader. The file is quarantined and Load returns
// (nil, nil) so a fresh run can begin.
func TestLoad_OversizeFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	prev := maxCheckpointBytes
	maxCheckpointBytes = 64
	defer func() { maxCheckpointBytes = prev }()

	path := Path(dir)
	huge := make([]byte, 256)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(path, huge, 0o644); err != nil {
		t.Fatalf("seed huge: %v", err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on oversize file should not return an error (quarantine path), got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on oversize file should return nil, got: %+v", got)
	}
	// Original path should be gone (quarantined aside).
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("expected oversize checkpoint to be quarantined away from %s, but it still exists", path)
	}
	// A .corrupt-* sibling should exist.
	siblings, _ := os.ReadDir(filepath.Dir(path))
	var found bool
	for _, e := range siblings {
		if strings.Contains(e.Name(), ".corrupt-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a .corrupt-* quarantine sibling next to %s", path)
	}
}

// TestLoadHistoryEntry_OversizeRejected verifies a single history entry that
// exceeds the cap is rejected with an error rather than loaded into memory.
func TestLoadHistoryEntry_OversizeRejected(t *testing.T) {
	dir := t.TempDir()
	hd := historyDir(dir, 7)
	if err := os.MkdirAll(hd, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	prev := maxCheckpointBytes
	maxCheckpointBytes = 64
	defer func() { maxCheckpointBytes = prev }()

	path := filepath.Join(hd, "entry-oversize.json")
	huge := make([]byte, 256)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(path, huge, 0o644); err != nil {
		t.Fatalf("seed huge: %v", err)
	}

	_, err := LoadHistoryEntry(dir, 7, "entry-oversize")
	if err == nil {
		t.Fatalf("LoadHistoryEntry should reject oversize file, got nil error")
	}
}

// TestListHistory_OversizeEntrySkipped verifies that when iterating history
// entries, a single oversize entry is skipped rather than aborting the whole
// listing.
func TestListHistory_OversizeEntrySkipped(t *testing.T) {
	dir := t.TempDir()
	hd := historyDir(dir, 9)
	if err := os.MkdirAll(hd, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	prev := maxCheckpointBytes
	maxCheckpointBytes = 256
	defer func() { maxCheckpointBytes = prev }()

	// Good entry (small JSON).
	good := &Checkpoint{TaskID: 9, TaskTitle: "good", StepNumber: 1, Timestamp: time.Now()}
	if err := SaveHistoryEntry(dir, good); err != nil {
		t.Fatalf("SaveHistoryEntry good: %v", err)
	}
	// Oversize entry (raw write to bypass the writer's marshal+atomic path).
	huge := make([]byte, 1024)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(hd, "huge.json"), huge, 0o644); err != nil {
		t.Fatalf("seed huge: %v", err)
	}

	entries, err := ListHistory(dir, 9)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected oversize entry to be skipped, got %d entries", len(entries))
	}
	if entries[0].Checkpoint.TaskTitle != "good" {
		t.Errorf("expected the good entry to survive, got %+v", entries[0])
	}
}
