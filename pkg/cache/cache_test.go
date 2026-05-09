package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestWriteEntry_Atomic_NoCorruptionFromConcurrentWriters writes the same key
// from many goroutines simultaneously. Without atomic rename the writers race
// on os.Create, so a reader interleaving between Create's truncate and the
// gzip flush would observe a 0-byte file (or a half-encoded gzip stream) and
// gzip.NewReader / json.Decode would error — turning a perfectly valid cache
// entry into a permanent miss until manual cleanup. With the tmp-file +
// rename approach below, every readback must succeed.
func TestWriteEntry_Atomic_NoCorruptionFromConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, time.Hour, 200)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const key = "atomic-test-key"
	// Seed an entry so reads have something to find before the first writer runs.
	if err := c.Put(key, "seed", "anthropic", "claude-x"); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	const writers = 8
	const iters = 25

	stop := make(chan struct{})
	readerDone := make(chan struct{})
	var writerWG sync.WaitGroup

	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func(wid int) {
			defer writerWG.Done()
			for i := 0; i < iters; i++ {
				select {
				case <-stop:
					return
				default:
				}
				body := fmt.Sprintf("response-%d-%d-%s", wid, i, strings.Repeat("x", 64))
				if err := c.Put(key, body, "anthropic", "claude-x"); err != nil {
					t.Errorf("writer %d iter %d Put: %v", wid, i, err)
					return
				}
			}
		}(w)
	}

	go func() {
		defer close(readerDone)
		// Hammer Get against the writers; each Get must observe a decodable
		// entry. The previous (non-atomic) writeEntry could leave a
		// truncated gzip blob mid-flush, which json.Decode would surface as
		// an error and Get would degrade silently to a miss.
		for i := 0; i < 400; i++ {
			if _, ok := c.Get(key); !ok {
				t.Errorf("reader iter %d: cache miss on key that always exists — likely partial-write corruption", i)
				return
			}
		}
	}()

	<-readerDone
	close(stop)
	writerWG.Wait()

	// Final entry must still be decodable after the storm.
	if _, ok := c.Get(key); !ok {
		t.Errorf("post-storm Get: key unreadable")
	}
}

// TestWriteEntry_LeavesNoTempFiles verifies the atomic-write path cleans up
// after itself. The cache directory should contain exactly one .json.gz file
// after a single Put, and no orphaned tmp files.
func TestWriteEntry_LeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, time.Hour, 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Put("k1", "value-one", "anthropic", "claude-x"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	cacheRoot := filepath.Join(dir, cacheDir)
	entries, err := os.ReadDir(cacheRoot)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	var gz, tmp int
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".json.gz"):
			gz++
		case strings.HasSuffix(e.Name(), ".tmp"):
			tmp++
		}
	}
	if gz != 1 {
		t.Errorf("expected 1 .json.gz cache file, got %d", gz)
	}
	if tmp != 0 {
		t.Errorf("expected 0 .tmp files, got %d (atomic-write cleanup leaked)", tmp)
	}
}
