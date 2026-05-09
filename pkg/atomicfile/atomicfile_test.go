package atomicfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestWrite_RoundTrip exercises the happy path: a fresh write must produce
// exactly the supplied bytes with the requested mode and no leftover files.
func TestWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")

	want := []byte(`{"hello":"world"}`)
	if err := Write(path, want, 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("content mismatch: got %q want %q", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0o600", info.Mode().Perm())
	}

	assertNoTmpLeftovers(t, dir)
}

// TestWrite_OverwriteAtomic confirms that overwriting an existing file with a
// new payload leaves the file with the new content and no stragglers. This is
// the critical property the previous os.WriteFile approach lacked: a torn
// write would leave a half-flushed file that subsequent readers couldn't parse.
func TestWrite_OverwriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")

	if err := Write(path, []byte("v1"), 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := Write(path, []byte("v2-longer-payload"), 0o644); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "v2-longer-payload" {
		t.Errorf("content = %q, want %q", got, "v2-longer-payload")
	}
	assertNoTmpLeftovers(t, dir)
}

// TestWrite_ReaderNeverSeesTorn pairs concurrent writers and readers. The
// reader must always observe a parseable, complete payload — never a half-
// written intermediate. Without atomic rename a long-running writer could
// truncate-then-extend the file and a racing reader would see a short read.
func TestWrite_ReaderNeverSeesTorn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "race.json")

	// Seed with a valid initial value so readers always have something to read.
	if err := Write(path, []byte(`{"v":0}`), 0o644); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	const writerIters = 200
	const readerIters = 1000

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: rotates through differently-sized payloads. If the rename were
	// not atomic, the reader would occasionally see a payload truncated in
	// the middle of a JSON token.
	go func() {
		defer wg.Done()
		for i := 0; i < writerIters; i++ {
			payload := []byte(fmt.Sprintf(`{"v":%d,"pad":%q}`, i, strings.Repeat("x", i%97)))
			if err := Write(path, payload, 0o644); err != nil {
				t.Errorf("Write iter %d: %v", i, err)
				return
			}
		}
	}()

	// Reader: every read must yield a payload that ends with `"}` and starts
	// with `{`. Anything else proves we observed a torn write.
	go func() {
		defer wg.Done()
		for i := 0; i < readerIters; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				continue // file may briefly not exist between rename steps
			}
			if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
				t.Errorf("reader saw torn payload (iter %d, len %d): %q", i, len(data), data)
				return
			}
		}
	}()

	wg.Wait()
	assertNoTmpLeftovers(t, dir)
}

// TestWrite_ConcurrentWritersAllValid drives multiple writers at the same path
// and confirms that whichever payload wins, the file remains valid and no
// .tmp stragglers accrete in the directory.
func TestWrite_ConcurrentWritersAllValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.json")

	const writers = 16
	const iters = 50

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				payload := []byte(fmt.Sprintf(`{"writer":%d,"i":%d}`, id, i))
				if err := Write(path, payload, 0o644); err != nil {
					t.Errorf("writer %d iter %d: %v", id, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after concurrent writers: %v", err)
	}
	if len(got) < 2 || got[0] != '{' || got[len(got)-1] != '}' {
		t.Errorf("final content invalid: %q", got)
	}
	assertNoTmpLeftovers(t, dir)
}

// TestWrite_ParentDirMissing returns an error when the target's parent does
// not exist. Callers are expected to MkdirAll before invoking Write — this
// test pins that contract so a future change doesn't silently swallow the
// case (which would mask a genuine bug in the caller).
func TestWrite_ParentDirMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist", "data.json")

	err := Write(path, []byte("x"), 0o644)
	if err == nil {
		t.Fatalf("expected error when parent dir missing")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("expected ENOENT-style error, got: %v", err)
	}
}

// assertNoTmpLeftovers fails the test if any .tmp staging files remain in dir.
// They indicate a bug in the cleanup defer that would slowly fill the user's
// .cloop/ directory over time.
func assertNoTmpLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") || strings.Contains(name, ".tmp.") {
			t.Errorf("leftover tmp file %q in %s", name, dir)
		}
	}
}
