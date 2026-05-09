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

// TestQuarantineCorrupt_RoundTrip pins the happy path: the corrupt file is
// renamed aside under a discoverable suffix and the original path is freed up
// so the caller's Load can fall back to a fresh store. The bytes must survive
// for forensics — quarantine, not delete.
func TestQuarantineCorrupt_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")

	// Write deliberately invalid JSON — the same shape a Load would see on a
	// torn pre-atomicfile write or a manual edit gone wrong.
	corrupt := []byte(`{"truncated":`)
	if err := os.WriteFile(path, corrupt, 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	qpath := QuarantineCorrupt(path)
	if qpath == "" {
		t.Fatalf("QuarantineCorrupt returned empty path on writable tmpfs")
	}
	if !strings.Contains(qpath, ".corrupt-") {
		t.Errorf("quarantine path %q missing .corrupt- marker", qpath)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("original path should be gone after quarantine, got err=%v", err)
	}
	got, err := os.ReadFile(qpath)
	if err != nil {
		t.Fatalf("read quarantined: %v", err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Errorf("quarantine clobbered content: got %q want %q", got, corrupt)
	}
}

// TestQuarantineCorrupt_MissingFile mirrors a benign race: the Load path
// observed a parse error, but by the time we tried to quarantine, another
// process already moved the file away. We must return "" rather than panic
// or pretend success — callers treat "" as "logged and moved on".
func TestQuarantineCorrupt_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "never-existed.json")

	if got := QuarantineCorrupt(path); got != "" {
		t.Errorf("expected empty return on missing source, got %q", got)
	}
}

// TestQuarantineCorrupt_SameSecondCollision drives two quarantines back-to-back
// against the same target. The second call must NOT clobber the first one's
// backup — both copies are evidence and we lose forensic value if the second
// silently overwrites. The numeric suffix branch in QuarantineCorrupt exists
// for exactly this case.
func TestQuarantineCorrupt_SameSecondCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")

	if err := os.WriteFile(path, []byte("first-corrupt"), 0o644); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	q1 := QuarantineCorrupt(path)
	if q1 == "" {
		t.Fatalf("first quarantine failed")
	}

	if err := os.WriteFile(path, []byte("second-corrupt"), 0o644); err != nil {
		t.Fatalf("seed second: %v", err)
	}
	q2 := QuarantineCorrupt(path)
	if q2 == "" {
		t.Fatalf("second quarantine failed")
	}
	if q1 == q2 {
		t.Fatalf("second quarantine clobbered the first: both at %s", q1)
	}

	// Both backups must still hold their distinct contents.
	got1, err := os.ReadFile(q1)
	if err != nil {
		t.Fatalf("read q1: %v", err)
	}
	if string(got1) != "first-corrupt" {
		t.Errorf("q1 content lost: got %q", got1)
	}
	got2, err := os.ReadFile(q2)
	if err != nil {
		t.Fatalf("read q2: %v", err)
	}
	if string(got2) != "second-corrupt" {
		t.Errorf("q2 content lost: got %q", got2)
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

// TestQuarantineCorrupt_RenamesAside verifies the happy path: a corrupt file
// is moved to "<path>.corrupt-<unix>" and the original location is left
// empty so the caller's Load can return (nil, nil) and start fresh.
func TestQuarantineCorrupt_RenamesAside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	want := []byte("garbage{not json")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	qpath := QuarantineCorrupt(path)
	if qpath == "" {
		t.Fatal("QuarantineCorrupt returned empty path on a writable directory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("original path still exists after quarantine: err=%v", err)
	}
	got, err := os.ReadFile(qpath)
	if err != nil {
		t.Fatalf("read quarantined file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("quarantined content mismatch: got %q want %q", got, want)
	}
	if !strings.Contains(qpath, ".corrupt-") {
		t.Errorf("quarantine path should contain .corrupt- marker; got %s", qpath)
	}
}

// TestQuarantineCorrupt_DisambiguatesSameSecond verifies that two
// quarantines within the same wall-clock second do not silently clobber each
// other. The second call must pick a numeric suffix (.1, .2, ...) and
// preserve both copies.
func TestQuarantineCorrupt_DisambiguatesSameSecond(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	first := QuarantineCorrupt(path)
	if first == "" {
		t.Fatal("first quarantine failed")
	}

	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("seed second: %v", err)
	}
	second := QuarantineCorrupt(path)
	if second == "" {
		t.Fatal("second quarantine failed")
	}
	if first == second {
		t.Fatalf("same-second quarantines collided onto the same path: %s", first)
	}

	firstBytes, err := os.ReadFile(first)
	if err != nil || !bytes.Equal(firstBytes, []byte("first")) {
		t.Errorf("first quarantine content damaged: bytes=%q err=%v", firstBytes, err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil || !bytes.Equal(secondBytes, []byte("second")) {
		t.Errorf("second quarantine content damaged: bytes=%q err=%v", secondBytes, err)
	}
}

// TestQuarantineCorrupt_MissingSourceReturnsEmpty verifies the soft-failure
// contract: when there's nothing to rename, the function returns "" rather
// than panicking. Callers treat "" as "couldn't quarantine; ignore and move
// on" so the recovery path can't add new failure modes to a Load that's
// already trying to recover from corruption.
func TestQuarantineCorrupt_MissingSourceReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	if got := QuarantineCorrupt(path); got != "" {
		t.Errorf("expected empty string for missing source, got %q", got)
	}
}
