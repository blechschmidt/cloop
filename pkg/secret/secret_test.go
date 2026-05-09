package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSave_AtomicNoLeftoverTmpFiles verifies the atomic-write rewrite — every
// Save() stages a sibling ".secrets.enc.*.tmp" file and must rename it away
// before returning. Lingering .tmp files mean the cleanup defer is broken or
// somebody reverted to os.WriteFile. Either regression silently exposes the
// store to torn writes (the encrypted blob's salt+nonce header MUST remain
// intact together — a partial write makes every secret unrecoverable).
func TestSave_AtomicNoLeftoverTmpFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvPassphraseKey, "test-passphrase")

	store, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 5; i++ {
		store.Set("API_KEY", "value")
		if err := store.Save(); err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == "secrets.enc" {
			continue
		}
		if strings.Contains(name, ".tmp") {
			t.Errorf("orphan tmp file from atomic write: %q", name)
		}
	}
}

// TestSave_RoundTripAfterAtomicRewrite ensures the rename-from-tmp path still
// produces a file that Open() can decrypt. A bug in the staging path (wrong
// permissions, missing fsync, premature close) might still write *bytes* but
// produce a file Open can't recover.
func TestSave_RoundTripAfterAtomicRewrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvPassphraseKey, "test-passphrase")

	first, err := Open(dir)
	if err != nil {
		t.Fatalf("open empty: %v", err)
	}
	first.Set("ANTHROPIC_API_KEY", "sk-ant-secret-001")
	first.Set("OPENAI_API_KEY", "sk-openai-secret-002")
	if err := first.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	second, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, _ := second.Get("ANTHROPIC_API_KEY"); got != "sk-ant-secret-001" {
		t.Errorf("anthropic key roundtrip failed: %q", got)
	}
	if got, _ := second.Get("OPENAI_API_KEY"); got != "sk-openai-secret-002" {
		t.Errorf("openai key roundtrip failed: %q", got)
	}

	// File mode must remain 0o600 (owner-only) after the rename — a chmod
	// regression here leaks an encrypted-but-readable-by-others store.
	info, err := os.Stat(secretsPath(dir))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("expected mode 0o600 after atomic save, got %o", mode)
	}
}

// TestSave_ConcurrentReaderNeverSeesPartialFile is the headline guarantee of
// the atomic-write refactor. With os.WriteFile (truncate-then-write) a
// concurrent reader could observe a 0-byte file or a buffer that hadn't been
// fully flushed yet. With rename-from-tmp the destination inode is swapped
// atomically, so the reader must see either the full previous blob or the
// full new blob — never a torn header that would corrupt the entire store.
func TestSave_ConcurrentReaderNeverSeesPartialFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvPassphraseKey, "test-passphrase")

	store, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	store.Set("API_KEY", "initial-value")
	if err := store.Save(); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	path := secretsPath(dir)
	stop := make(chan struct{})
	bad := make(chan int, 1) // observed-too-short byte length
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			// Anything shorter than the salt header (saltSize bytes) is a torn
			// write — Open() would reject it as "corrupt secrets file (too
			// short)" and the user's secrets are gone.
			if len(data) > 0 && len(data) < saltSize {
				select {
				case bad <- len(data):
				default:
				}
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		store.Set("API_KEY", "rotating-value")
		if err := store.Save(); err != nil {
			close(stop)
			t.Fatalf("save iter %d: %v", i, err)
		}
	}
	close(stop)

	select {
	case n := <-bad:
		t.Fatalf("reader observed torn file of %d bytes during Save() — write is not atomic", n)
	default:
	}
}
