package configvalidate

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestStripUnknownKeys_AtomicNoStaleTmpFiles verifies stripUnknownKeys uses
// pkg/atomicfile and cleans up its sibling .tmp on success — a leftover would
// signal a regression to bare os.WriteFile, which would silently lose API
// keys on a torn write.
func TestStripUnknownKeys_AtomicNoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	for i := 0; i < 10; i++ {
		seed := []byte("provider: anthropic\nbogus_key: noise\nanthropic:\n  api_key: sk-test-12345\n")
		if err := os.WriteFile(cfgPath, seed, 0o600); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		if err := stripUnknownKeys(cfgPath, seed); err != nil {
			t.Fatalf("strip %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if matched, _ := filepath.Match(".config.yaml.*.tmp", e.Name()); matched {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

// TestStripUnknownKeys_PreservesAPIKey is a behavioural regression test: the
// rewrite must drop unknown top-level keys but keep the known sub-tree (and
// in particular the API key inside it). A bug in the atomic write that
// truncated the file would cause this to fail.
func TestStripUnknownKeys_PreservesAPIKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	seed := []byte("provider: anthropic\nbogus_key: noise\nanthropic:\n  api_key: sk-test-99999\n  model: claude-3-opus\n")
	if err := os.WriteFile(cfgPath, seed, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := stripUnknownKeys(cfgPath, seed); err != nil {
		t.Fatalf("strip: %v", err)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read after strip: %v", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(got, &raw); err != nil {
		t.Fatalf("post-strip file is not valid YAML — atomic write may have torn: %v\n%s", err, got)
	}
	if _, has := raw["bogus_key"]; has {
		t.Errorf("bogus_key should have been removed; raw=%v", raw)
	}
	if !strings.Contains(string(got), "sk-test-99999") {
		t.Errorf("API key was not preserved across the rewrite:\n%s", got)
	}
}

// TestStripUnknownKeys_ReaderNeverSeesTornFile races a writer against a
// reader. A non-atomic os.WriteFile could expose a truncated file mid-write
// and cause the reader to fail YAML parsing. The atomic-rename path must
// always present a complete document.
func TestStripUnknownKeys_ReaderNeverSeesTornFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	seed := []byte("provider: anthropic\nbogus_key: noise\nanthropic:\n  api_key: sk-test-seed\n")
	if err := os.WriteFile(cfgPath, seed, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := stripUnknownKeys(cfgPath, seed); err != nil {
				t.Errorf("strip %d: %v", i, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Errorf("read %d: %v", i, err)
				return
			}
			var raw map[string]any
			if err := yaml.Unmarshal(data, &raw); err != nil {
				t.Errorf("reader saw torn YAML at iter %d: %v\n%s", i, err, data)
				return
			}
		}
	}()

	wg.Wait()
}
