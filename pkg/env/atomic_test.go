package env_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/env"
)

// TestSave_AtomicNoStaleTmpFiles verifies env.Save uses pkg/atomicfile and
// cleans up its sibling .tmp on success — a leftover would mean the temp-file
// lifecycle regressed (e.g. a revert to bare os.WriteFile).
func TestSave_AtomicNoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for i := 0; i < 10; i++ {
		vars := []env.Var{
			{Key: "FOO", Value: "bar"},
			{Key: "TOKEN", Value: "secret-value", Secret: true},
		}
		if err := env.Save(dir, vars); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		// pkg/atomicfile stages as ".env.yaml.<random>.tmp"
		if matched, _ := filepath.Match(".env.yaml.*.tmp", e.Name()); matched {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

// TestSave_ReaderNeverSeesTornFile races a writer against a reader on the same
// env file. With a non-atomic os.WriteFile the reader could observe a
// truncate-then-write window where Load sees an empty/partial YAML and either
// errors or returns zero entries despite the writer having vars to persist.
// The atomic-rename save must always present a complete file.
func TestSave_ReaderNeverSeesTornFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	seed := []env.Var{
		{Key: "FOO", Value: "seed"},
		{Key: "TOKEN", Value: "seed-secret", Secret: true},
	}
	if err := env.Save(dir, seed); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			vars := []env.Var{
				{Key: "FOO", Value: "bar"},
				{Key: "TOKEN", Value: "tok", Secret: true},
			}
			if err := env.Save(dir, vars); err != nil {
				t.Errorf("save %d: %v", i, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			loaded, err := env.Load(dir)
			if err != nil {
				t.Errorf("reader saw torn file at iter %d: %v", i, err)
				return
			}
			// Once the seed has been written, every successful Load must
			// return both keys — a torn write that produced an empty/partial
			// file would parse to an empty slice.
			if len(loaded) < 2 {
				t.Errorf("reader saw partial state at iter %d: %d vars", i, len(loaded))
				return
			}
		}
	}()

	wg.Wait()
}
