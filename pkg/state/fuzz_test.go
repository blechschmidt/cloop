package state

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzMigrateLegacyJSON feeds arbitrary bytes into the legacy state.json →
// state.db migration path. The migrator must reject bad JSON cleanly, never
// panic, and never produce a half-written state.db that would later confuse
// Load(). We exercise migrateFromJSON directly because it is the most
// hostile-input surface in the package.
func FuzzMigrateLegacyJSON(f *testing.F) {
	// Seeds derived from the canonical legacyState shape plus pathological
	// inputs that have historically tripped JSON decoders.
	seeds := [][]byte{
		[]byte(""),
		[]byte("{}"),
		[]byte(`{"goal":"build it","workdir":"/tmp","max_steps":10,"steps":[]}`),
		// Plan with tasks.
		[]byte(`{"goal":"g","plan":{"goal":"g","tasks":[{"id":1,"title":"a","priority":1,"status":"pending"}]}}`),
		// Steps array.
		[]byte(`{"goal":"g","steps":[{"step":1,"task":"t","output":"o","exit_code":0,"duration":"1s","time":"2026-01-01T00:00:00Z"}]}`),
		// Wrong types — must surface as an error, not panic.
		[]byte(`{"goal":42,"steps":"not-an-array"}`),
		// Mismatched brackets.
		[]byte(`{"goal":"g","steps":[}`),
		// Trailing garbage.
		[]byte(`{"goal":"g"} junk after`),
		// Deeply nested junk.
		[]byte(`{"plan":{"tasks":[{"depends_on":[1,2,3,4,5,6,7,8,9,10]}]}}`),
		// Pure binary.
		[]byte("\x00\x01\xff\xfe\x80\x81"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		cloopDir := filepath.Join(dir, ".cloop")
		if err := os.MkdirAll(cloopDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		jsonPath := filepath.Join(cloopDir, "state.json")
		dbPath := filepath.Join(cloopDir, "state.db")

		if err := os.WriteFile(jsonPath, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		// migrateFromJSON may legitimately return an error on bad input.
		// What we forbid: panics, and creating a state.db that subsequent
		// Load() calls would later trip over with a different error.
		if err := migrateFromJSON(dir, jsonPath, dbPath); err != nil {
			// Expected for malformed input — done.
			return
		}
		// On success, Load must round-trip cleanly.
		s, err := Load(dir)
		if err != nil {
			t.Fatalf("migration succeeded but Load failed: %v", err)
		}
		if s == nil {
			t.Fatal("Load returned nil state with nil error after successful migration")
		}
	})
}
