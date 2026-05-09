package planio

import (
	"os"
	"path/filepath"
	"testing"
)

// runImport writes the fuzz input to a temp file with the given extension and
// invokes Import. Returns the result so panics propagate but errors don't fail
// the fuzzer (a parse error on malformed input is the expected behaviour).
func runImport(t *testing.T, data []byte, ext string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plan."+ext)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Import may return an error for invalid plans — that's fine. We only care
	// that the parser does not panic and that successful parses produce a
	// non-nil result with a non-nil plan.
	res, err := Import(path, "", nil, MergeReplace)
	if err == nil {
		if res == nil {
			t.Fatal("Import returned nil result with nil error")
		}
		if res.Plan == nil {
			t.Fatal("Import returned non-nil result with nil Plan")
		}
	}
}

// FuzzImportYAML feeds arbitrary bytes into the YAML import path.
func FuzzImportYAML(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte("schema_version: \"1\"\ngoal: ship it\ntasks:\n  - id: 1\n    title: do thing\n    priority: 1\n    status: pending\n"),
		// Missing required goal.
		[]byte("schema_version: \"1\"\ntasks: []\n"),
		// Duplicate IDs (validation should reject, must not panic).
		[]byte("schema_version: \"1\"\ngoal: g\ntasks:\n  - id: 1\n    title: a\n  - id: 1\n    title: b\n"),
		// Negative priority.
		[]byte("schema_version: \"1\"\ngoal: g\ntasks:\n  - id: 1\n    title: a\n    priority: -5\n"),
		// Anchors / aliases that some decoders mishandle.
		[]byte("schema_version: \"1\"\ngoal: g\ntasks: &t\n  - id: 1\n    title: a\nrepeat: *t\n"),
		// Garbage.
		[]byte("\x00\x01\xff\xfe"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		runImport(t, data, "yaml")
	})
}

// FuzzImportJSON feeds arbitrary bytes into the JSON import path.
func FuzzImportJSON(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte("{}"),
		[]byte(`{"schema_version":"1","goal":"ship it","tasks":[{"id":1,"title":"do thing","priority":1,"status":"pending"}]}`),
		// Missing tasks.
		[]byte(`{"goal":"g","tasks":[]}`),
		// Wrong types — JSON decoder must error, not panic.
		[]byte(`{"goal":42,"tasks":"nope"}`),
		// Deeply nested arrays.
		[]byte(`{"goal":"g","tasks":[{"id":1,"title":"a","depends_on":[1,2,3,4,5]}]}`),
		// UTF-16 BOM (json package rejects).
		[]byte("\xff\xfe{}"),
		// Garbage.
		[]byte("\x00\x01\xff\xfe"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		runImport(t, data, "json")
	})
}

// FuzzImportTOML feeds arbitrary bytes into the TOML import path.
func FuzzImportTOML(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte("schema_version = \"1\"\ngoal = \"ship it\"\n\n[[tasks]]\nid = 1\ntitle = \"do thing\"\npriority = 1\nstatus = \"pending\"\n"),
		// Missing goal.
		[]byte("schema_version = \"1\"\n[[tasks]]\nid = 1\ntitle = \"a\"\n"),
		// Duplicate keys (TOML rejects, must not panic).
		[]byte("goal = \"a\"\ngoal = \"b\"\n"),
		// Nested arrays of tables.
		[]byte("goal = \"g\"\n[[tasks]]\nid = 1\ntitle = \"a\"\ndepends_on = [1, 2, 3]\n"),
		// Garbage.
		[]byte("\x00\x01\xff\xfe"),
		// Unterminated string.
		[]byte("goal = \"unterminated\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		runImport(t, data, "toml")
	})
}
