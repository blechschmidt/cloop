package multiui

// Tests for per-project ownership in the registry (Task 20152).

import (
	"path/filepath"
	"testing"
)

func TestAddPathsOwnedStampsAndPersists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dirA := t.TempDir()
	dirB := t.TempDir()

	if err := AddPathsOwned([]string{dirA}, "alice@example.com"); err != nil {
		t.Fatalf("AddPathsOwned: %v", err)
	}
	if err := AddPaths([]string{dirB}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}

	entries, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	byPath := map[string]ProjectEntry{}
	for _, e := range entries {
		byPath[e.Path] = e
	}
	absA, _ := filepath.Abs(dirA)
	absB, _ := filepath.Abs(dirB)
	if got := byPath[absA].Owner; got != "alice@example.com" {
		t.Errorf("dirA owner = %q, want alice@example.com", got)
	}
	if got := byPath[absB].Owner; got != "" {
		t.Errorf("dirB owner = %q, want unowned", got)
	}

	// Re-registering an already-known path must not reassign its owner.
	if err := AddPathsOwned([]string{dirA}, "mallory@example.com"); err != nil {
		t.Fatalf("AddPathsOwned re-register: %v", err)
	}
	entries, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, e := range entries {
		if e.Path == absA && e.Owner != "alice@example.com" {
			t.Errorf("re-registration changed owner to %q", e.Owner)
		}
	}
}

func TestOwnerSurvivesSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	in := []ProjectEntry{
		{Name: "shared", Path: "/p/shared"},
		{Name: "owned", Path: "/p/owned", Owner: "bob@example.com"},
	}
	if err := Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("Load returned %d entries", len(out))
	}
	if out[0].Owner != "" || out[1].Owner != "bob@example.com" {
		t.Errorf("owners after round trip = %q, %q", out[0].Owner, out[1].Owner)
	}
}
