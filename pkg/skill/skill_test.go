package skill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestList_OversizeUserSkillSkipped verifies that a user skill file whose
// size exceeds the cap is silently skipped during List(), so a planted
// runaway file in .cloop/skills/ cannot OOM the process. The remaining
// in-range skills (including built-ins) must still be returned.
func TestList_OversizeUserSkillSkipped(t *testing.T) {
	dir := t.TempDir()
	skillsAbs := filepath.Join(dir, skillsDir)
	if err := os.MkdirAll(skillsAbs, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	prev := maxSkillBytes
	maxSkillBytes = 64
	defer func() { maxSkillBytes = prev }()

	// In-range user skill: should appear in the result.
	if err := os.WriteFile(filepath.Join(skillsAbs, "good.md"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("seed good: %v", err)
	}
	// Oversize user skill: should be silently skipped.
	huge := make([]byte, 256)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(skillsAbs, "huge.md"), huge, 0o644); err != nil {
		t.Fatalf("seed huge: %v", err)
	}

	got, err := List(dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var sawGood, sawHuge bool
	for _, sk := range got {
		switch sk.Name {
		case "good":
			sawGood = true
			if sk.Builtin {
				t.Errorf("good was unexpectedly marked Builtin")
			}
		case "huge":
			sawHuge = true
		}
	}
	if !sawGood {
		t.Errorf("expected 'good' skill to be listed")
	}
	if sawHuge {
		t.Errorf("oversize 'huge' skill should have been skipped")
	}
}

// TestGet_OversizeUserSkillReturnsError verifies that Get() on a single
// oversize user skill returns an error rather than slurping the file into
// memory. Get() is the path used at prompt-render time, so the failure mode
// here is "skill missing" rather than "skill garbage" — much safer.
func TestGet_OversizeUserSkillReturnsError(t *testing.T) {
	dir := t.TempDir()
	skillsAbs := filepath.Join(dir, skillsDir)
	if err := os.MkdirAll(skillsAbs, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	prev := maxSkillBytes
	maxSkillBytes = 64
	defer func() { maxSkillBytes = prev }()

	huge := make([]byte, 256)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(skillsAbs, "huge.md"), huge, 0o644); err != nil {
		t.Fatalf("seed huge: %v", err)
	}

	_, err := Get(dir, "huge")
	if err == nil {
		t.Fatalf("Get on oversize skill should return error, got nil")
	}
	if !strings.Contains(err.Error(), "reading skill file") {
		t.Errorf("expected wrapped 'reading skill file' error, got: %v", err)
	}
}

// TestGet_OversizeUserDoesNotShadowBuiltin verifies that an oversize user
// override does NOT silently fall through to the built-in (that would mask
// the corruption). Get() should report the read error so the user notices.
func TestGet_OversizeUserDoesNotShadowBuiltin(t *testing.T) {
	dir := t.TempDir()
	skillsAbs := filepath.Join(dir, skillsDir)
	if err := os.MkdirAll(skillsAbs, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	prev := maxSkillBytes
	maxSkillBytes = 64
	defer func() { maxSkillBytes = prev }()

	// "tdd" is a built-in skill; plant an oversize override.
	huge := make([]byte, 256)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(skillsAbs, "tdd.md"), huge, 0o644); err != nil {
		t.Fatalf("seed huge override: %v", err)
	}

	_, err := Get(dir, "tdd")
	if err == nil {
		t.Fatalf("Get on oversize override should surface the read error rather than fall through to built-in")
	}
}
