package finetune

// Regression tests: loadOutput reads task artifact files with a size cap.
//
// loadOutput pulls the full AI output for a done task from one of three
// sources, in order: the canonical artifact markdown, the live streaming
// artifact under .cloop/artifacts/, and finally task.Result. The first two
// are file reads. Without a cap, a runaway streaming artifact (e.g. an
// interrupted task whose output kept growing) would be slurped into memory
// during fine-tune export — and an export iterates over every done task,
// so multiple oversize artifacts compound. boundedread.ReadFile stats each
// file first and refuses to load anything larger than
// maxFinetuneArtifactBytes; on overshoot the read silently falls through
// to the next fallback so the export can still emit a record from
// task.Result.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestLoadOutput_ArtifactOversizeFallsThroughToResult confirms that an
// oversized artifact file does not OOM the export — boundedread refuses
// to load it and loadOutput falls through to task.Result.
func TestLoadOutput_ArtifactOversizeFallsThroughToResult(t *testing.T) {
	prev := maxFinetuneArtifactBytes
	maxFinetuneArtifactBytes = 256
	t.Cleanup(func() { maxFinetuneArtifactBytes = prev })

	dir := t.TempDir()
	rel := filepath.Join(".cloop", "tasks", "1-big.md")
	abs := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// 4 KiB > 256 B cap — boundedread.ReadFile short-circuits on stat().
	body := make([]byte, 4096)
	for i := range body {
		body[i] = 'x'
	}
	if err := os.WriteFile(abs, body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	task := &pm.Task{ID: 1, ArtifactPath: rel, Result: "fallback-result"}
	got := loadOutput(dir, task)
	if got != "fallback-result" {
		t.Fatalf("oversize artifact should fall through to task.Result; got %q", got)
	}
}

// TestLoadOutput_LiveArtifactOversizeFallsThroughToResult confirms that an
// oversized live streaming artifact (.cloop/artifacts/<id>_output.txt)
// also falls through cleanly when the canonical artifact is missing.
func TestLoadOutput_LiveArtifactOversizeFallsThroughToResult(t *testing.T) {
	prev := maxFinetuneArtifactBytes
	maxFinetuneArtifactBytes = 256
	t.Cleanup(func() { maxFinetuneArtifactBytes = prev })

	dir := t.TempDir()
	livePath := filepath.Join(dir, ".cloop", "artifacts", "7_output.txt")
	if err := os.MkdirAll(filepath.Dir(livePath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := make([]byte, 4096)
	for i := range body {
		body[i] = 'y'
	}
	if err := os.WriteFile(livePath, body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	task := &pm.Task{ID: 7, ArtifactPath: "", Result: "tiny-result"}
	got := loadOutput(dir, task)
	if got != "tiny-result" {
		t.Fatalf("oversize live artifact should fall through to task.Result; got %q", got)
	}
}

// TestLoadOutput_ArtifactSmallParsesNormally confirms a normally sized
// artifact still reads correctly and frontmatter is stripped. Catches
// regressions where the size guard mis-rejects valid input.
func TestLoadOutput_ArtifactSmallParsesNormally(t *testing.T) {
	prev := maxFinetuneArtifactBytes
	maxFinetuneArtifactBytes = 1 << 20
	t.Cleanup(func() { maxFinetuneArtifactBytes = prev })

	dir := t.TempDir()
	rel := filepath.Join(".cloop", "tasks", "2-ok.md")
	abs := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "---\ntitle: t\n---\nhello world\n"
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	task := &pm.Task{ID: 2, ArtifactPath: rel, Result: "should-not-be-used"}
	got := loadOutput(dir, task)
	if got != "hello world\n" {
		t.Fatalf("normal artifact: want %q, got %q", "hello world\n", got)
	}
}

// TestLoadOutput_LiveArtifactSmallParsesNormally confirms the live
// streaming artifact also reads correctly under the cap when the
// canonical artifact is absent.
func TestLoadOutput_LiveArtifactSmallParsesNormally(t *testing.T) {
	prev := maxFinetuneArtifactBytes
	maxFinetuneArtifactBytes = 1 << 20
	t.Cleanup(func() { maxFinetuneArtifactBytes = prev })

	dir := t.TempDir()
	livePath := filepath.Join(dir, ".cloop", "artifacts", "3_output.txt")
	if err := os.MkdirAll(filepath.Dir(livePath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(livePath, []byte("  streamed output\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	task := &pm.Task{ID: 3, ArtifactPath: "", Result: "should-not-be-used"}
	got := loadOutput(dir, task)
	if got != "streamed output" {
		t.Fatalf("live artifact: want %q, got %q", "streamed output", got)
	}
}
