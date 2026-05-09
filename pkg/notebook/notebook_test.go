package notebook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestReadArtifact_BoundedReturnsEmptyOnOversize verifies a runaway artifact
// file (e.g. a provider that streamed gigabytes into a single .cloop/ file)
// is silently skipped instead of being slurped into memory during notebook
// export. The notebook builder treats an unreadable artifact as "no content"
// for that task, which is the same behaviour as a missing file — preserving
// the rest of the report.
func TestReadArtifact_BoundedReturnsEmptyOnOversize(t *testing.T) {
	dir := t.TempDir()
	artifactRel := filepath.Join(".cloop", "artifacts", "task-1.md")
	artifactPath := filepath.Join(dir, artifactRel)
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	prev := maxNotebookArtifactBytes
	maxNotebookArtifactBytes = 64
	defer func() { maxNotebookArtifactBytes = prev }()

	huge := make([]byte, 256)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(artifactPath, huge, 0o644); err != nil {
		t.Fatalf("seed huge: %v", err)
	}

	got := readArtifact(dir, &pm.Task{ID: 1, ArtifactPath: artifactRel})
	if got != "" {
		t.Errorf("expected empty content for oversize artifact, got %d bytes", len(got))
	}
}

// TestReadArtifact_UnderCapStripsFrontmatter is a happy-path regression check
// — the size cap must not interfere with normal frontmatter handling.
func TestReadArtifact_UnderCapStripsFrontmatter(t *testing.T) {
	dir := t.TempDir()
	artifactRel := filepath.Join(".cloop", "artifacts", "task-2.md")
	artifactPath := filepath.Join(dir, artifactRel)
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "---\ntask: 2\n---\nhello world"
	if err := os.WriteFile(artifactPath, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got := readArtifact(dir, &pm.Task{ID: 2, ArtifactPath: artifactRel})
	if !strings.Contains(got, "hello world") {
		t.Errorf("expected stripped frontmatter to leave 'hello world', got %q", got)
	}
	if strings.Contains(got, "task: 2") {
		t.Errorf("frontmatter still present in output: %q", got)
	}
}
