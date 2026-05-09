package simulate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadFileTruncated_SmallFileVerbatim verifies a small file is returned
// without the truncation marker.
func TestReadFileTruncated_SmallFileVerbatim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := "# project\n\nshort description\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readFileTruncated(path, 800)
	if err != nil {
		t.Fatalf("readFileTruncated: %v", err)
	}
	if got != body {
		t.Fatalf("body: want %q got %q", body, got)
	}
	if strings.HasSuffix(got, "...") {
		t.Fatalf("unexpected truncation marker on small file")
	}
}

// TestReadFileTruncated_TruncatesAtMaxBytes verifies a file longer than
// maxBytes is truncated and the "..." marker is appended (matches prior
// behaviour exactly).
func TestReadFileTruncated_TruncatesAtMaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	body := strings.Repeat("a", 500)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readFileTruncated(path, 300)
	if err != nil {
		t.Fatalf("readFileTruncated: %v", err)
	}
	want := strings.Repeat("a", 300) + "..."
	if got != want {
		t.Fatalf("body mismatch: len=%d", len(got))
	}
}

// TestReadFileTruncated_ExactlyMaxBytes verifies a file of size exactly
// maxBytes is returned without the "..." marker (matches prior behaviour:
// previous len(s) > maxBytes branch).
func TestReadFileTruncated_ExactlyMaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	body := strings.Repeat("a", 300)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readFileTruncated(path, 300)
	if err != nil {
		t.Fatalf("readFileTruncated: %v", err)
	}
	if got != body {
		t.Fatalf("body mismatch: want %d 'a's got %q", 300, got)
	}
	if strings.HasSuffix(got, "...") {
		t.Fatalf("unexpected truncation marker on exactly-maxBytes file")
	}
}

// TestReadFileTruncated_OversizeFileNotOOM verifies a multi-MiB README does
// not OOM the simulation prompt builder. Uses os.Truncate to create a
// 100 MiB sparse file in constant time — the previous implementation would
// have called os.ReadFile and allocated 100 MiB just to slice off the first
// 800 bytes.
func TestReadFileTruncated_OversizeFileNotOOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	if err := os.Truncate(path, 100<<20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	got, err := readFileTruncated(path, 800)
	if err != nil {
		t.Fatalf("readFileTruncated: %v", err)
	}
	// We should get exactly 800 bytes of content + "..." marker.
	if len(got) != 800+3 {
		t.Fatalf("expected len 803, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected truncation marker, got tail %q", got[len(got)-10:])
	}
}

// TestReadFileTruncated_MissingFile preserves the prior contract — callers
// rely on err to detect "file not found" (gatherCodebaseContext loops over
// readme path candidates and breaks on the first hit).
func TestReadFileTruncated_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := readFileTruncated(filepath.Join(dir, "does-not-exist"), 300)
	if err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
}

