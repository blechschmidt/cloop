package boundedread

// Tests for ReadFileTail, the primitive behind every outcome-seeking artifact
// read (Task 20220). A head-biased preview of a 2 GB build log is 16 MiB of
// compiler chatter and none of the answer, so callers that want to know how a
// run ended need the other end of the file.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFileTail_SmallFileReturnedWhole(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "small.log")
	body := "line one\nline two\nTASK_DONE\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	data, truncated, err := ReadFileTail(p, 1<<20)
	if err != nil {
		t.Fatalf("ReadFileTail: %v", err)
	}
	if truncated {
		t.Error("small file must not report truncation")
	}
	if string(data) != body {
		t.Fatalf("got %q, want %q", data, body)
	}
}

func TestReadFileTail_OversizeKeepsTailWithinCap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.log")

	const cap = 4096
	head := "START_OF_FILE\n"
	tail := "\nEND_OF_FILE_TASK_DONE\n"
	total := int64(cap) * 3

	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(total); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := f.WriteAt([]byte(head), 0); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := f.WriteAt([]byte(tail), total-int64(len(tail))); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	data, truncated, err := ReadFileTail(p, cap)
	if err != nil {
		t.Fatalf("ReadFileTail: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncation for a file 3x the cap")
	}
	if int64(len(data)) > cap {
		t.Fatalf("read %d bytes, exceeds cap %d", len(data), cap)
	}
	if !strings.Contains(string(data), "END_OF_FILE_TASK_DONE") {
		t.Error("tail read must keep the end of the file")
	}
	if strings.Contains(string(data), "START_OF_FILE") {
		t.Error("tail read must not include the start of an oversized file")
	}
}

func TestReadFileTail_ZeroMaxUsesDefault(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "default.log")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	data, truncated, err := ReadFileTail(p, 0)
	if err != nil {
		t.Fatalf("ReadFileTail: %v", err)
	}
	if truncated || string(data) != "x" {
		t.Fatalf("got %q truncated=%v", data, truncated)
	}
}

func TestReadFileTail_MissingFileMatchesErrNotExist(t *testing.T) {
	_, _, err := ReadFileTail(filepath.Join(t.TempDir(), "nope.log"), 1024)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestReadFileTail_DirectoryRejected(t *testing.T) {
	_, _, err := ReadFileTail(t.TempDir(), 1024)
	if err == nil {
		t.Fatal("expected an error for a directory")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("error %q should say it is a directory", err)
	}
}

// TestArtifactMaxBytes_IsUsableAsBothTypes pins the deliberate choice to leave
// the shared cap untyped: pkg/taskrecover uses it as an int64 byte bound and
// its test uses it as an int string length.
func TestArtifactMaxBytes_IsUsableAsBothTypes(t *testing.T) {
	var asInt64 int64 = ArtifactMaxBytes
	var asInt int = ArtifactMaxBytes
	if asInt64 != 16<<20 || asInt != 16<<20 {
		t.Fatalf("ArtifactMaxBytes = %d/%d, want 16 MiB", asInt64, asInt)
	}
}
