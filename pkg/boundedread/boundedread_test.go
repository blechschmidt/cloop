package boundedread

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestReadFile_UnderLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	writeFile(t, path, []byte("hello"))

	got, err := ReadFile(path, 1024)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestReadFile_AtLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.bin")
	payload := bytes.Repeat([]byte{'a'}, 1024)
	writeFile(t, path, payload)

	got, err := ReadFile(path, 1024)
	if err != nil {
		t.Fatalf("ReadFile at limit: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}
}

func TestReadFile_OverLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	writeFile(t, path, bytes.Repeat([]byte{'x'}, 2048))

	_, err := ReadFile(path, 1024)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected errors.Is(err, ErrTooLarge); got %v", err)
	}
	var se *SizeError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SizeError, got %T", err)
	}
	if se.Size != 2048 || se.Max != 1024 || se.Path != path {
		t.Fatalf("SizeError fields wrong: %+v", se)
	}
}

func TestReadFile_DefaultCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	writeFile(t, path, []byte("ok"))
	got, err := ReadFile(path, 0)
	if err != nil {
		t.Fatalf("ReadFile with default cap: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestReadFile_Missing(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "nope"), 1024)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist; got %v", err)
	}
}

func TestReadFile_Directory(t *testing.T) {
	_, err := ReadFile(t.TempDir(), 1024)
	if err == nil {
		t.Fatal("expected error reading directory")
	}
}

func TestReadFileTruncated_UnderLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	writeFile(t, path, []byte("hello"))

	got, truncated, err := ReadFileTruncated(path, 1024)
	if err != nil {
		t.Fatalf("ReadFileTruncated: %v", err)
	}
	if truncated {
		t.Fatal("did not expect truncation")
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestReadFileTruncated_AtLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.bin")
	writeFile(t, path, bytes.Repeat([]byte{'a'}, 1024))

	got, truncated, err := ReadFileTruncated(path, 1024)
	if err != nil {
		t.Fatalf("ReadFileTruncated at limit: %v", err)
	}
	if truncated {
		t.Fatal("file exactly at limit should not report truncation")
	}
	if len(got) != 1024 {
		t.Fatalf("got %d bytes, want 1024", len(got))
	}
}

func TestReadFileTruncated_OverLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	writeFile(t, path, bytes.Repeat([]byte{'x'}, 4096))

	got, truncated, err := ReadFileTruncated(path, 1024)
	if err != nil {
		t.Fatalf("ReadFileTruncated over limit: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncation flag")
	}
	if len(got) != 1024 {
		t.Fatalf("got %d bytes, want 1024", len(got))
	}
}

func TestReadFileTruncated_DefaultCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	writeFile(t, path, []byte("hi"))
	got, truncated, err := ReadFileTruncated(path, 0)
	if err != nil {
		t.Fatalf("ReadFileTruncated default cap: %v", err)
	}
	if truncated {
		t.Fatal("did not expect truncation under default cap")
	}
	if string(got) != "hi" {
		t.Fatalf("got %q", got)
	}
}

func TestReadFileTruncated_Missing(t *testing.T) {
	_, _, err := ReadFileTruncated(filepath.Join(t.TempDir(), "nope"), 1024)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist; got %v", err)
	}
}

func TestReadFileTruncated_Directory(t *testing.T) {
	_, _, err := ReadFileTruncated(t.TempDir(), 1024)
	if err == nil {
		t.Fatal("expected error reading directory")
	}
}
