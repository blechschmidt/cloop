package logtail

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestTail_SmallFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	writeFile(t, p, "a\nb\nc\nd\ne\n")

	got, err := Tail(p, 3)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	want := []string{"c", "d", "e"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTail_RequestMoreThanAvailable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	writeFile(t, p, "only\n")

	got, err := Tail(p, 10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(got) != 1 || got[0] != "only" {
		t.Fatalf("got %v, want [only]", got)
	}
}

func TestTail_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	writeFile(t, p, "")

	got, err := Tail(p, 5)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestTail_NoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	writeFile(t, p, "a\nb\nc")

	got, err := Tail(p, 2)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	want := []string{"b", "c"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTail_MissingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "does-not-exist.log")
	_, err := Tail(p, 5)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestTail_BoundedRead_LargeFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")

	// 5000 lines, each ~20 bytes => ~100 KiB. With a tight maxBytes=200
	// (forcing tail behaviour) we should still get the requested last lines.
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("line-")
		// pad to a known width so byte offsets are predictable
		b.WriteString(padNumber(i, 6))
		b.WriteByte('\n')
	}
	writeFile(t, p, b.String())

	got, err := TailWithMax(p, 3, 200)
	if err != nil {
		t.Fatalf("TailWithMax: %v", err)
	}
	want := []string{"line-004997", "line-004998", "line-004999"}
	if len(got) != 3 {
		t.Fatalf("got %d lines, want 3 (got=%v)", len(got), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTail_TruncatedWindow_DropsPartialFirstLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	// "aaaaaa\nbb\ncc\n" — 13 bytes; max=6 starts mid-first-line.
	writeFile(t, p, "aaaaaa\nbb\ncc\n")

	got, err := TailWithMax(p, 5, 6)
	if err != nil {
		t.Fatalf("TailWithMax: %v", err)
	}
	// First chunk has no newline at start, so the partial line is dropped.
	// Result must not contain a synthetic half-line.
	for _, line := range got {
		if strings.Contains(line, "aaaaaa") {
			t.Errorf("partial first line leaked: %q", line)
		}
	}
}

func TestTail_NegativeOrZeroN(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	writeFile(t, p, "a\nb\nc\n")

	for _, n := range []int{0, -1, -100} {
		got, err := Tail(p, n)
		if err != nil {
			t.Fatalf("Tail(n=%d): %v", n, err)
		}
		if len(got) != 0 {
			t.Errorf("Tail(n=%d) = %v, want empty", n, got)
		}
	}
}

func padNumber(n, width int) string {
	s := ""
	for i := 0; i < width; i++ {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
