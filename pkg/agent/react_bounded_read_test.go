package agent

// Regression test for the bounded read in the ReAct read_file tool.
//
// The previous implementation called os.ReadFile directly with no size cap.
// An LLM that hallucinated a path to a multi-gigabyte log/binary would slurp
// the whole file into memory and then re-encode the bytes back into the next
// prompt — both an OOM risk for the host process and a runaway token bill.
//
// Pinned invariants:
//  1. A small file is returned verbatim with no marker.
//  2. A file larger than readFileToolMaxBytes is truncated to the cap, and a
//     visible "[truncated: ...]" marker is appended so the LLM knows the
//     observation is partial.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFileTool_SmallFileVerbatim(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "small.txt")
	body := "hello world\nsecond line"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	tool := &readFileTool{}
	out, err := tool.Run(map[string]string{"path": p})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out != body {
		t.Fatalf("expected verbatim body, got %q", out)
	}
	if strings.Contains(out, "[truncated") {
		t.Fatalf("did not expect truncation marker for a small file")
	}
}

func TestReadFileTool_OversizeFileTruncated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.bin")
	// Write 2x the cap so we exercise the truncation branch deterministically.
	size := readFileToolMaxBytes*2 + 1
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatalf("truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	tool := &readFileTool{}
	out, err := tool.Run(map[string]string{"path": p})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "[truncated") {
		t.Fatalf("expected truncation marker, got tail %q", tail(out))
	}
	// The returned string must be cap + a small marker — never the full file.
	if int64(len(out)) > readFileToolMaxBytes+512 {
		t.Fatalf("output length %d exceeds cap+marker budget", len(out))
	}
}

func TestReadFileTool_MissingPathArg(t *testing.T) {
	tool := &readFileTool{}
	_, err := tool.Run(map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing path arg")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Fatalf("error %q should mention path", err.Error())
	}
}

func tail(s string) string {
	if len(s) < 200 {
		return s
	}
	return s[len(s)-200:]
}
