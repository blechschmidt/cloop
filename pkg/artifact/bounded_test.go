package artifact

// Regression tests for the artifact size cap (Task 20220).
//
// Task artifacts are the agent's own captured stdout. That is precisely why
// they went unbounded: nobody writes a hostile artifact, but a task that shells
// out to a build, a training run or a chatty test suite produces a
// multi-gigabyte one by accident, and every reader then pulled it whole into
// the hub's memory.
//
// Pinned invariants:
//  1. No reader returns more than MaxReadBytes (plus a small marker budget).
//  2. Hitting the cap is always reported, never silent.
//  3. The tail reader keeps the END of the artifact — where an agent's
//     conclusion and completion signal live — not the beginning.
//  4. Normal-sized artifacts are unaffected: verbatim body, no marker.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

const (
	headMarker = "HEAD_MARKER_FIRST_BYTES_OF_ARTIFACT"
	tailMarker = "TAIL_MARKER_LAST_BYTES_OF_ARTIFACT"
)

// writeOversizeArtifact creates an artifact twice the read cap, with a
// recognisable marker at each end so a test can tell which end was read.
//
// The file is sparse: Truncate reserves the length without allocating the
// middle, so a 32 MiB fixture costs no real disk and no measurable time.
func writeOversizeArtifact(t *testing.T, path string) int64 {
	t.Helper()
	total := int64(MaxReadBytes) * 2

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create artifact: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close artifact: %v", err)
		}
	}()

	if err := f.Truncate(total); err != nil {
		t.Fatalf("truncate artifact: %v", err)
	}
	// Real artifacts open with YAML frontmatter; include it so the
	// frontmatter-stripping path is exercised the same way in both directions.
	head := "---\nid: 1\ntitle: \"oversize\"\nstatus: done\n---\n\n" + headMarker + "\n"
	if _, err := f.WriteAt([]byte(head), 0); err != nil {
		t.Fatalf("write head marker: %v", err)
	}
	tail := "\n" + tailMarker + "\n"
	if _, err := f.WriteAt([]byte(tail), total-int64(len(tail))); err != nil {
		t.Fatalf("write tail marker: %v", err)
	}
	return total
}

// markerBudget is the slack allowed above the cap for a truncation notice.
const markerBudget = 512

func TestReadArtifactTail_OversizeStaysInCapAndKeepsTail(t *testing.T) {
	dir := t.TempDir()
	total := writeOversizeArtifact(t, filepath.Join(dir, "big.md"))

	data, truncated, reported, err := ReadArtifactTail(dir, "big.md")
	if err != nil {
		t.Fatalf("ReadArtifactTail: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true for an artifact twice the cap")
	}
	if reported != total {
		t.Fatalf("reported total = %d, want the on-disk size %d", reported, total)
	}
	if int64(len(data)) > MaxReadBytes {
		t.Fatalf("read %d bytes, exceeds cap of %d", len(data), MaxReadBytes)
	}
	if !strings.Contains(string(data), tailMarker) {
		t.Error("tail read must keep the END of the artifact; tail marker missing")
	}
	if strings.Contains(string(data), headMarker) {
		t.Error("tail read kept the head of the artifact; it should have been skipped")
	}
}

func TestReadArtifactHead_OversizeStaysInCapAndKeepsHead(t *testing.T) {
	dir := t.TempDir()
	total := writeOversizeArtifact(t, filepath.Join(dir, "big.md"))

	data, truncated, reported, err := ReadArtifactHead(dir, "big.md")
	if err != nil {
		t.Fatalf("ReadArtifactHead: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true for an artifact twice the cap")
	}
	if reported != total {
		t.Fatalf("reported total = %d, want the on-disk size %d", reported, total)
	}
	if int64(len(data)) > MaxReadBytes {
		t.Fatalf("read %d bytes, exceeds cap of %d", len(data), MaxReadBytes)
	}
	if !strings.Contains(string(data), headMarker) {
		t.Error("head read must keep the START of the artifact; head marker missing")
	}
	if strings.Contains(string(data), tailMarker) {
		t.Error("head read reached the tail of the artifact; it should have stopped at the cap")
	}
}

// TestReadTaskOutput_OversizeIsCappedAndAnnounced covers the shared reader used
// by the orchestrator's chain injection and auto-eval, acceptance checks,
// replay and the Web UI task detail panel.
func TestReadTaskOutput_OversizeIsCappedAndAnnounced(t *testing.T) {
	dir := t.TempDir()
	writeOversizeArtifact(t, filepath.Join(dir, "big.md"))

	task := &pm.Task{ID: 1, Title: "oversize", Status: pm.TaskDone, ArtifactPath: "big.md", Result: "fallback"}
	out := ReadTaskOutput(dir, task)

	if int64(len(out)) > MaxReadBytes+markerBudget {
		t.Fatalf("ReadTaskOutput returned %d bytes, exceeds cap+marker budget %d", len(out), MaxReadBytes+markerBudget)
	}
	if !strings.Contains(out, "[truncated") {
		t.Error("truncation must be visible to the consumer; no marker in output")
	}
	if !strings.HasPrefix(out, "[truncated") {
		t.Error("tail-biased truncation notice belongs at the top, before the surviving tail")
	}
	if !strings.Contains(out, tailMarker) {
		t.Error("ReadTaskOutput must keep the end of the transcript, where the outcome is")
	}
}

// TestReadTaskOutput_NormalArtifactUnaffected guards against the cap changing
// behaviour for the artifacts that actually occur — kilobytes, not gigabytes.
func TestReadTaskOutput_NormalArtifactUnaffected(t *testing.T) {
	dir := t.TempDir()
	body := "I implemented the thing.\n\nTASK_DONE\n"
	content := "---\nid: 7\ntitle: \"small\"\nstatus: done\n---\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, "small.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	task := &pm.Task{ID: 7, Title: "small", Status: pm.TaskDone, ArtifactPath: "small.md", Result: "fallback"}
	out := ReadTaskOutput(dir, task)

	if out != body {
		t.Fatalf("expected verbatim frontmatter-stripped body %q, got %q", body, out)
	}
	if strings.Contains(out, "[truncated") {
		t.Error("a small artifact must not be marked truncated")
	}
}

// TestReadTaskOutput_FallsBackToResult pins the pre-existing contract: a
// missing artifact falls back to task.Result rather than returning empty.
func TestReadTaskOutput_FallsBackToResult(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{ID: 3, Title: "gone", ArtifactPath: "does-not-exist.md", Result: "fallback result"}
	if got := ReadTaskOutput(dir, task); got != "fallback result" {
		t.Fatalf("expected fallback to task.Result, got %q", got)
	}
}

// TestReadArtifact_AbsolutePathAccepted pins that an absolute ArtifactPath is
// not joined onto workDir. Paths are stored relative, but callers occasionally
// hold an absolute one.
func TestReadArtifact_AbsolutePathAccepted(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "abs.md")
	if err := os.WriteFile(abs, []byte("body\n"), 0o644); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	data, truncated, _, err := ReadArtifactTail("/nonexistent-workdir", abs)
	if err != nil {
		t.Fatalf("ReadArtifactTail with absolute path: %v", err)
	}
	if truncated {
		t.Error("small artifact reported as truncated")
	}
	if string(data) != "body\n" {
		t.Fatalf("got %q", data)
	}
}

func TestTruncationNotices_StateBothSizes(t *testing.T) {
	tail := TailTruncationNotice(2 << 30)
	head := HeadTruncationNotice(2 << 30)

	for name, notice := range map[string]string{"tail": tail, "head": head} {
		if !strings.Contains(notice, "2.0 GiB") {
			t.Errorf("%s notice should state the artifact's real size, got %q", name, notice)
		}
		if !strings.Contains(notice, "16.0 MiB") {
			t.Errorf("%s notice should state how much was read, got %q", name, notice)
		}
		if !strings.Contains(notice, "[truncated") {
			t.Errorf("%s notice should carry the standard marker, got %q", name, notice)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512 B"},
		{1 << 10, "1.0 KiB"},
		{16 << 20, "16.0 MiB"},
		{2 << 30, "2.0 GiB"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.in); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
