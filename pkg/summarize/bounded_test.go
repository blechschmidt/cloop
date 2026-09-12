package summarize

// Regression test for the artifact size cap in the summary collector
// (Task 20220).
//
// CollectTaskContexts used to os.ReadFile the whole artifact and then keep the
// first 1500 characters of it — reading a gigabyte to retain a kilobyte, and
// reporting on the opening of a transcript rather than its conclusion. A
// summarizer that silently sees a fraction of the work writes exactly the same
// confident prose as one that sees all of it, so truncation is now stated in
// the prompt itself.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
)

const (
	headMarker = "HEAD_MARKER_FIRST_BYTES_OF_ARTIFACT"
	tailMarker = "TAIL_MARKER_LAST_BYTES_OF_ARTIFACT"
)

// writeOversizeArtifact creates a sparse artifact twice the read cap, marked at
// both ends so the test can tell which end reached the prompt.
func writeOversizeArtifact(t *testing.T, path string) {
	t.Helper()
	total := int64(artifact.MaxReadBytes) * 2

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
	if _, err := f.WriteAt([]byte("---\nid: 1\n---\n\n"+headMarker+"\n"), 0); err != nil {
		t.Fatalf("write head marker: %v", err)
	}
	tail := "\n" + tailMarker + "\n"
	if _, err := f.WriteAt([]byte(tail), total-int64(len(tail))); err != nil {
		t.Fatalf("write tail marker: %v", err)
	}
}

func TestCollectTaskContexts_OversizeArtifactCappedAndAnnounced(t *testing.T) {
	dir := t.TempDir()
	writeOversizeArtifact(t, filepath.Join(dir, "big.md"))

	plan := &pm.Plan{
		Goal: "ship it",
		Tasks: []*pm.Task{
			{ID: 1, Title: "oversize", Status: pm.TaskDone, ArtifactPath: "big.md", Result: "done"},
		},
	}

	got := CollectTaskContexts(dir, plan, 0)
	if len(got) != 1 {
		t.Fatalf("expected 1 task context, got %d", len(got))
	}
	content := got[0].ArtifactContent

	// The prompt budget is the binding limit here; the on-disk cap keeps the
	// gigabyte out of memory on the way to it.
	if len(content) > artifactPromptBudget+512 {
		t.Fatalf("artifact content is %d bytes, exceeds prompt budget %d plus marker", len(content), artifactPromptBudget)
	}
	if !strings.Contains(content, "[truncated") {
		t.Error("the prompt must say the artifact was truncated, not silently show a fragment")
	}
	if !strings.Contains(content, tailMarker) {
		t.Error("summary context should keep the end of the transcript, where the outcome is")
	}
	if strings.Contains(content, headMarker) {
		t.Error("summary context kept the head of an oversized artifact")
	}
}

// TestCollectTaskContexts_OverBudgetButUnderCapDescribesItself covers the
// middle case: an artifact small enough to read whole but longer than the
// prompt budget. The notice must describe the budget trim against the file's
// real size — claiming "only the final 16.0 MiB is shown" of a 5 KB file
// would be a plainly false statement in the prompt.
func TestCollectTaskContexts_OverBudgetButUnderCapDescribesItself(t *testing.T) {
	dir := t.TempDir()
	var body strings.Builder
	for i := 0; i < 400; i++ {
		body.WriteString("a line of ordinary task output\n")
	}
	body.WriteString(tailMarker + "\n")
	if err := os.WriteFile(filepath.Join(dir, "mid.md"), []byte(body.String()), 0o644); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "mid", Status: pm.TaskDone, ArtifactPath: "mid.md"},
	}}

	got := CollectTaskContexts(dir, plan, 0)
	if len(got) != 1 {
		t.Fatalf("expected 1 task context, got %d", len(got))
	}
	content := got[0].ArtifactContent

	if !strings.Contains(content, "[truncated") {
		t.Fatal("an artifact trimmed to the prompt budget must still say so")
	}
	if strings.Contains(content, "16.0 MiB") {
		t.Errorf("notice claims the read cap was hit for a file far below it: %q", firstLine(content))
	}
	if !strings.Contains(content, "KiB") {
		t.Errorf("notice should state the artifact's real size: %q", firstLine(content))
	}
	if !strings.Contains(content, tailMarker) {
		t.Error("the kept fragment should be the tail of the artifact")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func TestCollectTaskContexts_NormalArtifactUnaffected(t *testing.T) {
	dir := t.TempDir()
	body := "Implemented the parser and added tests.\n"
	if err := os.WriteFile(filepath.Join(dir, "small.md"), []byte(body), 0o644); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	plan := &pm.Plan{
		Tasks: []*pm.Task{
			{ID: 1, Title: "small", Status: pm.TaskDone, ArtifactPath: "small.md"},
		},
	}

	got := CollectTaskContexts(dir, plan, 0)
	if len(got) != 1 {
		t.Fatalf("expected 1 task context, got %d", len(got))
	}
	if got[0].ArtifactContent != body {
		t.Fatalf("expected verbatim body %q, got %q", body, got[0].ArtifactContent)
	}
}

func TestTailChars(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		n           int
		want        string
		wantTrimmed bool
	}{
		{"fits", "short", 100, "short", false},
		{"exact", "12345", 5, "12345", false},
		// Over budget: keep the tail, and drop the partial leading line so the
		// result never opens mid-sentence (which also keeps it valid UTF-8).
		{"drops partial first line", "aaaa\nbbbb\ncccc", 9, "cccc", true},
		{"no newline in window", "aaaaaaaaaa", 4, "aaaa", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, trimmed := tailChars(c.in, c.n)
			if got != c.want || trimmed != c.wantTrimmed {
				t.Fatalf("tailChars(%q, %d) = (%q, %v), want (%q, %v)", c.in, c.n, got, trimmed, c.want, c.wantTrimmed)
			}
		})
	}
}

// TestTailChars_KeepsValidUTF8 guards the reason the cut is moved to a newline:
// slicing a byte budget out of multi-byte text would otherwise split a rune.
func TestTailChars_KeepsValidUTF8(t *testing.T) {
	in := "α β γ δ ε ζ η θ\nτέλος\n"
	got, trimmed := tailChars(in, 12)
	if !trimmed {
		t.Fatal("expected trimming")
	}
	if !strings.Contains(got, "τέλος") {
		t.Fatalf("expected the tail line, got %q", got)
	}
	for i, r := range got {
		if r == '�' {
			t.Fatalf("invalid UTF-8 at byte %d of %q", i, got)
		}
	}
}
