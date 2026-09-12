package tui

// Regression test for the artifact size cap in the TUI task detail pane
// (Task 20220).
//
// buildDetailText used to os.ReadFile the artifact whole and then render its
// first 100 lines. Opening the detail view on a task that shelled out to a
// build pulled the entire log into the TUI's memory to display a screenful.
//
// This pane stays head-biased — someone browsing a transcript reads from the
// top — but the read is capped, and the cap is announced. Without the notice
// the "(N more lines)" counter silently counts lines within the window that
// was read, understating a file orders of magnitude larger.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	headMarker = "HEAD_MARKER_FIRST_BYTES_OF_ARTIFACT"
	tailMarker = "TAIL_MARKER_LAST_BYTES_OF_ARTIFACT"
)

// writeOversizeArtifact creates an artifact twice the read cap.
//
// The head holds real newline-separated lines so the "first 100 lines" render
// path is exercised the way it behaves on a real log; the middle is left
// sparse so the fixture costs no disk and no measurable time.
func writeOversizeArtifact(t *testing.T, path string) {
	t.Helper()
	total := int64(artifact.MaxReadBytes) * 2

	var head strings.Builder
	head.WriteString("---\nid: 1\nstatus: done\n---\n\n")
	head.WriteString(headMarker + "\n")
	for i := 0; i < 200; i++ {
		head.WriteString(fmt.Sprintf("log line %d\n", i))
	}

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
	if _, err := f.WriteAt([]byte(head.String()), 0); err != nil {
		t.Fatalf("write head: %v", err)
	}
	tail := "\n" + tailMarker + "\n"
	if _, err := f.WriteAt([]byte(tail), total-int64(len(tail))); err != nil {
		t.Fatalf("write tail marker: %v", err)
	}
}

func modelWithTask(dir string, task *pm.Task) Model {
	return Model{
		workdir: dir,
		state:   &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{task}}},
		cursor:  0,
	}
}

func TestBuildDetailText_OversizeArtifactCappedAndAnnounced(t *testing.T) {
	dir := t.TempDir()
	writeOversizeArtifact(t, filepath.Join(dir, "big.md"))

	m := modelWithTask(dir, &pm.Task{
		ID: 1, Title: "oversize", Status: pm.TaskDone, ArtifactPath: "big.md",
	})
	detail := m.buildDetailText()

	if int64(len(detail)) > artifact.MaxReadBytes+4096 {
		t.Fatalf("detail text is %d bytes, exceeds the %d cap plus render overhead",
			len(detail), artifact.MaxReadBytes)
	}
	if !strings.Contains(detail, "[truncated") {
		t.Error("the pane must say the artifact was truncated; otherwise the line count silently lies")
	}
	if !strings.Contains(detail, headMarker) {
		t.Error("the detail pane is head-biased and should show the start of the artifact")
	}
	if strings.Contains(detail, tailMarker) {
		t.Error("the read reached the end of an oversized artifact; it should have stopped at the cap")
	}
	if !strings.Contains(detail, "more lines") {
		t.Error("expected the existing line-overflow marker to still render")
	}
}

func TestBuildDetailText_NormalArtifactUnaffected(t *testing.T) {
	dir := t.TempDir()
	body := "line a\nline b\nline c\n"
	if err := os.WriteFile(filepath.Join(dir, "small.md"), []byte(body), 0o644); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	m := modelWithTask(dir, &pm.Task{
		ID: 2, Title: "small", Status: pm.TaskDone, ArtifactPath: "small.md",
	})
	detail := m.buildDetailText()

	if !strings.Contains(detail, "line a") || !strings.Contains(detail, "line c") {
		t.Fatalf("expected the whole small artifact to render, got:\n%s", detail)
	}
	if strings.Contains(detail, "[truncated") {
		t.Error("a small artifact must not be marked truncated")
	}
	if strings.Contains(detail, "more lines") {
		t.Error("a 3-line artifact must not report overflow")
	}
}

func TestBuildDetailText_MissingArtifactIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	m := modelWithTask(dir, &pm.Task{
		ID: 3, Title: "gone", Status: pm.TaskDone, ArtifactPath: "absent.md", Result: "the result",
	})
	detail := m.buildDetailText()

	if !strings.Contains(detail, "the result") {
		t.Fatalf("expected the task result to still render, got:\n%s", detail)
	}
	if strings.Contains(detail, "── Artifact") {
		t.Error("no artifact section should render when the file is missing")
	}
}
