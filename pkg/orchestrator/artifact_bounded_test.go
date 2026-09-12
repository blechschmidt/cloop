package orchestrator

// Regression test for the artifact size cap on the orchestrator's context
// injection path (Task 20220).
//
// injectChainOutput feeds a completed task's output into the prompt of the
// next task. That read is the one the task description calls out: the
// orchestrator "pulls the whole thing into memory on the next step to build
// context". A task that shelled out to a build produces a multi-gigabyte
// artifact, and the next step then tries to carry all of it into a prompt.
//
// It is also the clearest case for reading the tail rather than the head: what
// the downstream task needs is what the upstream one concluded, which is at
// the end of the transcript.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
)

const (
	chainHeadMarker = "HEAD_MARKER_FIRST_BYTES_OF_ARTIFACT"
	chainTailMarker = "TAIL_MARKER_LAST_BYTES_OF_ARTIFACT"
)

// writeOversizeChainArtifact creates a sparse artifact twice the read cap,
// marked at both ends so the test can tell which end reached the prompt.
func writeOversizeChainArtifact(t *testing.T, path string) {
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
	if _, err := f.WriteAt([]byte("---\nid: 1\n---\n\n"+chainHeadMarker+"\n"), 0); err != nil {
		t.Fatalf("write head marker: %v", err)
	}
	tail := "\n" + chainTailMarker + "\nTASK_DONE\n"
	if _, err := f.WriteAt([]byte(tail), total-int64(len(tail))); err != nil {
		t.Fatalf("write tail marker: %v", err)
	}
}

func TestInjectChainOutput_OversizeArtifactCappedAndAnnounced(t *testing.T) {
	dir := t.TempDir()
	writeOversizeChainArtifact(t, filepath.Join(dir, "big.md"))

	const tag = "chain:test-chain"
	upstream := &pm.Task{
		ID: 1, Title: "produces output", Status: pm.TaskDone,
		Tags: []string{tag}, ArtifactPath: "big.md", Result: "short result",
	}
	downstream := &pm.Task{
		ID: 2, Title: "consumes output", Status: pm.TaskPending,
		Tags: []string{tag}, DependsOn: []int{1},
	}
	plan := &pm.Plan{Tasks: []*pm.Task{upstream, downstream}}

	o := &Orchestrator{config: Config{WorkDir: dir}}
	o.injectChainOutput(plan, upstream, "fallback output")

	got := downstream.ChainInput
	if got == "" {
		t.Fatal("expected chain input to be injected")
	}
	if int64(len(got)) > artifact.MaxReadBytes+512 {
		t.Fatalf("chain input is %d bytes, exceeds the %d cap plus marker budget",
			len(got), artifact.MaxReadBytes)
	}
	if !strings.Contains(got, "[truncated") {
		t.Error("the downstream prompt must state that the upstream output was truncated")
	}
	if !strings.Contains(got, chainTailMarker) {
		t.Error("chain injection must carry the end of the upstream transcript, where its outcome is")
	}
	if strings.Contains(got, chainHeadMarker) {
		t.Error("chain injection carried the head of an oversized artifact instead of the tail")
	}
}

func TestInjectChainOutput_NormalArtifactUnaffected(t *testing.T) {
	dir := t.TempDir()
	body := "Built the index and verified it.\n\nTASK_DONE\n"
	content := "---\nid: 1\nstatus: done\n---\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, "small.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	const tag = "chain:small-chain"
	upstream := &pm.Task{
		ID: 1, Title: "produces", Status: pm.TaskDone,
		Tags: []string{tag}, ArtifactPath: "small.md",
	}
	downstream := &pm.Task{
		ID: 2, Title: "consumes", Status: pm.TaskPending,
		Tags: []string{tag}, DependsOn: []int{1},
	}
	plan := &pm.Plan{Tasks: []*pm.Task{upstream, downstream}}

	o := &Orchestrator{config: Config{WorkDir: dir}}
	o.injectChainOutput(plan, upstream, "fallback output")

	if downstream.ChainInput != body {
		t.Fatalf("expected the frontmatter-stripped body %q, got %q", body, downstream.ChainInput)
	}
}

// TestReadTaskOutput_ResolvesRelativeToProject pins the bug the cap work
// uncovered in the auto-eval branch: artifact paths are stored relative to the
// project directory, and the old inline os.ReadFile resolved them against the
// process working directory instead, so it only ever found the artifact when
// the two happened to coincide.
func TestReadTaskOutput_ResolvesRelativeToProject(t *testing.T) {
	dir := t.TempDir()
	body := "eval me\n"
	if err := os.WriteFile(filepath.Join(dir, "art.md"), []byte(body), 0o644); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	// Run from somewhere that is definitively not the project directory.
	t.Chdir(t.TempDir())

	task := &pm.Task{ID: 1, Title: "t", Status: pm.TaskDone, ArtifactPath: "art.md", Result: "fallback"}
	if got := artifact.ReadTaskOutput(dir, task); got != body {
		t.Fatalf("expected artifact body %q resolved against the project dir, got %q", body, got)
	}
}
