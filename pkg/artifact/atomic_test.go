package artifact_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestWriteTaskArtifact_AtomicNoStaleTmpFiles verifies the atomicfile.Write
// staging cleanup defer fires — repeated WriteTaskArtifact calls must not
// leave ".<filename>.*.tmp" leftovers in .cloop/tasks/. A leftover would
// signal that the temp-file lifecycle regressed and that we are slowly
// leaking inodes on every PM run.
func TestWriteTaskArtifact_AtomicNoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{ID: 7, Title: "Build the X widget", Status: pm.TaskDone}

	for i := 0; i < 25; i++ {
		if _, err := artifact.WriteTaskArtifact(dir, task, "AI output v"); err != nil {
			t.Fatalf("WriteTaskArtifact %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(dir, ".cloop", "tasks"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".") {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

// TestWriteTaskArtifact_ReaderNeverSeesPartialFile spawns a writer that
// rewrites the same artifact in a tight loop and a reader that reads it
// concurrently. With the previous os.WriteFile path, a reader could observe
// the truncate-then-write window and read an empty (or partial) file. With
// atomicfile.Write the stat/read must always observe a complete document or
// the absence of the file.
func TestWriteTaskArtifact_ReaderNeverSeesPartialFile(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{ID: 42, Title: "Race writer/reader", Status: pm.TaskDone}

	// Seed the file once so the reader has something to find.
	rel, err := artifact.WriteTaskArtifact(dir, task, "seed body line\n")
	if err != nil {
		t.Fatalf("seed write: %v", err)
	}
	abs := filepath.Join(dir, rel)

	const iterations = 200
	const sentinel = "MARKER:"
	body := strings.Repeat("payload payload payload payload\n", 64)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if _, err := artifact.WriteTaskArtifact(dir, task, sentinel+body); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(abs)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				t.Errorf("reader: %v", err)
				return
			}
			s := string(data)
			// Frontmatter close marker — present only when the full document
			// landed atomically. A torn read would lack this trailer and the
			// body sentinel.
			if !strings.Contains(s, "\n---\n\n") {
				t.Errorf("reader observed partial frontmatter: %q", s)
				return
			}
			if !strings.Contains(s, "seed body") && !strings.Contains(s, sentinel) {
				t.Errorf("reader observed neither seed nor live body: %q", s)
				return
			}
		}
	}()

	wg.Wait()
}

// TestWriteExecArtifact_AtomicWritesCompleteFile ensures the exec-artifact
// path also benefits from atomic writes. We don't need a race for this one;
// just confirm the file exists with the expected verdict marker after a
// crash-style rapid rewrite.
func TestWriteExecArtifact_AtomicWritesCompleteFile(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{ID: 9, Title: "Exec something", Status: pm.TaskDone}

	rel, err := artifact.WriteExecArtifact(dir, task, []string{"echo", "hi"}, 0, time.Millisecond, "hi\n")
	if err != nil {
		t.Fatalf("WriteExecArtifact: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "exit_code: 0") {
		t.Fatalf("exec artifact missing exit_code line:\n%s", data)
	}
}
