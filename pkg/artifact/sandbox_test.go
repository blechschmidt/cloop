package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestSandboxFrontmatterRoundTrips is the test frontmatterKeys' comment points
// at: it is what keeps the writer and the reader from drifting.
//
// A field added to frontmatter() without a matching entry in frontmatterKeys
// would still be written, still be read past, and silently stop being
// recoverable — which reads downstream as "this run had no sandbox", the one
// conclusion that must never be reached by accident.
func TestSandboxFrontmatterRoundTrips(t *testing.T) {
	want := SandboxRecord{
		ExecutorID:     "container-1",
		ExecutorKind:   "container",
		SpecHash:       "abc123",
		RequestedImage: "python:3.12",
		PinnedImage:    "python@sha256:deadbeef",
		SetupHash:      "setup999",
	}

	got, ok := ParseSandboxFrontmatter("---\n" + want.frontmatter() + "---\n\nbody\n")
	if !ok {
		t.Fatal("ParseSandboxFrontmatter refused frontmatter this package wrote")
	}
	if got.ExecutorID != want.ExecutorID || got.ExecutorKind != want.ExecutorKind ||
		got.SpecHash != want.SpecHash || got.RequestedImage != want.RequestedImage ||
		got.PinnedImage != want.PinnedImage || got.SetupHash != want.SetupHash {
		t.Errorf("round trip lost data:\n got %+v\nwant %+v", got, want)
	}
}

// TestSandboxFrontmatterEveryWrittenKeyIsRead walks the writer's output and
// asserts the reader knows every key in it.
//
// The round-trip test above would pass even if a new field were written and
// dropped, provided it happened to be the zero value in that fixture. This one
// cannot: it reads the writer's actual output.
func TestSandboxFrontmatterEveryWrittenKeyIsRead(t *testing.T) {
	full := SandboxRecord{
		ExecutorID: "e", ExecutorKind: "k", SpecHash: "s",
		RequestedImage: "r", PinnedImage: "p@sha256:x", SetupHash: "h",
	}
	// sandbox_reproducible is derived from PinnedImage rather than stored, so
	// it is written but deliberately not read back.
	derived := map[string]bool{"sandbox_reproducible": true}

	for _, line := range strings.Split(strings.TrimSpace(full.frontmatter()), "\n") {
		key, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if derived[key] {
			continue
		}
		if _, known := frontmatterKeys[key]; !known {
			t.Errorf("frontmatter() writes %q but frontmatterKeys cannot read it back — "+
				"add it to frontmatterKeys in sandbox.go", key)
		}
	}
}

func TestParseSandboxFrontmatterRejectsNonFrontmatter(t *testing.T) {
	for name, input := range map[string]string{
		"empty":           "",
		"no fence":        "executor_id: \"x\"\n",
		"fence not first": "hello\n---\nexecutor_id: \"x\"\n---\n",
		"no sandbox keys": "---\nid: 5\ntitle: \"t\"\n---\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := ParseSandboxFrontmatter(input); ok {
				t.Errorf("ParseSandboxFrontmatter(%q) = ok, want refused", input)
			}
		})
	}
}

// TestParseSandboxFrontmatterKeepsPartialBlock covers the reason this is a
// hand-rolled scan rather than a YAML decode: ReadTaskSandbox reads a bounded
// prefix, so the block can arrive cut in half.
func TestParseSandboxFrontmatterKeepsPartialBlock(t *testing.T) {
	partial := "---\nid: 7\nexecutor_id: \"remote-9\"\nexecutor_kind: \"remo"
	got, ok := ParseSandboxFrontmatter(partial)
	if !ok {
		t.Fatal("a truncated block yielded nothing; the keys before the cut should survive")
	}
	if got.ExecutorID != "remote-9" {
		t.Errorf("ExecutorID = %q, want remote-9", got.ExecutorID)
	}
}

// TestReadTaskSandboxFromWrittenArtifact exercises the whole durable path: the
// control plane writes a run record, WriteTaskArtifact stamps it into the
// artifact, and ReadTaskSandbox recovers it long afterwards.
func TestReadTaskSandboxFromWrittenArtifact(t *testing.T) {
	dir := t.TempDir()
	rec := SandboxRecord{
		ExecutorID:   "k8s-a",
		ExecutorKind: "kubernetes",
		SpecHash:     "spec-hash-1",
		PinnedImage:  "golang@sha256:abc",
		StartedAt:    time.Now(),
	}
	if _, err := WriteSandboxRun(dir, rec); err != nil {
		t.Fatalf("WriteSandboxRun: %v", err)
	}

	task := &pm.Task{ID: 42, Title: "Do the thing", Status: pm.TaskDone}
	path, err := WriteTaskArtifact(dir, task, "the agent said things\n")
	if err != nil {
		t.Fatalf("WriteTaskArtifact: %v", err)
	}
	task.ArtifactPath = path

	got, ok := ReadTaskSandbox(dir, task)
	if !ok {
		t.Fatal("ReadTaskSandbox found no stamp on an artifact written with one")
	}
	if got.ExecutorID != rec.ExecutorID || got.PinnedImage != rec.PinnedImage || got.SpecHash != rec.SpecHash {
		t.Errorf("recovered %+v, want executor %q / image %q / spec %q",
			got, rec.ExecutorID, rec.PinnedImage, rec.SpecHash)
	}
	if !got.Pinned() {
		t.Error("Pinned() = false for a digest-pinned image recovered from the artifact")
	}

	// The record the control plane wrote is per-run and gets overwritten; the
	// artifact stamp is the durable copy. Removing the former must not affect
	// the latter, which is the entire reason ReadTaskSandbox exists.
	if err := os.Remove(filepath.Join(dir, filepath.FromSlash(SandboxRunFile))); err != nil {
		t.Fatalf("remove run record: %v", err)
	}
	if _, ok := ReadTaskSandbox(dir, task); !ok {
		t.Error("the artifact stamp stopped resolving once .cloop/sandbox-run.json was gone — " +
			"ReadTaskSandbox must not depend on the per-run file")
	}
}

func TestReadTaskSandboxMissingArtifact(t *testing.T) {
	dir := t.TempDir()
	for name, task := range map[string]*pm.Task{
		"nil task":     nil,
		"no path":      {ID: 1},
		"missing file": {ID: 1, ArtifactPath: ".cloop/tasks/1-nope.md"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := ReadTaskSandbox(dir, task); ok {
				t.Error("ReadTaskSandbox = ok for a task with no readable artifact")
			}
		})
	}
}
