package taskreplay

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// newStoreFixture initialises a project so migration 0028 runs and the
// reproductions table exists.
func newStoreFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := state.Init(dir, "goal", 10); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return dir
}

func sampleReproduction(taskID int, v Verdict) *Reproduction {
	return &Reproduction{
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		TaskID:    taskID,
		TaskTitle: "Do the thing",
		Verdict:   v,
		Reason:    "because " + string(v),
		Provenance: &Provenance{
			TaskID: taskID, Provider: "anthropic", Model: "claude-opus-4-8", Effort: "high",
			BaseSource: BaseRecorded, PromptSHA256: "abc123",
			Sandbox:  artifact.SandboxRecord{ExecutorID: "c1", PinnedImage: "go@sha256:x"},
			Warnings: []string{"a warning"},
		},
		Comparison: &Comparison{
			BaseSHA: "base1", OriginalCommit: "orig1", ReplayCommit: "repl1",
			OriginalTree: "tree1", ReplayTree: "tree2", BaseConfirmed: true,
			DiffStat: " main.go | 2 +-", DiffOfDiffs: "@@ -1 +1 @@\n-a\n+b\n",
			FilesDiffering: []string{"main.go"},
		},
		ExecutorID: "c1", ExecutorKind: "container", Isolation: "container",
		OriginalTest:  &TestOutcome{Ran: true, Passed: true, Framework: "go test"},
		ReplayTest:    &TestOutcome{Ran: true, Passed: false, ExitCode: 1, Framework: "go test"},
		AgentExitCode: 0,
		Duration:      3 * time.Second,
	}
}

func TestSaveAndGetReproduction(t *testing.T) {
	dir := newStoreFixture(t)

	want := sampleReproduction(7, VerdictDivergent)
	if err := SaveReproduction(dir, want); err != nil {
		t.Fatalf("SaveReproduction: %v", err)
	}
	if want.ID == 0 {
		t.Fatal("SaveReproduction did not set the row ID")
	}

	got, err := GetReproduction(dir, want.ID)
	if err != nil {
		t.Fatalf("GetReproduction: %v", err)
	}
	if got.Verdict != VerdictDivergent || got.Reason != want.Reason {
		t.Errorf("verdict/reason = %q/%q, want %q/%q", got.Verdict, got.Reason, want.Verdict, want.Reason)
	}
	if got.Comparison == nil || got.Comparison.OriginalTree != "tree1" || got.Comparison.ReplayTree != "tree2" {
		t.Errorf("comparison round trip lost the trees: %+v", got.Comparison)
	}
	if got.Comparison.Identical {
		t.Error("Identical was recomputed as true for two different tree hashes")
	}
	// The diff is the evidence for a DIVERGENT verdict; a Get must carry it.
	if !strings.Contains(got.Comparison.DiffOfDiffs, "+b") {
		t.Errorf("GetReproduction dropped the diff-of-diffs: %q", got.Comparison.DiffOfDiffs)
	}
	if got.Provenance == nil || got.Provenance.Model != "claude-opus-4-8" ||
		got.Provenance.BaseSource != BaseRecorded {
		t.Errorf("provenance round trip lost data: %+v", got.Provenance)
	}
	if got.ReplayTest == nil || got.ReplayTest.ExitCode != 1 || got.OriginalTest == nil || !got.OriginalTest.Passed {
		t.Errorf("test outcomes did not round trip: original=%+v replay=%+v",
			got.OriginalTest, got.ReplayTest)
	}
	if got.Duration != 3*time.Second {
		t.Errorf("duration = %v, want 3s", got.Duration)
	}
}

// TestListReproductionsDropsTheDiff pins the amplification bound: fifty rows
// each carrying up to a megabyte of patch is exactly the artifact-read blowup
// Task 20220 bounded everywhere else.
func TestListReproductionsDropsTheDiff(t *testing.T) {
	dir := newStoreFixture(t)
	for i := 0; i < 3; i++ {
		if err := SaveReproduction(dir, sampleReproduction(7, VerdictDivergent)); err != nil {
			t.Fatalf("SaveReproduction: %v", err)
		}
	}
	if err := SaveReproduction(dir, sampleReproduction(8, VerdictIdentical)); err != nil {
		t.Fatalf("SaveReproduction: %v", err)
	}

	list, err := ListReproductions(dir, 7, 0)
	if err != nil {
		t.Fatalf("ListReproductions: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d rows for task 7, want 3 (task 8's row must not be included)", len(list))
	}
	for _, r := range list {
		if r.Comparison != nil && r.Comparison.DiffOfDiffs != "" {
			t.Error("a list row carries its diff-of-diffs; only GetReproduction should")
		}
		if r.Comparison == nil || r.Comparison.DiffStat == "" {
			t.Error("the list dropped DiffStat, which is the summary the list is for")
		}
	}
	// Newest first.
	if list[0].ID < list[len(list)-1].ID {
		t.Error("ListReproductions returned oldest first")
	}

	all, err := ListReproductions(dir, 0, 0)
	if err != nil {
		t.Fatalf("ListReproductions(all): %v", err)
	}
	if len(all) != 4 {
		t.Errorf("taskID=0 returned %d rows, want all 4", len(all))
	}
}

func TestGetReproductionNotFound(t *testing.T) {
	_, err := GetReproduction(newStoreFixture(t), 999)
	if !errors.Is(err, ErrReproductionNotFound) {
		t.Errorf("err = %v, want ErrReproductionNotFound", err)
	}
}

func TestVerdictCounts(t *testing.T) {
	dir := newStoreFixture(t)
	for _, v := range []Verdict{VerdictIdentical, VerdictIdentical, VerdictDivergent} {
		if err := SaveReproduction(dir, sampleReproduction(1, v)); err != nil {
			t.Fatalf("SaveReproduction: %v", err)
		}
	}
	counts, err := VerdictCounts(dir)
	if err != nil {
		t.Fatalf("VerdictCounts: %v", err)
	}
	if counts[VerdictIdentical] != 2 || counts[VerdictDivergent] != 1 {
		t.Errorf("counts = %v, want 2 identical and 1 divergent", counts)
	}
	// Every verdict is present even at zero, so a dashboard renders a stable
	// set of columns rather than one that appears as results arrive.
	for _, v := range AllVerdicts {
		if _, ok := counts[v]; !ok {
			t.Errorf("VerdictCounts omitted %q", v)
		}
	}
}

// TestUnknownVerdictReadsBackAsInconclusive: a row written by a newer binary
// must never be counted as a reproducible result by an older one.
func TestUnknownVerdictReadsBackAsInconclusive(t *testing.T) {
	dir := newStoreFixture(t)
	rep := sampleReproduction(1, Verdict("from-the-future"))
	if err := SaveReproduction(dir, rep); err != nil {
		t.Fatalf("SaveReproduction: %v", err)
	}
	got, err := GetReproduction(dir, rep.ID)
	if err != nil {
		t.Fatalf("GetReproduction: %v", err)
	}
	if got.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive — an unrecognised verdict must fail safe", got.Verdict)
	}
	if got.Verdict.Reproducible() {
		t.Error("an unrecognised verdict was read back as supporting a reproducibility claim")
	}
}

func TestReadProvenanceRejectsUnknownTask(t *testing.T) {
	dir := newStoreFixture(t)
	if _, err := ReadProvenance(dir, 4242); err == nil {
		t.Error("ReadProvenance accepted a task that does not exist")
	}
}

// TestReadProvenanceWithoutACommit covers the majority case on a hub that has
// not adopted isolated executors: a task whose work went into the working tree
// has nothing to reproduce against, and that must be a named condition rather
// than a generic failure.
func TestReadProvenanceWithoutACommit(t *testing.T) {
	dir := newStoreFixture(t)
	s, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	s.Plan = &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 1, Title: "local run", Status: pm.TaskDone}}}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	prov, err := ReadProvenance(dir, 1)
	if !errors.Is(err, ErrNoRecordedCommit) {
		t.Fatalf("err = %v, want ErrNoRecordedCommit", err)
	}
	if prov == nil {
		t.Fatal("ReadProvenance returned no provenance alongside ErrNoRecordedCommit; " +
			"the UI needs what was recovered in order to explain why the button is disabled")
	}
	if prov.Reproducible() {
		t.Error("a task with no commit reported itself reproducible")
	}
	if prov.Prompt == "" || prov.PromptSHA256 == "" {
		t.Error("the prompt was not reconstructed; it is recoverable without a commit")
	}
}
