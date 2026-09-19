package projectseed

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// sampleState is a project with the fields a sandbox actually runs on, plus
// the two that must not travel (Steps, WorkDir).
func sampleState(t *testing.T) *state.ProjectState {
	t.Helper()
	return &state.ProjectState{
		Goal:         "ship the thing",
		WorkDir:      "/hub/only/projects/demo",
		Instructions: "be careful",
		Provider:     "claudecode",
		Model:        "claude-opus-5",
		Effort:       "max",
		AutoEvolve:   true,
		InnovateMode: true,
		Parallel:     true,
		MaxParallel:  4,
		MaxSteps:     50,
		Status:       "running",
		CreatedAt:    time.Now().Add(-time.Hour).UTC(),
		UpdatedAt:    time.Now().UTC(),
		Plan: &pm.Plan{
			Goal: "ship the thing",
			Tasks: []*pm.Task{
				{ID: 1, Title: "first", Description: "do the first bit", Priority: 1, Status: pm.TaskDone},
				{ID: 2, Title: "second", Description: "do the second bit", Priority: 2, Status: pm.TaskPending},
			},
		},
		Steps: []state.StepResult{
			{Step: 1, Output: strings.Repeat("transcript ", 4096)},
		},
	}
}

// TestSeedRoundTripsThroughStateLoad is the end-to-end claim this package
// exists to make: bytes built on the hub, written into a directory that is
// otherwise an ordinary git checkout, become a project that `cloop run` can
// load — with no cloop project having been there beforehand.
//
// It drives the real state.Load rather than the legacy decoder directly,
// because the whole design bet is that the existing state.json migration is the
// import path. A test that bypassed it would pass even if that bet were wrong.
func TestSeedRoundTripsThroughStateLoad(t *testing.T) {
	seed, err := Build(sampleState(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A bare directory: exactly what a fresh git clone of a repository with no
	// .cloop/ committed looks like to the harness.
	sandbox := t.TempDir()
	if _, err := state.Load(sandbox); err == nil {
		t.Fatal("precondition: an empty directory must not load as a project")
	}

	if err := Write(sandbox, seed); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := state.Load(sandbox)
	if err != nil {
		t.Fatalf("state.Load after seeding: %v", err)
	}

	if got.Goal != "ship the thing" {
		t.Errorf("Goal = %q, want %q", got.Goal, "ship the thing")
	}
	if got.Instructions != "be careful" {
		t.Errorf("Instructions = %q", got.Instructions)
	}
	if got.Provider != "claudecode" || got.Model != "claude-opus-5" {
		t.Errorf("provider/model = %q/%q", got.Provider, got.Model)
	}
	// Effort was absent from the legacy decoder until this task; without that
	// fix a seeded sandbox would silently run at the provider default.
	if got.Effort != "max" {
		t.Errorf("Effort = %q, want %q — legacyState is missing the field again", got.Effort, "max")
	}
	if !got.AutoEvolve || !got.InnovateMode || !got.Parallel || got.MaxParallel != 4 {
		t.Errorf("run options lost: autoEvolve=%v innovate=%v parallel=%v maxParallel=%d",
			got.AutoEvolve, got.InnovateMode, got.Parallel, got.MaxParallel)
	}
	if got.Plan == nil || len(got.Plan.Tasks) != 2 {
		t.Fatalf("plan did not survive: %+v", got.Plan)
	}
	if got.Plan.Tasks[0].Title != "first" || got.Plan.Tasks[1].Status != pm.TaskPending {
		t.Errorf("tasks garbled: %+v, %+v", got.Plan.Tasks[0], got.Plan.Tasks[1])
	}

	// The trap from pkg/state: WorkDir is what Save writes back through, so a
	// seed carrying the hub's path would aim the sandbox's writes at a
	// directory on another machine.
	if got.WorkDir != sandbox {
		t.Errorf("WorkDir = %q, want the sandbox's own %q", got.WorkDir, sandbox)
	}
	if len(got.Steps) != 0 {
		t.Errorf("seed carried %d steps; a seed must carry none", len(got.Steps))
	}
}

// TestWriteSupersedesAStaleDatabase covers the reused-workspace bug the seed
// fixes as a side effect. An edge device that keeps its work directory between
// dispatches still holds the previous run's state.db; without the seed winning,
// the second dispatch reads stale state and reports every task already
// complete without running anything.
func TestWriteSupersedesAStaleDatabase(t *testing.T) {
	sandbox := t.TempDir()

	stale := sampleState(t)
	stale.Goal = "the previous dispatch"
	stale.Plan.Tasks = []*pm.Task{{ID: 1, Title: "already done", Status: pm.TaskDone}}
	staleSeed, err := Build(stale)
	if err != nil {
		t.Fatalf("Build stale: %v", err)
	}
	if err := Write(sandbox, staleSeed); err != nil {
		t.Fatalf("Write stale: %v", err)
	}
	if _, err := state.Load(sandbox); err != nil { // materialises state.db
		t.Fatalf("load stale: %v", err)
	}

	// The migration's freshness test is mtime-based and this test can run well
	// inside one filesystem timestamp tick, so make the database
	// unambiguously older rather than sleeping.
	db := filepath.Join(sandbox, ".cloop", "state.db")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(db, old, old); err != nil {
		t.Fatalf("age the database: %v", err)
	}

	fresh := sampleState(t)
	fresh.Goal = "the new dispatch"
	fresh.Plan.Tasks = []*pm.Task{{ID: 1, Title: "actually pending", Status: pm.TaskPending}}
	freshSeed, err := Build(fresh)
	if err != nil {
		t.Fatalf("Build fresh: %v", err)
	}
	if err := Write(sandbox, freshSeed); err != nil {
		t.Fatalf("Write fresh: %v", err)
	}

	got, err := state.Load(sandbox)
	if err != nil {
		t.Fatalf("load fresh: %v", err)
	}
	if got.Goal != "the new dispatch" {
		t.Errorf("Goal = %q; the stale database won over a newer seed", got.Goal)
	}
	if got.Plan == nil || len(got.Plan.Tasks) != 1 || got.Plan.Tasks[0].Status != pm.TaskPending {
		t.Errorf("stale plan survived: %+v", got.Plan)
	}
}

// TestBuildDropsStepHistory pins the size decision: step output is the bulk of
// a long-running project and none of it is any use to a sandbox.
func TestBuildDropsStepHistory(t *testing.T) {
	st := sampleState(t)
	seed, err := Build(st)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw := inflateForTest(t, seed)

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("seed is not a JSON object: %v", err)
	}
	var steps []json.RawMessage
	if err := json.Unmarshal(decoded["steps"], &steps); err != nil {
		t.Fatalf("decode steps: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("seed carries %d steps", len(steps))
	}
	if bytes.Contains(raw, []byte("transcript transcript")) {
		t.Error("step output reached the seed")
	}

	// The caller's state is very often the live one a handler still holds.
	if len(st.Steps) != 1 || st.WorkDir == "" {
		t.Error("Build mutated its argument")
	}
}

// TestBuildClearsHubOnlyRunState keeps the hub's own run status out of a
// sandbox that is about to start its own.
func TestBuildClearsHubOnlyRunState(t *testing.T) {
	seed, err := Build(sampleState(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var decoded struct {
		Status  string `json:"status"`
		WorkDir string `json:"workdir"`
		PMMode  bool   `json:"pm_mode"`
	}
	if err := json.Unmarshal(inflateForTest(t, seed), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Status != "" {
		t.Errorf("Status = %q, want empty", decoded.Status)
	}
	if decoded.WorkDir != "" {
		t.Errorf("WorkDir = %q, want empty", decoded.WorkDir)
	}
	if !decoded.PMMode {
		t.Error("PMMode should be stated true in a seed")
	}
}

func TestBuildRejectsNilState(t *testing.T) {
	if _, err := Build(nil); !errors.Is(err, ErrNoProject) {
		t.Fatalf("Build(nil) = %v, want ErrNoProject", err)
	}
}

// TestWriteAlwaysLandsAtTheSamePath is the security property: a seed names no
// destination, so nothing inside it can steer the write.
func TestWriteAlwaysLandsAtTheSamePath(t *testing.T) {
	dir := t.TempDir()
	seed, err := Build(sampleState(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := Write(dir, seed); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, ".cloop", "state.json"))
	if err != nil {
		t.Fatalf("seed did not land at .cloop/state.json: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("seed mode = %04o, want 0600", perm)
	}
	// Nothing else was created beside it.
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf(".cloop holds %v, want only state.json (a temp file leaked)", names)
	}
}

func TestWriteEmptySeedIsANoOp(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, nil); err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop")); !os.IsNotExist(err) {
		t.Error("an empty seed created .cloop/")
	}
}

func TestWriteRejectsMalformedSeeds(t *testing.T) {
	cases := []struct {
		name string
		seed []byte
		want string
	}{
		{"not gzip", []byte("{\"goal\":\"x\"}"), "not gzip-compressed"},
		{"gzip of non-JSON", gzipBytes(t, []byte("not json at all")), "not a JSON object"},
		{"gzip of a JSON array", gzipBytes(t, []byte(`["goal"]`)), "not a JSON object"},
		{"truncated gzip", gzipBytes(t, []byte(`{"goal":"x"}`))[:6], "read seed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			err := Write(dir, tc.seed)
			if err == nil {
				t.Fatal("Write accepted a malformed seed")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
			if _, statErr := os.Stat(filepath.Join(dir, ".cloop", "state.json")); statErr == nil {
				t.Error("a malformed seed still reached the filesystem")
			}
		})
	}
}

// TestWriteRefusesADecompressionBomb: the compressed cap is not a bound on what
// lands on an edge device's disk, so the inflated size has its own.
func TestWriteRefusesADecompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	// A JSON object whose padding inflates far past the ceiling but whose
	// compressed form is trivially small.
	zw.Write([]byte(`{"goal":"`))
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for written := 0; written <= MaxDecompressedBytes; written += len(chunk) {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatalf("compress: %v", err)
		}
	}
	zw.Write([]byte(`"}`))
	if err := zw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if buf.Len() > executor.MaxProjectSeedBytes {
		t.Fatalf("precondition: the bomb is %d compressed bytes, which the wire cap would "+
			"already have caught", buf.Len())
	}

	err := Write(t.TempDir(), buf.Bytes())
	if err == nil {
		t.Fatal("Write accepted a decompression bomb")
	}
	if !strings.Contains(err.Error(), "inflates past") {
		t.Errorf("error = %q, want it to name the inflated ceiling", err)
	}
}

func TestWriteRejectsAnOversizedSeed(t *testing.T) {
	err := Write(t.TempDir(), append([]byte{0x1f, 0x8b},
		bytes.Repeat([]byte{0}, executor.MaxProjectSeedBytes)...))
	if err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("Write of an oversized seed = %v, want a ceiling error", err)
	}
}

func inflateForTest(t *testing.T, seed []byte) []byte {
	t.Helper()
	raw, err := inflate(seed)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	return raw
}

func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
