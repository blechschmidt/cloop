package planio

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestExport_AtomicWrite_NoPartialFileOnConcurrentReader verifies that Export
// uses an atomic rename: a reader that opens the destination path before/after
// the write must see either no file (ENOENT) or the fully complete file with
// a parseable schema_version — never an empty or partially written file.
//
// This pins down the conversion from os.WriteFile -> atomicfile.Write done in
// pkg/planio/planio.go.
func TestExport_AtomicWrite_NoPartialFileOnConcurrentReader(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	out := filepath.Join(dir, "plan.json")

	plan := &pm.Plan{
		Goal: "test",
		Tasks: []*pm.Task{
			{ID: 1, Title: "first", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "second", Priority: 2, Status: pm.TaskPending},
		},
	}

	if err := Export(plan, "json", out); err != nil {
		t.Fatalf("Export: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("destination file is empty — atomic rename did not complete")
	}

	var pf PlanFile
	if err := json.Unmarshal(data, &pf); err != nil {
		t.Fatalf("destination is not valid JSON (torn write?): %v\ncontent: %s", err, data)
	}
	if pf.SchemaVersion != schemaVersion {
		t.Fatalf("schema version: want %q, got %q", schemaVersion, pf.SchemaVersion)
	}
	if len(pf.Tasks) != 2 {
		t.Fatalf("task count: want 2, got %d", len(pf.Tasks))
	}
}

// TestExport_NoTmpFileLeftover ensures the atomicfile-staged ".tmp" sibling is
// renamed away (not left as cruft) on a successful write.
func TestExport_NoTmpFileLeftover(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	out := filepath.Join(dir, "plan.yaml")

	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskPending}}}
	if err := Export(plan, "yaml", out); err != nil {
		t.Fatalf("Export: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == "plan.yaml" {
			continue
		}
		t.Errorf("unexpected residual file in destination dir: %q", name)
	}
}
