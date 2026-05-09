package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSaveReport_AtomicNoTmpResidue pins down that SaveReport produces a
// complete, parseable markdown file with no .tmp staging residue alongside
// it. A regression here would mean a power loss mid-write could leave a
// truncated bench report at the user-visible path or stale .tmp files
// accumulating in .cloop/bench-results/.
func TestSaveReport_AtomicNoTmpResidue(t *testing.T) {
	workDir := t.TempDir()

	r := &Report{
		Timestamp: time.Date(2026, 5, 9, 12, 34, 56, 0, time.UTC),
		Prompt:    "What is 2+2?",
		Runs:      1,
		Results: []*ProviderResult{
			{
				ProviderName:    "anthropic",
				Model:           "claude-opus-4-7",
				AvgLatencyMS:    1234.5,
				AvgInputTokens:  10,
				AvgOutputTokens: 20,
				TotalCostUSD:    0.001,
				SuccessfulRuns:  1,
			},
		},
	}

	path, err := SaveReport(workDir, r)
	if err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(got), "anthropic") {
		t.Fatalf("report missing provider row; got:\n%s", got)
	}
	if !strings.Contains(string(got), "claude-opus-4-7") {
		t.Fatalf("report missing model name; got:\n%s", got)
	}

	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("atomicfile staging residue left behind: %s", e.Name())
		}
	}
}
