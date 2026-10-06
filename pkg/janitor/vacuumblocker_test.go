package janitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/diskusage"
)

// TestVacuumBlockerIsThePassesDecision: whether a pass inside the hub rewrites
// the database — the thresholds, the in-process size ceiling and the room for
// the rebuild — is one function, so `cloop hub doctor` cannot promise a VACUUM
// the ceiling skips every pass (Task 20387).
func TestVacuumBlockerIsThePassesDecision(t *testing.T) {
	pol := DefaultPolicy()
	pol.VacuumFreeRatio, pol.VacuumMinFreeBytes, pol.VacuumMaxInlineBytes = 0.25, 64<<20, 1<<30

	worth := &diskusage.Usage{DBBytes: 3 << 30, ReclaimableBytes: 1200 << 20, FreeRatio: 0.4}
	if got := VacuumBlocker(pol, worth, false, 100<<30); got != "" {
		t.Errorf("out of process, with room: blocked by %q", got)
	}
	if got := VacuumBlocker(pol, worth, true, 100<<30); !strings.Contains(got, "in-process limit") {
		t.Errorf("inside the hub, 1.8 GiB live exceeds the 1 GiB ceiling; got %q", got)
	}
	if got := VacuumBlocker(pol, worth, false, 1<<30); !strings.Contains(got, "needs about") {
		t.Errorf("1 GiB free cannot hold a rebuild of 1.8 GiB live; got %q", got)
	}
	if got := VacuumBlocker(pol, worth, false, -1); got != "" {
		t.Errorf("unmeasured free space is not a full disk; got %q", got)
	}
	small := &diskusage.Usage{DBBytes: 100 << 20, ReclaimableBytes: 10 << 20, FreeRatio: 0.1}
	if got := VacuumBlocker(pol, small, true, 100<<30); got == "" {
		t.Error("10 MB reclaimable is under the floor")
	}
}

// TestArchiveSealsMeasuresTheDirectoryPruned: audit.export_dir moves the
// archive the janitor prunes, so the measure goes with it — and counts seals,
// not an operator's notes beside them.
func TestArchiveSealsMeasuresTheDirectoryPruned(t *testing.T) {
	export := t.TempDir()
	for name, size := range map[string]int{
		"audit-1-100-20261001T000000Z.jsonl.gz": 300,
		"audit-101-200-20261002T000000Z.jsonl":  200,
		"NOTES.txt":                             50,
	} {
		if err := os.WriteFile(filepath.Join(export, name), make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pol := DefaultPolicy()
	pol.ArchiveDir = export
	dir, bytes, seals, err := ArchiveSeals(t.TempDir(), pol)
	if err != nil || dir != export || bytes != 500 || seals != 2 {
		t.Errorf("ArchiveSeals = %q, %d bytes, %d seals, %v; want %q, 500, 2", dir, bytes, seals, err, export)
	}
}
