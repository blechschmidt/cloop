package diskusage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// writeFile creates a file of the given size beneath .cloop.
func writeFile(t *testing.T, workDir, rel string, sizeKB int) {
	t.Helper()
	path := filepath.Join(workDir, ".cloop", rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", sizeKB*1024)), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestMeasureFiles_BreaksDownByEntry is the point of the package: naming which
// directory is the problem, not just how big .cloop is in total.
func TestMeasureFiles_BreaksDownByEntry(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "plan-history/a.json", 40)
	writeFile(t, dir, "plan-history/b.json", 40)
	writeFile(t, dir, "audit-archive/seal.jsonl.gz", 10)
	writeFile(t, dir, "state.db", 5)

	u, err := MeasureFiles(dir)
	if err != nil {
		t.Fatalf("MeasureFiles: %v", err)
	}

	if want := int64((40 + 40 + 10 + 5) * 1024); u.TotalBytes != want {
		t.Errorf("TotalBytes = %d, want %d", u.TotalBytes, want)
	}
	// Largest first, so a caller rendering the top N shows the culprit.
	if len(u.Entries) == 0 || u.Entries[0].Name != "plan-history" {
		t.Fatalf("entries not sorted largest-first: %+v", u.Entries)
	}
	if got := u.Entries[0].Files; got != 2 {
		t.Errorf("plan-history reported %d files, want 2", got)
	}
	if !u.Entries[0].IsDir {
		t.Error("plan-history not reported as a directory")
	}
	if u.DBBytes != 5*1024 {
		t.Errorf("DBBytes = %d, want %d", u.DBBytes, 5*1024)
	}
	// A top-level file is an entry in its own right; state.db and its WAL are
	// the two biggest single files on a busy hub.
	if e, ok := u.Entry("state.db"); !ok || e.IsDir || e.Files != 1 {
		t.Errorf("state.db entry = %+v, ok=%v", e, ok)
	}
}

// TestMeasureFiles_MissingDirIsNotAnError: a project that has never run has no
// .cloop, and reporting that as a failure would break every caller's panel.
func TestMeasureFiles_MissingDirIsNotAnError(t *testing.T) {
	u, err := MeasureFiles(t.TempDir())
	if err != nil {
		t.Fatalf("MeasureFiles on a fresh directory: %v", err)
	}
	if u.TotalBytes != 0 || len(u.Entries) != 0 {
		t.Errorf("expected an empty measurement, got %+v", u)
	}
}

// TestMeasure_ReportsFreelist is the number no filesystem tool provides: the
// pages a database holds but no longer uses.
func TestMeasure_ReportsFreelist(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	u, err := Measure(dir)
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if u.DBError != "" {
		t.Fatalf("DBError = %q, want the database to be readable", u.DBError)
	}
	if u.DBBytes <= 0 {
		t.Errorf("DBBytes = %d, want a positive size", u.DBBytes)
	}
	if u.FreeRatio < 0 || u.FreeRatio > 1 {
		t.Errorf("FreeRatio = %v, want a fraction in [0,1]", u.FreeRatio)
	}
}

// TestMeasure_MissingDBIsNotAnError: a project with files but no database yet
// still reports its disk usage, and says nothing about a database error.
func TestMeasure_MissingDBIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "plan-history/a.json", 4)

	u, err := Measure(dir)
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if u.DBError != "" {
		t.Errorf("DBError = %q for a project with no database; absence is not an error", u.DBError)
	}
	if u.TotalBytes == 0 {
		t.Error("file usage was not reported")
	}
}

// TestFreeBytes_ReportsSomething guards the syscall wiring — principally the
// Bsize conversion, which differs in type between Linux and Darwin.
func TestFreeBytes_ReportsSomething(t *testing.T) {
	n, err := FreeBytes(t.TempDir())
	if err != nil {
		t.Fatalf("FreeBytes: %v", err)
	}
	if n < 0 {
		t.Fatalf("FreeBytes = %d, want a non-negative size", n)
	}
}

func TestFreeBytes_MissingPathErrors(t *testing.T) {
	if _, err := FreeBytes(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("FreeBytes on a missing path returned no error")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512 B"},
		{2048, "2.0 KB"},
		{5 << 20, "5.0 MB"},
		{2300 << 20, "2.25 GB"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.in); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
