package snapshot

// Feature worktrees live in .cloop/features (Task 20341). They are source
// checkouts of the project with work of their own, not the project's control
// state, so a snapshot must neither archive them — every snapshot would carry
// a full copy of the tree per feature — nor, on restore, delete or overwrite
// them: a restore would otherwise take uncommitted feature work with it.

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func archiveNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
}

func TestSnapshotLeavesFeatureWorktreesAlone(t *testing.T) {
	work := t.TempDir()
	cloop := filepath.Join(work, ".cloop")
	writeFile(t, filepath.Join(cloop, "config.yaml"), "provider: mock\n")
	feat := filepath.Join(cloop, "features", "login")
	writeFile(t, filepath.Join(feat, "main.go"), "package main // committed\n")
	writeFile(t, filepath.Join(feat, "wip.go"), "package main // not committed yet\n")

	meta, err := Save(work, "before")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	for _, n := range archiveNames(t, filepath.Join(snapshotsPath(work), meta.ID+".tar.gz")) {
		if strings.Contains(n, "features") {
			t.Errorf("the snapshot archived %s — a feature worktree is not project state", n)
		}
	}

	// Work continues in the feature after the snapshot…
	writeFile(t, filepath.Join(feat, "wip.go"), "package main // more work\n")
	writeFile(t, filepath.Join(cloop, "config.yaml"), "provider: changed\n")

	// …and a restore brings back the project's state without touching it.
	if err := Restore(work, meta.ID); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(cloop, "config.yaml")); string(b) != "provider: mock\n" {
		t.Errorf("config.yaml not restored: %q", b)
	}
	if b, err := os.ReadFile(filepath.Join(feat, "wip.go")); err != nil || string(b) != "package main // more work\n" {
		t.Errorf("the restore touched the feature's uncommitted work: %q, %v", b, err)
	}
}

// TestRestoreOfAnOlderArchiveKeepsLiveFeatures covers archives written before
// features were excluded: one that contains .cloop/features must not copy it
// over the worktrees that exist now.
func TestRestoreOfAnOlderArchiveKeepsLiveFeatures(t *testing.T) {
	work := t.TempDir()
	cloop := filepath.Join(work, ".cloop")
	writeFile(t, filepath.Join(cloop, "config.yaml"), "provider: mock\n")
	writeFile(t, filepath.Join(cloop, "features", "login", "wip.go"), "stale\n")
	// An archive that includes features, as the old writer produced.
	if err := os.MkdirAll(snapshotsPath(work), 0o750); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(snapshotsPath(work), "20260101-000000-old.tar.gz")
	if err := writeArchiveIncludingEverything(old, cloop); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(cloop, "features", "login", "wip.go"), "current\n")

	if err := Restore(work, "20260101-000000-old"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(cloop, "features", "login", "wip.go")); string(b) != "current\n" {
		t.Errorf("restoring an old archive overwrote a live feature: %q", b)
	}
}

// writeArchiveIncludingEverything writes src the way writeArchive did before
// it learned to skip features.
func writeArchiveIncludingEverything(dest, src string) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(filepath.Dir(src), path)
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = rel
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
}
