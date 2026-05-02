// Package snapshot implements atomic full-project backup and restore for the
// .cloop directory. Snapshots are stored as gzip-compressed tar archives in
// .cloop/snapshots/ and can be created, listed, restored, and deleted via the
// cloop snapshot subcommands.
package snapshot

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const snapshotsDir = "snapshots"

// Meta holds the parsed metadata for a single snapshot.
type Meta struct {
	ID        string    // base filename without .tar.gz
	Name      string    // user-supplied label (may be empty)
	CreatedAt time.Time // parsed from the timestamp portion of the filename
	Size      int64     // compressed file size in bytes
	Path      string    // absolute path to the archive
}

// filenameRE matches <YYYYMMDD-HHmmss>[-<slug>].tar.gz
var filenameRE = regexp.MustCompile(`^(\d{8}-\d{6})(?:-(.+))?\.tar\.gz$`)

// snapshotsPath returns the absolute path to the snapshots directory.
func snapshotsPath(workDir string) string {
	return filepath.Join(workDir, ".cloop", snapshotsDir)
}

// clootDir returns the absolute path to the .cloop directory.
func cloopDir(workDir string) string {
	return filepath.Join(workDir, ".cloop")
}

// Save creates a new snapshot of the .cloop directory.
// name is an optional human-readable label; if empty the snapshot gets a
// timestamp-only ID.  The snapshot excludes the snapshots/ subdirectory
// itself to avoid recursive growth.
func Save(workDir, name string) (Meta, error) {
	ts := time.Now()

	// Build filename / ID.
	slug := ts.Format("20060102-150405")
	id := slug
	if name != "" {
		// Sanitize: replace spaces and forbidden chars with hyphens.
		safe := sanitize(name)
		if safe != "" {
			id = slug + "-" + safe
		}
	}
	filename := id + ".tar.gz"

	snapDir := snapshotsPath(workDir)
	if err := os.MkdirAll(snapDir, 0o750); err != nil {
		return Meta{}, fmt.Errorf("create snapshots dir: %w", err)
	}

	destPath := filepath.Join(snapDir, filename)
	// Write atomically: write to a temp file then rename.
	tmpPath := destPath + ".tmp"
	if err := writeArchive(tmpPath, cloopDir(workDir), snapDir); err != nil {
		_ = os.Remove(tmpPath)
		return Meta{}, err
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return Meta{}, fmt.Errorf("finalize snapshot: %w", err)
	}

	fi, err := os.Stat(destPath)
	if err != nil {
		return Meta{}, fmt.Errorf("stat snapshot: %w", err)
	}

	return Meta{
		ID:        id,
		Name:      name,
		CreatedAt: ts,
		Size:      fi.Size(),
		Path:      destPath,
	}, nil
}

// List returns all snapshots in the snapshots directory, sorted oldest first.
func List(workDir string) ([]Meta, error) {
	snapDir := snapshotsPath(workDir)
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read snapshots dir: %w", err)
	}

	var metas []Meta
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m, ok := parseMeta(e.Name())
		if !ok {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		m.Size = fi.Size()
		m.Path = filepath.Join(snapDir, e.Name())
		metas = append(metas, m)
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].CreatedAt.Before(metas[j].CreatedAt)
	})
	return metas, nil
}

// Restore extracts the snapshot identified by id and replaces the contents of
// the .cloop directory, preserving the snapshots/ subdirectory.
func Restore(workDir, id string) error {
	snapDir := snapshotsPath(workDir)
	archivePath := filepath.Join(snapDir, id+".tar.gz")

	if _, err := os.Stat(archivePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("snapshot %q not found", id)
		}
		return fmt.Errorf("stat snapshot: %w", err)
	}

	dst := cloopDir(workDir)

	// Extract to a temporary staging directory beside .cloop.
	stageDir := dst + ".snap-restore-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := os.MkdirAll(stageDir, 0o750); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(stageDir)

	if err := extractArchive(archivePath, stageDir); err != nil {
		return fmt.Errorf("extract snapshot: %w", err)
	}

	// The archive stores files under a top-level ".cloop/" directory.
	// Find what was extracted.
	stagedCloop := filepath.Join(stageDir, ".cloop")
	if _, err := os.Stat(stagedCloop); err != nil {
		// Some archives may not have the .cloop prefix; use stageDir directly.
		stagedCloop = stageDir
	}

	// Remove everything in .cloop except the snapshots/ subdirectory.
	entries, err := os.ReadDir(dst)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read .cloop: %w", err)
	}
	for _, e := range entries {
		if e.Name() == snapshotsDir {
			continue // preserve existing snapshots
		}
		if err := os.RemoveAll(filepath.Join(dst, e.Name())); err != nil {
			return fmt.Errorf("remove %s: %w", e.Name(), err)
		}
	}

	// Copy staged files into .cloop, skipping the snapshots/ dir from the archive.
	if err := copyDir(stagedCloop, dst); err != nil {
		return fmt.Errorf("copy restored files: %w", err)
	}

	return nil
}

// Delete removes the snapshot with the given id.
func Delete(workDir, id string) error {
	snapDir := snapshotsPath(workDir)
	archivePath := filepath.Join(snapDir, id+".tar.gz")

	if err := os.Remove(archivePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("snapshot %q not found", id)
		}
		return fmt.Errorf("delete snapshot: %w", err)
	}
	return nil
}

// FindByPrefix resolves a potentially abbreviated id prefix (or exact id) to
// a full Meta. Returns an error if zero or more than one match.
func FindByPrefix(workDir, prefix string) (Meta, error) {
	metas, err := List(workDir)
	if err != nil {
		return Meta{}, err
	}
	var matches []Meta
	for _, m := range metas {
		if m.ID == prefix || strings.HasPrefix(m.ID, prefix) {
			matches = append(matches, m)
		}
	}
	switch len(matches) {
	case 0:
		return Meta{}, fmt.Errorf("no snapshot matching %q", prefix)
	case 1:
		return matches[0], nil
	default:
		return Meta{}, fmt.Errorf("ambiguous prefix %q matches %d snapshots", prefix, len(matches))
	}
}

// ─── internal helpers ────────────────────────────────────────────────────────

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-_")
}

func parseMeta(filename string) (Meta, bool) {
	m := filenameRE.FindStringSubmatch(filename)
	if m == nil {
		return Meta{}, false
	}
	ts, err := time.ParseInLocation("20060102-150405", m[1], time.Local)
	if err != nil {
		return Meta{}, false
	}
	id := m[1]
	name := m[2]
	if name != "" {
		id = m[1] + "-" + name
	}
	return Meta{
		ID:        id,
		Name:      name,
		CreatedAt: ts,
	}, true
}

// writeArchive creates a gzip-compressed tar of srcDir, excluding excludeDir.
// All entries are stored under a top-level ".cloop/" prefix.
func writeArchive(destPath, srcDir, excludeDir string) error {
	// Normalize excludeDir to an absolute path for comparison.
	absExclude, err := filepath.Abs(excludeDir)
	if err != nil {
		return err
	}
	absSrc, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.Walk(absSrc, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}

		// Skip the snapshots directory to avoid recursive bloat.
		if absPath == absExclude {
			return filepath.SkipDir
		}

		// Compute the in-archive name relative to srcDir's parent, prefixed
		// with ".cloop/".
		rel, err := filepath.Rel(filepath.Dir(absSrc), absPath)
		if err != nil {
			return err
		}
		// Ensure forward slashes in archive.
		archiveName := filepath.ToSlash(rel)

		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return fmt.Errorf("tar header for %s: %w", path, err)
		}
		hdr.Name = archiveName
		if fi.IsDir() {
			hdr.Name += "/"
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header: %w", err)
		}
		if fi.IsDir() {
			return nil
		}

		// Regular file: copy contents.
		src, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer src.Close()
		if _, err := io.Copy(tw, src); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		return nil
	})
}

// extractArchive extracts a gzip-compressed tar into destDir.
func extractArchive(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Security: reject absolute paths and path traversal.
		if filepath.IsAbs(hdr.Name) || strings.Contains(hdr.Name, "..") {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}

		target := filepath.Join(destDir, filepath.FromSlash(hdr.Name))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)|0o700); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", target, err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)|0o600)
			if err != nil {
				return fmt.Errorf("create %s: %w", target, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("write %s: %w", target, err)
			}
			out.Close()
		}
	}
	return nil
}

// copyDir recursively copies files from src to dst, skipping the snapshots/
// subdirectory.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Skip snapshots/ if somehow present in the archive.
		if rel == snapshotsDir || strings.HasPrefix(rel, snapshotsDir+string(os.PathSeparator)) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, fi.Mode()|0o700)
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()

		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode()|0o600)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		return err
	})
}
