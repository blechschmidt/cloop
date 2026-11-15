package projectmove

// pack.go captures, delivers and checks the files under a project's .cloop
// directory that no database holds (Task 20494).
//
// Only the project's own work travels: what its runs wrote (artifacts, task
// output, the attachment outbox, checkpoints) and its specs (sandbox.yaml,
// requirements.yaml). The rest stays in the hub's copy of the project, which a
// move never removes, and is recorded as kept: config.yaml can hold API keys,
// which a seed never carries either; the attachment store is the hub's,
// served from its database; and anything else under .cloop — a hub's own
// keys when the project directory is also the hub's — is nothing a target
// should receive.

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
)

// deliveredCategories are the .cloop file categories a move takes to the
// target.
var deliveredCategories = map[string]bool{
	FilesArtifacts:        true,
	FilesAttachmentOutbox: true,
	FilesCheckpoints:      true,
	FilesSandboxSpec:      true,
	FilesRequirementsSpec: true,
}

// keptReasons say why a category stays on the hub.
var keptReasons = map[string]string{
	FilesAttachments: "the attachment store is the hub's: its database holds the records and the dashboard serves the files from here",
	FilesConfig:      "the project's configuration can hold API keys, which never leave the hub; runs on the target get their provider and model with the project's state",
	FilesOther:       "files under .cloop that are not the project's work stay with the hub's copy of the project",
}

// notPacked are entries directly under .cloop a move never reads: the move
// store itself (a project directory may be the hub's own) and the disk
// reserve, which is placeholder blocks, not data.
var notPacked = map[string]bool{
	"moves":   true,
	"reserve": true,
}

// ErrFilesTooLarge refuses .cloop files over the move's bound.
var ErrFilesTooLarge = errors.New("projectmove: the project's .cloop files are larger than the move allows")

// tarEpoch stamps every tar entry, so the same files make the same tar.
var tarEpoch = time.Unix(0, 0).UTC()

// PackFiles writes the .cloop files of projectDir a move delivers into a tar
// at tarPath, at most maxBytes of file content (zero: no bound). It returns
// them with their digests, the categories kept on the hub, and the tar's
// digest. Nothing is followed through a symbolic link, and a file that is not
// regular is not packed.
func PackFiles(projectDir, tarPath string, maxBytes int64) ([]File, []Item, movegit.Digest, error) {
	dir := filepath.Join(projectDir, ".cloop")
	root, err := os.OpenRoot(projectDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		root = nil
	case err != nil:
		return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: %w", err)
	default:
		defer root.Close()
	}
	return PackFilesIn(root, dir, tarPath, maxBytes)
}

// PackFilesIn is PackFiles for the project whose directory root opens; dir is
// how the result names its .cloop directory. Every name goes through root, and
// each file is opened only once its own entry is known to be a regular file —
// and checked to be that same file once open — so a link planted beside it, or
// swapped in for it, is never read: how a device packs a working copy a
// workload wrote (Task 20495). A nil root packs nothing.
func PackFilesIn(root *os.Root, dir, tarPath string, maxBytes int64) ([]File, []Item, movegit.Digest, error) {
	return PackFileSets(tarPath, maxBytes, FileSet{Root: root, Dir: dir})
}

// FileSet is one .cloop directory PackFileSets packs.
type FileSet struct {
	// Root opens the directory that holds the .cloop directory; nil packs
	// nothing.
	Root *os.Root
	// Dir is how the result names the .cloop directory.
	Dir string
	// Prefix goes before each file's path in the tar and the result: empty
	// for the project's own files, features/<slug>/.cloop/ for a feature's
	// kept beside the project's (a device keeps each feature's working copy
	// in a directory of its own), so they land in the feature's .cloop under
	// the project's.
	Prefix string
}

// PackFileSets is PackFilesIn for several .cloop directories in one tar, each
// under its prefix; maxBytes bounds them together.
func PackFileSets(tarPath string, maxBytes int64, sets ...FileSet) ([]File, []Item, movegit.Digest, error) {
	type entry struct {
		set int
		rel string
	}
	var (
		files   []File
		entries []entry
	)
	kept := map[string]*Item{}
	for i, set := range sets {
		if set.Prefix != "" && (!cleanRel(strings.TrimSuffix(set.Prefix, "/")) || !strings.HasSuffix(set.Prefix, "/")) {
			return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: %q is not a plain relative prefix", set.Prefix)
		}
		keep := func(category, rel string, size int64) {
			it := kept[category]
			if it == nil {
				it = &Item{Name: category, Path: set.Dir, Detail: keptReasons[category]}
				kept[category] = it
			}
			it.Count++
			it.Bytes += size
			if len(it.Examples) < maxExamples {
				it.Examples = append(it.Examples, ".cloop/"+set.Prefix+rel)
			}
		}
		var info os.FileInfo
		err := os.ErrNotExist
		if set.Root != nil {
			info, err = set.Root.Lstat(".cloop")
		}
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: %w", err)
		case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
			return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: %s is not a directory (a link is not followed)", set.Dir)
		}
		seen := 0
		walkErr := fs.WalkDir(set.Root.FS(), ".cloop", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == ".cloop" {
				return nil
			}
			seen++
			if seen > maxInventoryEntries {
				return fmt.Errorf("projectmove: %s holds more than %d entries", set.Dir, maxInventoryEntries)
			}
			rel := strings.TrimPrefix(p, ".cloop/")
			if !strings.Contains(rel, "/") && (inDatabase[rel] || notFiles[rel] || notPacked[rel]) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				// Directories are walked; links and devices are neither
				// followed nor packed.
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			cat := categorize(rel)
			if !deliveredCategories[cat] {
				keep(cat, rel, fi.Size())
				return nil
			}
			entries = append(entries, entry{set: i, rel: rel})
			return nil
		})
		if walkErr != nil {
			return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: walk %s: %w", set.Dir, walkErr)
		}
	}
	sort.Slice(entries, func(a, b int) bool {
		return sets[entries[a].set].Prefix+entries[a].rel < sets[entries[b].set].Prefix+entries[b].rel
	})

	part := tarPath + ".part"
	out, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			os.Remove(part)
		}
	}()
	tw := tar.NewWriter(out)
	var total int64
	for _, e := range entries {
		f, err := packOne(tw, sets[e.set].Root, e.rel, sets[e.set].Prefix)
		if err != nil {
			return nil, nil, movegit.Digest{}, err
		}
		total += f.Bytes
		if maxBytes > 0 && total > maxBytes {
			return nil, nil, movegit.Digest{}, fmt.Errorf("%w: more than %d bytes", ErrFilesTooLarge, maxBytes)
		}
		files = append(files, f)
	}
	if err := tw.Close(); err != nil {
		return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: write %s: %w", tarPath, err)
	}
	if err := out.Sync(); err != nil {
		return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: sync %s: %w", tarPath, err)
	}
	if err := out.Close(); err != nil {
		return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: %w", err)
	}
	if err := os.Rename(part, tarPath); err != nil {
		return nil, nil, movegit.Digest{}, fmt.Errorf("projectmove: %w", err)
	}
	ok = true
	digest, err := movegit.FileDigest(tarPath)
	if err != nil {
		return nil, nil, movegit.Digest{}, err
	}
	var keptItems []Item
	for _, name := range categoryOrder {
		if it := kept[name]; it != nil {
			sort.Strings(it.Examples)
			keptItems = append(keptItems, *it)
		}
	}
	return files, keptItems, digest, nil
}

// packOne adds one file to the tar, read through root without following a
// link: its entry must be a regular file, and the file opened must be that
// entry.
func packOne(tw *tar.Writer, root *os.Root, rel, prefix string) (File, error) {
	name := ".cloop/" + rel
	li, err := root.Lstat(name)
	if err != nil {
		return File{}, fmt.Errorf("projectmove: read .cloop/%s: %w", rel, err)
	}
	if !li.Mode().IsRegular() {
		return File{}, fmt.Errorf("projectmove: .cloop/%s is not a regular file", rel)
	}
	f, err := root.Open(name)
	if err != nil {
		return File{}, fmt.Errorf("projectmove: read .cloop/%s: %w", rel, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return File{}, fmt.Errorf("projectmove: read .cloop/%s: %w", rel, err)
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		return File{}, fmt.Errorf("projectmove: .cloop/%s changed while it was packed (a link is not followed)", rel)
	}
	mode := uint32(fi.Mode().Perm() & 0o755)
	hdr := &tar.Header{Name: prefix + rel, Mode: int64(mode), Size: fi.Size(), ModTime: tarEpoch, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := tw.WriteHeader(hdr); err != nil {
		return File{}, fmt.Errorf("projectmove: pack .cloop/%s: %w", rel, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), io.LimitReader(f, fi.Size()))
	if err != nil {
		return File{}, fmt.Errorf("projectmove: pack .cloop/%s: %w", rel, err)
	}
	if n != fi.Size() {
		return File{}, fmt.Errorf("projectmove: .cloop/%s changed while it was packed", rel)
	}
	return File{Path: prefix + rel, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: mode}, nil
}

// openNoFollow opens a file for reading, refusing a symbolic link in its
// place.
func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// ExtractFiles writes the files of the tar at tarPath into cloopDir, each one
// checked against want before it is put in place: an entry the capture did
// not record, a path that is not plainly relative, or bytes whose digest
// differs refuse the whole extraction. No directory or file on the way is
// written through a symbolic link.
func ExtractFiles(tarPath, cloopDir string, want []File) error {
	if err := ensureDir(cloopDir); err != nil {
		return err
	}
	return readFilesTar(tarPath, want, func(rel string, r io.Reader, w File) error {
		return writeChecked(cloopDir, rel, r, w)
	})
}

// VerifyFilesTar holds the tar at tarPath to want as ExtractFiles would,
// writing nothing: a capture from a device is checked when it arrives, not
// first when it is delivered (Task 20495).
func VerifyFilesTar(tarPath string, want []File) error {
	return readFilesTar(tarPath, want, func(rel string, r io.Reader, w File) error {
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(r, w.Bytes+1))
		if err != nil {
			return fmt.Errorf("projectmove: read .cloop/%s: %w", rel, err)
		}
		if n != w.Bytes || hex.EncodeToString(h.Sum(nil)) != w.SHA256 {
			return fmt.Errorf("projectmove: .cloop/%s does not match what the capture recorded", rel)
		}
		return nil
	})
}

// readFilesTar hands each entry of the tar at tarPath to each, after holding
// it to want: recorded, plainly relative, a regular file of the recorded
// size. Every file want names must be in the tar.
func readFilesTar(tarPath string, want []File, each func(rel string, r io.Reader, w File) error) error {
	byPath := make(map[string]File, len(want))
	for _, f := range want {
		byPath[f.Path] = f
	}
	in, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("projectmove: %w", err)
	}
	defer in.Close()
	tr := tar.NewReader(in)
	got := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("projectmove: read %s: %w", tarPath, err)
		}
		rel := hdr.Name
		w, ok := byPath[rel]
		if !ok || !cleanRel(rel) || hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("projectmove: %s holds %q, which the capture did not record", tarPath, rel)
		}
		if hdr.Size != w.Bytes {
			return fmt.Errorf("projectmove: .cloop/%s is %d bytes in the tar, the capture recorded %d", rel, hdr.Size, w.Bytes)
		}
		if err := each(rel, tr, w); err != nil {
			return err
		}
		got[rel] = true
	}
	for _, f := range want {
		if !got[f.Path] {
			return fmt.Errorf("projectmove: the tar holds no .cloop/%s", f.Path)
		}
	}
	return nil
}

// ValidateFiles checks a capture's list of delivered files before anything
// acts on it: each a plain relative path, of a category a move delivers —
// directly under .cloop, or under a feature's .cloop beside it — listed once,
// with a size and a SHA-256. A list from a device (Task 20495) decides which
// tar entries are extracted, and where.
func ValidateFiles(files []File) error {
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if !cleanRel(f.Path) {
			return fmt.Errorf("projectmove: %q is not a plain relative path", f.Path)
		}
		rel := f.Path
		if rest, ok := strings.CutPrefix(rel, "features/"); ok {
			slug, inner, found := strings.Cut(rest, "/.cloop/")
			if !found || slug == "" || strings.Contains(slug, "/") {
				return fmt.Errorf("projectmove: %q is not under a feature's .cloop", f.Path)
			}
			rel = inner
		}
		if !deliveredCategories[categorize(rel)] {
			return fmt.Errorf("projectmove: .cloop/%s is not a file a move delivers", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("projectmove: .cloop/%s is listed twice", f.Path)
		}
		seen[f.Path] = true
		if f.Bytes < 0 || len(f.SHA256) != 64 || strings.Trim(f.SHA256, "0123456789abcdef") != "" || f.Mode&^0o777 != 0 {
			return fmt.Errorf("projectmove: .cloop/%s's size, digest or mode is malformed", f.Path)
		}
	}
	return nil
}

// cleanRel reports whether rel is a plain relative slash path.
func cleanRel(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") || strings.ContainsRune(rel, 0) {
		return false
	}
	if path.Clean(rel) != rel {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}

// ensureDir makes dir if it is absent, refusing one that is a link.
func ensureDir(dir string) error {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("projectmove: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("projectmove: %w", err)
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		return fmt.Errorf("projectmove: %s is not a directory (a link is not followed)", dir)
	}
	return nil
}

// writeChecked writes one file under root, through no link, and checks its
// digest before putting it in place.
func writeChecked(root, rel string, r io.Reader, w File) error {
	parts := strings.Split(rel, "/")
	dir := root
	for _, part := range parts[:len(parts)-1] {
		dir = filepath.Join(dir, part)
		if err := ensureDir(dir); err != nil {
			return err
		}
	}
	dst := filepath.Join(dir, parts[len(parts)-1])
	if info, err := os.Lstat(dst); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("projectmove: .cloop/%s is in the way and is not a regular file", rel)
	}
	tmp, err := os.CreateTemp(dir, ".move-*")
	if err != nil {
		return fmt.Errorf("projectmove: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, w.Bytes+1))
	if err != nil {
		return fmt.Errorf("projectmove: write .cloop/%s: %w", rel, err)
	}
	if n != w.Bytes || hex.EncodeToString(h.Sum(nil)) != w.SHA256 {
		return fmt.Errorf("projectmove: .cloop/%s does not match what the capture recorded", rel)
	}
	mode := os.FileMode(w.Mode&0o755) | 0o600
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("projectmove: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("projectmove: %w", err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("projectmove: %w", err)
	}
	ok = true
	return nil
}

// CheckFiles compares the files under cloopDir with what a capture recorded,
// returning what differs: a file missing, a link or anything else in its
// place, or bytes whose digest differs.
func CheckFiles(cloopDir string, want []File) []string {
	var out []string
	for _, w := range want {
		if !cleanRel(w.Path) {
			out = append(out, ".cloop/"+w.Path+": not a plain relative path")
			continue
		}
		f, err := openNoFollow(filepath.Join(cloopDir, filepath.FromSlash(w.Path)))
		if err != nil {
			out = append(out, ".cloop/"+w.Path+": "+err.Error())
			continue
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			f.Close()
			out = append(out, ".cloop/"+w.Path+": not a regular file")
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		switch {
		case err != nil:
			out = append(out, ".cloop/"+w.Path+": "+err.Error())
		case n != w.Bytes || hex.EncodeToString(h.Sum(nil)) != w.SHA256:
			out = append(out, fmt.Sprintf(".cloop/%s: %d bytes with digest %s, want %d with %s", w.Path, n, short16(hex.EncodeToString(h.Sum(nil))), w.Bytes, short16(w.SHA256)))
		}
	}
	return out
}

func short16(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
