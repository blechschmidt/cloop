// Package readonlysnap carries a snapshot of another project's source tree to
// an executor that does not share the hub's filesystem (Task 20501).
//
// A run whose project another project's readers list names is given that
// project read-only. A Kubernetes Pod or a remote device cannot bind the
// project's directory, so the hub builds a snapshot of it when the run's
// executor asks (Build), and the executor unpacks it where the run reads it
// (Extract) — the Pod's workspace container into a volume the harness mounts
// read-only, a device's agent into a directory it binds read-only or grants
// read-only to the confined payload.
//
// # What a snapshot holds
//
// The files git would put in a commit of the tree as it is on the hub: the
// tracked files and the untracked ones no .gitignore excludes, read from the
// working tree. Left out, at any depth, is every entry executor.ReadOnlyHidden
// names — the project's .cloop, its .git, the files credentials live in — and
// any file over MaxFileBytes, which the snapshot lists as skipped. Symbolic
// links travel as links: they are resolved inside the run's sandbox, which
// reaches nothing more for them. No history travels: a snapshot is a tree, not
// a repository.
//
// # Reading a tree someone else can write
//
// The project's own runs can change its tree while the hub reads it, and swap
// a file for a link at any moment. Every file is therefore opened beneath the
// project's directory through an os.Root, without following a link at its
// last component, and only a regular file is read; a project whose git
// configuration names a program never gets to run it, because git runs with
// executor.HardenedGitConfig and no system or global configuration, and only
// to list files.
//
// # Unpacking somewhere the workload cannot write
//
// Extract writes only beneath its destination (an os.Root again, so a link an
// earlier entry made cannot carry a later one out of it), refuses any entry
// that is not a regular file or a link, any path that is absolute, climbs or
// names a hidden entry, and bounds the count and the bytes. It leaves every
// directory 0555 and every file 0444 or 0555. The caller makes the result
// read-only to the workload in the way its executor can: a read-only mount,
// or a read-only grant in the workload's sandbox.
package readonlysnap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// Bounds on one snapshot.
const (
	// MaxFiles bounds the files a snapshot holds.
	MaxFiles = 50000
	// MaxFileBytes is the largest file a snapshot carries. A larger one is
	// left out and listed as skipped: a source tree's files are far smaller,
	// and a model or a dataset is not what a reader of the tree needs.
	MaxFileBytes = 32 << 20
	// MaxTreeBytes bounds the files' total size.
	MaxTreeBytes = 256 << 20
	// MaxArchiveBytes bounds the compressed snapshot that travels.
	MaxArchiveBytes = 64 << 20
	// maxPathBytes bounds a path inside the snapshot.
	maxPathBytes = 4096
	// maxLinkBytes bounds a link's target.
	maxLinkBytes = 4096
)

// gitTimeout bounds the listing.
const gitTimeout = 2 * time.Minute

// ErrTooLarge is a tree a snapshot cannot hold within its bounds.
var ErrTooLarge = errors.New("readonlysnap: the project's tree is too large to snapshot")

// ErrInvalid is a snapshot Extract refuses.
var ErrInvalid = errors.New("readonlysnap: invalid snapshot")

// Snapshot describes one Build.
type Snapshot struct {
	// Files and Links are the regular files and the links it holds; Bytes
	// the files' total size.
	Files int
	Links int
	Bytes int64
	// Skipped are the files left out for being over MaxFileBytes, by path.
	Skipped []string
	// Archive is the size of the compressed snapshot written.
	Archive int64
}

// Build writes a snapshot of the project directory dir to w, as a gzip
// compressed tar, and describes it. Nothing is written to w when the tree
// cannot be listed; a tree over the bounds fails with ErrTooLarge, and w then
// holds a partial archive the caller discards.
func Build(ctx context.Context, dir string, w io.Writer) (*Snapshot, error) {
	files, err := List(ctx, dir)
	if err != nil {
		return nil, err
	}
	if len(files) > MaxFiles {
		return nil, fmt.Errorf("%w: it holds %d files, more than %d", ErrTooLarge, len(files), MaxFiles)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("readonlysnap: open %s: %w", dir, err)
	}
	defer root.Close()

	counted := &countingWriter{w: w}
	gz := gzip.NewWriter(counted)
	tw := tar.NewWriter(gz)
	snap := &Snapshot{}
	for _, rel := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := addEntry(root, rel, tw, snap); err != nil {
			return nil, err
		}
		if counted.n > MaxArchiveBytes {
			return nil, fmt.Errorf("%w: it compresses to more than %d MiB", ErrTooLarge, MaxArchiveBytes>>20)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("readonlysnap: finish the snapshot: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("readonlysnap: finish the snapshot: %w", err)
	}
	if counted.n > MaxArchiveBytes {
		return nil, fmt.Errorf("%w: it compresses to more than %d MiB", ErrTooLarge, MaxArchiveBytes>>20)
	}
	snap.Archive = counted.n
	return snap, nil
}

// addEntry writes one listed path into the archive: a regular file or a link
// beneath root, as it is now. A path that is neither any more, or that has
// gone, is left out — the tree moved while it was read, and the snapshot is of
// the tree as the read found it.
func addEntry(root *os.Root, rel string, tw *tar.Writer, snap *Snapshot) error {
	fi, err := root.Lstat(rel)
	if err != nil {
		return nil
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := root.Readlink(rel)
		if err != nil || target == "" || len(target) > maxLinkBytes || strings.ContainsRune(target, 0) {
			return nil
		}
		snap.Links++
		return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: rel, Linkname: target,
			Mode: 0o777, ModTime: fi.ModTime(), Format: tar.FormatPAX})
	case !fi.Mode().IsRegular():
		return nil
	}
	if fi.Size() > MaxFileBytes {
		snap.Skipped = append(snap.Skipped, rel)
		return nil
	}
	// O_NOFOLLOW: a file swapped for a link since the Lstat is not followed
	// anywhere, not even elsewhere in the project. O_NONBLOCK: a file swapped
	// for a FIFO does not hang the read; it is refused below as not regular.
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxFileBytes {
		return nil
	}
	// Read whole, so the header names the size the archive holds even when
	// the file is being written while it is read.
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil || len(data) > MaxFileBytes {
		return nil
	}
	if snap.Bytes+int64(len(data)) > MaxTreeBytes {
		return fmt.Errorf("%w: its files add up to more than %d MiB", ErrTooLarge, MaxTreeBytes>>20)
	}
	mode := int64(0o644)
	if st.Mode().Perm()&0o111 != 0 {
		mode = 0o755
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: rel, Size: int64(len(data)),
		Mode: mode, ModTime: st.ModTime(), Format: tar.FormatPAX}); err != nil {
		return fmt.Errorf("readonlysnap: write %s: %w", rel, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("readonlysnap: write %s: %w", rel, err)
	}
	snap.Files++
	snap.Bytes += int64(len(data))
	return nil
}

// List returns the paths, relative and slash-separated, a snapshot of dir
// would hold before its bounds are applied: what git lists as tracked or
// untracked and not ignored, less every hidden one. A directory that is no
// git repository is listed against an empty one, so its .gitignore files
// still apply.
func List(ctx context.Context, dir string) ([]string, error) {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("readonlysnap: %s is not a directory", dir)
	}
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	var out []byte
	if isRepository(dir) {
		out, err = runGit(ctx, dir, nil, "-C", dir, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	} else {
		empty, merr := os.MkdirTemp("", "cloop-readonly-git-")
		if merr != nil {
			return nil, fmt.Errorf("readonlysnap: %w", merr)
		}
		defer os.RemoveAll(empty)
		if _, ierr := runGit(ctx, empty, nil, "init", "--quiet", "--bare", empty); ierr != nil {
			return nil, ierr
		}
		out, err = runGit(ctx, dir, []string{"GIT_DIR=" + empty, "GIT_WORK_TREE=" + dir},
			"ls-files", "-z", "--others", "--exclude-standard")
	}
	if err != nil {
		return nil, err
	}
	// The entries a hidden link points into — a .cloop kept as a link to a
	// directory of the tree — are hidden as the link is.
	aliases := map[string]bool{}
	for _, a := range executor.ReadOnlyHiddenAliases(dir) {
		aliases[a] = true
	}
	seen := map[string]bool{}
	var files []string
	for _, raw := range bytes.Split(out, []byte{0}) {
		rel := string(raw)
		if !validRel(rel) || executor.ReadOnlyHiddenPath(rel) || seen[rel] || aliases[strings.SplitN(rel, "/", 2)[0]] {
			continue
		}
		seen[rel] = true
		files = append(files, rel)
		if len(files) > MaxFiles {
			break
		}
	}
	sort.Strings(files)
	return files, nil
}

// isRepository reports whether dir is the top of a git working tree: it has a
// .git directory, or the .git file a linked worktree has.
func isRepository(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil
}

// runGit runs one hardened git command in dir and returns its output.
func runGit(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	pairs := append(executor.HardenedGitConfig(nil), [2]string{"safe.directory", "*"},
		[2]string{"core.quotePath", "false"})
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(append(executor.GitEnv(pairs...), "LC_ALL=C", "HOME="+os.TempDir()), env...)
	if path := os.Getenv("PATH"); path != "" {
		cmd.Env = append(cmd.Env, "PATH="+path)
	}
	gitprovision.BoundChild(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("readonlysnap: git %s: %w", args[0], ctx.Err())
		}
		return nil, fmt.Errorf("readonlysnap: list the project's files: %s", gitprovision.Collapse(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// validRel reports whether rel is a path a snapshot may hold: relative,
// clean, slash-separated, without a climbing or empty element, a control
// character or a backslash.
func validRel(rel string) bool {
	if rel == "" || len(rel) > maxPathBytes || strings.HasPrefix(rel, "/") || path.Clean(rel) != rel {
		return false
	}
	for _, r := range rel {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return false
		}
	}
	for _, elem := range strings.Split(rel, "/") {
		if elem == "" || elem == "." || elem == ".." {
			return false
		}
	}
	return true
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Extract unpacks a snapshot from r into dest, an existing empty directory,
// and leaves it read-only: directories 0555, files 0444 or 0555. On an error
// dest may hold part of the snapshot; the caller removes it with Remove.
func Extract(r io.Reader, dest string) (*Snapshot, error) {
	fi, err := os.Lstat(dest)
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("readonlysnap: %s is not a directory", dest)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return nil, fmt.Errorf("readonlysnap: open %s: %w", dest, err)
	}
	defer root.Close()
	limited := &io.LimitedReader{R: r, N: MaxArchiveBytes + 1}
	gz, err := gzip.NewReader(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	snap := &Snapshot{}
	dirs := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if limited.N <= 0 {
			return nil, fmt.Errorf("%w: it is larger than %d MiB", ErrInvalid, MaxArchiveBytes>>20)
		}
		name := hdr.Name
		if !validRel(name) {
			return nil, fmt.Errorf("%w: entry %q is not a relative path inside the snapshot", ErrInvalid, name)
		}
		if executor.ReadOnlyHiddenPath(name) {
			// Never written, whatever the archive says: a hub builds none.
			continue
		}
		if snap.Files+snap.Links >= MaxFiles {
			return nil, fmt.Errorf("%w: it holds more than %d entries", ErrInvalid, MaxFiles)
		}
		if parent := path.Dir(name); parent != "." && !dirs[parent] {
			if err := root.MkdirAll(parent, 0o755); err != nil {
				return nil, fmt.Errorf("%w: entry %q: %v", ErrInvalid, name, err)
			}
			for p := parent; p != "." && !dirs[p]; p = path.Dir(p) {
				dirs[p] = true
			}
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			if hdr.Size < 0 || hdr.Size > MaxFileBytes || snap.Bytes+hdr.Size > MaxTreeBytes {
				return nil, fmt.Errorf("%w: entry %q is over the snapshot's bounds", ErrInvalid, name)
			}
			f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			if err != nil {
				return nil, fmt.Errorf("%w: entry %q: %v", ErrInvalid, name, err)
			}
			n, cerr := io.CopyN(f, tr, hdr.Size)
			if err := f.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil || n != hdr.Size {
				return nil, fmt.Errorf("%w: entry %q is cut short", ErrInvalid, name)
			}
			mode := os.FileMode(0o444)
			if hdr.Mode&0o111 != 0 {
				mode = 0o555
			}
			if err := root.Chmod(name, mode); err != nil {
				return nil, fmt.Errorf("readonlysnap: make %s read-only: %w", name, err)
			}
			snap.Files++
			snap.Bytes += hdr.Size
		case tar.TypeSymlink:
			if hdr.Linkname == "" || len(hdr.Linkname) > maxLinkBytes || strings.ContainsRune(hdr.Linkname, 0) {
				return nil, fmt.Errorf("%w: link %q has no usable target", ErrInvalid, name)
			}
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				return nil, fmt.Errorf("%w: link %q: %v", ErrInvalid, name, err)
			}
			snap.Links++
		default:
			return nil, fmt.Errorf("%w: entry %q is neither a file nor a link", ErrInvalid, name)
		}
	}
	// Directories last, deepest first, so each is still writable while what
	// it holds is made.
	ordered := make([]string, 0, len(dirs))
	for d := range dirs {
		ordered = append(ordered, d)
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, d := range ordered {
		if err := root.Chmod(d, 0o555); err != nil {
			return nil, fmt.Errorf("readonlysnap: make %s read-only: %w", d, err)
		}
	}
	if err := os.Chmod(dest, 0o555); err != nil {
		return nil, fmt.Errorf("readonlysnap: make %s read-only: %w", dest, err)
	}
	return snap, nil
}

// Remove deletes a directory Extract filled: its read-only directories are
// opened first, without following a link, so the tree can go.
func Remove(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return os.Remove(dir)
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
	return os.RemoveAll(dir)
}
