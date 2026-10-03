package donecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fingerprint identifies a dirty entry's state: what git says about it (its
// status letters, modes and index object names), then a NUL, then its
// working-tree content. Two fingerprints are equal only if neither changed.
//
// method is the content half of the fingerprint the entry had at the
// baseline, or "" when taking one. A file whose baseline was hashed is hashed
// again — whatever the budget, since the baseline already paid for it once —
// and one whose baseline was its size and modification time is compared on
// those, so the two halves of a comparison are always computed the same way.
// budget, when not nil, is the content left to hash for this baseline; past
// it, files are fingerprinted by size and modification time.
func fingerprint(ctx context.Context, top string, e entry, method string, budget *int64) string {
	return e.state + "\x00" + contentPrint(ctx, top, e, method, budget)
}

func contentPrint(ctx context.Context, top string, e entry, method string, budget *int64) string {
	abs := filepath.Join(top, filepath.FromSlash(strings.TrimSuffix(e.path, "/")))
	fi, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "absent"
	case err != nil:
		return "unreadable:" + err.Error()
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(abs)
		if err != nil {
			return "unreadable-link"
		}
		return "link:" + target
	case fi.IsDir():
		return "dir:" + dirPrint(ctx, abs)
	case !fi.Mode().IsRegular():
		return fmt.Sprintf("mode:%v", fi.Mode().Type())
	}

	statPrint := fmt.Sprintf("stat:%d:%d:%v", fi.Size(), fi.ModTime().UnixNano(), fi.Mode().Perm())
	switch {
	case strings.HasPrefix(method, "stat:"):
		return statPrint
	case strings.HasPrefix(method, "sha256:"):
		// The baseline hashed this file, so it was no larger than
		// maxHashFileBytes then.
	case fi.Size() > maxHashFileBytes || (budget != nil && *budget < fi.Size()):
		return statPrint
	}
	sum, n, err := hashFile(abs)
	if err != nil {
		return "unreadable:" + err.Error()
	}
	if n > maxHashFileBytes {
		// Grown past what was hashed: it changed.
		return fmt.Sprintf("size:%d", n)
	}
	if budget != nil {
		*budget -= n
	}
	return "sha256:" + sum
}

// hashFile returns the SHA-256 of the file's first maxHashFileBytes+1 bytes
// and how many it read.
func hashFile(abs string) (string, int64, error) {
	f, err := os.Open(abs)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxHashFileBytes+1))
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// dirPrint fingerprints a directory entry — a submodule or an untracked nested
// repository — by the names, sizes, modes and modification times of what it
// holds, up to maxDirEntries of them. Contents are not read: a nested
// repository can be arbitrarily large, and any change to it moves a
// modification time.
func dirPrint(ctx context.Context, root string) string {
	type item struct {
		rel  string
		info string
	}
	var items []item
	walked := 0
	cut := false
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		walked++
		if walked > maxDirEntries {
			cut = true
			return fs.SkipAll
		}
		fi, ferr := d.Info()
		if ferr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		items = append(items, item{rel, fmt.Sprintf("%v:%d:%d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())})
		return nil
	})
	sort.Slice(items, func(i, j int) bool { return items[i].rel < items[j].rel })
	h := sha256.New()
	for _, it := range items {
		fmt.Fprintf(h, "%s\x00%s\x00", it.rel, it.info)
	}
	if cut {
		fmt.Fprintf(h, "cut:%d", maxDirEntries)
	}
	return hex.EncodeToString(h.Sum(nil))
}
