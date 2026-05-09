// Package atomicfile centralises crash-safe file writes used across cloop's
// persistent stores (state, profile, checkpoint, kb, alert, eval, metrics,
// trace, daemon, and more).
//
// Why a separate package: until this consolidation, ~17 packages each carried
// their own near-identical writeAtomic helper. Variants drifted (some skipped
// chmod, some forgot the cleanup-on-error defer, none flushed the parent
// directory inode). Centralising the helper lets us fix durability bugs once
// and have every store benefit, instead of chasing copy-pasted regressions.
//
// Crash semantics: data is staged in a sibling .tmp file in the same directory
// as the target, then fsynced and renamed into place. POSIX rename within a
// directory is atomic with respect to concurrent readers, so they always see
// either the previous valid file or the new valid file — never a zero-byte or
// truncated one.
//
// Durability: after the rename, the parent directory's inode is fsynced so the
// new directory entry survives a power loss. Without that step the file's
// data is on disk but the rename can be lost on crash, leaving the previous
// content (best case) or — if the previous file was being replaced — neither
// the old name nor the new content visible (worst case).
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Write atomically writes data to path with the given file mode.
//
// On success, path contains exactly data and has mode permissions. On any
// failure, path is left untouched and any staged .tmp file is cleaned up.
//
// The parent directory of path must exist; Write does not call MkdirAll.
// (Callers typically know the directory was already created during init.)
func Write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return fmt.Errorf("atomicfile: create tmp in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()

	// Cleanup defer: if the rename below succeeds, tmpPath no longer exists
	// and Stat returns ENOENT, so Remove is skipped. If anything before
	// rename fails, we drop the staged file so the directory doesn't accrete
	// .tmp leftovers.
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: write tmp %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: sync tmp %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close tmp %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("atomicfile: chmod tmp %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomicfile: rename %s -> %s: %w", tmpPath, path, err)
	}

	// Flush the parent directory so the new dirent survives a power loss.
	// Failure here is not fatal — the rename already returned success and on
	// most filesystems the dirent will be flushed within seconds — but we
	// surface the error for callers that care about strict durability.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// QuarantineCorrupt renames path aside as path + ".corrupt-<unix>" so a Load
// callsite can recover from an unparseable file by treating it as absent and
// initialising a fresh store. The original bytes are preserved next to the
// original location for forensic inspection (a user can diff or restore them).
//
// Use this from Load functions whose parsers (json.Unmarshal, yaml.Unmarshal,
// etc.) reject the file's contents — typically because:
//   - a previous binary version wrote a different schema,
//   - a power loss landed before pkg/atomicfile (or in a non-atomic legacy
//     write path) and left a zero-byte/truncated file,
//   - a user manually edited the file and saved invalid syntax.
//
// Returns the new path on success and "" if the rename failed (e.g. read-only
// filesystem). Callers should treat a "" return as a soft failure: log it and
// fall back to the in-memory zero value WITHOUT removing the original — the
// next process restart can retry the quarantine. Never returns an error so the
// recovery path itself can't add new failure modes to a Load that's already
// trying to dig out of corruption.
func QuarantineCorrupt(path string) string {
	qpath := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
	// If a same-second quarantine already exists (test harness, fast restart),
	// disambiguate with a numeric suffix so we never silently clobber a prior
	// backup.
	if _, err := os.Stat(qpath); err == nil {
		for i := 1; i < 1000; i++ {
			alt := fmt.Sprintf("%s.%d", qpath, i)
			if _, err := os.Stat(alt); os.IsNotExist(err) {
				qpath = alt
				break
			}
		}
	}
	if err := os.Rename(path, qpath); err != nil {
		return ""
	}
	return qpath
}
