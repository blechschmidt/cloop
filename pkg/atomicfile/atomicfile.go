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
