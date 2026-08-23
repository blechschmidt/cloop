// Package securewipe destroys credential material on disk and says whether it
// succeeded.
//
// # Why this is its own package
//
// Two copies of this code existed — pkg/secretbroker (the hub's lease mount)
// and pkg/executor/agent (an edge device's confined vault) — and both had the
// same defect: every step of the overwrite was written `_ =`. If the O_WRONLY
// open failed, or WriteAt failed, or Sync failed, the function still returned
// nil. Only the unlink was actually guaranteed, so a caller that logged
// "credential wiped" had been told the bytes were zeroed when they had merely
// been made unreachable through that name. On the os.TempDir() fallback path,
// where the lease directory is on a real filesystem rather than a tmpfs, that
// is the difference between a destroyed secret and a recoverable one.
//
// The duplication is why the defect survived: fixing one copy would have left
// the other lying. Neither package could host the shared version — the agent
// must build for a device that carries no secret store, so it cannot import
// the broker, and the broker has no business importing an agent. Hence a leaf
// package that depends on nothing outside the standard library.
//
// # What "wiped" means here, and what it does not
//
// File overwrites the bytes with zeros, fsyncs, and unlinks. That defeats a
// reader of the raw device on a conventional filesystem. It does not defeat:
//
//   - a copy-on-write or log-structured filesystem (btrfs, ZFS, F2FS, APFS),
//     where the overwrite lands in a new extent and the old one survives until
//     it is reclaimed;
//   - a filesystem-level or block-level snapshot taken while the file existed;
//   - an SSD's flash translation layer, which may have already relocated the
//     page.
//
// This is why callers put lease directories on a tmpfs first (/dev/shm, /run)
// and treat the wipe as the fallback rather than the primary guarantee. See
// secretbroker.tmpfsCandidates.
//
// # Confinement
//
// Dir refuses any directory whose name does not carry LeaseDirPrefix, and File
// refuses anything that is not a regular file. Both matter because on the
// agent side the paths originate from the control plane, which this system's
// threat model treats as a party that can be compromised: without the checks,
// "revoke this lease" is an arbitrary-unlink primitive on every enrolled
// device. See docs/security/model.md and pkg/executor/agent/vault.go.
package securewipe

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LeaseDirPrefix names every directory a lease's credential files live in, on
// the hub and inside a sandbox alike.
//
// It is load-bearing rather than cosmetic: an agent refuses to unlink any path
// whose parent is not named this way, so a directory chosen for a sandbox must
// carry the prefix too. See secretbroker.SandboxLeaseDir.
const LeaseDirPrefix = "cloop-lease-"

// zeroChunk bounds the overwrite buffer. A credential file is a few kilobytes,
// but the size comes off a stat of a path the caller was handed, so a single
// make([]byte, size) is an allocation an attacker could influence.
const zeroChunk = 64 << 10

// IsLeaseDir reports whether dir's final element is a lease directory.
//
// The prefix alone is not enough — "cloop-lease-" exactly would match every
// bare prefix — so a non-empty suffix is required.
func IsLeaseDir(dir string) bool {
	base := filepath.Base(filepath.Clean(strings.TrimSpace(dir)))
	return strings.HasPrefix(base, LeaseDirPrefix) && len(base) > len(LeaseDirPrefix)
}

// File overwrites a credential file with zeros, syncs it, and unlinks it.
//
// A missing file is not an error: something else having already cleaned up is
// the end state this function exists to reach.
//
// Every failure is returned. That is the entire point of the function, and the
// reason it replaced two copies that returned nil unconditionally: a caller
// deciding whether to tell an operator "the credential is gone" needs to know
// whether it is. When the overwrite fails the unlink is still attempted and
// both errors are joined — an unlinked-but-not-zeroed file is a weaker
// outcome than a destroyed one, but a strictly better one than leaving the
// plaintext in place because the first step failed.
//
// A symlink is removed, never followed. Following one would write zeros
// through the link into whatever it points at, which for a path supplied by a
// remote control plane is a write primitive rather than a wipe.
func File(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("securewipe: stat %s: %w", path, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("securewipe: remove symlink %s: %w", path, err)
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		// A device node, FIFO or socket in a lease directory is not something
		// this package put there. Refuse rather than write to it.
		return fmt.Errorf("securewipe: refused to wipe %s: not a regular file (mode %s)", path, info.Mode())
	}

	overwriteErr := overwrite(path, info)

	removeErr := os.Remove(path)
	if errors.Is(removeErr, fs.ErrNotExist) {
		removeErr = nil
	} else if removeErr != nil {
		removeErr = fmt.Errorf("securewipe: remove %s: %w", path, removeErr)
	}
	return errors.Join(overwriteErr, removeErr)
}

// overwrite zeros the file's bytes and flushes them to storage.
//
// info is the Lstat result the caller already has; it supplies the size and,
// through os.SameFile, the identity check below.
func overwrite(path string, info os.FileInfo) error {
	size := info.Size()
	if size <= 0 {
		return nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("securewipe: open %s for overwrite: %w", path, err)
	}
	defer f.Close()

	// The Lstat above proved the *name* was a regular file; this proves the
	// open reached the same one. Between the two calls a hostile writer with
	// access to the directory could replace the file with a symlink, and the
	// open would have followed it. os.SameFile compares device and inode, so a
	// swapped target fails here rather than being filled with zeros.
	opened, err := f.Stat()
	if err != nil {
		return fmt.Errorf("securewipe: stat open file %s: %w", path, err)
	}
	if !os.SameFile(info, opened) {
		return fmt.Errorf("securewipe: refused to wipe %s: it was replaced between stat and open", path)
	}

	bufLen := size
	if bufLen > zeroChunk {
		bufLen = zeroChunk
	}
	zeros := make([]byte, bufLen)
	for off := int64(0); off < size; {
		n := int64(len(zeros))
		if rem := size - off; rem < n {
			n = rem
		}
		written, werr := f.WriteAt(zeros[:n], off)
		if werr != nil {
			return fmt.Errorf("securewipe: overwrite %s at offset %d: %w", path, off, werr)
		}
		off += int64(written)
	}

	// Sync before Close, and check both. Without the sync the zeros may still
	// be in the page cache when the unlink frees the blocks, in which case the
	// original contents are what remain on the device — the exact outcome the
	// overwrite exists to prevent.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("securewipe: sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("securewipe: close %s: %w", path, err)
	}
	return nil
}

// Dir wipes every credential file in a lease directory and removes it.
//
// Only a directory whose name carries LeaseDirPrefix is accepted, and the walk
// is deliberately one level deep: a lease directory is flat by construction, so
// a subdirectory is something this system did not create and a recursive delete
// driven by a supplied path is precisely the primitive the confinement rules
// withhold. Anything unexpected is reported and left in place, which also
// leaves the directory non-empty so its own removal fails loudly rather than
// silently discarding the evidence.
//
// A missing directory is not an error.
func Dir(dir string) error {
	clean := filepath.Clean(strings.TrimSpace(dir))
	if clean == "" || clean == "." || !filepath.IsAbs(clean) {
		return fmt.Errorf("securewipe: refused to wipe %q: not an absolute path", dir)
	}
	if !IsLeaseDir(clean) {
		return fmt.Errorf(
			"securewipe: refused to wipe %s: its name does not start with %s, so it is not a lease directory",
			clean, LeaseDirPrefix)
	}

	entries, err := os.ReadDir(clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("securewipe: read lease directory %s: %w", clean, err)
	}

	var errs []error
	for _, entry := range entries {
		path := filepath.Join(clean, entry.Name())
		if entry.IsDir() {
			errs = append(errs, fmt.Errorf(
				"securewipe: refused to remove %s: a lease directory should not contain subdirectories", path))
			continue
		}
		if err := File(path); err != nil {
			errs = append(errs, err)
		}
	}

	// os.Remove, not RemoveAll: everything that belongs here is gone by now, and
	// a recursive delete is what the confinement rules exist to withhold.
	if err := os.Remove(clean); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("securewipe: remove lease directory %s: %w", clean, err))
	}
	return errors.Join(errs...)
}
