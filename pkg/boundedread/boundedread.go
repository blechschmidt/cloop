// Package boundedread reads user-supplied files with an explicit size cap so
// pointing cloop at a runaway artifact (a 5 GB log, a 2 GB binary) cannot OOM
// the process.
//
// Several cloop commands accept user-controlled file paths — `cloop kb add
// --file`, `cloop eval --rubric`, `cloop task show --show-artifact`, and the
// task-artifact reader used by the eval pipeline. Until now each one used
// os.ReadFile directly, which loads the whole file into memory regardless of
// size. A user pointing at a multi-gigabyte file would push the process into
// swap or get OOM-killed.
//
// All exported helpers stat the file first. ReadFile refuses to load anything
// larger than the cap (returning *SizeError, which matches errors.Is(err,
// ErrTooLarge)). ReadFileTruncated reads up to the cap and reports whether
// truncation happened — useful for "show me a preview" callers where a 1 MiB
// snippet of a huge file is more useful than failing.
package boundedread

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// DefaultMaxBytes caps reads when callers pass <= 0. 1 MiB comfortably covers
// human-readable inputs (KB entries, rubric YAML, terminal-displayed
// artifacts) while keeping a torn write or runaway log out of memory.
const DefaultMaxBytes int64 = 1 << 20

// ErrTooLarge is returned (wrapped in *SizeError) when the file exceeds the
// caller's size cap. Use errors.Is(err, ErrTooLarge) to detect it.
var ErrTooLarge = errors.New("file exceeds size limit")

// SizeError carries the path, observed size, and configured cap so callers
// can show a useful message ("foo.md is 5.0 GB, exceeds 1.0 MiB").
type SizeError struct {
	Path string
	Size int64
	Max  int64
}

func (e *SizeError) Error() string {
	return fmt.Sprintf("boundedread: %s is %d bytes, exceeds limit of %d bytes", e.Path, e.Size, e.Max)
}

// Is lets errors.Is(err, ErrTooLarge) match a *SizeError.
func (e *SizeError) Is(target error) bool { return target == ErrTooLarge }

// ReadFile loads the file at path into memory, refusing to read anything
// larger than maxBytes. Pass 0 for maxBytes to use DefaultMaxBytes.
//
// On size overrun ReadFile returns *SizeError without reading any data. On a
// missing file it returns the underlying os.PathError so callers can still
// match errors.Is(err, fs.ErrNotExist). Directories are rejected explicitly.
func ReadFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("boundedread: %s is a directory", path)
	}
	if info.Size() > maxBytes {
		return nil, &SizeError{Path: path, Size: info.Size(), Max: maxBytes}
	}
	return os.ReadFile(path)
}

// ReadFileTruncated reads up to maxBytes from path and reports whether the
// file was longer than the cap. Pass 0 for maxBytes to use DefaultMaxBytes.
//
// Use this when a partial preview is more useful than a hard failure —
// terminal-displayed artifacts, log previews, etc.
func ReadFileTruncated(path string, maxBytes int64) (data []byte, truncated bool, err error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	if info.IsDir() {
		return nil, false, fmt.Errorf("boundedread: %s is a directory", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	// Read maxBytes+1 so we can detect overruns even if the file grew between
	// stat and open. If we got more than maxBytes back, slice it down and
	// flag truncation.
	buf, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("boundedread: read %s: %w", path, err)
	}
	if int64(len(buf)) > maxBytes {
		return buf[:maxBytes], true, nil
	}
	return buf, false, nil
}
