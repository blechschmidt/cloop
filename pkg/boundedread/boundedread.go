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

// ArtifactMaxBytes is the shared cap for reads of a task artifact — the
// agent's own captured stdout, stored under .cloop/tasks/ and
// .cloop/artifacts/.
//
// This content is not adversarial in the usual sense, which is exactly why it
// went unbounded for so long: nobody writes a hostile artifact, but a task
// that shells out to a build, a training run, or a chatty test suite produces
// a multi-gigabyte one by accident. Every reader of that blob — context
// injection, summarization, evaluation, the TUI — then pulls it whole into
// the hub's memory.
//
// 16 MiB is far above any real transcript (they are kilobytes) and far below
// what would threaten the process. Callers that exceed it must report the
// truncation rather than silently reasoning over a prefix.
//
// Deliberately untyped: it is used both as an int64 byte cap and as an int
// length in callers and tests.
const ArtifactMaxBytes = 16 << 20

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

// hookAfterStat is a test-only hook fired after the initial Stat in ReadFile.
// Tests use it to simulate a file that grows between the stat and the read so
// the TOCTOU protection (LimitReader) is exercised deterministically.
var hookAfterStat func()

// ReadFile loads the file at path into memory, refusing to read anything
// larger than maxBytes. Pass 0 for maxBytes to use DefaultMaxBytes.
//
// On size overrun ReadFile returns *SizeError without reading any data. On a
// missing file it returns the underlying os.PathError so callers can still
// match errors.Is(err, fs.ErrNotExist). Directories are rejected explicitly.
//
// The cap is enforced both at stat time (fast path) and again at read time via
// io.LimitReader so a file that grew between the stat and the open (a live
// log being appended to, a torrent in progress) cannot slip past the cap.
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
	if hookAfterStat != nil {
		hookAfterStat()
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read maxBytes+1 so a file that grew between Stat and Open gets caught
	// rather than slipping through. Without this guard a slow-growing log
	// could push the in-memory allocation arbitrarily large.
	buf, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("boundedread: read %s: %w", path, err)
	}
	if int64(len(buf)) > maxBytes {
		return nil, &SizeError{Path: path, Size: int64(len(buf)), Max: maxBytes}
	}
	return buf, nil
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

// ReadFileTail reads up to the last maxBytes of path and reports whether
// earlier content was skipped. Pass 0 for maxBytes to use DefaultMaxBytes.
//
// Use this instead of ReadFileTruncated whenever the caller wants the outcome
// of a process rather than its preamble: a completion signal, a stack trace, a
// test summary and an agent's closing report all live at the end of a log. A
// head-biased preview of a 2 GB build log is 16 MiB of compiler chatter and
// none of the answer.
//
// The size is taken with fstat on the already-open handle, so there is no
// window in which the path could be swapped for a larger file between the
// check and the read. A file still being appended to may grow after the seek
// offset is computed; the read stays capped at maxBytes regardless, it simply
// ends slightly before the true end of file.
//
// The returned slice starts at a byte offset, not a line or rune boundary, so
// its first line may be a partial one. Callers that render the result should
// pair it with a visible truncation marker.
func ReadFileTail(path string, maxBytes int64) (data []byte, truncated bool, err error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.IsDir() {
		return nil, false, fmt.Errorf("boundedread: %s is a directory", path)
	}
	if info.Size() > maxBytes {
		if _, err := f.Seek(info.Size()-maxBytes, io.SeekStart); err != nil {
			return nil, false, fmt.Errorf("boundedread: seek %s: %w", path, err)
		}
		truncated = true
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return nil, false, fmt.Errorf("boundedread: read %s: %w", path, err)
	}
	return buf, truncated, nil
}
