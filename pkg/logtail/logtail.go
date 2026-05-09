// Package logtail reads the last N lines of a log file without loading the
// entire file into memory.
//
// `cloop daemon` and `cloop agent` keep long-lived append-only logs; tailing
// them with os.ReadFile + strings.Split worked fine on day-one logs but reads
// the whole file every time. After a few weeks of uptime that grows to
// hundreds of MB, and `cloop daemon status` (which prints an 8-line tail) can
// then OOM the user's terminal session.
//
// Tail seeks from the end of the file and reads at most DefaultMaxBytes,
// which is enough for at least the requested number of lines for any sane
// log line length.
package logtail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// DefaultMaxBytes caps how much of the file we will read from the end.
// 1 MiB comfortably covers thousands of typical log lines.
const DefaultMaxBytes = 1 << 20

// Tail returns the last n lines of the file at path. It reads at most
// DefaultMaxBytes from the end of the file. If the file is smaller than that
// the whole file is read.
//
// On a missing file Tail returns (nil, error wrapping fs.ErrNotExist) so
// callers can use errors.Is(err, fs.ErrNotExist) to render a friendly message.
// Empty files yield (nil, nil).
//
// If n <= 0 the result is an empty slice.
func Tail(path string, n int) ([]string, error) {
	return TailWithMax(path, n, DefaultMaxBytes)
}

// TailWithMax is like Tail but lets the caller override the byte cap.
// Useful for tests and for callers that want a tighter bound.
func TailWithMax(path string, n int, maxBytes int64) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}

	readSize := size
	truncated := false
	if readSize > maxBytes {
		readSize = maxBytes
		truncated = true
	}

	if _, err := f.Seek(size-readSize, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek %s: %w", path, err)
	}

	buf := make([]byte, readSize)
	if _, err := io.ReadFull(f, buf); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// If we cut into the middle of a line, drop the partial first line so we
	// never present a synthetic half-line to the caller.
	if truncated {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			// No newline in the tail window — we cannot present any complete
			// line, so behave like an empty file rather than emit garbage.
			return nil, nil
		}
	}

	text := strings.TrimRight(string(buf), "\n")
	if text == "" {
		return nil, nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
