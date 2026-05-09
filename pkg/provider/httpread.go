package provider

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// MaxResponseBytes caps a fully-buffered provider response body. The largest
// realistic AI completion (max output tokens × ~4 bytes/char + thinking +
// JSON overhead) sits in the low single-digit MB range; 32 MiB is generous
// enough that legitimate responses are never refused while bounding the
// damage from a misbehaving server (or proxy injecting a huge HTML error
// page) that would otherwise OOM the process via io.ReadAll.
const MaxResponseBytes int64 = 32 << 20

// MaxErrorBodyBytes caps error-path body reads. Error responses are echoed
// into user-facing error messages; we do not want to embed megabytes of
// stack traces or HTML into a wrapped error.
const MaxErrorBodyBytes int64 = 64 << 10

// ErrResponseTooLarge is returned by ReadResponseBody when the body exceeds
// the supplied cap.
var ErrResponseTooLarge = errors.New("provider: response body exceeds maximum allowed size")

// ReadResponseBody reads up to maxBytes from r and returns the buffer.
// If the body is larger than maxBytes it returns ErrResponseTooLarge with
// the limit included so the user-facing error is actionable.
//
// Implementation note: we read maxBytes+1 through io.LimitReader; if the
// final length is greater than maxBytes the cap was exceeded. This avoids a
// false positive when the body is exactly maxBytes long.
func ReadResponseBody(r io.Reader, maxBytes int64) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxBytes {
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, maxBytes)
	}
	return buf, nil
}

// ReadResponseBodyTruncated reads at most maxBytes from r and reports
// whether the underlying body was longer. Unlike ReadResponseBody, oversize
// is not an error — the caller wants whatever diagnostic content is
// available (typical use: error-path bodies that get embedded in a wrapped
// error message). The returned buffer is at most maxBytes long.
func ReadResponseBodyTruncated(r io.Reader, maxBytes int64) (data []byte, truncated bool, err error) {
	buf, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return buf, false, err
	}
	if int64(len(buf)) > maxBytes {
		return buf[:maxBytes], true, nil
	}
	return buf, false, nil
}

// MaxStreamLineBytes caps a single line in a streamed response (SSE event
// or NDJSON record). bufio.Scanner's default ceiling is 64 KiB; legitimate
// provider events can exceed that — Anthropic occasionally emits a single
// thinking_delta of several hundred KiB, and OpenAI's reasoning summaries
// can do the same. 4 MiB leaves comfortable headroom while still bounding
// the damage from a misbehaving server that emits one huge line.
const MaxStreamLineBytes = 4 << 20

// NewStreamScanner returns a *bufio.Scanner configured to read SSE / NDJSON
// streamed responses. It uses a 64 KiB initial buffer (cheap) and grows up
// to MaxStreamLineBytes per line. A line that exceeds the cap surfaces as
// bufio.ErrTooLong via Scanner.Err() — callers should wrap that error with
// provider context so users can tell streaming-cap-exceeded apart from a
// transport failure.
func NewStreamScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), MaxStreamLineBytes)
	return scanner
}
