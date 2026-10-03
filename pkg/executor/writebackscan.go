package executor

// writebackscan.go finds a sandbox's write-back report in its output stream,
// for the drivers whose only channel back from a finished sandbox is that
// stream: the Kubernetes driver's Pod, and the container driver's feature mode
// (Task 20367), where the write-back runs inside the container so that git is
// never run on the host in a repository the sandbox could write.
//
// # The forgery, and why it does not matter
//
// The harness shares that stream. Model-authored code can print a sentinel line
// naming any branch and commit it likes. Two things contain it:
//
//   - the scanner takes the *last* well-formed line, and the wrapper emits its
//     line only after the harness's stream has closed. A forged line is always
//     overwritten by the real one.
//   - nothing downstream trusts the value regardless. The hub verifies the
//     named commit, checks it descends from the base it pinned, and inspects
//     every changed path before anything moves. The sentinel says where to
//     look; it never says what is true.

import (
	"strings"
	"sync"
)

// WriteBackScanner finds the write-back line in a workload's output stream.
//
// The stream arrives as arbitrary chunks — a line may be split across two of
// them, and several lines may share one — so the scanner buffers a partial line
// rather than assuming chunk boundaries mean anything. Only text that could
// still become a sentinel is retained: the buffer is dropped the moment the
// current line is longer than a sentinel could be, so a workload that prints a
// gigabyte without a newline costs nothing. The zero value is ready to use.
type WriteBackScanner struct {
	mu      sync.Mutex
	partial []byte
	// result is the last well-formed sentinel seen. Later ones replace
	// earlier ones; see the file comment for why that direction.
	result *WriteBackResult
}

// maxSentinelLine bounds the partial-line buffer. Twice the encoded ceiling so
// a sentinel that arrives split across chunks still fits while it is being
// reassembled.
const maxSentinelLine = 2 * MaxWriteBackSentinelBytes

// Observe feeds one chunk of output to the scanner.
func (s *WriteBackScanner) Observe(text string) {
	if text == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(text) > 0 {
		nl := strings.IndexByte(text, '\n')
		if nl < 0 {
			// No line ending yet. Keep it only while it could still be a
			// sentinel — both in length and in prefix, since a line that has
			// already diverged from the marker will never match it.
			s.partial = append(s.partial, text...)
			if len(s.partial) > maxSentinelLine || !couldBeSentinel(s.partial) {
				s.partial = nil
			}
			return
		}
		line := append(s.partial, text[:nl]...)
		s.partial = nil
		text = text[nl+1:]
		if r, ok := ScanWriteBackSentinel(string(line)); ok {
			r := r
			s.result = &r
		}
	}
}

// Snapshot returns the last sentinel seen, or nil.
func (s *WriteBackScanner) Snapshot() *WriteBackResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result
}

// Buffered reports how many bytes of an unfinished line the scanner is holding,
// so a test can pin the memory bound.
func (s *WriteBackScanner) Buffered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.partial)
}

// couldBeSentinel reports whether b is still a viable prefix of a sentinel
// line, so an ordinary line of harness output is discarded on its first bytes
// rather than buffered to the length limit.
func couldBeSentinel(b []byte) bool {
	s := string(b)
	if len(s) >= len(WriteBackSentinel) {
		return strings.HasPrefix(s, WriteBackSentinel)
	}
	return strings.HasPrefix(WriteBackSentinel, s)
}
