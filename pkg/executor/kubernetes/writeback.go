package kubernetes

// writeback.go recovers a finished task's work product from a Pod.
//
// The Pod itself does the work — the harness container is wrapped so `cloop
// workspace writeback` runs after the harness and pushes the branch (see
// buildWriteBackArgv, and cmd/workspace_writeback_cmd.go for why a wrapper is
// the only moment a Pod has). What is left for the driver is learning what
// happened, and that is harder here than anywhere else in the system: a Pod
// built by this driver has no ServiceAccount token by design, so it cannot tell
// the API server anything, and by the time the driver could read a file the
// emptyDir holding it is gone.
//
// So the Pod reports through the one channel that survives: its own stdout. The
// wrapper prints a single executor.WriteBackSentinel line, and this file
// watches the log stream for it.
//
// # The forgery, and why it does not matter
//
// The harness shares that stdout. Model-authored code can print a sentinel line
// naming any branch and commit it likes. Two things contain it:
//
//   - the scanner takes the *last* well-formed line, and the wrapper emits its
//     line only after the harness's stream has closed. A forged line is always
//     overwritten by the real one.
//   - nothing downstream trusts the value regardless. pkg/writeback re-fetches
//     the named branch from the origin, checks it is at the named SHA, checks
//     it descends from the base the hub pinned, and inspects every changed path
//     before the merge queue sees it. The sentinel says where to look; it never
//     says what is true.

import (
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// sentinelScanner finds the write-back line in a Pod's output stream.
//
// The stream arrives as arbitrary chunks — a line may be split across two of
// them, and several lines may share one — so the scanner buffers a partial line
// rather than assuming chunk boundaries mean anything. Only text that could
// still become a sentinel is retained: the buffer is dropped the moment the
// current line is longer than a sentinel could be, so a workload that prints a
// gigabyte without a newline costs nothing.
type sentinelScanner struct {
	mu      sync.Mutex
	partial []byte
	// result is the last well-formed sentinel seen. Later ones replace
	// earlier ones; see the package comment for why that direction.
	result *executor.WriteBackResult
}

// maxSentinelLine bounds the partial-line buffer. Twice the encoded ceiling so
// a sentinel that arrives split across chunks still fits while it is being
// reassembled.
const maxSentinelLine = 2 * executor.MaxWriteBackSentinelBytes

// observe feeds one chunk of output to the scanner.
func (s *sentinelScanner) observe(text string) {
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
		if r, ok := executor.ScanWriteBackSentinel(string(line)); ok {
			r := r
			s.result = &r
		}
	}
}

// couldBeSentinel reports whether b is still a viable prefix of a sentinel
// line, so an ordinary line of harness output is discarded on its first bytes
// rather than buffered to the length limit.
func couldBeSentinel(b []byte) bool {
	s := string(b)
	if len(s) >= len(executor.WriteBackSentinel) {
		return strings.HasPrefix(s, executor.WriteBackSentinel)
	}
	return strings.HasPrefix(executor.WriteBackSentinel, s)
}

// snapshot returns the last sentinel seen, or nil.
func (s *sentinelScanner) snapshot() *executor.WriteBackResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result
}

// missingWriteBack is what the driver reports when a Spec asked for a
// write-back and the Pod's output never contained one.
//
// It is a synthesised failure rather than a nil result, and that is the whole
// point of tracking this. A run whose work was silently discarded and a run
// that changed nothing look identical from outside; without this the operator
// would be told the second story about the first. The reasons it happens are
// all worth naming: the image's cloop predates the wrapper, the Pod was
// evicted mid-push, or the harness was killed before the wrapper could run.
func missingWriteBack(wb executor.WriteBack) *executor.WriteBackResult {
	return &executor.WriteBackResult{
		Mode:   wb.Mode,
		Branch: strings.TrimSpace(wb.Branch),
		Err: "the Pod produced no write-back report, so any files the harness changed were " +
			"discarded with its workspace; check that the sandbox image's cloop is recent " +
			"enough to run `cloop workspace writeback`, and that the Pod was not evicted " +
			"before the harness finished",
	}
}
