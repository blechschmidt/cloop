package audit

// The leak scan behind the git-history and task-artifact checks.
//
// The shapes are pkg/redact's registry, which the provider-call audit, the
// secret broker and the telemetry scrubber also use; this file only decides
// how much text to hold at once and how a finding is worded. Before the
// registry, this package had its own eight regexes, and its GitHub ones —
// ghp_ and ghs_ followed by 30 letters and digits — had never heard of gho_,
// ghu_ or ghr_ and could not match an installation token minted since
// September 2026, whose seventh character is an underscore. `cloop audit`
// reported a clean history over a real leak.

import (
	"errors"
	"io"
	"strings"

	"github.com/blechschmidt/cloop/pkg/redact"
)

const (
	// scanChunk is how much of a stream is scanned at once. git log -p over a
	// long history can run to gigabytes, and it used to be read whole.
	scanChunk = 1 << 20
	// scanOverlap is how much of each chunk is carried into the next, so a
	// credential cut by a chunk boundary is whole in one of them. It is far
	// longer than any token shape; a PEM block only needs its header line.
	scanOverlap = 16 << 10
)

// configuredLabel names a hit on a value from the project's own config, as
// opposed to a shape from the registry.
const configuredLabel = "a secret from .cloop/config.yaml"

// leakScan accumulates what a text or a stream contained.
type leakScan struct {
	verbatim []string
	overlap  int

	detectors  map[string]bool
	configured bool

	// window and chunk are readFrom's buffers, kept so one scanner can read
	// a thousand small artifacts without allocating two megabytes for each.
	window, chunk []byte
}

// newLeakScan scans for every registry shape and, verbatim, for values the
// caller already knows to be secret.
func newLeakScan(verbatim []string) *leakScan {
	s := &leakScan{verbatim: verbatim, overlap: scanOverlap, detectors: map[string]bool{}}
	for _, v := range verbatim {
		if len(v) > s.overlap {
			s.overlap = len(v)
		}
	}
	return s
}

// reset forgets what was found, keeping the buffers, so the next stream's
// findings are its own.
func (s *leakScan) reset() {
	clear(s.detectors)
	s.configured = false
}

func (s *leakScan) scan(text string) {
	for _, m := range redact.Find(text) {
		s.detectors[m.Detector] = true
	}
	if !s.configured {
		for _, v := range s.verbatim {
			if v != "" && strings.Contains(text, v) {
				s.configured = true
				break
			}
		}
	}
}

// readFrom scans r to its end in overlapping windows, so memory is bounded by
// the window rather than by the history.
func (s *leakScan) readFrom(r io.Reader) error {
	if s.chunk == nil {
		s.chunk = make([]byte, scanChunk)
		s.window = make([]byte, 0, scanChunk+s.overlap)
	}
	window := s.window[:0]
	defer func() { s.window = window[:0] }()
	for {
		n, err := io.ReadFull(r, s.chunk)
		if n > 0 {
			window = append(window, s.chunk[:n]...)
			s.scan(string(window))
			if len(window) > s.overlap {
				window = append(window[:0], window[len(window)-s.overlap:]...)
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return nil
		default:
			return err
		}
	}
}

// found reports whether anything matched.
func (s *leakScan) found() bool { return s.configured || len(s.detectors) > 0 }

// names returns the matching detectors' names, in registry order.
func (s *leakScan) names() []string {
	var out []string
	for _, d := range redact.Detectors() {
		if s.detectors[d.Name] {
			out = append(out, d.Name)
		}
	}
	return out
}

// shapeLabels returns the matching detectors' labels, in registry order.
func (s *leakScan) shapeLabels() []string {
	var out []string
	for _, d := range redact.Detectors() {
		if s.detectors[d.Name] {
			out = append(out, d.Label)
		}
	}
	return out
}

// labels returns everything that matched, worded for a report line. Never a
// value: the report is printed to a terminal and pasted into tickets.
func (s *leakScan) labels() []string {
	out := s.shapeLabels()
	if s.configured {
		out = append(out, configuredLabel)
	}
	return out
}

// Leaks returns the names of the pkg/redact detectors that match text, in
// registry order: exactly the scan the git-history and task-artifact checks
// run, exported so tests/security holds this scanner to the same fixture
// corpus as the three that redact.
func Leaks(text string) []string {
	s := newLeakScan(nil)
	s.scan(text)
	return s.names()
}
